defmodule VulnCheck.Feeds.Store do
  @moduledoc """
  Facade of Stage 2: returns the enriched advisories that affect the locked
  packages of a workspace.

  1. Imports `--bundle` archives into the cache (air-gapped CI).
  2. Loads the OSV Hex archive and keeps only advisories whose package is
     locked at an affected version.
  3. Enriches those matches (and only those) with EEF CNA CVE 5.1 records,
     four at a time.
  4. Falls back to strict backtick signatures from the advisory text when no
     structured symbol data exists.
  5. Adds Hex.pm retirement advisories (unless `check_retired` is off) and
     `mix.lock` hygiene warnings.
  """

  alias VulnCheck.{Cache, Config, Semver}
  alias VulnCheck.Feeds.{CVSS, EefCna, HexRetired, OSV, TextHints}
  alias VulnCheck.Types.{Advisory, Package, Workspace}
  alias VulnCheck.Workspace.GitUrl

  @type result :: %{
          advisories: [Advisory.t()],
          warnings: [String.t()],
          stats: map()
        }

  @doc """
  Returns the advisories affecting the workspace.
  """
  @spec match_workspace(Workspace.t(), Config.t(), keyword()) ::
          {:ok, [Advisory.t()]} | {:error, term()}
  def match_workspace(%Workspace{} = workspace, %Config{} = config, opts \\ []) do
    case load(workspace, config, opts) do
      {:ok, %{advisories: advisories}} -> {:ok, advisories}
      {:error, _} = error -> error
    end
  end

  @doc """
  Like `match_workspace/3` but also returns warnings and feed statistics.

  Options: `:http_client`, `:osv_url`, `:cna_base_url`, `:mitre_base_url`,
  `:hex_api_url`, `:enrich` (default `true`) and `:retired` (default
  `config.check_retired`).
  """
  @spec load(Workspace.t(), Config.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def load(%Workspace{} = workspace, %Config{} = config, opts \\ []) do
    offline = not is_nil(config.bundle) or Keyword.get(opts, :offline, config.offline)
    opts = Keyword.put(opts, :offline, offline)

    with {:ok, config} <- select_feeds(%{config | offline: offline}),
         {:ok, all, feed_status, meta} <- load_osv(config, opts) do
      matched = match(OSV.index(all), workspace)
      {enriched, enrich_warnings} = enrich(matched, config, opts)
      cna_git = merge_cna_git(enriched, EefCna.offline_git_advisories(workspace, config))
      advisories = Enum.map(enriched ++ cna_git, &text_fallback/1)

      {retired, retired_warnings} =
        if Keyword.get(opts, :retired, config.check_retired),
          do: HexRetired.advisories(workspace, config, opts),
          else: {[], []}

      {:ok,
       %{
         advisories: advisories ++ retired,
         warnings:
           selection_warnings(config) ++
             stale_warning(feed_status, meta) ++
             enrich_warnings ++
             git_warnings(advisories, workspace) ++
             retired_warnings ++ HexRetired.hygiene(workspace),
         stats: %{
           feed_status: feed_status,
           feed:
             feed_status
             |> feed_info(meta, config)
             |> Map.put(:advisories, all |> Enum.uniq_by(& &1.id) |> length())
             |> Map.put(:sources, source_counts(workspace)),
           feed_advisories: length(all),
           matched_advisories: length(matched) + length(cna_git),
           enriched_advisories: Enum.count(advisories, & &1.enriched),
           advisories_with_routines: Enum.count(advisories, &(&1.affected_routines != [])),
           retired_releases: length(retired),
           sources: source_counts(workspace)
         }
       }}
    end
  end

  defp feed_info(status, meta, config) do
    at = meta["fetched_at_unix"]
    reason = meta["refresh_error"]

    rejected =
      case reason do
        {:invalid_osv_records, count} -> count
        _ -> 0
      end

    %{
      status: status,
      source: OSV.source(meta),
      age_seconds: if(is_integer(at), do: max(System.os_time(:second) - at, 0)),
      fetched_at_unix: at,
      rejected_records: rejected,
      offline: config.offline,
      snapshot: snapshot(config),
      selection: config.feed_selection && config.feed_selection.reason,
      refresh_error: if(reason, do: inspect(reason, limit: 10, printable_limit: 200))
    }
  end

  defp snapshot(%Config{feed_selection: %{snapshot: kind}}), do: kind
  defp snapshot(_config), do: :live

  @doc false
  def selection_warnings(%Config{feed_selection: %{warnings: warnings}}),
    do: Enum.map(warnings, &"offline feed: #{&1}")

  def selection_warnings(_config), do: []

  defp stale_warning(:stale, meta) do
    reason = inspect(meta["refresh_error"], limit: 10, printable_limit: 200)
    ["OSV refresh failed (#{reason}); using the previous verified copy"]
  end

  defp stale_warning(_status, _meta), do: []

  @doc """
  Filters an advisory index down to the advisories affecting locked
  packages. The advisory `package` is rewritten to the lockfile key.
  """
  @spec match(%{String.t() => [Advisory.t()]}, Workspace.t()) :: [Advisory.t()]
  def match(index, %Workspace{packages: packages}) do
    packages
    |> Map.values()
    |> Enum.filter(&matchable?/1)
    |> Enum.sort_by(& &1.name)
    |> Enum.flat_map(fn
      %Package{source: :hex} = package ->
        index
        |> Map.get(package.hex_name || package.name, [])
        |> Enum.filter(&Semver.affected?(package.version, &1))
        |> Enum.map(&bind_package(&1, package, nil))

      %Package{source: :git} = package ->
        keys =
          [package.hex_name || package.name, GitUrl.repo_slug(package.git_url)]
          |> Enum.reject(&is_nil/1)
          |> Enum.uniq()

        keys
        |> Enum.flat_map(&Map.get(index, &1, []))
        |> Enum.uniq_by(& &1.id)
        |> Enum.flat_map(fn advisory ->
          case Semver.git_affected?(package, advisory) do
            :unaffected -> []
            status -> [bind_package(advisory, package, status)]
          end
        end)
    end)
  end

  defp merge_cna_git(existing, cna_git) do
    seen =
      existing
      |> Enum.flat_map(fn adv ->
        for id <- [adv.id | adv.aliases], do: {adv.package, id}
      end)
      |> MapSet.new()

    Enum.reject(cna_git, fn adv ->
      Enum.any?([adv.id | adv.aliases], &MapSet.member?(seen, {adv.package, &1}))
    end)
  end

  defp bind_package(advisory, package, git_status) do
    scoped = advisory |> OSV.scope_symbols(package.version) |> CVSS.for_version(package.version)

    %{
      scoped
      | package: package.name,
        source_package: advisory.source_package || advisory.package,
        checked_version: package.version,
        git_match_status: git_status
    }
  end

  defp matchable?(%Package{source: source}) when source in [:hex, :git], do: true
  defp matchable?(_package), do: false

  defp git_warnings(advisories, workspace) do
    advisories
    |> Enum.filter(&(&1.git_match_status == :uncertain))
    |> Enum.map(fn adv ->
      pkg = Map.get(workspace.packages, adv.package)
      ref = if pkg, do: pkg.git_url || pkg.git_ref || pkg.version, else: adv.checked_version

      "git dependency #{adv.package} (#{ref}) could not be verified against #{adv.id} " <>
        "without commit history or matching upstream repository; keeping advisory open"
    end)
    |> Enum.uniq()
  end

  defp source_counts(%Workspace{packages: packages}) do
    packages
    |> Map.values()
    |> Enum.frequencies_by(& &1.source)
  end

  defp select_feeds(%Config{bundle: nil} = config), do: {:ok, Cache.pin_feeds(config)}

  defp select_feeds(%Config{bundle: bundle} = config) do
    case Cache.import_bundle_snapshot(bundle, config) do
      {:ok, _manifest, scoped} -> {:ok, scoped}
      {:error, reason} -> {:error, {:bundle, reason}}
    end
  end

  defp load_osv(config, opts) do
    case OSV.load_with_metadata(config, opts) do
      {:ok, _, _, _} = result -> result
      {:error, :offline_cache_missing} -> {:error, :offline_cache_missing}
      {:error, reason} -> {:error, {:osv_feed, reason}}
    end
  end

  defp enrich(advisories, config, opts) do
    if Keyword.get(opts, :enrich, true) and advisories != [] do
      advisories
      |> Task.async_stream(&{&1, EefCna.enrich_with_status(&1, config, opts)},
        max_concurrency: 4,
        timeout: 30_000,
        on_timeout: :kill_task,
        ordered: true
      )
      |> Enum.zip(advisories)
      |> Enum.map_reduce([], fn
        {{:ok, {_advisory, {:ok, enriched, new_warnings}}}, _original}, warnings ->
          {enriched, new_warnings ++ warnings}

        {{:ok, {advisory, {:error, reason}}}, _original}, warnings ->
          {advisory, [enrich_warning(advisory, reason) | warnings]}

        {{:exit, reason}, original}, warnings ->
          {original, [enrich_warning(original, reason) | warnings]}
      end)
      |> then(fn {list, warnings} -> {list, warnings |> Enum.reverse() |> Enum.uniq()} end)
    else
      {advisories, []}
    end
  end

  defp enrich_warning(advisory, :offline_cache_missing) do
    "no cached CVE 5.1 record for #{Advisory.cve_id(advisory) || advisory.id} " <>
      "(offline); function-level symbols unavailable"
  end

  defp enrich_warning(advisory, :no_matching_affected_product) do
    "CVE 5.1 record for #{Advisory.cve_id(advisory) || advisory.id} has no matching product " <>
      "for #{advisory.package}; using the OSV evidence"
  end

  defp enrich_warning(advisory, reason) do
    "could not fetch CVE 5.1 record for #{Advisory.cve_id(advisory) || advisory.id}: " <>
      inspect(reason)
  end

  defp text_fallback(%Advisory{affected_routines: []} = advisory) do
    case TextHints.symbols(advisory.summary <> "\n" <> advisory.details) do
      [] -> advisory
      routines -> %{advisory | affected_routines: routines, symbol_source: :text}
    end
  end

  defp text_fallback(advisory), do: advisory
end
