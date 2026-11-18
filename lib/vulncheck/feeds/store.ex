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
  """

  alias VulnCheck.{Cache, Config, Semver}
  alias VulnCheck.Feeds.{EefCna, OSV, TextHints}
  alias VulnCheck.Types.{Advisory, Package, Workspace}

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
  `:enrich` (default `true`).
  """
  @spec load(Workspace.t(), Config.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def load(%Workspace{} = workspace, %Config{} = config, opts \\ []) do
    with :ok <- import_bundle(config),
         {:ok, all, feed_status} <- load_osv(config, opts) do
      matched = match(OSV.index(all), workspace)
      {enriched, enrich_warnings} = enrich(matched, config, opts)
      advisories = Enum.map(enriched, &text_fallback/1)

      {:ok,
       %{
         advisories: advisories,
         warnings: enrich_warnings,
         stats: %{
           feed_status: feed_status,
           feed_advisories: length(all),
           matched_advisories: length(matched),
           enriched_advisories: Enum.count(advisories, & &1.enriched),
           advisories_with_routines: Enum.count(advisories, &(&1.affected_routines != []))
         }
       }}
    end
  end

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
    |> Enum.flat_map(fn %Package{} = package ->
      index
      |> Map.get(package.hex_name || package.name, [])
      |> Enum.filter(&Semver.affected?(package.version, &1))
      |> Enum.map(&%{&1 | package: package.name})
    end)
  end

  defp matchable?(%Package{source: :hex}), do: true
  defp matchable?(%Package{source: :git, version: version}), do: Semver.valid?(version)
  defp matchable?(_package), do: false

  defp import_bundle(%Config{bundle: nil}), do: :ok

  defp import_bundle(%Config{bundle: bundle} = config) do
    case Cache.import_bundle(bundle, config) do
      {:ok, _manifest} -> :ok
      {:error, reason} -> {:error, {:bundle, reason}}
    end
  end

  defp load_osv(config, opts) do
    case OSV.load(config, opts) do
      {:ok, advisories, status} -> {:ok, advisories, status}
      {:error, :offline_cache_missing} -> {:error, :offline_cache_missing}
      {:error, reason} -> {:error, {:osv_feed, reason}}
    end
  end

  defp enrich(advisories, config, opts) do
    if Keyword.get(opts, :enrich, true) and advisories != [] do
      advisories
      |> Task.async_stream(&{&1, EefCna.enrich(&1, config, opts)},
        max_concurrency: 4,
        timeout: 30_000,
        on_timeout: :kill_task,
        ordered: true
      )
      |> Enum.zip(advisories)
      |> Enum.map_reduce([], fn
        {{:ok, {_advisory, {:ok, enriched}}}, _original}, warnings ->
          {enriched, warnings}

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
