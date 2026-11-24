defmodule VulnCheck.Feeds.EefCna do
  @moduledoc """
  Enriches matched advisories with the original CVE 5.1 records published by
  the Erlang Ecosystem Foundation CNA (`https://cna.erlef.org/cves/<CVE>.json`,
  falling back to the MITRE CVE API).

  Converted OSV records drop the function-level `programRoutines` and
  `modules` lists; CVE 5.1 records keep them, together with CVSS metrics and
  CWE identifiers. Records are cached immutably and refreshed only when the
  OSV record was modified after the cached copy was fetched.
  """

  alias VulnCheck.{Cache, Config, Semver}
  alias VulnCheck.Feeds.{CVSS, TextHints}
  alias VulnCheck.Types.{Advisory, MFA}
  alias VulnCheck.Workspace.GitUrl

  @cna_base "https://cna.erlef.org/cves"
  @mitre_base "https://cveawg.mitre.org/api/cve"
  @timeout 8_000

  @doc """
  Fetches the CVE 5.1 record for `cve_id` (primary EEF CNA URL, then MITRE).

  Options: `:cna_base_url`, `:mitre_base_url`, `:modified_at` (ISO-8601; forces
  a refresh when newer than the cached copy) plus `VulnCheck.Cache.fetch/4`
  options.
  """
  @spec fetch_record(String.t(), Config.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def fetch_record(cve_id, %Config{} = config, opts \\ []) do
    with {:ok, record, _status, _meta} <- load_record(cve_id, config, opts), do: {:ok, record}
  end

  @doc false
  def load_record(cve_id, %Config{} = config, opts) do
    rel = "cves/#{cve_id}.json"
    cna = Keyword.get(opts, :cna_base_url, @cna_base) <> "/#{cve_id}.json"
    mitre = Keyword.get(opts, :mitre_base_url, @mitre_base) <> "/#{cve_id}"

    http_opts = Keyword.merge([timeout: @timeout, retries: 1], Keyword.get(opts, :http_opts, []))

    fetch_opts =
      opts
      |> Keyword.take([:http_client, :offline])
      |> Keyword.merge(
        immutable: true,
        http_opts: http_opts,
        force: Keyword.get(opts, :force, false) or stale?(rel, config, opts)
      )

    validator = &validate_record(&1, cve_id)

    case Cache.fetch_validated(
           cna,
           rel,
           config,
           Keyword.put(fetch_opts, :allow_stale, false),
           validator
         ) do
      {:error, _reason} = error ->
        if Keyword.get(fetch_opts, :offline, config.offline),
          do: error,
          else:
            Cache.fetch_validated(
              mitre,
              rel,
              config,
              Keyword.put(fetch_opts, :force, true),
              validator
            )

      result ->
        result
    end
  end

  @doc false
  def validate_record(body, cve_id) do
    case JSON.decode(body) do
      {:ok, %{"cveMetadata" => %{"cveId" => ^cve_id}, "containers" => %{"cna" => cna}} = record}
      when is_map(cna) ->
        {:ok, record}

      _ ->
        {:error, :invalid_cve_record}
    end
  end

  defp stale?(rel, config, opts) do
    with modified when is_binary(modified) <- Keyword.get(opts, :modified_at),
         {:ok, modified_at, _} <- DateTime.from_iso8601(modified),
         %{"fetched_at_unix" => fetched} when is_integer(fetched) <-
           Cache.read_meta(Path.join(Cache.feeds_dir(config), rel)) do
      DateTime.to_unix(modified_at) > fetched
    else
      _ -> false
    end
  end

  @doc """
  Fetches and applies the CVE 5.1 record of an advisory. Advisories without a
  CVE identifier are returned unchanged.
  """
  @spec enrich(Advisory.t(), Config.t(), keyword()) :: {:ok, Advisory.t()} | {:error, term()}
  def enrich(%Advisory{} = advisory, %Config{} = config, opts \\ []) do
    with {:ok, enriched, _warnings} <- enrich_with_status(advisory, config, opts),
         do: {:ok, enriched}
  end

  @doc false
  def enrich_with_status(%Advisory{} = advisory, %Config{} = config, opts) do
    case Advisory.cve_id(advisory) do
      nil ->
        {:ok, advisory, []}

      cve ->
        with {:ok, record, status, _meta} <-
               load_record(cve, config, Keyword.put(opts, :modified_at, advisory.modified_at)),
             %Advisory{enriched: true} = enriched <- apply_record(advisory, record) do
          warnings = if status == :stale, do: ["using a stale CVE 5.1 record for #{cve}"], else: []
          {:ok, enriched, warnings}
        else
          %Advisory{} -> {:error, :no_matching_affected_product}
          error -> error
        end
    end
  end

  @doc """
  Scans cached CVE 5.1 records for git-only products matching any `:git`
  dependency's normalized `owner/repo` slug. Atom-safe (no `String.to_atom/1`).
  """
  @spec offline_git_advisories(VulnCheck.Types.Workspace.t(), Config.t()) :: [Advisory.t()]
  def offline_git_advisories(workspace, %Config{} = config) do
    git_packages =
      workspace.packages
      |> Map.values()
      |> Enum.filter(&(&1.source == :git))

    slug_to_packages =
      Enum.reduce(git_packages, %{}, fn pkg, acc ->
        case GitUrl.repo_slug(pkg.git_url) do
          nil -> acc
          slug -> Map.update(acc, slug, [pkg], &[pkg | &1])
        end
      end)

    if map_size(slug_to_packages) == 0 do
      []
    else
      config
      |> Cache.list_feed_files()
      |> Enum.filter(&(String.starts_with?(&1, "cves/") and String.ends_with?(&1, ".json")))
      |> Enum.flat_map(fn rel ->
        with {:ok, body} <- Cache.read_feed(config, rel),
             {:ok, %{"cveMetadata" => %{"cveId" => cve_id}, "containers" => %{"cna" => cna}} = rec} <-
               JSON.decode(body) do
          match_git_cve(cve_id, cna, rec, slug_to_packages)
        else
          _ -> []
        end
      end)
    end
  end

  defp match_git_cve(cve_id, cna, record, slug_to_packages) do
    affected = list(cna, "affected")

    Enum.flat_map(slug_to_packages, fn {slug, pkgs} ->
      if Enum.any?(affected, &matches_targets?(&1, [slug])) do
        Enum.map(pkgs, fn pkg ->
          base = %Advisory{
            id: cve_id,
            aliases: [],
            package: pkg.name,
            source_package: slug,
            checked_version: pkg.version,
            summary: first_description(cna),
            git_repos: [slug]
          }

          enriched = apply_record(base, record)
          status = Semver.git_affected?(pkg, enriched)
          %{enriched | git_match_status: status}
        end)
      else
        []
      end
    end)
    |> Enum.reject(&(&1.git_match_status == :unaffected))
  end

  defp first_description(cna) do
    cna
    |> list("descriptions")
    |> Enum.find_value("", fn
      %{"value" => v} when is_binary(v) -> v
      _ -> nil
    end)
  end

  @doc """
  Applies a decoded CVE 5.1 record to an advisory: `programRoutines`,
  `modules`, CVSS metrics, CWE identifiers, OTP constraints and (when the OSV
  record had none) version ranges.
  """
  @spec apply_record(Advisory.t(), map()) :: Advisory.t()
  def apply_record(%Advisory{} = advisory, record) do
    cna = get_in_map(record, ["containers", "cna"])
    package = advisory.source_package || advisory.package
    targets = Enum.uniq([package | advisory.git_repos])
    products = cna |> list("affected") |> Enum.filter(&matches_targets?(&1, targets))
    entries = Enum.filter(products, &applies_to_version?(&1, advisory.checked_version))

    case entries do
      [] -> advisory
      _ -> enrich_product(advisory, cna, products, entries)
    end
  end

  defp enrich_product(advisory, cna, products, entries) do
    blocks = Enum.map(entries, &symbols/1)
    routines = blocks |> Enum.flat_map(& &1.routines) |> Enum.uniq()
    modules = blocks |> Enum.flat_map(& &1.modules) |> Enum.uniq()
    all_routines = Enum.uniq(advisory.affected_routines ++ routines)
    all_modules = Enum.uniq(advisory.affected_modules ++ modules)

    symbol_gaps =
      advisory.symbol_gaps or
        (length(blocks) > 1 and
           ((all_routines != [] and Enum.any?(blocks, &(&1.routines == []))) or
              (all_modules != [] and Enum.any?(blocks, &(&1.routines == [] and &1.modules == [])))))

    symbol_source =
      cond do
        routines == [] -> advisory.symbol_source
        all_routines == routines -> :cve
        true -> :osv_and_cve
      end

    {cna_rating, cna_label} = metrics(cna, "CNA " <> (Advisory.cve_id(advisory) || advisory.id))

    cwes =
      cna
      |> list("problemTypes")
      |> Enum.flat_map(&list(&1, "descriptions"))
      |> Enum.flat_map(fn
        %{"cweId" => cwe} when is_binary(cwe) -> [cwe]
        _ -> []
      end)

    descriptions =
      cna
      |> list("descriptions")
      |> Enum.flat_map(fn
        %{"value" => value} when is_binary(value) -> [value]
        _ -> []
      end)
      |> Enum.join("\n")

    ranges =
      if advisory.version_ranges == [] and advisory.affected_versions == [] do
        Enum.flat_map(products, &Semver.from_cve_affected/1)
      else
        advisory.version_ranges
      end

    rating = CVSS.strongest([CVSS.current(advisory), cna_rating])
    label = Advisory.max_severity(advisory.severity, cna_label)

    extra_repos =
      products
      |> Enum.flat_map(fn entry ->
        ([entry["repo"], entry["packageName"], entry["collectionURL"]]
         |> Enum.map(&GitUrl.repo_slug/1)) ++
          [purl_repo_slug(entry["packageURL"])]
      end)
      |> Enum.reject(&is_nil/1)

    git_ranges =
      Enum.flat_map(products, fn entry ->
        repo =
          GitUrl.repo_slug(entry["repo"]) ||
            purl_repo_slug(entry["packageURL"]) ||
            GitUrl.repo_slug(entry["packageName"])

        entry |> Semver.from_cve_git_versions() |> Enum.map(&%{&1 | repo: repo})
      end)

    %{
      advisory
      | affected_routines: all_routines,
        affected_modules: all_modules,
        symbol_source: symbol_source,
        symbol_gaps: symbol_gaps,
        cwes: Enum.uniq(advisory.cwes ++ cwes),
        version_ranges: ranges,
        fixed_versions: Enum.uniq(advisory.fixed_versions ++ Semver.fixed_versions(ranges)),
        git_repos: Enum.uniq(advisory.git_repos ++ extra_repos),
        git_ranges: Enum.uniq(advisory.git_ranges ++ git_ranges),
        otp_constraints: otp_constraints(advisory, descriptions),
        enriched: true
    }
    |> CVSS.apply_rating(rating, label)
  end

  defp applies_to_version?(_entry, nil), do: true

  # A product whose versions are all commit ids carries no numbered
  # information, so its applicability to a numbered version is unknown and
  # its symbols are kept.
  defp applies_to_version?(entry, version) do
    versions = list(entry, "versions")
    commit_only? = versions != [] and Enum.all?(versions, &(&1["versionType"] == "git"))

    commit_only? or
      Enum.any?(Semver.from_cve_affected(entry), &Semver.in_range?(version, &1)) or
      not Semver.valid?(version)
  end

  defp symbols(entry) do
    routines =
      entry
      |> list("programRoutines")
      |> Enum.flat_map(fn
        %{"name" => name} when is_binary(name) -> parse_routine(name)
        name when is_binary(name) -> parse_routine(name)
        _ -> []
      end)

    modules =
      entry
      |> list("modules")
      |> Enum.filter(&is_binary/1)
      |> Enum.map(&MFA.normalize_module/1)

    %{routines: routines, modules: modules}
  end

  defp otp_constraints(%Advisory{otp_constraints_conflict: true}, _descriptions), do: nil

  defp otp_constraints(advisory, descriptions),
    do: advisory.otp_constraints || TextHints.otp_constraint(descriptions)

  defp matches_targets?(entry, targets) when is_map(entry) do
    normalized = Enum.map(targets, &String.downcase/1)

    case entry["packageURL"] do
      "pkg:hex/" <> path ->
        [name | _] = String.split(path, ~r/[@?#]/, parts: 2)
        (name |> URI.decode() |> String.downcase()) in normalized

      "pkg:github/" <> path ->
        [owner_repo | _] = String.split(path, ~r/[@?#]/, parts: 2)
        (owner_repo |> URI.decode() |> String.downcase()) in normalized

      "pkg:gitlab/" <> path ->
        [repo_path | _] = String.split(path, ~r/[@?#]/, parts: 2)
        ("gitlab.com/" <> (repo_path |> URI.decode() |> String.downcase())) in normalized

      "pkg:bitbucket/" <> path ->
        [repo_path | _] = String.split(path, ~r/[@?#]/, parts: 2)
        ("bitbucket.org/" <> (repo_path |> URI.decode() |> String.downcase())) in normalized

      "pkg:" <> _other ->
        false

      _ ->
        candidates =
          [entry["packageName"], entry["product"], GitUrl.repo_slug(entry["repo"])]
          |> Enum.filter(&is_binary/1)
          |> Enum.map(&String.downcase/1)

        Enum.any?(candidates, &(&1 in normalized))
    end
  end

  defp matches_targets?(_entry, _targets), do: false

  defp purl_repo_slug("pkg:github/" <> path) do
    [owner_repo | _] = String.split(path, ~r/[@?#]/, parts: 2)
    GitUrl.repo_slug(URI.decode(owner_repo))
  end

  defp purl_repo_slug("pkg:gitlab/" <> path) do
    [repo_path | _] = String.split(path, ~r/[@?#]/, parts: 2)
    GitUrl.repo_slug("https://gitlab.com/" <> URI.decode(repo_path))
  end

  defp purl_repo_slug("pkg:bitbucket/" <> path) do
    [repo_path | _] = String.split(path, ~r/[@?#]/, parts: 2)
    GitUrl.repo_slug("https://bitbucket.org/" <> URI.decode(repo_path))
  end

  defp purl_repo_slug(_), do: nil

  defp metrics(cna, source) do
    entries =
      for metric <- list(cna, "metrics"),
          {key, method} <- [{"cvssV4_0", "CVSSv4"}, {"cvssV3_1", "CVSSv31"}, {"cvssV3_0", "CVSSv3"}],
          %{^key => %{} = data} <- [metric],
          do: {method, data}

    rating =
      entries
      |> Enum.map(fn {method, data} ->
        CVSS.published(data["baseScore"], data["vectorString"], method, source)
      end)
      |> CVSS.preferred()

    label =
      Enum.reduce(entries, :unknown, fn {_method, data}, best ->
        Advisory.max_severity(best, Advisory.parse_severity(data["baseSeverity"]))
      end)

    {rating, label}
  end

  defp parse_routine(name) do
    case MFA.parse_routine(name) do
      {:ok, mfa} -> [mfa]
      :error -> []
    end
  end

  defp get_in_map(map, []), do: map
  defp get_in_map(map, [key | rest]) when is_map(map), do: get_in_map(Map.get(map, key), rest)
  defp get_in_map(_other, _keys), do: %{}

  defp list(map, key) when is_map(map) do
    case Map.get(map, key) do
      list when is_list(list) -> list
      _ -> []
    end
  end

  defp list(_map, _key), do: []
end
