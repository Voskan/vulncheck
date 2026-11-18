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
  alias VulnCheck.Feeds.TextHints
  alias VulnCheck.Types.{Advisory, MFA}

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
    rel = "cves/#{cve_id}.json"
    cna = Keyword.get(opts, :cna_base_url, @cna_base) <> "/#{cve_id}.json"
    mitre = Keyword.get(opts, :mitre_base_url, @mitre_base) <> "/#{cve_id}"

    http_opts = Keyword.merge([timeout: @timeout, retries: 1], Keyword.get(opts, :http_opts, []))

    fetch_opts =
      opts
      |> Keyword.take([:http_client, :offline])
      |> Keyword.merge(immutable: true, http_opts: http_opts, force: stale?(rel, config, opts))

    result =
      case Cache.fetch(cna, rel, config, fetch_opts) do
        {:ok, body, _status} -> {:ok, body}
        {:error, :offline_cache_missing} = error -> error
        {:error, _reason} -> fetch_fallback(mitre, rel, config, fetch_opts)
      end

    with {:ok, body} <- result,
         {:ok, %{} = record} <- decode(body) do
      {:ok, record}
    end
  end

  defp fetch_fallback(url, rel, config, opts) do
    case Cache.fetch(url, rel, config, opts) do
      {:ok, body, _status} -> {:ok, body}
      error -> error
    end
  end

  defp decode(body) do
    case JSON.decode(body) do
      {:ok, %{} = record} -> {:ok, record}
      _ -> {:error, :invalid_cve_record}
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
    case Advisory.cve_id(advisory) do
      nil ->
        {:ok, advisory}

      cve ->
        with {:ok, record} <-
               fetch_record(cve, config, Keyword.put(opts, :modified_at, advisory.modified_at)) do
          {:ok, apply_record(advisory, record)}
        end
    end
  end

  @doc """
  Applies a decoded CVE 5.1 record to an advisory: `programRoutines`,
  `modules`, CVSS metrics, CWE identifiers, OTP constraints and (when the OSV
  record had none) version ranges.
  """
  @spec apply_record(Advisory.t(), map()) :: Advisory.t()
  def apply_record(%Advisory{} = advisory, record) do
    cna = get_in_map(record, ["containers", "cna"])
    entries = cna |> list("affected") |> Enum.filter(&matches_package?(&1, advisory.package))

    routines =
      entries
      |> Enum.flat_map(&list(&1, "programRoutines"))
      |> Enum.flat_map(fn
        %{"name" => name} when is_binary(name) -> parse_routine(name)
        name when is_binary(name) -> parse_routine(name)
        _ -> []
      end)
      |> Enum.uniq()

    modules =
      entries
      |> Enum.flat_map(&list(&1, "modules"))
      |> Enum.filter(&is_binary/1)
      |> Enum.map(&MFA.normalize_module/1)
      |> Enum.uniq()

    {score, vector, label} = metrics(cna)

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
        Enum.flat_map(entries, &Semver.from_cve_versions(&1["versions"]))
      else
        advisory.version_ranges
      end

    {cvss_score, cvss_vector} =
      strongest({advisory.cvss_score, advisory.cvss_vector}, {score, vector})

    record_severity =
      if score != nil,
        do: Advisory.severity_from_score(score),
        else: Advisory.parse_severity(label)

    severity = Advisory.max_severity(advisory.severity, record_severity)

    %{
      advisory
      | affected_routines: if(routines != [], do: routines, else: advisory.affected_routines),
        affected_modules: Enum.uniq(advisory.affected_modules ++ modules),
        symbol_source: if(routines != [], do: :cve, else: advisory.symbol_source),
        cvss_score: cvss_score,
        cvss_vector: cvss_vector,
        severity: severity,
        cwes: Enum.uniq(advisory.cwes ++ cwes),
        version_ranges: ranges,
        fixed_versions: Enum.uniq(advisory.fixed_versions ++ Semver.fixed_versions(ranges)),
        otp_constraints: advisory.otp_constraints || TextHints.otp_constraint(descriptions),
        enriched: true
    }
  end

  # Merged advisories keep the highest score of their sources.
  defp strongest({nil, own_vector}, {nil, vector}), do: {nil, own_vector || vector}
  defp strongest({nil, _own_vector}, {score, vector}), do: {score, vector}
  defp strongest({own, own_vector}, {nil, _vector}), do: {own, own_vector}

  defp strongest({own, own_vector}, {score, vector}),
    do: if(score > own, do: {score, vector}, else: {own, own_vector})

  defp matches_package?(entry, package) when is_map(entry) do
    names =
      [entry["packageName"], entry["product"]]
      |> Enum.filter(&is_binary/1)
      |> Enum.map(&String.downcase/1)

    purl = entry["packageURL"]

    String.downcase(package) in names or
      (is_binary(purl) and
         String.downcase(purl) |> String.starts_with?("pkg:hex/#{String.downcase(package)}"))
  end

  defp matches_package?(_entry, _package), do: false

  defp metrics(cna) do
    metrics = list(cna, "metrics")

    Enum.find_value(["cvssV3_1", "cvssV4_0", "cvssV3_0"], {nil, nil, nil}, fn key ->
      Enum.find_value(metrics, fn
        %{^key => %{"baseScore" => score} = m} when is_number(score) ->
          {score * 1.0, m["vectorString"], m["baseSeverity"]}

        _ ->
          nil
      end)
    end)
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
