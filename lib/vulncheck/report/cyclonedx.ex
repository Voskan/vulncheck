defmodule VulnCheck.Report.CycloneDX do
  @moduledoc """
  CycloneDX 1.6 JSON bill of materials (`--sbom` or `--format cyclonedx`).

  Lists every locked package with its package URL, scope (`required` for
  the production closure, `excluded` otherwise) and lockfile checksum, the
  dependency graph, and the matched advisories with a CycloneDX `analysis`
  block derived from the reachability verdict.

  Output is reproducible: the timestamp is the report's `generated_at` and
  the serial number is derived from the document content, unless they are
  given with the `:timestamp` and `:serial_number` options.
  """

  @behaviour VulnCheck.Report.Formatter

  import Bitwise

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Report.{Formatter, JSON}
  alias VulnCheck.Types.{Finding, Package, ScanReport, Workspace}
  alias VulnCheck.Workspace.GitUrl

  @not_in_execute_path [
    :function_not_called,
    :module_not_loaded,
    :adapter_not_configured,
    :otp_app_not_started
  ]

  @impl true
  def render(%ScanReport{} = report, %Config{} = config), do: encode(report, config)

  @doc """
  Encodes the bill of materials. Options: `:timestamp` (ISO-8601) and
  `:serial_number` (`urn:uuid:...`).
  """
  @spec encode(ScanReport.t(), Config.t(), keyword()) :: String.t()
  def encode(%ScanReport{} = report, %Config{} = config, opts \\ []) do
    report |> document(config, opts) |> JSON.encode() |> Kernel.<>("\n")
  end

  @doc "The bill of materials as plain maps."
  @spec document(ScanReport.t(), Config.t(), keyword()) :: map()
  def document(%ScanReport{} = report, %Config{} = _config, opts \\ []) do
    ws = report.workspace
    packages = if ws, do: ws.packages |> Map.values() |> Enum.sort_by(& &1.name), else: []
    root = root_ref(report)
    refs = component_refs(ws)

    body = %{
      "bomFormat" => "CycloneDX",
      "specVersion" => "1.6",
      "version" => 1,
      "metadata" => %{
        "timestamp" => Keyword.get(opts, :timestamp) || report.generated_at || now(),
        "tools" => %{
          "components" => [
            %{
              "type" => "application",
              "name" => "vulncheck",
              "version" => report.tool_version,
              "externalReferences" => [
                %{"type" => "website", "url" => "https://github.com/Voskan/vulncheck"}
              ]
            }
          ]
        },
        "component" => root_component(ws, root),
        "properties" => metadata_properties(report)
      },
      "components" => Enum.map(packages, &component(&1, Map.fetch!(refs, &1.name))),
      "dependencies" => dependencies(ws, packages, root, refs),
      "vulnerabilities" => vulnerabilities(ScanReport.complete_findings(report), refs)
    }

    serial = Keyword.get_lazy(opts, :serial_number, fn -> serial_number(body) end)
    Map.put(body, "serialNumber", serial)
  end

  @doc "Reference of the scanned project and the scope of the analysis."
  @spec root_ref(ScanReport.t() | Workspace.t() | nil) :: String.t()
  def root_ref(%ScanReport{workspace: %Workspace{} = ws} = report) do
    version = if ws.project_version, do: "@" <> encode_segment(ws.project_version), else: ""

    inventory =
      for {name, pkg} <- Enum.sort(ws.packages) do
        {name, pkg.source, purl(pkg), pkg.checksum, pkg.inner_checksum, pkg.git_url, pkg.scope,
         Enum.sort(pkg.deps), Enum.sort(pkg.optional_deps)}
      end

    analysis = Map.get(report.stats, :analysis, %{})

    scope =
      {ws.project_type, ws.env, ws.build_env, ws.elixir_version, ws.otp_release,
       Enum.sort(ws.root_apps), Enum.sort(ws.direct_deps), inventory, Map.get(analysis, :status),
       Map.get(analysis, :artifact_digest)}

    digest = scope |> :erlang.term_to_binary([:deterministic]) |> Cache.sha256()
    "pkg:generic/" <> encode_segment(ws.project_name) <> version <> "?scan_scope=" <> digest
  end

  def root_ref(%Workspace{} = ws), do: root_ref(%ScanReport{workspace: ws})
  def root_ref(_report), do: "urn:vulncheck:project:unspecified"

  defp root_component(ws, root) do
    base = %{
      "type" => "application",
      "name" => (ws && ws.project_name) || "project",
      "bom-ref" => root
    }

    if ws && ws.project_version, do: Map.put(base, "version", ws.project_version), else: base
  end

  defp metadata_properties(%ScanReport{workspace: nil}), do: []

  defp metadata_properties(%ScanReport{workspace: ws, stats: stats}) do
    analysis = Map.get(stats, :analysis, %{})
    status = Map.get(analysis, :status)
    digest = Map.get(analysis, :artifact_digest)
    scope = if digest, do: "compiled_workspace_snapshot", else: "dependency_inventory_snapshot"

    [
      {"vulncheck:project_type", Atom.to_string(ws.project_type)},
      {"vulncheck:env", Atom.to_string(ws.env)},
      {"vulncheck:elixir_version", ws.elixir_version},
      {"vulncheck:otp_release", ws.otp_release},
      {"vulncheck:product_scope", scope},
      {"vulncheck:build_profile", ws.build_env},
      {"vulncheck:build_analysis", status && Atom.to_string(status)},
      {"vulncheck:compiled_evidence_digest", digest}
    ]
    |> Enum.reject(fn {_name, value} -> is_nil(value) end)
    |> Enum.map(fn {name, value} -> %{"name" => name, "value" => value} end)
  end

  @doc """
  Package URL of a locked package.

      iex> VulnCheck.Report.CycloneDX.purl(%VulnCheck.Types.Package{name: "ash", version: "3.34.2", source: :hex, scope: :prod})
      "pkg:hex/ash@3.34.2"
  """
  @spec purl(Package.t()) :: String.t()
  def purl(%Package{source: :hex} = pkg) do
    "pkg:hex/" <>
      encode_segment(String.downcase(pkg.hex_name || pkg.name)) <>
      "@" <> encode_segment(pkg.version)
  end

  def purl(%Package{source: :git} = pkg) do
    ref = pkg.git_ref || pkg.version

    case GitUrl.github_repo(pkg.git_url) do
      {owner, repo} ->
        "pkg:github/#{encode_segment(owner)}/#{encode_segment(repo)}@#{encode_segment(ref)}"

      nil ->
        base = "pkg:generic/#{encode_segment(pkg.name)}@#{encode_segment(ref)}"
        if pkg.git_url, do: base <> "?vcs_url=" <> encode_segment("git+" <> pkg.git_url), else: base
    end
  end

  def purl(%Package{} = pkg),
    do: "pkg:generic/#{encode_segment(pkg.name)}@#{encode_segment(pkg.version)}"

  defp encode_segment(text), do: URI.encode(text, &URI.char_unreserved?/1)

  @doc "References of locked components, including distinct lock aliases of the same package."
  @spec component_refs(Workspace.t() | nil) :: %{String.t() => String.t()}
  def component_refs(nil), do: %{}

  def component_refs(%Workspace{packages: packages}) do
    purls = Map.new(packages, fn {name, pkg} -> {name, purl(pkg)} end)
    counts = purls |> Map.values() |> Enum.frequencies()

    Map.new(purls, fn {name, url} ->
      ref =
        if counts[url] == 1,
          do: url,
          else: "urn:vulncheck:component:" <> Cache.sha256([url, 0, name])

      {name, ref}
    end)
  end

  defp component(%Package{} = pkg, ref) do
    %{
      "type" => "library",
      "bom-ref" => ref,
      "name" => pkg.name,
      "version" => pkg.version,
      "purl" => purl(pkg),
      "scope" => if(pkg.scope == :prod, do: "required", else: "excluded")
    }
    |> put_hashes(pkg)
    |> put_references(pkg)
  end

  defp put_hashes(map, %Package{checksum: checksum}) when is_binary(checksum) do
    if checksum =~ ~r/\A[0-9a-fA-F]{64}\z/,
      do: Map.put(map, "hashes", [%{"alg" => "SHA-256", "content" => String.downcase(checksum)}]),
      else: map
  end

  defp put_hashes(map, _pkg), do: map

  defp put_references(map, %Package{source: :hex} = pkg) do
    url = "https://hex.pm/packages/#{pkg.hex_name || pkg.name}/#{pkg.version}"
    Map.put(map, "externalReferences", [%{"type" => "distribution", "url" => url}])
  end

  defp put_references(map, %Package{source: :git, git_url: url}) when is_binary(url),
    do: Map.put(map, "externalReferences", [%{"type" => "vcs", "url" => url}])

  defp put_references(map, _pkg), do: map

  defp dependencies(nil, _packages, root, _refs), do: [%{"ref" => root, "dependsOn" => []}]

  defp dependencies(%Workspace{} = ws, packages, root, refs) do
    direct =
      if ws.direct_deps == [] and not ws.direct_deps_known,
        do: sources(packages),
        else: ws.direct_deps

    entries =
      [{root, direct} | Enum.map(packages, &{refs[&1.name], &1.deps})]
      |> Enum.map(fn {ref, names} ->
        depends = names |> Enum.flat_map(&List.wrap(refs[&1])) |> Enum.uniq() |> Enum.sort()
        %{"ref" => ref, "dependsOn" => depends}
      end)

    Enum.sort_by(entries, & &1["ref"])
  end

  defp sources(packages) do
    required = packages |> Enum.flat_map(& &1.deps) |> MapSet.new()
    packages |> Enum.map(& &1.name) |> Enum.reject(&MapSet.member?(required, &1))
  end

  defp vulnerabilities(findings, refs) do
    entries =
      for finding <- findings,
          finding.verdict != :retired,
          {:ok, ref} <- [Map.fetch(refs, finding.package)],
          do: vulnerability(finding, ref)

    entries
    |> Enum.uniq_by(& &1["bom-ref"])
    |> Enum.sort_by(&{&1["id"], &1["bom-ref"]})
  end

  defp vulnerability(%Finding{} = f, ref) do
    %{
      "bom-ref" =>
        "urn:vulncheck:advisory:#{encode_segment(f.advisory_id)}:#{encode_segment(f.package)}",
      "id" => f.advisory_id,
      "source" => %{"name" => source_name(f.advisory_id), "url" => Formatter.help_uri(f)},
      "references" => Enum.map(f.aliases, &%{"id" => &1, "source" => %{"name" => source_name(&1)}}),
      "ratings" => [rating(f)],
      "cwes" => cwes(f.cwes),
      "description" => f.summary,
      "advisories" => Enum.map(f.references, &%{"url" => &1}),
      "affects" => [
        %{
          "ref" => ref,
          "versions" => [%{"version" => f.installed_version, "status" => "affected"}]
        }
      ],
      "analysis" => analysis(f)
    }
    |> put_recommendation(f)
  end

  defp source_name("CVE-" <> _), do: "NVD"
  defp source_name("GHSA-" <> _), do: "GitHub"
  defp source_name("EEF-" <> _), do: "EEF CNA"
  defp source_name(_id), do: "OSV"

  defp rating(%Finding{} = f) do
    base = %{
      "severity" => Atom.to_string(f.severity),
      "source" => %{"name" => f.cvss_source || source_name(f.advisory_id)}
    }

    for {key, value} <- [
          {"score", f.cvss_score},
          {"vector", f.cvss_vector},
          {"method", f.cvss_method}
        ],
        value != nil,
        into: base,
        do: {key, value}
  end

  defp cwes(cwes) do
    for cwe <- cwes, [_, id] <- [Regex.run(~r/(\d+)\z/, cwe)], do: String.to_integer(id)
  end

  defp put_recommendation(map, f) do
    case Formatter.fix_text(f) do
      nil -> map
      fix -> Map.put(map, "recommendation", "Upgrade #{f.package} to #{fix}")
    end
  end

  @doc "CycloneDX analysis block of a finding."
  @spec analysis(Finding.t()) :: map()
  def analysis(%Finding{verdict: :reachable} = f) do
    %{"state" => "exploitable", "detail" => trace_summary(f)}
    |> then(fn a -> if Formatter.fix_text(f), do: Map.put(a, "response", ["update"]), else: a end)
  end

  def analysis(%Finding{verdict: :potentially_reachable} = f),
    do: %{"state" => "in_triage", "detail" => detail(f)}

  def analysis(%Finding{verdict: :unreachable, reason: :otp_version_unaffected} = f),
    do: %{
      "state" => "not_affected",
      "justification" => "requires_environment",
      "detail" => detail(f)
    }

  def analysis(%Finding{verdict: :unreachable, reason: reason, package_scope: scope} = f)
      when reason in @not_in_execute_path or scope == :build_only,
      do: %{
        "state" => "not_affected",
        "justification" => "code_not_reachable",
        "detail" => detail(f)
      }

  def analysis(%Finding{verdict: :unreachable} = f),
    do: %{"state" => "not_affected", "justification" => "code_not_present", "detail" => detail(f)}

  defp detail(%Finding{reason_detail: detail} = f) when detail in [nil, ""],
    do: Formatter.reason_label(f.reason)

  defp detail(%Finding{reason_detail: detail}), do: detail

  defp trace_summary(%Finding{trace: []} = f), do: detail(f)

  defp trace_summary(%Finding{trace: hops}) do
    "Reachable call chain: " <> Enum.map_join(hops, " -> ", &Formatter.hop/1)
  end

  defp serial_number(body) do
    <<a::binary-size(6), b6, b7, b8, rest::binary-size(7), _::binary>> =
      :crypto.hash(:sha256, JSON.encode(body))

    bytes = a <> <<(b6 &&& 0x0F) ||| 0x80, b7, (b8 &&& 0x3F) ||| 0x80>> <> rest
    hex = Base.encode16(bytes, case: :lower)

    <<p1::binary-size(8), p2::binary-size(4), p3::binary-size(4), p4::binary-size(4),
      p5::binary-size(12)>> = hex

    "urn:uuid:#{p1}-#{p2}-#{p3}-#{p4}-#{p5}"
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
end
