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

  alias VulnCheck.Config
  alias VulnCheck.Report.{Formatter, JSON}
  alias VulnCheck.Types.{Finding, Package, ScanReport, Workspace}

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
    root = root_ref(ws)

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
        "properties" => metadata_properties(ws)
      },
      "components" => Enum.map(packages, &component/1),
      "dependencies" => dependencies(ws, packages, root),
      "vulnerabilities" => vulnerabilities(report.findings, ws)
    }

    serial = Keyword.get_lazy(opts, :serial_number, fn -> serial_number(body) end)
    Map.put(body, "serialNumber", serial)
  end

  @doc "Reference of the scanned project."
  @spec root_ref(Workspace.t() | nil) :: String.t()
  def root_ref(%Workspace{project_name: name}), do: "pkg:generic/" <> encode_segment(name)
  def root_ref(_workspace), do: "pkg:generic/project"

  defp root_component(ws, root) do
    %{"type" => "application", "name" => (ws && ws.project_name) || "project", "bom-ref" => root}
  end

  defp metadata_properties(nil), do: []

  defp metadata_properties(%Workspace{} = ws) do
    [
      {"vulncheck:project_type", Atom.to_string(ws.project_type)},
      {"vulncheck:env", Atom.to_string(ws.env)},
      {"vulncheck:elixir_version", ws.elixir_version},
      {"vulncheck:otp_release", ws.otp_release}
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

    case github_repo(pkg.git_url) do
      {owner, repo} ->
        "pkg:github/#{encode_segment(String.downcase(owner))}/#{encode_segment(String.downcase(repo))}@#{encode_segment(ref)}"

      nil ->
        base = "pkg:generic/#{encode_segment(pkg.name)}@#{encode_segment(ref)}"
        if pkg.git_url, do: base <> "?vcs_url=" <> encode_segment("git+" <> pkg.git_url), else: base
    end
  end

  def purl(%Package{} = pkg),
    do: "pkg:generic/#{encode_segment(pkg.name)}@#{encode_segment(pkg.version)}"

  defp github_repo(url) when is_binary(url) do
    case Regex.run(~r{github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$}, url) do
      [_, owner, repo] -> {owner, repo}
      _ -> nil
    end
  end

  defp github_repo(_url), do: nil

  defp encode_segment(text), do: URI.encode(text, &URI.char_unreserved?/1)

  defp component(%Package{} = pkg) do
    ref = purl(pkg)

    %{
      "type" => "library",
      "bom-ref" => ref,
      "name" => pkg.name,
      "version" => pkg.version,
      "purl" => ref,
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

  defp dependencies(nil, _packages, root), do: [%{"ref" => root, "dependsOn" => []}]

  defp dependencies(%Workspace{} = ws, packages, root) do
    refs = Map.new(packages, &{&1.name, purl(&1)})
    direct = if ws.direct_deps == [], do: sources(packages), else: ws.direct_deps

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

  defp vulnerabilities(findings, ws) do
    findings
    |> Enum.reject(&(&1.verdict == :retired))
    |> Enum.map(&vulnerability(&1, ws))
    |> Enum.sort_by(&{&1["id"], &1["bom-ref"]})
  end

  defp vulnerability(%Finding{} = f, ws) do
    ref = package_ref(f, ws)

    %{
      "bom-ref" => "#{f.advisory_id}/#{f.package}",
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

  defp package_ref(%Finding{package: name, installed_version: version}, %Workspace{
         packages: packages
       }) do
    case Map.get(packages, name) do
      %Package{} = pkg -> purl(pkg)
      nil -> "pkg:hex/#{encode_segment(name)}@#{encode_segment(version)}"
    end
  end

  defp package_ref(%Finding{package: name, installed_version: version}, _ws),
    do: "pkg:hex/#{encode_segment(name)}@#{encode_segment(version)}"

  defp source_name("CVE-" <> _), do: "NVD"
  defp source_name("GHSA-" <> _), do: "GitHub"
  defp source_name("EEF-" <> _), do: "EEF CNA"
  defp source_name(_id), do: "OSV"

  defp rating(%Finding{} = f) do
    base = %{
      "severity" => Atom.to_string(f.severity),
      "source" => %{"name" => source_name(f.advisory_id)}
    }

    if is_number(f.cvss_score), do: Map.put(base, "score", f.cvss_score), else: base
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
  def analysis(%Finding{suppressed: true, suppression_expired: false, verdict: verdict} = f)
      when verdict in [:reachable, :potentially_reachable] do
    %{
      "state" => "not_affected",
      "justification" => "protected_by_mitigating_control",
      "detail" => f.suppression_reason || "suppressed in .vulncheck.ignore"
    }
  end

  def analysis(%Finding{verdict: :reachable} = f) do
    %{"state" => "exploitable", "detail" => trace_summary(f)}
    |> then(fn a -> if Formatter.fix_text(f), do: Map.put(a, "response", ["update"]), else: a end)
  end

  def analysis(%Finding{verdict: :potentially_reachable} = f),
    do: %{"state" => "in_triage", "detail" => detail(f)}

  def analysis(%Finding{verdict: :unreachable, reason: reason} = f)
      when reason in @not_in_execute_path,
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
    "Reachable call chain: " <> Enum.map_join(hops, " -> ", &Formatter.mfa(&1.mfa))
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
