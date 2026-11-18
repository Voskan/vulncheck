defmodule VulnCheck.Report.OpenVEX do
  @moduledoc """
  OpenVEX v0.2.0 document (`--vex` or `--format openvex`).

  One statement per advisory and package. The status follows the
  reachability verdict:

  | Verdict and reason | `status` | `justification` |
  | :--- | :--- | :--- |
  | reachable | `affected` (with `action_statement`) | — |
  | potentially reachable | `under_investigation` | — |
  | unreachable: function not called, module not loaded, adapter not configured, OTP application not started | `not_affected` | `vulnerable_code_not_in_execute_path` |
  | unreachable: build-time only dependency (`runtime: false`) | `not_affected` | `vulnerable_code_not_in_execute_path` |
  | unreachable: development or test dependency | `not_affected` | `component_not_present` |
  | unreachable: OTP version unaffected | `not_affected` | OTP constraint in `impact_statement` |

  Retired releases are left out. With zero statements, no OpenVEX document
  is available. The document `@id` is derived from its content.
  """

  @behaviour VulnCheck.Report.Formatter

  alias VulnCheck.Config
  alias VulnCheck.Report.{CycloneDX, Formatter, JSON}
  alias VulnCheck.Types.{Finding, Package, ScanReport, Workspace}

  @context "https://openvex.dev/ns/v0.2.0"
  @not_in_execute_path [
    :function_not_called,
    :module_not_loaded,
    :adapter_not_configured,
    :otp_app_not_started
  ]

  @impl true
  def render(%ScanReport{} = report, %Config{} = config), do: encode(report, config)

  @doc "Encodes the VEX document, or returns an empty string when there are no statements."
  @spec encode(ScanReport.t(), Config.t(), keyword()) :: String.t()
  def encode(%ScanReport{} = report, %Config{} = config, opts \\ []) do
    case document(report, config, opts) do
      nil -> ""
      document -> JSON.encode(document) <> "\n"
    end
  end

  @doc "The VEX document as plain maps, or nil when there are no statements."
  @spec document(ScanReport.t(), Config.t(), keyword()) :: map() | nil
  def document(%ScanReport{} = report, %Config{} = _config, opts \\ []) do
    product = CycloneDX.root_ref(report)
    refs = CycloneDX.component_refs(report.workspace)

    statements =
      report
      |> ScanReport.complete_findings()
      |> Enum.reject(&(&1.verdict == :retired))
      |> Enum.map(&statement(&1, product, report.workspace, refs))
      |> Enum.sort_by(&{&1["vulnerability"]["name"], subcomponent(&1)})
      |> Enum.uniq_by(&{&1["vulnerability"]["name"], subcomponent(&1)})

    if statements != [], do: envelope(report, product, statements, opts)
  end

  defp envelope(report, product, statements, opts) do
    timestamp = Keyword.get(opts, :timestamp) || report.generated_at || now()

    digest =
      :crypto.hash(:sha256, JSON.encode([product, timestamp, statements]))
      |> Base.encode16(case: :lower)

    %{
      "@context" => @context,
      "@id" => "https://openvex.dev/docs/vulncheck/" <> digest,
      "author" => "VulnCheck",
      "role" => "Document Creator",
      "timestamp" => timestamp,
      "version" => 1,
      "tooling" => "vulncheck/" <> report.tool_version,
      "statements" => statements
    }
  end

  defp subcomponent(statement), do: hd(hd(statement["products"])["subcomponents"])["@id"]

  defp statement(%Finding{} = f, product, ws, refs) do
    name = Formatter.display_id(f)

    vulnerability =
      %{
        "@id" => "https://osv.dev/vulnerability/" <> URI.encode(f.advisory_id),
        "name" => name,
        "aliases" => Enum.uniq([f.advisory_id | f.aliases]) -- [name]
      }
      |> put_present("description", f.summary)

    purl = package_ref(f, ws)
    ref = Map.get(refs, f.package, purl)
    component = %{"@id" => ref}

    component =
      if ref == purl, do: component, else: Map.put(component, "identifiers", %{"purl" => purl})

    Map.merge(
      %{
        "vulnerability" => vulnerability,
        "products" => [%{"@id" => product, "subcomponents" => [component]}]
      },
      status(f)
    )
  end

  @doc "Status fields of the statement for a finding."
  @spec status(Finding.t()) :: map()
  def status(%Finding{verdict: :reachable} = f),
    do: %{"status" => "affected", "action_statement" => action(f)}

  def status(%Finding{verdict: :potentially_reachable} = f),
    do: %{"status" => "under_investigation", "status_notes" => impact(f)}

  def status(%Finding{verdict: :unreachable, reason: :otp_version_unaffected} = f),
    do: %{"status" => "not_affected", "impact_statement" => impact(f)}

  def status(%Finding{verdict: :unreachable, reason: reason, package_scope: scope} = f)
      when reason in @not_in_execute_path or scope == :build_only do
    %{
      "status" => "not_affected",
      "justification" => "vulnerable_code_not_in_execute_path",
      "impact_statement" => impact(f)
    }
  end

  def status(%Finding{verdict: :unreachable} = f) do
    %{
      "status" => "not_affected",
      "justification" => "component_not_present",
      "impact_statement" => impact(f)
    }
  end

  defp action(%Finding{} = f) do
    target = if f.target_mfa, do: " (reachable through #{Formatter.mfa(f.target_mfa)})", else: ""

    case Formatter.fix_text(f) do
      nil -> "No fixed release of #{f.package} is known; avoid calling the affected code#{target}"
      fix -> "Upgrade #{f.package} to #{fix}#{target}"
    end
  end

  defp impact(%Finding{} = f), do: present(f.reason_detail) || Formatter.reason_label(f.reason)

  defp package_ref(%Finding{package: name, installed_version: version}, ws) do
    case ws do
      %Workspace{packages: %{^name => %Package{} = pkg}} -> CycloneDX.purl(pkg)
      _ -> CycloneDX.purl(%Package{name: name, version: version, source: :hex, scope: :prod})
    end
  end

  defp put_present(map, key, value) do
    case present(value) do
      nil -> map
      value -> Map.put(map, key, value)
    end
  end

  defp present(value) when value in [nil, ""], do: nil
  defp present(value), do: value

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
end
