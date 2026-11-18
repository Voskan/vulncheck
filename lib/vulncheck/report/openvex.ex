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
  | unreachable: non-production dependency, OTP version unaffected | `not_affected` | `vulnerable_code_not_present` |
  | suppressed in `.vulncheck.ignore` (reachable or potentially reachable) | `not_affected` | `inline_mitigations_already_exist` |

  Retired releases are a package lifecycle status, not a vulnerability, and
  are left out. The document `@id` is derived from its content, so the same
  report always yields the same bytes.
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

  @doc "Encodes the VEX document. Options: `:timestamp` (ISO-8601)."
  @spec encode(ScanReport.t(), Config.t(), keyword()) :: String.t()
  def encode(%ScanReport{} = report, %Config{} = config, opts \\ []) do
    report |> document(config, opts) |> JSON.encode() |> Kernel.<>("\n")
  end

  @doc "The VEX document as plain maps."
  @spec document(ScanReport.t(), Config.t(), keyword()) :: map()
  def document(%ScanReport{} = report, %Config{} = _config, opts \\ []) do
    product = CycloneDX.root_ref(report.workspace)

    statements =
      report.findings
      |> Enum.reject(&(&1.verdict == :retired))
      |> Enum.map(&statement(&1, product, report.workspace))
      |> Enum.sort_by(&{&1["vulnerability"]["name"], subcomponent(&1)})
      |> Enum.uniq_by(&{&1["vulnerability"]["name"], subcomponent(&1)})

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

  defp statement(%Finding{} = f, product, ws) do
    name = Formatter.display_id(f)

    vulnerability =
      %{
        "@id" => "https://osv.dev/vulnerability/" <> URI.encode(f.advisory_id),
        "name" => name,
        "aliases" => Enum.uniq([f.advisory_id | f.aliases]) -- [name]
      }
      |> put_present("description", f.summary)

    Map.merge(
      %{
        "vulnerability" => vulnerability,
        "products" => [%{"@id" => product, "subcomponents" => [%{"@id" => package_ref(f, ws)}]}]
      },
      status(f)
    )
  end

  @doc "Status fields of the statement for a finding."
  @spec status(Finding.t()) :: map()
  def status(%Finding{suppressed: true, suppression_expired: false, verdict: verdict} = f)
      when verdict in [:reachable, :potentially_reachable] do
    %{
      "status" => "not_affected",
      "justification" => "inline_mitigations_already_exist",
      "impact_statement" => present(f.suppression_reason) || "suppressed in .vulncheck.ignore"
    }
  end

  def status(%Finding{verdict: :reachable} = f),
    do: %{"status" => "affected", "action_statement" => action(f)}

  def status(%Finding{verdict: :potentially_reachable} = f),
    do: %{"status" => "under_investigation", "status_notes" => impact(f)}

  def status(%Finding{verdict: :unreachable, reason: reason} = f)
      when reason in @not_in_execute_path do
    %{
      "status" => "not_affected",
      "justification" => "vulnerable_code_not_in_execute_path",
      "impact_statement" => impact(f)
    }
  end

  def status(%Finding{verdict: :unreachable} = f) do
    %{
      "status" => "not_affected",
      "justification" => "vulnerable_code_not_present",
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
