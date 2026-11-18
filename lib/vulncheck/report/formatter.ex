defmodule VulnCheck.Report.Formatter do
  @moduledoc """
  Contract of report renderers plus helpers shared by them.
  """

  alias VulnCheck.Types.{Advisory, Finding, MFA, TraceHop}

  @callback render(VulnCheck.Types.ScanReport.t(), VulnCheck.Config.t()) :: String.t()

  @reason_labels %{
    call_chain_proven: "call chain proven",
    active_network_daemon: "active network daemon",
    unresolved_dynamic_dispatch: "unresolved dynamic dispatch",
    missing_symbol_granularity: "no function-level advisory data",
    missing_beam_debug_info: "missing .beam debug info",
    package_retired: "retired on Hex.pm",
    non_prod_dependency: "non-production dependency",
    otp_version_unaffected: "OTP version unaffected",
    otp_app_not_started: "OTP application not started",
    adapter_not_configured: "adapter not configured",
    module_not_loaded: "module not loaded",
    function_not_called: "function not called"
  }

  @doc "Identifier shown to humans: the CVE alias when there is one."
  @spec display_id(Finding.t()) :: String.t()
  def display_id(%Finding{} = finding), do: Finding.cve_id(finding) || finding.advisory_id

  @doc "Upper-case severity label."
  @spec severity_label(Advisory.severity()) :: String.t()
  def severity_label(severity), do: severity |> Atom.to_string() |> String.upcase()

  @doc "Severity with CVSS score, e.g. `HIGH · CVSS 7.5`."
  @spec severity_text(Finding.t(), String.t()) :: String.t()
  def severity_text(%Finding{} = finding, separator \\ " · ") do
    case finding.cvss_score do
      score when is_number(score) ->
        severity_label(finding.severity) <> separator <> "CVSS " <> format_score(score)

      _ ->
        severity_label(finding.severity)
    end
  end

  @doc "Formats a CVSS score with one decimal."
  @spec format_score(number()) :: String.t()
  def format_score(score), do: :erlang.float_to_binary(score / 1, decimals: 1)

  @doc "Human description of a reason code."
  @spec reason_label(Finding.reason()) :: String.t()
  def reason_label(reason), do: Map.get(@reason_labels, reason, Atom.to_string(reason))

  @doc "Fix hint, e.g. `>= 1.16.4`, or `nil`."
  @spec fix_text(Finding.t()) :: String.t() | nil
  def fix_text(%Finding{recommended_fix: fix}) when is_binary(fix), do: ">= " <> fix
  def fix_text(%Finding{fixed_versions: [_ | _] = versions}), do: ">= " <> List.last(versions)
  def fix_text(_finding), do: nil

  @doc "Formats an MFA in Elixir or Erlang notation."
  @spec mfa(MFA.t() | nil) :: String.t() | nil
  def mfa(nil), do: nil
  def mfa(%MFA{} = mfa), do: MFA.format(mfa)

  @doc "Location of a trace hop (`file:line`), or `nil`."
  @spec location(TraceHop.t()) :: String.t() | nil
  def location(%TraceHop{file: nil}), do: nil
  def location(%TraceHop{file: file, line: nil}), do: file
  def location(%TraceHop{file: file, line: line}), do: "#{file}:#{line}"

  @doc "Findings grouped by verdict, preserving report order."
  @spec by_verdict([Finding.t()]) :: %{atom() => [Finding.t()]}
  def by_verdict(findings) do
    active = Enum.reject(findings, & &1.suppressed)

    Map.merge(
      %{reachable: [], potentially_reachable: [], retired: [], unreachable: []},
      Enum.group_by(active, & &1.verdict)
    )
  end
end
