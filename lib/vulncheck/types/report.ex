defmodule VulnCheck.Types.TraceHop do
  @moduledoc """
  One hop of a witness call chain from an entrypoint to a vulnerable routine.

  A chain whose entrypoint is not called by the project itself (protocol
  handlers of a network daemon, modules named in the configuration) starts
  with an activation hop (`:daemon_activation` or `:config_activation`): the
  place in the project that makes the entrypoint live, with `note` saying
  how. Its `mfa` is `nil` when that place is not a function (a `.app` file
  or a configuration file).

  An `:incoming_data` hop marks a receive function of a protocol client
  (`Mint.HTTP2.stream/2`, ...): the chain before it reaches the client
  from the project, the chain after it processes what servers send back.
  """

  @enforce_keys [:mfa]
  defstruct [:mfa, :file, :line, :kind, :note]

  @type kind ::
          :daemon_activation
          | :config_activation
          | :incoming_data
          | :entrypoint
          | :static_call
          | :macro_expanded
          | :behaviour_callback
          | :supervisor_child
          | :dynamic_apply
          | :dynamic_candidate
          | :imports

  @type t :: %__MODULE__{
          mfa: VulnCheck.Types.MFA.t() | nil,
          file: String.t() | nil,
          line: non_neg_integer() | nil,
          kind: kind() | nil,
          note: String.t() | nil
        }

  @doc "`true` for the activation hop that starts a chain."
  @spec activation?(t()) :: boolean()
  def activation?(%__MODULE__{kind: kind}), do: kind in [:daemon_activation, :config_activation]
end

defmodule VulnCheck.Types.Finding do
  @moduledoc """
  The verdict produced for one advisory against the scanned project.
  """

  alias VulnCheck.Types.{MFA, TraceHop}

  @type verdict :: :reachable | :potentially_reachable | :unreachable | :retired
  @type reason ::
          :call_chain_proven
          | :daemon_call_chain
          | :active_network_daemon
          | :unresolved_dynamic_dispatch
          | :missing_symbol_granularity
          | :missing_beam_debug_info
          | :package_retired
          | :non_prod_dependency
          | :otp_version_unaffected
          | :otp_app_not_started
          | :adapter_not_configured
          | :module_not_loaded
          | :function_not_called

  @enforce_keys [:advisory_id, :package, :installed_version, :severity, :verdict, :reason]
  defstruct [
    :advisory_id,
    aliases: [],
    package: "",
    installed_version: "",
    fixed_versions: [],
    recommended_fix: nil,
    summary: "",
    severity: :unknown,
    cvss_score: nil,
    cvss_vector: nil,
    cvss_method: nil,
    cvss_source: nil,
    cwes: [],
    references: [],
    verdict: :potentially_reachable,
    reason: :missing_symbol_granularity,
    reason_detail: "",
    target_mfa: nil,
    context_routines: [],
    trace: [],
    fingerprint: "",
    suppressed: false,
    suppression_reason: nil,
    suppression_expired: false,
    suppression_expires: nil,
    package_scope: :prod,
    git_match_status: nil
  ]

  @type t :: %__MODULE__{
          advisory_id: String.t(),
          aliases: [String.t()],
          package: String.t(),
          installed_version: String.t(),
          fixed_versions: [String.t()],
          recommended_fix: String.t() | nil,
          summary: String.t(),
          severity: VulnCheck.Types.Advisory.severity(),
          cvss_score: float() | nil,
          cvss_vector: String.t() | nil,
          cvss_method: String.t() | nil,
          cvss_source: String.t() | nil,
          cwes: [String.t()],
          references: [String.t()],
          verdict: verdict(),
          reason: reason(),
          reason_detail: String.t(),
          target_mfa: MFA.t() | nil,
          context_routines: [MFA.t()],
          trace: [TraceHop.t()],
          fingerprint: String.t(),
          suppressed: boolean(),
          suppression_reason: String.t() | nil,
          suppression_expired: boolean(),
          suppression_expires: String.t() | nil,
          package_scope: :prod | :build_only | :non_prod,
          git_match_status: :confirmed | :uncertain | nil
        }

  @verdicts [:reachable, :potentially_reachable, :retired, :unreachable]
  @reasons [
    :call_chain_proven,
    :daemon_call_chain,
    :active_network_daemon,
    :unresolved_dynamic_dispatch,
    :missing_symbol_granularity,
    :missing_beam_debug_info,
    :package_retired,
    :non_prod_dependency,
    :otp_version_unaffected,
    :otp_app_not_started,
    :adapter_not_configured,
    :module_not_loaded,
    :function_not_called
  ]

  @doc "Verdicts in report order (most actionable first)."
  @spec verdicts() :: [verdict()]
  def verdicts, do: @verdicts

  @doc "All reason codes."
  @spec reasons() :: [reason()]
  def reasons, do: @reasons

  @doc """
  Computes the stable SHA-256 fingerprint of a finding from its advisory id,
  package, verdict and target routine.
  """
  @spec fingerprint(String.t(), String.t(), verdict(), MFA.t() | nil) :: String.t()
  def fingerprint(advisory_id, package, verdict, target_mfa) do
    target = if target_mfa, do: MFA.format(target_mfa), else: ""
    material = Enum.join([advisory_id, package, Atom.to_string(verdict), target], ":")
    :crypto.hash(:sha256, material) |> Base.encode16(case: :lower)
  end

  @doc """
  Fingerprints the finding would have under each of its identifiers. A
  baseline recorded while the advisory was known by an alias (for example its
  GitHub id before the records of one CVE were merged) still matches.
  """
  @spec fingerprints(t()) :: [String.t()]
  def fingerprints(%__MODULE__{} = finding) do
    alternatives =
      for id <- Enum.uniq([finding.advisory_id | finding.aliases]),
          do: fingerprint(id, finding.package, finding.verdict, finding.target_mfa)

    Enum.uniq([finding.fingerprint | alternatives])
  end

  @doc "Returns `true` when the finding is active (not suppressed by a valid ignore rule)."
  @spec active?(t()) :: boolean()
  def active?(%__MODULE__{suppressed: suppressed}), do: not suppressed

  @doc "Returns the primary CVE identifier of the finding when known."
  @spec cve_id(t()) :: String.t() | nil
  def cve_id(%__MODULE__{advisory_id: id, aliases: aliases}) do
    Enum.find_value([id | aliases], fn candidate ->
      case Regex.run(~r/(CVE-\d{4}-\d{4,})/, candidate || "") do
        [_, cve] -> cve
        _ -> nil
      end
    end)
  end
end

defmodule VulnCheck.Types.Summary do
  @moduledoc """
  Aggregated counters of a scan report.
  """

  defstruct reachable: 0,
            potentially_reachable: 0,
            unreachable: 0,
            retired: 0,
            suppressed: 0,
            expired_suppressions: 0,
            total: 0

  @type t :: %__MODULE__{
          reachable: non_neg_integer(),
          potentially_reachable: non_neg_integer(),
          unreachable: non_neg_integer(),
          retired: non_neg_integer(),
          suppressed: non_neg_integer(),
          expired_suppressions: non_neg_integer(),
          total: non_neg_integer()
        }

  @doc """
  Builds the summary counters for a list of findings. Suppressed findings are
  counted only in `suppressed`.
  """
  @spec from_findings([VulnCheck.Types.Finding.t()]) :: t()
  def from_findings(findings) do
    Enum.reduce(findings, %__MODULE__{}, fn finding, acc ->
      acc = %{acc | total: acc.total + 1}

      acc =
        if finding.suppression_expired,
          do: %{acc | expired_suppressions: acc.expired_suppressions + 1},
          else: acc

      if finding.suppressed do
        %{acc | suppressed: acc.suppressed + 1}
      else
        Map.update!(acc, finding.verdict, &(&1 + 1))
      end
    end)
  end

  @doc """
  Percentage of matched advisories proven unreachable (0 when nothing matched).
  """
  @spec noise_reduction(t()) :: non_neg_integer()
  def noise_reduction(%__MODULE__{} = summary) do
    matched =
      summary.reachable + summary.potentially_reachable + summary.unreachable + summary.suppressed

    if matched > 0, do: round(summary.unreachable * 100 / matched), else: 0
  end
end

defmodule VulnCheck.Types.ScanReport do
  @moduledoc """
  The complete result of a scan, consumed by every reporter.
  """

  alias VulnCheck.Types.{Finding, Summary, Workspace}

  defstruct [
    :workspace,
    :generated_at,
    :all_findings,
    tool_version: "",
    findings: [],
    summary: %Summary{},
    policy_violations: [],
    warnings: [],
    duration_ms: 0,
    stats: %{}
  ]

  @type t :: %__MODULE__{
          workspace: Workspace.t() | nil,
          generated_at: String.t() | nil,
          all_findings: [Finding.t()] | nil,
          tool_version: String.t(),
          findings: [Finding.t()],
          summary: Summary.t(),
          policy_violations: [String.t()],
          warnings: [String.t()],
          duration_ms: non_neg_integer(),
          stats: map()
        }

  @doc "Findings before baseline, diff and presentation filters."
  @spec complete_findings(t()) :: [Finding.t()]
  def complete_findings(%__MODULE__{} = report), do: report.all_findings || report.findings
end
