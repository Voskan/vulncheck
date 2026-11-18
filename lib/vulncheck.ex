defmodule VulnCheck do
  @moduledoc """
  Function-level reachability vulnerability scanner for Elixir, Erlang and Gleam.

  VulnCheck matches locked dependencies against OSV.dev and EEF CNA CVE 5.1
  advisories, then proves — on compiled `.beam` call graphs enriched with OTP
  supervision roots, framework callbacks and runtime adapter configuration —
  whether the vulnerable functions can actually execute in production.
  """

  alias VulnCheck.{Config, Scanner}
  alias VulnCheck.Feeds.HexRetired
  alias VulnCheck.Types.{Finding, ScanReport}

  @version Mix.Project.config()[:version]

  @doc "Returns the VulnCheck version."
  @spec version() :: String.t()
  def version, do: @version

  @doc """
  Scans a project.

  Accepts a `VulnCheck.Config` or a project directory plus configuration
  fields as keyword options (for example `env: :prod, offline: true`).
  Feed options such as `:http_client` are passed to `VulnCheck.Scanner.run/2`.

      {:ok, report} = VulnCheck.scan("path/to/app", offline: true)
  """
  @spec scan(Config.t() | Path.t(), keyword()) :: {:ok, ScanReport.t()} | {:error, term()}
  def scan(config_or_path \\ ".", opts \\ [])

  def scan(%Config{} = config, opts), do: Scanner.run(config, opts)

  def scan(path, opts) when is_binary(path) do
    fields = Map.keys(%Config{}) -- [:__struct__]
    {config_opts, run_opts} = Keyword.split(opts, fields)
    Scanner.run(struct(%Config{project_dir: path}, config_opts), run_opts)
  end

  @doc """
  Returns `true` when the report must fail the build under `config`:

    * an active (not suppressed) finding with a verdict selected by
      `fail_on` and a severity of at least `min_severity`
      (unknown severities count as critical),
    * a retired release when `fail_on_retired` is set (production
      dependencies, or security retirements of others under `--fail-on any`),
    * a policy violation (for example a forbidden new suppression).
  """
  @spec should_fail?(ScanReport.t(), Config.t()) :: boolean()
  def should_fail?(%ScanReport{} = report, %Config{} = config) do
    report.policy_violations != [] or
      Enum.any?(report.findings, &failing?(&1, config))
  end

  defp failing?(%Finding{suppressed: true}, _config), do: false

  defp failing?(%Finding{verdict: :retired} = finding, config) do
    severe_enough?(finding, config) and HexRetired.gate?(finding, config)
  end

  defp failing?(%Finding{verdict: verdict} = finding, config) do
    severe_enough?(finding, config) and verdict in failing_verdicts(config.fail_on)
  end

  defp severe_enough?(finding, config),
    do: Config.severity_rank(finding.severity) >= Config.severity_rank(config.min_severity)

  defp failing_verdicts(:reachable), do: [:reachable]
  defp failing_verdicts(:potentially_reachable), do: [:reachable, :potentially_reachable]
  defp failing_verdicts(:any), do: [:reachable, :potentially_reachable, :unreachable]
  defp failing_verdicts(:none), do: []
end
