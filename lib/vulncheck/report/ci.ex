defmodule VulnCheck.Report.GitHub do
  @moduledoc """
  GitHub Actions report (`--format github`).

  Prints workflow commands that GitHub turns into pull request annotations:
  `::error` for reachable findings, `::warning` for potentially reachable
  findings and retired releases (`::notice` for unreachable ones with
  `--show-unreachable`). When `GITHUB_STEP_SUMMARY` is set, the Markdown
  report is appended to the job summary as well.
  """

  @behaviour VulnCheck.Report.Formatter

  alias VulnCheck.Config
  alias VulnCheck.Report.{Formatter, Markdown}
  alias VulnCheck.Types.{Finding, ScanReport, Summary}

  @impl true
  def render(%ScanReport{} = report, %Config{} = config) do
    write_step_summary(report, config)

    commands =
      Enum.map(Formatter.reported(report.findings, config.show_unreachable), &command(&1, report))

    violations =
      Enum.map(
        report.policy_violations,
        &("::error title=VulnCheck policy violation::" <> data(&1))
      )

    s = report.summary

    summary =
      "::notice title=VulnCheck::" <>
        data(
          "#{s.reachable} reachable, #{s.potentially_reachable} potentially reachable, " <>
            "#{s.unreachable} unreachable, #{s.retired} retired " <>
            "(#{Summary.noise_reduction(s)}% noise reduction)"
        )

    Enum.join(commands ++ violations ++ [summary], "\n") <> "\n"
  end

  @doc """
  Appends the Markdown report to the file named by `GITHUB_STEP_SUMMARY`.
  Does nothing when the variable is unset.
  """
  @spec write_step_summary(ScanReport.t(), Config.t()) :: :ok | {:error, File.posix()}
  def write_step_summary(%ScanReport{} = report, %Config{} = config) do
    case System.get_env("GITHUB_STEP_SUMMARY", "") do
      "" -> :ok
      path -> File.write(path, Markdown.render(report, config) <> "\n", [:append])
    end
  end

  defp command(%Finding{} = f, report) do
    {file, line} = Formatter.primary_location(f, report.workspace)

    severity =
      case f.verdict do
        :reachable -> "error"
        :unreachable -> "notice"
        _ -> "warning"
      end

    title =
      "#{Formatter.display_id(f)} (#{Formatter.severity_text(f, ", ")}) in #{f.package} #{f.installed_version}"

    "::#{severity} file=#{property(file)},line=#{line},title=#{property(title)}::" <>
      data(message(f))
  end

  defp message(%Finding{} = f) do
    fix = Formatter.fix_text(f)

    trace =
      case f.trace do
        [] ->
          []

        hops ->
          ["Trace:"] ++
            (hops
             |> Enum.with_index(1)
             |> Enum.map(fn {hop, i} ->
               location = Formatter.location(hop)
               "  #{i}. #{Formatter.mfa(hop.mfa)}" <> if(location, do: " (#{location})", else: "")
             end))
      end

    [
      "#{verdict_label(f.verdict)}: #{Formatter.reason_label(f.reason)}",
      f.summary != "" && "Summary: #{f.summary}",
      f.target_mfa && "Target: #{Formatter.mfa(f.target_mfa)}",
      f.reason_detail != "" && "Reason: #{f.reason_detail}",
      fix && "Fix: upgrade #{f.package} to #{fix}"
    ]
    |> Enum.filter(&is_binary/1)
    |> Kernel.++(trace)
    |> Enum.join("\n")
  end

  defp verdict_label(:reachable), do: "REACHABLE"
  defp verdict_label(:potentially_reachable), do: "POTENTIALLY REACHABLE"
  defp verdict_label(:retired), do: "RETIRED"
  defp verdict_label(:unreachable), do: "UNREACHABLE"

  @doc """
  Escapes workflow command data.

      iex> VulnCheck.Report.GitHub.data("50% done\\nnext")
      "50%25 done%0Anext"
  """
  @spec data(String.t()) :: String.t()
  def data(text) do
    text
    |> String.replace("%", "%25")
    |> String.replace("\r", "%0D")
    |> String.replace("\n", "%0A")
  end

  @doc """
  Escapes a workflow command property value.

      iex> VulnCheck.Report.GitHub.property("a:b,c")
      "a%3Ab%2Cc"
  """
  @spec property(String.t()) :: String.t()
  def property(text), do: text |> data() |> String.replace(":", "%3A") |> String.replace(",", "%2C")
end

defmodule VulnCheck.Report.GitLab do
  @moduledoc """
  GitLab Code Quality report (`--format gitlab`), usually saved as
  `gl-code-quality-report.json` and published with
  `artifacts:reports:codequality`.
  """

  @behaviour VulnCheck.Report.Formatter

  alias VulnCheck.Config
  alias VulnCheck.Report.{Formatter, JSON}
  alias VulnCheck.Types.{Finding, ScanReport}

  @impl true
  def render(%ScanReport{} = report, %Config{} = config) do
    report |> issues(config) |> JSON.encode() |> Kernel.<>("\n")
  end

  @doc "Code Quality issues of a report."
  @spec issues(ScanReport.t(), Config.t()) :: [map()]
  def issues(%ScanReport{} = report, %Config{} = config) do
    for %Finding{} = f <- Formatter.reported(report.findings, config.show_unreachable) do
      {path, line} = Formatter.primary_location(f, report.workspace)
      fix = Formatter.fix_text(f)
      fix = if fix, do: " Fix: upgrade to #{fix}.", else: ""
      target = if f.target_mfa, do: " via #{Formatter.mfa(f.target_mfa)}", else: ""

      %{
        "type" => "issue",
        "engine_name" => "vulncheck",
        "check_name" => f.advisory_id,
        "categories" => ["Security"],
        "description" =>
          "[#{f.verdict}] #{Formatter.display_id(f)} in #{f.package} #{f.installed_version}#{target}: " <>
            "#{summary(f)}#{fix}",
        "content" => %{
          "body" => "#{Formatter.reason_label(f.reason)}. #{f.reason_detail}" |> String.trim()
        },
        "fingerprint" => f.fingerprint,
        "severity" => severity(f),
        "location" => %{"path" => path, "lines" => %{"begin" => line}}
      }
    end
  end

  defp summary(%Finding{summary: summary}) when summary not in [nil, ""], do: summary
  defp summary(%Finding{} = f), do: Formatter.reason_label(f.reason)

  @doc "Code Quality severity of a finding."
  @spec severity(Finding.t()) :: String.t()
  def severity(%Finding{verdict: :unreachable}), do: "info"

  def severity(%Finding{severity: severity}) do
    case severity do
      :high -> "critical"
      :medium -> "major"
      :low -> "minor"
      _ -> "blocker"
    end
  end
end
