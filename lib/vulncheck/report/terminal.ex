defmodule VulnCheck.Report.Terminal do
  @moduledoc """
  Human-oriented console report (`--format terminal`, the default).

  Actionable findings come first with their witness call chains, followed by
  a compact summary of the advisories proven unreachable and the totals.
  ANSI colors are disabled with `--no-color` or when `NO_COLOR` is set.
  """

  @behaviour VulnCheck.Report.Formatter

  alias VulnCheck.Cache.Snapshot
  alias VulnCheck.Config
  alias VulnCheck.Report.Formatter
  alias VulnCheck.Types.{Finding, ScanReport, Summary, Workspace}

  @impl true
  def render(%ScanReport{} = report, %Config{} = config) do
    paint = painter(color?(config))
    groups = Formatter.by_verdict(report.findings)
    suppressed = Enum.filter(report.findings, & &1.suppressed)

    [
      header(report, paint),
      Enum.map(groups.reachable, &actionable(&1, "[REACHABLE]", [:red, :bright], paint)),
      Enum.map(
        groups.potentially_reachable,
        &actionable(&1, "[POTENTIALLY REACHABLE]", [:yellow, :bright], paint)
      ),
      Enum.map(groups.retired, &actionable(&1, "[RETIRED]", [:yellow], paint)),
      unreachable(groups.unreachable, config, paint),
      suppressed_section(suppressed),
      nothing_found(report),
      footer(report, config, paint)
    ]
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n\n")
    |> Kernel.<>("\n")
  end

  @doc """
  Returns `true` when colors are enabled: `color` is set in the
  configuration and the `NO_COLOR` environment variable is unset or empty.
  """
  @spec color?(Config.t()) :: boolean()
  def color?(%Config{color: color}), do: color and System.get_env("NO_COLOR", "") == ""

  defp painter(true), do: fn text, styles -> IO.ANSI.format([styles, text], true) |> to_string() end
  defp painter(false), do: fn text, _styles -> text end

  defp header(report, paint) do
    title =
      paint.("VulnCheck #{report.tool_version} — BEAM Reachability Vulnerability Audit", [:bright])

    Enum.join([title | target_lines(report)] ++ feed_line(report), "\n")
  end

  defp feed_line(%ScanReport{stats: %{feed: %{advisories: count} = feed}}) do
    origin =
      if feed.offline,
        do: "offline, " <> Snapshot.label(feed.snapshot),
        else: Atom.to_string(feed.status)

    ["Feed: #{count} advisories, fetched #{Snapshot.age(feed.fetched_at_unix)} (#{origin})"]
  end

  defp feed_line(_report), do: []

  defp target_lines(%ScanReport{workspace: nil} = report),
    do: ["Scan time: #{scan_time(report)}"]

  defp target_lines(%ScanReport{workspace: %Workspace{} = ws} = report) do
    runtime =
      [ws.elixir_version && "Elixir #{ws.elixir_version}", "OTP #{ws.otp_release}"]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" / ")

    prod = ws |> Workspace.prod_packages() |> length()
    non_prod = ws |> Workspace.non_prod_packages() |> length()

    lockfile =
      if ws.lockfile,
        do: "Lockfile: #{prod} prod packages (#{non_prod} dev/test excluded)",
        else: "Lockfile: none"

    [
      "Target: #{ws.project_name} (#{ws.project_type}, #{runtime}, env: #{ws.env})",
      lockfile <> " · Scan time: " <> scan_time(report)
    ]
  end

  defp scan_time(report) do
    cached =
      case Map.get(report.stats, :feed_status) do
        :cached -> " (cached)"
        :stale -> " (stale cache)"
        _ -> ""
      end

    "#{report.duration_ms} ms#{cached}"
  end

  defp actionable(%Finding{} = finding, label, styles, paint) do
    title = paint.(label, styles) <> " " <> title(finding)

    lines =
      [
        field("Summary", finding.summary),
        finding.target_mfa && field("Target", Formatter.mfa(finding.target_mfa)),
        finding.verdict != :reachable && field("Reason", reason_text(finding)),
        finding.suppression_expired && field("Ignore", expired_text(finding)),
        trace(finding)
      ]
      |> Enum.reject(&(&1 in [nil, false]))

    Enum.join([title | lines], "\n")
  end

  defp title(%Finding{} = finding) do
    fix = Formatter.fix_text(finding)

    "#{identifier(finding)} (#{Formatter.severity_text(finding)}) — " <>
      "#{finding.package} #{finding.installed_version}" <>
      if(fix, do: " (fix: #{fix})", else: "")
  end

  defp identifier(%Finding{} = finding), do: Formatter.title_id(finding)

  defp field(_name, value) when value in [nil, ""], do: nil
  defp field(name, value), do: String.pad_trailing("  #{name}:", 11) <> one_line(value)

  defp reason_text(%Finding{reason: reason, reason_detail: detail}) do
    case one_line(detail) do
      "" -> Formatter.reason_label(reason)
      detail -> "#{detail} (#{reason})"
    end
  end

  defp expired_text(%Finding{} = finding) do
    reason =
      if finding.suppression_reason, do: " (#{one_line(finding.suppression_reason)})", else: ""

    "suppression expired on #{finding.suppression_expires}#{reason}; the finding is active again"
  end

  defp trace(%Finding{trace: []}), do: nil

  defp trace(%Finding{trace: hops}) do
    entries =
      hops
      |> Formatter.numbered()
      |> Enum.map(fn {hop, index} ->
        {"#{index}. #{Formatter.hop(hop)}", Formatter.location(hop)}
      end)

    width = entries |> Enum.map(&String.length(elem(&1, 0))) |> Enum.max()

    rows =
      Enum.map(entries, fn
        {call, nil} -> "    " <> call
        {call, location} -> "    " <> String.pad_trailing(call, width) <> " (#{location})"
      end)

    Enum.join(["  Trace:" | rows], "\n")
  end

  defp unreachable([], _config, _paint), do: nil

  defp unreachable(findings, %Config{show_unreachable: true}, paint) do
    Enum.map(findings, fn finding ->
      Enum.join(
        [
          paint.("[UNREACHABLE]", [:green]) <> " " <> title(finding),
          field("Summary", finding.summary),
          finding.target_mfa && field("Target", Formatter.mfa(finding.target_mfa)),
          field("Reason", reason_text(finding))
        ]
        |> Enum.reject(&(&1 in [nil, false])),
        "\n"
      )
    end)
  end

  defp unreachable(findings, _config, paint) do
    groups =
      findings
      |> Enum.group_by(&{&1.package, &1.installed_version, &1.reason})
      |> Enum.map(fn {{package, version, reason}, members} ->
        details = members |> Enum.map(&one_line(&1.reason_detail)) |> Enum.uniq()

        detail =
          if match?([d] when d != "", details), do: "#{reason}: #{hd(details)}", else: "#{reason}"

        {"#{length(members)} in #{package} #{version}", detail, length(members), package}
      end)
      |> Enum.sort_by(fn {_label, detail, count, package} -> {-count, package, detail} end)

    width = groups |> Enum.map(&String.length(elem(&1, 0))) |> Enum.max()
    count = length(findings)
    noun = if count == 1, do: "advisory", else: "advisories"

    rows =
      Enum.map(groups, fn {label, detail, _count, _package} ->
        "  • " <> String.pad_trailing(label, width) <> " (#{detail})"
      end)

    heading =
      paint.("Suppressed as UNREACHABLE", [:green]) <>
        " (#{count} #{noun} — pass --show-unreachable for details):"

    Enum.join([heading | rows], "\n")
  end

  defp suppressed_section([]), do: nil

  defp suppressed_section(findings) do
    rows =
      Enum.map(findings, fn finding ->
        expires =
          if finding.suppression_expires, do: ", until #{finding.suppression_expires}", else: ""

        reason = one_line(finding.suppression_reason || "")

        "  • #{identifier(finding)} in #{finding.package} #{finding.installed_version} (#{reason}#{expires})"
      end)

    Enum.join(["Suppressed by .vulncheck.ignore (#{length(findings)}):" | rows], "\n")
  end

  defp nothing_found(%ScanReport{findings: []}),
    do: "No known advisories affect the locked dependencies."

  defp nothing_found(_report), do: nil

  defp footer(report, config, paint) do
    s = report.summary

    counts =
      [
        "#{s.reachable} reachable",
        "#{s.potentially_reachable} potentially reachable",
        "#{s.unreachable} unreachable",
        s.retired > 0 && "#{s.retired} retired",
        s.suppressed > 0 && "#{s.suppressed} suppressed",
        s.expired_suppressions > 0 && plural(s.expired_suppressions, "expired suppression")
      ]
      |> Enum.filter(&is_binary/1)
      |> Enum.join(", ")

    summary = "Summary: #{counts} (#{Summary.noise_reduction(s)}% noise reduction)"

    violations =
      list_block(paint.("Policy violations:", [:red, :bright]), report.policy_violations)

    warnings = if config.quiet, do: nil, else: list_block("Warnings:", report.warnings)

    [summary, violations, warnings]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
  end

  defp list_block(_heading, []), do: nil

  defp list_block(heading, items),
    do: Enum.join([heading | Enum.map(items, &("  ! " <> one_line(&1)))], "\n")

  defp plural(1, noun), do: "1 #{noun}"
  defp plural(count, noun), do: "#{count} #{noun}s"

  defp one_line(nil), do: ""
  defp one_line(text), do: text |> String.split() |> Enum.join(" ")
end
