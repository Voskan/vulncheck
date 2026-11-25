defmodule VulnCheck.Report.SARIF do
  @moduledoc """
  SARIF 2.1.0 report (`--format sarif`) for GitHub Code Scanning and other
  static analysis dashboards.

  Every advisory becomes a rule whose `security-severity` carries the CVSS
  score. Each result is anchored at the first project hop, or at the
  package entry of the lockfile. Additional project hops are related
  locations, and `codeFlows` replay the whole witness call chain. Unreachable
  findings are emitted with `level: "none"` only with `--show-unreachable`.
  """

  @behaviour VulnCheck.Report.Formatter

  alias VulnCheck.Config
  alias VulnCheck.Report.{Formatter, JSON}
  alias VulnCheck.Types.{Finding, ScanReport, TraceHop}

  @schema "https://json.schemastore.org/sarif-2.1.0.json"
  @information_uri "https://github.com/Voskan/vulncheck"

  @impl true
  def render(%ScanReport{} = report, %Config{} = config) do
    report |> document(config) |> JSON.encode() |> Kernel.<>("\n")
  end

  @doc "The SARIF log as plain maps."
  @spec document(ScanReport.t(), Config.t()) :: map()
  def document(%ScanReport{} = report, %Config{} = config) do
    findings = Formatter.reported(report.findings, config.show_unreachable)

    grouped = Enum.group_by(findings, & &1.advisory_id)

    rules =
      findings
      |> Enum.map(& &1.advisory_id)
      |> Enum.uniq()
      |> Enum.map(fn id -> rule(Map.fetch!(grouped, id)) end)

    index = rules |> Enum.with_index() |> Map.new(fn {rule, i} -> {rule["id"], i} end)

    %{
      "$schema" => @schema,
      "version" => "2.1.0",
      "runs" => [
        %{
          "tool" => %{
            "driver" => %{
              "name" => "VulnCheck",
              "informationUri" => @information_uri,
              "version" => report.tool_version,
              "semanticVersion" => report.tool_version,
              "rules" => rules
            }
          },
          "automationDetails" => %{"id" => "vulncheck/#{env(report)}"},
          "columnKind" => "unicodeCodePoints",
          "results" => Enum.map(findings, &result(&1, index, report))
        }
        |> put_feed(Map.get(report.stats, :feed))
      ]
    }
  end

  defp put_feed(run, nil), do: run
  defp put_feed(run, feed), do: Map.put(run, "properties", %{"feed" => feed})

  defp env(%ScanReport{workspace: %{env: env}}), do: env
  defp env(_report), do: "prod"

  defp rule([%Finding{} = f]), do: single_rule(f, [f])
  defp rule([%Finding{} = f | _] = group), do: single_rule(f, group)

  defp single_rule(%Finding{} = f, group) do
    title = Formatter.display_id(f)
    packages = group |> Enum.map(& &1.package) |> Enum.uniq()

    summary =
      cond do
        f.summary != "" -> f.summary
        length(packages) == 1 -> "#{title} in #{f.package}"
        true -> "#{title} in #{Enum.join(packages, ", ")}"
      end

    cwes = group |> Enum.flat_map(& &1.cwes) |> Enum.uniq()

    %{
      "id" => f.advisory_id,
      "name" => rule_name(f.advisory_id),
      "shortDescription" => %{"text" => "#{title}: #{summary}"},
      "fullDescription" => %{"text" => full_description(f, packages, summary)},
      "helpUri" => Formatter.help_uri(f),
      "help" => %{"text" => help_text(group, f), "markdown" => help_text(group, f)},
      "defaultConfiguration" => %{"level" => group_level(group)},
      "properties" => %{
        "security-severity" => group_security_severity(group),
        "tags" => Enum.uniq(["security", "vulnerability", "dependency" | cwes]),
        "precision" => group_precision(group)
      }
    }
  end

  defp rule_name(id) do
    id |> String.split(~r/[^A-Za-z0-9]+/, trim: true) |> Enum.map_join(&String.capitalize/1)
  end

  defp full_description(%Finding{} = f, [pkg], summary) do
    aliases = if f.aliases == [], do: "", else: " Aliases: #{Enum.join(f.aliases, ", ")}."
    "#{summary} (package #{pkg}).#{aliases}"
  end

  defp full_description(%Finding{} = f, packages, summary) do
    aliases = if f.aliases == [], do: "", else: " Aliases: #{Enum.join(f.aliases, ", ")}."
    "#{summary} (packages #{Enum.join(packages, ", ")}).#{aliases}"
  end

  defp help_text([%Finding{} = f], _primary) do
    case Formatter.fix_text(f) do
      nil -> "No fixed release is known yet. See #{Formatter.help_uri(f)}"
      fix -> "Upgrade #{f.package} to #{fix}. See #{Formatter.help_uri(f)}"
    end
  end

  defp help_text(group, primary) do
    upgrades =
      group
      |> Enum.uniq_by(& &1.package)
      |> Enum.flat_map(fn f ->
        case Formatter.fix_text(f) do
          nil -> []
          fix -> ["#{f.package} to #{fix}"]
        end
      end)

    case upgrades do
      [] -> "No fixed release is known yet. See #{Formatter.help_uri(primary)}"
      list -> "Upgrade #{Enum.join(list, ", ")}. See #{Formatter.help_uri(primary)}"
    end
  end

  defp group_precision([%Finding{} = f]), do: precision(f)

  defp group_precision(group) do
    cond do
      Enum.all?(group, &(&1.verdict == :reachable)) -> "very-high"
      Enum.any?(group, &(&1.verdict in [:reachable, :retired])) -> "high"
      true -> "medium"
    end
  end

  defp group_level([%Finding{} = f]), do: level(f)

  defp group_level(group) do
    rank = %{"error" => 3, "warning" => 2, "note" => 1, "none" => 0}
    group |> Enum.map(&level/1) |> Enum.max_by(&Map.fetch!(rank, &1))
  end

  defp group_security_severity([%Finding{} = f]), do: Formatter.security_severity(f)

  defp group_security_severity(group) do
    group
    |> Enum.map(&Formatter.security_severity/1)
    |> Enum.max_by(fn s ->
      case Float.parse(s) do
        {val, _} -> val
        :error -> -1.0
      end
    end)
  end

  defp precision(%Finding{verdict: :reachable}), do: "very-high"
  defp precision(%Finding{verdict: :retired}), do: "high"
  defp precision(_finding), do: "medium"

  @doc "SARIF level of a finding."
  @spec level(Finding.t()) :: String.t()
  def level(%Finding{verdict: :unreachable}), do: "none"

  def level(%Finding{severity: severity}) do
    case severity do
      :medium -> "warning"
      low when low in [:low, :none] -> "note"
      _ -> "error"
    end
  end

  defp result(%Finding{} = f, index, report) do
    {file, line} = Formatter.primary_location(f, report.workspace)

    %{
      "ruleId" => f.advisory_id,
      "ruleIndex" => Map.fetch!(index, f.advisory_id),
      "level" => level(f),
      "kind" => if(f.verdict == :unreachable, do: "pass", else: "fail"),
      "message" => %{"text" => message(f)},
      "locations" => [location(file, line, nil)],
      "partialFingerprints" => %{"primaryLocationLineHash" => f.fingerprint},
      "properties" =>
        %{
          "verdict" => Atom.to_string(f.verdict),
          "reason" => Atom.to_string(f.reason),
          "package" => f.package,
          "installedVersion" => f.installed_version,
          "fixedVersions" => f.fixed_versions,
          "targetMfa" => Formatter.mfa(f.target_mfa)
        }
        |> put_context(f.context_routines)
    }
    |> put_related_locations(f, report.workspace)
    |> put_code_flows(f, report.workspace)
  end

  defp put_related_locations(result, finding, workspace) do
    locations = Formatter.project_locations(finding.trace, workspace)

    related =
      locations
      |> Enum.drop(1)
      |> Enum.with_index(1)
      |> Enum.map(fn {hop, id} ->
        hop.file |> location(hop.line, Formatter.hop(hop)) |> Map.put("id", id)
      end)

    if related == [], do: result, else: Map.put(result, "relatedLocations", related)
  end

  defp put_context(properties, []), do: properties

  defp put_context(properties, routines),
    do: Map.put(properties, "contextRoutines", Enum.map(routines, &Formatter.mfa/1))

  defp message(%Finding{} = f) do
    verdict =
      case f.verdict do
        :reachable -> "is reachable"
        :potentially_reachable -> "may be reachable"
        :retired -> "affects a retired release"
        :unreachable -> "is unreachable"
      end

    target = if f.target_mfa, do: " through #{Formatter.mfa(f.target_mfa)}", else: ""
    fix = Formatter.fix_text(f)
    fix = if fix, do: " Fix: upgrade to #{fix}.", else: ""
    detail = if f.reason_detail == "", do: "", else: " #{f.reason_detail}."

    "#{Formatter.display_id(f)} in #{f.package} #{f.installed_version} #{verdict}#{target} " <>
      "(#{Formatter.reason_label(f.reason)}).#{detail}#{fix}"
  end

  defp put_code_flows(result, %Finding{trace: []}, _workspace), do: result

  defp put_code_flows(result, %Finding{trace: hops}, workspace) do
    prefix = Formatter.repo_prefix(workspace)

    locations =
      hops
      |> Formatter.numbered()
      |> Enum.with_index(1)
      |> Enum.map(fn {{%TraceHop{} = hop, step}, order} ->
        text = "#{step}. #{Formatter.hop(hop)}"
        file = Formatter.prefix_path(hop.file, prefix)

        %{
          "executionOrder" => order,
          "kinds" => [kind(hop.kind)],
          "location" => location(file, hop.line, text)
        }
      end)

    Map.put(result, "codeFlows", [
      %{
        "message" => %{"text" => "Call chain from #{Formatter.hop(hd(hops))}"},
        "threadFlows" => [%{"locations" => locations}]
      }
    ])
  end

  defp kind(:entrypoint), do: "enter"
  defp kind(nil), do: "call"
  defp kind(kind), do: Atom.to_string(kind)

  defp location(file, _line, text) when file in [nil, ""] do
    if is_binary(text) and text != "", do: %{"message" => %{"text" => text}}, else: %{}
  end

  defp location(file, line, text) do
    start_line = if is_integer(line) and line >= 1, do: line, else: 1

    physical = %{
      "artifactLocation" => artifact(file),
      "region" => %{"startLine" => start_line}
    }

    if text,
      do: %{"physicalLocation" => physical, "message" => %{"text" => text}},
      else: %{"physicalLocation" => physical}
  end

  defp artifact(file) do
    if Path.type(file) == :absolute,
      do: %{"uri" => "file://" <> encode_path(file, true)},
      else: %{"uri" => encode_path(file, false), "uriBaseId" => "%SRCROOT%"}
  end

  defp encode_path(file, absolute?) do
    URI.encode(file, &(&1 == ?/ or URI.char_unreserved?(&1) or (absolute? and &1 == ?:)))
  end
end
