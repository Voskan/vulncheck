defmodule VulnCheck.Report.SARIF do
  @moduledoc """
  SARIF 2.1.0 report (`--format sarif`) for GitHub Code Scanning and other
  static analysis dashboards.

  Every advisory becomes a rule whose `security-severity` carries the CVSS
  score. Each result is anchored at the call site in the project's own code
  from which the vulnerable dependency is entered (or at the package entry
  of the lockfile when the chain starts in configuration or supervision),
  and its `codeFlows` replay the whole witness call chain. Unreachable
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
    rules = findings |> Enum.uniq_by(& &1.advisory_id) |> Enum.map(&rule/1)
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
      ]
    }
  end

  defp env(%ScanReport{workspace: %{env: env}}), do: env
  defp env(_report), do: "prod"

  defp rule(%Finding{} = f) do
    title = Formatter.display_id(f)
    summary = if f.summary == "", do: "#{title} in #{f.package}", else: f.summary

    %{
      "id" => f.advisory_id,
      "name" => rule_name(f.advisory_id),
      "shortDescription" => %{"text" => "#{title}: #{summary}"},
      "fullDescription" => %{"text" => full_description(f, summary)},
      "helpUri" => Formatter.help_uri(f),
      "help" => %{"text" => help_text(f), "markdown" => help_text(f)},
      "defaultConfiguration" => %{"level" => level(f)},
      "properties" => %{
        "security-severity" => Formatter.security_severity(f),
        "tags" => Enum.uniq(["security", "vulnerability", "dependency" | f.cwes]),
        "precision" => precision(f)
      }
    }
  end

  defp rule_name(id) do
    id |> String.split(~r/[^A-Za-z0-9]+/, trim: true) |> Enum.map_join(&String.capitalize/1)
  end

  defp full_description(%Finding{} = f, summary) do
    aliases = if f.aliases == [], do: "", else: " Aliases: #{Enum.join(f.aliases, ", ")}."
    "#{summary} (package #{f.package}).#{aliases}"
  end

  defp help_text(%Finding{} = f) do
    case Formatter.fix_text(f) do
      nil -> "No fixed release is known yet. See #{Formatter.help_uri(f)}"
      fix -> "Upgrade #{f.package} to #{fix}. See #{Formatter.help_uri(f)}"
    end
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
      :low -> "note"
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
    |> put_code_flows(f)
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

  defp put_code_flows(result, %Finding{trace: []}), do: result

  defp put_code_flows(result, %Finding{trace: hops}) do
    locations =
      hops
      |> Enum.with_index(1)
      |> Enum.map(fn {%TraceHop{} = hop, step} ->
        text = "#{step}. #{Formatter.mfa(hop.mfa)}"

        %{
          "executionOrder" => step,
          "kinds" => [kind(hop.kind)],
          "location" => location(hop.file, hop.line, text)
        }
      end)

    Map.put(result, "codeFlows", [
      %{
        "message" => %{"text" => "Call chain from #{Formatter.mfa(hd(hops).mfa)}"},
        "threadFlows" => [%{"locations" => locations}]
      }
    ])
  end

  defp kind(:entrypoint), do: "enter"
  defp kind(nil), do: "call"
  defp kind(kind), do: Atom.to_string(kind)

  defp location(nil, _line, text), do: %{"message" => %{"text" => text}}

  defp location(file, line, text) do
    physical = %{
      "artifactLocation" => artifact(file),
      "region" => %{"startLine" => line || 1}
    }

    if text,
      do: %{"physicalLocation" => physical, "message" => %{"text" => text}},
      else: %{"physicalLocation" => physical}
  end

  defp artifact(file) do
    if Path.type(file) == :absolute,
      do: %{"uri" => "file://" <> URI.encode(file)},
      else: %{"uri" => URI.encode(file), "uriBaseId" => "%SRCROOT%"}
  end
end
