defmodule VulnCheck.Report.JSON do
  @moduledoc """
  Native JSON report (`--format json`, `schema_version` 1.0.0).

  Keys are sorted and the output is pretty-printed with two spaces, so
  rendering the same report always produces the same bytes. The document
  is also accepted as a `--baseline`.
  """

  @behaviour VulnCheck.Report.Formatter

  alias VulnCheck.Report.Formatter
  alias VulnCheck.Diff
  alias VulnCheck.Types.{Finding, ScanReport, Summary, TraceHop, Workspace}

  @schema_version "1.0.0"

  @impl true
  def render(%ScanReport{} = report, _config) do
    report |> document() |> encode() |> Kernel.<>("\n")
  end

  @doc "The report as plain maps, lists and scalars."
  @spec document(ScanReport.t()) :: map()
  def document(%ScanReport{} = report) do
    %{
      "schema_version" => @schema_version,
      "tool" => %{"name" => "vulncheck", "version" => report.tool_version},
      "generated_at" => report.generated_at,
      "duration_ms" => report.duration_ms,
      "target" => target(report.workspace),
      "summary" => summary(report.summary),
      "findings" => Enum.map(report.findings, &finding(&1, report.workspace)),
      "policy_violations" => report.policy_violations,
      "warnings" => report.warnings
    }
    |> put_optional("analysis", Map.get(report.stats, :analysis))
    |> put_optional("feed", Map.get(report.stats, :feed))
  end

  defp target(nil), do: %{}

  defp target(%Workspace{} = ws) do
    %{
      "project_name" => ws.project_name,
      "project_version" => ws.project_version,
      "project_type" => Atom.to_string(ws.project_type),
      "env" => Atom.to_string(ws.env),
      "elixir_version" => ws.elixir_version,
      "otp_release" => ws.otp_release,
      "lockfile" => ws.lockfile && Path.relative_to(ws.lockfile, ws.root_dir),
      "prod_packages_count" => ws |> Workspace.prod_packages() |> length(),
      "non_prod_packages_count" => ws |> Workspace.non_prod_packages() |> length()
    }
  end

  defp summary(%Summary{} = s) do
    %{
      "reachable" => s.reachable,
      "potentially_reachable" => s.potentially_reachable,
      "unreachable" => s.unreachable,
      "retired" => s.retired,
      "suppressed" => s.suppressed,
      "expired_suppressions" => s.expired_suppressions,
      "total" => s.total,
      "noise_reduction_percent" => Summary.noise_reduction(s)
    }
  end

  defp finding(%Finding{} = f, workspace) do
    %{
      "advisory_id" => f.advisory_id,
      "aliases" => f.aliases,
      "package" => f.package,
      "package_scope" => Atom.to_string(f.package_scope),
      "installed_version" => f.installed_version,
      "fixed_versions" => f.fixed_versions,
      "recommended_fix" => f.recommended_fix,
      "summary" => f.summary,
      "severity" => Atom.to_string(f.severity),
      "cvss_score" => f.cvss_score,
      "cwes" => f.cwes,
      "references" => f.references,
      "verdict" => Atom.to_string(f.verdict),
      "reason" => Atom.to_string(f.reason),
      "reason_detail" => f.reason_detail,
      "target_mfa" => Formatter.mfa(f.target_mfa),
      "context_routines" => Enum.map(f.context_routines, &Formatter.mfa/1),
      "trace" => Enum.map(f.trace, &hop/1),
      "fingerprint" => f.fingerprint,
      "suppressed" => f.suppressed,
      "suppression_reason" => f.suppression_reason,
      "suppression_expires" => f.suppression_expires,
      "suppression_expired" => f.suppression_expired
    }
    |> put_optional("cvss_vector", f.cvss_vector)
    |> put_optional("cvss_method", f.cvss_method)
    |> put_optional("cvss_source", f.cvss_source)
    |> put_optional("git_match_status", f.git_match_status && Atom.to_string(f.git_match_status))
    |> put_optional("package_identity", Diff.package_identity(workspace, f.package))
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp hop(%TraceHop{} = hop) do
    base = %{
      "mfa" => Formatter.mfa(hop.mfa),
      "file" => hop.file,
      "line" => hop.line,
      "kind" => hop.kind && Atom.to_string(hop.kind)
    }

    if hop.note, do: Map.put(base, "note", hop.note), else: base
  end

  @doc """
  Encodes a term with sorted object keys and two-space indentation.

      iex> VulnCheck.Report.JSON.encode(%{"b" => [1, %{}], "a" => nil})
      "{\\n  \\"a\\": null,\\n  \\"b\\": [\\n    1,\\n    {}\\n  ]\\n}"
  """
  @spec encode(term(), non_neg_integer()) :: String.t()
  def encode(value, level \\ 0), do: value |> encode_iodata(level) |> IO.iodata_to_binary()

  defp encode_iodata(map, _level) when map == %{}, do: "{}"

  defp encode_iodata(map, level) when is_map(map) do
    pad = indent(level + 1)

    body =
      map
      |> Enum.map(fn {key, value} -> {to_string(key), value} end)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {key, value} ->
        [pad, JSON.encode!(key), ": ", encode_iodata(value, level + 1)]
      end)
      |> Enum.intersperse(",\n")

    ["{\n", body, "\n", indent(level), "}"]
  end

  defp encode_iodata([], _level), do: "[]"

  defp encode_iodata(list, level) when is_list(list) do
    pad = indent(level + 1)

    body =
      list
      |> Enum.map(fn item -> [pad, encode_iodata(item, level + 1)] end)
      |> Enum.intersperse(",\n")

    ["[\n", body, "\n", indent(level), "]"]
  end

  defp encode_iodata(value, _level), do: JSON.encode!(value)

  defp indent(0), do: ""
  defp indent(1), do: "  "
  defp indent(2), do: "    "
  defp indent(3), do: "      "
  defp indent(4), do: "        "
  defp indent(5), do: "          "
  defp indent(6), do: "            "
  defp indent(7), do: "              "
  defp indent(8), do: "                "
  defp indent(n), do: String.duplicate("  ", n)
end
