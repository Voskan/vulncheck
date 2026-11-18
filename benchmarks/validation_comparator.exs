defmodule VulnCheck.Bench.ValidationComparator do
  @moduledoc false

  @type expected_verdict :: {String.t(), String.t(), atom(), atom()}
  @type expected_package :: {String.t(), String.t(), String.t()}

  @spec compare(String.t(), map(), [expected_verdict()], [expected_package()]) :: map()
  def compare(project, report, expected_verdicts, expected_packages \\ []) do
    findings = Map.get(report, "findings", [])
    actual_by_id = Map.new(findings, fn f -> {f["advisory_id"], f} end)

    project_verdicts =
      Enum.filter(expected_verdicts, fn {proj, _id, _v, _r} -> proj == project end)

    {matched, mismatches, missing} =
      Enum.reduce(project_verdicts, {[], [], []}, fn {_proj, id, exp_v, exp_r}, {ok, bad, miss} ->
        exp_v_str = Atom.to_string(exp_v)
        exp_r_str = Atom.to_string(exp_r)

        case Map.get(actual_by_id, id) do
          nil ->
            {ok, bad,
             [%{advisory_id: id, expected_verdict: exp_v_str, expected_reason: exp_r_str} | miss]}

          %{"verdict" => ^exp_v_str, "reason" => ^exp_r_str} = f ->
            {[f | ok], bad, miss}

          %{"verdict" => got_v, "reason" => got_r} ->
            mismatch = %{
              advisory_id: id,
              expected_verdict: exp_v_str,
              expected_reason: exp_r_str,
              actual_verdict: got_v,
              actual_reason: got_r
            }

            {ok, [mismatch | bad], miss}
        end
      end)

    expected_ids = MapSet.new(project_verdicts, &elem(&1, 1))

    unexpected =
      findings
      |> Enum.reject(&MapSet.member?(expected_ids, &1["advisory_id"]))
      |> Enum.map(&%{advisory_id: &1["advisory_id"], verdict: &1["verdict"], reason: &1["reason"]})

    total_actual = length(findings)
    unreachable_count = Enum.count(findings, &(&1["verdict"] == "unreachable"))
    actionable_expected = Enum.count(project_verdicts, fn {_, _, v, _} -> v != :unreachable end)

    actionable_matched =
      Enum.count(matched, fn f -> f["verdict"] != "unreachable" end)

    actionable_actual =
      Enum.count(findings, fn f -> f["verdict"] != "unreachable" end)

    project_pkgs =
      Enum.filter(expected_packages, fn {proj, _pkg, _ver} -> proj == project end)

    pkg_missing =
      Enum.reject(project_pkgs, fn {_proj, pkg, ver} ->
        Enum.any?(findings, &(&1["package"] == pkg and &1["installed_version"] == ver))
      end)

    %{
      project: project,
      total_expected: length(project_verdicts),
      total_actual: total_actual,
      matched: length(matched),
      mismatches: Enum.reverse(mismatches),
      missing: Enum.reverse(missing),
      unexpected: unexpected,
      unreachable: unreachable_count,
      noise_reduction_percent: percent(unreachable_count, total_actual),
      precision_percent: percent(actionable_matched, actionable_actual),
      recall_percent: percent(actionable_matched, actionable_expected),
      denominators: %{
        actionable_matched: actionable_matched,
        actionable_actual: actionable_actual,
        actionable_expected: actionable_expected,
        unreachable: unreachable_count,
        total_actual: total_actual
      },
      package_missing: pkg_missing,
      passed?: mismatches == [] and missing == []
    }
  end

  @spec summarize([map()]) :: map()
  def summarize(results) do
    tot_expected = Enum.sum(Enum.map(results, & &1.total_expected))
    tot_actual = Enum.sum(Enum.map(results, & &1.total_actual))
    tot_matched = Enum.sum(Enum.map(results, & &1.matched))
    tot_unreach = Enum.sum(Enum.map(results, & &1.unreachable))

    act_matched = Enum.sum(Enum.map(results, & &1.denominators.actionable_matched))
    act_actual = Enum.sum(Enum.map(results, & &1.denominators.actionable_actual))
    act_expected = Enum.sum(Enum.map(results, & &1.denominators.actionable_expected))

    %{
      projects: results,
      total_expected: tot_expected,
      total_actual: tot_actual,
      matched: tot_matched,
      precision_percent: percent(act_matched, act_actual),
      recall_percent: percent(act_matched, act_expected),
      noise_reduction_percent: percent(tot_unreach, tot_actual),
      passed?: Enum.all?(results, & &1.passed?)
    }
  end

  @spec to_markdown(map()) :: String.t()
  def to_markdown(summary) do
    rows =
      Enum.map_join(summary.projects, "\n", fn r ->
        "| `#{r.project}` | #{r.matched}/#{r.total_expected} | #{r.precision_percent}% | #{r.recall_percent}% | #{r.noise_reduction_percent}% (#{r.unreachable}/#{r.total_actual}) | #{if(r.passed?, do: "PASS", else: "FAIL")} |"
      end)

    """
    | Project | Matched | Precision | Recall | Noise Reduction | Status |
    | :--- | ---: | ---: | ---: | ---: | :---: |
    #{rows}
    | **Total** | **#{summary.matched}/#{summary.total_expected}** | **#{summary.precision_percent}%** | **#{summary.recall_percent}%** | **#{summary.noise_reduction_percent}%** | **#{if(summary.passed?, do: "PASS", else: "FAIL")}** |
    """
  end

  defp percent(_num, 0), do: 100.0
  defp percent(num, den), do: Float.round(num * 100.0 / den, 1)
end
