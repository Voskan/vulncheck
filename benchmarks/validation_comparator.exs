defmodule VulnCheck.Bench.ValidationComparator do
  @moduledoc false

  # Scores the reports of the real-world validation projects.
  #
  # Two independent checks run on every project:
  #
  #   * the recorded verdicts (`real_world_expected.exs`) pin VulnCheck's output,
  #     so any verdict change is reviewed
  #   * the ground-truth labels (`real_world_ground_truth.exs`) state whether the
  #     vulnerable routine runs. Precision and recall are computed against them,
  #     and an `unreachable` verdict for a called routine fails the run
  #
  # A project also fails when its noise reduction differs from its floor.

  @type expected_verdict :: {String.t(), String.t(), atom(), atom()}
  @type expected_package :: {String.t(), String.t(), String.t()}
  @type label :: :called | :not_called

  @doc "Expands ground-truth entries into `%{{project, advisory_id} => {label, evidence}}`."
  @spec labels([{[String.t()], String.t(), label(), String.t()}]) :: map()
  def labels(entries) do
    Enum.reduce(entries, %{}, fn {projects, id, label, evidence}, acc
                                 when label in [:called, :not_called] ->
      Enum.reduce(projects, acc, fn project, acc ->
        key = {project, id}

        if Map.has_key?(acc, key),
          do: raise(ArgumentError, "duplicate label for #{project} #{id}"),
          else: Map.put(acc, key, {label, evidence})
      end)
    end)
  end

  @spec compare(String.t(), map(), map()) :: map()
  def compare(project, report, expected) do
    findings = Map.get(report, "findings", [])
    project_verdicts = project_verdicts(expected.verdicts, project)
    {matched, mismatches, missing} = match_verdicts(project_verdicts, findings)
    expected_ids = MapSet.new(project_verdicts, &elem(&1, 1))

    unexpected =
      findings
      |> Enum.reject(&MapSet.member?(expected_ids, &1["advisory_id"]))
      |> Enum.map(&%{advisory_id: &1["advisory_id"], verdict: &1["verdict"], reason: &1["reason"]})

    pkg_missing =
      expected.packages
      |> Enum.filter(fn {proj, _pkg, _ver} -> proj == project end)
      |> Enum.reject(fn {_proj, pkg, ver} ->
        Enum.any?(findings, &(&1["package"] == pkg and &1["installed_version"] == ver))
      end)

    score = score(project, findings, expected.labels)
    total = length(findings)
    unreachable = Enum.count(findings, &(&1["verdict"] == "unreachable"))
    noise = percent(unreachable, total)
    floor = Map.get(expected.noise_floors, project)

    floor_error =
      cond do
        is_nil(floor) ->
          "no noise reduction floor is recorded"

        noise < floor ->
          "noise reduction #{noise}% is below the floor of #{floor}%"

        noise > floor ->
          "noise reduction #{noise}% is above the floor of #{floor}%; raise the floor"

        true ->
          nil
      end

    %{
      project: project,
      status: :ok,
      error: nil,
      total_expected: length(project_verdicts),
      total_actual: total,
      matched: length(matched),
      mismatches: mismatches,
      missing: missing,
      unexpected: unexpected,
      package_missing: pkg_missing,
      unreachable: unreachable,
      noise_reduction_percent: noise,
      noise_floor_percent: floor,
      floor_error: floor_error,
      confusion: score.confusion,
      precision_percent: percent(score.confusion.tp, score.confusion.tp + score.confusion.fp),
      recall_percent: percent(score.confusion.tp, score.confusion.tp + score.confusion.fn),
      false_negatives: score.false_negatives,
      not_called_actionable: score.not_called_actionable,
      unlabeled: score.unlabeled,
      stale_labels: score.stale_labels,
      passed?:
        mismatches == [] and missing == [] and unexpected == [] and pkg_missing == [] and
          score.false_negatives == [] and score.unlabeled == [] and score.stale_labels == [] and
          is_nil(floor_error)
    }
  end

  defp project_verdicts(verdicts, project),
    do: Enum.filter(verdicts, fn {proj, _id, _v, _r} -> proj == project end)

  defp match_verdicts(project_verdicts, findings) do
    actual_by_id = Map.new(findings, fn f -> {f["advisory_id"], f} end)

    {matched, bad, miss} =
      Enum.reduce(project_verdicts, {[], [], []}, fn {_proj, id, exp_v, exp_r}, {ok, bad, miss} ->
        exp_v = Atom.to_string(exp_v)
        exp_r = Atom.to_string(exp_r)

        case Map.get(actual_by_id, id) do
          nil ->
            {ok, bad, [%{advisory_id: id, expected_verdict: exp_v, expected_reason: exp_r} | miss]}

          %{"verdict" => ^exp_v, "reason" => ^exp_r} = f ->
            {[f | ok], bad, miss}

          %{"verdict" => got_v, "reason" => got_r} ->
            mismatch = %{
              advisory_id: id,
              expected_verdict: exp_v,
              expected_reason: exp_r,
              actual_verdict: got_v,
              actual_reason: got_r
            }

            {ok, [mismatch | bad], miss}
        end
      end)

    {Enum.reverse(matched), Enum.reverse(bad), Enum.reverse(miss)}
  end

  defp score(project, findings, labels) do
    empty = %{tp: 0, fp: 0, fn: 0, tn: 0}

    {confusion, false_negatives, not_called, unlabeled} =
      Enum.reduce(findings, {empty, [], [], []}, fn f, {c, fns, ncs, unl} ->
        id = f["advisory_id"]
        actionable = f["verdict"] != "unreachable"
        entry = %{advisory_id: id, verdict: f["verdict"], reason: f["reason"]}

        case {Map.get(labels, {project, id}), actionable} do
          {nil, _} ->
            {c, fns, ncs, [id | unl]}

          {{:called, _}, true} ->
            {Map.update!(c, :tp, &(&1 + 1)), fns, ncs, unl}

          {{:not_called, ev}, true} ->
            {Map.update!(c, :fp, &(&1 + 1)), fns, [Map.put(entry, :evidence, ev) | ncs], unl}

          {{:called, ev}, false} ->
            {Map.update!(c, :fn, &(&1 + 1)), [Map.put(entry, :evidence, ev) | fns], ncs, unl}

          {{:not_called, _}, false} ->
            {Map.update!(c, :tn, &(&1 + 1)), fns, ncs, unl}
        end
      end)

    reported = MapSet.new(findings, & &1["advisory_id"])

    stale =
      for {{^project, id}, _} <- labels, not MapSet.member?(reported, id), do: id

    %{
      confusion: confusion,
      false_negatives: Enum.reverse(false_negatives),
      not_called_actionable: Enum.reverse(not_called),
      unlabeled: Enum.reverse(unlabeled),
      stale_labels: Enum.sort(stale)
    }
  end

  @spec failed_project(String.t(), String.t(), map()) :: map()
  def failed_project(project, error, expected) do
    project_verdicts = project_verdicts(expected.verdicts, project)

    %{
      project: project,
      status: :error,
      error: error,
      total_expected: length(project_verdicts),
      total_actual: 0,
      matched: 0,
      mismatches: [],
      missing:
        Enum.map(project_verdicts, fn {_, id, v, r} ->
          %{
            advisory_id: id,
            expected_verdict: Atom.to_string(v),
            expected_reason: Atom.to_string(r)
          }
        end),
      unexpected: [],
      package_missing: [],
      unreachable: 0,
      noise_reduction_percent: 0.0,
      noise_floor_percent: Map.get(expected.noise_floors, project),
      floor_error: nil,
      confusion: %{tp: 0, fp: 0, fn: 0, tn: 0},
      precision_percent: 0.0,
      recall_percent: 0.0,
      false_negatives: [],
      not_called_actionable: [],
      unlabeled: [],
      stale_labels: [],
      passed?: false
    }
  end

  @spec summarize([map()], map()) :: map()
  def summarize(results, expected) do
    seen = MapSet.new(results, & &1.project)

    missing_projects =
      expected.verdicts
      |> Enum.map(&elem(&1, 0))
      |> Enum.uniq()
      |> Enum.reject(&MapSet.member?(seen, &1))
      |> Enum.map(&failed_project(&1, "project was not executed", expected))

    all = results ++ missing_projects
    sum = fn key -> all |> Enum.map(&Map.fetch!(&1.confusion, key)) |> Enum.sum() end
    confusion = %{tp: sum.(:tp), fp: sum.(:fp), fn: sum.(:fn), tn: sum.(:tn)}
    total = all |> Enum.map(& &1.total_actual) |> Enum.sum()
    unreachable = all |> Enum.map(& &1.unreachable) |> Enum.sum()

    %{
      projects: all,
      total_expected: all |> Enum.map(& &1.total_expected) |> Enum.sum(),
      total_actual: total,
      matched: all |> Enum.map(& &1.matched) |> Enum.sum(),
      unreachable: unreachable,
      confusion: confusion,
      precision_percent: percent(confusion.tp, confusion.tp + confusion.fp),
      recall_percent: percent(confusion.tp, confusion.tp + confusion.fn),
      noise_reduction_percent: percent(unreachable, total),
      passed?: Enum.all?(all, & &1.passed?)
    }
  end

  @spec failures(map()) :: [String.t()]
  def failures(result) do
    Enum.concat([
      if(result.error, do: ["error: #{result.error}"], else: []),
      Enum.map(result.mismatches, fn m ->
        "#{m.advisory_id}: expected #{m.expected_verdict}/#{m.expected_reason}, " <>
          "got #{m.actual_verdict}/#{m.actual_reason}"
      end),
      Enum.map(result.missing, &"#{&1.advisory_id}: expected finding is missing"),
      Enum.map(result.unexpected, &"#{&1.advisory_id}: unexpected #{&1.verdict}/#{&1.reason}"),
      Enum.map(result.package_missing, fn {_, pkg, ver} -> "#{pkg} #{ver}: no finding" end),
      Enum.map(result.false_negatives, fn f ->
        "#{f.advisory_id}: #{f.verdict}/#{f.reason}, but the routine is called (#{f.evidence})"
      end),
      Enum.map(result.unlabeled, &"#{&1}: no ground-truth label"),
      Enum.map(result.stale_labels, &"#{&1}: labeled but not reported"),
      if(result.floor_error, do: [result.floor_error], else: [])
    ])
  end

  @spec to_markdown(map()) :: String.t()
  def to_markdown(summary) do
    rows =
      Enum.map_join(summary.projects, "\n", fn r ->
        c = r.confusion

        "| `#{r.project}` | #{r.matched}/#{r.total_expected} | #{c.tp} | #{c.fp} | #{c.fn} | #{c.tn} | " <>
          "#{r.precision_percent}% | #{r.recall_percent}% | " <>
          "#{r.noise_reduction_percent}% (#{r.unreachable}/#{r.total_actual}) | " <>
          "#{r.noise_floor_percent}% | #{status(r.passed?)} |"
      end)

    c = summary.confusion

    not_called =
      for r <- summary.projects, f <- r.not_called_actionable do
        "| `#{r.project}` | #{f.advisory_id} | `#{f.verdict}` | `#{f.reason}` |"
      end

    """
    | Project | Verdicts | TP | FP | FN | TN | Precision | Recall | Noise reduction | Floor | Status |
    | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
    #{rows}
    | **Total** | **#{summary.matched}/#{summary.total_expected}** | **#{c.tp}** | **#{c.fp}** | **#{c.fn}** | **#{c.tn}** | **#{summary.precision_percent}%** | **#{summary.recall_percent}%** | **#{summary.noise_reduction_percent}% (#{summary.unreachable}/#{summary.total_actual})** | - | **#{status(summary.passed?)}** |

    | Project | Advisory | Verdict | Reason |
    | :--- | :--- | :--- | :--- |
    #{Enum.join(not_called, "\n")}
    """
  end

  defp status(true), do: "PASS"
  defp status(false), do: "FAIL"

  defp percent(_num, 0), do: 100.0
  defp percent(num, den), do: Float.round(num * 100.0 / den, 1)
end
