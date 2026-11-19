Code.require_file("../../benchmarks/validation_comparator.exs", __DIR__)

defmodule VulnCheck.ValidationComparatorTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Bench.ValidationComparator

  defp finding(id, package, verdict, reason) do
    %{
      "advisory_id" => id,
      "package" => package,
      "installed_version" => if(package == "plug", do: "1.15.2", else: "1.18.1"),
      "verdict" => verdict,
      "reason" => reason
    }
  end

  defp expected(overrides \\ []) do
    base = %{
      verdicts: [
        {"proj_a", "EEF-CVE-2026-54892", :reachable, :call_chain_proven},
        {"proj_a", "EEF-CVE-2026-56813", :potentially_reachable, :active_network_daemon},
        {"proj_a", "GHSA-unused", :unreachable, :adapter_not_configured}
      ],
      packages: [{"proj_a", "plug", "1.15.2"}, {"proj_a", "hackney", "1.18.1"}],
      labels:
        ValidationComparator.labels([
          {["proj_a"], "EEF-CVE-2026-54892", :called, "the router decodes query strings"},
          {["proj_a"], "EEF-CVE-2026-56813", :not_called, "no response cookies"},
          {["proj_a"], "GHSA-unused", :not_called, "hackney is never called"}
        ]),
      noise_floors: %{"proj_a" => 33.3}
    }

    Enum.into(overrides, base)
  end

  @report %{
    "findings" => [
      %{
        "advisory_id" => "EEF-CVE-2026-54892",
        "package" => "plug",
        "installed_version" => "1.15.2",
        "verdict" => "reachable",
        "reason" => "call_chain_proven"
      },
      %{
        "advisory_id" => "EEF-CVE-2026-56813",
        "package" => "plug",
        "installed_version" => "1.15.2",
        "verdict" => "potentially_reachable",
        "reason" => "active_network_daemon"
      },
      %{
        "advisory_id" => "GHSA-unused",
        "package" => "hackney",
        "installed_version" => "1.18.1",
        "verdict" => "unreachable",
        "reason" => "adapter_not_configured"
      }
    ]
  }

  test "scores verdicts against the ground-truth labels" do
    ok = ValidationComparator.compare("proj_a", @report, expected())
    assert ok.passed?
    assert ok.confusion == %{tp: 1, fp: 1, fn: 0, tn: 1}
    assert ok.precision_percent == 50.0
    assert ok.recall_percent == 100.0
    assert ok.noise_reduction_percent == 33.3

    assert [%{advisory_id: "EEF-CVE-2026-56813", verdict: "potentially_reachable"}] =
             ok.not_called_actionable

    summary = ValidationComparator.summarize([ok], expected())
    assert summary.passed?
    assert summary == ValidationComparator.summarize([ok], expected())

    markdown = ValidationComparator.to_markdown(summary)

    assert markdown =~
             "| `proj_a` | 3/3 | 1 | 1 | 0 | 1 | 50.0% | 100.0% | 33.3% (1/3) | 33.3% | PASS |"

    assert markdown =~
             "| `proj_a` | EEF-CVE-2026-56813 | `potentially_reachable` | `active_network_daemon` |"
  end

  test "an unreachable verdict for a called routine fails the run" do
    labels =
      ValidationComparator.labels([
        {["proj_a"], "EEF-CVE-2026-54892", :called, "decoded"},
        {["proj_a"], "EEF-CVE-2026-56813", :not_called, "no cookies"},
        {["proj_a"], "GHSA-unused", :called, "hackney:get/1 is called"}
      ])

    result = ValidationComparator.compare("proj_a", @report, expected(labels: labels))
    refute result.passed?
    assert result.recall_percent == 50.0
    assert [%{advisory_id: "GHSA-unused"}] = result.false_negatives

    assert Enum.any?(
             ValidationComparator.failures(result),
             &(&1 =~ "GHSA-unused: unreachable/adapter_not_configured, but the routine is called")
           )
  end

  test "the noise reduction must equal its floor" do
    below =
      ValidationComparator.compare("proj_a", @report, expected(noise_floors: %{"proj_a" => 50.0}))

    refute below.passed?
    assert below.floor_error == "noise reduction 33.3% is below the floor of 50.0%"

    above =
      ValidationComparator.compare("proj_a", @report, expected(noise_floors: %{"proj_a" => 10.0}))

    refute above.passed?
    assert above.floor_error =~ "above the floor of 10.0%; raise the floor"

    missing = ValidationComparator.compare("proj_a", @report, expected(noise_floors: %{}))
    refute missing.passed?
  end

  test "unlabeled findings, stale labels and verdict changes fail the run" do
    extra =
      Map.update!(
        @report,
        "findings",
        &(&1 ++ [finding("EEF-CVE-2026-X", "plug", "reachable", "call_chain_proven")])
      )

    result =
      ValidationComparator.compare("proj_a", extra, expected(noise_floors: %{"proj_a" => 25.0}))

    refute result.passed?
    assert result.unlabeled == ["EEF-CVE-2026-X"]
    assert [%{advisory_id: "EEF-CVE-2026-X"}] = result.unexpected

    dropped = %{"findings" => Enum.drop(@report["findings"], 1)}

    result =
      ValidationComparator.compare("proj_a", dropped, expected(noise_floors: %{"proj_a" => 50.0}))

    refute result.passed?
    assert result.stale_labels == ["EEF-CVE-2026-54892"]
    assert [%{advisory_id: "EEF-CVE-2026-54892"}] = result.missing

    changed =
      put_in(
        @report,
        ["findings", Access.at(2)],
        finding("GHSA-unused", "hackney", "potentially_reachable", "unresolved_dynamic_dispatch")
      )

    result =
      ValidationComparator.compare("proj_a", changed, expected(noise_floors: %{"proj_a" => 0.0}))

    refute result.passed?

    assert [%{advisory_id: "GHSA-unused", actual_verdict: "potentially_reachable"}] =
             result.mismatches

    summary =
      ValidationComparator.summarize(
        [ValidationComparator.compare("proj_a", @report, expected())],
        expected(
          verdicts: expected().verdicts ++ [{"proj_b", "CVE-1", :reachable, :call_chain_proven}]
        )
      )

    refute summary.passed?

    assert Enum.any?(
             summary.projects,
             &(&1.project == "proj_b" and &1.error == "project was not executed")
           )
  end

  test "a project is labeled once per advisory" do
    assert_raise ArgumentError, ~r/duplicate label for proj_a A/, fn ->
      ValidationComparator.labels([
        {["proj_a"], "A", :called, "x"},
        {["proj_a"], "A", :not_called, "y"}
      ])
    end
  end
end
