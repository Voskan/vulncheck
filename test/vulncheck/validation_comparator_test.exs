Code.require_file("../../benchmarks/validation_comparator.exs", __DIR__)

defmodule VulnCheck.ValidationComparatorTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Bench.ValidationComparator

  test "computes precision, recall, noise reduction and detects mismatches, missing and unexpected findings" do
    expected = [
      {"proj_a", "EEF-CVE-2026-54892", :reachable, :call_chain_proven},
      {"proj_a", "GHSA-unused", :unreachable, :adapter_not_configured}
    ]

    expected_pkgs = [
      {"proj_a", "plug", "1.15.2"},
      {"proj_a", "hackney", "1.18.1"}
    ]

    exact_report = %{
      "findings" => [
        %{
          "advisory_id" => "EEF-CVE-2026-54892",
          "package" => "plug",
          "installed_version" => "1.15.2",
          "verdict" => "reachable",
          "reason" => "call_chain_proven"
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

    ok = ValidationComparator.compare("proj_a", exact_report, expected, expected_pkgs)
    assert ok.passed?
    assert ok.precision_percent == 100.0
    assert ok.recall_percent == 100.0
    assert ok.noise_reduction_percent == 50.0
    assert ok.package_missing == []

    summary1 = ValidationComparator.summarize([ok], expected)
    summary2 = ValidationComparator.summarize([ok], expected)
    assert summary1 == summary2
    assert summary1.passed?

    md1 = ValidationComparator.to_markdown(summary1)
    md2 = ValidationComparator.to_markdown(summary2)
    assert md1 == md2
    assert md1 =~ "| `proj_a` | 2/2 | 100.0% | 100.0% | 50.0% (1/2) | PASS |"

    # Unexpected finding fails the run
    extra_report =
      Map.update!(exact_report, "findings", fn list ->
        list ++
          [
            %{
              "advisory_id" => "EEF-CVE-2026-EXTRA",
              "package" => "plug",
              "installed_version" => "1.15.2",
              "verdict" => "reachable",
              "reason" => "call_chain_proven"
            }
          ]
      end)

    extra = ValidationComparator.compare("proj_a", extra_report, expected, expected_pkgs)
    refute extra.passed?
    assert [%{advisory_id: "EEF-CVE-2026-EXTRA"}] = extra.unexpected

    # Missing expected project fails summarize/2
    missing_proj =
      ValidationComparator.summarize(
        [ok],
        expected ++ [{"proj_b", "CVE-1", :reachable, :call_chain_proven}]
      )

    refute missing_proj.passed?
    assert Enum.any?(missing_proj.projects, &(&1.project == "proj_b" and not &1.passed?))

    # Missed expected actionable finding lowers recall and fails
    missed_report = %{"findings" => Enum.drop(exact_report["findings"], 1)}
    missed = ValidationComparator.compare("proj_a", missed_report, expected, expected_pkgs)
    refute missed.passed?
    assert missed.recall_percent == 0.0
    assert [%{advisory_id: "EEF-CVE-2026-54892"}] = missed.missing

    # Wrong reason is reported as a mismatch
    mismatch_report = %{
      "findings" => [
        %{
          "advisory_id" => "EEF-CVE-2026-54892",
          "package" => "plug",
          "installed_version" => "1.15.2",
          "verdict" => "reachable",
          "reason" => "call_chain_proven"
        },
        %{
          "advisory_id" => "GHSA-unused",
          "package" => "hackney",
          "installed_version" => "1.18.1",
          "verdict" => "potentially_reachable",
          "reason" => "unresolved_dynamic_dispatch"
        }
      ]
    }

    bad = ValidationComparator.compare("proj_a", mismatch_report, expected, expected_pkgs)
    refute bad.passed?
    assert [%{advisory_id: "GHSA-unused", actual_verdict: "potentially_reachable"}] = bad.mismatches
  end
end
