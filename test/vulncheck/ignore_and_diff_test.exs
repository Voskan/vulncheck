defmodule VulnCheck.IgnoreAndDiffTest do
  use ExUnit.Case, async: true

  alias VulnCheck.{Config, Diff, Ignore}
  alias VulnCheck.Test.Tmp
  alias VulnCheck.Types.{Finding, MFA, ScanReport, TraceHop, Workspace}

  @today ~D[2026-11-18]

  defp finding(id, package, verdict, extra \\ []) do
    f =
      struct(
        %Finding{
          advisory_id: id,
          package: package,
          installed_version: "1.0.0",
          severity: :high,
          verdict: verdict,
          reason: :call_chain_proven
        },
        extra
      )

    %{f | fingerprint: Finding.fingerprint(id, package, verdict, f.target_mfa)}
  end

  defp run_step(step, findings, config, workspace \\ nil) do
    step.(findings, %{config: config, workspace: workspace})
  end

  defp git!(dir, args) do
    {output, 0} =
      System.cmd("git", ["-c", "user.name=Test", "-c", "user.email=test@example.invalid" | args],
        cd: dir,
        stderr_to_stdout: true
      )

    output
  end

  describe "parsing" do
    test "accepts maps and keyword lists without evaluating code" do
      source = """
      [
        %{id: "CVE-2026-54892", package: "plug", reason: "WAF rule", expires: "2027-01-31"},
        [id: "GHSA-xxxx", reason: "not exposed"]
      ]
      """

      assert {:ok, [plug, ghsa], []} = Ignore.parse(source, %Config{})
      assert plug.expires == ~D[2027-01-31]
      assert plug.package == "plug"
      assert ghsa.package == nil

      assert {:error, message} = Ignore.parse("[%{id: System.halt()}]", %Config{})
      assert message =~ "not a literal"
      assert {:error, _} = Ignore.parse("%{id: 1}", %Config{})
      assert {:error, _} = Ignore.parse("[", %Config{})
    end

    test "rejects entries violating the governance rules" do
      source = """
      [
        %{id: "A", reason: ""},
        %{id: "B", reason: "ok"},
        %{id: "C", reason: "ok", expires: "tomorrow"},
        %{reason: "no id"},
        %{id: "D", reason: "ok", package: :plug},
        %{id: "E", reason: "ok", expires: "2027-01-01"}
      ]
      """

      assert {:ok, rules, warnings} = Ignore.parse(source, %Config{require_ignore_expiry: true})
      assert Enum.map(rules, & &1.id) == ["E"]
      assert length(warnings) == 5
      assert Enum.any?(warnings, &(&1 =~ "(A) rejected: a reason is required"))
      assert Enum.any?(warnings, &(&1 =~ "(B) rejected: an expires date is required"))
      assert Enum.any?(warnings, &(&1 =~ "invalid expires date"))
      assert Enum.any?(warnings, &(&1 =~ "an id is required"))

      assert {:ok, [_, _ | _], _} = Ignore.parse(source, %Config{require_ignore_reason: false})
    end
  end

  describe "suppressions" do
    setup do
      dir = Tmp.mkdir!("ignore-project")
      %{dir: dir, config: %Config{project_dir: dir}}
    end

    test "a valid suppression hides the finding and passes the gate", %{dir: dir, config: config} do
      Tmp.write!(dir, ".vulncheck.ignore", """
      [%{id: "CVE-2026-54892", package: "plug", reason: "WAF blocks it", expires: "2027-01-31"}]
      """)

      findings = [finding("EEF-CVE-2026-54892", "plug", :reachable, aliases: ["CVE-2026-54892"])]
      {[f], violations, []} = run_step(Ignore.step(today: @today), findings, config)

      assert f.suppressed
      refute f.suppression_expired
      assert f.suppression_reason == "WAF blocks it"
      assert f.suppression_expires == "2027-01-31"
      assert violations == []

      report = %ScanReport{findings: [f], policy_violations: violations}
      refute VulnCheck.should_fail?(report, config)
    end

    test "an expired suppression keeps the finding active and fails", %{dir: dir, config: config} do
      Tmp.write!(dir, ".vulncheck.ignore", """
      [%{id: "CVE-2026-1", reason: "temporary", expires: "2025-01-01"}, %{id: "UNUSED", reason: "x"}]
      """)

      findings = [finding("CVE-2026-1", "ash", :unreachable)]
      {[f], violations, warnings} = run_step(Ignore.step(today: @today), findings, config)

      refute f.suppressed
      assert f.suppression_expired
      assert violations == ["suppression of CVE-2026-1 (ash) expired on 2025-01-01"]
      assert warnings == ["suppression of UNUSED matches no finding"]

      assert VulnCheck.should_fail?(
               %ScanReport{findings: [f], policy_violations: violations},
               config
             )
    end

    test "package-scoped rules only match that package", %{config: config} do
      rules = [%Ignore.Rule{id: "X", package: "plug", reason: "r"}]
      {[f], [], [warning]} = Ignore.apply_rules([finding("X", "ash", :reachable)], rules, @today)
      refute f.suppressed
      assert warning =~ "X (plug) matches no finding"
      assert {[], [], []} = run_step(Ignore.step(today: @today), [], config)
    end

    test "unreadable ignore files are policy violations", %{dir: dir, config: config} do
      Tmp.write!(dir, ".vulncheck.ignore", "[%{id: Foo.bar()}]")
      {[], [violation], []} = run_step(Ignore.step(today: @today), [], config)
      assert violation =~ "cannot read suppressions"
    end
  end

  describe "git guardrails" do
    setup do
      dir = Tmp.mkdir!("ignore-git")
      git!(dir, ["init", "-q", "-b", "main"])

      Tmp.write!(dir, "mix.lock", """
      %{
        "plug": {:hex, :plug, "1.16.2", "#{String.duplicate("a", 64)}", [:mix], [], "hexpm", "#{String.duplicate("b", 64)}"},
      }
      """)

      Tmp.write!(dir, ".vulncheck.ignore", """
      [%{id: "CVE-OLD", reason: "accepted", expires: "2027-01-01"}]
      """)

      Tmp.write!(dir, "lib/shop.ex", "defmodule Shop do\nend\n")
      git!(dir, ["add", "."])
      git!(dir, ["commit", "-q", "-m", "base"])
      %{dir: dir}
    end

    test "new and extended suppressions are rejected", %{dir: dir} do
      Tmp.write!(dir, ".vulncheck.ignore", """
      [
        %{id: "CVE-OLD", reason: "accepted", expires: "2028-01-01"},
        %{id: "CVE-NEW", reason: "please", expires: "2027-01-01"}
      ]
      """)

      git!(dir, ["commit", "-q", "-am", "add suppression"])
      config = %Config{project_dir: dir, forbid_new_suppressions: true}

      {[], violations, _} = run_step(Ignore.step(today: @today), [], config)

      assert violations == [
               "suppression of CVE-OLD extended since HEAD~1",
               "new suppression of CVE-NEW added since HEAD~1"
             ]

      # explicit base ref, and an unchanged file
      config = %{config | diff: "HEAD"}
      assert {[], [], _} = run_step(Ignore.step(today: @today), [], config)

      bad = %{config | diff: "no-such-ref"}
      {[], [violation], _} = run_step(Ignore.step(today: @today), [], bad)
      assert violation =~ "cannot verify suppressions"
    end

    test "--diff keeps upgraded packages and findings through changed files", %{dir: dir} do
      Tmp.write!(dir, "mix.lock", """
      %{
        "plug": {:hex, :plug, "1.16.2", "#{String.duplicate("a", 64)}", [:mix], [], "hexpm", "#{String.duplicate("b", 64)}"},
        "ash": {:hex, :ash, "3.34.2", "#{String.duplicate("a", 64)}", [:mix], [], "hexpm", "#{String.duplicate("b", 64)}"},
      }
      """)

      Tmp.write!(dir, "lib/web.ex", "defmodule Web do\nend\n")

      {:ok, packages} = VulnCheck.Workspace.MixLock.parse_file(Path.join(dir, "mix.lock"))

      ws = %Workspace{
        root_dir: dir,
        project_name: "shop",
        project_type: :mix,
        env: :prod,
        otp_release: "27",
        lockfile: Path.join(dir, "mix.lock"),
        packages: packages
      }

      hop = fn file -> %TraceHop{mfa: MFA.new("Elixir.Web", "x", 0), file: file, line: 1} end

      findings = [
        finding("A-1", "ash", :reachable),
        finding("P-1", "plug", :reachable, trace: [hop.("lib/web.ex")]),
        finding("P-2", "plug", :reachable, trace: [hop.("lib/shop.ex")]),
        finding("P-3", "plug", :unreachable)
      ]

      config = %Config{project_dir: dir}
      {kept, [], [note]} = run_step(Diff.diff_step("HEAD"), findings, config, ws)

      assert Enum.map(kept, & &1.advisory_id) == ["A-1", "P-1"]
      assert note =~ "2 finding(s) unrelated to changes since HEAD hidden"

      {all, [], [warning]} = run_step(Diff.diff_step("missing-ref"), findings, config, ws)
      assert length(all) == 4
      assert warning =~ "diff against missing-ref ignored"
    end
  end

  describe "baselines" do
    test "hide known findings and report escalations" do
      dir = Tmp.mkdir!("baseline")
      path = Path.join(dir, "baseline.json")

      old = [
        finding("CVE-1", "ash", :unreachable),
        finding("CVE-2", "plug", :potentially_reachable)
      ]

      :ok = Diff.write_baseline(%ScanReport{findings: old, tool_version: "1.0.0"}, path)

      current = [
        finding("CVE-1", "ash", :reachable),
        finding("CVE-2", "plug", :potentially_reachable),
        finding("CVE-3", "jason", :reachable)
      ]

      {kept, [], warnings} = run_step(Diff.baseline_step(path), current, %Config{project_dir: dir})

      assert Enum.map(kept, & &1.advisory_id) == ["CVE-1", "CVE-3"]

      assert warnings == [
               "CVE-1 (ash) escalated from unreachable to reachable",
               "1 finding(s) already present in the baseline"
             ]

      File.write!(path, "{}")

      {^current, [], [warning]} =
        run_step(Diff.baseline_step(path), current, %Config{project_dir: dir})

      assert warning =~ "not a vulncheck JSON report"

      assert {:error, message} = Diff.read_baseline(Path.join(dir, "missing.json"))
      assert message =~ "no such file"
    end
  end
end
