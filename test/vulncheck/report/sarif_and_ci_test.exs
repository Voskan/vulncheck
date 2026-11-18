defmodule VulnCheck.Report.SarifAndCiTest do
  use ExUnit.Case, async: false

  alias VulnCheck.Config
  alias VulnCheck.Report.{GitHub, GitLab, SARIF}
  alias VulnCheck.Types.{Finding, MFA, Package, ScanReport, Summary, TraceHop, Workspace}

  doctest VulnCheck.Report.GitHub

  defp mfa(module, function, arity), do: %MFA{module: module, function: function, arity: arity}

  defp workspace do
    packages =
      for {name, version, line} <- [
            {"ash", "3.34.2", 3},
            {"plug", "1.16.2", 7},
            {"hackney", "1.20.1", 5}
          ],
          into: %{},
          do:
            {name,
             %Package{name: name, version: version, source: :hex, scope: :prod, lock_line: line}}

    %Workspace{
      root_dir: "/srv/ledger",
      project_name: "ledger_api",
      project_type: :mix,
      env: :prod,
      elixir_version: "1.18.2",
      otp_release: "27",
      lockfile: "/srv/ledger/mix.lock",
      packages: packages
    }
  end

  defp finding(fields) do
    finding =
      struct(
        %Finding{
          advisory_id: "GHSA-0000",
          package: "ash",
          installed_version: "3.34.2",
          severity: :medium,
          verdict: :unreachable,
          reason: :function_not_called
        },
        fields
      )

    %{
      finding
      | fingerprint:
          Finding.fingerprint(
            finding.advisory_id,
            finding.package,
            finding.verdict,
            finding.target_mfa
          )
    }
  end

  defp reachable do
    finding(
      advisory_id: "EEF-CVE-2026-101028",
      aliases: ["CVE-2026-101028"],
      severity: :high,
      cvss_score: 7.5,
      cwes: ["CWE-863"],
      fixed_versions: ["3.34.6"],
      references: ["https://github.com/ash-project/ash/security/advisories/GHSA-xj24"],
      verdict: :reachable,
      reason: :call_chain_proven,
      summary: "Aggregates skip read policies",
      target_mfa: mfa("Elixir.Ash.Actions.Aggregate", "run", 4),
      trace: [
        %TraceHop{
          mfa: mfa("Elixir.Ledger.Application", "start", 2),
          file: "lib/ledger/application.ex",
          line: 9,
          kind: :entrypoint
        },
        %TraceHop{
          mfa: mfa("Elixir.Ledger.Reports", "count", 2),
          file: "lib/ledger/reports.ex",
          line: 112,
          kind: :static_call
        },
        %TraceHop{
          mfa: mfa("Elixir.Ash", "count", 2),
          file: "deps/ash/lib/ash.ex",
          line: 40,
          kind: :static_call
        },
        %TraceHop{
          mfa: mfa("Elixir.Ash.Actions.Aggregate", "run", 4),
          file: "deps/ash/lib/ash/actions/aggregate.ex",
          line: 29,
          kind: :static_call
        }
      ]
    )
  end

  defp findings do
    [
      reachable(),
      finding(
        advisory_id: "GHSA-plug-0001",
        aliases: ["CVE-2026-54892"],
        package: "plug",
        installed_version: "1.16.2",
        fixed_versions: ["1.16.4"],
        verdict: :potentially_reachable,
        reason: :active_network_daemon,
        summary: "Quadratic, nested: decoding 100%",
        reason_detail: "Plug.Parsers enabled"
      ),
      finding(
        advisory_id: "GHSA-hk-1",
        package: "hackney",
        installed_version: "1.20.1",
        severity: :low,
        reason: :adapter_not_configured
      ),
      finding(
        advisory_id: "GHSA-plug-0002",
        package: "plug",
        installed_version: "1.16.2",
        verdict: :reachable,
        reason: :call_chain_proven,
        suppressed: true
      )
    ]
  end

  defp report(findings \\ findings()) do
    %ScanReport{
      workspace: workspace(),
      generated_at: "2026-11-18T10:00:00Z",
      tool_version: "1.0.0",
      findings: findings,
      summary: Summary.from_findings(findings),
      duration_ms: 12
    }
  end

  describe "sarif" do
    test "produces a SARIF 2.1.0 log with indexed rules, locations and code flows" do
      rendered = SARIF.render(report(), %Config{})
      assert rendered == SARIF.render(report(), %Config{})

      log = JSON.decode!(rendered)
      assert log["version"] == "2.1.0"
      assert log["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

      [run] = log["runs"]
      driver = run["tool"]["driver"]
      assert driver["name"] == "VulnCheck"
      assert driver["informationUri"] == "https://github.com/Voskan/vulncheck"
      assert driver["version"] == "1.0.0"

      rules = driver["rules"]
      assert Enum.map(rules, & &1["id"]) == ["EEF-CVE-2026-101028", "GHSA-plug-0001"]

      for result <- run["results"] do
        assert Enum.at(rules, result["ruleIndex"])["id"] == result["ruleId"]
      end

      [ash_rule, plug_rule] = rules
      assert ash_rule["properties"]["security-severity"] == "7.5"

      assert ash_rule["properties"]["tags"] == [
               "security",
               "vulnerability",
               "dependency",
               "CWE-863"
             ]

      assert ash_rule["helpUri"] =~ "github.com/ash-project"
      assert plug_rule["properties"]["security-severity"] == "5.5"
      assert plug_rule["helpUri"] == "https://osv.dev/vulnerability/GHSA-plug-0001"

      [ash, plug] = run["results"]
      assert ash["level"] == "error"
      assert plug["level"] == "warning"
      assert ash["partialFingerprints"]["primaryLocationLineHash"] == reachable().fingerprint

      assert ash["message"]["text"] =~
               "CVE-2026-101028 in ash 3.34.2 is reachable through Ash.Actions.Aggregate.run/4"

      assert [%{"physicalLocation" => primary}] = ash["locations"]

      assert primary["artifactLocation"] == %{
               "uri" => "lib/ledger/reports.ex",
               "uriBaseId" => "%SRCROOT%"
             }

      assert primary["region"] == %{"startLine" => 112}

      assert [%{"physicalLocation" => lock}] = plug["locations"]
      assert lock["artifactLocation"]["uri"] == "mix.lock"
      assert lock["region"] == %{"startLine" => 7}
      refute Map.has_key?(plug, "codeFlows")

      [%{"threadFlows" => [%{"locations" => steps}]}] = ash["codeFlows"]
      assert length(steps) == 4
      assert Enum.map(steps, & &1["executionOrder"]) == [1, 2, 3, 4]
      assert hd(steps)["kinds"] == ["enter"]

      last = List.last(steps)["location"]
      assert last["message"]["text"] == "4. Ash.Actions.Aggregate.run/4"

      assert last["physicalLocation"]["artifactLocation"]["uri"] ==
               "deps/ash/lib/ash/actions/aggregate.ex"

      assert last["physicalLocation"]["region"]["startLine"] == 29
    end

    test "unreachable findings are emitted with level none only on request" do
      default = SARIF.document(report(), %Config{})
      refute Enum.any?(hd(default["runs"])["results"], &(&1["ruleId"] == "GHSA-hk-1"))

      shown = SARIF.document(report(), %Config{show_unreachable: true})
      unreachable = Enum.find(hd(shown["runs"])["results"], &(&1["ruleId"] == "GHSA-hk-1"))
      assert unreachable["level"] == "none"
      assert unreachable["kind"] == "pass"
      assert hd(unreachable["locations"])["physicalLocation"]["region"]["startLine"] == 5
    end

    test "severity bands fill in missing CVSS scores and levels" do
      cases = [
        {:critical, "9.5", "error"},
        {:high, "8.0", "error"},
        {:low, "3.0", "note"},
        {:unknown, "9.5", "error"}
      ]

      for {severity, score, level} <- cases do
        f = finding(severity: severity, verdict: :potentially_reachable)
        assert VulnCheck.Report.Formatter.security_severity(f) == score
        assert SARIF.level(f) == level
      end
    end
  end

  describe "github" do
    setup do
      dir = Path.join(System.tmp_dir!(), "vulncheck-gh-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      previous = System.get_env("GITHUB_STEP_SUMMARY")

      on_exit(fn ->
        if previous,
          do: System.put_env("GITHUB_STEP_SUMMARY", previous),
          else: System.delete_env("GITHUB_STEP_SUMMARY")

        File.rm_rf!(dir)
      end)

      {:ok, dir: dir}
    end

    test "prints annotations and appends the job summary", %{dir: dir} do
      summary = Path.join(dir, "summary.md")
      File.write!(summary, "# Earlier step\n")
      System.put_env("GITHUB_STEP_SUMMARY", summary)

      output =
        GitHub.render(
          %{report() | policy_violations: ["new suppression of X added since main"]},
          %Config{}
        )

      lines = String.split(output, "\n", trim: true)

      assert [error, warning, violation, notice] = lines

      assert error =~
               ~r/^::error file=lib\/ledger\/reports\.ex,line=112,title=CVE-2026-101028 \(HIGH%2C CVSS 7\.5\) in ash 3\.34\.2::/

      assert error =~ "REACHABLE: call chain proven%0ASummary: Aggregates skip read policies"
      assert error =~ "%0ATrace:%0A  1. Ledger.Application.start/2 (lib/ledger/application.ex:9)"
      refute error =~ "\n"

      assert warning =~
               ~r/^::warning file=mix\.lock,line=7,title=CVE-2026-54892 \(MEDIUM\) in plug 1\.16\.2::/

      assert warning =~ "Summary: Quadratic, nested: decoding 100%25"

      assert violation ==
               "::error title=VulnCheck policy violation::new suppression of X added since main"

      assert notice =~
               "::notice title=VulnCheck::1 reachable, 1 potentially reachable, 1 unreachable, 0 retired"

      written = File.read!(summary)
      assert String.starts_with?(written, "# Earlier step\n## VulnCheck report")
      assert written =~ "| Reachable | 1 |"
    end

    test "leaves the job summary alone when the variable is unset" do
      System.delete_env("GITHUB_STEP_SUMMARY")
      assert GitHub.write_step_summary(report(), %Config{}) == :ok
    end
  end

  describe "gitlab" do
    test "emits a Code Quality issue array" do
      issues = report() |> GitLab.render(%Config{}) |> JSON.decode!()

      assert is_list(issues) and length(issues) == 2

      for issue <- issues do
        assert %{
                 "description" => description,
                 "check_name" => check,
                 "fingerprint" => fingerprint,
                 "severity" => severity,
                 "location" => %{"path" => path, "lines" => %{"begin" => line}}
               } = issue

        assert is_binary(description) and is_binary(check) and is_binary(path)
        assert String.length(fingerprint) == 64
        assert severity in ~w(info minor major critical blocker)
        assert is_integer(line) and line > 0
      end

      [ash, plug] = issues
      assert ash["severity"] == "critical"
      assert ash["location"] == %{"path" => "lib/ledger/reports.ex", "lines" => %{"begin" => 112}}

      assert ash["description"] =~
               "[reachable] CVE-2026-101028 in ash 3.34.2 via Ash.Actions.Aggregate.run/4"

      assert plug["severity"] == "major"
      assert plug["location"]["path"] == "mix.lock"
      assert Enum.uniq_by(issues, & &1["fingerprint"]) == issues

      with_unreachable = GitLab.issues(report(), %Config{show_unreachable: true})
      assert Enum.find(with_unreachable, &(&1["check_name"] == "GHSA-hk-1"))["severity"] == "info"
    end
  end
end
