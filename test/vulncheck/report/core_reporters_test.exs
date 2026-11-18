defmodule VulnCheck.Report.CoreReportersTest do
  use ExUnit.Case, async: false

  doctest VulnCheck.Report.JSON

  alias VulnCheck.Config
  alias VulnCheck.Report.{JSON, Markdown, Terminal}
  alias VulnCheck.Types.{Finding, MFA, Package, ScanReport, Summary, TraceHop, Workspace}

  setup do
    previous = System.get_env("NO_COLOR")
    System.put_env("NO_COLOR", "1")

    on_exit(fn ->
      if previous, do: System.put_env("NO_COLOR", previous), else: System.delete_env("NO_COLOR")
    end)

    :ok
  end

  defp mfa(module, function, arity), do: %MFA{module: module, function: function, arity: arity}

  defp package(name, version, scope \\ :prod),
    do: {name, %Package{name: name, version: version, source: :hex, scope: scope}}

  defp workspace do
    %Workspace{
      root_dir: "/srv/ledger",
      project_name: "ledger_api",
      project_type: :mix,
      env: :prod,
      elixir_version: "1.18.2",
      otp_release: "27",
      lockfile: "/srv/ledger/mix.lock",
      packages:
        Map.new([
          package("ash", "3.34.2"),
          package("plug", "1.16.2"),
          package("hackney", "1.20.1"),
          package("hex_core", "0.10.0"),
          package("meck", "0.9.2", :non_prod)
        ])
    }
  end

  defp finding(fields) do
    base = %Finding{
      advisory_id: "GHSA-0000",
      package: "ash",
      installed_version: "3.34.2",
      severity: :medium,
      verdict: :unreachable,
      reason: :function_not_called
    }

    finding = struct(base, fields)

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

  defp findings do
    [
      finding(
        advisory_id: "EEF-CVE-2026-101028",
        aliases: ["CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"],
        severity: :high,
        cvss_score: 7.5,
        fixed_versions: ["3.34.6"],
        verdict: :reachable,
        reason: :call_chain_proven,
        summary: "Aggregates skip related resources' read policies",
        target_mfa: mfa("Elixir.Ash.Actions.Aggregate", "run", 4),
        trace: [
          %TraceHop{
            mfa: mfa("Elixir.Ledger.Application", "start", 2),
            file: "lib/ledger/application.ex",
            line: 9,
            kind: :entrypoint
          },
          %TraceHop{
            mfa: mfa("Elixir.Ledger.Reports", "count_entries", 2),
            file: "lib/ledger/reports.ex",
            line: 112,
            kind: :static_call
          },
          %TraceHop{
            mfa: mfa("Elixir.Ash.Actions.Aggregate", "run", 4),
            file: "deps/ash/lib/ash/actions/aggregate.ex",
            line: 29,
            kind: :static_call
          }
        ]
      ),
      finding(
        advisory_id: "GHSA-plug-0001",
        aliases: ["CVE-2026-54892"],
        package: "plug",
        installed_version: "1.16.2",
        cvss_score: 6.5,
        fixed_versions: ["1.16.4"],
        verdict: :potentially_reachable,
        reason: :active_network_daemon,
        summary: "Quadratic-time nested parameter decoding",
        reason_detail: "Plug.Parsers :urlencoded enabled in the endpoint"
      ),
      finding(
        advisory_id: "GHSA-hk-1",
        package: "hackney",
        installed_version: "1.20.1",
        reason: :adapter_not_configured,
        reason_detail: "Tesla configured with Tesla.Adapter.Mint"
      ),
      finding(
        advisory_id: "GHSA-hk-2",
        package: "hackney",
        installed_version: "1.20.1",
        reason: :adapter_not_configured,
        reason_detail: "Tesla configured with Tesla.Adapter.Mint"
      ),
      finding(
        advisory_id: "GHSA-hc-1",
        package: "hex_core",
        installed_version: "0.10.0",
        severity: :low,
        reason: :otp_version_unaffected,
        reason_detail: "requires OTP <= 25; running OTP 27"
      ),
      finding(
        advisory_id: "GHSA-mk-1",
        package: "meck",
        installed_version: "0.9.2",
        package_scope: :non_prod,
        reason: :non_prod_dependency,
        reason_detail: "restricted to :test"
      ),
      finding(
        advisory_id: "GHSA-ex-1",
        package: "plug",
        installed_version: "1.16.2",
        verdict: :potentially_reachable,
        reason: :missing_symbol_granularity,
        summary: "Session fixation",
        suppressed: false,
        suppression_expired: true,
        suppression_reason: "accepted risk",
        suppression_expires: "2026-01-01"
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
      policy_violations: ["suppression of GHSA-ex-1 (plug) expired on 2026-01-01"],
      warnings: ["hackney 1.20.1 has no checksum in mix.lock"],
      duration_ms: 142,
      stats: %{feed_status: :cached}
    }
  end

  describe "terminal" do
    test "renders header, traces, grouped unreachable evidence and the footer" do
      output = Terminal.render(report(), %Config{})

      refute output =~ "\e["
      assert output =~ "VulnCheck 1.0.0 — BEAM Reachability Vulnerability Audit"
      assert output =~ "Target: ledger_api (mix, Elixir 1.18.2 / OTP 27, env: prod)"

      assert output =~
               "Lockfile: 4 prod packages (1 dev/test excluded) · Scan time: 142 ms (cached)"

      assert output =~
               "[REACHABLE] CVE-2026-101028 (GHSA-xj24-8f5c-pp5p) (HIGH · CVSS 7.5) — ash 3.34.2 (fix: >= 3.34.6)"

      assert output =~ "  Target:  Ash.Actions.Aggregate.run/4"

      assert output =~
               """
                 Trace:
                   1. Ledger.Application.start/2     (lib/ledger/application.ex:9)
                   2. Ledger.Reports.count_entries/2 (lib/ledger/reports.ex:112)
                   3. Ash.Actions.Aggregate.run/4    (deps/ash/lib/ash/actions/aggregate.ex:29)
               """

      assert output =~
               "[POTENTIALLY REACHABLE] CVE-2026-54892 (GHSA-plug-0001) (MEDIUM · CVSS 6.5) — plug 1.16.2 (fix: >= 1.16.4)"

      assert output =~
               "  Reason:  Plug.Parsers :urlencoded enabled in the endpoint (active_network_daemon)"

      assert output =~
               "Suppressed as UNREACHABLE (4 advisories — pass --show-unreachable for details):"

      assert output =~
               "  • 2 in hackney 1.20.1  (adapter_not_configured: Tesla configured with Tesla.Adapter.Mint)"

      assert output =~
               "  • 1 in hex_core 0.10.0 (otp_version_unaffected: requires OTP <= 25; running OTP 27)"

      assert output =~ "  • 1 in meck 0.9.2      (non_prod_dependency: restricted to :test)"

      assert output =~
               "Summary: 1 reachable, 2 potentially reachable, 4 unreachable, 1 expired suppression (57% noise reduction)"

      assert output =~
               "Policy violations:\n  ! suppression of GHSA-ex-1 (plug) expired on 2026-01-01"

      assert output =~ "Warnings:\n  ! hackney 1.20.1 has no checksum in mix.lock"

      assert output =~
               "  Ignore:  suppression expired on 2026-01-01 (accepted risk); the finding is active again"

      refute output =~ "[UNREACHABLE]"
    end

    test "--show-unreachable lists every unreachable finding" do
      output = Terminal.render(report(), %Config{show_unreachable: true})

      refute output =~ "Suppressed as UNREACHABLE"
      assert output |> String.split("[UNREACHABLE]") |> length() == 5

      assert output =~
               "[UNREACHABLE] GHSA-hc-1 (LOW) — hex_core 0.10.0\n  Reason:  requires OTP <= 25; running OTP 27 (otp_version_unaffected)"
    end

    test "colors follow NO_COLOR and the color option" do
      System.delete_env("NO_COLOR")
      assert Terminal.render(report(), %Config{}) =~ IO.ANSI.red()
      refute Terminal.render(report(), %Config{color: false}) =~ "\e["
      System.put_env("NO_COLOR", "1")
      refute Terminal.color?(%Config{color: true})
    end

    test "quiet mode hides warnings and suppressed findings are listed" do
      [first | rest] = findings()

      suppressed = %{
        first
        | suppressed: true,
          suppression_reason: "fixed upstream",
          suppression_expires: "2027-01-01"
      }

      output = Terminal.render(report([suppressed | rest]), %Config{quiet: true})

      refute output =~ "Warnings:"
      refute output =~ "[REACHABLE]"

      assert output =~
               "Suppressed by .vulncheck.ignore (1):\n  • CVE-2026-101028 (GHSA-xj24-8f5c-pp5p) in ash 3.34.2 (fixed upstream, until 2027-01-01)"
    end

    test "an empty report says so" do
      empty = %{report([]) | policy_violations: [], warnings: []}
      output = Terminal.render(empty, %Config{})

      assert output =~ "No known advisories affect the locked dependencies."

      assert output =~
               "Summary: 0 reachable, 0 potentially reachable, 0 unreachable (0% noise reduction)"
    end
  end

  describe "json" do
    test "lists context routines of a finding" do
      [first | rest] = findings()

      with_context = %{
        first
        | context_routines: [MFA.new("Elixir.List", "delete", 2), MFA.new("lists", "reverse", 1)]
      }

      doc = Elixir.JSON.decode!(JSON.render(report([with_context | rest]), %Config{}))
      [rendered | others] = doc["findings"]
      assert rendered["context_routines"] == ["List.delete/2", ":lists.reverse/1"]
      assert Enum.all?(others, &(&1["context_routines"] == []))
    end

    test "round-trips all schema fields and is byte-reproducible" do
      rendered = JSON.render(report(), %Config{})
      assert rendered == JSON.render(report(), %Config{})

      doc = Elixir.JSON.decode!(rendered)

      assert doc["schema_version"] == "1.0.0"
      assert doc["tool"] == %{"name" => "vulncheck", "version" => "1.0.0"}

      assert %{
               "project_name" => "ledger_api",
               "project_type" => "mix",
               "env" => "prod",
               "elixir_version" => "1.18.2",
               "otp_release" => "27",
               "prod_packages_count" => 4,
               "non_prod_packages_count" => 1
             } = doc["target"]

      assert %{
               "reachable" => 1,
               "potentially_reachable" => 2,
               "unreachable" => 4,
               "retired" => 0,
               "suppressed" => 0,
               "noise_reduction_percent" => 57
             } = doc["summary"]

      [reachable | _] = doc["findings"]

      assert %{
               "advisory_id" => "EEF-CVE-2026-101028",
               "aliases" => ["CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"],
               "package" => "ash",
               "installed_version" => "3.34.2",
               "fixed_versions" => ["3.34.6"],
               "severity" => "high",
               "cvss_score" => 7.5,
               "verdict" => "reachable",
               "reason" => "call_chain_proven",
               "target_mfa" => "Ash.Actions.Aggregate.run/4"
             } = reachable

      assert List.last(reachable["trace"]) == %{
               "mfa" => "Ash.Actions.Aggregate.run/4",
               "file" => "deps/ash/lib/ash/actions/aggregate.ex",
               "line" => 29,
               "kind" => "static_call"
             }

      assert String.length(reachable["fingerprint"]) == 64
      assert length(doc["findings"]) == 7
    end

    test "object keys are sorted" do
      rendered = JSON.render(report(), %Config{})

      top_level =
        Regex.scan(~r/^  "([a-z_]+)":/m, rendered, capture: :all_but_first) |> List.flatten()

      assert top_level == Enum.sort(top_level)
    end

    test "the document is accepted as a baseline" do
      dir =
        Path.join(
          System.tmp_dir!(),
          "vulncheck-json-baseline-#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      path = Path.join(dir, "report.json")
      File.write!(path, JSON.render(report(), %Config{}))

      assert {:ok, entries} = VulnCheck.Diff.read_baseline(path)
      assert length(entries) == 7
    end
  end

  describe "markdown" do
    test "renders a metrics table, expanded traces and folded unreachable evidence" do
      output = Markdown.render(report(), %Config{})

      assert output =~ "## VulnCheck report — `ledger_api`"
      assert output =~ "| Metric | Count |\n| --- | ---: |\n| Reachable | 1 |"
      assert output =~ "| Noise reduction | 57% |"
      assert output =~ "### Reachable (1)"
      assert output =~ "#### CVE-2026-101028 (GHSA-xj24-8f5c-pp5p) — `ash` 3.34.2"
      assert output =~ "- **Fix:** `>= 3.34.6`"
      assert output =~ "| # | Call | Location |\n| ---: | --- | --- |"

      assert output =~
               "| 3 | `Ash.Actions.Aggregate.run/4` | `deps/ash/lib/ash/actions/aggregate.ex:29` |"

      assert output =~ "### Potentially reachable (2)"
      assert output =~ "<details>\n<summary>Unreachable advisories (4)</summary>\n\n| Advisory |"
      assert output =~ "requires OTP &lt;= 25; running OTP 27"
      assert output =~ "</details>"

      assert output =~
               "### Policy violations\n\n- suppression of GHSA-ex-1 (plug) expired on 2026-01-01"

      tables =
        output
        |> String.split("\n")
        |> Enum.chunk_by(&String.starts_with?(&1, "|"))
        |> Enum.filter(&String.starts_with?(hd(&1), "|"))

      assert length(tables) == 3

      for [header, rule | rows] <- tables do
        columns = cell_count(header)
        assert cell_count(rule) == columns
        assert rule =~ ~r/^\|( -+:? \|)+$/
        for row <- rows, do: assert(cell_count(row) == columns)
      end
    end

    test "pipes inside cells are escaped" do
      [first | rest] = findings()
      hop = %TraceHop{mfa: mfa("Elixir.Kernel", "|>", 2), file: "lib/a.ex", line: 1}
      output = Markdown.render(report([%{first | trace: [hop]} | rest]), %Config{})
      assert output =~ "| 1 | `Kernel.\\|>/2` | `lib/a.ex:1` |"
    end
  end

  defp cell_count(line) do
    line |> String.replace("\\|", "") |> String.split("|") |> length() |> Kernel.-(2)
  end
end
