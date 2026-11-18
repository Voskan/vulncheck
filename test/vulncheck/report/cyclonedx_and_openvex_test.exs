defmodule VulnCheck.Report.CycloneDXAndOpenVEXTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Config
  alias VulnCheck.Report.{CycloneDX, OpenVEX}
  alias VulnCheck.Types.{Finding, MFA, Package, ScanReport, Summary, TraceHop, Workspace}

  doctest VulnCheck.Report.CycloneDX

  @ash_sha "8A7ABE6D183372CEB21CAA2709BEC928AB2B72E18A3911AA1771639BEF82651E"

  defp pkg(name, version, fields \\ []) do
    {name, struct(%Package{name: name, version: version, source: :hex, scope: :prod}, fields)}
  end

  defp workspace do
    %Workspace{
      root_dir: "/srv/ledger",
      project_name: "ledger_api",
      project_version: "3.2.1",
      project_type: :mix,
      env: :prod,
      elixir_version: "1.18.2",
      otp_release: "27",
      lockfile: "/srv/ledger/mix.lock",
      direct_deps: ["ash", "meck", "my_fork", "plug"],
      packages:
        Map.new([
          pkg("ash", "3.34.2", checksum: @ash_sha, deps: ["spark", "telemetry"]),
          pkg("spark", "2.2.0", deps: ["telemetry"]),
          pkg("telemetry", "1.3.0"),
          pkg("plug", "1.16.2", checksum: "not-a-sha"),
          pkg("hackney", "1.20.1"),
          pkg("meck", "0.9.2", scope: :non_prod),
          pkg("my_fork", "0.1.0",
            source: :git,
            git_url: "https://github.com/Acme/my_fork.git",
            git_ref: "2f2c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
          ),
          pkg("local_lib", "0.2.0", source: :path)
        ])
    }
  end

  defp finding(fields) do
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
  end

  defp findings do
    [
      finding(
        advisory_id: "EEF-CVE-2026-101028",
        aliases: ["CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"],
        severity: :high,
        cvss_score: 7.5,
        cwes: ["CWE-863"],
        fixed_versions: ["3.34.6"],
        recommended_fix: "3.34.6",
        summary: "Aggregates skip read policies",
        verdict: :reachable,
        reason: :call_chain_proven,
        target_mfa: %MFA{module: "Elixir.Ash.Actions.Aggregate", function: "run", arity: 4},
        trace: [
          %TraceHop{
            mfa: %MFA{module: "Elixir.Ledger.Reports", function: "count", arity: 2},
            file: "lib/ledger/reports.ex",
            line: 3
          },
          %TraceHop{
            mfa: %MFA{module: "Elixir.Ash.Actions.Aggregate", function: "run", arity: 4},
            file: "deps/ash/lib/a.ex",
            line: 9
          }
        ]
      ),
      finding(
        advisory_id: "GHSA-plug-0001",
        package: "plug",
        installed_version: "1.16.2",
        verdict: :potentially_reachable,
        reason: :active_network_daemon,
        reason_detail: "Plug.Parsers enabled"
      ),
      finding(
        advisory_id: "GHSA-ash-fn",
        reason: :function_not_called,
        reason_detail: "Ash.Query.unsafe/1 is never called"
      ),
      finding(advisory_id: "GHSA-ash-mod", reason: :module_not_loaded),
      finding(
        advisory_id: "GHSA-hk-1",
        package: "hackney",
        installed_version: "1.20.1",
        reason: :adapter_not_configured,
        reason_detail: "Tesla uses Mint"
      ),
      finding(
        advisory_id: "GHSA-hk-2",
        package: "hackney",
        installed_version: "1.20.1",
        reason: :otp_app_not_started,
        reason_detail: "hackney is never started"
      ),
      finding(
        advisory_id: "GHSA-mk-1",
        package: "meck",
        installed_version: "0.9.2",
        reason: :non_prod_dependency,
        reason_detail: "restricted to :test"
      ),
      finding(
        advisory_id: "GHSA-otp-1",
        package: "telemetry",
        installed_version: "1.3.0",
        reason: :otp_version_unaffected,
        reason_detail: "requires OTP <= 25"
      ),
      finding(
        advisory_id: "GHSA-sup-1",
        package: "plug",
        installed_version: "1.16.2",
        verdict: :reachable,
        reason: :call_chain_proven,
        suppressed: true,
        suppression_reason: "upgrade planned",
        suppression_expires: "2027-01-01"
      ),
      finding(
        advisory_id: "HEX-RETIRED-plug-1.16.2",
        package: "plug",
        installed_version: "1.16.2",
        verdict: :retired,
        reason: :package_retired
      )
    ]
  end

  defp report do
    %ScanReport{
      workspace: workspace(),
      generated_at: "2026-11-18T10:00:00Z",
      tool_version: "1.0.0",
      findings: findings(),
      summary: Summary.from_findings(findings())
    }
  end

  describe "CycloneDX" do
    test "documents components, scopes, hashes and the dependency graph" do
      bom = report() |> CycloneDX.render(%Config{}) |> JSON.decode!()

      assert bom["bomFormat"] == "CycloneDX"
      assert bom["specVersion"] == "1.6"
      assert bom["version"] == 1

      assert bom["serialNumber"] =~
               ~r/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

      metadata = bom["metadata"]
      assert metadata["timestamp"] == "2026-11-18T10:00:00Z"

      assert [%{"type" => "application", "name" => "vulncheck", "version" => "1.0.0"}] =
               metadata["tools"]["components"]

      assert metadata["component"] == %{
               "type" => "application",
               "name" => "ledger_api",
               "version" => "3.2.1",
               "bom-ref" => CycloneDX.root_ref(report())
             }

      components = Map.new(bom["components"], &{&1["name"], &1})
      assert Enum.map(bom["components"], & &1["name"]) == Enum.sort(Map.keys(components))

      ash = components["ash"]
      assert ash["purl"] == "pkg:hex/ash@3.34.2"
      assert ash["bom-ref"] == ash["purl"]
      assert ash["type"] == "library"
      assert ash["scope"] == "required"
      assert ash["hashes"] == [%{"alg" => "SHA-256", "content" => String.downcase(@ash_sha)}]
      refute Map.has_key?(components["plug"], "hashes")
      assert components["meck"]["scope"] == "excluded"

      assert components["my_fork"]["purl"] ==
               "pkg:github/acme/my_fork@2f2c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"

      assert components["my_fork"]["externalReferences"] == [
               %{"type" => "vcs", "url" => "https://github.com/Acme/my_fork.git"}
             ]

      assert components["local_lib"]["purl"] == "pkg:generic/local_lib@0.2.0"

      deps = Map.new(bom["dependencies"], &{&1["ref"], &1["dependsOn"]})
      assert Enum.map(bom["dependencies"], & &1["ref"]) == Enum.sort(Map.keys(deps))

      assert deps[CycloneDX.root_ref(report())] ==
               Enum.sort([
                 "pkg:hex/ash@3.34.2",
                 "pkg:hex/meck@0.9.2",
                 "pkg:hex/plug@1.16.2",
                 components["my_fork"]["purl"]
               ])

      assert deps["pkg:hex/ash@3.34.2"] == ["pkg:hex/spark@2.2.0", "pkg:hex/telemetry@1.3.0"]
      assert deps["pkg:hex/telemetry@1.3.0"] == []
    end

    test "maps verdicts to analysis states" do
      bom = report() |> CycloneDX.document(%Config{})
      vulns = Map.new(bom["vulnerabilities"], &{&1["id"], &1})

      refute Map.has_key?(vulns, "HEX-RETIRED-plug-1.16.2")
      assert length(bom["vulnerabilities"]) == 9

      reachable = vulns["EEF-CVE-2026-101028"]

      assert reachable["affects"] == [
               %{
                 "ref" => "pkg:hex/ash@3.34.2",
                 "versions" => [%{"version" => "3.34.2", "status" => "affected"}]
               }
             ]

      assert reachable["ratings"] == [
               %{"score" => 7.5, "severity" => "high", "source" => %{"name" => "EEF CNA"}}
             ]

      assert reachable["cwes"] == [863]
      assert reachable["recommendation"] == "Upgrade ash to 3.34.6"

      assert reachable["analysis"] == %{
               "state" => "exploitable",
               "detail" =>
                 "Reachable call chain: Ledger.Reports.count/2 -> Ash.Actions.Aggregate.run/4",
               "response" => ["update"]
             }

      assert vulns["GHSA-plug-0001"]["analysis"] == %{
               "state" => "in_triage",
               "detail" => "Plug.Parsers enabled"
             }

      for id <- ~w(GHSA-ash-fn GHSA-ash-mod GHSA-hk-1 GHSA-hk-2) do
        assert %{"state" => "not_affected", "justification" => "code_not_reachable"} =
                 vulns[id]["analysis"]
      end

      assert vulns["GHSA-ash-mod"]["analysis"]["detail"] == "module not loaded"

      assert %{"state" => "not_affected", "justification" => "code_not_present"} =
               vulns["GHSA-mk-1"]["analysis"]

      assert %{"state" => "not_affected", "justification" => "requires_environment"} =
               vulns["GHSA-otp-1"]["analysis"]

      assert vulns["GHSA-sup-1"]["analysis"]["state"] == "exploitable"
      refute Map.has_key?(vulns["GHSA-sup-1"]["analysis"], "justification")
    end

    test "is byte-reproducible and honours explicit identifiers" do
      assert CycloneDX.render(report(), %Config{}) == CycloneDX.render(report(), %Config{})

      bom =
        report()
        |> CycloneDX.encode(%Config{},
          timestamp: "2030-01-01T00:00:00Z",
          serial_number: "urn:uuid:00000000-0000-4000-8000-000000000000"
        )
        |> JSON.decode!()

      assert bom["metadata"]["timestamp"] == "2030-01-01T00:00:00Z"
      assert bom["serialNumber"] == "urn:uuid:00000000-0000-4000-8000-000000000000"

      other =
        report() |> CycloneDX.encode(%Config{}, timestamp: "2030-01-01T00:00:00Z") |> JSON.decode!()

      refute other["serialNumber"] == CycloneDX.document(report(), %Config{})["serialNumber"]
    end
  end

  describe "OpenVEX" do
    test "has the v0.2.0 envelope" do
      vex = report() |> OpenVEX.render(%Config{}) |> JSON.decode!()

      assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
      assert vex["@id"] =~ ~r"^https://openvex\.dev/docs/vulncheck/[0-9a-f]{64}$"
      assert vex["author"] == "VulnCheck"
      assert vex["role"] == "Document Creator"
      assert vex["tooling"] == "vulncheck/1.0.0"
      assert vex["version"] == 1
      assert vex["timestamp"] == "2026-11-18T10:00:00Z"
      assert length(vex["statements"]) == 9
      refute Enum.any?(vex["statements"], &(&1["vulnerability"]["name"] =~ "RETIRED"))
    end

    test "maps every verdict and reason to status and justification" do
      statements =
        report()
        |> OpenVEX.document(%Config{})
        |> Map.fetch!("statements")
        |> Map.new(&{&1["vulnerability"]["@id"] |> String.split("/") |> List.last(), &1})

      reachable = statements["EEF-CVE-2026-101028"]
      assert reachable["status"] == "affected"

      assert reachable["action_statement"] ==
               "Upgrade ash to 3.34.6 (reachable through Ash.Actions.Aggregate.run/4)"

      refute Map.has_key?(reachable, "justification")
      refute Map.has_key?(reachable, "impact_statement")

      assert reachable["vulnerability"] == %{
               "@id" => "https://osv.dev/vulnerability/EEF-CVE-2026-101028",
               "name" => "CVE-2026-101028",
               "description" => "Aggregates skip read policies",
               "aliases" => ["EEF-CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"]
             }

      assert reachable["products"] == [
               %{
                 "@id" => CycloneDX.root_ref(report()),
                 "subcomponents" => [%{"@id" => "pkg:hex/ash@3.34.2"}]
               }
             ]

      investigating = statements["GHSA-plug-0001"]
      assert investigating["status"] == "under_investigation"
      refute Map.has_key?(investigating, "justification")
      refute Map.has_key?(investigating, "action_statement")

      for id <- ~w(GHSA-ash-fn GHSA-ash-mod GHSA-hk-1 GHSA-hk-2) do
        assert %{
                 "status" => "not_affected",
                 "justification" => "vulnerable_code_not_in_execute_path"
               } = statements[id]

        refute Map.has_key?(statements[id], "action_statement")
      end

      assert statements["GHSA-ash-fn"]["impact_statement"] == "Ash.Query.unsafe/1 is never called"
      assert statements["GHSA-ash-mod"]["impact_statement"] == "module not loaded"

      assert %{"status" => "not_affected", "justification" => "component_not_present"} =
               statements["GHSA-mk-1"]

      assert statements["GHSA-mk-1"]["impact_statement"] == "restricted to :test"

      assert %{"status" => "not_affected", "impact_statement" => "requires OTP <= 25"} =
               statements["GHSA-otp-1"]

      refute Map.has_key?(statements["GHSA-otp-1"], "justification")

      assert statements["GHSA-sup-1"]["status"] == "affected"
      refute Map.has_key?(statements["GHSA-sup-1"], "justification")
    end

    test "an expired suppression keeps the original verdict" do
      expired =
        finding(
          verdict: :reachable,
          reason: :call_chain_proven,
          suppressed: false,
          suppression_expired: true
        )

      assert OpenVEX.status(expired)["status"] == "affected"
    end

    test "is byte-reproducible for a fixed timestamp" do
      first = OpenVEX.encode(report(), %Config{}, timestamp: "2030-01-01T00:00:00Z")
      assert first == OpenVEX.encode(report(), %Config{}, timestamp: "2030-01-01T00:00:00Z")
      refute first == OpenVEX.encode(report(), %Config{}, timestamp: "2030-01-02T00:00:00Z")
      assert JSON.decode!(first)["timestamp"] == "2030-01-01T00:00:00Z"
    end
  end

  test "product identity distinguishes versions, environments and compiled snapshots" do
    report = report()
    first = CycloneDX.root_ref(report)
    assert first =~ ~r"^pkg:generic/ledger_api@3\.2\.1\?scan_scope=[0-9a-f]{64}$"

    assert CycloneDX.root_ref(%{report | workspace: %{report.workspace | project_version: "3.2.2"}}) !=
             first

    assert CycloneDX.root_ref(%{report | workspace: %{report.workspace | otp_release: "28"}}) !=
             first

    partial = %{report | stats: %{analysis: %{status: :partial, artifact_digest: "evidence"}}}
    ref = CycloneDX.root_ref(partial)
    assert ref != first
    bom = CycloneDX.document(partial, %Config{})
    assert bom["metadata"]["component"]["bom-ref"] == ref

    assert %{"name" => "vulncheck:build_analysis", "value" => "partial"} in bom["metadata"][
             "properties"
           ]

    vex = OpenVEX.document(partial, %Config{})
    assert Enum.all?(vex["statements"], fn statement -> hd(statement["products"])["@id"] == ref end)
  end

  test "full attestations keep filtered findings and distinguish lock aliases" do
    report = report()
    {"ash_alias", aliased} = pkg("ash_alias", "3.34.2", hex_name: "ash")
    packages = Map.put(report.workspace.packages, "ash_alias", aliased)

    ws = %{
      report.workspace
      | packages: packages,
        direct_deps: ["ash_alias" | report.workspace.direct_deps]
    }

    original = hd(report.findings)

    duplicate = %{
      original
      | package: "ash_alias",
        verdict: :potentially_reachable,
        reason: :missing_beam_debug_info
    }

    filtered = %{report | findings: [], all_findings: [original, duplicate], workspace: ws}

    bom = CycloneDX.document(filtered, %Config{})
    aliases = Enum.filter(bom["components"], &(&1["purl"] == "pkg:hex/ash@3.34.2"))
    refs = MapSet.new(aliases, & &1["bom-ref"])
    assert MapSet.size(refs) == 2

    assert all_refs =
             List.flatten([bom["metadata"]["component"], bom["components"], bom["vulnerabilities"]])

    assert Enum.uniq_by(all_refs, & &1["bom-ref"]) == all_refs
    graph_refs = MapSet.new(all_refs, & &1["bom-ref"])

    assert Enum.all?(bom["dependencies"], fn entry ->
             Enum.all?([entry["ref"] | entry["dependsOn"]], &MapSet.member?(graph_refs, &1))
           end)

    assert MapSet.new(bom["vulnerabilities"], &hd(&1["affects"])["ref"]) == refs

    vex = OpenVEX.document(filtered, %Config{})

    assert Enum.sort(Enum.map(vex["statements"], & &1["status"])) == [
             "affected",
             "under_investigation"
           ]

    components = Enum.map(vex["statements"], &hd(hd(&1["products"])["subcomponents"]))
    assert MapSet.new(components, & &1["@id"]) == refs
    assert Enum.all?(components, &(&1["identifiers"]["purl"] == "pkg:hex/ash@3.34.2"))
  end

  test "empty and retired-only scans have no OpenVEX document" do
    report = report()

    for findings <- [[], [List.last(report.findings)]] do
      clean = %{report | findings: findings}
      assert OpenVEX.document(clean, %Config{}) == nil
      assert OpenVEX.render(clean, %Config{}) == ""
      assert CycloneDX.document(clean, %Config{})["vulnerabilities"] == []
    end
  end
end
