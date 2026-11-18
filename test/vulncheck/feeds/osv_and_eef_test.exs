defmodule VulnCheck.Feeds.OsvAndEefTest do
  # Measures the global atom table, so it must not run concurrently.
  use ExUnit.Case, async: false

  alias VulnCheck.{Cache, Config, Solver}
  alias VulnCheck.Feeds.{CVSS, EefCna, Merge, OSV, Store, TextHints}
  alias VulnCheck.Test.{Feeds, HTTPServer, Tmp}
  alias VulnCheck.Types.{Advisory, Finding, MFA, Package, ScanReport, Workspace}

  doctest VulnCheck.Feeds.CVSS
  doctest VulnCheck.Feeds.TextHints

  defp workspace(packages) do
    %Workspace{
      root_dir: "/tmp/shop",
      project_name: "shop",
      project_type: :mix,
      env: :prod,
      otp_release: "27",
      packages:
        Map.new(packages, fn {name, version} ->
          {name, %Package{name: name, hex_name: name, version: version, source: :hex, scope: :prod}}
        end)
    }
  end

  defp config(extra \\ []) do
    struct(
      %Config{project_dir: Tmp.mkdir!("feeds-project"), cache_dir: Tmp.mkdir!("feeds-cache")},
      extra
    )
  end

  describe "OSV archive" do
    test "parses records into per-package advisories" do
      zip =
        Feeds.zip([Feeds.osv_ash(), Feeds.osv_plug(), Feeds.osv_phoenix(), Feeds.osv_withdrawn()])

      assert {:ok, advisories} = OSV.parse_archive(zip)

      assert Enum.map(advisories, & &1.id) |> Enum.sort() ==
               ["EEF-CVE-2026-101028", "EEF-CVE-2026-54892", "GHSA-ph0x-0000-0001"]

      index = OSV.index(advisories)
      [ash] = index["ash"]
      assert ash.aliases == ["CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"]
      assert ash.cvss_score == 7.5
      assert ash.severity == :high
      assert ash.cwes == ["CWE-863"]
      assert ash.fixed_versions == ["3.34.6"]
      assert ash.affected_routines == []
      assert ash.published_at == "2026-03-02T10:00:00Z"
      assert length(ash.references) == 2

      [plug] = index["plug"]
      assert plug.cvss_score == 6.5
      assert plug.severity == :medium
      assert length(plug.version_ranges) == 5

      [phoenix] = index["phoenix"]
      assert phoenix.severity == :medium
      assert phoenix.cvss_score == nil
    end

    test "extracts OTP constraints and handles odd records" do
      [hex_core] = OSV.parse_record(Feeds.osv_hex_core())
      assert hex_core.otp_constraints == "24 || 25"

      assert OSV.parse_record(%{"no" => "id"}) == []

      [multi] =
        OSV.parse_record(%{
          "id" => "X-1",
          "affected" => [
            %{"package" => %{"ecosystem" => "Hex", "name" => "a"}, "versions" => ["1.0.0"]},
            %{"package" => %{"ecosystem" => "npm", "name" => "b"}},
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "a"},
              "ranges" => [%{"type" => "SEMVER", "events" => [%{"introduced" => "2.0.0"}]}],
              "severity" => [
                %{
                  "type" => "CVSS_V4",
                  "score" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                }
              ],
              "ecosystem_specific" => %{
                "affected_functions" => ["'Elixir.A.B':run/2", "bad"],
                "modules" => ["A.B"]
              }
            }
          ]
        })

      assert multi.package == "a"
      assert multi.affected_versions == ["1.0.0"]
      assert multi.cvss_vector =~ "CVSS:4.0"
      assert {multi.cvss_score, multi.severity} == {9.3, :critical}
      assert multi.affected_routines == [MFA.new("Elixir.A.B", "run", 2)]
      assert multi.affected_modules == ["Elixir.A.B"]
      assert multi.symbol_source == :osv
    end

    test "rejects invalid archives" do
      assert {:error, {:invalid_archive, _}} = OSV.parse_archive("not a zip")
    end

    test "uses a valid rating for the installed package and version in the CI gate" do
      low = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
      high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      malformed = "CVSS:3.1/AV:N"
      scores = fn vectors -> Enum.map(vectors, &%{"type" => "CVSS_V3", "score" => &1}) end

      block = fn name, version, vectors ->
        %{
          "package" => %{"ecosystem" => "Hex", "name" => name},
          "versions" => [version],
          "severity" => scores.(vectors)
        }
      end

      osv = %{
        "id" => "RATING-1",
        "severity" => scores.(~w(18.5)),
        "affected" => [
          block.("fixture", "1.0.0", [low]),
          block.("fixture", "2.0.0", [malformed, high]),
          block.("other", "1.0.0", [high])
        ]
      }

      alias_record = %{
        "id" => "RATING-2",
        "aliases" => ["RATING-1"],
        "severity" => scores.([high]),
        "affected" => [block.("fixture", "2.0.0", [])]
      }

      advisories = Merge.merge(OSV.parse_record(osv) ++ OSV.parse_record(alias_record))
      index = OSV.index(advisories)
      gate = %Config{min_severity: :high}

      for {name, version, vector, failure?} <- [
            {"fixture", "1.0.0", low, false},
            {"fixture", "2.0.0", high, true},
            {"other", "1.0.0", high, true}
          ] do
        ws = workspace([{name, version}])
        [advisory] = Store.match(index, ws)
        assert advisory.cvss_vector == vector
        assert advisory.cvss_method == "CVSSv31"
        assert advisory.cvss_score == CVSS.base_score(vector)

        [finding] = Solver.solve(ws, nil, nil, [advisory], gate)
        assert VulnCheck.should_fail?(%ScanReport{findings: [finding]}, gate) == failure?
      end

      source = [%{"type" => "CVSS_V3", "score" => "18.5"}]
      assert CVSS.ratings(source, "RATING-INVALID") == nil

      assert CVSS.ratings(scores.([high, low]), "RATING-TIE") ==
               CVSS.ratings(scores.([low, high]), "RATING-TIE")
    end
  end

  describe "Store.load/3 with a local feed server" do
    setup do
      zip = Feeds.zip([Feeds.osv_ash(), Feeds.osv_plug(), Feeds.osv_phoenix()])

      ash_cve =
        Feeds.cve_record("CVE-2026-101028", "ash", ["'Elixir.Ash.Actions.Aggregate':run/4"],
          cvss: {7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
          cwe: "CWE-863"
        )

      plug_cve =
        Feeds.cve_record(
          "CVE-2026-54892",
          "plug",
          [
            "'Elixir.Plug.Conn.Query':decode/4",
            "'Elixir.Plug.Conn.Query':decode_each/2",
            "'Elixir.Plug.Conn.Query':split_keys/6"
          ],
          modules: ["'Elixir.Plug.Conn.Query'"]
        )

      server =
        HTTPServer.start!(fn
          %{path: "/osv/all.zip"} -> {200, [{"etag", "\"osv-1\""}], zip}
          %{path: "/cna/CVE-2026-101028.json"} -> {200, [], JSON.encode!(ash_cve)}
          %{path: "/cna/CVE-2026-54892.json"} -> {200, [], "{invalid json"}
          %{path: "/cna/" <> _} -> {404, [], "not found"}
          %{path: "/mitre/CVE-2026-54892"} -> {200, [], JSON.encode!(plug_cve)}
          %{path: _} -> {404, [], ""}
        end)

      opts = [
        osv_url: server.url <> "/osv/all.zip",
        cna_base_url: server.url <> "/cna",
        mitre_base_url: server.url <> "/mitre",
        retired: false,
        http_opts: [retry_delay_ms: 1, retries: 0]
      ]

      %{server: server, opts: opts}
    end

    test "enriches only version-matched advisories and falls back to MITRE", %{
      server: server,
      opts: opts
    } do
      ws = workspace([{"ash", "3.34.2"}, {"plug", "1.16.2"}, {"phoenix", "1.7.18"}])
      config = config()

      # warm-up run so lazily loaded modules do not skew the atom count
      assert {:ok, _} = Store.load(ws, config(), opts)
      before = :erlang.system_info(:atom_count)
      assert {:ok, result} = Store.load(ws, config, opts)
      assert :erlang.system_info(:atom_count) == before

      by_id = Map.new(result.advisories, &{&1.id, &1})
      assert Map.keys(by_id) |> Enum.sort() == ["EEF-CVE-2026-101028", "EEF-CVE-2026-54892"]

      ash = by_id["EEF-CVE-2026-101028"]
      assert ash.enriched
      assert ash.symbol_source == :cve
      assert ash.affected_routines == [MFA.new("Elixir.Ash.Actions.Aggregate", "run", 4)]
      assert ash.affected_modules == ["Elixir.Ash.Actions.Aggregate"]

      plug = by_id["EEF-CVE-2026-54892"]
      assert plug.enriched
      assert length(plug.affected_routines) == 3
      assert MFA.new("Elixir.Plug.Conn.Query", "decode", 4) in plug.affected_routines
      assert plug.affected_modules == ["Elixir.Plug.Conn.Query"]
      assert plug.cwes == ["CWE-400"]

      paths = server |> HTTPServer.requests() |> Enum.map(& &1.path)
      refute Enum.any?(paths, &String.contains?(&1, "CVE-2026-77777"))

      # second run: CVE records come from the immutable cache
      cna_requests = Enum.count(paths, &String.starts_with?(&1, "/cna/"))
      assert cna_requests == 4
      assert Enum.count(paths, &(&1 == "/mitre/CVE-2026-54892")) == 2

      assert result.stats.feed_advisories == 3
      assert result.stats.matched_advisories == 2
      assert result.stats.enriched_advisories == 2
      assert result.warnings == []

      assert {:ok, again} = Store.load(ws, config, opts)
      assert length(again.advisories) == 2
      paths_after = server |> HTTPServer.requests() |> Enum.map(& &1.path)
      assert Enum.count(paths_after, &String.starts_with?(&1, "/cna/")) == cna_requests

      assert {:ok, advisories} = Store.match_workspace(ws, config, opts)
      assert length(advisories) == 2
    end

    test "unaffected versions do not trigger enrichment", %{server: server, opts: opts} do
      ws = workspace([{"ash", "3.34.6"}, {"plug", "1.15.5"}])
      assert {:ok, %{advisories: []}} = Store.load(ws, config(), opts)
      paths = server |> HTTPServer.requests() |> Enum.map(& &1.path)
      assert paths == ["/osv/all.zip"]
    end

    test "OSV validation preserves the last usable feed and reports a rejected refresh", %{
      server: server,
      opts: opts
    } do
      ws = workspace([{"ash", "3.34.2"}])
      config = config()
      assert {:ok, first} = Store.load(ws, config, opts)
      assert first.stats.feed.status == :network

      {:ok, {_, invalid_zip}} =
        :zip.create(~c"all.zip", [{~c"invalid.json", "{bad record"}], [:memory])

      HTTPServer.set_handler(server, fn _ -> {200, [], invalid_zip} end)
      opts = Keyword.put(opts, :force, true) |> Keyword.put(:enrich, false)

      assert {:ok, stale} = Store.load(ws, config, opts)
      assert stale.stats.feed.status == :stale
      assert stale.stats.feed.rejected_records == 1
      assert stale.stats.feed.age_seconds >= 0
      assert [warning] = stale.warnings
      assert warning =~ "using the previous verified copy"
      assert length(stale.advisories) == length(first.advisories)

      assert {:error, {:osv_feed, {:invalid_osv_records, 1}}} = Store.load(ws, config(), opts)

      assert {:ok, offline} =
               Store.load(ws, %{config | offline: true}, Keyword.drop(opts, [:force]))

      assert offline.stats.feed.status == :cached
      assert offline.stats.feed.rejected_records == 0
    end

    test "valid empty and invalid OSV archives are distinct" do
      assert {:ok, []} = OSV.parse_archive(Feeds.zip([]))
      {:ok, {_, archive}} = :zip.create(~c"all.zip", [{~c"record.json", "{}"}], [:memory])
      assert {:error, {:invalid_osv_records, 1}} = OSV.parse_archive(archive)

      assert {:error, {:archive_too_large, :uncompressed}} =
               VulnCheck.Feeds.Archive.inflate(:zlib.gzip("valid data"), 31, 1)
    end

    test "offline mode uses the cache and reports missing CVE records", %{opts: opts} do
      ws = workspace([{"ash", "3.34.2"}])
      config = config()
      assert {:error, :offline_cache_missing} = Store.load(ws, %{config | offline: true}, opts)

      # Prime only the OSV archive.
      assert {:ok, _} = Store.load(ws, config, Keyword.put(opts, :enrich, false))
      assert {:ok, result} = Store.load(ws, %{config | offline: true}, opts)
      assert [%Advisory{enriched: false}] = result.advisories
      assert [warning] = result.warnings
      assert warning =~ "offline"
      assert hd(result.advisories).affected_routines == [MFA.new("Elixir.Ash", "count", 2)]
      assert hd(result.advisories).symbol_source == :text
    end

    test "network failures while enriching keep the advisory", %{opts: opts} do
      ws = workspace([{"ash", "3.34.2"}])
      config = config()

      opts =
        Keyword.merge(opts,
          cna_base_url: "http://127.0.0.1:1",
          mitre_base_url: "http://127.0.0.1:1"
        )

      assert {:ok, result} = Store.load(ws, config, opts)
      assert [%Advisory{enriched: false}] = result.advisories
      assert [warning] = result.warnings
      assert warning =~ "could not fetch CVE 5.1 record for CVE-2026-101028"
    end

    test "imports bundles before reading feeds", %{opts: opts} do
      source = config()
      ws = workspace([{"plug", "1.16.2"}])
      assert {:ok, _} = Store.load(ws, source, opts)
      bundle = Path.join(Tmp.mkdir!("store-bundle"), "feeds.tar.gz")
      assert {:ok, _} = Cache.export_bundle(source, bundle)

      target = config(offline: true, bundle: bundle)
      assert {:ok, %{advisories: [plug]}} = Store.load(ws, target, opts)
      assert plug.enriched

      broken = config(offline: true, bundle: Path.join(Tmp.mkdir!("x"), "missing.tar.gz"))
      assert {:error, {:bundle, _}} = Store.load(ws, broken, opts)
    end

    test "reports feed errors", %{opts: opts} do
      ws = workspace([{"plug", "1.16.2"}])
      bad = Keyword.put(opts, :osv_url, "http://127.0.0.1:1/osv/all.zip")
      assert {:error, {:osv_feed, _}} = Store.load(ws, config(), bad)
    end
  end

  describe "EefCna.apply_record/2" do
    test "preserves Hex identity under a lock alias and scopes symbols to the installed version" do
      [advisory] =
        OSV.parse_record(%{
          "id" => "CVE-2026-1",
          "affected" =>
            for version <- ["1.0.0", "2.0.0"] do
              %{
                "package" => %{"ecosystem" => "Hex", "name" => "fixture"},
                "versions" => [version],
                "ecosystem_specific" => %{
                  "affected_functions" => ["Fixture.osv_#{hd(String.split(version, "."))}/0"]
                }
              }
            end
        })

      pkg = %Package{
        name: "local_alias",
        hex_name: "fixture",
        version: "1.0.0",
        source: :hex,
        scope: :prod
      }

      ws = %{workspace([]) | packages: %{pkg.name => pkg}}
      assert [matched] = Store.match(OSV.index([advisory]), ws)
      assert matched.package == "local_alias"
      assert matched.source_package == "fixture"
      assert matched.affected_routines == [MFA.new("Fixture", "osv_1", 0)]

      product = fn purl, version, function ->
        %{
          "packageURL" => purl,
          "defaultStatus" => "unaffected",
          "versions" => [%{"version" => version, "status" => "affected"}],
          "programRoutines" => [%{"name" => "Fixture.#{function}/0"}]
        }
      end

      entries = [
        product.("pkg:hex/fixture_extra", "1.0.0", "foreign"),
        product.("pkg:hex/fixture", "2.0.0", "other_version"),
        product.("pkg:hex/fixture@1.0.0?repository_url=example", "1.0.0", "cna")
      ]

      record = %{"containers" => %{"cna" => %{"affected" => entries}}}
      enriched = EefCna.apply_record(matched, record)
      assert enriched.enriched
      assert enriched.symbol_source == :osv_and_cve

      assert enriched.affected_routines == [
               MFA.new("Fixture", "osv_1", 0),
               MFA.new("Fixture", "cna", 0)
             ]

      finding = %Finding{
        advisory_id: enriched.id,
        package: pkg.name,
        installed_version: pkg.version,
        severity: :unknown,
        verdict: :potentially_reachable,
        reason: :missing_beam_debug_info
      }

      assert VulnCheck.Explain.format(%{
               advisories: [enriched],
               local: %{workspace: ws, findings: [finding]},
               warnings: []
             }) =~ "Installed: local_alias 1.0.0"
    end

    test "adds metrics, CWEs, OTP constraints and CVE version ranges" do
      advisory = %Advisory{id: "CVE-2026-1", package: "hex_core"}

      record =
        Feeds.cve_record("CVE-2026-1", "hex_core", ["hex_http_httpc:http_options/2"],
          cvss: {8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
          versions: [%{"version" => "0", "lessThan" => "0.10.3", "status" => "affected"}],
          description: "Only affects deployments running on OTP 25 and earlier."
        )

      enriched = EefCna.apply_record(advisory, record)
      assert enriched.affected_routines == [MFA.new("hex_http_httpc", "http_options", 2)]
      assert enriched.affected_modules == ["hex_http_httpc"]
      assert enriched.cvss_score == 8.1
      assert enriched.severity == :high
      assert enriched.otp_constraints == "<= 25"
      assert enriched.fixed_versions == ["0.10.3"]
      assert enriched.enriched

      other_package = EefCna.apply_record(%Advisory{id: "CVE-2026-1", package: "other"}, record)
      assert other_package.affected_routines == []
      refute EefCna.apply_record(advisory, %{}).enriched
    end

    test "keeps the highest score of the merged records and the CVE record" do
      v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"

      merged = %Advisory{
        id: "EEF-CVE-2026-2",
        aliases: ["CVE-2026-2", "GHSA-x"],
        package: "bandit",
        cvss_score: 7.5,
        cvss_vector: v3,
        severity: :high
      }

      higher = Feeds.cve_record("CVE-2026-2", "bandit", [], cvss: {9.1, "CVSS:3.1/higher"})
      enriched = EefCna.apply_record(merged, higher)

      assert {enriched.cvss_score, enriched.cvss_vector, enriched.severity} ==
               {9.1, nil, :critical}

      lower = Feeds.cve_record("CVE-2026-2", "bandit", [], cvss: {5.0, "CVSS:3.1/lower"})
      kept = EefCna.apply_record(merged, lower)
      assert {kept.cvss_score, kept.cvss_vector, kept.severity} == {7.5, v3, :high}
    end

    test "advisories without a CVE id are not fetched" do
      advisory = %Advisory{id: "GHSA-only", package: "x"}
      assert {:ok, ^advisory} = EefCna.enrich(advisory, config(offline: true))
    end
  end

  describe "text hints" do
    test "only explicit signatures with arity are extracted" do
      text = """
      The `Plug.CSRFProtection.valid_state_and_csrf_token?/2` check and
      `hex_http_httpc:http_options/2` are affected. `decode` and `Ash.read` and `2/3` are not.
      """

      assert TextHints.symbols(text) == [
               MFA.new("Elixir.Plug.CSRFProtection", "valid_state_and_csrf_token?", 2),
               MFA.new("hex_http_httpc", "http_options", 2)
             ]

      assert TextHints.symbols(nil) == []
    end

    test "OTP constraints require an affected-context sentence" do
      assert TextHints.otp_constraint("Vulnerable on OTP 24, 25 and 26.") == "24 || 25 || 26"
      assert TextHints.otp_constraint("Only affects releases before OTP 26.") == "< 26"
      assert TextHints.otp_constraint("Affects OTP <= 25 when verify_none is set.") == "<= 25"
      assert TextHints.otp_constraint("Affects OTP 24 and later.") == nil
      assert TextHints.otp_constraint("Fixed in OTP 26 and 27.") == nil
      assert TextHints.otp_constraint("This does not affect OTP 24 and 25.") == nil
      assert TextHints.otp_constraint("This affects OTP 24 and 25 and later.") == nil
      assert TextHints.otp_constraint("This is exploitable before OTP 27.3.") == "< 27.3"
      assert TextHints.otp_constraint("Vulnerable on OTP 26.2 and 27.3.") == "26.2 || 27.3"
      assert TextHints.otp_constraint(nil) == nil
    end
  end

  test "CVSS v3 scoring matches the specification examples" do
    assert CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H") == 9.9
    assert CVSS.base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert CVSS.base_score("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N") == 4.0
    assert CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert CVSS.base_score("CVSS:3.1/AV:X/AC:L") == nil
    assert CVSS.version("CVSS:4.0/AV:N") == 4
    assert CVSS.version(nil) == nil
  end

  test "rejects unknown revisions, repeated fields and invalid optional fields" do
    base = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert CVSS.base_score("CVSS:3.9/" <> base) == nil
    assert CVSS.base_score("CVSS:3.1/" <> base <> "/AV:L") == nil
    assert CVSS.base_score("CVSS:3.1/" <> base <> "/RL:invalid") == nil
    assert CVSS.base_score("CVSS:3.1/" <> base <> "/RL:X") == 9.8
  end

  describe "git dependency matching" do
    alias VulnCheck.Workspace.GitUrl

    test "normalizes git URLs without creating atoms" do
      before = :erlang.system_info(:atom_count)

      assert GitUrl.repo_slug("https://github.com/benoitc/hackney.git") == "benoitc/hackney"
      assert GitUrl.repo_slug("git@github.com:BenoitC/Hackney.git") == "benoitc/hackney"
      assert GitUrl.repo_slug("ssh://git@github.com/benoitc/hackney") == "benoitc/hackney"
      assert GitUrl.repo_slug("benoitc/hackney") == "benoitc/hackney"
      assert GitUrl.repo_slug("file:///tmp/obscure_local_repo_xyz") == nil
      assert GitUrl.repo_slug("") == nil

      assert :erlang.system_info(:atom_count) == before
    end

    test "matches git dependencies by tag, git-only OSV record, pinned SHA and fork without dropping uncertainty" do
      git_only_osv = %{
        "id" => "EEF-CVE-2026-99001",
        "aliases" => ["CVE-2026-99001"],
        "summary" => "Git-only advisory for hackney",
        "affected" => [
          %{
            "ranges" => [
              %{
                "type" => "GIT",
                "repo" => "https://github.com/benoitc/hackney.git",
                "events" => [
                  %{"introduced" => "0"},
                  %{"fixed" => "deadbeef1234"}
                ]
              }
            ]
          }
        ]
      }

      hex_osv = %{
        "id" => "EEF-CVE-2026-99002",
        "aliases" => ["CVE-2026-99002"],
        "summary" => "SemVer advisory for hackney",
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "hackney"},
            "ranges" => [
              %{
                "type" => "SEMVER",
                "events" => [%{"introduced" => "1.18.0"}, %{"fixed" => "1.18.2"}]
              }
            ]
          }
        ]
      }

      zip = Feeds.zip([git_only_osv, hex_osv])
      config = config()

      :ok =
        VulnCheck.Cache.atomic_write(
          Path.join(VulnCheck.Cache.feeds_dir(config), "osv_hex_all.zip"),
          zip
        )

      # 1) Upstream benoitc/hackney at tag 1.18.1
      ws_tag = %Workspace{
        root_dir: "/tmp/git-tag",
        project_name: "demo",
        project_type: :mix,
        env: :prod,
        otp_release: "27",
        packages: %{
          "hackney" => %Package{
            name: "hackney",
            version: "1.18.1",
            source: :git,
            scope: :prod,
            git_url: "https://github.com/benoitc/hackney.git",
            git_ref: "abc123"
          }
        }
      }

      assert {:ok, res_tag} =
               Store.load(ws_tag, %{config | offline: true}, enrich: false, retired: false)

      assert res_tag.stats.sources == %{git: 1}
      by_id = Map.new(res_tag.advisories, &{&1.id, &1})
      assert by_id["EEF-CVE-2026-99002"].git_match_status == :confirmed
      assert by_id["EEF-CVE-2026-99001"].git_match_status == :uncertain
      assert Enum.any?(res_tag.warnings, &(&1 =~ "EEF-CVE-2026-99001"))

      # 2) Pinned SHA without tag
      ws_sha = put_in(ws_tag.packages["hackney"].version, "abcdef123456")

      assert {:ok, res_sha} =
               Store.load(ws_sha, %{config | offline: true}, enrich: false, retired: false)

      assert Enum.all?(res_sha.advisories, &(&1.git_match_status == :uncertain))

      # 3) Fork with an apparently fixed tag still stays uncertain
      ws_fork =
        ws_tag
        |> put_in(
          [Access.key(:packages), "hackney", Access.key(:git_url)],
          "https://github.com/fork/hackney.git"
        )
        |> put_in([Access.key(:packages), "hackney", Access.key(:version)], "1.18.5")

      assert {:ok, res_fork} =
               Store.load(ws_fork, %{config | offline: true}, enrich: false, retired: false)

      assert Enum.any?(
               res_fork.advisories,
               &(&1.id == "EEF-CVE-2026-99002" and &1.git_match_status == :uncertain)
             )

      # 4) Obscure URL preserves hygiene warning without crashing
      ws_obscure = put_in(ws_tag.packages["hackney"].git_url, "file:///tmp/custom_obscure_url")

      assert {:ok, res_obs} =
               Store.load(ws_obscure, %{config | offline: true}, enrich: false, retired: false)

      assert Enum.any?(res_obs.warnings, &(&1 =~ "git dependency"))
    end
  end
end
