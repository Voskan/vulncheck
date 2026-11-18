defmodule VulnCheck.Feeds.OsvAndEefTest do
  # Measures the global atom table, so it must not run concurrently.
  use ExUnit.Case, async: false

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Feeds.{CVSS, EefCna, OSV, Store, TextHints}
  alias VulnCheck.Test.{Feeds, HTTPServer, Tmp}
  alias VulnCheck.Types.{Advisory, MFA, Package, Workspace}

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
      assert multi.cvss_score == nil
      assert multi.affected_routines == [MFA.new("Elixir.A.B", "run", 2)]
      assert multi.affected_modules == ["Elixir.A.B"]
      assert multi.symbol_source == :osv
    end

    test "rejects invalid archives" do
      assert {:error, {:invalid_archive, _}} = OSV.parse_archive("not a zip")
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
      assert EefCna.apply_record(advisory, %{}).enriched
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
end
