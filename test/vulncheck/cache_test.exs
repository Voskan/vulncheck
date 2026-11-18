defmodule VulnCheck.CacheTest do
  use ExUnit.Case, async: true

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Test.{HTTPServer, Tmp}

  defp config(extra \\ []) do
    dir = Tmp.mkdir!("cache")
    project = Tmp.mkdir!("cache-project")
    struct(%Config{project_dir: project, cache_dir: dir}, extra)
  end

  @fast [http_opts: [retry_delay_ms: 1, retries: 0]]

  test "default directory honours XDG_CACHE_HOME and explicit settings" do
    assert Cache.dir(%Config{cache_dir: "/var/cache/x"}) == "/var/cache/x"
    assert Cache.dir(cache_dir: "/opt/c") == "/opt/c"
    assert Cache.dir(%Config{}) =~ "vulncheck"
    assert Cache.feeds_dir(%Config{cache_dir: "/c"}) == "/c/feeds"
    assert Cache.beam_dir(%Config{cache_dir: "/c"}) == "/c/beam-v3"
  end

  test "atomic writes survive 20 concurrent writers" do
    dir = Tmp.mkdir!("atomic")
    path = Path.join(dir, "feeds/osv_hex_all.zip")

    payloads = for i <- 1..20, do: String.duplicate(<<i>>, 64 * 1024)

    payloads
    |> Enum.map(fn payload -> Task.async(fn -> Cache.atomic_write(path, payload) end) end)
    |> Enum.each(fn task -> assert Task.await(task) == :ok end)

    final = File.read!(path)
    assert final in payloads
    assert Path.wildcard(Path.join(dir, "feeds/*.tmp.*")) == []
  end

  test "atomic_write reports failures" do
    dir = Tmp.mkdir!("atomic-fail")
    File.write!(Path.join(dir, "file"), "x")

    assert {:error, {:cache_write_failed, _, _}} =
             Cache.atomic_write(Path.join(dir, "file/sub"), "y")
  end

  describe "fetch/4" do
    test "downloads, caches and revalidates with ETag" do
      server =
        HTTPServer.start!(fn request ->
          if request.headers["if-none-match"] == "\"abc\"" do
            {304, [], ""}
          else
            {200, [{"etag", "\"abc\""}], "payload"}
          end
        end)

      config = config(cache_ttl_seconds: 3600)
      url = server.url <> "/all.zip"

      assert {:ok, "payload", :network} = Cache.fetch(url, "osv_hex_all.zip", config, @fast)
      meta = Cache.read_meta(Path.join(Cache.feeds_dir(config), "osv_hex_all.zip"))
      assert meta["etag"] == "\"abc\""
      assert meta["sha256"] == Cache.sha256("payload")
      assert is_integer(meta["fetched_at_unix"])

      # fresh: no request
      assert {:ok, "payload", :cached} = Cache.fetch(url, "osv_hex_all.zip", config, @fast)
      assert length(HTTPServer.requests(server)) == 1

      # stale: conditional request answered with 304
      assert {:ok, "payload", :revalidated} =
               Cache.fetch(url, "osv_hex_all.zip", %{config | cache_ttl_seconds: 0}, @fast)

      assert [_, %{headers: %{"if-none-match" => "\"abc\""}}] = HTTPServer.requests(server)

      # forced refresh
      assert {:ok, "payload", :revalidated} =
               Cache.fetch(url, "osv_hex_all.zip", config, [force: true] ++ @fast)
    end

    test "immutable entries are never revalidated" do
      server = HTTPServer.start!(fn _ -> {200, [], "{\"cve\":1}"} end)
      config = config(cache_ttl_seconds: 0)
      url = server.url <> "/cves/CVE-1.json"

      assert {:ok, _, :network} =
               Cache.fetch(url, "cves/CVE-1.json", config, [immutable: true] ++ @fast)

      assert {:ok, _, :cached} =
               Cache.fetch(url, "cves/CVE-1.json", config, [immutable: true] ++ @fast)

      assert length(HTTPServer.requests(server)) == 1
      assert Cache.list_feed_files(config) == ["cves/CVE-1.json", "cves/CVE-1.json.meta.json"]
      assert {:ok, "{\"cve\":1}"} = Cache.read_feed(config, "cves/CVE-1.json")
    end

    test "offline mode never touches the network" do
      config = config(offline: true)

      assert {:error, :offline_cache_missing} =
               Cache.fetch("https://example.invalid/x", "x.json", config)

      :ok = Cache.atomic_write(Path.join(Cache.feeds_dir(config), "x.json"), "cached")
      assert {:ok, "cached", :cached} = Cache.fetch("https://example.invalid/x", "x.json", config)
    end

    test "falls back to a stale copy when the network fails" do
      server = HTTPServer.start!(fn _ -> {200, [], "v1"} end)
      config = config(cache_ttl_seconds: 0)
      url = server.url <> "/feed"
      assert {:ok, "v1", :network} = Cache.fetch(url, "feed", config, @fast)

      HTTPServer.set_handler(server, fn _ -> {500, [], "boom"} end)
      assert {:ok, "v1", :stale} = Cache.fetch(url, "feed", config, @fast)

      HTTPServer.set_handler(server, fn _ -> {404, [], ""} end)
      assert {:error, {:http_status, 404}} = Cache.fetch(url, "feed", config, @fast)

      GenServer.stop(server.pid)
      assert {:ok, "v1", :stale} = Cache.fetch(url, "feed", config, @fast)
      assert {:error, _} = Cache.fetch(url, "other", config, @fast)
    end

    test "a partial refresh leaves the complete cached body intact" do
      server = HTTPServer.start!(fn _ -> {200, [], "complete"} end)
      config = config(cache_ttl_seconds: 0)

      assert {:ok, "complete", :network} = Cache.fetch(server.url, "feed", config, @fast)

      HTTPServer.set_handler(server, fn _ ->
        {206, [{"content-range", "bytes 0-3/8"}], "part"}
      end)

      assert {:ok, "complete", :stale} = Cache.fetch(server.url, "feed", config, @fast)
      assert {:ok, "complete"} = Cache.read_feed(config, "feed")

      assert Cache.read_meta(Path.join(Cache.feeds_dir(config), "feed"))["sha256"] ==
               Cache.sha256("complete")
    end
  end

  describe "beam summaries" do
    test "round-trips summaries and treats corrupt or unsafe entries as misses" do
      config = config()
      sha = Cache.sha256("beam bytes")
      summary = %VulnCheck.Types.ModuleSummary{module: "Elixir.Demo"}
      assert :miss = Cache.get_beam(config, sha)
      assert :ok = Cache.put_beam(config, sha, summary)
      assert {:ok, ^summary} = Cache.get_beam(config, sha)
      assert {:ok, ^summary} = Cache.get_beam([cache_dir: config.cache_dir], sha)

      path = Path.join(Cache.beam_dir(config), sha <> ".etf")
      File.write!(path, "garbage")
      assert :miss = Cache.get_beam(config, sha)

      name = "zz_never_existing_atom_#{System.unique_integer([:positive])}"
      File.write!(path, <<131, 119, byte_size(name)>> <> name)
      assert :miss = Cache.get_beam(config, sha)

      other = Cache.sha256("other")
      :ok = Cache.put_beam(config, other, summary)
      File.cp!(Path.join(Cache.beam_dir(config), other <> ".etf"), path)
      assert :miss = Cache.get_beam(config, sha)
    end
  end

  describe "bundles" do
    test "export then import into a clean cache and read offline" do
      source = config()
      feeds = Cache.feeds_dir(source)

      {:ok, {_, zip}} =
        :zip.create(~c"all.zip", [{~c"EEF-1.json", "{}"}, {~c"GHSA-2.json", "{}"}], [:memory])

      :ok = Cache.atomic_write(Path.join(feeds, "osv_hex_all.zip"), zip)
      :ok = Cache.atomic_write(Path.join(feeds, "cves/CVE-2026-1.json"), "{\"id\":1}")

      bundle = Path.join(Tmp.mkdir!("bundle"), "feeds.tar.gz")
      assert {:ok, manifest} = Cache.export_bundle(source, bundle)
      assert manifest["advisory_count"] == 2
      assert length(manifest["files"]) == 2
      assert File.regular?(bundle)

      target = config(offline: true)
      assert {:ok, imported} = Cache.import_bundle(bundle, target)
      assert imported["advisory_count"] == 2

      assert {:ok, ^zip, :cached} =
               Cache.fetch("https://example.invalid/all.zip", "osv_hex_all.zip", target)

      assert {:ok, "{\"id\":1}", :cached} =
               Cache.fetch("https://example.invalid/c", "cves/CVE-2026-1.json", target)
    end

    test "refuses to export an empty cache" do
      assert {:error, :empty_cache} =
               Cache.export_bundle(config(), Path.join(Tmp.mkdir!("e"), "x.tar.gz"))
    end

    test "rejects Tar Slip paths, symlinks, tampering and garbage" do
      dir = Tmp.mkdir!("evil")
      target = %Config{project_dir: dir, cache_dir: Path.join(dir, "workspace/cache")}

      evil = Path.join(dir, "evil.tar.gz")

      :ok =
        :erl_tar.create(
          String.to_charlist(evil),
          [{~c"manifest.json", "{}"}, {~c"../../etc/passwd", "root::0:0"}],
          [:compressed]
        )

      assert {:error, {:unsafe_bundle_entry, "../../etc/passwd", :path}} =
               Cache.import_bundle(evil, target)

      refute File.exists?(Path.expand("../../etc/passwd", Cache.feeds_dir(target)))

      absolute = Path.join(dir, "abs.tar.gz")
      :ok = :erl_tar.create(String.to_charlist(absolute), [{~c"/etc/x", "x"}], [:compressed])
      assert {:error, {:unsafe_bundle_entry, _, _}} = Cache.import_bundle(absolute, target)

      File.write!(Path.join(dir, "real"), "x")
      File.ln_s!("/etc/passwd", Path.join(dir, "link"))
      linked = Path.join(dir, "link.tar.gz")

      :ok =
        :erl_tar.create(
          String.to_charlist(linked),
          [{~c"link", String.to_charlist(Path.join(dir, "link"))}],
          [:compressed]
        )

      assert {:error, {:unsafe_bundle_entry, "link", :symlink}} =
               Cache.import_bundle(linked, target)

      tampered = Path.join(dir, "tampered.tar.gz")

      manifest =
        JSON.encode!(%{
          "format" => "vulncheck-feeds-bundle",
          "files" => [%{"path" => "osv_hex_all.zip", "sha256" => Cache.sha256("original")}]
        })

      :ok =
        :erl_tar.create(
          String.to_charlist(tampered),
          [{~c"manifest.json", manifest}, {~c"osv_hex_all.zip", "modified"}],
          [:compressed]
        )

      assert {:error, {:invalid_bundle, {:checksum_mismatch, "osv_hex_all.zip"}}} =
               Cache.import_bundle(tampered, target)

      unlisted = Path.join(dir, "unlisted.tar.gz")

      :ok =
        :erl_tar.create(
          String.to_charlist(unlisted),
          [{~c"manifest.json", manifest}, {~c"extra.json", "{}"}],
          [:compressed]
        )

      assert {:error, {:invalid_bundle, {:unlisted_file, "extra.json"}}} =
               Cache.import_bundle(unlisted, target)

      no_manifest = Path.join(dir, "nomanifest.tar.gz")
      :ok = :erl_tar.create(String.to_charlist(no_manifest), [{~c"a.json", "{}"}], [:compressed])

      assert {:error, {:invalid_bundle, :missing_manifest}} =
               Cache.import_bundle(no_manifest, target)

      garbage = Path.join(dir, "garbage.tar.gz")
      File.write!(garbage, "not a tarball")
      assert {:error, {:invalid_bundle, _}} = Cache.import_bundle(garbage, target)
    end

    test "safe_name?/1" do
      assert Cache.safe_name?("cves/CVE-1.json")
      refute Cache.safe_name?("../x")
      refute Cache.safe_name?("a/../../x")
      refute Cache.safe_name?("/abs")
      refute Cache.safe_name?("C:/win")
      refute Cache.safe_name?("a\\b")
      refute Cache.safe_name?("a//b")
      refute Cache.safe_name?("")
    end
  end
end
