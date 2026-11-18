defmodule VulnCheck.CLITest do
  use ExUnit.Case, async: true

  alias VulnCheck.{CLI, Config}
  alias VulnCheck.Test.{Feeds, HTTPServer, Project, Tmp}

  defp cli(argv, opts \\ []) do
    {:ok, stdout} = StringIO.open("")
    {:ok, stderr} = StringIO.open("")
    code = CLI.run(argv, Keyword.merge([stdout: stdout, stderr: stderr], opts))
    {_, out} = StringIO.contents(stdout)
    {_, err} = StringIO.contents(stderr)
    {code, out, err}
  end

  defp scan_args(root, cache, extra \\ []),
    do:
      ["--project-dir", root, "--cache-dir", cache, "--offline", "--no-color", "--no-retired"] ++
        extra

  describe "version and help" do
    test "print and exit 0" do
      assert {0, "vulncheck " <> version, ""} = cli(["--version"])
      assert String.trim(version) == VulnCheck.version()
      assert {0, _, ""} = cli(["-v"])
      assert {0, help, ""} = cli(["--help"])
      assert help =~ "Exit codes: 0 clean, 1 policy violation, 2 execution error."

      for flag <- ~w(--project-dir --env --format --output --sbom --vex --fail-on --min-severity
                     --show-unreachable --diff --baseline --write-baseline --forbid-new-suppressions
                     --otp-version --offline --bundle --no-color --quiet) do
        assert help =~ flag
      end
    end
  end

  describe "scan exit codes" do
    test "0 on a project without vulnerable dependencies" do
      root = Project.shop!(deps: [{"jason", "1.4.4"}])
      assert {0, out, ""} = cli(scan_args(root, Project.cache!()))
      assert out =~ "No known advisories affect the locked dependencies."
    end

    test "1 on a reachable finding; 0 with --fail-on none" do
      root = Project.shop!()
      cache = Project.cache!()

      assert {1, out, ""} = cli(scan_args(root, cache))
      assert out =~ "[REACHABLE] CVE-2026-54892"
      assert out =~ "Shop.Web.params/1"
      assert out =~ "Exit code: 1 (threshold: --fail-on potentially_reachable, --min-severity low)"

      assert {0, _, ""} = cli(scan_args(root, cache, ["--fail-on", "none"]))
      assert {0, _, ""} = cli(scan_args(root, cache, ["--min-severity", "critical"]))
    end

    test "--fail-on reachable passes when findings are only potentially reachable" do
      root = Project.shop!()
      cache = Project.cache!(plug_routines: false)

      assert {1, out, ""} = cli(scan_args(root, cache))
      assert out =~ "[POTENTIALLY REACHABLE] CVE-2026-54892"
      refute out =~ "[REACHABLE]"

      assert {0, _, ""} = cli(scan_args(root, cache, ["--fail-on", "reachable"]))
    end

    test "1 when a pull request adds a suppression under --forbid-new-suppressions" do
      root = Project.shop!()
      cache = Project.cache!()
      git = fn args -> {_, 0} = System.cmd("git", args, cd: root, stderr_to_stdout: true) end

      git.(["init", "-q"])
      git.(["add", "mix.exs", "mix.lock"])

      git.([
        "-c",
        "user.name=ci",
        "-c",
        "user.email=ci@example.invalid",
        "commit",
        "-q",
        "-m",
        "init"
      ])

      Tmp.write!(root, ".vulncheck.ignore", """
      [%{id: "CVE-2026-54892", package: "plug", reason: "patched at the edge", expires: "2099-01-01"}]
      """)

      assert {0, _, ""} = cli(scan_args(root, cache))

      assert {1, out, ""} =
               cli(scan_args(root, cache, ["--diff", "HEAD", "--forbid-new-suppressions"]))

      assert out =~ "Policy violations:"
      assert out =~ "new suppression of CVE-2026-54892"
    end

    test "2 on invalid flags, a missing lockfile or an empty offline cache" do
      assert {2, "", err} = cli(["--unknown-flag"])
      assert err =~ "invalid option(s): --unknown-flag"

      assert {2, "", err} = cli(["--format", "pdf"])
      assert err =~ "invalid value for --format"

      no_lock = Tmp.mkdir!("cli-nolock")
      Tmp.write!(no_lock, "mix.exs", "defmodule X.MixProject do\nend\n")
      assert {2, "", err} = cli(scan_args(no_lock, Project.cache!()))
      assert err =~ "mix.lock"

      root = Project.shop!()
      assert {2, "", err} = cli(scan_args(root, Tmp.mkdir!("cli-empty-cache")))
      assert err =~ "no cached advisory feed is available offline"

      assert {2, "", err} = cli(["frobnicate"])
      assert err =~ ~s(unknown command "frobnicate")
    end

    test "2 on an invalid .vulncheck.exs" do
      root = Project.shop!(deps: [{"jason", "1.4.4"}])
      Tmp.write!(root, ".vulncheck.exs", "[fail_on: :sometimes]")
      assert {2, "", err} = cli(scan_args(root, Project.cache!()))
      assert err =~ ".vulncheck.exs"
    end
  end

  describe "artifacts" do
    test "writes the report, SBOM and VEX in one run" do
      root = Project.shop!()
      out_dir = Tmp.mkdir!("cli-out")

      argv =
        scan_args(root, Project.cache!(), [
          "--format",
          "json",
          "--output",
          "report.json",
          "--sbom",
          "sbom.cdx.json",
          "--vex",
          "vex.openvex.json"
        ])

      assert {1, "", ""} = cli(argv, cwd: out_dir)

      report = out_dir |> Path.join("report.json") |> File.read!() |> JSON.decode!()
      assert report["schema_version"] == "1.0.0"
      assert report["summary"]["reachable"] == 1

      sbom = out_dir |> Path.join("sbom.cdx.json") |> File.read!() |> JSON.decode!()
      assert sbom["bomFormat"] == "CycloneDX"
      assert Enum.any?(sbom["components"], &(&1["purl"] == "pkg:hex/plug@1.16.2"))

      vex = out_dir |> Path.join("vex.openvex.json") |> File.read!() |> JSON.decode!()
      assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"

      assert Enum.map(vex["statements"], & &1["status"]) |> Enum.sort() == [
               "affected",
               "not_affected"
             ]

      assert out_dir |> File.ls!() |> Enum.sort() == [
               "report.json",
               "sbom.cdx.json",
               "vex.openvex.json"
             ]
    end

    test "every format renders" do
      root = Project.shop!()
      cache = Project.cache!()

      for format <- Config.formats() do
        assert {1, out, ""} =
                 cli(scan_args(root, cache, ["--format", Atom.to_string(format), "--quiet"]))

        assert out != ""
      end
    end
  end

  describe "init" do
    test "writes a parseable configuration and refuses to overwrite it" do
      root =
        Project.shop!(
          deps: [
            {"tesla", "1.11.0"},
            {"mint", "1.6.2"},
            {"ecto_sql", "3.12.0"},
            {"postgrex", "0.19.1"}
          ]
        )

      Tmp.write!(
        root,
        "config/config.exs",
        "import Config\nconfig :tesla, adapter: Tesla.Adapter.Mint\n"
      )

      Tmp.write!(root, "lib/shop/release.ex", """
      defmodule Shop.Release do
        def migrate do
          :ok
        end

        def rollback(repo, version), do: {repo, version}
      end
      """)

      assert {0, out, ""} = cli(["init", "--project-dir", root])
      assert out =~ "Wrote #{Path.join(root, ".vulncheck.exs")}"

      content = File.read!(Path.join(root, ".vulncheck.exs"))
      assert content =~ "# VulnCheck configuration for shop (mix project)."
      assert content =~ "# Detected: Tesla, Ecto."
      assert content =~ "    tesla: Tesla.Adapter.Mint,\n"
      assert content =~ "    # ecto: Ecto.Adapters.Postgres,\n"
      assert content =~ "    {Shop.Release, :migrate, 0},\n    {Shop.Release, :rollback, 2},\n"

      assert {:ok, config} = Config.from_cli_and_file(["--project-dir", root])
      assert config.fail_on == :potentially_reachable
      assert config.configured_adapters[:tesla] == ["Elixir.Tesla.Adapter.Mint"]

      assert [
               %VulnCheck.Types.MFA{module: "Elixir.Shop.Release", function: "migrate", arity: 0}
               | _
             ] = config.extra_entrypoints

      assert {2, "", err} = cli(["init", "--project-dir", root])
      assert err =~ "already exists; pass --force"

      File.write!(Path.join(root, ".vulncheck.exs"), "[]")
      assert {0, _, ""} = cli(["init", "--project-dir", root, "--force"])
      assert File.read!(Path.join(root, ".vulncheck.exs")) == content
    end

    test "works for projects without detectable frameworks" do
      root = Project.shop!(deps: [{"jason", "1.4.4"}], compile: false)
      assert {0, _, ""} = cli(["init", "--project-dir", root])
      assert {:ok, _} = Config.parse_config_file(Path.join(root, ".vulncheck.exs"))
    end
  end

  describe "explain" do
    test "describes the advisory with its local verdict and trace" do
      root = Project.shop!()
      cache = Project.cache!()

      assert {0, out, ""} =
               cli([
                 "explain",
                 "CVE-2026-54892",
                 "--project-dir",
                 root,
                 "--cache-dir",
                 cache,
                 "--offline",
                 "--no-retired"
               ])

      assert out =~ "CVE-2026-54892 — Quadratic-time nested parameter decoding in Plug.Conn.Query"
      assert out =~ "Advisory:  EEF-CVE-2026-54892 (aliases: CVE-2026-54892)"
      assert out =~ "Package:   plug"
      assert out =~ "Routines:  Plug.Conn.Query.decode/4 (source: cve)"
      assert out =~ "Fixed:"
      assert out =~ "Local project: shop (mix, env: prod)"
      assert out =~ "  Installed: plug 1.16.2"
      assert out =~ "  Verdict:   REACHABLE — call chain proven"
      assert out =~ "      2. Shop.Web.params/1"

      assert {0, out, ""} =
               cli([
                 "explain",
                 "ghsa-xj24-8f5c-pp5p",
                 "--project-dir",
                 root,
                 "--cache-dir",
                 cache,
                 "--offline",
                 "--no-retired"
               ])

      assert out =~ "Verdict:   UNREACHABLE — function not called"
    end

    test "separates platform routines from package routines" do
      advisory = %VulnCheck.Types.Advisory{
        id: "EEF-CVE-2026-108529",
        package: "bandit",
        summary: "quadratic work",
        affected_routines: [
          VulnCheck.Types.MFA.new("Elixir.Bandit.HTTP2.Connection", "do_pending_sends", 2),
          VulnCheck.Types.MFA.new("Elixir.List", "delete", 2)
        ],
        symbol_source: :cve
      }

      out =
        VulnCheck.Explain.format(%{query: "x", advisories: [advisory], local: nil, warnings: []})

      assert out =~ "Routines:  Bandit.HTTP2.Connection.do_pending_sends/2 (source: cve)"
      assert out =~ "Context:   List.delete/2 (Erlang/OTP or Elixir; not a target)"
    end

    test "fails for unknown advisories and missing ids" do
      cache = Project.cache!()
      dir = Tmp.mkdir!("cli-explain")

      assert {2, "", err} =
               cli([
                 "explain",
                 "CVE-1999-0001",
                 "--project-dir",
                 dir,
                 "--cache-dir",
                 cache,
                 "--offline"
               ])

      assert err =~ "advisory CVE-1999-0001 was not found"

      assert {2, "", err} =
               cli(["explain", "--project-dir", dir, "--cache-dir", cache, "--offline"])

      assert err =~ "explain requires exactly one advisory id"
    end

    test "is available from the public API" do
      assert {:ok, %{advisories: [advisory], local: nil}} =
               VulnCheck.explain("CVE-2026-101028",
                 project_dir: Tmp.mkdir!("api-explain"),
                 cache_dir: Project.cache!(),
                 offline: true
               )

      assert advisory.package == "ash"
      assert [%VulnCheck.Types.MFA{function: "run", arity: 4}] = advisory.affected_routines
    end
  end

  describe "feeds" do
    test "status, bundle and an offline scan from the bundle" do
      cache = Project.cache!()
      work = Tmp.mkdir!("cli-bundle")

      assert {0, status, ""} = cli(["feeds", "status", "--cache-dir", cache])
      assert status =~ "Cache: #{Path.join(cache, "feeds")}"
      assert status =~ "OSV Hex archive: 2 advisories"
      assert status =~ "CVE 5.1 records: 2 cached, 2 with function-level routines"

      assert {0, out, ""} =
               cli(["feeds", "bundle", "-o", "bundle.tar.gz", "--cache-dir", cache], cwd: work)

      assert out =~ "Wrote #{Path.join(work, "bundle.tar.gz")}"

      root = Project.shop!()
      fresh = Tmp.mkdir!("cli-fresh-cache")

      assert {1, out, ""} =
               cli(scan_args(root, fresh, ["--bundle", Path.join(work, "bundle.tar.gz")]))

      assert out =~ "[REACHABLE] CVE-2026-54892"

      assert {2, "", err} = cli(["feeds", "bundle", "--cache-dir", cache])
      assert err =~ "requires --output"

      assert {2, "", err} =
               cli(["feeds", "bundle", "-o", "x.tar.gz", "--cache-dir", Tmp.mkdir!("e")], cwd: work)

      assert err =~ "feed cache is empty"

      assert {2, "", err} =
               cli(
                 scan_args(root, Tmp.mkdir!("bad"), ["--bundle", Path.join(work, "missing.tar.gz")])
               )

      assert err =~ "cannot import the advisory bundle"
    end

    test "sync refreshes the archive and CVE records" do
      zip = Feeds.zip([Feeds.osv_ash(), Feeds.osv_plug()])
      ash = Feeds.cve_record("CVE-2026-101028", "ash", ["'Elixir.Ash.Actions.Aggregate':run/4"])

      server =
        HTTPServer.start!(fn
          %{path: "/osv/all.zip"} -> {200, [{"etag", ~s("v1")}], zip}
          %{path: "/cna/CVE-2026-101028.json"} -> {200, [], JSON.encode!(ash)}
          _ -> {404, [], ""}
        end)

      scan_opts = [
        osv_url: server.url <> "/osv/all.zip",
        cna_base_url: server.url <> "/cna",
        mitre_base_url: server.url <> "/mitre"
      ]

      cache = Tmp.mkdir!("cli-sync")

      assert {0, out, ""} = cli(["feeds", "sync", "--cache-dir", cache], scan_opts: scan_opts)
      assert out =~ "OSV Hex archive: 2 advisories for 2 packages (network)"
      assert out =~ "CVE 5.1 records: 1 available, 1 with function-level routines, 1 unavailable"

      assert {0, status, ""} = cli(["feeds", "status", "--cache-dir", cache])
      assert status =~ ~s(etag:    "v1")
      assert status =~ "ago)"

      assert {2, "", err} = cli(["feeds", "sync", "--cache-dir", cache, "--offline"])
      assert err =~ "needs network access"
      assert {2, "", _} = cli(["feeds", "prune"])
    end
  end
end
