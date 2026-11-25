defmodule VulnCheck.AuditV103RegressionTest do
  use ExUnit.Case, async: false

  alias VulnCheck.Beam.{CallGraph, Loader}
  alias VulnCheck.{CLI, Cache, Config, Diff, Entrypoints, ErlTerm, Git, HTTP, Ignore, Literal}
  alias VulnCheck.{Semver, Solver, Workspace}
  alias VulnCheck.Cache.Bundle
  alias VulnCheck.Entrypoints.Adapters
  alias VulnCheck.Report.{CycloneDX, Formatter, Markdown, SARIF}
  alias VulnCheck.Test.{Beams, Project, Tmp}
  alias VulnCheck.Types.{Advisory, Finding, MFA, Package, ScanReport, Summary, TraceHop}
  alias VulnCheck.Workspace.{GleamManifest, MixProject, RebarLock, Toml}

  defp mfa(mod, fun, arity), do: %MFA{module: mod, function: fun, arity: arity}

  defp advisory(id, pkg, opts) do
    %Advisory{
      id: id,
      aliases: Keyword.get(opts, :aliases, []),
      package: pkg,
      summary: Keyword.get(opts, :summary, id),
      severity: Keyword.get(opts, :severity, :high),
      affected_routines: Keyword.get(opts, :affected_routines, []),
      affected_modules: Keyword.get(opts, :affected_modules, []),
      otp_constraints: Keyword.get(opts, :otp_constraints, nil)
    }
  end

  defp run_cli(argv, opts \\ []) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")

    try do
      code = CLI.run(argv, Keyword.merge([stdout: out, stderr: err], opts))
      {_, stdout} = StringIO.contents(out)
      {_, stderr} = StringIO.contents(err)
      {code, stdout, stderr}
    after
      StringIO.close(out)
      StringIO.close(err)
    end
  end

  # -- F-01: Phoenix.Controller soundness & precision ----------------------------

  describe "F-01: Phoenix.Controller narrowing closes bypasses without regressing normal Phoenix routing" do
    defp build_phoenix_fixture!(name, extra_app_source, opts \\ []) do
      root = Tmp.mkdir!("v103-#{name}")
      ebin = &Path.join(root, "_build/prod/lib/#{&1}/ebin")

      if cfg = Keyword.get(opts, :config_exs) do
        Tmp.write!(root, "config/config.exs", cfg)
      end

      if rt = Keyword.get(opts, :runtime_exs) do
        Tmp.write!(root, "config/runtime.exs", rt)
      end

      router_body =
        Keyword.get(opts, :router_body, """
          def init(opts), do: opts
          def call(conn, opts), do: Phoenix.Router.__call__(conn, __match_route__(["safe"], "GET", opts, nil))
          def __match_route__(["safe"], "GET", _host, _opts), do: {DemoV103.Controller, :safe}
          def __routes__, do: [%{plug: DemoV103.Controller, plug_opts: :safe}]
        """)

      Beams.compile!(ebin.("vuln_dep"), [
        {"vuln_dep.ex",
         """
         defmodule VulnDep do
           def safe_vuln, do: :ok
           def secret_vuln, do: :boom
         end
         """}
      ])

      Beams.compile!(ebin.("phoenix"), [
        {"phoenix.ex",
         """
         defmodule Phoenix.Controller do
           @callback init(term()) :: term()
           @callback call(term(), term()) :: term()
           @callback action(term(), term()) :: term()
         end

         defmodule Phoenix.Router do
           def __call__(conn, {plug, opts}), do: plug.call(conn, plug.init(opts))
         end
         """}
      ])

      Beams.compile!(ebin.("bandit"), [
        {"bandit.ex",
         """
         defmodule Bandit do
           def child_spec(opts), do: %{id: Bandit, start: {Bandit, :start_link, [opts]}}
           def start_link(opts), do: Bandit.Pipeline.run(opts)
         end

         defmodule Bandit.Pipeline do
           def run(plug), do: plug.call(%{}, [])
         end
         """}
      ])

      Beams.compile!(ebin.("demo"), [
        {"demo.ex",
         """
         defmodule DemoV103.Controller do
           @behaviour Phoenix.Controller
           def init(action), do: action
           def call(conn, action), do: action(conn, action)
           def action(conn, action), do: apply(__MODULE__, action, [conn, %{}])
           def safe(_conn, _params), do: VulnDep.safe_vuln()
           def secret(_conn, _params), do: VulnDep.secret_vuln()
         end

         defmodule DemoV103.Router do
           #{router_body}
         end

         defmodule DemoV103.Application do
           def start(_type, _args) do
             _ = Bandit.child_spec(plug: DemoV103.Router)
             DemoV103.Router.call(%{}, [])
             DemoV103.Extra.run(%{})
             {:ok, self()}
           end
         end

         defmodule DemoV103.Extra do
           #{extra_app_source}
         end
         """}
      ])

      Beams.write_app!(ebin.("vuln_dep"), "vuln_dep")
      Beams.write_app!(ebin.("phoenix"), "phoenix")
      Beams.write_app!(ebin.("bandit"), "bandit")

      Beams.write_app!(ebin.("demo"), "demo",
        applications: [:kernel, :stdlib, :elixir, :phoenix, :bandit, :vuln_dep],
        mod: "Elixir.DemoV103.Application"
      )

      ws = %VulnCheck.Types.Workspace{
        root_dir: root,
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        root_apps: ["demo"],
        root_ebin_dirs: [ebin.("demo")],
        packages: %{
          "vuln_dep" => %Package{
            name: "vuln_dep",
            version: "1.0.0",
            source: :hex,
            scope: :prod,
            otp_app: "vuln_dep",
            ebin_dir: ebin.("vuln_dep")
          },
          "phoenix" => %Package{
            name: "phoenix",
            version: "1.7.14",
            source: :hex,
            scope: :prod,
            otp_app: "phoenix",
            ebin_dir: ebin.("phoenix")
          },
          "bandit" => %Package{
            name: "bandit",
            version: "1.5.0",
            source: :hex,
            scope: :prod,
            otp_app: "bandit",
            ebin_dir: ebin.("bandit")
          }
        }
      }

      loaded = Loader.load_workspace(ws, %Config{}, cache: false)
      graph = CallGraph.build(loaded.modules)
      {model, graph} = Entrypoints.build(ws, graph, %Config{})

      safe_mfa = mfa("Elixir.VulnDep", "safe_vuln", 0)
      secret_mfa = mfa("Elixir.VulnDep", "secret_vuln", 0)

      advisories = [
        advisory("ADV-SAFE", "vuln_dep", affected_routines: [safe_mfa]),
        advisory("ADV-SECRET", "vuln_dep", affected_routines: [secret_mfa])
      ]

      findings = Solver.solve(ws, graph, model, advisories, %Config{})
      Map.new(findings, &{&1.advisory_id, &1})
    end

    test "normal Phoenix.Router + Bandit keeps routed action :reachable and unrouted action :unreachable" do
      res = build_phoenix_fixture!("normal", "def run(_conn), do: :ok")
      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict == :unreachable
      assert res["ADV-SECRET"].reason == :function_not_called
    end

    test "P4A: indirect mod.call(conn, :secret) via module-returning helper prevents false negative" do
      res =
        build_phoenix_fixture!("p4a", """
        def run(conn) do
          mod = pick_controller()
          mod.call(conn, :secret)
        end

        defp pick_controller, do: DemoV103.Controller
        """)

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end

    test "P4A2: Plug.run-style tuple list dispatch prevents false negative" do
      res =
        build_phoenix_fixture!("p4a2", """
        def run(conn) do
          Enum.reduce([{DemoV103.Controller, :secret}], conn, fn {m, o}, c ->
            m.call(c, o)
          end)
        end
        """)

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end

    test "P4B: direct external Ctrl.action(conn, :secret) call prevents false negative" do
      res =
        build_phoenix_fixture!("p4b", """
        def run(conn), do: DemoV103.Controller.action(conn, :secret)
        """)

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end

    test "P4C: &Ctrl.call/2 and &Ctrl.action/2 function captures prevent false negative" do
      res_call =
        build_phoenix_fixture!("p4c-call", """
        def run(conn), do: invoke(&DemoV103.Controller.call/2, conn, :secret)
        defp invoke(fun, conn, opt), do: fun.(conn, opt)
        """)

      assert res_call["ADV-SAFE"].verdict == :reachable
      assert res_call["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]

      res_action =
        build_phoenix_fixture!("p4c-action", """
        def run(conn), do: invoke(&DemoV103.Controller.action/2, conn, :secret)
        defp invoke(fun, conn, opt), do: fun.(conn, opt)
        """)

      assert res_action["ADV-SAFE"].verdict == :reachable
      assert res_action["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end
  end

  # -- F-02 & F-22: MixProject literal env calls, branch merging, default args --

  describe "F-02 & F-22: MixProject literal env calls, scope union, and default arguments" do
    test "unconditional deps(:common) keeps only: :all and unions duplicate deps across branches" do
      src = """
      defmodule CommonDeps.MixProject do
        use Mix.Project

        def project, do: [app: :common_deps, version: "1.0.0", deps: deps()]

        defp deps, do: deps(:common) ++ deps(Mix.env())

        defp deps(:common) do
          [
            {:plug, "~> 1.16"},
            {:shared, "~> 1.0"}
          ]
        end

        defp deps(:prod) do
          [
            {:bandit, "~> 1.5"},
            {:shared, "~> 1.0", runtime: false}
          ]
        end

        defp deps(:dev), do: [{:dev_only, "~> 1.0"}, {:dev_or_test, "~> 1.0"}]
        defp deps(:test), do: [{:dev_or_test, "~> 1.0"}]
        defp deps(_), do: []
      end
      """

      {:ok, ast} = Literal.quote_string(src, file: "mix.exs")
      proj = MixProject.analyze(ast, "mix.exs")
      assert proj.deps_parsed == true
      by_name = Map.new(proj.deps, &{&1.name, &1})

      assert by_name["plug"].only == :all
      assert by_name["bandit"].only == ["prod"]
      assert by_name["dev_only"].only == ["dev"]
      assert Enum.sort(by_name["dev_or_test"].only) == ["dev", "test"]
      assert by_name["shared"].only == :all
      assert by_name["shared"].runtime == true
    end

    test "resolves default arguments on bodyless header and single-clause deps/1 helpers" do
      header_src = """
      defmodule DefaultHeader.MixProject do
        use Mix.Project

        def project, do: [app: :default_header, version: "1.0.0", deps: deps()]

        defp deps(env \\\\ Mix.env())
        defp deps(:prod), do: [{:prod_pkg, "~> 1.0"}]
        defp deps(:dev), do: [{:dev_pkg, "~> 1.0"}]
        defp deps(_), do: []
      end
      """

      {:ok, ast1} = Literal.quote_string(header_src, file: "mix.exs")
      proj1 = MixProject.analyze(ast1, "mix.exs")
      assert proj1.deps_parsed == true
      by1 = Map.new(proj1.deps, &{&1.name, &1})
      assert by1["prod_pkg"].only == ["prod"]
      assert by1["dev_pkg"].only == ["dev"]

      single_src = """
      defmodule DefaultSingle.MixProject do
        use Mix.Project

        def project, do: [app: :default_single, version: "1.0.0", deps: deps() ++ extra_deps()]

        defp deps(env \\\\ Mix.env()) do
          if env == :test, do: [{:test_pkg, "~> 1.0"}], else: [{:main_pkg, "~> 1.0"}]
        end

        defp extra_deps(tag \\\\ :common)
        defp extra_deps(:common), do: [{:extra_pkg, "~> 1.0"}]
      end
      """

      {:ok, ast2} = Literal.quote_string(single_src, file: "mix.exs")
      proj2 = MixProject.analyze(ast2, "mix.exs")
      assert proj2.deps_parsed == true
      by2 = Map.new(proj2.deps, &{&1.name, &1})
      assert by2["test_pkg"].only == ["test"]
      assert "prod" in by2["main_pkg"].only
      assert by2["extra_pkg"].only == :all
    end
  end

  # -- F-03: Adapters import_config + nested dynamic adapter detection ----------

  describe "F-03: Adapters import_config resolution and nested dynamic adapter detection" do
    test "follows static and env-templated import_config, respects guards, cycles, and root containment" do
      dir = Tmp.mkdir!("v103-adapters")

      Tmp.write!(dir, "config/config.exs", """
      import Config
      import_config "tesla.exs"
      import_config "\#{config_env()}.exs"
      if File.exists?("config/optional_missing.exs") do
        import_config "optional_missing.exs"
      end
      """)

      Tmp.write!(dir, "config/tesla.exs", """
      import Config
      config :tesla, adapter: Tesla.Adapter.Mint
      import_config "cycle_a.exs"
      """)

      Tmp.write!(dir, "config/cycle_a.exs", """
      import Config
      import_config "cycle_b.exs"
      """)

      Tmp.write!(dir, "config/cycle_b.exs", """
      import Config
      import_config "cycle_a.exs"
      """)

      Tmp.write!(dir, "config/prod.exs", """
      import Config
      config :swoosh, api_client: Swoosh.ApiClient.Finch
      """)

      ws = %VulnCheck.Types.Workspace{
        root_dir: dir,
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        packages: %{
          "tesla" => %Package{name: "tesla", version: "1.11.0", source: :hex, scope: :prod},
          "mint" => %Package{name: "mint", version: "1.6.0", source: :hex, scope: :prod},
          "hackney" => %Package{name: "hackney", version: "1.20.0", source: :hex, scope: :prod},
          "swoosh" => %Package{name: "swoosh", version: "1.16.0", source: :hex, scope: :prod},
          "finch" => %Package{name: "finch", version: "0.18.0", source: :hex, scope: :prod}
        }
      }

      res = Adapters.resolve(ws, %{}, %Config{env: :prod})
      assert res.notes == []
      assert res.untracked_fun_sources == false
      assert res.configured[:tesla] == ["Elixir.Tesla.Adapter.Mint"]
      assert res.configured[:swoosh] == ["Elixir.Swoosh.ApiClient.Finch"]
      assert Map.has_key?(res.inactive, "hackney")
    end

    test "marks dynamic on missing unconditional import_config, dynamic import, root escape, and nested dynamic adapter" do
      for {label, content} <- [
            {"missing_import", ~s[import Config\nimport_config "does_not_exist.exs"\n]},
            {"dynamic_import", ~s[import Config\nimport_config System.get_env("CFG")\n]},
            {"root_escape", ~s[import Config\nimport_config "../../outside.exs"\n]},
            {"nested_kw",
             ~s[import Config\nconfig :my_app, MyApp.Mailer, adapter: System.get_env("A")\n]},
            {"nested_map",
             ~s[import Config\nconfig :my_app, opts: %{adapter: System.get_env("A")}\n]},
            {"nested_put_env",
             ~s[Application.put_env(:my_app, :client, adapter: System.get_env("A"))\n]}
          ] do
        dir = Tmp.mkdir!("v103-dyn-#{label}")

        Tmp.write!(
          dir,
          "config/config.exs",
          "import Config\nconfig :tesla, adapter: Tesla.Adapter.Mint\n" <> content
        )

        ws = %VulnCheck.Types.Workspace{
          root_dir: dir,
          project_type: :mix,
          project_name: "demo",
          env: :prod,
          otp_release: "27.0",
          packages: %{
            "tesla" => %Package{name: "tesla", version: "1.11.0", source: :hex, scope: :prod},
            "mint" => %Package{name: "mint", version: "1.6.0", source: :hex, scope: :prod},
            "hackney" => %Package{name: "hackney", version: "1.20.0", source: :hex, scope: :prod}
          }
        }

        res = Adapters.resolve(ws, %{}, %Config{env: :prod})

        assert res.inactive == %{},
               "expected no adapters dropped for #{label}, got: #{inspect(res)}"

        assert res.notes != [], "expected conservative note for #{label}"
      end
    end
  end

  # -- F-04: Solver :build_only ordering ---------------------------------------

  describe "F-04: Solver :build_only respects artifact issues, reachable packages, and dynamic escapes" do
    test "reports :potentially_reachable for uncompiled :build_only dep, reachable package-level CVE, and dynamic escape" do
      root = Tmp.mkdir!("v103-build-only")
      ebin = &Path.join(root, "_build/prod/lib/#{&1}/ebin")

      Beams.compile!(ebin.("bo_used"), [
        {"bo_used.ex", "defmodule BoUsed do\n  def helper, do: :ok\nend\n"}
      ])

      Beams.compile!(ebin.("bo_dyn"), [
        {"bo_dyn.ex",
         """
         defmodule BoDyn do
           def ping, do: :ok
           def secret(x), do: x
         end
         """}
      ])

      Beams.compile!(ebin.("app"), [
        {"app.ex",
         """
         defmodule BoApp.Application do
           def start(_t, _a) do
             BoUsed.helper()
             BoDyn.ping()
             mod = Process.get(:m) || BoDyn
             apply(mod, :secret, [1])
             {:ok, self()}
           end
         end
         """}
      ])

      Beams.write_app!(ebin.("bo_used"), "bo_used")
      Beams.write_app!(ebin.("bo_dyn"), "bo_dyn")

      Beams.write_app!(ebin.("app"), "app",
        applications: [:kernel, :stdlib, :elixir],
        mod: "Elixir.BoApp.Application"
      )

      ws = %VulnCheck.Types.Workspace{
        root_dir: root,
        project_type: :mix,
        project_name: "app",
        env: :prod,
        otp_release: "27.0",
        root_apps: ["app"],
        root_ebin_dirs: [ebin.("app")],
        packages: %{
          "bo_used" => %Package{
            name: "bo_used",
            version: "1.0.0",
            source: :hex,
            scope: :build_only,
            runtime: false,
            otp_app: "bo_used",
            ebin_dir: ebin.("bo_used")
          },
          "bo_dyn" => %Package{
            name: "bo_dyn",
            version: "1.0.0",
            source: :hex,
            scope: :build_only,
            runtime: false,
            otp_app: "bo_dyn",
            ebin_dir: ebin.("bo_dyn")
          },
          "bo_missing" => %Package{
            name: "bo_missing",
            version: "1.0.0",
            source: :hex,
            scope: :build_only,
            runtime: false,
            otp_app: "bo_missing",
            ebin_dir: nil
          }
        }
      }

      loaded = Loader.load_workspace(ws, %Config{}, cache: false)
      graph = CallGraph.build(loaded.modules)
      {model, graph} = Entrypoints.build(ws, graph, %Config{})
      model = %{model | artifact_issues: [{"bo_missing", "not compiled"}]}

      findings =
        Solver.solve(
          ws,
          graph,
          model,
          [
            advisory("BO-MISSING", "bo_missing", affected_routines: []),
            advisory("BO-USED-PKG", "bo_used", affected_routines: []),
            advisory("BO-DYN", "bo_dyn", affected_routines: [mfa("Elixir.BoDyn", "secret", 1)])
          ],
          %Config{}
        )
        |> Map.new(&{&1.advisory_id, &1})

      assert findings["BO-MISSING"].verdict == :potentially_reachable
      assert findings["BO-MISSING"].reason == :missing_beam_debug_info

      assert findings["BO-USED-PKG"].verdict == :potentially_reachable
      assert findings["BO-USED-PKG"].reason == :missing_symbol_granularity

      assert findings["BO-DYN"].verdict == :potentially_reachable
      assert findings["BO-DYN"].reason == :unresolved_dynamic_dispatch
    end
  end

  # -- F-05: CLI feeds isolation from ambient .vulncheck.exs --------------------

  describe "F-05: CLI feeds subcommands do not inherit scan output or offline from .vulncheck.exs" do
    test "feeds bundle ignores .vulncheck.exs output and feeds sync ignores .vulncheck.exs offline" do
      dir = Tmp.mkdir!("v103-feeds-isolation")
      cache = Project.cache!()
      sentinel = Path.join(dir, "scan-report.json")
      File.write!(sentinel, "DO_NOT_OVERWRITE")

      Tmp.write!(dir, ".vulncheck.exs", """
      [
        output: "scan-report.json",
        offline: true
      ]
      """)

      # Without --output on CLI, `feeds bundle` must fail instead of overwriting scan-report.json
      {code, _out, err} = run_cli(["feeds", "bundle", "--cache-dir", cache], cwd: dir)
      assert code == 2
      assert err =~ "feeds bundle requires --output FILE"
      assert File.read!(sentinel) == "DO_NOT_OVERWRITE"

      # With explicit --output, bundle writes there and leaves scan-report.json intact
      {code, out, _err} =
        run_cli(["feeds", "bundle", "--cache-dir", cache, "-o", "my-bundle.tar.gz"], cwd: dir)

      assert code == 0
      assert out =~ "Wrote"
      assert File.exists?(Path.join(dir, "my-bundle.tar.gz"))
      assert File.read!(sentinel) == "DO_NOT_OVERWRITE"

      # Relative path in `feeds import` resolves against cwd
      target_cache = Tmp.mkdir!("v103-feeds-import-target")

      {code, out, _err} =
        run_cli(["feeds", "import", "my-bundle.tar.gz", "--cache-dir", target_cache], cwd: dir)

      assert code == 0
      assert out =~ "Imported my-bundle.tar.gz"

      # `feeds sync` must NOT fail with "drop --offline" just because .vulncheck.exs has offline: true
      {_code, _out, err} =
        run_cli(["feeds", "sync", "--cache-dir", cache],
          cwd: dir,
          scan_opts: [
            osv_url: "https://invalid.example.test/all.zip",
            http_get: fn _url, _opts -> {:error, :econnrefused} end
          ]
        )

      refute err =~ "drop --offline"

      # Explicit CLI `--offline` DOES still fail with "drop --offline"
      {code, _out, err} =
        run_cli(["feeds", "sync", "--cache-dir", cache, "--offline"], cwd: dir)

      assert code == 2
      assert err =~ "drop --offline"
    end
  end

  # -- F-06 & F-14: Config relative paths & max_feed_age_seconds: nil -----------

  describe "F-06 & F-14: Config canonicalizes relative paths and accepts max_feed_age_seconds: nil" do
    test "expands relative file paths against project_dir and catches overlapping CLI/file destinations" do
      proj = Tmp.mkdir!("v103-cfg-proj")
      other = Tmp.mkdir!("v103-cfg-other")

      Tmp.write!(proj, ".vulncheck.exs", """
      [
        output: "reports/out.json",
        sarif: "reports/out.sarif",
        sbom: "reports/sbom.json",
        vex: "reports/vex.json",
        bundle: "feeds/bundle.tar.gz",
        cache_dir: ".cache",
        baseline: "reports/base.json",
        max_feed_age_seconds: nil
      ]
      """)

      assert {:ok, cfg} = Config.from_cli_and_file(["--project-dir", proj], cwd: other)
      assert cfg.output == Path.join(proj, "reports/out.json")
      assert cfg.sarif == Path.join(proj, "reports/out.sarif")
      assert cfg.sbom == Path.join(proj, "reports/sbom.json")
      assert cfg.vex == Path.join(proj, "reports/vex.json")
      assert cfg.bundle == Path.join(proj, "feeds/bundle.tar.gz")
      assert cfg.cache_dir == Path.join(proj, ".cache")
      assert cfg.baseline == Path.join(proj, "reports/base.json")
      assert cfg.max_feed_age_seconds == nil

      # Overlapping output (from .vulncheck.exs) and --sarif (from CLI) must fail validation
      assert {:ok, overlap_cfg} =
               Config.from_cli_and_file(
                 ["--project-dir", proj, "--sarif", Path.join(proj, "reports/out.json")],
                 cwd: other
               )

      assert {:error, msg} = Config.validate_output_paths(overlap_cfg)
      assert msg =~ "overlap"
    end
  end

  # -- F-07: Diff.identity/1 stability across pre/post compile ------------------

  describe "F-07: Diff.package_identity stays stable before and after .app enrichment" do
    test "rebar3 workspace has identical package_identity pre-compile and post-compile" do
      dir = Tmp.mkdir!("v103-rebar-diff")

      Tmp.write!(dir, "rebar.config", "{deps, [cowlib, ranch]}.\n")

      Tmp.write!(dir, "rebar.lock", """
      {"1.2.0",
       [{<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},0},
        {<<"ranch">>,{pkg,<<"ranch">>,<<"2.1.0">>},0}]}.
      [
      {pkg_hash,[{<<"cowlib">>, <<"AA11BB22">>}, {<<"ranch">>, <<"CC33DD44">>}]}
      ].
      """)

      {:ok, ws_pre} = Workspace.load(%Config{project_dir: dir})
      id_pre = Diff.package_identity(ws_pre, "cowlib")
      assert is_binary(id_pre)

      # Now add compiled _build/default/lib/cowlib/ebin/cowlib.app with runtime dependency on ranch
      ebin = Path.join(dir, "_build/default/lib/cowlib/ebin")
      Beams.write_app!(ebin, "cowlib", vsn: "2.12.1", applications: [:kernel, :stdlib, :ranch])

      {:ok, ws_post} = Workspace.load(%Config{project_dir: dir})
      assert "ranch" in ws_post.packages["cowlib"].deps
      assert ws_post.packages["cowlib"].lock_deps == []
      id_post = Diff.package_identity(ws_post, "cowlib")
      assert id_post == id_pre
    end
  end

  # -- F-08 & F-20 (ignore): Case-insensitive ignore/baseline & external check --

  describe "F-08 & F-20: Ignore & baseline case-insensitive CVE matching and external ignore check" do
    test "matches lowercase CVE IDs in .vulncheck.ignore and baselines and normalizes new_suppressions" do
      f = %Finding{
        advisory_id: "EEF-CVE-2026-101028",
        aliases: ["CVE-2026-101028"],
        package: "ash",
        installed_version: "3.34.2",
        severity: :high,
        verdict: :reachable,
        reason: :call_chain_proven,
        fingerprint: "fp1"
      }

      cve_fp = Finding.fingerprint("CVE-2026-101028", "ash", :reachable, nil)
      assert cve_fp in Finding.fingerprints(f)

      dir = Tmp.mkdir!("v103-ignore-case")

      Tmp.write!(dir, ".vulncheck.ignore", """
      [
        %{id: "cve-2026-101028", package: "ash", reason: "accepted", expires: "2099-01-01"}
      ]
      """)

      assert {:ok, rules, []} = Ignore.load(%Config{project_dir: dir})
      {[suppressed], [], []} = Ignore.apply_rules([f], rules, ~D[2026-11-25])
      assert suppressed.suppressed == true

      ws = %VulnCheck.Types.Workspace{
        root_dir: dir,
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        packages: %{"ash" => %Package{name: "ash", version: "3.34.2", source: :hex, scope: :prod}}
      }

      # Baseline lookup via CVE fingerprint hides the finding; lowercase CVE detects escalations
      baseline_map = %{
        "findings" => [
          %{
            "fingerprint" => cve_fp,
            "advisory_id" => "cve-2026-101028",
            "package" => "ash",
            "installed_version" => "3.34.2",
            "package_scope" => "prod",
            "package_identity" => Diff.package_identity(ws, "ash"),
            "severity" => "high",
            "verdict" => "reachable",
            "suppressed" => false
          }
        ]
      }

      baseline_file = Tmp.write!(dir, "base.json", JSON.encode!(baseline_map))

      assert {:ok, entries} = Diff.read_baseline(baseline_file)
      assert {[], _warnings} = Diff.apply_baseline([f], entries, ws)

      # Escalation check matches lowercase CVE ID in previous baseline entry
      esc_entries = [%{hd(entries) | fingerprint: "different", verdict: "unreachable"}]
      assert {[^f], esc_warnings} = Diff.apply_baseline([f], esc_entries, ws)
      assert Enum.any?(esc_warnings, &(&1 =~ "escalated from unreachable to reachable"))

      # Case-only change in Git repo is NOT flagged as a new suppression; extending expiry IS
      {_, 0} = System.cmd("git", ["init", "-q"], cd: dir)
      {_, 0} = System.cmd("git", ["config", "user.email", "test@example.com"], cd: dir)
      {_, 0} = System.cmd("git", ["config", "user.name", "Test"], cd: dir)

      Tmp.write!(dir, ".vulncheck.ignore", """
      [%{id: "CVE-2026-101028", package: "ash", reason: "ok", expires: "2027-01-01"}]
      """)

      {_, 0} = System.cmd("git", ["add", "."], cd: dir)
      {_, 0} = System.cmd("git", ["commit", "-q", "-m", "base"], cd: dir)

      cfg = %Config{project_dir: dir, diff: "HEAD", forbid_new_suppressions: true}

      lower = [
        %Ignore.Rule{id: "cve-2026-101028", package: "ash", reason: "ok", expires: ~D[2027-01-01]}
      ]

      extended = [
        %Ignore.Rule{id: "cve-2026-101028", package: "ash", reason: "ok", expires: ~D[2028-01-01]}
      ]

      assert Ignore.new_suppressions(cfg, lower) == []
      assert [msg] = Ignore.new_suppressions(cfg, extended)
      assert msg =~ "extended"
    end

    test "--forbid-new-suppressions flags ignore file outside the Git repository" do
      repo = Tmp.mkdir!("v103-git-repo")
      outside = Tmp.mkdir!("v103-outside-ignore")
      ext_ignore = Tmp.write!(outside, ".vulncheck.ignore", "[]\n")

      {_, 0} = System.cmd("git", ["init", "-q"], cd: repo)
      {_, 0} = System.cmd("git", ["config", "user.email", "test@example.com"], cd: repo)
      {_, 0} = System.cmd("git", ["config", "user.name", "Test"], cd: repo)
      Tmp.write!(repo, "README.md", "hi\n")
      {_, 0} = System.cmd("git", ["add", "."], cd: repo)
      {_, 0} = System.cmd("git", ["commit", "-q", "-m", "init"], cd: repo)

      cfg = %Config{
        project_dir: repo,
        diff: "HEAD",
        forbid_new_suppressions: true,
        ignore_file: ext_ignore
      }

      violations =
        Ignore.new_suppressions(cfg, [
          %Ignore.Rule{id: "CVE-2026-101028", package: "ash", reason: "bypass"}
        ])

      assert [msg] = violations
      assert msg =~ "outside the git repository"
    end
  end

  # -- F-09: Semver ~> 3+ segment upper bound -----------------------------------

  describe "F-09: Semver pessimistic ~> upper bound handles 3+ segments accurately" do
    test "enforces segment-accurate upper bounds for 1, 2, 3, and 4 segments" do
      assert Semver.otp_affected?("25.0", "~> 25")
      assert Semver.otp_affected?("25.9.9", "~> 25")
      refute Semver.otp_affected?("26.0", "~> 25")

      assert Semver.otp_affected?("25.3", "~> 25.3")
      assert Semver.otp_affected?("25.9.1", "~> 25.3")
      refute Semver.otp_affected?("26.0", "~> 25.3")

      assert Semver.otp_affected?("25.3.2", "~> 25.3.2")
      assert Semver.otp_affected?("25.3.9", "~> 25.3.2")
      refute Semver.otp_affected?("25.4.0", "~> 25.3.2")
      refute Semver.otp_affected?("25.3.1", "~> 25.3.2")

      assert Semver.otp_affected?("25.3.2.1", "~> 25.3.2.1")
      assert Semver.otp_affected?("25.3.2.9", "~> 25.3.2.1")
      refute Semver.otp_affected?("25.3.3.0", "~> 25.3.2.1")
    end
  end

  # -- F-10: MFA.parse_routine/1 operators, MACRO-*, quoted names ---------------

  describe "F-10: MFA.parse_routine/1 supports operators, MACRO-* and quoted Erlang names" do
    test "parses operators, macros, and quoted Erlang routines without creating atoms" do
      before = :erlang.system_info(:atom_count)

      assert {:ok, %MFA{module: "Elixir.Kernel", function: "==", arity: 2}} =
               MFA.parse_routine("Kernel.==/2")

      assert {:ok, %MFA{module: "Elixir.Kernel", function: "..", arity: 2}} =
               MFA.parse_routine("Kernel.../2")

      assert {:ok, %MFA{module: "Elixir.Kernel", function: "..//", arity: 3}} =
               MFA.parse_routine("Kernel...///3")

      assert :error == MFA.parse_routine("Kernel...//3")

      assert {:ok, %MFA{module: "Elixir.Kernel", function: "..", arity: 2}} =
               MFA.parse_routine("'Elixir.Kernel':'..'/2")

      assert {:ok, %MFA{module: "Elixir.Foo", function: "MACRO-bar", arity: 3}} =
               MFA.parse_routine("'Elixir.Foo':'MACRO-bar'/3")

      assert {:ok, %MFA{module: "erlang", function: "+", arity: 2}} =
               MFA.parse_routine(":erlang.'+'/2")

      assert {:ok, %MFA{module: "my_mod_v103_unique", function: "weird-fn", arity: 1}} =
               MFA.parse_routine("'my_mod_v103_unique':'weird-fn'/1")

      assert :erlang.system_info(:atom_count) - before == 0
    end
  end

  # -- F-11: HTTP SSRF hardening ------------------------------------------------

  describe "F-11: HTTP blocks IPv6 zone IDs, multicast, reserved, IPv4-compatible IPv6, and site-local" do
    test "blocks restricted redirect targets while allowing public HTTPS addresses" do
      blocked = [
        "https://[fe80::1%25eth0]/a",
        "https://[fe80::1%eth0]/a",
        "https://224.0.0.1/a",
        "https://239.255.255.250/a",
        "https://240.0.0.1/a",
        "https://255.255.255.255/a",
        "https://[::127.0.0.1]/a",
        "https://[::10.0.0.1]/a",
        "https://[fec0::1]/a",
        "https://[ff02::1]/a"
      ]

      for target <- blocked do
        assert {:error, {:insecure_url, _}} =
                 HTTP.validate_redirect(
                   "https://osv-vulnerabilities.storage.googleapis.com/a",
                   target
                 ),
               "expected #{target} to be blocked"
      end

      assert :ok ==
               HTTP.validate_redirect(
                 "https://osv-vulnerabilities.storage.googleapis.com/a",
                 "https://93.184.216.34/a"
               )

      assert :ok ==
               HTTP.validate_redirect(
                 "https://osv-vulnerabilities.storage.googleapis.com/a",
                 "https://[2606:2800:220:1:248:1893:25c8:1946]/a"
               )
    end
  end

  # -- F-12: CycloneDX GitHub PURL hardening ------------------------------------

  describe "F-12: CycloneDX uses GitUrl.github_repo/1 to reject lookalike hosts and strip .GIT" do
    test "rejects not-github.com and strips .GIT case-insensitively" do
      ws = %VulnCheck.Types.Workspace{
        root_dir: "/tmp",
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        packages: %{
          "spoof" => %Package{
            name: "spoof",
            version: "abc123",
            source: :git,
            scope: :prod,
            git_url: "https://not-github.com/org/spoof.git",
            git_ref: "abc123"
          },
          "real_gh" => %Package{
            name: "real_gh",
            version: "def456",
            source: :git,
            scope: :prod,
            git_url: "https://github.com/Org/Repo.GIT",
            git_ref: "def456"
          },
          "ssh_gh" => %Package{
            name: "ssh_gh",
            version: "789abc",
            source: :git,
            scope: :prod,
            git_url: "git@github.com:org/ssh_repo.git",
            git_ref: "789abc"
          }
        }
      }

      report = %ScanReport{
        tool_version: "1.0.3",
        generated_at: "2026-11-25T00:00:00Z",
        workspace: ws,
        findings: [],
        summary: %Summary{}
      }

      doc = CycloneDX.document(report, %Config{})
      by_name = Map.new(doc["components"], &{&1["name"], &1})

      assert String.starts_with?(by_name["spoof"]["purl"], "pkg:generic/spoof@abc123")
      refute String.starts_with?(by_name["spoof"]["purl"], "pkg:github/")
      assert by_name["real_gh"]["purl"] == "pkg:github/org/repo@def456"
      assert by_name["ssh_gh"]["purl"] == "pkg:github/org/ssh_repo@789abc"
    end
  end

  # -- F-13 & F-24: SARIF empty file, line clamping, multi-package rules --------

  describe "F-13 & F-24: SARIF omits empty physicalLocation, clamps line >= 1, and merges multi-package rules" do
    test "handles empty file / line 0 and merges multi-package findings under one rule" do
      ws = %VulnCheck.Types.Workspace{
        root_dir: "/tmp/proj",
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        lockfile: nil,
        packages: %{}
      }

      f1 = %Finding{
        advisory_id: "CVE-2026-99999",
        aliases: [],
        package: "pkg_a",
        installed_version: "1.0.0",
        recommended_fix: "1.0.1",
        severity: :high,
        cvss_score: 8.1,
        cwes: ["CWE-79"],
        verdict: :reachable,
        reason: :call_chain_proven,
        summary: "Multi-package bug",
        fingerprint: "fp-a",
        trace: [
          %TraceHop{
            mfa: mfa("Elixir.Demo", "run", 0),
            file: "lib/demo.ex",
            line: 0,
            kind: :entrypoint
          },
          %TraceHop{mfa: mfa("Elixir.PkgA", "boom", 0), file: "", line: nil, kind: :static_call}
        ]
      }

      f2 = %Finding{
        advisory_id: "CVE-2026-99999",
        aliases: [],
        package: "pkg_b",
        installed_version: "2.0.0",
        recommended_fix: "2.0.1",
        severity: :medium,
        cvss_score: 5.0,
        cwes: ["CWE-89"],
        verdict: :potentially_reachable,
        reason: :missing_symbol_granularity,
        summary: "Multi-package bug",
        fingerprint: "fp-b",
        trace: []
      }

      report = %ScanReport{
        tool_version: "1.0.3",
        generated_at: "2026-11-25T00:00:00Z",
        workspace: ws,
        findings: [f1, f2],
        summary: %Summary{reachable: 1, potentially_reachable: 1, total: 2}
      }

      doc = SARIF.document(report, %Config{})
      [run] = doc["runs"]
      [rule] = run["tool"]["driver"]["rules"]

      assert rule["id"] == "CVE-2026-99999"
      assert rule["defaultConfiguration"]["level"] == "error"
      assert rule["properties"]["precision"] == "high"
      assert "CWE-79" in rule["properties"]["tags"]
      assert "CWE-89" in rule["properties"]["tags"]
      assert rule["help"]["markdown"] =~ "pkg_a"
      assert rule["help"]["markdown"] =~ "pkg_b"

      [res1, res2] = run["results"]
      # line 0 on lib/demo.ex is clamped to 1
      assert get_in(res1, ["locations", Access.at(0), "physicalLocation", "region", "startLine"]) ==
               1

      # second hop with empty file omits physicalLocation
      flow_locs =
        get_in(res1, ["codeFlows", Access.at(0), "threadFlows", Access.at(0), "locations"])

      assert length(flow_locs) == 2
      refute Map.has_key?(Enum.at(flow_locs, 1)["location"], "physicalLocation")

      # f2 has no trace and ws.lockfile is nil -> Formatter returns {"mix.lock", 1} or valid >= 1
      assert get_in(res2, ["locations", Access.at(0), "physicalLocation", "region", "startLine"]) >=
               1
    end
  end

  # -- F-15 & F-20 (CLI): init multi-adapter, --version --bogus, --diff -h ------

  describe "F-15 & F-20: CLI init multi-adapter and strict --version / help? parsing" do
    test "init_template renders multiple adapters per family as a parseable list" do
      dir = Tmp.mkdir!("v103-init-multi")

      Tmp.write!(dir, "mix.exs", """
      defmodule Multi.MixProject do
        use Mix.Project
        def project, do: [app: :multi, version: "0.1.0", deps: [{:tesla, "~> 1.11"}]]
      end
      """)

      Tmp.write!(dir, "mix.lock", """
      %{
        "tesla": {:hex, :tesla, "1.11.0", "#{String.duplicate("a", 64)}", [:mix], [], "hexpm", "#{String.duplicate("a", 64)}"}
      }
      """)

      Tmp.write!(dir, "config/config.exs", """
      import Config
      config :tesla, adapter: Tesla.Adapter.Mint
      config :my_app, MyApp.Client, adapter: Tesla.Adapter.Finch
      """)

      template = CLI.init_template(dir)
      assert template =~ "tesla: [Tesla.Adapter.Finch, Tesla.Adapter.Mint],"

      Tmp.write!(dir, ".vulncheck.exs", template)
      assert {:ok, cfg} = Config.load_file(%Config{project_dir: dir})

      assert Enum.sort(cfg.configured_adapters[:tesla]) == [
               "Elixir.Tesla.Adapter.Finch",
               "Elixir.Tesla.Adapter.Mint"
             ]
    end

    test "rejects extra args after --version and does not treat option values like --diff -h as help" do
      {code, _out, err} = run_cli(["--version", "--bogus"])
      assert code == 2
      assert err =~ "unexpected argument(s)"

      {code, out, _err} = run_cli(["--version"])
      assert code == 0
      assert out =~ "vulncheck 1.0.3"

      dir = Tmp.mkdir!("v103-diff-dash-h")
      {code, out, _err} = run_cli(["--project-dir", dir, "--diff", "-h"])
      assert code == 2
      refute out =~ "usage: vulncheck"
    end
  end

  # -- F-16: RebarLock git tag version preservation -----------------------------

  describe "F-16: RebarLock preserves full git tag version without 12-char truncation" do
    test "strips leading v on tag refs while still slicing commit sha refs to 12 chars" do
      lock = """
      {"1.2.0",
       [{<<"tagged_lib">>, {git, "https://github.com/org/tagged_lib.git", {tag, "v1.2.3-rc.1+build.42"}}, 0},
        {<<"sha_lib">>, {git, "https://github.com/org/sha_lib.git", {ref, "0123456789abcdef9999"}}, 0}]}.
      """

      assert {:ok, pkgs} = RebarLock.parse(lock)
      assert pkgs["tagged_lib"].version == "1.2.3-rc.1+build.42"
      assert pkgs["tagged_lib"].git_ref == "v1.2.3-rc.1+build.42"
      assert pkgs["sha_lib"].version == "0123456789ab"
      assert pkgs["sha_lib"].git_ref == "0123456789abcdef9999"
    end
  end

  # -- F-17: ErlTerm extensions + coverage --------------------------------------

  describe "F-17: ErlTerm supports +, underscores, full escapes, and binary segment sizes/types" do
    test "parses extended Erlang literals without creating atoms" do
      # Warm up ErlTerm module & stdlib calls before checking atom delta
      {:ok, _} = ErlTerm.parse("1.2.")
      {:error, _} = ErlTerm.parse_file(Path.join(System.tmp_dir!(), "missing_warmup.app"))
      before = :erlang.system_info(:atom_count)

      assert {:ok, [42, 3.14, 16]} = ErlTerm.parse("+42. +3.14. +16#10.")
      assert {:ok, [0xFFFF, 123.45e10]} = ErlTerm.parse("16#FF_FF. 123.45_0e+1_0.")

      assert {:ok, [<<8, 127, 12, 11, ?A, 0x1F600::utf8, ?A, 0>>]} =
               ErlTerm.parse(~S["\b\d\f\v\x41\x{1F600}\101\0".])

      assert {:ok, [65, 65, 0x1F600]} = ErlTerm.parse(~S[$\x41. $\101. $\x{1F600}.])

      assert {:ok, [<<"abc", 65>>]} =
               ErlTerm.parse(~S[<<"abc":3/binary, 65:8/integer-unsigned-big>>.])

      assert {:ok, [{:atom, "never_interned_erl_atom_v103_xyz"}]} =
               ErlTerm.parse("never_interned_erl_atom_v103_xyz.")

      assert {:error, _} = ErlTerm.parse(~S["\xZZ".])
      assert {:error, _} = ErlTerm.parse(~S["\x{FFFFFF}".])
      assert {:error, _} = ErlTerm.parse(~S[<<"abc":/binary>>.])
      assert {:error, _} = ErlTerm.parse("+foo.")
      assert {:error, _} = ErlTerm.parse("<<65:8/>>.")

      # Proplist & atom_names helpers
      assert ErlTerm.proplist_get([{:tuple, [{:atom, "k"}, 1]}], "k") == 1
      assert ErlTerm.proplist_get(:not_a_list, "k", :def) == :def
      assert ErlTerm.atom_names([{:atom, "a"}, 1, {:atom, "b"}]) == ["a", "b"]
      assert ErlTerm.atom_names(:not_a_list) == []
      assert {:error, _} = ErlTerm.parse_file(Path.join(System.tmp_dir!(), "missing_v103.app"))

      assert :erlang.system_info(:atom_count) - before == 0
    end
  end

  # -- F-18: Toml extensions + depth guard --------------------------------------

  describe "F-18: Toml handles CRLF multiline, unicode escapes, embedded quotes, and max depth" do
    test "parses spec-compliant TOML strings and rejects invalid literal newlines and excessive depth" do
      # Warm up Toml module before measuring atom delta
      {:ok, _} = Toml.parse("k = 1\n")
      before = :erlang.system_info(:atom_count)

      src =
        "a = \"\\b\\f\\u0041\\U0001F600\"\r\n" <>
          "b = \"\"\"\r\nline1\r\nline2\"\"\"\"\r\n" <>
          "c = \"\"\"hello\"\"\"\"\"\r\n" <>
          "d = \"\"\"foo \\\r\n   bar\"\"\"\r\n" <>
          "e = '''\r\nraw\\n'end''''\r\n" <>
          "f = '''two'''''\r\n"

      assert {:ok, map} = Toml.parse(src)
      assert map["a"] == <<8, 12, ?A, 0x1F600::utf8>>
      assert map["b"] == "line1\r\nline2\""
      assert map["c"] == "hello\"\""
      assert map["d"] == "foo bar"
      assert map["e"] == "raw\\n'end'"
      assert map["f"] == "two''"

      assert {:error, _} = Toml.parse("bad = 'line1\nline2'")
      assert {:error, _} = Toml.parse("bad = 'line1\rline2'")
      assert {:error, _} = Toml.parse("bad = \"\\uZZZZ\"")
      assert {:error, _} = Toml.parse("bad = \"\\uD800\"")
      assert {:error, _} = Toml.parse("bad = \"\"\"\"\"\"\"\"\"")

      deep = "x = " <> String.duplicate("[", 140) <> String.duplicate("]", 140)
      assert {:error, msg} = Toml.parse(deep)
      assert msg =~ "maximum nesting depth exceeded"

      assert :erlang.system_info(:atom_count) - before == 0
    end
  end

  # -- F-19: Markdown escaping + pure GitHub render + CLI summary write ---------

  describe "F-19: Markdown escapes table cells and CLI writes GITHUB_STEP_SUMMARY cleanly" do
    test "escapes pipes in Markdown suppressed and unreachable tables" do
      report = %ScanReport{
        tool_version: "1.0.3",
        generated_at: "2026-11-25T00:00:00Z",
        findings: [
          %Finding{
            advisory_id: "ADV-1",
            package: "weird|pkg",
            installed_version: "1.0|beta",
            severity: :low,
            verdict: :unreachable,
            reason: :function_not_called,
            reason_detail: "unused",
            fingerprint: "fp1"
          },
          %Finding{
            advisory_id: "ADV-2",
            package: "sup|pkg",
            installed_version: "1.0.0",
            severity: :high,
            verdict: :reachable,
            reason: :call_chain_proven,
            suppressed: true,
            suppression_reason: "ok | fine",
            suppression_expires: "2027|01|01",
            fingerprint: "fp2"
          }
        ],
        summary: %Summary{unreachable: 1, suppressed: 1, total: 2}
      }

      md = Markdown.render(report, %Config{})
      assert md =~ "`weird\\|pkg`"
      assert md =~ "1.0\\|beta"
      assert md =~ "`sup\\|pkg`"
      assert md =~ "2027\\|01\\|01"
    end

    test "CLI writes GITHUB_STEP_SUMMARY once on --format github and warns on write error" do
      prev = System.get_env("GITHUB_STEP_SUMMARY")

      on_exit(fn ->
        if prev,
          do: System.put_env("GITHUB_STEP_SUMMARY", prev),
          else: System.delete_env("GITHUB_STEP_SUMMARY")
      end)

      proj = Project.shop!()
      cache = Project.cache!()
      summary_file = Path.join(Tmp.mkdir!("v103-gh-sum"), "summary.md")
      System.put_env("GITHUB_STEP_SUMMARY", summary_file)

      {code, out, err} =
        run_cli([
          "--project-dir",
          proj,
          "--cache-dir",
          cache,
          "--offline",
          "--no-retired",
          "--format",
          "github",
          "--fail-on",
          "none"
        ])

      assert code == 0
      assert out =~ "::notice title=VulnCheck::"
      assert err == ""
      assert File.read!(summary_file) =~ "## VulnCheck report"

      # Pointing GITHUB_STEP_SUMMARY to a non-existent directory logs a warning on stderr
      bad_path = Path.join(Tmp.mkdir!("v103-gh-bad"), "no_such_dir/summary.md")
      System.put_env("GITHUB_STEP_SUMMARY", bad_path)

      {code2, _out2, err2} =
        run_cli([
          "--project-dir",
          proj,
          "--cache-dir",
          cache,
          "--offline",
          "--no-retired",
          "--format",
          "github",
          "--fail-on",
          "none"
        ])

      assert code2 == 0
      assert err2 =~ "warning: could not write GITHUB_STEP_SUMMARY"
    end
  end

  # -- F-24: Coverage boosters for Git, Formatter, GleamManifest, Bundle --------

  describe "F-24: Edge-case coverage for Git, Formatter, GleamManifest, and Cache.Bundle" do
    test "Git handles non-git directories and invalid refs gracefully" do
      dir = Tmp.mkdir!("v103-no-git")
      assert Git.ref?(dir, "HEAD") == false
      assert {:error, :no_base_ref} = Git.default_base(dir, nil)
      assert {:ok, "main"} = Git.default_base(dir, "main")
      assert {:error, {:invalid_ref, "-bad"}} = Git.changed_files(dir, "-bad")
      assert {:error, {:unknown_ref, "HEAD"}} = Git.changed_files(dir, "HEAD")
      assert {:error, {:unknown_ref, "HEAD"}} = Git.show(dir, "HEAD", "mix.lock")
    end

    test "Formatter helpers cover display_id, title_id, severity_text, fix_text, and primary_location" do
      f = %Finding{
        advisory_id: "GHSA-1234",
        aliases: ["CVE-2026-1234"],
        package: "plug",
        installed_version: "1.16.0",
        recommended_fix: "1.16.4",
        fixed_versions: ["1.16.4"],
        severity: :high,
        cvss_score: 7.5,
        verdict: :reachable,
        reason: :call_chain_proven,
        trace: []
      }

      assert Formatter.display_id(f) == "CVE-2026-1234"
      assert Formatter.title_id(f) == "CVE-2026-1234 (GHSA-1234)"
      assert Formatter.severity_text(f) == "HIGH · CVSS 7.5"
      assert Formatter.fix_text(f) == "1.16.4"

      no_cve = %{f | aliases: [], cvss_score: nil, recommended_fix: nil, fixed_versions: ["1.17.0"]}
      assert Formatter.display_id(no_cve) == "GHSA-1234"
      assert Formatter.title_id(no_cve) == "GHSA-1234"
      assert Formatter.severity_text(no_cve) == "HIGH"
      assert Formatter.fix_text(no_cve) == nil
      assert Formatter.primary_location(no_cve, nil) == {"mix.lock", 1}
    end

    test "GleamManifest parses hex, git, and local path packages and gleam.toml" do
      manifest = """
      packages = [
        { name = "gleam_stdlib", version = "0.44.0", build_tools = ["gleam"], requirements = [], otp_app = "gleam_stdlib", source = "hex", outer_checksum = "AABBCC" },
        { name = "my_git", version = "0.1.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], source = "git", repo = "https://github.com/org/my_git.git", commit = "1234567890abcdef" },
        { name = "local_pkg", version = "0.1.0", build_tools = ["gleam"], requirements = [], source = "local", path = "../local_pkg" }
      ]
      """

      assert {:ok, pkgs} = GleamManifest.parse_manifest(manifest)
      assert pkgs["gleam_stdlib"].source == :hex
      assert pkgs["my_git"].source == :git
      assert pkgs["local_pkg"].source == :path

      assert {:ok, proj} =
               GleamManifest.parse_project("""
               name = "demo_gleam"
               version = "0.2.0"

               [dependencies]
               gleam_stdlib = ">= 0.44.0"

               [dev-dependencies]
               gleeunit = ">= 1.0.0"
               """)

      assert proj.name == "demo_gleam"
      assert proj.version == "0.2.0"
      assert proj.dependencies == ["gleam_stdlib"]
      assert proj.dev_dependencies == ["gleeunit"]
    end

    test "Cache.Bundle rejects empty cache export and corrupted tarballs" do
      empty_cache = Tmp.mkdir!("v103-empty-bundle")
      out = Path.join(empty_cache, "out.tar.gz")
      assert {:error, :empty_cache} = Bundle.export_bundle(%Config{cache_dir: empty_cache}, out)

      bad_tar = Tmp.write!(empty_cache, "bad.tar.gz", "not a gzip tarball")
      assert {:error, _} = Cache.import_bundle(bad_tar, %Config{cache_dir: empty_cache})
    end
  end

  # -- Round-2 QA polish (R3-01 through R3-07) ---------------------------------

  describe "R3-01: Phoenix.Controller loaded from config/*.exs via Application.get_env" do
    test "prevents unsafe narrowing when controller is named in config/*.exs and invoked via Application.get_env" do
      res =
        build_phoenix_fixture!(
          "r301-config-ctrl",
          """
          def run(conn) do
            mod = Application.get_env(:demo, :ctrl)
            mod.call(conn, :secret)
          end
          """,
          config_exs: """
          import Config
          config :demo, ctrl: DemoV103.Controller
          """
        )

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end

    test "prevents unsafe narrowing when config is dynamic and project reads Application.get_env" do
      res =
        build_phoenix_fixture!(
          "r301-dynamic-cfg",
          """
          def run(conn) do
            mod = Application.get_env(:demo, :ctrl)
            mod.call(conn, :secret)
          end
          """,
          config_exs: """
          import Config
          import_config System.get_env("EXTRA_CFG")
          """
        )

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end

    test "normal Phoenix endpoint config keeps routed action :reachable and unrouted action :unreachable" do
      res =
        build_phoenix_fixture!(
          "r301-normal-endpoint",
          "def run(_conn), do: :ok",
          config_exs: """
          import Config
          config :demo, DemoV103.Endpoint, http: [port: 4000]
          """
        )

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict == :unreachable
      assert res["ADV-SECRET"].reason == :function_not_called
    end
  end

  describe "R3-02: 4-tuple scoping outside __match_route__ and mixed bare refs inside __match_route__" do
    test "4-tuple in user function does not blind dynamically_entered? to indirect mod.call" do
      res =
        build_phoenix_fixture!("r302-user-4tuple", """
        def run(conn) do
          _ = {:a, :b, :c, {DemoV103.Controller, :safe}}
          mod = hd([DemoV103.Controller])
          mod.call(conn, :secret)
        end
        """)

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end

    test "Phoenix 1.7 metadata map in __match_route__/4 keeps precision while sneaky bare ref stays sound" do
      clean_res =
        build_phoenix_fixture!(
          "r302-phx17-clean",
          "def run(_conn), do: :ok",
          router_body: """
          def init(opts), do: opts
          def call(conn, opts), do: Phoenix.Router.__call__(conn, elem(__match_route__(["safe"], "GET", opts, nil), 3))
          def __match_route__(["safe"], "GET", _host, _opts) do
            {%{plug: DemoV103.Controller, plug_opts: :safe}, fn c -> c end, [], {DemoV103.Controller, :safe}}
          end
          def __routes__, do: [%{plug: DemoV103.Controller, plug_opts: :safe}]
          """
        )

      assert clean_res["ADV-SAFE"].verdict == :reachable
      assert clean_res["ADV-SECRET"].verdict == :unreachable
      assert clean_res["ADV-SECRET"].reason == :function_not_called

      sneaky_res =
        build_phoenix_fixture!(
          "r302-phx17-sneaky",
          """
          def run(_conn), do: :ok
          def sneak(mod, conn), do: mod.call(conn, :secret)
          """,
          router_body: """
          def init(opts), do: opts
          def call(conn, opts), do: Phoenix.Router.__call__(conn, elem(__match_route__(["safe"], "GET", opts, nil), 3))
          def __match_route__(["safe"], "GET", _host, _opts) do
            DemoV103.Extra.sneak(DemoV103.Controller, %{})
            {%{plug: DemoV103.Controller, plug_opts: :safe}, fn c -> c end, [], {DemoV103.Controller, :safe}}
          end
          def __routes__, do: [%{plug: DemoV103.Controller, plug_opts: :safe}]
          """
        )

      assert sneaky_res["ADV-SAFE"].verdict == :reachable
      assert sneaky_res["ADV-SECRET"].verdict in [:reachable, :potentially_reachable]
    end
  end

  describe "R3-03 & R3-04: Adapters symlink escape protection and %Struct{} dynamic adapter detection" do
    test "blocks symlink escape outside root and symlink loops, while allowing in-root symlinks" do
      outside = Tmp.mkdir!("v103-outside-symlink")
      secret = Tmp.write!(outside, "secret.exs", "import Config\nconfig :secret, mod: Secret.Mod\n")

      proj = Tmp.mkdir!("v103-symlink-proj")
      Tmp.write!(proj, "config/config.exs", "import Config\nimport_config \"linked.exs\"\n")
      :ok = File.ln_s(secret, Path.join(proj, "config/linked.exs"))

      ws = %VulnCheck.Types.Workspace{
        root_dir: proj,
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        packages: %{
          "tesla" => %Package{name: "tesla", version: "1.11.0", source: :hex, scope: :prod},
          "hackney" => %Package{name: "hackney", version: "1.20.0", source: :hex, scope: :prod}
        }
      }

      res = Adapters.resolve(ws, %{}, %Config{env: :prod})
      assert res.config_dynamic? == true
      assert res.untracked_fun_sources == true
      refute "Elixir.Secret.Mod" in res.config_refs
      assert Enum.any?(res.notes, &(&1 =~ "outside project root"))

      # Symlink loop terminates safely and marks dynamic
      loop_proj = Tmp.mkdir!("v103-symlink-loop")
      Tmp.write!(loop_proj, "config/config.exs", "import Config\nimport_config \"loop_a.exs\"\n")
      :ok = File.ln_s("loop_b.exs", Path.join(loop_proj, "config/loop_a.exs"))
      :ok = File.ln_s("loop_a.exs", Path.join(loop_proj, "config/loop_b.exs"))

      loop_res = Adapters.resolve(%{ws | root_dir: loop_proj}, %{}, %Config{env: :prod})
      assert loop_res.config_dynamic? == true
      assert loop_res.untracked_fun_sources == true

      # Valid in-root symlink is followed safely
      ok_proj = Tmp.mkdir!("v103-symlink-inroot")
      Tmp.write!(ok_proj, "config/config.exs", "import Config\nimport_config \"ok_link.exs\"\n")

      Tmp.write!(
        ok_proj,
        "config/real_tesla.exs",
        "import Config\nconfig :tesla, adapter: Tesla.Adapter.Mint\n"
      )

      :ok = File.ln_s("real_tesla.exs", Path.join(ok_proj, "config/ok_link.exs"))

      ok_res = Adapters.resolve(%{ws | root_dir: ok_proj}, %{}, %Config{env: :prod})
      assert ok_res.config_dynamic? == false
      assert ok_res.configured[:tesla] == ["Elixir.Tesla.Adapter.Mint"]
    end

    test "detects dynamic adapter inside %Struct{} literals while keeping literal structs static" do
      dyn_dir = Tmp.mkdir!("v103-struct-dyn")

      Tmp.write!(dyn_dir, "config/config.exs", """
      import Config
      config :demo, Demo.Mailer, cfg: %MyStruct{api_client: System.get_env("CLIENT")}
      """)

      ws = %VulnCheck.Types.Workspace{
        root_dir: dyn_dir,
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        packages: %{
          "swoosh" => %Package{name: "swoosh", version: "1.16.0", source: :hex, scope: :prod},
          "hackney" => %Package{name: "hackney", version: "1.20.0", source: :hex, scope: :prod}
        }
      }

      dyn_res = Adapters.resolve(ws, %{}, %Config{env: :prod})
      assert dyn_res.config_dynamic? == true
      assert dyn_res.inactive == %{}

      static_dir = Tmp.mkdir!("v103-struct-static")

      Tmp.write!(static_dir, "config/config.exs", """
      import Config
      config :demo, Demo.Mailer, cfg: %MyStruct{api_client: Swoosh.ApiClient.Finch}
      """)

      static_res = Adapters.resolve(%{ws | root_dir: static_dir}, %{}, %Config{env: :prod})
      assert static_res.config_dynamic? == false
      assert static_res.configured[:swoosh] == ["Elixir.Swoosh.ApiClient.Finch"]
    end
  end

  describe "R3-05: HTTP IPv6 zone ID check is authority-scoped and enforced in validate_url/1" do
    test "allows query brackets containing % while rejecting IPv6 zone IDs in both validate_url and validate_redirect" do
      assert :ok == HTTP.validate_url("https://example.com/api?filter=[a%20b]")

      assert :ok ==
               HTTP.validate_redirect(
                 "https://example.com/start",
                 "https://example.com/api?filter=[a%20b]"
               )

      assert {:error, {:insecure_url, _}} = HTTP.validate_url("https://[fe80::1%25eth0]/x")
      assert {:error, {:insecure_url, _}} = HTTP.validate_url("https://[fe80::1%eth0]/x")

      assert {:error, {:insecure_url, _}} =
               HTTP.validate_redirect(
                 "https://example.com/start",
                 "https://[fe80::1%25eth0]/x"
               )
    end
  end

  describe "R3-06: SARIF picks max security-severity across multi-package group and avoids nil message text" do
    test "computes max security-severity and omits nil message when file is empty" do
      ws = %VulnCheck.Types.Workspace{
        root_dir: "/tmp/proj",
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        lockfile: nil,
        packages: %{}
      }

      f_low = %Finding{
        advisory_id: "CVE-2026-88888",
        aliases: [],
        package: "pkg_a",
        installed_version: "1.0.0",
        severity: :medium,
        cvss_score: 4.3,
        verdict: :potentially_reachable,
        reason: :missing_symbol_granularity,
        summary: "Shared advisory",
        fingerprint: "fp-low",
        trace: []
      }

      f_crit = %Finding{
        advisory_id: "CVE-2026-88888",
        aliases: [],
        package: "pkg_b",
        installed_version: "2.0.0",
        severity: :critical,
        cvss_score: 9.8,
        verdict: :reachable,
        reason: :call_chain_proven,
        summary: "Shared advisory",
        fingerprint: "fp-crit",
        trace: [
          %TraceHop{mfa: mfa("Elixir.Demo", "run", 0), file: "", line: nil, kind: :entrypoint}
        ]
      }

      report = %ScanReport{
        tool_version: "1.0.3",
        generated_at: "2026-11-25T00:00:00Z",
        workspace: ws,
        findings: [f_low, f_crit],
        summary: %Summary{reachable: 1, potentially_reachable: 1, total: 2}
      }

      doc = SARIF.document(report, %Config{})
      [run] = doc["runs"]
      [rule] = run["tool"]["driver"]["rules"]
      assert rule["properties"]["security-severity"] == "9.8"

      # Verify empty hop file omits physicalLocation and no location anywhere emits "text":null
      encoded = JSON.encode!(doc)
      refute encoded =~ ~s("text":null)

      [_, crit_result] = run["results"]

      [flow_loc] =
        get_in(crit_result, ["codeFlows", Access.at(0), "threadFlows", Access.at(0), "locations"])

      refute Map.has_key?(flow_loc["location"], "physicalLocation")
      assert flow_loc["location"] == %{"message" => %{"text" => "1. Demo.run/0"}}
    end
  end

  describe "R3-07: Toml enforces @max_depth 128 on empty nested arrays and inline tables" do
    test "allows depth 128 and rejects depth 129 for empty arrays and inline tables" do
      arr_128 = "x = " <> String.duplicate("[", 128) <> String.duplicate("]", 128)
      arr_129 = "x = " <> String.duplicate("[", 129) <> String.duplicate("]", 129)
      assert {:ok, %{"x" => _}} = Toml.parse(arr_128)
      assert {:error, "maximum nesting depth exceeded"} = Toml.parse(arr_129)

      tbl_129 =
        "x = " <> String.duplicate("{a = ", 129) <> "{}" <> String.duplicate("}", 129)

      assert {:error, "maximum nesting depth exceeded"} = Toml.parse(tbl_129)
    end
  end

  describe "R4: config/*.exs eval & dynamic module builders and strict TOML unicode hex escapes" do
    test "Code.eval_string in config/runtime.exs marks config_dynamic? and preserves alternative adapters" do
      dir = Tmp.mkdir!("v103-r4-eval-adapter")

      Tmp.write!(dir, "config/config.exs", """
      import Config
      config :tesla, adapter: Tesla.Adapter.Mint
      """)

      Tmp.write!(dir, "config/runtime.exs", """
      import Config
      Code.eval_string(System.get_env("EXTRA"))
      """)

      ws = %VulnCheck.Types.Workspace{
        root_dir: dir,
        project_type: :mix,
        project_name: "demo",
        env: :prod,
        otp_release: "27.0",
        packages: %{
          "tesla" => %Package{name: "tesla", version: "1.11.0", source: :hex, scope: :prod},
          "mint" => %Package{name: "mint", version: "1.6.0", source: :hex, scope: :prod},
          "hackney" => %Package{name: "hackney", version: "1.20.0", source: :hex, scope: :prod}
        }
      }

      res = Adapters.resolve(ws, %{}, %Config{env: :prod})
      assert res.config_dynamic? == true
      assert res.config_dynamic_modules? == true
      assert res.untracked_fun_sources == true
      assert res.inactive == %{}
    end

    test "String.to_existing_atom in config/runtime.exs keeps Phoenix.Controller unrouted action sound" do
      res =
        build_phoenix_fixture!(
          "r4-runtime-ctrl-atom",
          """
          def run(conn) do
            Application.get_env(:demo, :handler).call(conn, :secret)
          end
          """,
          runtime_exs: """
          import Config
          config :demo, handler: String.to_existing_atom(System.get_env("CTRL_MOD"))
          """
        )

      assert res["ADV-SAFE"].verdict == :reachable
      assert res["ADV-SECRET"].verdict == :potentially_reachable
      assert res["ADV-SECRET"].reason == :unresolved_dynamic_dispatch
    end

    test "Module.concat in config/runtime.exs keeps non-controller dependency dynamic call sound" do
      root = Tmp.mkdir!("v103-r4-runtime-worker")
      ebin = &Path.join(root, "_build/prod/lib/#{&1}/ebin")

      Tmp.write!(root, "config/runtime.exs", """
      import Config
      config :my_app, worker: Module.concat([System.get_env("W")])
      """)

      Beams.compile!(ebin.("worker_dep"), [
        {"worker_dep.ex",
         """
         defmodule WorkerDepV103 do
           def sink(arg), do: arg
         end
         """}
      ])

      Beams.compile!(ebin.("my_app"), [
        {"my_app.ex",
         """
         defmodule WorkerAppV103.Application do
           def start(_type, _args) do
             Application.get_env(:my_app, :worker).sink(:payload)
             {:ok, self()}
           end
         end
         """}
      ])

      Beams.write_app!(ebin.("worker_dep"), "worker_dep")

      Beams.write_app!(ebin.("my_app"), "my_app",
        applications: [:kernel, :stdlib, :elixir, :worker_dep],
        mod: "Elixir.WorkerAppV103.Application"
      )

      ws = %VulnCheck.Types.Workspace{
        root_dir: root,
        project_type: :mix,
        project_name: "my_app",
        env: :prod,
        otp_release: "27.0",
        root_apps: ["my_app"],
        root_ebin_dirs: [ebin.("my_app")],
        packages: %{
          "worker_dep" => %Package{
            name: "worker_dep",
            version: "1.0.0",
            source: :hex,
            scope: :prod,
            otp_app: "worker_dep",
            ebin_dir: ebin.("worker_dep")
          }
        }
      }

      loaded = Loader.load_workspace(ws, %Config{}, cache: false)
      graph = CallGraph.build(loaded.modules)
      {model, graph} = Entrypoints.build(ws, graph, %Config{})

      assert model.config_atoms_constructed == true

      [finding] =
        Solver.solve(
          ws,
          graph,
          model,
          [
            advisory("ADV-WORKER", "worker_dep",
              affected_routines: [mfa("Elixir.WorkerDepV103", "sink", 1)]
            )
          ],
          %Config{}
        )

      assert finding.verdict == :potentially_reachable
      assert finding.reason == :unresolved_dynamic_dispatch
    end

    test "Toml rejects signed hex digits in \\uXXXX and \\UXXXXXXXX escapes" do
      assert {:error, "invalid unicode escape"} = Toml.parse(~S[a = "\u+041"])
      assert {:error, "invalid unicode escape"} = Toml.parse(~S[a = "\u-000"])
      assert {:error, "invalid unicode escape"} = Toml.parse(~S[a = "\U+0000041"])
      assert {:error, "invalid unicode escape"} = Toml.parse(~S[a = "\U-0000000"])
    end
  end
end
