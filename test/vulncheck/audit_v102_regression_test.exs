defmodule VulnCheck.AuditV102RegressionTest do
  use ExUnit.Case, async: true

  alias VulnCheck.{Cache, CLI, Config, ErlTerm, HTTP, Ignore, Literal, Scanner, Workspace}
  alias VulnCheck.Cache.BeamCodec
  alias VulnCheck.Entrypoints.Adapters
  alias VulnCheck.Feeds.EefCna
  alias VulnCheck.Report.{CycloneDX, GitHub, GitLab, SARIF}
  alias VulnCheck.Report.JSON, as: ReportJSON
  alias VulnCheck.Types.{Advisory, Finding, MFA, Package, ScanReport, TraceHop}
  alias VulnCheck.Workspace.{GitUrl, MixProject, Toml}
  alias VulnCheck.Test.{Beams, Feeds, HTTPServer, Tmp}

  @sha String.duplicate("a", 64)

  # -- helpers -----------------------------------------------------------------

  defp compile_erl!(ebin, name, source) do
    File.mkdir_p!(ebin)
    src_dir = ebin |> Path.join("../src") |> Path.expand()
    File.mkdir_p!(src_dir)
    path = Path.join(src_dir, name)
    File.write!(path, source)

    {:ok, _mod} =
      :compile.file(String.to_charlist(path), [
        :debug_info,
        {:outdir, String.to_charlist(ebin)},
        :return_errors
      ])

    :ok
  end

  defp build_mix_project!(app, opts) do
    root = Tmp.mkdir!("v102-#{app}")
    deps = Keyword.fetch!(opts, :deps)
    dep_specs = Keyword.get(opts, :dep_specs)
    mod = Keyword.get(opts, :mod)

    deps_code =
      dep_specs ||
        Enum.map_join(deps, ", ", fn {name, _ver} -> ~s({:#{name}, ">= 0.0.0"}) end)

    app_code = if mod, do: "[mod: {#{mod}, []}]", else: "[]"

    Tmp.write!(root, "mix.exs", """
    defmodule #{Macro.camelize(app)}.MixProject do
      use Mix.Project
      def project, do: [app: :#{app}, version: "0.1.0", deps: deps()]
      def application, do: #{app_code}
      defp deps, do: [#{deps_code}]
    end
    """)

    lock =
      Enum.map_join(deps, "\n", fn {name, ver} ->
        ~s(  "#{name}": {:hex, :#{name}, "#{ver}", "#{@sha}", [:mix], [], "hexpm", "#{@sha}"},)
      end)

    Tmp.write!(root, "mix.lock", "%{\n#{lock}\n}\n")

    for {file, content} <- Keyword.get(opts, :configs, []) do
      Tmp.write!(root, Path.join("config", file), content)
    end

    lib = &Path.join(root, "_build/prod/lib/#{&1}/ebin")

    for {dep_name, dep_ver, ex_sources, erl_sources} <- Keyword.get(opts, :dep_modules, []) do
      if ex_sources != [], do: Beams.compile!(lib.(dep_name), ex_sources)
      for {erl_file, erl_src} <- erl_sources, do: compile_erl!(lib.(dep_name), erl_file, erl_src)
      Beams.write_app!(lib.(dep_name), dep_name, vsn: dep_ver)
    end

    app_ex = Keyword.get(opts, :app_ex, [])
    app_erl = Keyword.get(opts, :app_erl, [])
    if app_ex != [], do: Beams.compile!(lib.(app), app_ex)
    for {erl_file, erl_src} <- app_erl, do: compile_erl!(lib.(app), erl_file, erl_src)

    started_apps =
      Keyword.get(opts, :started_apps, [
        :kernel,
        :stdlib,
        :elixir | Enum.map(deps, &String.to_atom(elem(&1, 0)))
      ])

    app_opts =
      [vsn: "0.1.0", applications: started_apps] ++ if(mod, do: [mod: "Elixir.#{mod}"], else: [])

    Beams.write_app!(lib.(app), app, app_opts)

    root
  end

  defp seed_single_advisory!(id, pkg, version_fixed, routines) do
    cache = Tmp.mkdir!("v102-cache")
    feeds = Path.join(cache, "feeds")
    File.mkdir_p!(Path.join(feeds, "cves"))

    osv = %{
      "id" => "EEF-#{id}",
      "aliases" => [id],
      "summary" => "Test advisory #{id} in #{pkg}",
      "severity" => [
        %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
      ],
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => pkg, "purl" => "pkg:hex/#{pkg}"},
          "ranges" => [
            %{
              "type" => "SEMVER",
              "events" => [%{"introduced" => "0.0.0"}, %{"fixed" => version_fixed}]
            }
          ]
        }
      ]
    }

    File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([osv]))

    File.write!(
      Path.join(feeds, "cves/#{id}.json"),
      JSON.encode!(Feeds.cve_record(id, pkg, routines))
    )

    cache
  end

  defp scan_project!(root, cache, extra \\ []) do
    cfg =
      struct(
        %Config{
          project_dir: root,
          cache_dir: cache,
          offline: true,
          check_retired: false,
          env: :prod
        },
        extra
      )

    {:ok, report} = Scanner.run(cfg, beam_cache: false)
    report
  end

  # -- F-01: Erlang & Gleam module atoms in tuple heads & map keys -------------

  describe "F-01: Erlang and Gleam module atoms in tuple heads and map keys" do
    test "Erlang worker in 2-tuple Elixir Supervisor child spec reaches vulnerable dep" do
      root =
        build_mix_project!("f01_sup",
          mod: "F01Sup.Application",
          deps: [{"evuln", "1.0.0"}],
          dep_modules: [
            {"evuln", "1.0.0", [],
             [
               {"evuln_lib.erl",
                """
                -module(evuln_lib).
                -export([boom/1]).
                boom(X) -> X.
                """}
             ]}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule F01Sup.Application do
               def start(_type, _args) do
                 children = [{:f01_erl_worker, :init_arg}]
                 Supervisor.start_link(children, strategy: :one_for_one)
               end
             end
             """}
          ],
          app_erl: [
            {"f01_erl_worker.erl",
             """
             -module(f01_erl_worker).
             -behaviour(gen_server).
             -export([init/1, handle_call/3, handle_cast/2]).
             init(Arg) -> {ok, Arg}.
             handle_call(Req, _From, State) -> {reply, evuln_lib:boom(Req), State}.
             handle_cast(_Msg, State) -> {noreply, State}.
             """}
          ]
        )

      cache = seed_single_advisory!("CVE-2026-90001", "evuln", "2.0.0", ["evuln_lib:boom/1"])
      report = scan_project!(root, cache)

      assert [%Finding{verdict: :reachable, reason: :call_chain_proven}] = report.findings
    end

    test "Erlang and Gleam module atoms in tuple heads and map keys survive for apply/3 escapes" do
      root =
        build_mix_project!("f01_dyn",
          mod: "F01Dyn.Application",
          deps: [{"edyn", "1.0.0"}, {"gleam_dep", "1.0.0"}],
          dep_modules: [
            {"edyn", "1.0.0", [],
             [
               {"edyn_mod.erl",
                """
                -module(edyn_mod).
                -export([vuln/1]).
                vuln(X) -> X.
                """}
             ]},
            {"gleam_dep", "1.0.0", [],
             [
               {"gleam@http.erl",
                """
                -module('gleam@http').
                -export([vuln/1]).
                vuln(X) -> X.
                """}
             ]}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule F01Dyn.Application do
               def start(_type, _args) do
                 dispatch(:erlang.get(:target), :arg)
               end

               def dispatch(mod, x) do
                 _map = %{edyn_mod: 1}
                 _tuple = {:"gleam@http", :a, :b, :c}
                 apply(mod, :vuln, [x])
               end
             end
             """}
          ]
        )

      cache = Tmp.mkdir!("f01-dyn-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osv1 = %{
        "id" => "EEF-CVE-2026-90002",
        "aliases" => ["CVE-2026-90002"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "edyn"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      osv2 = %{
        "id" => "EEF-CVE-2026-90003",
        "aliases" => ["CVE-2026-90003"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "gleam_dep"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([osv1, osv2]))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90002.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-90002", "edyn", ["edyn_mod:vuln/1"]))
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90003.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-90003", "gleam_dep", ["gleam@http:vuln/1"]))
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["edyn"].verdict == :potentially_reachable
      assert by_pkg["edyn"].reason == :unresolved_dynamic_dispatch
      assert by_pkg["gleam_dep"].verdict == :potentially_reachable
      assert by_pkg["gleam_dep"].reason == :unresolved_dynamic_dispatch
    end
  end

  # -- F-02 & F-03: config captures, broken config, binary_to_term -------------

  describe "F-02 & F-03: config captures, untracked fun sources, and binary_to_term" do
    test "explicit Elixir and Erlang function captures in config/*.exs produce active findings" do
      root =
        build_mix_project!("f02_cfg",
          mod: "F02Cfg.Application",
          deps: [{"cbdep", "1.0.0"}, {"erlcb", "1.0.0"}],
          configs: [
            {"config.exs",
             """
             import Config
             config :f02_cfg, cb: &CbDep.boom/1, erl_cb: &:erl_cb_mod.boom/1
             """}
          ],
          dep_modules: [
            {"cbdep", "1.0.0",
             [
               {"cb_dep.ex",
                """
                defmodule CbDep do
                  def boom(x), do: x
                end
                """}
             ], []},
            {"erlcb", "1.0.0", [],
             [
               {"erl_cb_mod.erl",
                """
                -module(erl_cb_mod).
                -export([boom/1]).
                boom(X) -> X.
                """}
             ]}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule F02Cfg.Application do
               def start(_type, _args) do
                 cb = Application.get_env(:f02_cfg, :cb)
                 cb.(:hello)
                 {:ok, self()}
               end
             end
             """}
          ]
        )

      cache = Tmp.mkdir!("f02-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osv1 = %{
        "id" => "EEF-CVE-2026-90010",
        "aliases" => ["CVE-2026-90010"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "cbdep"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      osv2 = %{
        "id" => "EEF-CVE-2026-90011",
        "aliases" => ["CVE-2026-90011"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "erlcb"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([osv1, osv2]))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90010.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-90010", "cbdep", ["'Elixir.CbDep':boom/1"]))
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90011.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-90011", "erlcb", ["erl_cb_mod:boom/1"]))
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["cbdep"].verdict == :reachable
      assert by_pkg["erlcb"].verdict == :reachable
    end

    test "unparseable config/runtime.exs marks untracked_fun_sources and makes fun.(x) escape" do
      root =
        build_mix_project!("f02_broken",
          mod: "F02Broken.Application",
          deps: [{"cbdep", "1.0.0"}],
          configs: [
            {"runtime.exs", "config :f02_broken, cb: (broken syntax"}
          ],
          dep_modules: [
            {"cbdep", "1.0.0",
             [
               {"cb_dep.ex",
                """
                defmodule CbDep do
                  def boom(x), do: x
                end
                """}
             ], []}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule F02Broken.Application do
               def start(_type, _args) do
                 cb = Application.get_env(:f02_broken, :cb)
                 cb.(:x)
                 {:ok, self()}
               end
             end
             """}
          ]
        )

      cache = seed_single_advisory!("CVE-2026-90012", "cbdep", "2.0.0", ["'Elixir.CbDep':boom/1"])
      report = scan_project!(root, cache)

      assert [%Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch}] =
               report.findings
    end

    test ":erlang.binary_to_term/2 escapes fun.(x) while Plug.Crypto.non_executable_binary_to_term/2 does not" do
      vuln_dep =
        {"deserdep", "1.0.0",
         [
           {"deser_dep.ex",
            """
            defmodule DeserDep do
              def boom(x), do: x
            end
            """}
         ], []}

      unsafe_root =
        build_mix_project!("f03_unsafe",
          mod: "F03Unsafe.Application",
          deps: [{"deserdep", "1.0.0"}],
          dep_modules: [vuln_dep],
          app_ex: [
            {"application.ex",
             """
             defmodule F03Unsafe.Application do
               def start(_type, _args) do
                 fun = :erlang.binary_to_term(:erlang.get(:bin), [:safe])
                 fun.(:x)
               end
             end
             """}
          ]
        )

      safe_root =
        build_mix_project!("f03_safe",
          mod: "F03Safe.Application",
          deps: [{"deserdep", "1.0.0"}],
          dep_modules: [vuln_dep],
          app_ex: [
            {"application.ex",
             """
             defmodule F03Safe.Application do
               def start(_type, _args) do
                 _term = Plug.Crypto.non_executable_binary_to_term(:erlang.get(:bin), [:safe])
                 cb = :erlang.get(:cb)
                 cb.(:x)
               end
             end
             """}
          ]
        )

      cross_mod_root =
        build_mix_project!("f03_cross",
          mod: "F03Cross.Application",
          deps: [{"deserdep", "1.0.0"}],
          dep_modules: [vuln_dep],
          app_ex: [
            {"application.ex",
             """
             defmodule F03Cross.Application do
               def start(_type, _args) do
                 {m, f, a} = F03Cross.Decoder.decode(:erlang.get(:bin))
                 F03Cross.Runner.run(m, f, a)
               end
             end

             defmodule F03Cross.Decoder do
               def decode(bin), do: :erlang.binary_to_term(bin)
             end

             defmodule F03Cross.Runner do
               def run(m, f, a), do: apply(m, f, [a])
             end
             """}
          ]
        )

      cache =
        seed_single_advisory!("CVE-2026-90013", "deserdep", "2.0.0", ["'Elixir.DeserDep':boom/1"])

      assert [%Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch}] =
               scan_project!(unsafe_root, cache).findings

      assert [%Finding{verdict: :unreachable, reason: :function_not_called}] =
               scan_project!(safe_root, cache).findings

      assert [%Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch}] =
               scan_project!(cross_mod_root, cache).findings
    end
  end

  # -- F-04: :build_only (runtime: false) packages called from prod code -------

  describe "F-04: build_only (runtime: false) packages" do
    test "triggers BEAM analysis and distinguishes called vs uncalled build_only dep" do
      dep_mod =
        {"builddep", "1.0.0",
         [
           {"build_dep.ex",
            """
            defmodule BuildDep do
              def macro_helper(x), do: x
            end
            """}
         ], []}

      called_root =
        build_mix_project!("f04_called",
          mod: "F04Called.Application",
          deps: [{"builddep", "1.0.0"}],
          dep_specs: ~s({:builddep, ">= 0.0.0", runtime: false}),
          started_apps: [:kernel, :stdlib, :elixir],
          dep_modules: [dep_mod],
          app_ex: [
            {"application.ex",
             """
             defmodule F04Called.Application do
               def start(_type, _args), do: {:ok, BuildDep.macro_helper(:live)}
             end
             """}
          ]
        )

      uncalled_root =
        build_mix_project!("f04_uncalled",
          mod: "F04Uncalled.Application",
          deps: [{"builddep", "1.0.0"}],
          dep_specs: ~s({:builddep, ">= 0.0.0", runtime: false}),
          started_apps: [:kernel, :stdlib, :elixir],
          dep_modules: [dep_mod],
          app_ex: [
            {"application.ex",
             """
             defmodule F04Uncalled.Application do
               def start(_type, _args), do: {:ok, self()}
             end
             """}
          ]
        )

      cache =
        seed_single_advisory!("CVE-2026-90020", "builddep", "2.0.0", [
          "'Elixir.BuildDep':macro_helper/1"
        ])

      called_report = scan_project!(called_root, cache)
      assert [%Finding{verdict: :reachable, reason: :call_chain_proven}] = called_report.findings

      uncalled_report = scan_project!(uncalled_root, cache)

      assert [%Finding{verdict: :unreachable, reason: :non_prod_dependency}] =
               uncalled_report.findings
    end
  end

  # -- F-05: Custom Plug.Parsers modules ---------------------------------------

  describe "F-05: custom Plug.Parsers modules in compiled Plug.Parsers.call/2" do
    test "custom Plug.Parsers module is reached while unconfigured MULTIPART stays unreachable" do
      root =
        build_mix_project!("f05_parsers",
          mod: "F05Parsers.Application",
          deps: [{"plug", "1.16.2"}, {"xmlvuln", "1.0.0"}],
          dep_modules: [
            {"plug", "1.16.2",
             [
               {"plug_parsers.ex",
                """
                defmodule Plug.Parsers do
                  @callback init(term()) :: term()
                  @callback parse(term(), binary(), binary(), map(), term()) :: term()
                  def call(conn, %{parsers: parsers}), do: reduce(parsers, conn)
                  defp reduce([{parser, opts} | _], conn), do: parser.parse(conn, "application", "xml", %{}, opts)
                end

                defmodule Plug.Parsers.MULTIPART do
                  @behaviour Plug.Parsers
                  def init(opts), do: opts
                  def parse(conn, _type, _sub, _headers, _opts), do: read_part(conn)
                  def read_part(conn), do: conn
                end
                """}
             ], []},
            {"xmlvuln", "1.0.0",
             [
               {"xml_vuln.ex",
                """
                defmodule XmlVuln do
                  def parse_doc(data), do: data
                end
                """}
             ], []}
          ],
          app_ex: [
            {"router.ex",
             """
             defmodule F05Parsers.Application do
               def start(_type, _args), do: F05Parsers.Router.call(%{}, [])
             end

             defmodule F05Parsers.XmlParser do
               @behaviour Plug.Parsers
               def init(opts), do: opts
               def parse(_conn, _t, _s, _h, _o), do: XmlVuln.parse_doc("<x/>")
             end

             defmodule F05Parsers.Router do
               def call(conn, _opts) do
                 Plug.Parsers.call(conn, %{parsers: [{F05Parsers.XmlParser, []}]})
               end
             end
             """}
          ]
        )

      cache = Tmp.mkdir!("f05-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osv1 = %{
        "id" => "EEF-CVE-2026-90030",
        "aliases" => ["CVE-2026-90030"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "xmlvuln"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      osv2 = %{
        "id" => "EEF-CVE-2026-90031",
        "aliases" => ["CVE-2026-90031"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "plug"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "1.17.0"}]}
            ]
          }
        ]
      }

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([osv1, osv2]))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90030.json"),
        JSON.encode!(
          Feeds.cve_record("CVE-2026-90030", "xmlvuln", ["'Elixir.XmlVuln':parse_doc/1"])
        )
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90031.json"),
        JSON.encode!(
          Feeds.cve_record("CVE-2026-90031", "plug", ["'Elixir.Plug.Parsers.MULTIPART':read_part/1"])
        )
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["xmlvuln"].verdict in [:reachable, :potentially_reachable]
      assert by_pkg["plug"].verdict == :unreachable
      assert by_pkg["plug"].reason == :function_not_called
    end
  end

  # -- F-06: Erlang config refs, :gen_statem state_functions, :cowboy_rest -----

  describe "F-06: Erlang config modules, gen_statem state_functions, and cowboy_rest" do
    test "config/*.exs naming an Erlang module activates its behaviour callbacks" do
      root =
        build_mix_project!("f06_cfg",
          mod: "F06Cfg.Application",
          deps: [{"evuln", "1.0.0"}],
          configs: [
            {"config.exs",
             """
             import Config
             config :f06_cfg, handler: :f06_erl_handler
             """}
          ],
          dep_modules: [
            {"evuln", "1.0.0", [],
             [
               {"evuln_api.erl",
                """
                -module(evuln_api).
                -export([sink/1]).
                sink(X) -> X.
                """}
             ]}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule F06Cfg.Application do
               def start(_type, _args), do: {:ok, self()}
             end
             """}
          ],
          app_erl: [
            {"f06_erl_handler.erl",
             """
             -module(f06_erl_handler).
             -behaviour(gen_server).
             -export([init/1, handle_call/3]).
             init(Arg) -> {ok, Arg}.
             handle_call(Req, _From, State) -> {reply, evuln_api:sink(Req), State}.
             """}
          ]
        )

      cache = seed_single_advisory!("CVE-2026-90040", "evuln", "2.0.0", ["evuln_api:sink/1"])
      report = scan_project!(root, cache)

      assert [%Finding{verdict: :reachable}] = report.findings
    end

    test ":gen_statem state_functions mode and :cowboy_rest callbacks reach vulnerable deps" do
      root =
        build_mix_project!("f06_beh",
          mod: "F06Beh.Application",
          deps: [{"statemvuln", "1.0.0"}, {"restvuln", "1.0.0"}],
          dep_modules: [
            {"statemvuln", "1.0.0", [],
             [
               {"statem_sink.erl",
                """
                -module(statem_sink).
                -export([hit/1]).
                hit(X) -> X.
                """}
             ]},
            {"restvuln", "1.0.0", [],
             [
               {"rest_sink.erl",
                """
                -module(rest_sink).
                -export([hit/1]).
                hit(X) -> X.
                """}
             ]}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule F06Beh.Application do
               def start(_type, _args) do
                 _ = {:f06_door_fsm, :arg}
                 _ = {:f06_rest_handler, []}
                 {:ok, self()}
               end
             end
             """}
          ],
          app_erl: [
            {"f06_door_fsm.erl",
             """
             -module(f06_door_fsm).
             -behaviour(gen_statem).
             -export([callback_mode/0, init/1, locked/3]).
             callback_mode() -> state_functions.
             init(Data) -> {ok, locked, Data}.
             locked(_Type, Event, Data) -> {keep_state, statem_sink:hit({Event, Data})}.
             """},
            {"f06_rest_handler.erl",
             """
             -module(f06_rest_handler).
             -behaviour(cowboy_rest).
             -export([init/2, content_types_provided/2, to_json/2]).
             init(Req, State) -> {cowboy_rest, Req, State}.
             content_types_provided(Req, State) -> {[{<<"application/json">>, to_json}], Req, State}.
             to_json(Req, State) -> {rest_sink:hit(Req), Req, State}.
             """}
          ]
        )

      cache = Tmp.mkdir!("f06-beh-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osv1 = %{
        "id" => "EEF-CVE-2026-90041",
        "aliases" => ["CVE-2026-90041"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "statemvuln"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      osv2 = %{
        "id" => "EEF-CVE-2026-90042",
        "aliases" => ["CVE-2026-90042"],
        "affected" => [
          %{
            "package" => %{"ecosystem" => "Hex", "name" => "restvuln"},
            "ranges" => [
              %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
            ]
          }
        ]
      }

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([osv1, osv2]))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90041.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-90041", "statemvuln", ["statem_sink:hit/1"]))
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-90042.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-90042", "restvuln", ["rest_sink:hit/1"]))
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["statemvuln"].verdict == :reachable
      assert by_pkg["restvuln"].verdict == :reachable
    end
  end

  # -- F-07: Proven Phoenix.Router -> Phoenix.Controller action dispatch -------

  describe "F-07: Phoenix.Router -> Phoenix.Controller proven action dispatch" do
    for {form_name, router_body} <- [
          {"direct call/2", "F07App.ReportController.call(conn, :index)"},
          {"Plug.Builder init/1",
           "F07App.ReportController.call(conn, F07App.ReportController.init(:index))"},
          {"Phoenix 1.7 __match_route__ tuple",
           """
           __match_route__(conn)
           end
           def __match_route__(_conn) do
             {%{plug: F07App.ReportController}, fn c -> c end, [], {F07App.ReportController, :index}}
           """}
        ] do
      test "form '#{form_name}' proves routed action reachable and unrouted action unreachable" do
        root =
          build_mix_project!("f07_phx",
            mod: "F07App.Application",
            deps: [{"livevuln", "1.0.0"}, {"deadvuln", "1.0.0"}],
            dep_modules: [
              {"livevuln", "1.0.0",
               [
                 {"live_vuln.ex",
                  """
                  defmodule LiveVuln do
                    def boom(x), do: x
                  end
                  """}
               ], []},
              {"deadvuln", "1.0.0",
               [
                 {"dead_vuln.ex",
                  """
                  defmodule DeadVuln do
                    def boom(x), do: x
                  end
                  """}
               ], []}
            ],
            app_ex: [
              {"phoenix_stub.ex",
               """
               defmodule Phoenix.Controller do
                 @callback init(term()) :: term()
                 @callback call(term(), term()) :: term()
                 @callback action(term(), term()) :: term()
               end

               defmodule F07App.Application do
                 def start(_type, _args) do
                   F07App.Endpoint.call(%{params: %{}}, [])
                   {:ok, self()}
                 end
               end

               defmodule F07App.Endpoint do
                 def call(conn, opts), do: F07App.Router.call(conn, opts)
               end

               defmodule F07App.Router do
                 def call(conn, _opts) do
                   #{unquote(router_body)}
                 end
               end

               defmodule F07App.ReportController do
                 @behaviour Phoenix.Controller
                 def init(opts), do: opts
                 def call(conn, opts), do: action(conn, opts)
                 def action(conn, _opts), do: apply(__MODULE__, action_name(conn), [conn, conn.params])
                 defp action_name(conn), do: Map.get(conn, :action)
                 def index(_conn, params), do: LiveVuln.boom(params)
                 def unused_action(_conn, params), do: DeadVuln.boom(params)
               end
               """}
            ]
          )

        cache = Tmp.mkdir!("f07-cache")
        feeds = Path.join(cache, "feeds")
        File.mkdir_p!(Path.join(feeds, "cves"))

        osv1 = %{
          "id" => "EEF-CVE-2026-90050",
          "aliases" => ["CVE-2026-90050"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "livevuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        }

        osv2 = %{
          "id" => "EEF-CVE-2026-90051",
          "aliases" => ["CVE-2026-90051"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "deadvuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        }

        File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip([osv1, osv2]))

        File.write!(
          Path.join(feeds, "cves/CVE-2026-90050.json"),
          JSON.encode!(Feeds.cve_record("CVE-2026-90050", "livevuln", ["'Elixir.LiveVuln':boom/1"]))
        )

        File.write!(
          Path.join(feeds, "cves/CVE-2026-90051.json"),
          JSON.encode!(Feeds.cve_record("CVE-2026-90051", "deadvuln", ["'Elixir.DeadVuln':boom/1"]))
        )

        report = scan_project!(root, cache)
        by_pkg = Map.new(report.findings, &{&1.package, &1})

        assert by_pkg["livevuln"].verdict == :reachable
        assert by_pkg["livevuln"].reason == :call_chain_proven
        assert by_pkg["deadvuln"].verdict == :unreachable
        assert by_pkg["deadvuln"].reason == :function_not_called

        assert VulnCheck.should_fail?(report, %Config{fail_on: :reachable})

        dead_only = %{report | findings: [by_pkg["deadvuln"]]}
        refute VulnCheck.should_fail?(dead_only, %Config{fail_on: :reachable})

        # Verify CLI exit codes with --fail-on reachable
        live_cache =
          seed_single_advisory!("CVE-2026-90050", "livevuln", "2.0.0", ["'Elixir.LiveVuln':boom/1"])

        dead_cache =
          seed_single_advisory!("CVE-2026-90051", "deadvuln", "2.0.0", ["'Elixir.DeadVuln':boom/1"])

        {:ok, out1} = StringIO.open("")
        {:ok, err1} = StringIO.open("")
        {:ok, out2} = StringIO.open("")
        {:ok, err2} = StringIO.open("")

        assert 1 ==
                 CLI.run(
                   [
                     "--project-dir",
                     root,
                     "--cache-dir",
                     live_cache,
                     "--offline",
                     "--no-retired",
                     "--fail-on",
                     "reachable"
                   ],
                   stdout: out1,
                   stderr: err1
                 )

        assert 0 ==
                 CLI.run(
                   [
                     "--project-dir",
                     root,
                     "--cache-dir",
                     dead_cache,
                     "--offline",
                     "--no-retired",
                     "--fail-on",
                     "reachable"
                   ],
                   stdout: out2,
                   stderr: err2
                 )
      end
    end

    test "dynamic controller action option falls back soundly to potentially_reachable" do
      root =
        build_mix_project!("f07_dyn",
          mod: "F07Dyn.Application",
          deps: [{"deadvuln", "1.0.0"}],
          dep_modules: [
            {"deadvuln", "1.0.0",
             [
               {"dead_vuln.ex",
                """
                defmodule DeadVuln do
                  def boom(x), do: x
                end
                """}
             ], []}
          ],
          app_ex: [
            {"dyn_ctrl.ex",
             """
             defmodule Phoenix.Controller do
               @callback init(term()) :: term()
               @callback call(term(), term()) :: term()
               @callback action(term(), term()) :: term()
             end

             defmodule F07Dyn.Application do
               def start(_type, _args), do: F07Dyn.Router.call(%{params: %{}}, :erlang.get(:act))
             end

             defmodule F07Dyn.Router do
               def call(conn, dyn_action), do: F07Dyn.ReportController.call(conn, dyn_action)
             end

             defmodule F07Dyn.ReportController do
               @behaviour Phoenix.Controller
               def init(opts), do: opts
               def call(conn, opts), do: action(conn, opts)
               def action(conn, _opts), do: apply(__MODULE__, Map.get(conn, :action), [conn, conn.params])
               def secret_action(_conn, params), do: DeadVuln.boom(params)
             end
             """}
          ]
        )

      cache =
        seed_single_advisory!("CVE-2026-90052", "deadvuln", "2.0.0", ["'Elixir.DeadVuln':boom/1"])

      report = scan_project!(root, cache)

      assert [%Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch}] =
               report.findings
    end
  end

  # -- F-08: MixProject static mix.exs reader & CycloneDX ----------------------

  describe "F-08: MixProject static evaluator and CycloneDX self-dogfooding" do
    test "self-dogfooding on VulnCheck itself classifies all dev/test deps as non_prod and exact direct deps" do
      {:ok, ws} = Workspace.load(%Config{project_dir: File.cwd!(), env: :prod})

      refute Enum.any?(ws.warnings, &(&1 =~ "built dynamically"))
      assert ws.direct_deps_known == true
      assert ws.direct_deps == ["dialyxir", "ex_doc"]

      for {name, pkg} <- ws.packages do
        assert pkg.scope == :non_prod, "expected #{name} to be :non_prod, got #{pkg.scope}"
      end

      report = %ScanReport{
        workspace: ws,
        tool_version: VulnCheck.version(),
        generated_at: "2026-11-24T00:00:00Z"
      }

      bom = CycloneDX.document(report, %Config{})

      for comp <- bom["components"] do
        assert comp["scope"] == "excluded", "expected #{comp["name"]} excluded in CycloneDX"
      end

      root_ref = bom["metadata"]["component"]["bom-ref"]
      root_dep = Enum.find(bom["dependencies"], &(&1["ref"] == root_ref))

      assert Enum.sort(root_dep["dependsOn"]) == [
               "pkg:hex/dialyxir@#{ws.packages["dialyxir"].version}",
               "pkg:hex/ex_doc@#{ws.packages["ex_doc"].version}"
             ]

      refute Enum.any?(root_dep["dependsOn"], &String.contains?(&1, "makeup_elixir"))
    end

    test "MixProject.analyze/2 handles helper ++, blocks, @project, @version, and 3-tuple path deps without hallucination" do
      source = """
      defmodule Fancy.MixProject do
        use Mix.Project

        @version "1.2.3"
        @project [app: :fancy, version: @version, deps: deps()]

        def project do
          _note = :ignored
          @project
        end

        defp deps do
          common_deps() ++ dev_deps() ++ extra_deps(Mix.env())
        end

        defp common_deps do
          [
            {:sub, @version, path: "../sub"},
            {:plug, "~> 1.16"}
          ]
        end

        defp dev_deps do
          [{:credo, "~> 1.7", only: :dev, runtime: false}]
        end

        defp extra_deps(:prod), do: []
        defp extra_deps(_), do: [{:ex_doc, "~> 0.34", runtime: false}]
      end
      """

      {:ok, ast} = Literal.quote_string(source, file: "mix.exs")
      proj = MixProject.analyze(ast, "mix.exs")

      assert proj.app == "fancy"
      assert proj.version == "1.2.3"
      assert proj.deps_parsed == true

      names = Enum.map(proj.deps, & &1.name)
      assert names == ["sub", "plug", "credo", "ex_doc"]
      refute "path" in names

      sub = Enum.find(proj.deps, &(&1.name == "sub"))
      assert sub.requirement == "1.2.3"
      assert sub.path == "../sub"

      ex_doc = Enum.find(proj.deps, &(&1.name == "ex_doc"))
      assert ex_doc.runtime == false
      refute "prod" in ex_doc.only
      assert "dev" in ex_doc.only
    end

    test "MixProject.analyze/2 handles if/unless/case/cond on Mix.env(), guarded clauses, and cycles" do
      source = """
      defmodule EnvBranch.MixProject do
        use Mix.Project
        def project, do: [app: :env_branch, version: "0.1.0", deps: deps()]

        defp deps do
          List.flatten([
            if(Mix.env() == :dev, do: [{:a_dev, "~> 1.0"}], else: [{:b_non_dev, "~> 1.0"}]),
            unless(Mix.env() == :prod, do: [{:c_not_prod, "~> 1.0"}]),
            case Mix.env() do
              :test -> [{:d_test, "~> 1.0"}]
              _ -> [{:e_non_test, "~> 1.0"}]
            end,
            guarded(Mix.env())
          ])
        end

        defp guarded(env) when env in [:dev, :test], do: [{:f_dev_test, "~> 1.0"}]
        defp guarded(_), do: [{:g_prod, "~> 1.0"}]
      end
      """

      {:ok, ast} = Literal.quote_string(source, file: "mix.exs")
      proj = MixProject.analyze(ast, "mix.exs")
      assert proj.deps_parsed == true
      by_name = Map.new(proj.deps, &{&1.name, &1})

      assert by_name["a_dev"].only == ["dev"]
      assert "prod" in by_name["b_non_dev"].only
      refute "prod" in by_name["c_not_prod"].only
      assert by_name["d_test"].only == ["test"]
      assert "prod" in by_name["e_non_test"].only
      assert by_name["f_dev_test"].only == ["dev", "test"]
      assert "prod" in by_name["g_prod"].only

      cycle = """
      defmodule Cycle.MixProject do
        use Mix.Project
        def project, do: [app: :cycle, deps: deps()]
        defp deps, do: other()
        defp other, do: deps()
      end
      """

      {:ok, cycle_ast} = Literal.quote_string(cycle, file: "mix.exs")
      assert MixProject.analyze(cycle_ast, "mix.exs").deps_parsed == false

      extra_src = """
      defmodule Extra.MixProject do
        use Mix.Project
        @ver "2.0.0"
        @base_deps [{:base_pkg, @ver}]

        def project do
          base = [app: :extra, version: @ver]
          base ++ [deps: deps()]
        end

        defp deps do
          local = @base_deps
          local ++
            cond_deps() ++
            literal_env_deps(:dev) ++
            if(Mix.env() != :prod, do: [{:non_prod_a, "~> 1.0"}]) ++
            if(Mix.env() in [:dev, :test], do: [{:in_env_b, "~> 1.0"}]) ++
            if(not (Mix.env() == :prod), do: [{:not_prod_c, "~> 1.0"}]) ++
            case System.get_env("X") do
              "1" -> [{:sys_dep, "~> 1.0"}]
              _ -> []
            end
        end

        defp cond_deps do
          cond do
            Mix.env() == :test -> [{:cond_test, "~> 1.0"}]
            true -> [{:cond_other, "~> 1.0"}]
          end
        end

        defp literal_env_deps(:dev), do: [{:lit_dev, "~> 1.0"}]
        defp literal_env_deps(_), do: []
      end
      """

      {:ok, extra_ast} = Literal.quote_string(extra_src, file: "mix.exs")
      extra_proj = MixProject.analyze(extra_ast, "mix.exs")
      assert extra_proj.app == "extra"
      assert extra_proj.version == "2.0.0"
      assert extra_proj.deps_parsed == true
      extra_by_name = Map.new(extra_proj.deps, &{&1.name, &1})
      assert extra_by_name["base_pkg"].requirement == "2.0.0"
      assert extra_by_name["lit_dev"].only == :all
      assert extra_by_name["cond_test"].only == ["test"]
      assert "prod" in extra_by_name["cond_other"].only
      refute "prod" in extra_by_name["non_prod_a"].only
      assert extra_by_name["in_env_b"].only == ["dev", "test"]
      refute "prod" in extra_by_name["not_prod_c"].only
      assert extra_by_name["sys_dep"].only == :all
    end

    test "Adapters scans MFA 3-tuples, maps, anonymous funs, and dynamic fun calls in config/*.exs" do
      dir = Tmp.mkdir!("adapters-scan")

      Tmp.write!(dir, "config/config.exs", """
      import Config
      config :demo, Demo.Endpoint,
        mfa: {Demo.Worker, :run, [1, 2]},
        erl_mfa: {:erl_worker, :go, 1},
        opts: %{Demo.MapKey => :ok, key: :erl_map_val},
        anon: fn x -> x end,
        short_cap: &Demo.Other.call(&1),
        dyn_cap: Function.capture(Demo.Dyn, :run, 1)
      """)

      ws = %VulnCheck.Types.Workspace{
        root_dir: dir,
        project_name: "demo",
        project_type: :mix,
        env: :prod,
        otp_release: "27"
      }

      res = Adapters.resolve(ws, %{}, nil)
      assert res.untracked_fun_sources == true
      assert "erl_map_val" in res.config_refs
      assert "Elixir.Demo.Endpoint" in res.config_refs
      assert "Elixir.Demo.MapKey" in res.config_refs

      mfas = Enum.map(res.config_mfas, &elem(&1, 0))
      assert %MFA{module: "Elixir.Demo.Worker", function: "run", arity: 2} in mfas
      assert %MFA{module: "erl_worker", function: "go", arity: 1} in mfas

      {sites, _dyn, _notes} = Adapters.read_config_files(ws)
      assert Enum.any?(sites, &(elem(&1, 0) == "erl_map_val"))
      assert {:ok, _} = MixProject.parse_file(Path.join(File.cwd!(), "mix.exs"))
      assert {:error, _} = MixProject.parse_file(Path.join(Tmp.mkdir!("no-mix"), "missing.exs"))
    end
  end

  describe "F-07: Phoenix.Router.__call__ framework dispatch resolution" do
    test "resolves Phoenix.Router dynamic call/2 to reachable plugs without escaping" do
      root =
        build_mix_project!("f07_router_disp",
          mod: "F07RouterDisp.Application",
          deps: [{"phoenix", "1.7.14"}, {"unuseddep", "1.0.0"}],
          dep_modules: [
            {"phoenix", "1.7.14",
             [
               {"phoenix_router.ex",
                """
                defmodule Phoenix.Router do
                  def __call__(conn, plug, opts), do: plug.call(conn, plug.init(opts))
                end
                """}
             ], []},
            {"unuseddep", "1.0.0",
             [
               {"unused_dep.ex",
                """
                defmodule UnusedDep do
                  def call(_a, _b), do: :boom
                end
                """}
             ], []}
          ],
          app_ex: [
            {"app.ex",
             """
             defmodule F07RouterDisp.Application do
               def start(_type, _args) do
                 F07RouterDisp.Router.call(%{}, [])
                 {:ok, self()}
               end
             end

             defmodule F07RouterDisp.Router do
               def call(conn, _opts) do
                 Phoenix.Router.__call__(conn, F07RouterDisp.SafePlug, :ok)
               end
             end

             defmodule F07RouterDisp.SafePlug do
               def init(opts), do: opts
               def call(conn, _opts), do: conn
             end
             """}
          ]
        )

      cache =
        seed_single_advisory!("CVE-2026-90059", "unuseddep", "2.0.0", ["'Elixir.UnusedDep':call/2"])

      report = scan_project!(root, cache)

      assert [%Finding{verdict: :unreachable, reason: :function_not_called}] = report.findings
    end
  end

  # -- F-09 & F-14: ErlTerm totality & Toml fixes ------------------------------

  describe "F-09 & F-14: ErlTerm and Toml parser hardening" do
    test "ErlTerm.parse/1 returns {:error, _} without raising on malformed numbers and invalid UTF-8" do
      bad_inputs = [
        "99#abc.",
        "1#0.",
        "0#0.",
        "1.2e+.",
        "1.2e-",
        <<?', 0xFF, ?', ?.>>,
        <<?$, 0xFF, ?.>>,
        <<?", ?\\, 0xFF, ?", ?.>>
      ]

      for input <- bad_inputs do
        assert {:error, _reason} = ErlTerm.parse(input),
               "expected {:error, _} for #{inspect(input)}"
      end
    end

    test "Toml.parse/1 handles boolean prefixes, quoted dotted keys, and rejects empty headers" do
      {:ok, doc} =
        Toml.parse("""
        a = true_val
        b = falsehood
        c = true
        d = false
        "a.b" = 1
        "p.q".c = 2
        's.t' = 3

        [ "x.y".z ]
        k = "v"
        """)

      assert doc["a"] == "true_val"
      assert doc["b"] == "falsehood"
      assert doc["c"] == true
      assert doc["d"] == false
      assert doc["a.b"] == 1
      assert doc["p.q"] == %{"c" => 2}
      assert doc["s.t"] == 3
      assert doc["x.y"] == %{"z" => %{"k" => "v"}}

      for bad <- ["[]\n", "[[]]\n", "[a..b]\n", "[.a]\n", "[a.]\n"] do
        assert {:error, _} = Toml.parse(bad), "expected {:error, _} for #{inspect(bad)}"
      end
    end
  end

  # -- F-10: Cache compressed ETF bomb & BeamCodec validation ------------------

  describe "F-10: Cache decompression cap and BeamCodec structural validation" do
    test "Cache.get_beam_packed/2 rejects compressed ETF claiming > 32 MiB before inflating" do
      dir = Tmp.mkdir!("f10-cache")
      cfg = %Config{cache_dir: dir}
      sha = Cache.sha256("bomb")
      path = Path.join(Cache.beam_dir(cfg), sha <> ".etf")
      File.mkdir_p!(Path.dirname(path))

      # Forged ETF compressed header: version 131, tag 80 (?P), uncompressed size = 64 MiB
      forged = <<131, 80, 64 * 1024 * 1024::unsigned-big-32, 0x78, 0x9C, 0x03, 0x00>>
      File.write!(path, forged)

      assert :miss = Cache.get_beam_packed(cfg, sha)
    end

    test "BeamCodec.valid?/2 rejects non-tuples in functions, bad attributes, bad init_literals, and improper lists" do
      summary = %VulnCheck.Types.ModuleSummary{
        module: "Elixir.Demo",
        functions: [{"run", 1}],
        attributes: %{"behaviour" => [{:atom, "Elixir.GenServer"}]},
        init_literals: [
          {%MFA{module: "Elixir.Demo", function: "run", arity: 1},
           %MFA{module: "Elixir.Demo", function: "run", arity: 1}, [{:atom, "ok"}], "lib/demo.ex",
           1}
        ]
      }

      {strings, packed} = BeamCodec.pack(summary)
      assert BeamCodec.valid?(strings, packed)

      refute BeamCodec.valid?(strings, put_elem(packed, 5, [:bad]))
      refute BeamCodec.valid?(strings, put_elem(packed, 5, [{0, 1} | :improper]))
      refute BeamCodec.valid?(strings, put_elem(packed, 9, %{0 => :not_a_list}))
      refute BeamCodec.valid?(strings, put_elem(packed, 9, %{0 => [:raw_atom]}))
      refute BeamCodec.valid?(strings, put_elem(packed, 9, %{0 => [{:bad_tag, "x"}]}))

      bad_init = [{{0, 0, 1}, {0, 0, 1}, [:raw_atom], nil, 1}]
      refute BeamCodec.valid?(strings, put_elem(packed, 14, bad_init))
    end
  end

  # -- F-11: SARIF 2.1.0 executionOrder >= 1 -----------------------------------

  describe "F-11: SARIF executionOrder is 1-based" do
    test "executionOrder starts at 1 even with daemon_activation or config_activation hop" do
      finding = %Finding{
        advisory_id: "CVE-2026-90100",
        package: "bandit",
        installed_version: "1.5.0",
        severity: :high,
        verdict: :reachable,
        reason: :daemon_call_chain,
        fingerprint: "fp-1",
        trace: [
          %TraceHop{
            mfa: %MFA{module: "Elixir.MyApp.Application", function: "start", arity: 2},
            file: "lib/my_app/application.ex",
            line: 10,
            kind: :daemon_activation,
            note: "starts Bandit"
          },
          %TraceHop{
            mfa: %MFA{module: "Elixir.Bandit.HTTP2.Handler", function: "handle_data", arity: 3},
            file: "deps/bandit/lib/bandit/http2/handler.ex",
            line: 42,
            kind: :entrypoint
          }
        ]
      }

      report = %ScanReport{
        tool_version: VulnCheck.version(),
        findings: [finding],
        all_findings: [finding]
      }

      doc = SARIF.document(report, %Config{})
      [result] = hd(doc["runs"])["results"]
      [loc1, loc2] = hd(hd(result["codeFlows"])["threadFlows"])["locations"]

      assert loc1["executionOrder"] == 1
      assert loc1["location"]["message"]["text"] == "0. MyApp.Application.start/2 starts Bandit"
      assert loc2["executionOrder"] == 2
      assert loc2["location"]["message"]["text"] == "1. Bandit.HTTP2.Handler.handle_data/3"
    end
  end

  # -- F-12: Invalid .vulncheck.ignore entries are policy violations -----------

  describe "F-12: malformed .vulncheck.ignore entries fail policy with exit code 1" do
    test "Ignore.step/1 routes rejected entries into policy_violations and CLI exits 1" do
      root =
        build_mix_project!("f12_ign",
          mod: "F12Ign.Application",
          deps: [{"safe_pkg", "1.0.0"}],
          app_ex: [
            {"application.ex",
             """
             defmodule F12Ign.Application do
               def start(_type, _args), do: {:ok, self()}
             end
             """}
          ]
        )

      Tmp.write!(root, ".vulncheck.ignore", """
      [
        %{id: "CVE-2026-1", reason: ""},
        %{reason: "missing id"}
      ]
      """)

      cfg = %Config{project_dir: root, require_ignore_reason: true}
      {[], violations, warnings} = Ignore.step().([], %{config: cfg, workspace: nil})

      assert length(violations) == 2
      assert warnings == []

      cache = seed_single_advisory!("CVE-2026-99999", "other_pkg", "2.0.0", [])
      {:ok, stdout} = StringIO.open("")
      {:ok, stderr} = StringIO.open("")

      code =
        CLI.run(
          ["--project-dir", root, "--cache-dir", cache, "--offline", "--no-retired"],
          stdout: stdout,
          stderr: stderr
        )

      assert code == 1
    end
  end

  # -- F-13: GitUrl host isolation, GitLab subgroups, non-GitHub PURLs ---------

  describe "F-13: GitUrl host isolation and non-GitHub PURLs" do
    test "preserves GitHub slugs, isolates non-GitHub hosts, keeps GitLab subgroups, and matches pkg:gitlab" do
      assert GitUrl.repo_slug("https://github.com/benoitc/hackney.git") == "benoitc/hackney"
      assert GitUrl.repo_slug("benoitc/hackney") == "benoitc/hackney"

      assert GitUrl.repo_slug("https://gitlab.com/group/subgroup/repo.git") ==
               "gitlab.com/group/subgroup/repo"

      assert GitUrl.repo_slug("git@gitlab.com:Group/SubGroup/Repo.git") ==
               "gitlab.com/group/subgroup/repo"

      assert GitUrl.repo_slug("https://git.corp.internal/benoitc/hackney.git") ==
               "git.corp.internal/benoitc/hackney"

      refute GitUrl.repo_slug("https://git.corp.internal/benoitc/hackney.git") ==
               GitUrl.repo_slug("https://github.com/benoitc/hackney.git")

      assert GitUrl.repo_slug("file:///tmp/owner/repo.git") == nil
      assert GitUrl.repo_slug("https://github.com/owner//repo.git") == nil

      record = %{
        "cveMetadata" => %{"cveId" => "CVE-2026-90130"},
        "containers" => %{
          "cna" => %{
            "affected" => [
              %{
                "packageURL" => "pkg:gitlab/group%2Fsubgroup/repo",
                "programRoutines" => [%{"name" => "repo_mod:boom/1"}],
                "versions" => [%{"version" => "0", "lessThan" => "2.0.0", "status" => "affected"}]
              }
            ]
          }
        }
      }

      base = %Advisory{
        id: "CVE-2026-90130",
        package: "repo",
        source_package: "gitlab.com/group/subgroup/repo",
        checked_version: "1.0.0",
        git_repos: ["gitlab.com/group/subgroup/repo"]
      }

      enriched = EefCna.apply_record(base, record)
      assert enriched.enriched == true
      assert enriched.affected_routines == [%MFA{module: "repo_mod", function: "boom", arity: 1}]
    end
  end

  # -- F-15: Monorepo --project-dir paths via .git ancestor --------------------

  describe "F-15: monorepo repository-relative paths in SARIF, GitHub, and GitLab" do
    test "prefixes locations, relatedLocations, and codeFlows relative to surrounding .git root" do
      repo = Tmp.mkdir!("f15-mono")
      File.mkdir_p!(Path.join(repo, ".git"))
      sub = Path.join(repo, "services/payments")
      File.mkdir_p!(sub)

      ws = %VulnCheck.Types.Workspace{
        root_dir: sub,
        project_name: "payments",
        project_type: :mix,
        env: :prod,
        otp_release: "27",
        lockfile: Path.join(sub, "mix.lock"),
        packages: %{
          "plug" => %Package{
            name: "plug",
            version: "1.16.2",
            source: :hex,
            scope: :prod,
            lock_line: 12
          }
        }
      }

      finding = %Finding{
        advisory_id: "CVE-2026-54892",
        package: "plug",
        installed_version: "1.16.2",
        severity: :high,
        verdict: :reachable,
        reason: :call_chain_proven,
        fingerprint: "fp-mono",
        trace: [
          %TraceHop{
            mfa: %MFA{module: "Elixir.Payments.Web", function: "call", arity: 2},
            file: "lib/payments/web.ex",
            line: 14,
            kind: :entrypoint
          },
          %TraceHop{
            mfa: %MFA{module: "Elixir.Payments.Query", function: "parse", arity: 1},
            file: "lib/payments/query.ex",
            line: 8,
            kind: :static_call
          },
          %TraceHop{
            mfa: %MFA{module: "Elixir.Plug.Conn.Query", function: "decode", arity: 4},
            file: "deps/plug/lib/plug/conn/query.ex",
            line: 50,
            kind: :static_call
          }
        ]
      }

      report = %ScanReport{
        workspace: ws,
        tool_version: VulnCheck.version(),
        findings: [finding],
        all_findings: [finding]
      }

      cfg = %Config{}

      sarif = SARIF.document(report, cfg)
      [res] = hd(sarif["runs"])["results"]

      assert hd(res["locations"])["physicalLocation"]["artifactLocation"]["uri"] ==
               "services/payments/lib/payments/web.ex"

      assert hd(res["relatedLocations"])["physicalLocation"]["artifactLocation"]["uri"] ==
               "services/payments/lib/payments/query.ex"

      flow_uris =
        hd(hd(res["codeFlows"])["threadFlows"])["locations"]
        |> Enum.map(& &1["location"]["physicalLocation"]["artifactLocation"]["uri"])

      assert flow_uris == [
               "services/payments/lib/payments/web.ex",
               "services/payments/lib/payments/query.ex",
               "services/payments/deps/plug/lib/plug/conn/query.ex"
             ]

      gh = GitHub.render(report, cfg)
      assert gh =~ "file=services/payments/lib/payments/web.ex,line=14"

      [gl_issue] = GitLab.issues(report, cfg)
      assert gl_issue["location"]["path"] == "services/payments/lib/payments/web.ex"

      # JSON remains project-relative
      json_doc = ReportJSON.document(report)
      [json_hop | _] = hd(json_doc["findings"])["trace"]
      assert json_hop["file"] == "lib/payments/web.ex"
    end
  end

  # -- F-16: HTTP redirect downgrade & loopback SSRF ---------------------------

  describe "F-16: HTTP redirect downgrade and loopback SSRF protection" do
    test "blocks HTTPS-to-HTTP downgrade and external-to-loopback redirects" do
      assert {:error, {:insecure_url, "http://127.0.0.1:8080/secret"}} =
               HTTP.validate_redirect(
                 "https://feeds.example.com/osv.zip",
                 "http://127.0.0.1:8080/secret"
               )

      assert {:error, {:insecure_url, "http://localhost:4000/secret"}} =
               HTTP.validate_redirect("https://localhost:8443/feed", "http://localhost:4000/secret")

      assert {:error, {:insecure_url, "https://127.0.0.1/admin"}} =
               HTTP.validate_redirect(
                 "https://feeds.example.com/osv.zip",
                 "https://127.0.0.1/admin"
               )

      assert {:error, {:insecure_url, "https://[::1]/admin"}} =
               HTTP.validate_redirect("https://feeds.example.com/osv.zip", "https://[::1]/admin")

      assert :ok =
               HTTP.validate_redirect("https://feeds.example.com/a", "https://cdn.example.com/b")

      assert :ok =
               HTTP.validate_redirect("http://127.0.0.1:4000/a", "http://127.0.0.1:4001/b")
    end

    @tag capture_log: true
    test "live HTTPS server redirecting to http://127.0.0.1 is rejected" do
      plain = HTTPServer.start!(fn _ -> {200, [], "secret"} end)

      san = {:Extension, {2, 5, 29, 17}, false, [{:dNSName, ~c"localhost"}]}
      cert_opts = [digest: :sha256, key: {:namedCurve, :secp256r1}]
      chain = %{root: cert_opts, intermediates: [], peer: cert_opts}

      %{server_config: server_opts, client_config: client_opts} =
        :public_key.pkix_test_data(%{
          server_chain: %{chain | peer: [extensions: [san]] ++ cert_opts},
          client_chain: chain
        })

      {:ok, listener} =
        :ssl.listen(0, [mode: :binary, active: false, ip: {127, 0, 0, 1}] ++ server_opts)

      on_exit(fn -> :ssl.close(listener) end)
      {:ok, {_, port}} = :ssl.sockname(listener)

      server =
        Task.async(fn ->
          {:ok, sock} = :ssl.transport_accept(listener, 5_000)

          try do
            {:ok, conn} = :ssl.handshake(sock, 5_000)
            {:ok, _req} = :ssl.recv(conn, 0, 5_000)

            :ssl.send(
              conn,
              "HTTP/1.1 302 Found\r\nLocation: #{plain.url}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
          after
            :ssl.close(sock)
          end
        end)

      expected = plain.url <> "/secret"

      assert {:error, {:insecure_url, ^expected}} =
               HTTP.get("https://localhost:#{port}/", [],
                 cacerts: client_opts[:cacerts],
                 retries: 0,
                 retry_delay_ms: 1
               )

      assert :ok = Task.await(server, 5_000)
      assert HTTPServer.requests(plain) == []
    end
  end

  # -- F-17 & F-19: Config adapter families & CLI help -------------------------

  describe "F-17 & F-19: adapter_families reconciliation and CLI help" do
    test "Config rejects :finch and :req and matches Adapters.families/0 1:1" do
      assert Enum.sort(Config.adapter_families()) == Enum.sort(Map.keys(Adapters.families()))
      refute :finch in Config.adapter_families()
      refute :req in Config.adapter_families()

      dir = Tmp.mkdir!("f17-cfg")

      for family <- ["finch", "req"] do
        Tmp.write!(dir, ".vulncheck.exs", "[configured_adapters: [#{family}: SomeMod]]")
        assert {:error, msg} = Config.from_cli_and_file(["--project-dir", dir])
        assert msg =~ "unknown adapter family"
      end
    end

    test "CLI.usage/0 documents feeds import, feeds prune, and single-scan --bundle semantics" do
      help = CLI.usage()
      assert help =~ "vulncheck feeds import FILE"
      assert help =~ "vulncheck feeds prune"
      assert help =~ "does not import into cache"
    end
  end

  # -- Round 2 Audit Fixes (R-01 through R-09) ---------------------------------

  describe "R-01: closures, shorthand captures, remote calls and 2nd-arg Erlang keys in config/*.exs" do
    test "detects arity-mismatched fn/shorthand remote calls and 2nd-arg Erlang module keys" do
      root =
        build_mix_project!("r01_app",
          mod: "R01App.Application",
          deps: [
            {"exvuln", "1.0.0"},
            {"erlvuln", "1.0.0"},
            {"shortvuln", "1.0.0"},
            {"srvvuln", "1.0.0"}
          ],
          configs: [
            {"runtime.exs",
             """
             import Config
             config :r01_app, :cb, fn x -> ExVuln.boom(x, :opt) end
             config :r01_app, :erl_cb, fn x -> :erl_vuln_r01.boom(x, :opt) end
             config :r01_app, :shorthand, &ShortVuln.boom(&1, :opt)
             config :r01_app, :r01_erl_server, [port: 8080]
             """}
          ],
          dep_modules: [
            {"exvuln", "1.0.0",
             [
               {"ex_vuln.ex",
                """
                defmodule ExVuln do
                  def boom(x, _opt), do: x
                end
                """}
             ], []},
            {"erlvuln", "1.0.0", [],
             [
               {"erl_vuln_r01.erl",
                """
                -module(erl_vuln_r01).
                -export([boom/2]).
                boom(X, _Opt) -> X.
                """}
             ]},
            {"shortvuln", "1.0.0",
             [
               {"short_vuln.ex",
                """
                defmodule ShortVuln do
                  def boom(x, _opt), do: x
                end
                """}
             ], []},
            {"srvvuln", "1.0.0", [],
             [
               {"srv_vuln.erl",
                """
                -module(srv_vuln).
                -export([hit/1]).
                hit(X) -> X.
                """}
             ]}
          ],
          app_ex: [
            {"application.ex",
             """
             defmodule R01App.Application do
               def start(_type, _args) do
                 Application.get_env(:r01_app, :cb).(:hello)
                 {:ok, self()}
               end
             end
             """}
          ],
          app_erl: [
            {"r01_erl_server.erl",
             """
             -module(r01_erl_server).
             -behaviour(gen_server).
             -export([init/1, handle_call/3]).
             init(Arg) -> {ok, Arg}.
             handle_call(Req, _From, State) -> {reply, srv_vuln:hit(Req), State}.
             """}
          ]
        )

      cache = Tmp.mkdir!("r01-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      specs = [
        {"CVE-2026-91001", "exvuln", "'Elixir.ExVuln':boom/2"},
        {"CVE-2026-91002", "erlvuln", "erl_vuln_r01:boom/2"},
        {"CVE-2026-91003", "shortvuln", "'Elixir.ShortVuln':boom/2"},
        {"CVE-2026-91004", "srvvuln", "srv_vuln:hit/1"}
      ]

      osvs =
        Enum.map(specs, fn {cve, pkg, _r} ->
          %{
            "id" => "EEF-#{cve}",
            "aliases" => [cve],
            "affected" => [
              %{
                "package" => %{"ecosystem" => "Hex", "name" => pkg},
                "ranges" => [
                  %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
                ]
              }
            ]
          }
        end)

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip(osvs))

      for {cve, pkg, routine} <- specs do
        File.write!(
          Path.join(feeds, "cves/#{cve}.json"),
          JSON.encode!(Feeds.cve_record(cve, pkg, [routine]))
        )
      end

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["exvuln"].verdict == :reachable
      assert by_pkg["erlvuln"].verdict == :reachable
      assert by_pkg["shortvuln"].verdict == :reachable
      assert by_pkg["srvvuln"].verdict == :reachable
    end
  end

  describe "R-02: Code.eval_string, Code.eval_quoted and :erl_eval emit unconstrained escapes" do
    for {label, body} <- [
          {"Code.eval_string/1", "Code.eval_string(expr)"},
          {"Code.eval_quoted/1", "Code.eval_quoted(expr)"},
          {":erl_eval.expr/2", ":erl_eval.expr(expr, [])"}
        ] do
      test "#{label} without any separate apply/3 or fun.(x) escapes to potentially_reachable" do
        root =
          build_mix_project!("r02_eval",
            mod: "R02Eval.Application",
            deps: [{"evaldep", "1.0.0"}],
            dep_modules: [
              {"evaldep", "1.0.0",
               [
                 {"eval_dep.ex",
                  """
                  defmodule EvalDep do
                    def boom(a, b, c), do: {a, b, c}
                  end
                  """}
               ], []}
            ],
            app_ex: [
              {"application.ex",
               """
               defmodule R02Eval.Application do
                 def start(_type, _args) do
                   run(:erlang.get(:code))
                   {:ok, self()}
                 end

                 def run(expr) do
                   #{unquote(body)}
                 end
               end
               """}
            ]
          )

        cache =
          seed_single_advisory!("CVE-2026-91010", "evaldep", "2.0.0", ["'Elixir.EvalDep':boom/3"])

        report = scan_project!(root, cache)

        assert [%Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch}] =
                 report.findings
      end
    end
  end

  describe "R-03 & R-04: Phoenix.Controller soundness guards and scoped __plug_tuple__" do
    test "R-03: custom action/2 with two apply/3 calls proves routed action and keeps hook target potentially_reachable" do
      root =
        build_mix_project!("r03_two_apply",
          mod: "R03Two.Application",
          deps: [{"livevuln", "1.0.0"}, {"hookvuln", "1.0.0"}],
          dep_modules: [
            {"livevuln", "1.0.0", [{"live.ex", "defmodule R03Live do def boom(x), do: x end"}], []},
            {"hookvuln", "1.0.0", [{"hook.ex", "defmodule R03Hook do def boom(x), do: x end"}], []}
          ],
          app_ex: [
            {"app.ex",
             """
             defmodule Phoenix.Controller do
               @callback init(term()) :: term()
               @callback call(term(), term()) :: term()
               @callback action(term(), term()) :: term()
             end

             defmodule R03Two.Application do
               def start(_type, _args), do: R03Two.Router.call(%{params: %{}}, [])
             end

             defmodule R03Two.Router do
               def call(conn, _opts), do: R03Two.ReportController.call(conn, :index)
             end

             defmodule R03Two.ReportController do
               @behaviour Phoenix.Controller
               def init(opts), do: opts
               def call(conn, opts), do: action(conn, opts)

               def action(conn, _opts) do
                 apply(__MODULE__, :erlang.get(:hook), [conn, conn.params])
                 apply(__MODULE__, Map.get(conn, :action), [conn, conn.params])
               end

               def index(_conn, params), do: R03Live.boom(params)
               def audit_request(_conn, params), do: R03Hook.boom(params)
             end
             """}
          ]
        )

      cache = Tmp.mkdir!("r03-two-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osvs = [
        %{
          "id" => "EEF-CVE-2026-91020",
          "aliases" => ["CVE-2026-91020"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "livevuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        },
        %{
          "id" => "EEF-CVE-2026-91021",
          "aliases" => ["CVE-2026-91021"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "hookvuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        }
      ]

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip(osvs))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-91020.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-91020", "livevuln", ["'Elixir.R03Live':boom/1"]))
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-91021.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-91021", "hookvuln", ["'Elixir.R03Hook':boom/1"]))
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["livevuln"].verdict == :reachable
      assert by_pkg["livevuln"].reason == :call_chain_proven
      assert by_pkg["hookvuln"].verdict == :potentially_reachable
      assert by_pkg["hookvuln"].reason == :unresolved_dynamic_dispatch
    end

    test "R-03: custom action/2 with dynamic args list (arity: nil) does not silence exports" do
      root =
        build_mix_project!("r03_dyn_args",
          mod: "R03DynArgs.Application",
          deps: [{"hookvuln", "1.0.0"}],
          dep_modules: [
            {"hookvuln", "1.0.0", [{"hook.ex", "defmodule R03HookA do def boom(x), do: x end"}], []}
          ],
          app_ex: [
            {"app.ex",
             """
             defmodule Phoenix.Controller do
               @callback init(term()) :: term()
               @callback call(term(), term()) :: term()
               @callback action(term(), term()) :: term()
             end

             defmodule R03DynArgs.Application do
               def start(_type, _args), do: R03DynArgs.Router.call(%{}, [])
             end

             defmodule R03DynArgs.Router do
               def call(conn, _opts), do: R03DynArgs.Ctrl.call(conn, :index)
             end

             defmodule R03DynArgs.Ctrl do
               @behaviour Phoenix.Controller
               def init(opts), do: opts
               def call(conn, opts), do: action(conn, opts)
               def action(_conn, _opts), do: apply(__MODULE__, :erlang.get(:f), :erlang.get(:args))
               def index(_c, p), do: p
               def secret(_c, p), do: R03HookA.boom(p)
             end
             """}
          ]
        )

      cache =
        seed_single_advisory!("CVE-2026-91022", "hookvuln", "2.0.0", ["'Elixir.R03HookA':boom/1"])

      report = scan_project!(root, cache)

      assert [%Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch}] =
               report.findings
    end

    test "R-03: external apply(Ctrl, :call, [conn, dyn_action]) prevents silencing unrouted actions" do
      root =
        build_mix_project!("r03_ext_apply",
          mod: "R03Ext.Application",
          deps: [{"livevuln", "1.0.0"}, {"deadvuln", "1.0.0"}],
          dep_modules: [
            {"livevuln", "1.0.0", [{"live.ex", "defmodule R03ExtLive do def boom(x), do: x end"}],
             []},
            {"deadvuln", "1.0.0", [{"dead.ex", "defmodule R03ExtDead do def boom(x), do: x end"}],
             []}
          ],
          app_ex: [
            {"app.ex",
             """
             defmodule Phoenix.Controller do
               @callback init(term()) :: term()
               @callback call(term(), term()) :: term()
               @callback action(term(), term()) :: term()
             end

             defmodule R03Ext.Application do
               def start(_type, _args) do
                 R03Ext.Router.call(%{params: %{}}, [])
                 R03Ext.Bypass.call(%{params: %{}}, :erlang.get(:act))
               end
             end

             defmodule R03Ext.Router do
               def call(conn, _opts), do: R03Ext.Ctrl.call(conn, :index)
             end

             defmodule R03Ext.Bypass do
               def call(conn, dyn), do: apply(R03Ext.Ctrl, :call, [conn, dyn])
             end

             defmodule R03Ext.Ctrl do
               @behaviour Phoenix.Controller
               def init(opts), do: opts
               def call(conn, opts), do: action(conn, opts)
               def action(conn, _opts), do: apply(__MODULE__, Map.get(conn, :action), [conn, conn.params])
               def index(_c, p), do: R03ExtLive.boom(p)
               def hidden(_c, p), do: R03ExtDead.boom(p)
             end
             """}
          ]
        )

      cache = Tmp.mkdir!("r03-ext-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osvs = [
        %{
          "id" => "EEF-CVE-2026-91023",
          "aliases" => ["CVE-2026-91023"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "livevuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        },
        %{
          "id" => "EEF-CVE-2026-91024",
          "aliases" => ["CVE-2026-91024"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "deadvuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        }
      ]

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip(osvs))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-91023.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-91023", "livevuln", ["'Elixir.R03ExtLive':boom/1"]))
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-91024.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-91024", "deadvuln", ["'Elixir.R03ExtDead':boom/1"]))
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["livevuln"].verdict == :reachable
      assert by_pkg["deadvuln"].verdict == :potentially_reachable
      assert by_pkg["deadvuln"].reason == :unresolved_dynamic_dispatch
    end

    test "R-04: unrelated {Controller, self()} 2-tuple does not poison Phoenix.Controller precision" do
      root =
        build_mix_project!("r04_tuple",
          mod: "R04Tuple.Application",
          deps: [{"livevuln", "1.0.0"}, {"deadvuln", "1.0.0"}],
          dep_modules: [
            {"livevuln", "1.0.0", [{"live.ex", "defmodule R04Live do def boom(x), do: x end"}], []},
            {"deadvuln", "1.0.0", [{"dead.ex", "defmodule R04Dead do def boom(x), do: x end"}], []}
          ],
          app_ex: [
            {"app.ex",
             """
             defmodule Phoenix.Controller do
               @callback init(term()) :: term()
               @callback call(term(), term()) :: term()
               @callback action(term(), term()) :: term()
             end

             defmodule R04Tuple.Application do
               def start(_type, _args) do
                 R04Tuple.Metrics.track()
                 R04Tuple.Router.call(%{params: %{}}, [])
                 {:ok, self()}
               end
             end

             defmodule R04Tuple.Metrics do
               def track, do: {R04Tuple.ReportController, self()}
             end

             defmodule R04Tuple.Router do
               def call(conn, _opts), do: R04Tuple.ReportController.call(conn, :index)
             end

             defmodule R04Tuple.ReportController do
               @behaviour Phoenix.Controller
               def init(opts), do: opts
               def call(conn, opts), do: action(conn, opts)
               def action(conn, _opts), do: apply(__MODULE__, Map.get(conn, :action), [conn, conn.params])
               def index(_c, p), do: R04Live.boom(p)
               def unused_action(_c, p), do: R04Dead.boom(p)
             end
             """}
          ]
        )

      cache = Tmp.mkdir!("r04-cache")
      feeds = Path.join(cache, "feeds")
      File.mkdir_p!(Path.join(feeds, "cves"))

      osvs = [
        %{
          "id" => "EEF-CVE-2026-91025",
          "aliases" => ["CVE-2026-91025"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "livevuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        },
        %{
          "id" => "EEF-CVE-2026-91026",
          "aliases" => ["CVE-2026-91026"],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => "deadvuln"},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
              ]
            }
          ]
        }
      ]

      File.write!(Path.join(feeds, "osv_hex_all.zip"), Feeds.zip(osvs))

      File.write!(
        Path.join(feeds, "cves/CVE-2026-91025.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-91025", "livevuln", ["'Elixir.R04Live':boom/1"]))
      )

      File.write!(
        Path.join(feeds, "cves/CVE-2026-91026.json"),
        JSON.encode!(Feeds.cve_record("CVE-2026-91026", "deadvuln", ["'Elixir.R04Dead':boom/1"]))
      )

      report = scan_project!(root, cache)
      by_pkg = Map.new(report.findings, &{&1.package, &1})

      assert by_pkg["livevuln"].verdict == :reachable
      assert by_pkg["livevuln"].reason == :call_chain_proven
      assert by_pkg["deadvuln"].verdict == :unreachable
      assert by_pkg["deadvuln"].reason == :function_not_called
    end
  end

  describe "R-05 & R-06: MixProject project/0 helpers, pipes, ~w(...)a, boolean ops, custom envs and coverage" do
    test "resolves delegated project/0 helper, flags unresolved project/0, supports |>, ~w(...)a, or/||/and/&&, and custom envs" do
      delegated = """
      defmodule Delegated.MixProject do
        use Mix.Project
        def project, do: base_project()
        defp base_project, do: [app: :delegated, version: "0.9.0", deps: deps()]

        defp deps do
          [
            [{:sigil_dev, "~> 1.0", only: ~w(dev test)a}],
            [{:sigil_str, "~> 1.0", only: ~w(dev test)s}],
            if(Mix.env() == :dev or Mix.env() == :test, do: [{:or_dep, "~> 1.0"}]),
            if(Mix.env() == :dev || Mix.env() == :test, do: [{:pipe_or_dep, "~> 1.0"}]),
            if(Mix.env() != :prod && Mix.env() != :docs, do: [{:and_dep, "~> 1.0"}]),
            if(:dev == Mix.env(), do: [{:rev_eq, "~> 1.0"}]),
            if(Mix.env() in ~w(dev test)a, do: [{:in_sigil, "~> 1.0"}]),
            env_deps(Mix.env())
          ]
          |> List.flatten()
        end

        defp env_deps(:prod), do: []
        defp env_deps(_), do: [{:benchee, "~> 1.0", only: :bench}]
      end
      """

      {:ok, ast} = Literal.quote_string(delegated, file: "mix.exs")
      proj = MixProject.analyze(ast, "mix.exs")
      assert proj.app == "delegated"
      assert proj.version == "0.9.0"
      assert proj.deps_parsed == true

      by_name = Map.new(proj.deps, &{&1.name, &1})
      assert by_name["sigil_dev"].only == ["dev", "test"]
      assert by_name["sigil_str"].only == :all
      assert by_name["or_dep"].only == ["dev", "test"]
      assert by_name["pipe_or_dep"].only == ["dev", "test"]
      refute "prod" in by_name["and_dep"].only
      refute "docs" in by_name["and_dep"].only
      assert by_name["rev_eq"].only == ["dev"]
      assert by_name["in_sigil"].only == ["dev", "test"]
      assert by_name["benchee"].only == ["bench"]

      # Unresolved project/0 must NEVER silently report deps_parsed: true
      unresolved = """
      defmodule Unresolved.MixProject do
        use Mix.Project
        def project, do: External.project_opts()
        defp deps, do: [{:fallback_dep, "~> 1.0"}]
      end
      """

      {:ok, u_ast} = Literal.quote_string(unresolved, file: "mix.exs")
      u_proj = MixProject.analyze(u_ast, "mix.exs")
      assert u_proj.deps_parsed == false
      assert Enum.map(u_proj.deps, & &1.name) == ["fallback_dep"]

      # Missing project/0 altogether also returns deps_parsed: false
      {:ok, empty_ast} = Literal.quote_string("defmodule Empty do end", file: "mix.exs")
      assert MixProject.analyze(empty_ast, "mix.exs").deps_parsed == false
    end

    test "covers guarded clauses, case/cond edge branches, cycles, and pipes in project/0" do
      guarded_src = """
      defmodule Guarded.MixProject do
        use Mix.Project
        @bad_attr @bad_attr
        def project, do: [app: :guarded, version: "1.0.0", deps: deps()]

        defp deps do
          g_clause(Mix.env()) ++
            g_literal(:dev) ++
            g_literal(:prod) ++
            g_literal(:none_match) ++
            case_guards() ++
            cond_neq()
        end

        defp g_clause(e) when e === :dev or e == :test, do: [{:g_or, "~> 1.0"}]
        defp g_clause(e) when e != :prod and not (e == :docs), do: [{:g_and_neq, "~> 1.0"}]
        defp g_clause(e) when :bench == e, do: [{:g_rev, "~> 1.0"}]
        defp g_clause(e) when is_atom(e), do: [{:g_unknown, "~> 1.0"}]

        defp g_literal(e) when e in ~w(dev test)a, do: [{:lit_in, "~> 1.0"}]
        defp g_literal(e) when e != :dev, do: [{:lit_neq, "~> 1.0"}]

        defp case_guards do
          case Mix.env() do
            e when e == :dev -> [{:c_dev, "~> 1.0"}]
            e when e != :prod -> [{:c_not_prod, "~> 1.0"}]
            _ -> [{:c_rest, "~> 1.0"}]
          end
        end

        defp cond_neq do
          cond do
            Mix.env() != :prod -> [{:cond_not_prod, "~> 1.0"}]
            System.get_env("ANY") -> [{:cond_unk, "~> 1.0"}]
            true -> [{:cond_default, "~> 1.0"}]
          end
        end
      end
      """

      {:ok, ast} = Literal.quote_string(guarded_src, file: "mix.exs")
      proj = MixProject.analyze(ast, "mix.exs")
      assert proj.deps_parsed == true
      names = Enum.map(proj.deps, & &1.name)
      assert "g_or" in names
      assert "g_and_neq" in names
      assert "g_rev" in names
      assert "lit_in" in names
      assert "lit_neq" in names
      assert "c_dev" in names
      assert "cond_not_prod" in names

      # Cyclic project/0 helper & cyclic @attr / local var in deps/0
      for bad_src <- [
            """
            defmodule CyclicProj.MixProject do
              use Mix.Project
              def project, do: p1()
              defp p1, do: p2()
              defp p2, do: p1()
            end
            """,
            """
            defmodule MissingHelperProj.MixProject do
              use Mix.Project
              def project, do: nonexistent_project_helper()
            end
            """,
            """
            defmodule BadAttr.MixProject do
              use Mix.Project
              @a @b
              @b @a
              def project, do: [app: :bad_attr, deps: @a]
            end
            """,
            """
            defmodule UnknownCall.MixProject do
              use Mix.Project
              def project, do: [app: :unk, deps: missing_fn() ++ missing_1(Mix.env()) ++ one_arg(var)]
              defp one_arg(:prod), do: []
            end
            """,
            """
            defmodule BadTuples.MixProject do
              use Mix.Project
              @non_str 123
              def project, do: [app: :bad_tuples, version: @non_str, deps: [{:a, 123}, {:b, []}, {:c, "~> 1.0", :not_kw}]]
            end
            """
          ] do
        {:ok, b_ast} = Literal.quote_string(bad_src, file: "mix.exs")
        assert MixProject.analyze(b_ast, "mix.exs").deps_parsed == false
      end

      # Pipe + Keyword.merge in project/0, compound boolean env combinators,
      # unknown branches, non-assignment block statements, bare tuple dep, and
      # literal env wildcard/unknown/no-match clauses.
      combo_src = """
      defmodule Combo.MixProject do
        use Mix.Project

        def project do
          [app: :combo, version: "2.0.0"]
          |> Keyword.merge(deps: deps())
        end

        defp deps do
          :noop_statement

          [
            if(Mix.env() == :dev, do: {:bare_dev, "~> 1.0", only: [:dev, :test]}),
            if(System.get_env("FLAG"), do: [{:unk_do, "~> 1.0"}], else: [{:unk_else, "~> 1.0"}]),
            if(not System.get_env("FLAG"), do: [{:neg_unk, "~> 1.0"}]),
            if(Mix.env() != :prod or Mix.env() != :dev, do: [{:or_excl, "~> 1.0"}]),
            if(Mix.env() == :dev or System.get_env("X"), do: [{:or_unk, "~> 1.0"}]),
            if(Mix.env() in [:dev, :test] and Mix.env() in [:test, :prod], do: [{:and_inc, "~> 1.0"}]),
            if(Mix.env() in [:dev, :test] and Mix.env() != :test, do: [{:and_inc_exc, "~> 1.0"}]),
            if(Mix.env() != :test and Mix.env() in [:dev, :test], do: [{:and_exc_inc, "~> 1.0"}]),
            if(Mix.env() == :dev and System.get_env("X"), do: [{:and_unk, "~> 1.0"}]),
            if(other_env() == :dev, do: [{:other_eq, "~> 1.0"}]),
            if(Mix.env() == other_env(), do: [{:rhs_non_atom, "~> 1.0"}]),
            if(Mix.env() in [], do: [{:empty_in, "~> 1.0"}]),
            if(Mix.env() in other_env(), do: [{:non_list_in, "~> 1.0"}]),
            {:only_non_list, "~> 1.0", only: 123}
          ] ++
            lit_only_dev(:prod) ++
            lit_wild(:prod) ++
            lit_unk(:prod)
        end

        defp lit_only_dev(:dev), do: [{:never_hit, "~> 1.0"}]
        defp lit_wild(_), do: [{:wild_hit, "~> 1.0"}]
        defp lit_unk(e) when is_atom(e), do: [{:unk_guard_hit, "~> 1.0"}]
      end
      """

      {:ok, c_ast} = Literal.quote_string(combo_src, file: "mix.exs")
      c_proj = MixProject.analyze(c_ast, "mix.exs")
      assert c_proj.app == "combo"
      assert c_proj.version == "2.0.0"
      # lit_only_dev(:prod) has no matching clause -> conservatively marks deps_parsed: false
      assert c_proj.deps_parsed == false

      by_name = Map.new(c_proj.deps, &{&1.name, &1})
      assert by_name["bare_dev"].only == ["dev"]
      assert by_name["and_inc"].only == ["test"]
      assert by_name["and_inc_exc"].only == ["dev"]
      assert by_name["and_exc_inc"].only == ["dev"]
      assert by_name["only_non_list"].only == :all
      assert Map.has_key?(by_name, "wild_hit")
      assert Map.has_key?(by_name, "unk_guard_hit")
      refute Map.has_key?(by_name, "never_hit")
    end
  end

  describe "R-07: HTTP redirect SSRF protection across IPv4/IPv6 loopback, unspecified, link-local and private ranges" do
    test "blocks redirects from public origins to all restricted internal addresses" do
      blocked_targets = [
        "https://0.0.0.0/a",
        "https://[::]/a",
        "https://[::ffff:127.0.0.1]/a",
        "https://[::ffff:169.254.169.254]/latest/meta-data",
        "https://[0:0:0:0:0:0:0:1]/a",
        "https://localhost./a",
        "https://sub.localhost/a",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/a",
        "https://172.16.0.1/a",
        "https://192.168.1.1/a",
        "https://100.64.0.1/a",
        "https://[fc00::1]/a",
        "https://[fd12:3456::1]/a",
        "https://[fe80::1]/a"
      ]

      for target <- blocked_targets do
        assert {:error, {:insecure_url, ^target}} =
                 HTTP.validate_redirect("https://example.com/a", target),
               "expected redirect to #{target} to be blocked"
      end

      assert :ok = HTTP.validate_redirect("https://example.com/a", "https://8.8.8.8/a")

      assert :ok =
               HTTP.validate_redirect("https://example.com/a", "https://[2606:4700:4700::1111]/a")

      # validate_url keeps plain http restricted strictly to loopback
      assert :ok = HTTP.validate_url("http://127.0.0.1:4000/a")
      assert :ok = HTTP.validate_url("http://[::1]:4000/a")
      assert :ok = HTTP.validate_url("http://localhost./a")
      assert {:error, {:insecure_url, _}} = HTTP.validate_url("http://0.0.0.0/a")
      assert {:error, {:insecure_url, _}} = HTTP.validate_url("http://169.254.169.254/a")
    end
  end

  describe "R-08: Toml subtables under [[array_of_tables]]" do
    test "parses [packages.extra] subtables belonging to [[packages]] array items" do
      {:ok, doc} =
        Toml.parse("""
        [[packages]]
        name = "p1"
        [packages.extra]
        k = 1

        [[packages]]
        name = "p2"
        [packages.extra]
        k = 2
        """)

      assert doc == %{
               "packages" => [
                 %{"name" => "p1", "extra" => %{"k" => 1}},
                 %{"name" => "p2", "extra" => %{"k" => 2}}
               ]
             }
    end
  end

  describe "R-09: GitUrl case-insensitive .GIT suffix and ErlTerm nesting depth limit" do
    test "strips .GIT suffix case-insensitively" do
      assert GitUrl.repo_slug("https://GITHUB.COM/Owner/Repo.GIT") == "owner/repo"
      assert GitUrl.repo_slug("Owner/Repo.GIT") == "owner/repo"

      assert GitUrl.repo_slug("https://gitlab.com/Group/Sub/Repo.Git") ==
               "gitlab.com/group/sub/repo"
    end

    test "ErlTerm.parse/1 enforces maximum nesting depth on lists, tuples, maps and negations" do
      deep_list = String.duplicate("[", 150) <> "1" <> String.duplicate("]", 150) <> "."
      deep_tuple = String.duplicate("{", 150) <> "1" <> String.duplicate("}", 150) <> "."
      deep_map = String.duplicate("\#{a => ", 150) <> "1" <> String.duplicate("}", 150) <> "."
      deep_neg = String.duplicate("-", 150) <> "1."

      for input <- [deep_list, deep_tuple, deep_map, deep_neg] do
        assert {:error, msg} = ErlTerm.parse(input)
        assert msg =~ "maximum nesting depth exceeded"
      end
    end
  end
end

defmodule VulnCheck.AuditV102EnvRegressionTest do
  use ExUnit.Case, async: false

  alias VulnCheck.Report.Formatter
  alias VulnCheck.Test.Tmp
  alias VulnCheck.Types.Workspace

  test "F-15: Formatter.repo_prefix/1 honors GITHUB_WORKSPACE env var" do
    repo = Tmp.mkdir!("f15-gh")
    sub = Path.join(repo, "services/payments")
    File.mkdir_p!(sub)

    previous = System.get_env("GITHUB_WORKSPACE")
    System.put_env("GITHUB_WORKSPACE", repo)

    on_exit(fn ->
      if previous,
        do: System.put_env("GITHUB_WORKSPACE", previous),
        else: System.delete_env("GITHUB_WORKSPACE")
    end)

    ws = %Workspace{
      root_dir: sub,
      project_name: "payments",
      project_type: :mix,
      env: :prod,
      otp_release: "27"
    }

    assert Formatter.repo_prefix(ws) == "services/payments"
  end
end
