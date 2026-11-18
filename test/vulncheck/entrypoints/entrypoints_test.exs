defmodule VulnCheck.Entrypoints.EntrypointsTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Beam.{CallGraph, Loader}
  alias VulnCheck.Config
  alias VulnCheck.Entrypoints
  alias VulnCheck.Entrypoints.{Adapters, Behaviours, OtpApp}
  alias VulnCheck.Test.{Beams, Tmp}
  alias VulnCheck.Types.{Entrypoint, EntrypointModel, MFA, Package, Workspace}

  defp package(name, ebin, extra \\ []) do
    struct(
      %Package{
        name: name,
        version: "1.0.0",
        source: :hex,
        scope: :prod,
        otp_app: name,
        ebin_dir: ebin
      },
      extra
    )
  end

  defp workspace(root, root_apps, packages) do
    %Workspace{
      root_dir: root,
      project_name: hd(root_apps),
      project_type: :mix,
      env: :prod,
      otp_release: "27",
      root_apps: root_apps,
      root_ebin_dirs: Enum.map(root_apps, &Path.join(root, "_build/prod/lib/#{&1}/ebin")),
      packages: Map.new(packages, &{&1.name, &1})
    }
  end

  defp ebin(root, app), do: Path.join(root, "_build/prod/lib/#{app}/ebin")

  defp analyze(ws, config \\ nil) do
    %{modules: modules} = Loader.load_workspace(ws)
    graph = CallGraph.build(modules)
    {model, graph} = Entrypoints.build(ws, graph, config)
    {model, graph, CallGraph.reachable(graph, model.roots)}
  end

  defp mfa(m, f, a), do: MFA.new(m, f, a)

  describe "OTP supervision and GenServer callbacks" do
    setup do
      root = Tmp.mkdir!("ep-genserver")

      Beams.compile!(ebin(root, "ep_dep"), [
        {"vuln.ex",
         """
         defmodule EpFix.Dep.Vuln do
           def run(x), do: x
           def unused, do: :nope
         end
         """}
      ])

      Beams.write_app!(ebin(root, "ep_dep"), "ep_dep", applications: [:kernel, :stdlib])

      Beams.compile!(ebin(root, "ep_app"), [
        {"app.ex",
         """
         defmodule EpFix.Application do
           use Application

           def start(_type, _args) do
             children = [EpFix.Cache]
             EpFix.Worker.start_link(:arg)
             Supervisor.start_link(children, strategy: :one_for_one)
           end
         end

         defmodule EpFix.Worker do
           use GenServer

           def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
           def init(arg), do: {:ok, arg}
           def handle_call(:run, _from, state), do: {:reply, EpFix.Dep.Vuln.run(state), state}
         end

         defmodule EpFix.Cache do
           use GenServer

           def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
           def init(state), do: {:ok, state}
           def handle_info(:tick, state), do: {:noreply, EpFix.Render.render(state)}
         end

         defprotocol EpFix.Render do
           def render(value)
         end

         defimpl EpFix.Render, for: Map do
           def render(map), do: EpFix.Dyn.dispatch(map, :a)
         end

         defmodule EpFix.Dyn do
           def dispatch(x, fun), do: apply(EpFix.Dyn, fun, [x])
           def a(x), do: x
           def b(x), do: x
           def c(x, y), do: {x, y}
         end

         defmodule EpFix.Orphan do
           def lonely, do: EpFix.Dep.Vuln.unused()
         end
         """}
      ])

      Beams.write_app!(ebin(root, "ep_app"), "ep_app",
        applications: [:kernel, :stdlib, :elixir, :ep_dep],
        optional_applications: [:ep_missing],
        mod: "Elixir.EpFix.Application"
      )

      ws = workspace(root, ["ep_app"], [package("ep_dep", ebin(root, "ep_dep"))])
      %{ws: ws}
    end

    test "application start makes GenServer callbacks and their callees reachable", %{ws: ws} do
      {model, graph, reachable} = analyze(ws)

      assert %EntrypointModel{boot_tree_known: true} = model

      assert [%Entrypoint{kind: :application_start, mfa: start, source: "ep_app.app"}] =
               model.roots

      assert start == mfa("Elixir.EpFix.Application", "start", 2)
      assert "ep_dep" in model.started_otp_apps
      refute "ep_missing" in model.started_otp_apps

      assert mfa("Elixir.EpFix.Worker", "handle_call", 3) in reachable
      assert mfa("Elixir.EpFix.Dep.Vuln", "run", 1) in reachable
      refute mfa("Elixir.EpFix.Dep.Vuln", "unused", 0) in reachable
      refute mfa("Elixir.EpFix.Orphan", "lonely", 0) in reachable

      # supervisor child referenced by literal, then protocol dispatch and apply/3
      assert mfa("Elixir.EpFix.Cache", "handle_info", 2) in reachable
      assert mfa("Elixir.EpFix.Render.Map", "render", 1) in reachable
      assert mfa("Elixir.EpFix.Dyn", "a", 1) in reachable
      assert mfa("Elixir.EpFix.Dyn", "b", 1) in reachable
      refute mfa("Elixir.EpFix.Dyn", "c", 2) in reachable

      assert model.resolved_dynamic_modules["Elixir.EpFix.Render"] == ["Elixir.EpFix.Render.Map"]

      assert {:ok, hops} =
               CallGraph.shortest_path(graph, model.roots, [mfa("Elixir.EpFix.Dep.Vuln", "run", 1)])

      assert Enum.map(hops, &{&1.mfa.function, &1.kind}) == [
               {"start", :entrypoint},
               {"start_link", :static_call},
               {"handle_call", :behaviour_callback},
               {"run", :static_call}
             ]
    end

    test "libraries and unknown boot trees expose every public function", %{ws: ws} do
      File.rm!(Path.join(hd(ws.root_ebin_dirs), "ep_app.app"))
      {model, _graph, reachable} = analyze(ws)

      refute model.boot_tree_known
      assert [note] = model.notes
      assert note =~ "no compiled .app file for ep_app"
      assert Enum.all?(model.roots, &(&1.kind == :library_export))
      assert mfa("Elixir.EpFix.Dep.Vuln", "unused", 0) in reachable
    end

    test "extra entrypoints and config references become roots", %{ws: ws} do
      config_dir = Path.join(ws.root_dir, "config")
      File.mkdir_p!(config_dir)

      File.write!(
        Path.join(config_dir, "config.exs"),
        "import Config\nconfig :ep_app, worker: EpFix.Orphan\n"
      )

      config = %Config{extra_entrypoints: [mfa("Elixir.EpFix.Orphan", "lonely", 0)]}
      {model, _graph, reachable} = analyze(ws, config)

      assert Enum.any?(model.roots, &(&1.kind == :extra))
      assert mfa("Elixir.EpFix.Dep.Vuln", "unused", 0) in reachable
    end
  end

  describe "Plug.Parsers" do
    setup do
      root = Tmp.mkdir!("ep-plug")

      Beams.compile!(ebin(root, "plug"), [
        {"parsers.ex",
         """
         defmodule Plug.Parsers do
           def init(opts) do
             for parser <- Keyword.fetch!(opts, :parsers) do
               module = Module.concat(Plug.Parsers, String.upcase(Atom.to_string(parser)))
               {module, module.init(opts)}
             end
           end

           def call(conn, parsers) do
             Enum.reduce(parsers, conn, fn {parser, opts}, acc ->
               parser.parse(acc, "application", "x", %{}, opts)
             end)
           end
         end

         defmodule Plug.Parsers.JSON do
           def init(opts), do: Keyword.get(opts, :json_decoder)
           def parse(conn, _type, _subtype, _headers, decoder), do: decoder.decode!(conn)
         end

         defmodule Plug.Parsers.MULTIPART do
           def init(opts), do: opts
           def parse(conn, _type, _subtype, _headers, _opts), do: Plug.Parsers.MULTIPART.Vuln.boundary(conn)
         end

         defmodule Plug.Parsers.MULTIPART.Vuln do
           def boundary(conn), do: conn
         end

         defmodule Plug.Parsers.URLENCODED do
           def init(opts), do: opts
           def parse(conn, _type, _subtype, _headers, _opts), do: conn
         end
         """}
      ])

      Beams.compile!(ebin(root, "ep_jason"), [
        {"jason.ex", "defmodule Jason do\n  def decode!(x), do: x\nend\n"}
      ])

      %{root: root}
    end

    defp plug_workspace(root, endpoint_source) do
      Beams.compile!(ebin(root, "ep_web"), [{"endpoint.ex", endpoint_source}])

      workspace(root, ["ep_web"], [
        package("plug", ebin(root, "plug")),
        package("jason", ebin(root, "ep_jason"))
      ])
    end

    test "static parser lists only activate the configured parsers", %{root: root} do
      ws =
        plug_workspace(root, """
        defmodule EpFix.Endpoint do
          def call(conn, _opts) do
            Plug.Parsers.call(conn, Plug.Parsers.init(parsers: [:json], json_decoder: Jason))
          end
        end
        """)

      {model, _graph, reachable} = analyze(ws)

      assert model.active_plug_parsers == ["Elixir.Plug.Parsers.JSON"]
      assert mfa("Elixir.Plug.Parsers.JSON", "parse", 5) in reachable
      assert mfa("Elixir.Jason", "decode!", 1) in reachable
      refute mfa("Elixir.Plug.Parsers.MULTIPART", "parse", 5) in reachable
      refute mfa("Elixir.Plug.Parsers.MULTIPART.Vuln", "boundary", 1) in reachable
    end

    test "parser configurations in unreachable code are ignored", %{root: root} do
      Beams.compile!(ebin(root, "plug"), [
        {"debugger.ex",
         """
         defmodule Plug.Debugger do
           def call(conn, _opts) do
             Plug.Parsers.call(conn, Plug.Parsers.init(parsers: [:urlencoded, :multipart]))
           end
         end
         """}
      ])

      json_only = """
      defmodule EpFix.JsonEndpoint do
        def call(conn, _opts) do
          Plug.Parsers.call(conn, Plug.Parsers.init(parsers: [:json], json_decoder: Jason))
        end
      end
      """

      {model, _graph, reachable} = analyze(plug_workspace(root, json_only))

      assert model.active_plug_parsers == ["Elixir.Plug.Parsers.JSON"]
      refute mfa("Elixir.Plug.Parsers.URLENCODED", "parse", 5) in reachable
      refute mfa("Elixir.Plug.Parsers.MULTIPART.Vuln", "boundary", 1) in reachable

      with_debugger = """
      defmodule EpFix.DebugEndpoint do
        def call(conn, opts) do
          conn = Plug.Debugger.call(conn, opts)
          Plug.Parsers.call(conn, Plug.Parsers.init(parsers: [:json], json_decoder: Jason))
        end
      end
      """

      {model, _graph, reachable} = analyze(plug_workspace(root, with_debugger))

      assert model.active_plug_parsers == [
               "Elixir.Plug.Parsers.JSON",
               "Elixir.Plug.Parsers.MULTIPART",
               "Elixir.Plug.Parsers.URLENCODED"
             ]

      assert mfa("Elixir.Plug.Parsers.MULTIPART.Vuln", "boundary", 1) in reachable
    end

    test "dynamic parser lists activate every parser", %{root: root} do
      ws =
        plug_workspace(root, """
        defmodule EpFix.DynamicEndpoint do
          def call(conn, parsers) do
            Plug.Parsers.call(conn, Plug.Parsers.init(parsers: parsers))
          end
        end
        """)

      {model, _graph, reachable} = analyze(ws)
      assert model.active_plug_parsers == :all
      assert mfa("Elixir.Plug.Parsers.MULTIPART.Vuln", "boundary", 1) in reachable
    end
  end

  describe "adapters" do
    defp adapter_workspace(config_source, extra_packages \\ []) do
      root = Tmp.mkdir!("ep-adapters")

      if config_source do
        File.mkdir_p!(Path.join(root, "config"))
        File.write!(Path.join(root, "config/prod.exs"), config_source)
      end

      packages = [
        package("tesla", nil, optional_deps: ["hackney", "mint", "finch"]),
        package("hackney", nil),
        package("mint", nil),
        package("finch", nil, deps: ["mint"])
      ]

      workspace(root, ["ep_tesla_app"], packages ++ extra_packages)
    end

    test "an unconfigured Tesla adapter package is inactive" do
      ws = adapter_workspace("import Config\nconfig :tesla, adapter: Tesla.Adapter.Mint\n")
      result = Adapters.resolve(ws, %{}, nil)

      assert result.configured == %{tesla: ["Elixir.Tesla.Adapter.Mint"]}
      assert result.inactive["hackney"] =~ "tesla (configured: Tesla.Adapter.Mint)"
      refute Map.has_key?(result.inactive, "mint")
      # finch is inactive too, but mint stays because finch depends on it
      assert Map.has_key?(result.inactive, "finch")
    end

    test "adapters with options, CLI configuration and other dependents" do
      ws =
        adapter_workspace(
          "import Config\nconfig :tesla, MyClient, adapter: {Tesla.Adapter.Finch, name: F}\n",
          [package("sentry", nil, deps: ["hackney"])]
        )

      config = %Config{configured_adapters: %{tesla: ["Tesla.Adapter.Gun"]}}
      result = Adapters.resolve(ws, %{}, config)

      assert result.configured.tesla == ["Elixir.Tesla.Adapter.Finch", "Elixir.Tesla.Adapter.Gun"]
      # sentry needs hackney on its own
      refute Map.has_key?(result.inactive, "hackney")
      refute Map.has_key?(result.inactive, "finch")
    end

    test "defaults apply without configuration and dynamic values keep everything" do
      ws = adapter_workspace(nil)
      assert Adapters.resolve(ws, %{}, nil).configured.tesla == ["Elixir.Tesla.Adapter.Httpc"]

      ws = adapter_workspace("import Config\nconfig :tesla, adapter: System.get_env(\"A\")\n")
      result = Adapters.resolve(ws, %{}, nil)
      assert result.inactive == %{}
      assert [note] = result.notes
      assert note =~ "configured dynamically"

      ws = adapter_workspace("import Config\nconfig :tesla, adapter: \n")
      result = Adapters.resolve(ws, %{}, nil)
      assert result.inactive == %{}
      assert Enum.any?(result.notes, &(&1 =~ "could not parse config/prod.exs"))
    end

    test "module literals in project code count as configuration" do
      ws = adapter_workspace(nil)

      summary = %VulnCheck.Types.ModuleSummary{
        module: "Elixir.MyClient",
        module_refs: [
          {mfa("Elixir.MyClient", "__adapter__", 0), "Elixir.Tesla.Adapter.Hackney", nil, 1}
        ]
      }

      result = Adapters.resolve(ws, %{"Elixir.MyClient" => summary}, nil)
      assert result.configured.tesla == ["Elixir.Tesla.Adapter.Hackney"]
      refute Map.has_key?(result.inactive, "hackney")
      # finch (an adapter package itself) is the only other dependent of mint
      assert Map.has_key?(result.inactive, "mint")
    end
  end

  test "daemon packages started at boot are active and expose their handlers" do
    root = Tmp.mkdir!("ep-daemon")

    Beams.compile!(ebin(root, "thousand_island"), [
      {"handler.ex",
       """
       defmodule ThousandIsland.Handler do
         @callback handle_data(term(), term(), term()) :: term()
       end

       defmodule EpFix.Daemon.Conn do
         @behaviour ThousandIsland.Handler
         def handle_data(data, _socket, state), do: {data, state}
       end
       """}
    ])

    Beams.write_app!(ebin(root, "thousand_island"), "thousand_island")

    Beams.compile!(ebin(root, "ep_d"), [
      {"app.ex", "defmodule EpFix.DaemonApp do\n  def start(_, _), do: :ok\nend\n"}
    ])

    Beams.write_app!(ebin(root, "ep_d"), "ep_d",
      applications: [:thousand_island],
      mod: "Elixir.EpFix.DaemonApp"
    )

    ws = workspace(root, ["ep_d"], [package("thousand_island", ebin(root, "thousand_island"))])
    {model, _graph, reachable} = analyze(ws)

    assert model.active_daemon_packages == ["thousand_island"]
    assert Enum.any?(model.roots, &(&1.kind == :daemon))
    assert mfa("Elixir.EpFix.Daemon.Conn", "handle_data", 3) in reachable
    assert Entrypoints.daemon_packages() |> Enum.member?("bandit")
  end

  test "OTP application tree follows included applications" do
    root = Tmp.mkdir!("ep-otp")
    Beams.write_app!(ebin(root, "top"), "top", included_applications: [:inc], mod: "Elixir.Top")
    Beams.write_app!(ebin(root, "inc"), "inc", applications: [:deep], mod: "Elixir.Inc")
    Beams.write_app!(ebin(root, "deep"), "deep")

    ws =
      workspace(root, ["top"], [
        package("inc", ebin(root, "inc")),
        package("deep", ebin(root, "deep"))
      ])

    result = OtpApp.analyze(ws)
    assert result.started == ["deep", "inc", "top"]
    assert result.app_modules == %{"inc" => "Elixir.Inc", "top" => "Elixir.Top"}
    assert result.root_has_mod
    assert Behaviours.callbacks("Elixir.GenServer") |> Enum.member?("handle_call/3")
  end
end
