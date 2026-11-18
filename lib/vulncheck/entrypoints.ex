defmodule VulnCheck.Entrypoints do
  @moduledoc """
  Synthesizes the BEAM execution model of a workspace: the roots of the
  reachability analysis and the indirect edges created by OTP, frameworks
  and configuration.

  Roots:

    * `start/2` of every application callback module that boots
      (`:application_start`),
    * every public function of the project when it is a library without an
      application callback, or when no compiled `.app` file is available
      (`:library_export`),
    * start functions and callbacks of modules named in `config/*.exs`
      (`:entrypoint`),
    * protocol handlers of active network daemons (`:daemon`),
    * `extra_entrypoints` from the configuration (`:extra`).
  """

  alias VulnCheck.Beam.CallGraph
  alias VulnCheck.Config
  alias VulnCheck.Entrypoints.{Adapters, Behaviours, OtpApp}
  alias VulnCheck.Types.{Entrypoint, EntrypointModel, MFA, ModuleSummary, Workspace}

  @daemon_packages ~w(bandit cowboy cowlib ranch thousand_island grpc plug_cowboy)
  @daemon_behaviours ~w(ranch_protocol cowboy_stream cowboy_handler cowboy_websocket cowboy_middleware
                        Elixir.ThousandIsland.Handler Elixir.Bandit.HTTPTransport Elixir.WebSock)
  @daemon_modules %{
    "Elixir.Bandit" => "bandit",
    "Elixir.Plug.Cowboy" => "plug_cowboy",
    "cowboy" => "cowboy",
    "ranch" => "ranch",
    "Elixir.ThousandIsland" => "thousand_island",
    "Elixir.GRPC.Server.Supervisor" => "grpc"
  }

  @doc "Packages treated as network-facing daemons."
  @spec daemon_packages() :: [String.t()]
  def daemon_packages, do: @daemon_packages

  @doc """
  Builds the entrypoint model and returns the call graph extended with the
  synthetic edges.
  """
  @spec build(Workspace.t(), CallGraph.t(), Config.t() | nil) ::
          {EntrypointModel.t(), CallGraph.t()}
  def build(%Workspace{} = workspace, %CallGraph{} = graph, config \\ nil) do
    otp = OtpApp.analyze(workspace)
    adapters = Adapters.resolve(workspace, graph.modules, config)
    started = MapSet.new(otp.started)
    daemons = active_daemons(workspace, graph, started)

    roots =
      (application_roots(otp) ++
         library_roots(otp, graph) ++
         config_roots(adapters.config_refs, graph) ++
         daemon_roots(daemons, graph) ++ extra_roots(config))
      |> Enum.uniq_by(& &1.mfa)

    synthetic = synthesize(graph, roots)

    model = %EntrypointModel{
      roots: roots,
      synthetic_edges: synthetic.edges,
      started_otp_apps: otp.started,
      active_daemon_packages: daemons,
      configured_adapters: adapters.configured,
      inactive_adapter_packages: adapters.inactive,
      resolved_dynamic_modules: synthetic.resolved_dynamic_modules,
      active_plug_parsers: synthetic.active_plug_parsers,
      boot_tree_known: otp.boot_tree_known,
      notes: otp.notes ++ adapters.notes
    }

    {model, CallGraph.add_edges(graph, synthetic.edges)}
  end

  # `Plug.Parsers` options written in unreachable code (for example inside
  # `Plug.Debugger`) are dropped by recomputing the parsers from the
  # configurations that the previous graph reaches. When no configuration
  # is reachable every parser stays linked, as without configurations.
  @parser_rounds 4

  defp synthesize(graph, roots) do
    synthetic = Behaviours.synthesize(graph)

    if CallGraph.module?(graph, "Elixir.Plug.Parsers"),
      do: refine_parsers(graph, roots, synthetic, @parser_rounds),
      else: synthetic
  end

  defp refine_parsers(_graph, _roots, synthetic, 0), do: synthetic

  defp refine_parsers(_graph, _roots, %{active_plug_parsers: :all} = synthetic, _rounds),
    do: synthetic

  defp refine_parsers(graph, roots, synthetic, rounds) do
    reachable = graph |> CallGraph.add_edges(synthetic.edges) |> CallGraph.reachable(roots)
    refined = Behaviours.synthesize(graph, parser_callers: reachable)

    if refined.active_plug_parsers == synthetic.active_plug_parsers,
      do: synthetic,
      else: refine_parsers(graph, roots, refined, rounds - 1)
  end

  defp application_roots(otp) do
    for {app, module} <- Enum.sort(otp.app_modules) do
      %Entrypoint{
        mfa: %MFA{module: module, function: "start", arity: 2},
        kind: :application_start,
        source: "#{app}.app"
      }
    end
  end

  defp library_roots(otp, graph) do
    if otp.root_has_mod and otp.boot_tree_known do
      []
    else
      for summary <- project_modules(graph),
          {function, arity} <- summary.exports,
          function not in ["module_info", "__info__"] do
        %Entrypoint{
          mfa: %MFA{module: summary.module, function: function, arity: arity},
          kind: :library_export,
          source: summary.source_file || summary.module
        }
      end
    end
  end

  defp config_roots(refs, graph) do
    for ref <- Enum.uniq(refs),
        {:ok, summary} <- [Map.fetch(graph.modules, ref)],
        mfa <- Behaviours.entry_functions(summary) do
      %Entrypoint{mfa: mfa, kind: :entrypoint, source: "config"}
    end
  end

  defp daemon_roots(daemons, graph) do
    daemons = MapSet.new(daemons)

    for summary <- graph.modules |> Map.values() |> Enum.sort_by(& &1.module),
        MapSet.member?(daemons, summary.package),
        Enum.any?(summary.behaviours, &(&1 in @daemon_behaviours)),
        {function, arity} <- summary.exports,
        function not in ["module_info", "__info__"] do
      %Entrypoint{
        mfa: %MFA{module: summary.module, function: function, arity: arity},
        kind: :daemon,
        source: summary.package
      }
    end
  end

  defp extra_roots(%Config{extra_entrypoints: extra}) when is_list(extra) do
    for %MFA{} = mfa <- extra, do: %Entrypoint{mfa: mfa, kind: :extra, source: "configuration"}
  end

  defp extra_roots(_config), do: []

  defp active_daemons(workspace, graph, started) do
    present =
      workspace
      |> Workspace.prod_packages()
      |> Enum.map(& &1.name)
      |> MapSet.new()

    by_app = OtpApp.packages_by_app(workspace)

    started_daemons =
      for app <- started,
          %{name: name} <- [Map.get(by_app, app)],
          name in @daemon_packages,
          do: name

    referenced =
      for summary <- project_modules(graph),
          {_caller, ref, _file, _line} <- summary.module_refs,
          package = Map.get(@daemon_modules, ref),
          do: package

    (started_daemons ++ referenced)
    |> Enum.filter(&MapSet.member?(present, &1))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp project_modules(%CallGraph{modules: modules}) do
    modules
    |> Map.values()
    |> Enum.filter(fn %ModuleSummary{package: package} -> is_nil(package) end)
    |> Enum.sort_by(& &1.module)
  end
end
