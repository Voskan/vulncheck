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

  Roots the project does not call itself carry an activation hop
  (`VulnCheck.Types.Entrypoint`): a daemon's protocol handlers point to the
  project function that starts the daemon (or one depending on it, such as
  `Bandit` for `thousand_island`), else to the `.app` file whose boot tree
  starts it; modules of dependencies named in the configuration point to
  the configuration line.
  """

  alias VulnCheck.Beam.CallGraph
  alias VulnCheck.Config
  alias VulnCheck.Entrypoints.{Adapters, Behaviours, OtpApp}
  alias VulnCheck.Types.{Entrypoint, EntrypointModel, MFA, ModuleSummary, TraceHop, Workspace}

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
    activations = daemon_activations(workspace, graph, otp, daemons)

    roots =
      (application_roots(otp) ++
         library_roots(otp, graph) ++
         config_roots(adapters, graph) ++
         daemon_roots(daemons, activations, graph) ++ extra_roots(config, workspace, graph))
      |> Enum.uniq_by(& &1.mfa)

    configured =
      Enum.uniq(adapters.config_refs ++ Enum.flat_map(adapters.configured, &elem(&1, 1)))

    synthetic = synthesize(graph, roots, configured)

    model = %EntrypointModel{
      roots: roots,
      synthetic_edges: synthetic.edges,
      started_otp_apps: otp.started,
      active_daemon_packages: daemons,
      configured_adapters: adapters.configured,
      inactive_adapter_packages: adapters.inactive,
      resolved_dynamic_modules: synthetic.resolved_dynamic_modules,
      resolved_dynamic_calls: synthetic.resolved_dynamic_calls,
      active_plug_parsers: synthetic.active_plug_parsers,
      boot_tree_known: otp.boot_tree_known,
      notes: otp.notes ++ adapters.notes
    }

    {model, CallGraph.add_edges(graph, synthetic.edges)}
  end

  # Framework rules read configurations and module names, which only count
  # when written in reachable code: `Plug.Parsers` options inside
  # `Plug.Debugger` must not enable parsers for the whole application, and a
  # Tesla middleware that only names itself is not part of any stack. The
  # rules start from nothing reachable and are recomputed from what the
  # graph reaches until nothing new is reached (the least fixpoint). If that
  # takes too many rounds, the rules fall back to every configuration and
  # name in the code, which over-approximates.
  @refine_rounds 10
  @refined_modules ["Elixir.Plug.Parsers", "Elixir.Tesla"]

  defp synthesize(graph, roots, configured) do
    if Enum.any?(@refined_modules, &CallGraph.module?(graph, &1)),
      do: grow(graph, roots, configured, MapSet.new(), nil, @refine_rounds),
      else: Behaviours.synthesize(graph, configured_modules: configured)
  end

  defp grow(graph, _roots, configured, _reachable, _previous, 0),
    do: Behaviours.synthesize(graph, configured_modules: configured)

  defp grow(graph, roots, configured, reachable, previous, rounds) do
    synthetic = Behaviours.synthesize(graph, reachable: reachable, configured_modules: configured)

    if previous != nil and synthetic.state == previous.state do
      synthetic
    else
      next = graph |> CallGraph.add_edges(synthetic.edges) |> CallGraph.reachable(roots)
      grow(graph, roots, configured, next, synthetic, rounds - 1)
    end
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

  defp config_roots(adapters, graph) do
    for ref <- Enum.uniq(adapters.config_refs),
        {:ok, summary} <- [Map.fetch(graph.modules, ref)],
        activation = config_activation(summary, Map.get(adapters.config_sites, ref)),
        mfa <- Behaviours.entry_functions(summary) do
      %Entrypoint{mfa: mfa, kind: :entrypoint, source: "config", activation: activation}
    end
  end

  defp config_activation(%ModuleSummary{package: nil}, _site), do: nil

  defp config_activation(%ModuleSummary{module: module}, site) do
    {file, line} = site || {nil, nil}

    %TraceHop{
      mfa: nil,
      file: file,
      line: line,
      kind: :config_activation,
      note: "the configuration names #{MFA.display_module(module)}"
    }
  end

  defp daemon_roots(daemons, activations, graph) do
    daemons = MapSet.new(daemons)

    for summary <- graph.modules |> Map.values() |> Enum.sort_by(& &1.module),
        MapSet.member?(daemons, summary.package),
        Enum.any?(summary.behaviours, &(&1 in @daemon_behaviours)),
        {function, arity} <- summary.exports,
        function not in ["module_info", "__info__"] do
      %Entrypoint{
        mfa: %MFA{module: summary.module, function: function, arity: arity},
        kind: :daemon,
        source: summary.package,
        activation: Map.get(activations, summary.package)
      }
    end
  end

  defp extra_roots(%Config{extra_entrypoints: extra} = config, workspace, graph)
       when is_list(extra) do
    for %MFA{} = mfa <- extra do
      activation =
        case Map.fetch(graph.modules, mfa.module) do
          {:ok, %ModuleSummary{package: package}} when is_binary(package) ->
            %TraceHop{
              mfa: nil,
              file: config_file(config, workspace),
              kind: :config_activation,
              note: "extra_entrypoints lists #{MFA.format(mfa)}"
            }

          _ ->
            nil
        end

      %Entrypoint{mfa: mfa, kind: :extra, source: "configuration", activation: activation}
    end
  end

  defp extra_roots(_config, _workspace, _graph), do: []

  defp config_file(%Config{config_file: file}, %Workspace{root_dir: root}) when is_binary(file),
    do: Path.relative_to(file, root)

  defp config_file(_config, _workspace), do: nil

  # Why the protocol handlers of each active daemon package run: the project
  # function that names the daemon's module (preferring application `start/2`
  # callbacks), or one naming a daemon that depends on the package, or the
  # boot tree of the project's application.
  defp daemon_activations(workspace, graph, otp, daemons) do
    starters = otp.app_modules |> Map.values() |> MapSet.new()

    direct =
      for summary <- project_modules(graph),
          {caller, ref, file, line} <- summary.module_refs,
          package = Map.get(@daemon_modules, ref),
          package in daemons do
        {package, {caller, ref, file, line}}
      end
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Map.new(fn {package, sites} ->
        {package,
         Enum.min_by(sites, fn {caller, _ref, file, line} ->
           start? = caller.function == "start" and MapSet.member?(starters, caller.module)
           {not start?, file || "", line || 0, MFA.format(caller)}
         end)}
      end)

    Map.new(daemons, fn package ->
      {package, daemon_activation(workspace, direct, package)}
    end)
  end

  defp daemon_activation(workspace, direct, package) do
    case Map.fetch(direct, package) do
      {:ok, site} ->
        site_hop(site, "starts #{display(site)}")

      :error ->
        runner =
          direct
          |> Enum.sort()
          |> Enum.find(fn {starter, _site} ->
            Map.has_key?(dependency_closure(workspace, starter), package)
          end)

        case runner do
          {_starter, site} -> site_hop(site, "starts #{display(site)}, which runs #{package}")
          nil -> boot_hop(workspace, package)
        end
    end
  end

  defp site_hop({caller, _ref, file, line}, note),
    do: %TraceHop{mfa: caller, file: file, line: line, kind: :daemon_activation, note: note}

  defp display({_caller, ref, _file, _line}), do: MFA.display_module(ref)

  defp boot_hop(%Workspace{} = workspace, package) do
    {app, file} =
      Enum.find_value(workspace.root_apps, {nil, nil}, fn app ->
        Enum.find_value(workspace.root_ebin_dirs, fn dir ->
          path = Path.join(dir, "#{app}.app")
          if File.regular?(path), do: {app, Path.relative_to(path, workspace.root_dir)}
        end)
      end)

    note =
      if app,
        do: "the #{app} application starts #{package} at boot",
        else: "#{package} is started at boot"

    %TraceHop{mfa: nil, file: file, kind: :daemon_activation, note: note}
  end

  defp dependency_closure(%Workspace{packages: packages}, name) do
    walk_deps([name], packages, %{})
  end

  defp walk_deps([], _packages, seen), do: seen

  defp walk_deps([name | rest], packages, seen) do
    if Map.has_key?(seen, name) do
      walk_deps(rest, packages, seen)
    else
      deps =
        case Map.get(packages, name) do
          %{deps: deps} -> deps
          nil -> []
        end

      walk_deps(deps ++ rest, packages, Map.put(seen, name, true))
    end
  end

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
