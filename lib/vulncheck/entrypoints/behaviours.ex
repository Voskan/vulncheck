defmodule VulnCheck.Entrypoints.Behaviours do
  @moduledoc """
  Synthesizes the call edges that OTP and framework behaviours create at
  runtime and that never appear as direct calls in the bytecode.

    * Starting a behaviour module (`start_link/*`, `child_spec/1`, `init/1`,
      `new/*` for Oban workers, `__live__/0` for LiveViews) links all of its
      callbacks (`:behaviour_callback`).
    * A literal reference to a module (a supervisor child, a plug, a
      registered GenServer name, a router target) links the referencing
      function to that module's start functions and callbacks
      (`:supervisor_child`).
    * `apply(Mod, fun, args)` with a known module and an unknown function
      links every exported function of matching arity as a candidate.
    * Protocol functions are linked to the matching `defimpl` functions.
    * `Plug.Parsers` is linked only to the parsers configured statically
      (`parsers: [:json]`), or to every parser when the list is dynamic;
      parsers are linked to the callback modules of their options (body
      reader, JSON decoder).
    * Framework dispatch through a module held in a variable is linked to
      the implementations of the framework's behaviour: ThousandIsland
      transports, Mint connections and transports.
    * The Tesla middleware stack (`Tesla.run/2`) is linked to the `call`
      functions of the modules named in reachable code or configuration.
  """

  alias VulnCheck.Beam.CallGraph
  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary}

  @callbacks %{
    "Elixir.GenServer" =>
      ~w(init/1 handle_call/3 handle_cast/2 handle_info/2 handle_continue/2 terminate/2 code_change/3 format_status/1 format_status/2),
    "gen_server" =>
      ~w(init/1 handle_call/3 handle_cast/2 handle_info/2 handle_continue/2 terminate/2 code_change/3 format_status/1 format_status/2),
    "Elixir.Supervisor" => ~w(init/1),
    "supervisor" => ~w(init/1),
    "supervisor_bridge" => ~w(init/1 terminate/2),
    "Elixir.DynamicSupervisor" => ~w(init/1),
    "Elixir.Application" => ~w(start/2 stop/1 prep_stop/1 start_phase/3 config_change/3),
    "application" => ~w(start/2 stop/1 prep_stop/1 start_phase/3 config_change/3),
    "gen_statem" => ~w(init/1 callback_mode/0 handle_event/4 terminate/3 code_change/4),
    "gen_event" => ~w(init/1 handle_event/2 handle_call/2 handle_info/2 terminate/2),
    "Elixir.Task" => ~w(start_link/1),
    "Elixir.Plug" => ~w(init/1 call/2),
    "Elixir.Plug.Parsers" => ~w(init/1 parse/5),
    "Elixir.Phoenix.Endpoint" => ~w(init/1 call/2 start_link/1 config_change/2),
    "Elixir.Phoenix.Router" => ~w(init/1 call/2),
    "Elixir.Phoenix.Controller" => ~w(init/1 call/2 action/2),
    "Elixir.Phoenix.LiveView" =>
      ~w(mount/3 handle_params/3 handle_event/3 handle_info/2 handle_call/3 handle_cast/2 handle_async/3 render/1 terminate/2),
    "Elixir.Phoenix.LiveComponent" =>
      ~w(mount/1 update/2 update_many/1 handle_event/3 handle_async/3 render/1),
    "Elixir.Phoenix.Channel" => ~w(join/3 handle_in/3 handle_info/2 handle_out/3 terminate/2),
    "Elixir.Phoenix.Socket" => ~w(connect/2 connect/3 id/1),
    "Elixir.Phoenix.Socket.Transport" =>
      ~w(child_spec/1 connect/1 init/1 handle_in/2 handle_info/2 handle_control/2 terminate/2),
    "Elixir.Oban.Worker" => ~w(perform/1 backoff/1 timeout/1),
    "Elixir.Broadway" => ~w(handle_message/3 handle_batch/4 handle_failed/2 prepare_messages/2),
    "Elixir.GenStage" =>
      ~w(init/1 handle_events/3 handle_demand/2 handle_call/3 handle_cast/2 handle_info/2 handle_subscribe/4 handle_cancel/3),
    "cowboy_handler" => ~w(init/2 terminate/3),
    "cowboy_websocket" =>
      ~w(init/2 websocket_init/1 websocket_handle/2 websocket_info/2 terminate/3),
    "cowboy_rest" => ~w(init/2 terminate/3),
    "cowboy_stream" => ~w(init/3 data/4 info/3 terminate/3 early_error/5),
    "ranch_protocol" => ~w(start_link/3 start_link/4),
    "Elixir.ThousandIsland.Handler" =>
      ~w(handle_connection/2 handle_data/3 handle_close/2 handle_error/3 handle_shutdown/2 handle_timeout/2),
    "Elixir.WebSock" => ~w(init/1 handle_in/2 handle_info/2 handle_control/2 terminate/2),
    "Elixir.Logger.Backend" => ~w(init/1 handle_event/2 handle_call/2 handle_info/2)
  }

  @activation ~w(child_spec/1 start_link/0 start_link/1 start_link/2 start_link/3 start/0 start/1 start/2
                 init/1 init/2 call/2 __live__/0)
  @extra_activation %{"Elixir.Oban.Worker" => ~w(new/1 new/2)}

  @parser_modules %{
    "urlencoded" => "Elixir.Plug.Parsers.URLENCODED",
    "multipart" => "Elixir.Plug.Parsers.MULTIPART",
    "json" => "Elixir.Plug.Parsers.JSON"
  }
  # {caller module prefix, behaviours implemented by every possible target}
  @behaviour_dispatch [
    {"Elixir.ThousandIsland.", ["Elixir.ThousandIsland.Transport"]},
    {"Elixir.Mint.", ["Elixir.Mint.Core.Conn", "Elixir.Mint.Core.Transport"]}
  ]
  @tesla_run %MFA{module: "Elixir.Tesla", function: "run", arity: 2}

  @default_json_decoders ["Elixir.Jason", "Elixir.JSON", "Elixir.Poison"]
  @protocol_internal ~w(__protocol__/1 impl_for/1 impl_for!/1 __info__/1 module_info/0 module_info/1 behaviour_info/1)
  @internal_exports ~w(module_info __info__ behaviour_info)

  @type result :: %{
          edges: [CallEdge.t()],
          resolved_dynamic_modules: %{String.t() => [String.t()]},
          resolved_dynamic_calls: MapSet.t(DynamicCall.t()),
          active_plug_parsers: [String.t()] | :all,
          state: term()
        }

  @doc "Callback signatures (`\"name/arity\"`) known for a behaviour."
  @spec callbacks(String.t()) :: [String.t()]
  def callbacks(behaviour), do: Map.get(@callbacks, behaviour, [])

  @doc """
  Computes all synthetic edges for the loaded modules.

  Options:

    * `:reachable` (a set of functions, default `:all`) restricts the
      `Plug.Parsers` configurations and the module names that feed dynamic
      framework calls to those written in these functions;
    * `:configured_modules` — modules named by the project configuration.
  """
  @spec synthesize(CallGraph.t(), keyword()) :: result()
  def synthesize(%CallGraph{modules: modules}, opts \\ []) do
    exports = Map.new(modules, fn {name, s} -> {name, MapSet.new(s.exports)} end)
    defined = Map.new(modules, fn {name, s} -> {name, MapSet.new(s.functions)} end)
    sorted = modules |> Map.values() |> Enum.sort_by(& &1.module)
    reachable = Keyword.get(opts, :reachable, :all)

    {parsers, parser_edges, parser_resolved, parser_dispatch} =
      plug_parsers(modules, exports, reachable)

    {protocol_edges, protocol_resolved} = protocols(sorted, exports)
    resolved = Map.merge(parser_resolved, protocol_resolved)

    configured = Keyword.get(opts, :configured_modules, [])
    named = named_modules(sorted, reachable, configured)

    {controller_edges, controller_resolved_calls, controller_state} =
      phoenix_controllers(sorted, exports, reachable)

    dispatch =
      parser_dispatch ++
        behaviour_dispatch(sorted, exports) ++
        tesla_stack(sorted, modules, exports, named, configured) ++
        phoenix_router_dispatch(modules, exports, named)

    resolved_calls =
      dispatch
      |> MapSet.new(&elem(&1, 0))
      |> MapSet.union(controller_resolved_calls)

    plug_parsers_loaded? = Map.has_key?(modules, "Elixir.Plug.Parsers")

    edges =
      Enum.flat_map(sorted, &intra_module_edges(&1, defined, plug_parsers_loaded?)) ++
        Enum.flat_map(sorted, &reference_edges(&1, modules, defined, plug_parsers_loaded?)) ++
        Enum.flat_map(sorted, &dynamic_edges(&1, exports, resolved, resolved_calls)) ++
        protocol_edges ++ parser_edges ++ controller_edges ++ dispatch_edges(dispatch)

    %{
      edges: edges,
      resolved_dynamic_modules: resolved,
      resolved_dynamic_calls: resolved_calls,
      active_plug_parsers: parsers,
      state:
        {parsers, Enum.sort(Enum.map(dispatch, fn {call, targets} -> {call, targets} end)),
         Enum.sort(controller_state)}
    }
  end

  @doc """
  Functions that a reference to `module` may run: start functions and
  behaviour callbacks that the module defines.
  """
  @spec entry_functions(ModuleSummary.t()) :: [MFA.t()]
  def entry_functions(%ModuleSummary{} = summary) do
    defined = MapSet.new(summary.functions)

    (@activation ++ callback_names(summary) ++ extra_activation(summary))
    |> Enum.uniq()
    |> Enum.flat_map(&to_mfa(summary.module, &1, defined))
  end

  defp intra_module_edges(%ModuleSummary{} = summary, defined, plug_parsers_loaded?) do
    callbacks =
      summary
      |> callback_names()
      |> filter_managed_parser_callbacks(summary, plug_parsers_loaded?)

    if callbacks == [] do
      []
    else
      functions = Map.fetch!(defined, summary.module)

      starters =
        Enum.flat_map(
          @activation ++ extra_activation(summary),
          &to_mfa(summary.module, &1, functions)
        )

      targets = Enum.flat_map(callbacks, &to_mfa(summary.module, &1, functions))

      for from <- starters, to <- targets, from != to do
        %CallEdge{from: from, to: to, kind: :behaviour_callback}
      end
    end
  end

  defp reference_edges(%ModuleSummary{module_refs: refs}, modules, _defined, plug_parsers_loaded?) do
    refs
    |> Enum.flat_map(fn {caller, ref, file, line} ->
      case Map.fetch(modules, ref) do
        {:ok, target} ->
          entries =
            target
            |> entry_functions()
            |> filter_managed_parser_entries(target, plug_parsers_loaded?)

          for to <- entries, to != caller do
            %CallEdge{from: caller, to: to, file: file, line: line, kind: :supervisor_child}
          end

        :error ->
          []
      end
    end)
  end

  # When `Plug.Parsers` is loaded, `plug_parsers/3` owns dispatching `parse/5`
  # exclusively to configured parsers (preserving both parser filtering and
  # `:dynamic_candidate` attribution).
  defp filter_managed_parser_callbacks(callbacks, %ModuleSummary{behaviours: behaviours}, true) do
    if "Elixir.Plug.Parsers" in behaviours,
      do: Enum.reject(callbacks, &(&1 == "parse/5")),
      else: callbacks
  end

  defp filter_managed_parser_callbacks(callbacks, _summary, false), do: callbacks

  defp filter_managed_parser_entries(entries, %ModuleSummary{behaviours: behaviours}, true) do
    if "Elixir.Plug.Parsers" in behaviours,
      do: Enum.reject(entries, &(&1.function == "parse" and &1.arity == 5)),
      else: entries
  end

  defp filter_managed_parser_entries(entries, _summary, false), do: entries

  defp dynamic_edges(
         %ModuleSummary{module: module, dynamic_dispatches: calls},
         exports,
         resolved,
         resolved_calls
       ) do
    calls
    |> Enum.filter(&(&1.kind == :module_function and not MapSet.member?(resolved_calls, &1)))
    |> Enum.flat_map(fn %DynamicCall{} = call ->
      targets =
        case call.known_module do
          nil -> Map.get(resolved, module, [])
          known -> [known]
        end

      for target <- targets,
          {:ok, functions} <- [Map.fetch(exports, target)],
          {function, arity} <- Enum.sort(functions),
          call.known_function in [nil, function],
          DynamicCall.arity_compatible?(call, arity),
          function not in ["module_info", "__info__"] do
        %CallEdge{
          from: call.caller,
          to: %MFA{module: target, function: function, arity: arity},
          file: call.file,
          line: call.line,
          kind: :dynamic_candidate
        }
      end
    end)
  end

  # A framework that keeps a transport or connection module in a variable
  # only ever calls implementations of its own behaviour. Calls whose
  # function no implementation exports stay unresolved.
  defp behaviour_dispatch(sorted, exports) do
    for {prefix, behaviours} <- @behaviour_dispatch,
        implementers = implementers(sorted, behaviours),
        implementers != [],
        %ModuleSummary{module: module, dynamic_dispatches: calls} <- sorted,
        String.starts_with?(module, prefix),
        %DynamicCall{known_module: nil, known_function: fun} = call when is_binary(fun) <- calls,
        targets = matching(implementers, exports, call, fun),
        targets != [],
        do: {call, targets}
  end

  defp implementers(sorted, behaviours) do
    for %ModuleSummary{module: module, behaviours: declared} <- sorted,
        Enum.any?(declared, &(&1 in behaviours)),
        do: module
  end

  # `Tesla.run/2` applies `{module, :call, args}` entries of the middleware
  # stack; every entry comes from a literal written in a client, the
  # configuration or Tesla itself (the default adapter). Middlewares are
  # `call/3` functions; the last entry is an adapter (`call/2`), which
  # implements `Tesla.Adapter` or is named by the configuration.
  defp tesla_stack(sorted, modules, exports, named, configured) do
    case Map.fetch(modules, "Elixir.Tesla") do
      {:ok, %ModuleSummary{dynamic_dispatches: calls}} ->
        adapters = MapSet.new(implementers(sorted, ["Elixir.Tesla.Adapter"]) ++ configured)
        exported? = fn module, fa -> MapSet.member?(Map.get(exports, module, MapSet.new()), fa) end

        candidates =
          Enum.filter(named, fn module ->
            exported?.(module, {"call", 3}) or
              (exported?.(module, {"call", 2}) and MapSet.member?(adapters, module))
          end)

        for %DynamicCall{caller: @tesla_run, known_module: nil, known_function: fun} = call <-
              calls,
            fun in [nil, "call"],
            do: {call, tesla_targets(candidates, exports, adapters, call)}

      :error ->
        []
    end
  end

  defp tesla_targets(candidates, exports, adapters, call) do
    candidates
    |> matching(exports, call, "call")
    |> Enum.filter(&(&1.arity == 3 or MapSet.member?(adapters, &1.module)))
  end

  # `Phoenix.Router.__call__/5` dispatches to the plug/controller matched by
  # the router; only plugs named in reachable code or configuration can run.
  defp phoenix_router_dispatch(modules, exports, named) do
    case Map.fetch(modules, "Elixir.Phoenix.Router") do
      {:ok, %ModuleSummary{dynamic_dispatches: calls}} ->
        plugs =
          named
          |> Enum.filter(fn mod ->
            MapSet.member?(Map.get(exports, mod, MapSet.new()), {"call", 2})
          end)
          |> Enum.uniq()
          |> Enum.sort()

        for %DynamicCall{known_module: nil, kind: :module_function, known_function: fun} = call <-
              calls,
            (fun == "call" and DynamicCall.arity_compatible?(call, 2)) or
              (fun == "init" and DynamicCall.arity_compatible?(call, 1)),
            do: {call, matching(plugs, exports, call, fun)}

      :error ->
        []
    end
  end

  # `use Phoenix.Controller` implements `action/2` as
  # `apply(__MODULE__, action_name(conn), [conn, conn.params])`. When every
  # reachable router/plug site targeting `ctrl` passes a literal exported
  # action atom, emit proven `:behaviour_callback` edges to those actions and
  # resolve `action/2`'s dynamic call. If no sites are known or any site is
  # dynamic, leave `action/2` unresolved so `dynamic_edges/4` falls back
  # soundly to `:dynamic_candidate` across all `/2` exports.
  defp phoenix_controllers(sorted, exports, reachable) do
    in_scope? = fn caller -> reachable == :all or MapSet.member?(reachable, caller) end

    controller_sites =
      for %ModuleSummary{init_literals: literals} <- sorted,
          {caller, %MFA{module: ctrl, function: fun, arity: 2}, args, file, line} <- literals,
          fun in ["call", "__plug_tuple__"],
          in_scope?.(caller),
          reduce: %{} do
        acc ->
          opt =
            case {fun, args} do
              {"call", [_conn, opt]} -> opt
              {"__plug_tuple__", [opt]} -> opt
              _ -> :dynamic
            end

          Map.update(acc, ctrl, [{opt, file, line}], &[{opt, file, line} | &1])
      end

    Enum.reduce(sorted, {[], MapSet.new(), []}, fn
      %ModuleSummary{module: ctrl, behaviours: behaviours, dynamic_dispatches: calls},
      {edges_acc, resolved_acc, state_acc} ->
        if "Elixir.Phoenix.Controller" in behaviours do
          sites = controller_sites |> Map.get(ctrl, []) |> Enum.reverse()
          ctrl_exports = Map.get(exports, ctrl, MapSet.new())
          action_mfa = %MFA{module: ctrl, function: "action", arity: 2}

          static_sites =
            Enum.filter(sites, fn
              {{:atom, action}, _file, _line} ->
                action not in ["call", "init", "action"] and
                  MapSet.member?(ctrl_exports, {action, 2})

              _ ->
                false
            end)

          new_edges =
            static_sites
            |> Enum.uniq_by(fn {{:atom, action}, _, _} -> action end)
            |> Enum.map(fn {{:atom, action}, file, line} ->
              %CallEdge{
                from: action_mfa,
                to: %MFA{module: ctrl, function: action, arity: 2},
                file: file,
                line: line,
                kind: :behaviour_callback
              }
            end)

          all_static_actions? = sites != [] and length(static_sites) == length(sites)

          resolved_calls_for_ctrl =
            with true <- all_static_actions?,
                 false <- dynamically_entered?(ctrl, sorted, in_scope?, action_mfa),
                 [
                   %DynamicCall{
                     kind: :module_function,
                     known_module: ^ctrl,
                     known_function: nil,
                     arity: 2
                   } = single_call
                 ] <- Enum.filter(calls, &(&1.caller == action_mfa)) do
              [single_call]
            else
              _ -> []
            end

          resolved_acc = Enum.reduce(resolved_calls_for_ctrl, resolved_acc, &MapSet.put(&2, &1))

          actions =
            static_sites
            |> Enum.map(fn {{:atom, a}, _, _} -> a end)
            |> Enum.uniq()
            |> Enum.sort()

          state_acc =
            if actions != [] or resolved_calls_for_ctrl != [],
              do: [{ctrl, actions, resolved_calls_for_ctrl != []} | state_acc],
              else: state_acc

          {new_edges ++ edges_acc, resolved_acc, state_acc}
        else
          {edges_acc, resolved_acc, state_acc}
        end
    end)
  end

  defp dynamically_entered?(ctrl, sorted, in_scope?, action_mfa) do
    Enum.any?(sorted, fn %ModuleSummary{edges: edges, mfa_refs: refs, dynamic_dispatches: dcalls} ->
      Enum.any?(edges ++ refs, fn
        %CallEdge{
          from: from,
          to: %MFA{module: ^ctrl, function: fun, arity: 2},
          kind: :dynamic_apply
        } ->
          fun in ["call", "action"] and in_scope?.(from)

        _ ->
          false
      end) or
        Enum.any?(dcalls, fn
          %DynamicCall{caller: caller, known_module: ^ctrl, kind: :module_function} = dc ->
            caller != action_mfa and in_scope?.(caller) and
              dc.known_function in [nil, "call", "action"] and
              DynamicCall.arity_compatible?(dc, 2)

          _ ->
            false
        end)
    end)
  end

  defp matching(modules, exports, call, fun) do
    for module <- Enum.sort(modules),
        {function, arity} <- Enum.sort(Map.get(exports, module, MapSet.new())),
        function == fun,
        DynamicCall.arity_compatible?(call, arity),
        do: %MFA{module: module, function: function, arity: arity}
  end

  defp dispatch_edges(dispatch) do
    for {%DynamicCall{} = call, targets} <- dispatch, target <- targets do
      %CallEdge{
        from: call.caller,
        to: target,
        file: call.file,
        line: call.line,
        kind: :dynamic_apply
      }
    end
  end

  # Modules named as values (literals, `{Mod, :fun, args}` triples) in
  # reachable functions, plus modules named by the configuration.
  defp named_modules(sorted, reachable, configured) do
    in_scope? = fn caller -> reachable == :all or MapSet.member?(reachable, caller) end

    refs =
      for %ModuleSummary{module_refs: refs} <- sorted,
          {caller, ref, _file, _line} <- refs,
          in_scope?.(caller),
          do: ref

    triples =
      for %ModuleSummary{mfa_refs: edges} <- sorted,
          %CallEdge{from: from, to: %MFA{module: module}} <- edges,
          in_scope?.(from),
          do: module

    Enum.uniq(refs ++ triples ++ configured)
  end

  # Protocol dispatch: `Proto.fun(data)` runs `Impl.fun(data)`.
  defp protocols(sorted, exports) do
    protocols =
      sorted
      |> Enum.filter(&protocol?/1)
      |> Map.new(&{&1.module, []})

    impls =
      Enum.reduce(sorted, protocols, fn summary, acc ->
        case impl_of(summary) do
          protocol when is_map_key(acc, protocol) ->
            Map.update!(acc, protocol, &[summary.module | &1])

          _ ->
            acc
        end
      end)
      |> Map.new(fn {protocol, list} -> {protocol, Enum.sort(list)} end)

    edges =
      for {protocol, impl_modules} <- Enum.sort(impls),
          {function, arity} <- Enum.sort(Map.get(exports, protocol, MapSet.new())),
          "#{function}/#{arity}" not in @protocol_internal,
          impl <- impl_modules,
          MapSet.member?(Map.get(exports, impl, MapSet.new()), {function, arity}) do
        %CallEdge{
          from: %MFA{module: protocol, function: function, arity: arity},
          to: %MFA{module: impl, function: function, arity: arity},
          kind: :behaviour_callback
        }
      end

    {edges, impls}
  end

  defp protocol?(%ModuleSummary{} = s),
    do: Map.has_key?(s.attributes, "__protocol__") or "Elixir.Protocol" in s.behaviours

  defp impl_of(%ModuleSummary{attributes: attributes}) do
    attributes
    |> Map.get("__impl__", [])
    |> List.flatten()
    |> Enum.find_value(fn
      {:tuple, [{:atom, "protocol"}, {:atom, protocol}]} -> protocol
      _ -> nil
    end)
  end

  # Plug.Parsers dispatches to parser modules computed from its options.
  # Only sites whose caller is in `callers` (`:all`, or the reachable
  # functions) contribute: `Plug.Debugger` enabling `:urlencoded` must not
  # widen an endpoint configured with `parsers: [:json]`. When Plug.Parsers
  # runs without any known configuration, every parser is linked.
  defp plug_parsers(modules, exports, callers) do
    sites =
      for {_name, summary} <- modules,
          {caller, %MFA{module: "Elixir.Plug.Parsers"} = target, args, _file, _line} <-
            summary.init_literals,
          target.function in ["init", "call"],
          callers == :all or MapSet.member?(callers, caller),
          do: {target.function, args}

    {parsers, decoders} =
      Enum.reduce(sites, {[], []}, fn
        {"init", [opts]}, {parsers, decoders} ->
          {merge(parsers, init_parsers(opts)), decoders ++ init_decoders(opts)}

        {"call", [_conn, opts]}, {parsers, decoders} ->
          {merge(parsers, compiled_parsers(opts, modules, exports)),
           decoders ++ compiled_decoders(opts)}

        _site, {_parsers, decoders} ->
          {:all, decoders}
      end)

    parsers =
      cond do
        sites == [] and callers != :all and not parsers_reached?(callers) -> []
        sites == [] -> :all
        parsers in [[], :all] -> :all
        true -> parsers |> Enum.uniq() |> Enum.sort()
      end

    parser_modules =
      case parsers do
        :all ->
          modules
          |> Enum.filter(fn {mod, %ModuleSummary{behaviours: behaviours}} ->
            MapSet.member?(Map.get(exports, mod, MapSet.new()), {"parse", 5}) and
              (String.starts_with?(mod, "Elixir.Plug.Parsers.") or
                 "Elixir.Plug.Parsers" in behaviours)
          end)
          |> Enum.map(&elem(&1, 0))

        list ->
          list
      end
      |> Enum.uniq()
      |> Enum.sort()

    decoders =
      case Enum.uniq(decoders) do
        [] -> Enum.filter(@default_json_decoders, &Map.has_key?(modules, &1))
        list -> list
      end

    resolved =
      if Map.has_key?(modules, "Elixir.Plug.Parsers"),
        do: %{"Elixir.Plug.Parsers" => parser_modules},
        else: %{}

    # Parsers call back into the functions named by their options: the body
    # reader (`Plug.Conn.read_body/2` by default), the JSON decoder,
    # multipart callbacks. With runtime-computed options those calls stay
    # unresolved.
    dispatch =
      case parser_callbacks(sites) do
        :dynamic ->
          []

        callbacks ->
          for parser <- parser_modules,
              {:ok, %ModuleSummary{dynamic_dispatches: calls}} <- [Map.fetch(modules, parser)],
              %DynamicCall{known_module: nil, kind: :module_function} = call <- calls do
            json = if parser == "Elixir.Plug.Parsers.JSON", do: decoders, else: []

            targets =
              [{"Elixir.Plug.Conn", "read_body"}, {parser, nil} | callbacks] ++
                Enum.map(json, &{&1, nil})

            {call, callback_targets(Enum.uniq(targets), exports, call)}
          end
      end

    init = %MFA{module: "Elixir.Plug.Parsers", function: "init", arity: 1}
    calls = Map.get(modules, init.module, %{dynamic_dispatches: []}).dynamic_dispatches

    site =
      Enum.find(calls, fn call ->
        call.caller == init and call.known_function == "init" and
          DynamicCall.arity_compatible?(call, 1)
      end)

    edges =
      for parser <- parser_modules, Map.has_key?(modules, parser) do
        %CallEdge{
          from: init,
          to: %MFA{module: parser, function: "init", arity: 1},
          file: site && site.file,
          line: site && site.line,
          kind: if(parsers == :all, do: :dynamic_candidate, else: :dynamic_apply)
        }
      end

    {parsers, edges, resolved, dispatch}
  end

  defp parsers_reached?(callers),
    do: Enum.any?(callers, &(&1.module == "Elixir.Plug.Parsers"))

  defp parser_callbacks([]), do: :dynamic

  defp parser_callbacks(sites) do
    init? = Enum.any?(sites, &match?({"init", _}, &1))

    sites
    |> Enum.reduce_while([], fn
      {"call", [_conn, :dynamic]}, acc when init? -> {:cont, acc}
      {_fun, [_ | _] = args}, acc -> literal_options(List.last(args), acc)
      _site, _acc -> {:halt, :dynamic}
    end)
    |> case do
      :dynamic -> :dynamic
      atoms -> Enum.uniq(atoms)
    end
  end

  defp literal_options(opts, acc) do
    if dynamic?(opts), do: {:halt, :dynamic}, else: {:cont, acc ++ callback_refs(opts)}
  end

  # `{Mod, :fun, args}` triples name one function; other atoms may be
  # modules called with any function (`json_decoder: Jason`).
  defp callback_refs({:tuple, [{:atom, module}, {:atom, function}, args]}) when is_list(args),
    do: [{module, function} | callback_refs(args)]

  defp callback_refs({:atom, name}), do: [{name, nil}]
  defp callback_refs({:tuple, items}), do: Enum.flat_map(items, &callback_refs/1)

  defp callback_refs({:map, pairs}),
    do: Enum.flat_map(pairs, fn {k, v} -> callback_refs(k) ++ callback_refs(v) end)

  defp callback_refs(list) when is_list(list), do: Enum.flat_map(list, &callback_refs/1)
  defp callback_refs(_), do: []

  defp callback_targets(refs, exports, %DynamicCall{} = call) do
    for {module, function} <- Enum.sort(refs),
        {name, arity} <- Enum.sort(Map.get(exports, module, MapSet.new())),
        function in [nil, name],
        call.known_function in [nil, name],
        name not in ["module_info", "__info__"],
        DynamicCall.arity_compatible?(call, arity),
        uniq: true,
        do: %MFA{module: module, function: name, arity: arity}
  end

  defp merge(:all, _), do: :all
  defp merge(_, :all), do: :all
  defp merge(left, right), do: left ++ right

  defp init_parsers(opts) do
    case kw(opts, "parsers") do
      list when is_list(list) ->
        Enum.reduce_while(list, [], fn
          {:atom, name}, acc -> {:cont, [Map.get(@parser_modules, name, name) | acc]}
          _other, _acc -> {:halt, :all}
        end)

      _ ->
        :all
    end
  end

  defp init_decoders(opts) do
    case kw(opts, "json_decoder") do
      {:atom, decoder} -> [decoder]
      {:tuple, [{:atom, decoder} | _]} -> [decoder]
      _ -> []
    end
  end

  # A runtime-computed options term is covered by the `init/1` sites.
  defp compiled_parsers(:dynamic, _modules, _exports), do: []

  defp compiled_parsers(opts, modules, exports) do
    if dynamic?(opts) do
      :all
    else
      opts
      |> literal_atoms()
      |> Enum.filter(&plug_parser_module?(&1, modules, exports))
    end
  end

  defp plug_parser_module?(mod, modules, exports) do
    String.starts_with?(mod, "Elixir.Plug.Parsers.") or
      case Map.fetch(modules, mod) do
        {:ok, %ModuleSummary{behaviours: behaviours}} ->
          "Elixir.Plug.Parsers" in behaviours or
            MapSet.member?(Map.get(exports, mod, MapSet.new()), {"parse", 5})

        :error ->
          false
      end
  end

  defp compiled_decoders(opts) do
    opts
    |> literal_atoms()
    |> Enum.filter(&String.starts_with?(&1, "Elixir."))
    |> Enum.reject(&String.starts_with?(&1, "Elixir.Plug."))
  end

  defp kw(list, key) when is_list(list) do
    Enum.find_value(list, fn
      {:tuple, [{:atom, ^key}, value]} -> value
      _ -> nil
    end)
  end

  defp kw(_other, _key), do: nil

  defp literal_atoms({:atom, name}), do: [name]
  defp literal_atoms({:tuple, items}), do: Enum.flat_map(items, &literal_atoms/1)

  defp literal_atoms({:map, pairs}),
    do: Enum.flat_map(pairs, fn {k, v} -> literal_atoms(k) ++ literal_atoms(v) end)

  defp literal_atoms(list) when is_list(list), do: Enum.flat_map(list, &literal_atoms/1)
  defp literal_atoms(_), do: []

  defp dynamic?(:dynamic), do: true
  defp dynamic?({:tuple, items}), do: Enum.any?(items, &dynamic?/1)
  defp dynamic?({:map, pairs}), do: Enum.any?(pairs, fn {k, v} -> dynamic?(k) or dynamic?(v) end)
  defp dynamic?(list) when is_list(list), do: Enum.any?(list, &dynamic?/1)
  defp dynamic?(_), do: false

  defp callback_names(%ModuleSummary{behaviours: behaviours, exports: exports}) do
    static = Enum.flat_map(behaviours, &callbacks/1)

    dynamic =
      Enum.flat_map(behaviours, fn
        b when b in ["gen_statem", "Elixir.GenStatem"] ->
          for {fun, arity} <- exports,
              arity in [3, 4],
              fun not in @internal_exports,
              do: "#{fun}/#{arity}"

        "cowboy_rest" ->
          for {fun, 2} <- exports,
              fun not in @internal_exports,
              do: "#{fun}/2"

        _ ->
          []
      end)

    Enum.uniq(static ++ dynamic)
  end

  defp extra_activation(%ModuleSummary{behaviours: behaviours}) do
    Enum.flat_map(behaviours, &Map.get(@extra_activation, &1, []))
  end

  defp to_mfa(module, signature, functions) do
    [function, arity] = String.split(signature, "/")
    arity = String.to_integer(arity)

    if MapSet.member?(functions, {function, arity}),
      do: [%MFA{module: module, function: function, arity: arity}],
      else: []
  end
end
