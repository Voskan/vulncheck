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
      links every exported function of matching arity (`:dynamic_apply`).
    * Protocol functions are linked to the matching `defimpl` functions.
    * `Plug.Parsers` is linked only to the parsers configured statically
      (`parsers: [:json]`), or to every parser when the list is dynamic.
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
    "cowboy_rest" => ~w(init/2),
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
  @default_json_decoders ["Elixir.Jason", "Elixir.JSON", "Elixir.Poison"]
  @protocol_internal ~w(__protocol__/1 impl_for/1 impl_for!/1 __info__/1 module_info/0 module_info/1 behaviour_info/1)

  @type result :: %{
          edges: [CallEdge.t()],
          resolved_dynamic_modules: %{String.t() => [String.t()]},
          active_plug_parsers: [String.t()] | :all
        }

  @doc "Callback signatures (`\"name/arity\"`) known for a behaviour."
  @spec callbacks(String.t()) :: [String.t()]
  def callbacks(behaviour), do: Map.get(@callbacks, behaviour, [])

  @doc """
  Computes all synthetic edges for the loaded modules.

  Option `:parser_callers` (a set of functions) restricts the `Plug.Parsers`
  configurations taken into account to those written in these functions.
  """
  @spec synthesize(CallGraph.t(), keyword()) :: result()
  def synthesize(%CallGraph{modules: modules}, opts \\ []) do
    exports = Map.new(modules, fn {name, s} -> {name, MapSet.new(s.exports)} end)
    defined = Map.new(modules, fn {name, s} -> {name, MapSet.new(s.functions)} end)
    sorted = modules |> Map.values() |> Enum.sort_by(& &1.module)
    callers = Keyword.get(opts, :parser_callers, :all)

    {parsers, parser_edges, parser_resolved} = plug_parsers(modules, exports, callers)
    {protocol_edges, protocol_resolved} = protocols(sorted, exports)
    resolved = Map.merge(parser_resolved, protocol_resolved)

    edges =
      Enum.flat_map(sorted, &intra_module_edges(&1, defined)) ++
        Enum.flat_map(sorted, &reference_edges(&1, modules, defined)) ++
        Enum.flat_map(sorted, &dynamic_edges(&1, exports, resolved)) ++
        protocol_edges ++ parser_edges

    %{edges: edges, resolved_dynamic_modules: resolved, active_plug_parsers: parsers}
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

  defp intra_module_edges(%ModuleSummary{} = summary, defined) do
    callbacks = callback_names(summary)

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

  defp reference_edges(%ModuleSummary{module_refs: refs}, modules, _defined) do
    refs
    |> Enum.flat_map(fn {caller, ref, file, line} ->
      case Map.fetch(modules, ref) do
        {:ok, target} ->
          for to <- entry_functions(target), to != caller do
            %CallEdge{from: caller, to: to, file: file, line: line, kind: :supervisor_child}
          end

        :error ->
          []
      end
    end)
  end

  defp dynamic_edges(%ModuleSummary{module: module, dynamic_dispatches: calls}, exports, resolved) do
    Enum.flat_map(calls, fn %DynamicCall{} = call ->
      targets =
        case call.known_module do
          nil -> Map.get(resolved, module, [])
          known -> [known]
        end

      for target <- targets,
          {:ok, functions} <- [Map.fetch(exports, target)],
          {function, arity} <- Enum.sort(functions),
          call.known_function in [nil, function],
          call.arity in [nil, arity],
          function not in ["module_info", "__info__"] do
        %CallEdge{
          from: call.caller,
          to: %MFA{module: target, function: function, arity: arity},
          file: call.file,
          line: call.line,
          kind: :dynamic_apply
        }
      end
    end)
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
  # widen an endpoint configured with `parsers: [:json]`.
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
          {merge(parsers, compiled_parsers(opts)), decoders ++ compiled_decoders(opts)}

        _site, {_parsers, decoders} ->
          {:all, decoders}
      end)

    parsers =
      cond do
        sites == [] -> :all
        parsers in [[], :all] -> :all
        true -> parsers |> Enum.uniq() |> Enum.sort()
      end

    parser_modules =
      case parsers do
        :all ->
          modules
          |> Map.keys()
          |> Enum.filter(&String.starts_with?(&1, "Elixir.Plug.Parsers."))
          |> Enum.filter(&MapSet.member?(Map.get(exports, &1, MapSet.new()), {"parse", 5}))

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
      if Map.has_key?(modules, "Elixir.Plug.Parsers") do
        %{"Elixir.Plug.Parsers" => parser_modules, "Elixir.Plug.Parsers.JSON" => decoders}
      else
        %{}
      end

    edges =
      for parser <- parser_modules, Map.has_key?(modules, parser) do
        %CallEdge{
          from: %MFA{module: "Elixir.Plug.Parsers", function: "init", arity: 1},
          to: %MFA{module: parser, function: "init", arity: 1},
          kind: :dynamic_apply
        }
      end

    {parsers, edges, resolved}
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
  defp compiled_parsers(:dynamic), do: []

  defp compiled_parsers(opts) do
    atoms = literal_atoms(opts)

    if dynamic?(opts) do
      :all
    else
      Enum.filter(atoms, &String.starts_with?(&1, "Elixir.Plug.Parsers."))
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

  defp callback_names(%ModuleSummary{behaviours: behaviours}) do
    behaviours |> Enum.flat_map(&callbacks/1) |> Enum.uniq()
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
