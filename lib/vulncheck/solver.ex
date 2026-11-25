defmodule VulnCheck.Solver do
  @moduledoc """
  Classifies every matched advisory as `:reachable`, `:potentially_reachable`,
  `:unreachable` or `:retired` (see `docs/REACHABILITY_MODEL.md`).

  Protocol clients (`mint`, `gun`, `finch`) receive data on the
  connections the project opens: once a function of a client package is
  reachable, the traversal continues from the client's receive functions,
  and their chains continue the chain that reaches the client.

  Breadth-first traversal from the entrypoints computes the
  reachable functions and a parent edge for each of them, so the shortest
  witness trace of any reachable function is rebuilt in time proportional
  to its length. The traversal first visits everything reachable from the
  project's own entrypoints and only then continues from the protocol
  handlers of network daemons, so a function is attributed to a daemon only
  when no proven chain reaches it. Chains from a root the project does not
  call itself start with the root's activation hop. A separate traversal
  excludes speculative edges when they occur in the graph.

  Routines and modules of the advisory that belong to other packages or to
  Erlang/OTP and Elixir are context only (`VulnCheck.Solver.RoutineScope`).

  Decision order for an advisory of package `pkg`:

    1. retired release → `:retired`
    2. `pkg` outside the production closure (development, test or
       build-time only) → `:non_prod_dependency`
    3. runtime OTP release outside the affected range → `:otp_version_unaffected`
    4. an affected routine is reachable → `:reachable` with a trace
       (`:daemon_call_chain` when the chain starts at a daemon's protocol
       handler); an affected module is reachable without routine data →
       potentially
    5. unused adapter / application not started, with nothing of `pkg`
       reachable → `:adapter_not_configured` / `:otp_app_not_started`
    6. soundness boundaries → `:missing_beam_debug_info`,
       `:active_network_daemon`, `:unresolved_dynamic_dispatch`,
       `:missing_symbol_granularity`
    7. proven absence → `:module_not_loaded` / `:function_not_called`
  """

  alias VulnCheck.{Config, Semver}
  alias VulnCheck.Beam.CallGraph
  alias VulnCheck.Feeds.HexRetired
  alias VulnCheck.Solver.RoutineScope

  alias VulnCheck.Types.{
    Advisory,
    CallEdge,
    DynamicCall,
    Entrypoint,
    EntrypointModel,
    Finding,
    MFA,
    ModuleSummary,
    Package,
    TraceHop,
    Workspace
  }

  # Functions that build module names or arbitrary terms from other atoms or
  # strings. Outside modules whose dynamic calls a rule resolves (such as
  # `Plug.Parsers`), their result may reach any dynamic call of the program.
  @module_builders [
    {"Elixir.Module", "concat", 1},
    {"Elixir.Module", "concat", 2},
    {"Elixir.Module", "safe_concat", 1},
    {"Elixir.Module", "safe_concat", 2},
    {"erlang", "binary_to_term", 1},
    {"erlang", "binary_to_term", 2},
    {"Elixir.Plug.Crypto", "non_executable_binary_to_term", 1},
    {"Elixir.Plug.Crypto", "non_executable_binary_to_term", 2},
    {"Elixir.Code", "eval_string", 1},
    {"Elixir.Code", "eval_string", 2},
    {"Elixir.Code", "eval_string", 3},
    {"Elixir.Code", "eval_quoted", 1},
    {"Elixir.Code", "eval_quoted", 2},
    {"Elixir.Code", "eval_quoted", 3},
    {"file", "consult", 1},
    {"erl_eval", "exprs", 2},
    {"erl_eval", "exprs", 3},
    {"erl_eval", "exprs", 4},
    {"erl_eval", "expr", 2},
    {"erl_eval", "expr", 3},
    {"erl_eval", "expr", 4},
    {"erl_eval", "expr", 5}
  ]

  # Functions that can construct or deserialize executable function values
  # outside the static call graph (excludes `Plug.Crypto.non_executable_binary_to_term`,
  # which forbids executable funs at runtime).
  @fun_constructors [
    {"erlang", "binary_to_term", 1},
    {"erlang", "binary_to_term", 2},
    {"Elixir.Code", "eval_string", 1},
    {"Elixir.Code", "eval_string", 2},
    {"Elixir.Code", "eval_string", 3},
    {"Elixir.Code", "eval_quoted", 1},
    {"Elixir.Code", "eval_quoted", 2},
    {"Elixir.Code", "eval_quoted", 3},
    {"erl_eval", "exprs", 2},
    {"erl_eval", "exprs", 3},
    {"erl_eval", "exprs", 4},
    {"erl_eval", "expr", 2},
    {"erl_eval", "expr", 3},
    {"erl_eval", "expr", 4},
    {"erl_eval", "expr", 5}
  ]

  # Functions that turn data into atoms. Their result is taken to feed the
  # dynamic calls of the module that calls them.
  @atom_constructors MapSet.new([
                       {"Elixir.String", "to_atom", 1},
                       {"Elixir.String", "to_existing_atom", 1},
                       {"Elixir.List", "to_atom", 1},
                       {"Elixir.List", "to_existing_atom", 1},
                       {"erlang", "binary_to_atom", 1},
                       {"erlang", "binary_to_atom", 2},
                       {"erlang", "binary_to_existing_atom", 1},
                       {"erlang", "binary_to_existing_atom", 2},
                       {"erlang", "list_to_atom", 1},
                       {"erlang", "list_to_existing_atom", 1}
                     ])

  # Functions that read application environment populated by `config/*.exs`.
  @config_env_readers [
    {"Elixir.Application", "get_env", 2},
    {"Elixir.Application", "get_env", 3},
    {"Elixir.Application", "fetch_env", 2},
    {"Elixir.Application", "fetch_env!", 2},
    {"Elixir.Application", "get_all_env", 1},
    {"application", "get_env", 1},
    {"application", "get_env", 2},
    {"application", "get_env", 3},
    {"application", "get_all_env", 0},
    {"application", "get_all_env", 1},
    {"application", "get_key", 1},
    {"application", "get_key", 2}
  ]

  @verdict_order %{reachable: 0, potentially_reachable: 1, retired: 2, unreachable: 3}

  defmodule Index do
    @moduledoc false
    defstruct [
      :graph,
      :model,
      :workspace,
      :config,
      :reachable,
      :parents,
      :proven_parents,
      :proven_client_anchors,
      :artifact_issues,
      :modules_by_package,
      :reachable_packages,
      :reachable_modules,
      :escapes,
      :named_modules,
      :atoms_constructed,
      :atom_modules,
      :started,
      :app_by_package,
      :activations,
      :client_anchors
    ]
  end

  @doc """
  Builds the reachability index once for a workspace.
  """
  @spec index(Workspace.t(), CallGraph.t(), EntrypointModel.t(), Config.t()) :: %Index{}
  def index(%Workspace{} = workspace, %CallGraph{} = graph, %EntrypointModel{} = model, config) do
    {daemon_roots, proven_roots} = Enum.split_with(model.roots, &(&1.kind == :daemon))
    package_of = Map.new(graph.modules, fn {name, summary} -> {name, summary.package} end)
    root_groups = [proven_roots, daemon_roots]

    {parents, client_anchors} =
      traverse(graph, root_groups, model.client_roots, package_of, false)

    {proven_parents, proven_client_anchors} =
      if Enum.any?(graph.out_edges, fn {_, edges} ->
           Enum.any?(edges, &(not CallEdge.proven?(&1)))
         end) do
        traverse(graph, root_groups, model.client_roots, package_of, true)
      else
        {parents, client_anchors}
      end

    reachable = parents |> Map.keys() |> MapSet.new()

    modules_by_package =
      graph.modules
      |> Map.values()
      |> Enum.group_by(& &1.package)

    reachable_modules = MapSet.new(reachable, & &1.module)

    reachable_packages =
      reachable_modules
      |> Enum.flat_map(fn module ->
        case Map.fetch(package_of, module) do
          {:ok, package} when is_binary(package) -> [package]
          _ -> []
        end
      end)
      |> MapSet.new()

    # A function value is ordinarily a closure or capture created by analyzed
    # code (captures are edges of the function that takes them, closure bodies
    # are part of the function that defines them, and `make_fun/3` /
    # `Function.capture/3` are dynamic calls of their own). However, when
    # external funs may enter via unparseable/dynamic `config/*.exs` or
    # reachable `:erlang.binary_to_term`/`Code.eval_*`/`:erl_eval` calls,
    # reachable `:function_value` call sites must also be treated as escapes.
    untracked_funs? =
      model.untracked_fun_sources or
        any_target_called?(graph, model, reachable, @fun_constructors)

    escapes =
      for {_name, %ModuleSummary{} = summary} <- graph.modules,
          not Map.has_key?(model.resolved_dynamic_modules, summary.module),
          %DynamicCall{known_module: nil} = call <- summary.dynamic_dispatches,
          call.kind == :module_function or (untracked_funs? and call.kind == :function_value),
          not MapSet.member?(model.resolved_dynamic_calls, call),
          MapSet.member?(reachable, call.caller),
          do: call

    named_modules =
      for {_name, %ModuleSummary{} = summary} <- graph.modules,
          {caller, ref, _file, _line} <- summary.module_refs,
          MapSet.member?(reachable, caller),
          into: MapSet.new(),
          do: ref

    %Index{
      graph: graph,
      model: model,
      workspace: workspace,
      config: config,
      reachable: reachable,
      parents: parents,
      proven_parents: proven_parents,
      proven_client_anchors: proven_client_anchors,
      artifact_issues:
        affected_by_incomplete_artifacts(
          workspace,
          graph,
          model,
          reachable_modules,
          reachable_packages
        ),
      modules_by_package: modules_by_package,
      reachable_packages: reachable_packages,
      reachable_modules: reachable_modules,
      escapes: escapes,
      named_modules: named_modules,
      atoms_constructed: module_builder_reachable?(graph, model, reachable),
      atom_modules: atom_constructing_modules(graph, reachable),
      started: MapSet.new(model.started_otp_apps),
      app_by_package:
        Map.new(workspace.packages, fn {name, package} -> {name, package.otp_app || name} end),
      activations:
        for(
          %Entrypoint{activation: %TraceHop{} = hop, mfa: mfa} <- model.roots,
          into: %{},
          do: {mfa, hop}
        ),
      client_anchors: client_anchors
    }
  end

  @doc """
  Classifies advisories and returns findings in report order.
  """
  @spec solve(
          Workspace.t(),
          CallGraph.t() | nil,
          EntrypointModel.t() | nil,
          [Advisory.t()],
          Config.t()
        ) ::
          [Finding.t()]
  def solve(%Workspace{} = workspace, graph, model, advisories, %Config{} = config) do
    graph = graph || CallGraph.build(%{})
    model = model || %EntrypointModel{boot_tree_known: false}
    index = index(workspace, graph, model, config)

    advisories
    |> Enum.map(&classify(&1, index))
    |> sort()
  end

  @doc """
  One warning per dynamic call site that keeps active findings potentially
  reachable, naming the affected packages, so that a single unresolved
  `apply/3` widening many advisories is visible.
  """
  @spec dynamic_dispatch_warnings([Finding.t()]) :: [String.t()]
  def dynamic_dispatch_warnings(findings) do
    findings
    |> Enum.filter(&(&1.reason == :unresolved_dynamic_dispatch and Finding.active?(&1)))
    |> Enum.filter(&(&1.trace != []))
    |> Enum.group_by(&dynamic_call_site(&1.trace))
    |> Enum.sort_by(fn {%TraceHop{} = hop, _} -> {MFA.format(hop.mfa), hop.file, hop.line} end)
    |> Enum.map(fn {%TraceHop{} = hop, group} ->
      packages = group |> Enum.map(& &1.package) |> Enum.uniq() |> Enum.sort()
      site = if hop.file, do: " (#{hop.file}:#{hop.line})", else: ""

      "the dynamic call in #{MFA.format(hop.mfa)}#{site} cannot be resolved statically " <>
        "and keeps #{length(group)} advisory(ies) of #{Enum.join(packages, ", ")} potentially reachable"
    end)
  end

  defp dynamic_call_site(hops) do
    hops
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.find_value(List.last(hops), fn
      [caller, %TraceHop{kind: :dynamic_candidate}] -> caller
      _ -> nil
    end)
  end

  @doc """
  Sorts findings: verdict, severity (most severe first), package, advisory id.
  """
  @spec sort([Finding.t()]) :: [Finding.t()]
  def sort(findings) do
    Enum.sort_by(findings, fn %Finding{} = f ->
      {Map.get(@verdict_order, f.verdict, 9), -Config.severity_rank(f.severity), f.package,
       f.advisory_id}
    end)
  end

  @doc """
  Classifies one advisory against a prepared index.
  """
  @spec classify(Advisory.t(), %Index{}) :: Finding.t()
  def classify(%Advisory{} = advisory, %Index{} = index) do
    package =
      Map.get(index.workspace.packages, advisory.package) ||
        %Package{name: advisory.package, version: "", source: :hex, scope: :prod}

    if advisory.retirement do
      HexRetired.to_finding(advisory, package)
    else
      {scoped, context} = scope(advisory, package, index)
      {verdict, reason, detail, target, trace} = decide(scoped, package, index)

      %{
        finding(advisory, package, verdict, reason, detail, target, trace)
        | context_routines: context
      }
    end
  end

  # Routines outside the package (stdlib functions, other dependencies) are
  # context, never targets.
  defp scope(advisory, package, index) do
    owners = Enum.uniq([package.name, Map.get(index.app_by_package, package.name, package.name)])
    RoutineScope.scope(advisory, owners, index.graph.modules)
  end

  # -- decision procedure ----------------------------------------------------------

  defp decide(advisory, package, index) do
    otp = index.config.otp_version || index.workspace.otp_release
    routines = advisory.affected_routines
    modules = affected_modules(advisory)
    pkg = package.name
    package_reachable? = MapSet.member?(index.reachable_packages, pkg)

    witness = best_witness(index, routines)
    hit = if routines == [] and modules != [], do: first_reachable_in(index, modules)

    cond do
      package.scope == :non_prod ->
        unreachable(:non_prod_dependency, "#{pkg} is not part of the production dependency closure")

      not Semver.otp_affected?(otp, advisory.otp_constraints) ->
        unreachable(
          :otp_version_unaffected,
          "only OTP #{advisory.otp_constraints} is affected; the project runs OTP #{otp}"
        )

      witness != nil ->
        routine_verdict(witness)

      hit != nil ->
        if pkg in index.model.active_daemon_packages do
          potentially(
            :active_network_daemon,
            "#{MFA.format(hit)} is part of an active network daemon",
            hit,
            trace(index, hit)
          )
        else
          potentially(
            :missing_symbol_granularity,
            "the advisory names #{Enum.map_join(modules, ", ", &MFA.display_module/1)} " <>
              "but no affected functions; #{MFA.format(hit)} is reachable",
            hit,
            trace(index, hit)
          )
        end

      issue = Map.get(index.artifact_issues, nil) || Map.get(index.artifact_issues, pkg) ->
        potentially(:missing_beam_debug_info, "compiled evidence is incomplete: #{issue}", nil, [])

      package.scope == :build_only and not package_reachable? and
          not escape_toward?(index, advisory, package) ->
        unreachable(
          :non_prod_dependency,
          "#{pkg} is build-time only (runtime: false); it is not started in the production release"
        )

      not package_reachable? and Map.has_key?(index.model.inactive_adapter_packages, pkg) and
          not escape_toward?(index, advisory, package) ->
        unreachable(
          :adapter_not_configured,
          "#{pkg} is an adapter of #{index.model.inactive_adapter_packages[pkg]}; " <>
            "nothing calls into it"
        )

      not package_reachable? and index.model.boot_tree_known and
        not MapSet.member?(index.started, Map.get(index.app_by_package, pkg, pkg)) and
          not escape_toward?(index, advisory, package) ->
        unreachable(
          :otp_app_not_started,
          "the #{Map.get(index.app_by_package, pkg, pkg)} application is not started " <>
            "and none of its functions are reachable"
        )

      true ->
        boundaries(advisory, package, index, routines, modules, package_reachable?)
    end
  end

  defp best_witness(index, routines) do
    proof = %{index | parents: index.proven_parents, client_anchors: index.proven_client_anchors}

    case shortest_witness(proof, routines) do
      {routine, hops} ->
        {:proven, routine, hops}

      nil ->
        case shortest_witness(index, routines) do
          {routine, hops} -> {:possible, routine, hops}
          nil -> nil
        end
    end
  end

  defp shortest_witness(index, routines) do
    routines
    |> Enum.filter(&Map.has_key?(index.parents, &1))
    |> Enum.map(&{&1, trace(index, &1)})
    |> Enum.min_by(
      fn {routine, hops} ->
        indirect? = Enum.any?(hops, &(&1.kind in [:daemon_activation, :incoming_data]))
        {indirect?, length(hops), routine}
      end,
      fn -> nil end
    )
  end

  defp routine_verdict({:proven, routine, hops}), do: proven(routine, hops)

  defp routine_verdict({:possible, routine, hops}) do
    if Enum.any?(hops, &(&1.kind == :dynamic_candidate)) do
      potentially(
        :unresolved_dynamic_dispatch,
        "#{MFA.format(routine)} is a possible target of an unresolved invocation",
        routine,
        hops
      )
    else
      potentially(
        :missing_beam_debug_info,
        "#{MFA.format(routine)} is reachable only through modules without debug info",
        routine,
        hops
      )
    end
  end

  defp affected_by_incomplete_artifacts(
         workspace,
         graph,
         model,
         reachable_modules,
         reachable_packages
       ) do
    stripped =
      for name <- Enum.sort(reachable_modules),
          %ModuleSummary{has_debug_info: false, package: pkg} <- [graph.modules[name]],
          do: {pkg, "#{MFA.display_module(name)} has no debug info"}

    started = MapSet.new(model.started_otp_apps)

    {active, inactive} =
      Enum.split_with(model.artifact_issues ++ stripped, fn {owner, _detail} ->
        app = Map.get(workspace.packages, owner, %{otp_app: nil}).otp_app || owner

        is_nil(owner) or MapSet.member?(started, app) or MapSet.member?(reachable_packages, owner)
      end)

    propagated =
      Enum.reduce(active, %{}, fn {owner, detail}, issues ->
        add_affected_issues([owner], workspace.packages, detail, issues)
      end)

    Enum.reduce(inactive, propagated, fn {owner, detail}, issues ->
      Map.put_new(issues, owner, detail)
    end)
  end

  defp add_affected_issues([], _packages, _detail, issues), do: issues

  defp add_affected_issues([name | rest], packages, detail, issues) do
    if Map.has_key?(issues, name) do
      add_affected_issues(rest, packages, detail, issues)
    else
      deps =
        case packages[name] do
          %{deps: deps} -> deps
          _ -> []
        end

      add_affected_issues(deps ++ rest, packages, detail, Map.put(issues, name, detail))
    end
  end

  defp boundaries(advisory, package, index, routines, modules, package_reachable?) do
    pkg = package.name
    package_modules = Map.get(index.modules_by_package, pkg, [])
    stripped = Enum.filter(package_modules, &(not &1.has_debug_info))

    cond do
      package_modules == [] and
          (package_reachable? or started?(index, package) or
             not index.model.boot_tree_known) ->
        potentially(
          :missing_beam_debug_info,
          "no compiled .beam files were found for #{pkg}; build the project for the scanned environment",
          nil,
          []
        )

      stripped != [] and (package_reachable? or calls_into?(index, stripped)) ->
        potentially(
          :missing_beam_debug_info,
          "#{length(stripped)} module(s) of #{pkg} have no debug info " <>
            "(e.g. #{MFA.display_module(hd(stripped).module)})",
          nil,
          []
        )

      pkg in index.model.active_daemon_packages ->
        potentially(
          :active_network_daemon,
          "#{pkg} is an active network daemon in the boot tree",
          nil,
          []
        )

      call = escape_toward(index, advisory, package) ->
        potentially(
          :unresolved_dynamic_dispatch,
          "#{MFA.format(call.caller)} makes a dynamic call" <>
            if(call.file, do: " at #{call.file}:#{call.line}", else: "") <>
            " that may reach #{pkg}",
          nil,
          trace(index, call.caller, {call.file, call.line})
        )

      routines == [] and modules == [] and package_reachable? ->
        hit = first_reachable_in_package(index, package_modules)

        potentially(
          :missing_symbol_granularity,
          "the advisory has no function or module data and #{pkg} is used",
          hit,
          if(hit, do: trace(index, hit), else: [])
        )

      routines != [] and advisory.symbol_source == :text and package_reachable? ->
        potentially(
          :missing_symbol_granularity,
          "affected functions were inferred from the advisory text only and #{pkg} is used",
          nil,
          []
        )

      advisory.symbol_gaps and (package_reachable? or started?(index, package)) ->
        potentially(
          :missing_symbol_granularity,
          "some affected version blocks for #{pkg} lack function or module information",
          nil,
          []
        )

      routines != [] ->
        unreachable(
          :function_not_called,
          "none of #{Enum.map_join(routines, ", ", &MFA.format/1)} is reachable"
        )

      modules != [] and first_reachable_in(index, modules) == nil ->
        unreachable(
          :module_not_loaded,
          "no function of #{Enum.map_join(modules, ", ", &MFA.display_module/1)} is reachable"
        )

      true ->
        unreachable(:module_not_loaded, "no function of #{pkg} is reachable")
    end
  end

  # A chain from a daemon's protocol handler rests on the model of the
  # daemon (it receives requests once started), not on a call written in
  # the project, so it gets its own reason.
  defp proven(routine, [%TraceHop{kind: :daemon_activation}, %TraceHop{mfa: root} | _] = trace) do
    {:reachable, :daemon_call_chain,
     "#{MFA.format(routine)} is called from #{MFA.format(root)}, " <>
       "a protocol handler of an active network daemon", routine, trace}
  end

  defp proven(routine, trace) do
    case Enum.find(trace, &(&1.kind == :incoming_data)) do
      %TraceHop{mfa: receiver} ->
        {:reachable, :daemon_call_chain,
         "#{MFA.format(routine)} is called from #{MFA.format(receiver)}, which processes " <>
           "data that servers send on the connections the project opens", routine, trace}

      nil ->
        direct(routine, trace)
    end
  end

  defp direct(routine, trace) do
    {:reachable, :call_chain_proven, "#{MFA.format(routine)} is called from an entrypoint", routine,
     trace}
  end

  defp unreachable(reason, detail), do: {:unreachable, reason, detail, nil, []}

  defp potentially(reason, detail, target, trace),
    do: {:potentially_reachable, reason, detail, target, trace}

  defp started?(index, package),
    do: MapSet.member?(index.started, Map.get(index.app_by_package, package.name, package.name))

  defp affected_modules(%Advisory{affected_modules: modules, affected_routines: routines}) do
    (modules ++ Enum.map(routines, & &1.module)) |> Enum.uniq()
  end

  defp first_reachable_in(index, modules) do
    modules = MapSet.new(modules)

    index.reachable
    |> Enum.filter(&MapSet.member?(modules, &1.module))
    |> Enum.min_by(&depth(index, &1), fn -> nil end)
  end

  defp first_reachable_in_package(index, package_modules) do
    first_reachable_in(index, Enum.map(package_modules, & &1.module))
  end

  defp calls_into?(index, summaries) do
    names = MapSet.new(summaries, & &1.module)
    Enum.any?(index.reachable, &MapSet.member?(names, &1.module))
  end

  defp escape_toward?(index, advisory, package), do: escape_toward(index, advisory, package) != nil

  # An unresolved dynamic call may target the advisory when its known
  # function/arity are compatible, the package's application runs (or the
  # package is used), and the target module name is available at runtime.
  defp escape_toward(%Index{escapes: []}, _advisory, _package), do: nil

  defp escape_toward(index, advisory, package) do
    pkg = package.name

    if MapSet.member?(index.reachable_packages, pkg) or started?(index, package) do
      targets = candidate_targets(index, advisory, pkg)

      Enum.find(index.escapes, fn %DynamicCall{} = call ->
        Enum.any?(targets, fn %MFA{} = target ->
          case call.kind do
            :function_value ->
              DynamicCall.arity_compatible?(call, target.arity)

            :module_function ->
              call.known_function in [nil, target.function] and
                DynamicCall.arity_compatible?(call, target.arity) and
                (index.atoms_constructed or
                   MapSet.member?(index.atom_modules, call.caller.module) or
                   MapSet.member?(index.named_modules, target.module))
          end
        end)
      end)
    end
  end

  defp module_builder_reachable?(graph, model, reachable) do
    (model.config_atoms_constructed and config_env_reader_reachable?(graph, reachable)) or
      any_target_called?(graph, model, reachable, @module_builders)
  end

  defp config_env_reader_reachable?(graph, reachable) do
    Enum.any?(@config_env_readers, fn {m, f, a} ->
      graph
      |> CallGraph.callers(%MFA{module: m, function: f, arity: a})
      |> Enum.any?(fn %CallEdge{from: from} -> MapSet.member?(reachable, from) end)
    end)
  end

  defp any_target_called?(graph, model, reachable, targets) do
    Enum.any?(targets, fn {m, f, a} ->
      graph
      |> CallGraph.callers(%MFA{module: m, function: f, arity: a})
      |> Enum.any?(fn %CallEdge{from: from} ->
        MapSet.member?(reachable, from) and
          not Map.has_key?(model.resolved_dynamic_modules, from.module)
      end)
    end)
  end

  defp atom_constructing_modules(graph, reachable) do
    for {m, f, a} <- @atom_constructors,
        %CallEdge{from: from} <- CallGraph.callers(graph, %MFA{module: m, function: f, arity: a}),
        MapSet.member?(reachable, from),
        into: MapSet.new(),
        do: from.module
  end

  defp candidate_targets(_index, %Advisory{affected_routines: [_ | _] = routines}, _pkg),
    do: routines

  defp candidate_targets(index, advisory, pkg) do
    modules =
      case affected_modules(advisory) do
        [] -> index.modules_by_package |> Map.get(pkg, []) |> Enum.map(& &1.module)
        list -> list
      end

    for module <- modules,
        {:ok, summary} <- [Map.fetch(index.graph.modules, module)],
        {function, arity} <- summary.exports,
        do: %MFA{module: module, function: function, arity: arity}
  end

  # -- traversal ---------------------------------------------------------------------

  # Receive functions of protocol clients whose package is reachable become
  # roots; each is anchored to the reachable function of its package closest
  # to an entrypoint (the call that opens connections). Repeated until no
  # further client package becomes reachable.
  defp activate_clients(graph, clients, package_of, parents, anchors, proven_only?) do
    packages = clients |> Enum.map(& &1.source) |> MapSet.new()

    nearest =
      Enum.reduce(parents, %{}, fn {%MFA{module: module} = mfa, {_parent, depth}}, acc ->
        package = Map.get(package_of, module)

        if MapSet.member?(packages, package) do
          Map.update(acc, package, {depth, mfa}, &min(&1, {depth, mfa}))
        else
          acc
        end
      end)

    fresh =
      for %Entrypoint{mfa: mfa, source: package} <- clients,
          not Map.has_key?(parents, mfa),
          {:ok, {depth, anchor}} <- [Map.fetch(nearest, package)],
          do: {mfa, package, anchor, depth}

    if fresh == [] do
      {parents, anchors}
    else
      parents =
        Enum.reduce(fresh, parents, fn {mfa, _package, _anchor, depth}, acc ->
          Map.put(acc, mfa, {:root, depth + 1})
        end)

      anchors =
        Enum.reduce(fresh, anchors, fn {mfa, package, anchor, _depth}, acc ->
          Map.put(acc, mfa, {anchor, package})
        end)

      queue = :queue.from_list(Enum.map(fresh, &elem(&1, 0)))
      parents = bfs_loop(graph, queue, parents, proven_only?)
      activate_clients(graph, clients, package_of, parents, anchors, proven_only?)
    end
  end

  # Root groups are traversed in order; a later group only reaches
  # functions that no earlier group reached.
  defp traverse(graph, root_groups, clients, package_of, proven_only?) do
    Enum.reduce(root_groups, {%{}, %{}}, fn roots, {parents, anchors} ->
      fresh = roots |> Enum.map(& &1.mfa) |> Enum.uniq() |> Enum.sort()
      fresh = Enum.reject(fresh, &Map.has_key?(parents, &1))
      parents = Enum.reduce(fresh, parents, &Map.put(&2, &1, {:root, 0}))
      parents = bfs_loop(graph, :queue.from_list(fresh), parents, proven_only?)
      activate_clients(graph, clients, package_of, parents, anchors, proven_only?)
    end)
  end

  defp bfs_loop(graph, queue, parents, proven_only?) do
    case :queue.out(queue) do
      {:empty, _} ->
        parents

      {{:value, mfa}, queue} ->
        depth = parents |> Map.fetch!(mfa) |> elem(1)

        {queue, parents} =
          graph
          |> CallGraph.edges_from(mfa)
          |> Enum.reduce({queue, parents}, fn %CallEdge{to: to} = edge, {q, p} ->
            if Map.has_key?(p, to) or (proven_only? and not CallEdge.proven?(edge)),
              do: {q, p},
              else: {:queue.in(to, q), Map.put(p, to, {edge, depth + 1})}
          end)

        bfs_loop(graph, queue, parents, proven_only?)
    end
  end

  defp depth(index, mfa), do: index.parents |> Map.fetch!(mfa) |> elem(1)

  # Trace hops are presented as "function (location)": every hop carries
  # the call site inside that function that leads to the next hop, and the
  # last hop carries the definition of the target (or `last` when given).
  # Paths inside dependencies are shown under `deps/<package>/`.
  defp trace(index, %MFA{} = mfa, last \\ nil) do
    if Map.has_key?(index.parents, mfa) do
      {mfas, edges} = path(index.parents, mfa, [], [])
      kinds = [:entrypoint | Enum.map(edges, & &1.kind)]
      sites = Enum.map(edges, &{&1.file, &1.line}) ++ [last || definition(index, mfa)]

      hops =
        [mfas, kinds, sites]
        |> Enum.zip()
        |> Enum.map(fn {hop, kind, {file, line}} ->
          %TraceHop{mfa: hop, file: display_path(index, hop, file), line: line, kind: kind}
        end)

      cond do
        Map.has_key?(index.client_anchors, hd(mfas)) ->
          {anchor, package} = Map.fetch!(index.client_anchors, hd(mfas))
          [receiver | rest] = hops

          receiver = %{
            receiver
            | kind: :incoming_data,
              note: "processes data received by the #{package} client"
          }

          trace(index, anchor) ++ [receiver | rest]

        Map.has_key?(index.activations, hd(mfas)) ->
          [Map.fetch!(index.activations, hd(mfas)) | hops]

        true ->
          hops
      end
    else
      []
    end
  end

  defp path(parents, mfa, mfas, edges) do
    case Map.fetch!(parents, mfa) do
      {:root, _} -> {[mfa | mfas], edges}
      {%CallEdge{from: from} = edge, _} -> path(parents, from, [mfa | mfas], [edge | edges])
    end
  end

  defp definition(index, %MFA{module: module, function: function, arity: arity}) do
    case Map.fetch(index.graph.modules, module) do
      {:ok, %ModuleSummary{} = summary} ->
        {summary.source_file, Map.get(summary.function_lines, {function, arity})}

      :error ->
        {nil, nil}
    end
  end

  defp display_path(_index, _mfa, nil), do: nil

  defp display_path(index, %MFA{module: module}, file) do
    case Map.fetch(index.graph.modules, module) do
      {:ok, %ModuleSummary{package: package}} when is_binary(package) ->
        if Path.type(file) == :relative and not String.starts_with?(file, ["deps/", "_build/"]),
          do: Path.join(["deps", package, file]),
          else: file

      _ ->
        file
    end
  end

  # -- findings ----------------------------------------------------------------------

  defp finding(advisory, package, verdict, reason, detail, target, trace) do
    %Finding{
      advisory_id: advisory.id,
      aliases: advisory.aliases,
      package: package.name,
      installed_version: package.version || "",
      fixed_versions: advisory.fixed_versions,
      recommended_fix: Semver.recommended_fix(package.version || "", advisory),
      summary: advisory.summary,
      severity: advisory.severity,
      cvss_score: advisory.cvss_score,
      cvss_vector: advisory.cvss_vector,
      cvss_method: advisory.cvss_method,
      cvss_source: advisory.cvss_source,
      cwes: advisory.cwes,
      references: advisory.references,
      verdict: verdict,
      reason: reason,
      reason_detail: detail,
      target_mfa: target,
      trace: trace,
      fingerprint: Finding.fingerprint(advisory.id, package.name, verdict, target),
      package_scope: package.scope,
      git_match_status: advisory.git_match_status
    }
  end
end
