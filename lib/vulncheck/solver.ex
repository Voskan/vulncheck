defmodule VulnCheck.Solver do
  @moduledoc """
  Classifies every matched advisory as `:reachable`, `:potentially_reachable`,
  `:unreachable` or `:retired` (see `docs/REACHABILITY_MODEL.md`).

  A single breadth-first traversal from the entrypoints computes the
  reachable functions and a parent edge for each of them, so the shortest
  witness trace of any reachable function is rebuilt in time proportional
  to its length.

  Decision order for an advisory of package `pkg`:

    1. retired release → `:retired`
    2. `pkg` outside the production closure → `:non_prod_dependency`
    3. runtime OTP release outside the affected range → `:otp_version_unaffected`
    4. an affected routine is reachable → `:reachable` with a trace; an
       affected module is reachable without routine data → potentially
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

  @atom_constructors MapSet.new([
                       {"Elixir.Module", "concat", 1},
                       {"Elixir.Module", "concat", 2},
                       {"Elixir.Module", "safe_concat", 1},
                       {"Elixir.Module", "safe_concat", 2},
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
      :modules_by_package,
      :reachable_packages,
      :reachable_modules,
      :escapes,
      :named_modules,
      :atoms_constructed,
      :started,
      :app_by_package
    ]
  end

  @doc """
  Builds the reachability index once for a workspace.
  """
  @spec index(Workspace.t(), CallGraph.t(), EntrypointModel.t(), Config.t()) :: %Index{}
  def index(%Workspace{} = workspace, %CallGraph{} = graph, %EntrypointModel{} = model, config) do
    roots = model.roots |> Enum.map(fn %Entrypoint{mfa: mfa} -> mfa end) |> Enum.uniq()
    parents = bfs(graph, roots)
    reachable = parents |> Map.keys() |> MapSet.new()

    package_of = Map.new(graph.modules, fn {name, summary} -> {name, summary.package} end)

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

    escapes =
      for {_name, %ModuleSummary{} = summary} <- graph.modules,
          not Map.has_key?(model.resolved_dynamic_modules, summary.module),
          %DynamicCall{known_module: nil} = call <- summary.dynamic_dispatches,
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
      modules_by_package: modules_by_package,
      reachable_packages: reachable_packages,
      reachable_modules: reachable_modules,
      escapes: escapes,
      named_modules: named_modules,
      atoms_constructed:
        Enum.any?(reachable, fn %MFA{module: m, function: f, arity: a} ->
          MapSet.member?(@atom_constructors, {m, f, a})
        end),
      started: MapSet.new(model.started_otp_apps),
      app_by_package:
        Map.new(workspace.packages, fn {name, package} -> {name, package.otp_app || name} end)
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
      {verdict, reason, detail, target, trace} = decide(advisory, package, index)
      finding(advisory, package, verdict, reason, detail, target, trace)
    end
  end

  # -- decision procedure ----------------------------------------------------------

  defp decide(advisory, package, index) do
    otp = index.config.otp_version || index.workspace.otp_release
    routines = advisory.affected_routines
    modules = affected_modules(advisory)
    pkg = package.name
    package_reachable? = MapSet.member?(index.reachable_packages, pkg)

    reachable_routine = Enum.find(routines, &MapSet.member?(index.reachable, &1))
    hit = if routines == [] and modules != [], do: first_reachable_in(index, modules)

    cond do
      package.scope == :non_prod ->
        unreachable(:non_prod_dependency, "#{pkg} is not part of the production dependency closure")

      not Semver.otp_affected?(otp, advisory.otp_constraints) ->
        unreachable(
          :otp_version_unaffected,
          "only OTP #{advisory.otp_constraints} is affected; the project runs OTP #{otp}"
        )

      reachable_routine != nil ->
        {:reachable, :call_chain_proven,
         "#{MFA.format(reachable_routine)} is called from an entrypoint", reachable_routine,
         trace(index, reachable_routine)}

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
          call.known_function in [nil, target.function] and call.arity in [nil, target.arity] and
            (index.atoms_constructed or MapSet.member?(index.named_modules, target.module))
        end)
      end)
    end
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

  defp bfs(graph, roots) do
    parents = Map.new(roots, &{&1, {:root, 0}})
    bfs_loop(graph, :queue.from_list(roots), parents)
  end

  defp bfs_loop(graph, queue, parents) do
    case :queue.out(queue) do
      {:empty, _} ->
        parents

      {{:value, mfa}, queue} ->
        depth = parents |> Map.fetch!(mfa) |> elem(1)

        {queue, parents} =
          graph
          |> CallGraph.edges_from(mfa)
          |> Enum.reduce({queue, parents}, fn %CallEdge{to: to} = edge, {q, p} ->
            if Map.has_key?(p, to),
              do: {q, p},
              else: {:queue.in(to, q), Map.put(p, to, {edge, depth + 1})}
          end)

        bfs_loop(graph, queue, parents)
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

      [mfas, kinds, sites]
      |> Enum.zip()
      |> Enum.map(fn {hop, kind, {file, line}} ->
        %TraceHop{mfa: hop, file: display_path(index, hop, file), line: line, kind: kind}
      end)
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
      cwes: advisory.cwes,
      references: advisory.references,
      verdict: verdict,
      reason: reason,
      reason_detail: detail,
      target_mfa: target,
      trace: trace,
      fingerprint: Finding.fingerprint(advisory.id, package.name, verdict, target),
      package_scope: if(package.scope == :non_prod, do: :non_prod, else: :prod)
    }
  end
end
