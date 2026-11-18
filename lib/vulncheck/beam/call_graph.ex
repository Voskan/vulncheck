defmodule VulnCheck.Beam.CallGraph do
  @moduledoc """
  Immutable call graph indexed by caller and callee.

  Built from module summaries: static and resolved dynamic edges, `{M, F, A}`
  references and, for modules without debug info, over-approximated edges
  from every exported function to every imported function (`:imports`).
  Further edges (behaviour callbacks, supervisor children, ...) are added
  with `add_edges/2`.
  """

  alias VulnCheck.Types.{CallEdge, Entrypoint, MFA, ModuleSummary, TraceHop}

  defstruct out_edges: %{}, in_edges: %{}, modules: %{}, pairs: %{}

  @type t :: %__MODULE__{
          out_edges: %{MFA.t() => [CallEdge.t()]},
          in_edges: %{MFA.t() => [CallEdge.t()]},
          modules: %{String.t() => ModuleSummary.t()},
          pairs: %{{MFA.t(), MFA.t()} => boolean()}
        }

  @doc """
  Builds the graph from summaries (a map keyed by module name or a list).
  """
  @spec build(%{String.t() => ModuleSummary.t()} | [ModuleSummary.t()], keyword()) :: t()
  def build(summaries, opts \\ []) do
    modules =
      case summaries do
        %{} = map -> map
        list when is_list(list) -> Map.new(list, &{&1.module, &1})
      end

    edges =
      modules
      |> Map.values()
      |> Enum.sort_by(& &1.module)
      |> Enum.flat_map(&summary_edges/1)

    add_edges(%__MODULE__{modules: modules}, edges ++ Keyword.get(opts, :extra_edges, []))
  end

  @doc """
  Adds edges to the graph. Duplicate pairs prefer proven edges, with ties
  keeping the first edge.
  """
  @spec add_edges(t(), [CallEdge.t()]) :: t()
  def add_edges(%__MODULE__{} = graph, edges) do
    {fresh, pairs} =
      Enum.reduce(edges, {[], graph.pairs}, fn %CallEdge{from: from, to: to} = edge, {acc, pairs} ->
        proof = CallEdge.proven?(edge)

        if Map.get(pairs, {from, to}) in [proof, true],
          do: {acc, pairs},
          else: {[edge | acc], Map.put(pairs, {from, to}, proof)}
      end)

    fresh = Enum.reverse(fresh)

    %{
      graph
      | pairs: pairs,
        out_edges: append(graph.out_edges, Enum.group_by(fresh, & &1.from), pairs),
        in_edges: append(graph.in_edges, Enum.group_by(fresh, & &1.to), pairs)
    }
  end

  defp append(index, groups, pairs) do
    Enum.reduce(groups, index, fn {key, list}, acc ->
      edges =
        Enum.filter(Map.get(acc, key, []) ++ list, fn edge ->
          Map.fetch!(pairs, {edge.from, edge.to}) == CallEdge.proven?(edge)
        end)

      Map.put(acc, key, edges)
    end)
  end

  @doc "Outgoing edges of a function."
  @spec edges_from(t(), MFA.t()) :: [CallEdge.t()]
  def edges_from(%__MODULE__{out_edges: out}, %MFA{} = mfa), do: Map.get(out, mfa, [])

  @doc "Incoming edges of a function."
  @spec callers(t(), MFA.t()) :: [CallEdge.t()]
  def callers(%__MODULE__{in_edges: inn}, %MFA{} = mfa), do: Map.get(inn, mfa, [])

  @doc "Number of distinct edges."
  @spec edge_count(t()) :: non_neg_integer()
  def edge_count(%__MODULE__{out_edges: out}),
    do: Enum.reduce(out, 0, fn {_, edges}, acc -> acc + length(edges) end)

  @doc "Returns `true` when the module was loaded from a `.beam` file."
  @spec module?(t(), String.t()) :: boolean()
  def module?(%__MODULE__{modules: modules}, module), do: Map.has_key?(modules, module)

  @doc """
  All functions reachable from `roots` (MFAs or entrypoints), roots included.
  """
  @spec reachable(t(), [MFA.t() | Entrypoint.t()]) :: MapSet.t(MFA.t())
  def reachable(%__MODULE__{} = graph, roots) do
    roots = Enum.map(roots, &root_mfa/1)
    visit(graph, roots, MapSet.new(roots))
  end

  defp visit(_graph, [], seen), do: seen

  defp visit(graph, [mfa | rest], seen) do
    {next, seen} =
      graph
      |> edges_from(mfa)
      |> Enum.reduce({rest, seen}, fn %CallEdge{to: to}, {stack, seen} ->
        if MapSet.member?(seen, to),
          do: {stack, seen},
          else: {[to | stack], MapSet.put(seen, to)}
      end)

    visit(graph, next, seen)
  end

  @doc "Modules containing at least one reachable function."
  @spec reachable_modules(MapSet.t(MFA.t())) :: MapSet.t(String.t())
  def reachable_modules(reachable), do: MapSet.new(reachable, & &1.module)

  @doc """
  Finds a shortest call chain (fewest hops) from any root to any target.

  Returns `{:ok, hops}` where the first hop is the entrypoint and every
  following hop carries the call site (`file:line`) in its caller and the
  kind of the edge, or `:none`.
  """
  @spec shortest_path(t(), [MFA.t() | Entrypoint.t()], MapSet.t(MFA.t()) | [MFA.t()]) ::
          {:ok, [TraceHop.t()]} | :none
  def shortest_path(%__MODULE__{} = graph, roots, targets) do
    targets = MapSet.new(targets)
    roots = roots |> Enum.map(&root_mfa/1) |> Enum.uniq()

    case Enum.find(roots, &MapSet.member?(targets, &1)) do
      %MFA{} = root ->
        {:ok, [%TraceHop{mfa: root, kind: :entrypoint}]}

      nil ->
        parents = Map.new(roots, &{&1, :root})
        queue = :queue.from_list(roots)
        bfs(graph, queue, parents, targets)
    end
  end

  defp bfs(graph, queue, parents, targets) do
    case :queue.out(queue) do
      {:empty, _} ->
        :none

      {{:value, mfa}, queue} ->
        result =
          graph
          |> edges_from(mfa)
          |> Enum.reduce_while({queue, parents}, fn %CallEdge{to: to} = edge, {q, p} ->
            cond do
              Map.has_key?(p, to) -> {:cont, {q, p}}
              MapSet.member?(targets, to) -> {:halt, {:found, Map.put(p, to, edge), to}}
              true -> {:cont, {:queue.in(to, q), Map.put(p, to, edge)}}
            end
          end)

        case result do
          {:found, parents, target} -> {:ok, rebuild(parents, target, [])}
          {queue, parents} -> bfs(graph, queue, parents, targets)
        end
    end
  end

  defp rebuild(parents, mfa, acc) do
    case Map.fetch!(parents, mfa) do
      :root ->
        [%TraceHop{mfa: mfa, kind: :entrypoint} | acc]

      %CallEdge{from: from, file: file, line: line, kind: kind} ->
        rebuild(parents, from, [%TraceHop{mfa: mfa, file: file, line: line, kind: kind} | acc])
    end
  end

  defp root_mfa(%Entrypoint{mfa: mfa}), do: mfa
  defp root_mfa(%MFA{} = mfa), do: mfa

  defp summary_edges(%ModuleSummary{has_debug_info: true} = summary),
    do: summary.edges ++ summary.mfa_refs

  defp summary_edges(%ModuleSummary{has_debug_info: false} = summary) do
    targets =
      Enum.map(summary.imports, fn {module, function, arity} ->
        %MFA{module: module, function: function, arity: arity}
      end)

    for {function, arity} <- summary.exports,
        from = %MFA{module: summary.module, function: function, arity: arity},
        to <- targets,
        do: %CallEdge{from: from, to: to, kind: :imports}
  end
end
