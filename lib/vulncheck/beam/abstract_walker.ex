defmodule VulnCheck.Beam.AbstractWalker do
  @moduledoc """
  Walks the Erlang Abstract Format (`:raw_abstract_v1`) of one module and
  produces a `VulnCheck.Types.ModuleSummary`.

  Extracted facts:

    * local and remote calls with exact `file:line` (`:static_call`),
    * function captures (`&Mod.fun/2`, `fun mod:f/1`),
    * `apply/3` and `mod.fun(...)` sites; literal modules and functions,
      including variables bound to a literal in the same clause, are
      resolved to `:dynamic_apply` edges, everything else is recorded as a
      `VulnCheck.Types.DynamicCall`,
    * `{Mod, :fun, args}` triples (spawn, timers, child specs) as `mfa_refs`,
    * literal atoms used as values (`module_refs`) so supervision trees and
      plugs can be linked later,
    * literal arguments of selected framework calls (`init_literals`).

  The output contains only strings, integers, lists, tuples and maps, so it
  can be cached and decoded with `:erlang.binary_to_term(bin, [:safe])`.
  """

  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary}

  @init_targets MapSet.new([
                  {"Elixir.Plug.Parsers", "init", 1},
                  {"Elixir.Plug.Parsers", "call", 2},
                  {"Elixir.Supervisor", "init", 2},
                  {"Elixir.Supervisor", "start_link", 2},
                  {"Elixir.Supervisor", "start_link", 3},
                  {"Elixir.Supervisor", "child_spec", 2},
                  {"Elixir.DynamicSupervisor", "start_child", 2},
                  {"supervisor", "start_link", 2},
                  {"supervisor", "start_link", 3},
                  {"Elixir.Application", "put_env", 3},
                  {"Elixir.Application", "put_env", 4}
                ])

  @boring_atoms MapSet.new(~w(true false nil ok error undefined ignore infinity noreply reply
                             stop normal shutdown default all none __struct__ __exception__))
  @kept_attributes ~w(__impl__ __protocol__ behaviour behavior deprecated)
  @generators [:generate, :b_generate, :m_generate, :generate_strict, :b_generate_strict] ++
                [:m_generate_strict]
  @max_literal_depth 12

  @doc """
  Builds a summary from abstract forms.

  Options:

    * `:root_dir` — project root used to make absolute source paths relative
    * `:attributes` — the `:attributes` chunk (used when forms carry none)
    * `:exports` — the `:exports` chunk
  """
  @spec summarize(module() | String.t(), [tuple()], keyword()) :: ModuleSummary.t()
  def summarize(module, forms, opts \\ []) when is_list(forms) do
    module = name(module)
    root = Keyword.get(opts, :root_dir)

    defined =
      for {:function, _, fun, arity, _} <- forms, into: MapSet.new(), do: {fun, arity}

    imports =
      for {:attribute, _, :import, {mod, funs}} <- forms,
          {fun, arity} <- funs,
          into: %{},
          do: {{fun, arity}, mod}

    attributes = attributes(forms, Keyword.get(opts, :attributes, []))

    {facts, source_file} =
      Enum.reduce(forms, {empty_facts(), nil}, fn
        {:attribute, _, :file, {file, _}}, {facts, source} ->
          {%{facts | file: normalize_file(file, root)}, source || normalize_file(file, root)}

        {:function, _, fun, arity, clauses}, {facts, source}
        when fun not in [:__info__, :module_info] ->
          caller = mfa(module, Atom.to_string(fun), arity)

          ctx = %{
            module: module,
            caller: caller,
            file: facts.file,
            defined: defined,
            imports: imports,
            env: %{}
          }

          facts = Enum.reduce(clauses, facts, &walk_clause(&1, ctx, &2))
          {facts, source}

        _form, acc ->
          acc
      end)

    exports =
      case Keyword.get(opts, :exports) do
        list when is_list(list) -> list
        _ -> for {:attribute, _, :export, list} <- forms, entry <- list, do: entry
      end

    %ModuleSummary{
      module: module,
      source_file: source_file,
      has_debug_info: true,
      functions: defined |> Enum.map(&fa/1) |> Enum.sort(),
      exports: exports |> Enum.map(&fa/1) |> Enum.uniq() |> Enum.sort(),
      behaviours: behaviours(attributes),
      attributes: attributes,
      edges: finish(facts.edges),
      dynamic_dispatches: Enum.reverse(facts.dynamic),
      module_refs:
        facts.refs
        |> Enum.reverse()
        |> Enum.uniq_by(fn {caller, mod, _, _} -> {caller, mod} end),
      mfa_refs: finish(facts.mfa_refs),
      init_literals: Enum.reverse(facts.init)
    }
  end

  @doc """
  Builds the summary of a module without debug info from its `:exports`,
  `:imports` and `:attributes` chunks.
  """
  @spec summarize_stripped(module() | String.t(), keyword()) :: ModuleSummary.t()
  def summarize_stripped(module, opts) do
    exports = opts |> Keyword.get(:exports, []) |> Enum.map(&fa/1) |> Enum.uniq() |> Enum.sort()
    attributes = attributes([], Keyword.get(opts, :attributes, []))

    imports =
      opts
      |> Keyword.get(:imports, [])
      |> Enum.map(fn {m, f, a} -> {name(m), Atom.to_string(f), a} end)
      |> Enum.uniq()
      |> Enum.sort()

    %ModuleSummary{
      module: name(module),
      has_debug_info: false,
      functions: exports,
      exports: exports,
      behaviours: behaviours(attributes),
      attributes: attributes,
      imports: imports
    }
  end

  @doc """
  Encodes an Erlang term (for example an attribute value) in the string-based
  literal format used by summaries.

      iex> VulnCheck.Beam.AbstractWalker.encode_term([protocol: Enumerable, for: List])
      [{:tuple, [{:atom, "protocol"}, {:atom, "Elixir.Enumerable"}]}, {:tuple, [{:atom, "for"}, {:atom, "Elixir.List"}]}]
  """
  @spec encode_term(term()) :: ModuleSummary.literal()
  def encode_term(term), do: encode_term(term, 0)

  defp encode_term(_term, depth) when depth > @max_literal_depth, do: :dynamic
  defp encode_term(atom, _depth) when is_atom(atom), do: {:atom, Atom.to_string(atom)}
  defp encode_term(term, _depth) when is_binary(term) or is_number(term), do: term

  defp encode_term(list, depth) when is_list(list) do
    if proper_list?(list), do: Enum.map(list, &encode_term(&1, depth + 1)), else: :dynamic
  end

  defp encode_term(tuple, depth) when is_tuple(tuple),
    do: {:tuple, tuple |> Tuple.to_list() |> Enum.map(&encode_term(&1, depth + 1))}

  defp encode_term(map, depth) when is_map(map),
    do:
      {:map,
       map |> Enum.map(fn {k, v} -> {encode_term(k, depth + 1), encode_term(v, depth + 1)} end)}

  defp encode_term(_term, _depth), do: :dynamic

  # -- clause walking ------------------------------------------------------------

  defp empty_facts, do: %{file: nil, edges: [], dynamic: [], refs: [], mfa_refs: [], init: []}

  defp walk_clause(clause, ctx, facts) do
    walk(clause, %{ctx | env: bindings(clause)}, facts)
  end

  # Local call.
  defp walk({:call, anno, {:atom, _, fun}, args}, ctx, facts) when is_list(args) do
    arity = length(args)

    target =
      cond do
        MapSet.member?(ctx.defined, {fun, arity}) -> ctx.module
        mod = Map.get(ctx.imports, {fun, arity}) -> name(mod)
        :erl_internal.bif(fun, arity) -> "erlang"
        true -> ctx.module
      end

    facts
    |> add_edge(ctx, mfa(target, Atom.to_string(fun), arity), anno, kind(anno))
    |> add_mfa_refs(args, ctx, anno)
    |> walk_list(args, ctx)
  end

  # Static remote call (with the apply family handled specially).
  defp walk({:call, anno, {:remote, _, {:atom, _, mod}, {:atom, _, fun}}, args}, ctx, facts)
       when is_list(args) do
    mod = name(mod)
    fun = Atom.to_string(fun)
    arity = length(args)

    facts =
      cond do
        apply3?(mod, fun, arity) ->
          [m, f, a] = args
          dynamic_site(facts, ctx, anno, m, f, list_length(a, ctx.env))

        {mod, fun, arity} in [{"erlang", "make_fun", 3}, {"Elixir.Function", "capture", 3}] ->
          [m, f, a] = args
          dynamic_site(facts, ctx, anno, m, f, integer(a, ctx.env))

        true ->
          facts
          |> add_edge(ctx, mfa(mod, fun, arity), anno, kind(anno))
          |> add_mfa_refs(args, ctx, anno)
      end

    facts =
      if MapSet.member?(@init_targets, {mod, fun, arity}) do
        literals = Enum.map(args, &literal(&1, ctx.env, 0))
        entry = {ctx.caller, mfa(mod, fun, arity), literals, ctx.file, line(anno)}
        %{facts | init: [entry | facts.init]}
      else
        facts
      end

    walk_list(facts, args, ctx)
  end

  # Remote call with a computed module and/or function (`mod.fun(...)`).
  defp walk({:call, anno, {:remote, _, mod_expr, fun_expr}, args}, ctx, facts)
       when is_list(args) do
    facts
    |> dynamic_site(ctx, anno, mod_expr, fun_expr, length(args))
    |> walk_list([mod_expr, fun_expr | args], ctx)
  end

  # Local capture `&fun/1`.
  defp walk({:fun, anno, {:function, fun, arity}}, ctx, facts)
       when is_atom(fun) and is_integer(arity) do
    target =
      if MapSet.member?(ctx.defined, {fun, arity}) or not :erl_internal.bif(fun, arity),
        do: ctx.module,
        else: "erlang"

    add_edge(facts, ctx, mfa(target, Atom.to_string(fun), arity), anno, :static_call)
  end

  # Remote capture `&Mod.fun/2` (possibly with computed parts).
  defp walk({:fun, anno, {:function, mod_expr, fun_expr, arity_expr}}, ctx, facts) do
    case {mod_expr, fun_expr, arity_expr} do
      {{:atom, _, mod}, {:atom, _, fun}, {:integer, _, arity}} ->
        add_edge(facts, ctx, mfa(name(mod), Atom.to_string(fun), arity), anno, :static_call)

      _ ->
        dynamic_site(facts, ctx, anno, mod_expr, fun_expr, integer(arity_expr, ctx.env))
    end
  end

  # `{Mod, :fun, [args]}` / `{Mod, :fun, arity}` triples.
  defp walk({:tuple, anno, [{:atom, _, _}, {:atom, _, _}, _] = elements} = node, ctx, facts) do
    facts
    |> add_mfa_refs(elements, ctx, anno)
    |> walk_children(node, ctx)
  end

  # Anonymous functions: their bodies run on behalf of the enclosing function.
  defp walk({:fun, _anno, {:clauses, clauses}}, ctx, facts), do: walk_list(facts, clauses, ctx)

  defp walk({:named_fun, _anno, _name, clauses}, ctx, facts),
    do: walk_list(facts, clauses, ctx)

  # Patterns and guards never transfer control to another module.
  defp walk({:clause, _anno, _patterns, _guards, body}, ctx, facts),
    do: walk_list(facts, body, ctx)

  defp walk({:match, _anno, _pattern, expr}, ctx, facts), do: walk(expr, ctx, facts)

  defp walk({gen, _anno, _pattern, expr}, ctx, facts) when gen in @generators,
    do: walk(expr, ctx, facts)

  # Tags (`{:ok, _}`, keyword keys) and map keys are only references when
  # they are Elixir aliases (`{MyWorker, arg}`).
  defp walk({:tuple, _anno, [{:atom, _, tag} | rest]} = node, ctx, facts) do
    if elixir_alias?(tag),
      do: walk_children(facts, node, ctx),
      else: walk_list(facts, rest, ctx)
  end

  defp walk({assoc, _anno, {:atom, _, key}, value} = node, ctx, facts)
       when assoc in [:map_field_assoc, :map_field_exact] do
    if elixir_alias?(key),
      do: walk_children(facts, node, ctx),
      else: walk(value, ctx, facts)
  end

  defp walk({:atom, anno, atom}, ctx, facts) do
    value = Atom.to_string(atom)

    if MapSet.member?(@boring_atoms, value) do
      facts
    else
      %{facts | refs: [{ctx.caller, value, ctx.file, line(anno)} | facts.refs]}
    end
  end

  defp walk(list, ctx, facts) when is_list(list), do: walk_list(facts, list, ctx)
  defp walk(tuple, ctx, facts) when is_tuple(tuple), do: walk_children(facts, tuple, ctx)
  defp walk(_other, _ctx, facts), do: facts

  defp walk_children(facts, tuple, ctx) do
    tuple |> Tuple.to_list() |> Enum.drop(2) |> Enum.reduce(facts, &walk(&1, ctx, &2))
  end

  defp walk_list(facts, list, ctx) when is_list(list),
    do: Enum.reduce(list, facts, &walk(&1, ctx, &2))

  defp walk_list(facts, other, ctx), do: walk(other, ctx, facts)

  defp apply3?("erlang", "apply", 3), do: true
  defp apply3?("Elixir.Kernel", "apply", 3), do: true
  defp apply3?(_mod, _fun, _arity), do: false

  # -- dynamic dispatch ------------------------------------------------------------

  defp dynamic_site(facts, ctx, anno, mod_expr, fun_expr, arity) do
    mods = resolve_atoms(mod_expr, ctx.env, 0)
    funs = resolve_atoms(fun_expr, ctx.env, 0)

    case {mods, funs, arity} do
      {{:ok, mods}, {:ok, funs}, arity} when is_integer(arity) ->
        Enum.reduce(for(m <- mods, f <- funs, do: {m, f}), facts, fn {m, f}, acc ->
          add_edge(acc, ctx, mfa(m, f, arity), anno, :dynamic_apply)
        end)

      _ ->
        known_modules =
          case mods do
            {:ok, list} -> list
            :error -> [nil]
          end

        known_function =
          case funs do
            {:ok, [single]} -> single
            _ -> nil
          end

        calls =
          for module <- known_modules do
            %DynamicCall{
              caller: ctx.caller,
              known_module: module,
              known_function: known_function,
              arity: arity,
              file: ctx.file,
              line: line(anno)
            }
          end

        %{facts | dynamic: Enum.reverse(calls) ++ facts.dynamic}
    end
  end

  defp add_mfa_refs(facts, args, ctx, anno) do
    args
    |> Enum.chunk_every(3, 1, :discard)
    |> Enum.reduce(facts, fn
      [{:atom, _, mod}, {:atom, _, fun}, third], acc ->
        case list_length(third, ctx.env) || integer(third, ctx.env) do
          arity when is_integer(arity) and arity in 0..255 ->
            edge = %CallEdge{
              from: ctx.caller,
              to: mfa(name(mod), Atom.to_string(fun), arity),
              file: ctx.file,
              line: line(anno),
              kind: :dynamic_apply
            }

            %{acc | mfa_refs: [edge | acc.mfa_refs]}

          _ ->
            acc
        end

      _, acc ->
        acc
    end)
  end

  defp add_edge(facts, ctx, %MFA{} = to, anno, kind) do
    edge = %CallEdge{from: ctx.caller, to: to, file: ctx.file, line: line(anno), kind: kind}
    %{facts | edges: [edge | facts.edges]}
  end

  defp finish(edges) do
    edges
    |> Enum.reverse()
    |> Enum.uniq_by(fn %CallEdge{from: from, to: to, kind: kind} -> {from, to, kind} end)
  end

  defp kind(anno) do
    if :erl_anno.generated(anno), do: :macro_expanded, else: :static_call
  end

  # -- clause-local constant propagation -------------------------------------------

  # Maps variable names bound exactly by `Var = Expr` to the list of their
  # right-hand sides. Variables also bound by patterns are left out.
  defp bindings(clause) do
    {matches, pattern_vars} = collect_bindings(clause, {%{}, MapSet.new()})

    matches
    |> Map.drop(MapSet.to_list(pattern_vars))
    |> Map.delete(:_)
  end

  defp collect_bindings({:clause, _, patterns, guards, body}, acc) do
    acc = add_pattern_vars(patterns, acc)
    acc = collect_bindings(guards, acc)
    collect_bindings(body, acc)
  end

  defp collect_bindings({:match, _, {:var, _, var}, rhs}, {matches, vars}) do
    collect_bindings(rhs, {Map.update(matches, var, [rhs], &[rhs | &1]), vars})
  end

  defp collect_bindings({:match, _, lhs, rhs}, acc) do
    acc = add_pattern_vars(lhs, acc)
    collect_bindings(rhs, collect_bindings(lhs, acc))
  end

  defp collect_bindings({gen, _, pattern, expr}, acc) when gen in @generators do
    collect_bindings(expr, add_pattern_vars(pattern, acc))
  end

  defp collect_bindings({:fun, _, {:clauses, clauses}}, acc), do: collect_bindings(clauses, acc)

  defp collect_bindings({:named_fun, _, name, clauses}, {matches, vars}),
    do: collect_bindings(clauses, {matches, MapSet.put(vars, name)})

  defp collect_bindings(list, acc) when is_list(list),
    do: Enum.reduce(list, acc, &collect_bindings/2)

  defp collect_bindings(tuple, acc) when is_tuple(tuple) and tuple_size(tuple) > 2,
    do: tuple |> Tuple.to_list() |> Enum.drop(2) |> collect_bindings(acc)

  defp collect_bindings(_other, acc), do: acc

  defp add_pattern_vars(pattern, {matches, vars}), do: {matches, pattern_vars(pattern, vars)}

  defp pattern_vars({:var, _, var}, acc), do: MapSet.put(acc, var)
  defp pattern_vars(list, acc) when is_list(list), do: Enum.reduce(list, acc, &pattern_vars/2)

  defp pattern_vars(tuple, acc) when is_tuple(tuple) and tuple_size(tuple) > 2,
    do: tuple |> Tuple.to_list() |> Enum.drop(2) |> pattern_vars(acc)

  defp pattern_vars(_other, acc), do: acc

  defp resolve_atoms(_expr, _env, depth) when depth > 8, do: :error
  defp resolve_atoms({:atom, _, atom}, _env, _depth), do: {:ok, [name(atom)]}
  defp resolve_atoms({:match, _, _lhs, rhs}, env, depth), do: resolve_atoms(rhs, env, depth + 1)

  defp resolve_atoms({:var, _, var}, env, depth) do
    case Map.get(env, var) do
      nil ->
        :error

      exprs ->
        Enum.reduce_while(exprs, {:ok, []}, fn expr, {:ok, acc} ->
          case resolve_atoms(expr, env, depth + 1) do
            {:ok, atoms} -> {:cont, {:ok, acc ++ atoms}}
            :error -> {:halt, :error}
          end
        end)
        |> case do
          {:ok, atoms} -> {:ok, Enum.uniq(atoms)}
          :error -> :error
        end
    end
  end

  defp resolve_atoms(_expr, _env, _depth), do: :error

  defp list_length(expr, env, depth \\ 0)
  defp list_length(_expr, _env, depth) when depth > 8, do: nil
  defp list_length({nil, _}, _env, _depth), do: 0

  defp list_length({:cons, _, _head, tail}, env, depth) do
    case list_length(tail, env, depth + 1) do
      nil -> nil
      n -> n + 1
    end
  end

  defp list_length({:var, _, var}, env, depth) do
    case Map.get(env, var) do
      [single] -> list_length(single, env, depth + 1)
      _ -> nil
    end
  end

  defp list_length(_expr, _env, _depth), do: nil

  defp integer({:integer, _, value}, _env), do: value

  defp integer({:var, _, var}, env) do
    case Map.get(env, var) do
      [{:integer, _, value}] -> value
      _ -> nil
    end
  end

  defp integer(_expr, _env), do: nil

  # -- literals --------------------------------------------------------------------

  defp literal(_expr, _env, depth) when depth > @max_literal_depth, do: :dynamic
  defp literal({:atom, _, atom}, _env, _depth), do: {:atom, Atom.to_string(atom)}
  defp literal({type, _, value}, _env, _depth) when type in [:integer, :float, :char], do: value
  defp literal({:string, _, chars}, _env, _depth), do: chars
  defp literal({nil, _}, _env, _depth), do: []

  defp literal({:cons, _, head, tail}, env, depth) do
    case literal(tail, env, depth + 1) do
      list when is_list(list) -> [literal(head, env, depth + 1) | list]
      _ -> :dynamic
    end
  end

  defp literal({:tuple, _, elements}, env, depth),
    do: {:tuple, Enum.map(elements, &literal(&1, env, depth + 1))}

  defp literal({:map, _, assocs}, env, depth) do
    {:map,
     Enum.map(assocs, fn
       {_assoc, _, key, value} -> {literal(key, env, depth + 1), literal(value, env, depth + 1)}
       _ -> {:dynamic, :dynamic}
     end)}
  end

  defp literal({:bin, _, elements}, _env, _depth) do
    elements
    |> Enum.reduce_while([], fn
      {:bin_element, _, {:string, _, chars}, :default, :default}, acc -> {:cont, [chars | acc]}
      _, _ -> {:halt, :dynamic}
    end)
    |> case do
      :dynamic -> :dynamic
      parts -> parts |> Enum.reverse() |> List.to_string()
    end
  rescue
    _ -> :dynamic
  end

  defp literal({:fun, _, {:function, {:atom, _, m}, {:atom, _, f}, {:integer, _, a}}}, _, _),
    do: {:fun, MFA.format(mfa(name(m), Atom.to_string(f), a))}

  defp literal({:var, _, var}, env, depth) do
    case Map.get(env, var) do
      [single] -> literal(single, env, depth + 1)
      _ -> :dynamic
    end
  end

  defp literal({:match, _, _lhs, rhs}, env, depth), do: literal(rhs, env, depth + 1)
  defp literal(_expr, _env, _depth), do: :dynamic

  # -- helpers -------------------------------------------------------------------

  defp attributes(forms, chunk) do
    from_forms = for {:attribute, _, key, value} <- forms, do: {key, value}

    entries =
      case chunk do
        list when is_list(list) and list != [] ->
          for {key, values} <- list, value <- List.wrap(values), do: {key, value}

        _ ->
          from_forms
      end

    entries
    |> Enum.filter(fn {key, _} -> is_atom(key) and Atom.to_string(key) in @kept_attributes end)
    |> Enum.group_by(fn {key, _} -> Atom.to_string(key) end, fn {_, value} ->
      encode_term(value)
    end)
  end

  defp behaviours(attributes) do
    (Map.get(attributes, "behaviour", []) ++ Map.get(attributes, "behavior", []))
    |> List.flatten()
    |> Enum.flat_map(fn
      {:atom, name} -> [name]
      _ -> []
    end)
    |> Enum.uniq()
  end

  defp normalize_file(file, root) do
    path = if is_list(file), do: List.to_string(file), else: to_string(file)

    cond do
      is_binary(root) and Path.type(path) == :absolute ->
        expanded_root = Path.expand(root)

        case Path.relative_to(path, expanded_root) do
          ^path -> path
          relative -> relative
        end

      true ->
        path
    end
  rescue
    _ -> nil
  end

  defp proper_list?([]), do: true
  defp proper_list?([_ | tail]), do: proper_list?(tail)
  defp proper_list?(_), do: false

  defp fa({fun, arity}), do: {Atom.to_string(fun), arity}

  defp line(anno) do
    case :erl_anno.line(anno) do
      line when is_integer(line) and line > 0 -> line
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp elixir_alias?(atom), do: match?("Elixir." <> _, Atom.to_string(atom))

  defp mfa(module, function, arity),
    do: %MFA{module: module, function: function, arity: arity}

  defp name(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp name(binary) when is_binary(binary), do: binary
end
