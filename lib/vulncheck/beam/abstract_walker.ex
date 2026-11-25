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

  @eval_calls MapSet.new([
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
      function_lines: function_lines(forms),
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
    target = local_module(ctx, fun, length(args))
    named_call(facts, ctx, anno, target, Atom.to_string(fun), args)
  end

  # Static remote call (with the apply family handled specially).
  defp walk({:call, anno, {:remote, _, {:atom, _, mod}, {:atom, _, fun}}, args}, ctx, facts)
       when is_list(args) do
    mod = name(mod)
    fun = Atom.to_string(fun)
    named_call(facts, ctx, anno, mod, fun, args)
  end

  # Remote call with a computed module and/or function (`mod.fun(...)`).
  defp walk({:call, anno, {:remote, _, mod_expr, fun_expr}, args}, ctx, facts)
       when is_list(args) do
    facts
    |> dynamic_site(ctx, anno, mod_expr, fun_expr, length(args))
    |> walk_list([mod_expr, fun_expr | args], ctx)
  end

  # Erlang also lowers apply(Fun, [Args]) to an invocation through a function value.
  defp walk({:call, anno, capture, args}, ctx, facts) when is_list(args) do
    facts
    |> invoke_fun(ctx, anno, capture, length(args), length(args))
    |> walk_list(args, ctx)
  end

  # Local capture `&fun/1`.
  defp walk({:fun, anno, {:function, fun, arity}}, ctx, facts)
       when is_atom(fun) and is_integer(arity) do
    target = local_module(ctx, fun, arity)
    fun_name = Atom.to_string(fun)

    facts
    |> add_edge(ctx, mfa(target, fun_name, arity), anno, :static_call)
    |> record_plug_capture(ctx, target, fun_name, arity, anno)
  end

  # Remote capture `&Mod.fun/2` (possibly with computed parts).
  defp walk({:fun, anno, {:function, mod_expr, fun_expr, arity_expr}}, ctx, facts) do
    case {mod_expr, fun_expr, arity_expr} do
      {{:atom, _, mod}, {:atom, _, fun}, {:integer, _, arity}} ->
        mod_name = name(mod)
        fun_name = Atom.to_string(fun)

        facts
        |> add_edge(ctx, mfa(mod_name, fun_name, arity), anno, :static_call)
        |> record_plug_capture(ctx, mod_name, fun_name, arity, anno)

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

  # Phoenix 1.7+ `__match_route__/4` returns `{metadata, prepare, pipe, {Controller, :action}}`.
  # Restrict `"__plug_tuple__"` recording strictly to router match functions (`__match_route__`,
  # `match`) so arbitrary tuples in user functions do not mask unattributed controller refs.
  # Walk route metadata skipping only the matching `plug: Controller` entry, and flag any other
  # `Elixir.*` module atom appearing outside the recognized plug-tuple slot in `__match_route__`
  # / `match` as a `:dynamic` `"__plug_tuple__"` site so mixed static+dynamic refs stay sound.
  defp walk(
         {:tuple, _anno,
          [e1, e2, e3, {:tuple, inner_anno, [{:atom, _, mod_atom}, opt_expr]} = inner]},
         ctx,
         facts
       ) do
    if elixir_alias?(mod_atom) and ctx.caller.function in ["__match_route__", "match"] do
      facts
      |> record_plug_tuple(ctx, mod_atom, opt_expr, inner_anno)
      |> add_module_ref(ctx, mod_atom, inner_anno)
      |> walk_route_metadata(e1, mod_atom, ctx)
      |> walk_list([e2, e3, opt_expr], ctx)
    else
      facts
      |> walk_list([e1, e2, e3], ctx)
      |> walk_children(inner, ctx)
    end
  end

  defp walk({:tuple, anno, [{:atom, _, mod_atom}, opt_expr]} = node, ctx, facts) do
    if elixir_alias?(mod_atom) and ctx.caller.function in ["__match_route__", "match"] do
      facts
      |> record_plug_tuple(ctx, mod_atom, opt_expr, anno)
      |> add_module_ref(ctx, mod_atom, anno)
      |> walk_list([opt_expr], ctx)
    else
      walk_children(facts, node, ctx)
    end
  end

  defp walk({:atom, anno, atom}, ctx, facts) do
    value = Atom.to_string(atom)

    if MapSet.member?(@boring_atoms, value) do
      facts
    else
      facts = %{facts | refs: [{ctx.caller, value, ctx.file, line(anno)} | facts.refs]}

      if ctx.caller.function in ["__match_route__", "match"] and elixir_alias?(atom) do
        entry = {ctx.caller, mfa(value, "__plug_tuple__", 2), [:dynamic], ctx.file, line(anno)}
        %{facts | init: [entry | facts.init]}
      else
        facts
      end
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

  defp local_module(ctx, fun, arity) do
    cond do
      MapSet.member?(ctx.defined, {fun, arity}) -> ctx.module
      mod = Map.get(ctx.imports, {fun, arity}) -> name(mod)
      :erl_internal.bif(fun, arity) -> "erlang"
      true -> ctx.module
    end
  end

  defp named_call(facts, ctx, anno, mod, "apply", [capture, args])
       when mod in ["erlang", "Elixir.Kernel"] do
    facts
    |> invoke_fun(ctx, anno, capture, list_length(args, ctx.env), min_length(args, ctx.env))
    |> walk_list([args], ctx)
  end

  defp named_call(facts, ctx, anno, mod, fun, args) do
    arity = length(args)

    facts =
      case {mod, fun, args} do
        {mod, "apply", [m, f, a]} when mod in ["erlang", "Elixir.Kernel"] ->
          dynamic_site(facts, ctx, anno, m, f, list_length(a, ctx.env), min_length(a, ctx.env))

        {"erlang", "make_fun", [m, f, a]} ->
          dynamic_site(facts, ctx, anno, m, f, integer(a, ctx.env))

        {"Elixir.Function", "capture", [m, f, a]} ->
          dynamic_site(facts, ctx, anno, m, f, integer(a, ctx.env))

        _ ->
          facts
          |> add_edge(ctx, mfa(mod, fun, arity), anno, kind(anno))
          |> add_mfa_refs(args, ctx, anno)
      end

    facts =
      if MapSet.member?(@eval_calls, {mod, fun, arity}) do
        eval_call = %DynamicCall{
          caller: ctx.caller,
          known_module: nil,
          known_function: nil,
          arity: nil,
          min_arity: 0,
          file: ctx.file,
          line: line(anno),
          kind: :module_function
        }

        %{facts | dynamic: [eval_call | facts.dynamic]}
      else
        facts
      end

    facts =
      if MapSet.member?(@init_targets, {mod, fun, arity}) or
           (fun == "call" and arity == 2 and String.starts_with?(mod, "Elixir.")) do
        literals = init_call_literals(mod, fun, args, ctx.env)
        entry = {ctx.caller, mfa(mod, fun, arity), literals, ctx.file, line(anno)}
        %{facts | init: [entry | facts.init]}
      else
        facts
      end

    walk_list(facts, args, ctx)
  end

  defp init_call_literals(mod, "call", [conn_expr, opts_expr], env)
       when mod != "Elixir.Plug.Parsers" do
    opts_literal =
      case bound_value(opts_expr, env, 0) do
        {:call, _, {:remote, _, {:atom, _, m2}, {:atom, _, :init}}, [inner_opt]} ->
          if name(m2) == mod, do: literal(inner_opt, env, 0), else: literal(opts_expr, env, 0)

        _ ->
          literal(opts_expr, env, 0)
      end

    [literal(conn_expr, env, 0), opts_literal]
  end

  defp init_call_literals(_mod, _fun, args, env) do
    Enum.map(args, &literal(&1, env, 0))
  end

  # -- dynamic dispatch ------------------------------------------------------------

  defp invoke_fun(facts, ctx, anno, capture, arity, min_arity) do
    case bound_value(capture, ctx.env, 0) do
      {:fun, _, {:function, fun, n}} when is_atom(fun) and is_integer(n) ->
        invoke_known_fun(
          facts,
          ctx,
          anno,
          local_module(ctx, fun, n),
          name(fun),
          n,
          arity,
          min_arity
        )

      {:fun, _, {:function, {:atom, _, mod}, {:atom, _, fun}, {:integer, _, n}}} ->
        invoke_known_fun(facts, ctx, anno, name(mod), name(fun), n, arity, min_arity)

      {:fun, _, {:clauses, _}} ->
        walk(capture, ctx, facts)

      {:named_fun, _, _, _} ->
        walk(capture, ctx, facts)

      _ ->
        call = %DynamicCall{
          caller: ctx.caller,
          kind: :function_value,
          arity: arity,
          min_arity: min_arity,
          file: ctx.file,
          line: line(anno)
        }

        walk(capture, ctx, %{facts | dynamic: [call | facts.dynamic]})
    end
  end

  defp invoke_known_fun(facts, ctx, anno, mod, fun, n, arity, min_arity) do
    cond do
      n == arity ->
        add_edge(facts, ctx, mfa(mod, fun, n), anno, :dynamic_apply)

      is_nil(arity) and n >= min_arity ->
        add_edge(facts, ctx, mfa(mod, fun, n), anno, :dynamic_candidate)

      true ->
        facts
    end
  end

  defp bound_value({:var, _, var} = expr, env, depth) when depth < 8 do
    case Map.get(env, var) do
      [value] -> bound_value(value, env, depth + 1)
      _ -> expr
    end
  end

  defp bound_value({:match, _, _lhs, expr}, env, depth) when depth < 8,
    do: bound_value(expr, env, depth + 1)

  defp bound_value(expr, _env, _depth), do: expr

  defp dynamic_site(facts, ctx, anno, mod_expr, fun_expr, arity, min_arity \\ 0) do
    mods = resolve_atoms(mod_expr, ctx.env, 0)
    funs = resolve_atoms(fun_expr, ctx.env, 0)

    case {mods, funs, arity} do
      {{:ok, mods}, {:ok, funs}, arity} when is_integer(arity) ->
        targets = for m <- mods, f <- funs, do: {m, f}
        kind = if match?([_], targets), do: :dynamic_apply, else: :dynamic_candidate

        Enum.reduce(targets, facts, fn {m, f}, acc ->
          add_edge(acc, ctx, mfa(m, f, arity), anno, kind)
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
              min_arity: if(is_integer(arity), do: arity, else: min_arity),
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

  # Number of elements known to precede the tail of an argument list:
  # `[env, next | rest]` has at least two.
  defp min_length(expr, env, depth \\ 0)
  defp min_length(_expr, _env, depth) when depth > 8, do: 0
  defp min_length({:cons, _, _head, tail}, env, depth), do: 1 + min_length(tail, env, depth + 1)

  defp min_length({:var, _, var}, env, depth) do
    case Map.get(env, var) do
      [single] -> min_length(single, env, depth + 1)
      _ -> 0
    end
  end

  defp min_length(_expr, _env, _depth), do: 0

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

  defp function_lines(forms) do
    for {:function, anno, fun, arity, _} <- forms,
        line = line(anno),
        into: %{},
        do: {{Atom.to_string(fun), arity}, line}
  end

  defp add_module_ref(facts, ctx, mod_atom, anno) do
    %{facts | refs: [{ctx.caller, name(mod_atom), ctx.file, line(anno)} | facts.refs]}
  end

  defp walk_route_metadata(facts, {:map, _anno, assocs}, mod_atom, ctx) when is_list(assocs) do
    Enum.reduce(assocs, facts, fn
      {:map_field_assoc, _, {:atom, _, :plug}, {:atom, _, ^mod_atom}}, acc ->
        acc

      assoc, acc ->
        walk(assoc, ctx, acc)
    end)
  end

  defp walk_route_metadata(facts, expr, _mod_atom, ctx), do: walk(expr, ctx, facts)

  defp record_plug_tuple(facts, ctx, mod_atom, opt_expr, anno) do
    entry =
      {ctx.caller, mfa(name(mod_atom), "__plug_tuple__", 2), [literal(opt_expr, ctx.env, 0)],
       ctx.file, line(anno)}

    %{facts | init: [entry | facts.init]}
  end

  defp record_plug_capture(facts, ctx, mod_name, fun_name, 2, anno)
       when fun_name in ["call", "action"] do
    if String.starts_with?(mod_name, "Elixir.") do
      entry =
        {ctx.caller, mfa(mod_name, "call", 2), [:dynamic, :dynamic], ctx.file, line(anno)}

      %{facts | init: [entry | facts.init]}
    else
      facts
    end
  end

  defp record_plug_capture(facts, _ctx, _mod_name, _fun_name, _arity, _anno), do: facts

  defp elixir_alias?(atom), do: match?("Elixir." <> _, Atom.to_string(atom))

  defp mfa(module, function, arity),
    do: %MFA{module: module, function: function, arity: arity}

  defp name(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp name(binary) when is_binary(binary), do: binary
end
