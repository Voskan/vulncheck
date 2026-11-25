defmodule VulnCheck.Workspace.MixProject do
  @moduledoc """
  Static (non-evaluating) reader for `mix.exs` files.

  Extracts the application name, version, `apps_path` and the declared
  dependencies with their `only:`, `runtime:`, `optional:`, `path:` and
  `in_umbrella:` options. Multi-clause helpers such as `defp deps(:prod)` /
  `defp deps(_)` and expressions composed with `++`, `|>`, `List.flatten/1`,
  `~w(...)a`, module attributes, `if`/`unless`, `case` and `cond` are
  evaluated statically without executing code.
  """

  alias VulnCheck.Literal

  @known_envs ["prod", "dev", "test", "docs"]

  defmodule Dep do
    @moduledoc "A dependency declared in `mix.exs`."
    @enforce_keys [:name]
    defstruct [
      :name,
      :requirement,
      :path,
      only: :all,
      runtime: true,
      optional: false,
      in_umbrella: false,
      git: nil
    ]

    @type t :: %__MODULE__{
            name: String.t(),
            requirement: String.t() | nil,
            path: String.t() | nil,
            only: :all | [String.t()],
            runtime: boolean(),
            optional: boolean(),
            in_umbrella: boolean(),
            git: String.t() | nil
          }
  end

  defstruct [:file, :app, :version, :apps_path, deps: [], deps_parsed: true]

  @type t :: %__MODULE__{
          file: String.t(),
          app: String.t() | nil,
          version: String.t() | nil,
          apps_path: String.t() | nil,
          deps: [Dep.t()],
          deps_parsed: boolean()
        }

  @doc "Reads and analyzes a `mix.exs` file."
  @spec parse_file(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def parse_file(path) do
    with {:ok, source} <- read(path),
         {:ok, ast} <- Literal.quote_string(source, file: path) do
      {:ok, analyze(ast, path)}
    end
  end

  @doc "Analyzes an already encoded `mix.exs` AST."
  @spec analyze(Macro.t(), String.t()) :: t()
  def analyze(ast, file) do
    {functions, attrs} = collect_definitions(ast)
    ctx = %{functions: functions, attrs: attrs, vars: %{}, env_vars: MapSet.new()}
    {project, project_ok?} = project_keyword(ctx)

    {deps, parsed?} =
      case kw_value(project, "deps") do
        nil when project_ok? ->
          {[], true}

        nil ->
          case Map.fetch(ctx.functions, {"deps", 0}) do
            {:ok, _} ->
              {fallback_deps, _} = call_local_zero("deps", ctx, %{})
              {fallback_deps, false}

            :error ->
              {[], false}
          end

        deps_ast ->
          {deps, deps_ok?} = eval_deps(deps_ast, ctx, %{})
          {deps, project_ok? and deps_ok?}
      end

    %__MODULE__{
      file: file,
      app: project |> kw_value("app") |> atom_value(),
      version: project |> kw_value("version") |> string_value(attrs),
      apps_path: project |> kw_value("apps_path") |> string_value(attrs),
      deps: merge_dep_scopes(deps),
      deps_parsed: parsed?
    }
  end

  # Deduplicates dependencies declared across multiple branches/clauses by
  # unioning their environment scopes (`:all` dominates any explicit list)
  # and keeping `runtime: true` if any active declaration runs at runtime.
  defp merge_dep_scopes(deps) do
    {order, merged} =
      Enum.reduce(deps, {[], %{}}, fn %Dep{name: name} = dep, {order, acc} ->
        case Map.fetch(acc, name) do
          :error ->
            {[name | order], Map.put(acc, name, dep)}

          {:ok, existing} ->
            combined = %{
              existing
              | only: union_only(existing.only, dep.only),
                runtime: existing.runtime or dep.runtime,
                optional: existing.optional and dep.optional,
                in_umbrella: existing.in_umbrella or dep.in_umbrella,
                path: existing.path || dep.path,
                git: existing.git || dep.git,
                requirement: existing.requirement || dep.requirement
            }

            {order, Map.put(acc, name, combined)}
        end
      end)

    order |> Enum.reverse() |> Enum.map(&Map.fetch!(merged, &1))
  end

  defp union_only(:all, _), do: :all
  defp union_only(_, :all), do: :all
  defp union_only(a, b) when is_list(a) and is_list(b), do: Enum.uniq(a ++ b)

  defp read(path) do
    case File.read(path) do
      {:ok, source} -> {:ok, source}
      {:error, reason} -> {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  # Collects all `def`/`defp` clauses grouped by `{name, arity}` in declaration
  # order, along with module attributes `@name`.
  defp collect_definitions(ast) do
    {_ast, {funcs, attrs}} =
      Macro.prewalk(ast, {%{}, %{}}, fn
        {{:__lit_atom__, kind}, _meta, [head, body]} = node, {funcs, attrs}
        when kind in ["def", "defp"] ->
          case {parse_head(head), body_of(body)} do
            {{name, args, guard}, body_ast} when is_binary(name) and body_ast != nil ->
              key = {name, length(args)}
              {clean_args, defaults} = extract_defaults(args)
              clause = {clean_args, guard, body_ast}
              funcs = Map.update(funcs, key, [clause], &[clause | &1])
              funcs = add_default_dispatchers(funcs, name, clean_args, defaults)
              {node, {funcs, attrs}}

            _ ->
              {node, {funcs, attrs}}
          end

        {{:__lit_atom__, kind}, _meta, [head]} = node, {funcs, attrs}
        when kind in ["def", "defp"] ->
          case parse_head(head) do
            {name, args, _guard} when is_binary(name) ->
              {clean_args, defaults} = extract_defaults(args)
              funcs = add_default_dispatchers(funcs, name, clean_args, defaults)
              {node, {funcs, attrs}}

            _ ->
              {node, {funcs, attrs}}
          end

        {:@, _meta, [{{:__lit_atom__, name}, _, [value]}]} = node, {funcs, attrs} ->
          {node, {funcs, Map.put(attrs, name, value)}}

        node, acc ->
          {node, acc}
      end)

    funcs = Map.new(funcs, fn {key, clauses} -> {key, Enum.reverse(clauses)} end)
    {funcs, attrs}
  end

  defp extract_defaults(args) do
    Enum.map_reduce(args, [], fn
      {:\\, _meta, [arg, default]}, defaults -> {arg, defaults ++ [default]}
      arg, defaults -> {arg, defaults}
    end)
  end

  # Supports `defp deps(env \\ Mix.env())` invoked as `deps()`: registers a
  # synthetic 0-arity clause delegating to the 1-arity definition with the
  # default argument AST.
  defp add_default_dispatchers(funcs, name, [_single], [default_ast]) do
    key0 = {name, 0}

    if Map.has_key?(funcs, key0) do
      funcs
    else
      delegate = {{:__lit_atom__, name}, [], [default_ast]}
      Map.put(funcs, key0, [{[], nil, delegate}])
    end
  end

  defp add_default_dispatchers(funcs, _name, _args, _defaults), do: funcs

  defp parse_head({:when, _meta, [call, guard]}) do
    case parse_head(call) do
      {name, args, nil} -> {name, args, guard}
      _ -> nil
    end
  end

  defp parse_head({{:__lit_atom__, name}, _meta, args}) when is_binary(name) do
    cond do
      args in [nil, []] or is_atom(args) -> {name, [], nil}
      is_list(args) -> {name, args, nil}
      true -> nil
    end
  end

  defp parse_head(_), do: nil

  defp body_of(body) when is_list(body) do
    body |> keyword_entries() |> kw_value("do")
  end

  defp body_of(_), do: nil

  # -- project/0 keyword resolution --------------------------------------------

  defp project_keyword(ctx) do
    case Map.get(ctx.functions, {"project", 0}) do
      [{[], _guard, body} | _] -> resolve_keyword(body, ctx, %{})
      _ -> {[], false}
    end
  end

  defp resolve_keyword({:|>, _, [_, {_, _, _}]} = pipe, ctx, seen) do
    resolve_keyword(desugar_pipe(pipe), ctx, seen)
  end

  defp resolve_keyword(
         {{:., _, [{:__aliases__, _, [{:__lit_atom__, "Keyword"}]}, {:__lit_atom__, "merge"}]}, _,
          [left, right]},
         ctx,
         seen
       ) do
    {l_entries, l_ok?} = resolve_keyword(left, ctx, seen)
    {r_entries, r_ok?} = resolve_keyword(right, ctx, seen)
    {r_entries ++ l_entries, l_ok? and r_ok?}
  end

  defp resolve_keyword({:__block__, _meta, exprs}, ctx, seen) when is_list(exprs) and exprs != [] do
    {ctx, last} = collect_block_vars(exprs, ctx)
    resolve_keyword(last, ctx, seen)
  end

  defp resolve_keyword({:@, _meta, [{{:__lit_atom__, name}, _, _}]}, ctx, seen) do
    lookup_once(seen, {:attr, name}, ctx.attrs, name, &resolve_keyword(&1, ctx, &2))
  end

  defp resolve_keyword({:++, _meta, [left, right]}, ctx, seen) do
    {l_entries, l_ok?} = resolve_keyword(left, ctx, seen)
    {r_entries, r_ok?} = resolve_keyword(right, ctx, seen)
    {l_entries ++ r_entries, l_ok? and r_ok?}
  end

  defp resolve_keyword({{:__lit_atom__, name}, _meta, args}, ctx, seen)
       when args in [nil, []] or is_atom(args) do
    cond do
      is_atom(args) and Map.has_key?(ctx.vars, name) ->
        lookup_once(seen, {:var, name}, ctx.vars, name, &resolve_keyword(&1, ctx, &2))

      Map.has_key?(ctx.functions, {name, 0}) ->
        call_local_keyword(name, ctx, seen)

      true ->
        {[], false}
    end
  end

  defp resolve_keyword(list, _ctx, _seen) when is_list(list), do: {keyword_entries(list), true}
  defp resolve_keyword(_other, _ctx, _seen), do: {[], false}

  defp call_local_keyword(name, ctx, seen) do
    key = {:kw_fun, name, 0}

    if Map.has_key?(seen, key) do
      {[], false}
    else
      case Map.get(ctx.functions, {name, 0}) do
        [{[], _guard, body} | _] -> resolve_keyword(body, ctx, Map.put(seen, key, true))
        _ -> {[], false}
      end
    end
  end

  defp lookup_once(seen, key, map, map_key, fun) do
    with false <- Map.has_key?(seen, key),
         {:ok, value} <- Map.fetch(map, map_key) do
      fun.(value, Map.put(seen, key, true))
    else
      _ -> {[], false}
    end
  end

  defp keyword_entries(list) do
    Enum.flat_map(list, fn
      {{:__lit_atom__, key}, value} -> [{key, value}]
      {key, value} when key in [:do, :else] -> [{Atom.to_string(key), value}]
      _ -> []
    end)
  end

  defp kw_value(entries, key) do
    case List.keyfind(entries, key, 0) do
      {^key, value} -> value
      nil -> nil
    end
  end

  defp atom_value({:__lit_atom__, name}), do: name
  defp atom_value(_), do: nil

  defp string_value(value, _attrs) when is_binary(value), do: value

  defp string_value({:@, _meta, [{{:__lit_atom__, name}, _, _}]}, attrs) do
    case Map.get(attrs, name) do
      value when is_binary(value) -> value
      _ -> nil
    end
  end

  defp string_value(_value, _attrs), do: nil

  # -- static dependency evaluator ---------------------------------------------

  defp eval_deps({:|>, _, [_, {_, _, _}]} = pipe, ctx, visited) do
    eval_deps(desugar_pipe(pipe), ctx, visited)
  end

  defp eval_deps(list, ctx, visited) when is_list(list) do
    Enum.reduce(list, {[], true}, fn item, {acc, ok?} ->
      case dep_tuple(item, ctx.attrs) do
        {:ok, dep} ->
          {acc ++ [dep], ok?}

        :error ->
          {sub, sub_ok?} = eval_deps(item, ctx, visited)
          {acc ++ sub, ok? and sub_ok?}
      end
    end)
  end

  defp eval_deps({:++, _meta, [left, right]}, ctx, visited) do
    {l_deps, l_ok?} = eval_deps(left, ctx, visited)
    {r_deps, r_ok?} = eval_deps(right, ctx, visited)
    {l_deps ++ r_deps, l_ok? and r_ok?}
  end

  defp eval_deps(
         {{:., _, [{:__aliases__, _, [{:__lit_atom__, "List"}]}, {:__lit_atom__, "flatten"}]}, _,
          [arg]},
         ctx,
         visited
       ) do
    eval_deps(arg, ctx, visited)
  end

  defp eval_deps({:__block__, _meta, []}, _ctx, _visited), do: {[], true}

  defp eval_deps({:__block__, _meta, exprs}, ctx, visited) when is_list(exprs) do
    {ctx, last} = collect_block_vars(exprs, ctx)
    eval_deps(last, ctx, visited)
  end

  defp eval_deps({:@, _meta, [{{:__lit_atom__, name}, _, _}]}, ctx, visited) do
    lookup_once(visited, {:attr, name}, ctx.attrs, name, &eval_deps(&1, ctx, &2))
  end

  defp eval_deps({{:__lit_atom__, op}, _meta, [cond_ast, branches]}, ctx, visited)
       when op in ["if", "unless"] and is_list(branches) do
    entries = keyword_entries(branches)
    {do_deps, do_ok?} = eval_branch(kw_value(entries, "do"), ctx, visited)
    {else_deps, else_ok?} = eval_branch(kw_value(entries, "else"), ctx, visited)

    condition =
      cond_ast
      |> eval_env_condition(&mix_env_expr?(&1, ctx))
      |> then(fn c -> if op == "unless", do: invert_condition(c), else: c end)

    {do_deps, else_deps} =
      case condition do
        :unknown -> {do_deps, else_deps}
        scope -> {narrow_deps(do_deps, scope), narrow_deps(else_deps, invert_condition(scope))}
      end

    {do_deps ++ else_deps, do_ok? and else_ok?}
  end

  defp eval_deps({{:__lit_atom__, "case"}, _meta, [subject, branches]}, ctx, visited)
       when is_list(branches) do
    case kw_value(keyword_entries(branches), "do") do
      clauses when is_list(clauses) ->
        if mix_env_expr?(subject, ctx),
          do: eval_env_case_clauses(clauses, ctx, visited),
          else: eval_unscoped_clauses(clauses, ctx, visited)

      _ ->
        {[], false}
    end
  end

  defp eval_deps({{:__lit_atom__, "cond"}, _meta, [branches]}, ctx, visited)
       when is_list(branches) do
    case kw_value(keyword_entries(branches), "do") do
      clauses when is_list(clauses) -> eval_cond_clauses(clauses, ctx, visited)
      _ -> {[], false}
    end
  end

  # Local variable bound earlier in a block, or 0-arity local function call.
  defp eval_deps({{:__lit_atom__, name}, _meta, args}, ctx, visited)
       when args in [nil, []] or is_atom(args) do
    cond do
      is_atom(args) and Map.has_key?(ctx.vars, name) ->
        lookup_once(visited, {:var, name}, ctx.vars, name, &eval_deps(&1, ctx, &2))

      Map.has_key?(ctx.functions, {name, 0}) ->
        call_local_zero(name, ctx, visited)

      true ->
        {[], false}
    end
  end

  # Local 1-arity call such as `deps(Mix.env())` or `deps(:prod)`.
  defp eval_deps({{:__lit_atom__, name}, _meta, [arg]}, ctx, visited) do
    key = {name, 1}

    case {Map.has_key?(visited, key), Map.fetch(ctx.functions, key)} do
      {false, {:ok, clauses}} ->
        next_visited = Map.put(visited, key, true)

        cond do
          mix_env_expr?(arg, ctx) ->
            eval_env_fun_clauses(clauses, ctx, next_visited)

          match?({:__lit_atom__, _}, arg) ->
            {:__lit_atom__, env_name} = arg
            eval_literal_env_fun_clauses(clauses, env_name, ctx, next_visited)

          true ->
            {[], false}
        end

      _ ->
        {[], false}
    end
  end

  defp eval_deps(node, ctx, _visited) do
    case dep_tuple(node, ctx.attrs) do
      {:ok, dep} -> {[dep], true}
      :error -> {[], false}
    end
  end

  defp desugar_pipe({:|>, meta, [lhs, {head, call_meta, args}]}) do
    args = if is_list(args), do: [lhs | args], else: [lhs]
    {head, call_meta || meta, args}
  end

  defp eval_branch(nil, _ctx, _visited), do: {[], true}
  defp eval_branch(ast, ctx, visited), do: eval_deps(ast, ctx, visited)

  defp call_local_zero(name, ctx, visited) do
    key = {name, 0}

    if Map.has_key?(visited, key) do
      {[], false}
    else
      next_visited = Map.put(visited, key, true)

      ctx.functions
      |> Map.fetch!(key)
      |> Enum.reduce({[], true}, fn {_args, _guard, body}, {acc, ok?} ->
        {deps, sub_ok?} = eval_deps(body, ctx, next_visited)
        {acc ++ deps, ok? and sub_ok?}
      end)
    end
  end

  defp eval_env_fun_clauses(clauses, ctx, visited) do
    {deps, ok?, _matched} =
      Enum.reduce(clauses, {[], true, []}, fn {args, guard, body}, {acc, ok?, matched} ->
        clause_ctx =
          case args do
            [{{:__lit_atom__, var}, _, c}] when is_atom(c) and var != "_" ->
              %{ctx | env_vars: MapSet.put(ctx.env_vars, var)}

            _ ->
              ctx
          end

        {sub_deps, sub_ok?} = eval_deps(body, clause_ctx, visited)
        {narrowed, next_matched} = apply_clause_scope(sub_deps, args, guard, matched)
        {acc ++ narrowed, ok? and sub_ok?, next_matched}
      end)

    {deps, ok?}
  end

  # Unconditional call with a literal atom argument such as `deps(:common)` or
  # `deps(:prod)` runs in every environment that reaches the call site; do not
  # narrow its result to `only: [env_name]`.
  defp eval_literal_env_fun_clauses(clauses, env_name, ctx, visited) do
    clause =
      Enum.find(clauses, fn {args, guard, _body} ->
        case args do
          [{:__lit_atom__, ^env_name}] when is_nil(guard) -> true
          [{{:__lit_atom__, var}, _, c}] when is_atom(c) -> guard_matches_env?(guard, var, env_name)
          _ -> false
        end
      end)

    case clause do
      {_args, _guard, body} ->
        eval_deps(body, ctx, visited)

      nil ->
        {[], false}
    end
  end

  defp eval_env_case_clauses(clauses, ctx, visited) do
    {deps, ok?, _matched} =
      Enum.reduce(clauses, {[], true, []}, fn
        {:->, _, [[pat], body]}, {acc, ok?, matched} ->
          {args, guard} =
            case pat do
              {:when, _, [inner, g]} -> {[inner], g}
              other -> {[other], nil}
            end

          {sub_deps, sub_ok?} = eval_deps(body, ctx, visited)
          {narrowed, next_matched} = apply_clause_scope(sub_deps, args, guard, matched)
          {acc ++ narrowed, ok? and sub_ok?, next_matched}

        _, {acc, _ok?, matched} ->
          {acc, false, matched}
      end)

    {deps, ok?}
  end

  defp eval_unscoped_clauses(clauses, ctx, visited) do
    Enum.reduce(clauses, {[], true}, fn
      {:->, _, [_lhs, body]}, {acc, ok?} ->
        {sub_deps, sub_ok?} = eval_deps(body, ctx, visited)
        {acc ++ sub_deps, ok? and sub_ok?}

      _, {acc, _ok?} ->
        {acc, false}
    end)
  end

  defp eval_cond_clauses(clauses, ctx, visited) do
    {deps, ok?, _matched} =
      Enum.reduce(clauses, {[], true, []}, fn
        {:->, _, [[test], body]}, {acc, ok?, matched} ->
          {sub_deps, sub_ok?} = eval_deps(body, ctx, visited)

          case eval_env_condition(test, &mix_env_expr?(&1, ctx)) do
            {:include, envs} ->
              {acc ++ narrow_deps(sub_deps, {:include, envs}), ok? and sub_ok?,
               Enum.uniq(matched ++ envs)}

            {:exclude, excluded} ->
              {acc ++ narrow_deps(sub_deps, {:exclude, excluded}), ok? and sub_ok?,
               Enum.uniq(matched ++ (@known_envs -- excluded))}

            :unknown ->
              narrowed =
                if test == true and matched != [],
                  do: narrow_deps(sub_deps, {:exclude, matched}),
                  else: sub_deps

              {acc ++ narrowed, ok? and sub_ok?, matched}
          end

        _, {acc, _ok?, matched} ->
          {acc, false, matched}
      end)

    {deps, ok?}
  end

  defp apply_clause_scope(deps, [{:__lit_atom__, env}], nil, matched) do
    {narrow_deps(deps, {:include, [env]}), Enum.uniq(matched ++ [env])}
  end

  defp apply_clause_scope(deps, [{{:__lit_atom__, _var}, _, c}], nil, matched) when is_atom(c) do
    narrowed = if matched == [], do: deps, else: narrow_deps(deps, {:exclude, matched})
    {narrowed, matched}
  end

  defp apply_clause_scope(deps, [{{:__lit_atom__, var}, _, c}], guard, matched)
       when is_atom(c) and guard != nil do
    case eval_env_condition(guard, &var_ref?(&1, var)) do
      {:include, envs} ->
        {narrow_deps(deps, {:include, envs}), Enum.uniq(matched ++ envs)}

      {:exclude, excluded} ->
        {narrow_deps(deps, {:exclude, excluded}), Enum.uniq(matched ++ (@known_envs -- excluded))}

      :unknown ->
        {deps, matched}
    end
  end

  defp apply_clause_scope(deps, _args, _guard, matched), do: {deps, matched}

  defp guard_matches_env?(nil, _var, _env), do: true

  defp guard_matches_env?(guard, var, env) do
    case eval_env_condition(guard, &var_ref?(&1, var)) do
      {:include, envs} -> env in envs
      {:exclude, excluded} -> env not in excluded
      :unknown -> true
    end
  end

  defp var_ref?({{:__lit_atom__, var}, _, c}, var) when is_atom(c), do: true
  defp var_ref?(_, _var), do: false

  # Evaluates boolean environment predicates against `target?.(node)` (either
  # `Mix.env()` or a clause variable) into `{:include, envs}`, `{:exclude, envs}`
  # or `:unknown`.
  defp eval_env_condition({op, _, [left, right]}, target?) when op in [:==, :===, :!=, :!==] do
    env =
      cond do
        target?.(left) -> atom_value(right)
        target?.(right) -> atom_value(left)
        true -> nil
      end

    case env do
      nil -> :unknown
      name when op in [:==, :===] -> {:include, [name]}
      name -> {:exclude, [name]}
    end
  end

  defp eval_env_condition({:in, _, [left, right]}, target?) do
    if target?.(left) do
      case atom_list(right) do
        {:ok, [_ | _] = envs} -> {:include, Enum.uniq(envs)}
        _ -> :unknown
      end
    else
      :unknown
    end
  end

  defp eval_env_condition({op, _, [inner]}, target?) when op in [:not, :!] do
    invert_condition(eval_env_condition(inner, target?))
  end

  defp eval_env_condition({op, _, [left, right]}, target?) when op in [:or, :||] do
    case {eval_env_condition(left, target?), eval_env_condition(right, target?)} do
      {{:include, a}, {:include, b}} -> {:include, Enum.uniq(a ++ b)}
      {{:exclude, a}, {:exclude, b}} -> {:exclude, Enum.filter(a, &(&1 in b))}
      _ -> :unknown
    end
  end

  defp eval_env_condition({op, _, [left, right]}, target?) when op in [:and, :&&] do
    case {eval_env_condition(left, target?), eval_env_condition(right, target?)} do
      {{:exclude, a}, {:exclude, b}} -> {:exclude, Enum.uniq(a ++ b)}
      {{:include, a}, {:include, b}} -> {:include, Enum.filter(a, &(&1 in b))}
      {{:include, inc}, {:exclude, exc}} -> {:include, inc -- exc}
      {{:exclude, exc}, {:include, inc}} -> {:include, inc -- exc}
      _ -> :unknown
    end
  end

  defp eval_env_condition(_, _target?), do: :unknown

  defp invert_condition({:include, envs}), do: {:exclude, envs}
  defp invert_condition({:exclude, envs}), do: {:include, envs}
  defp invert_condition(:unknown), do: :unknown

  defp mix_env_expr?(node, ctx) do
    case node do
      {{:__lit_atom__, var}, _, c} when is_atom(c) ->
        MapSet.member?(ctx.env_vars, var)

      other ->
        mix_env_call?(other)
    end
  end

  defp mix_env_call?(
         {{:., _, [{:__aliases__, _, [{:__lit_atom__, "Mix"}]}, {:__lit_atom__, "env"}]}, _, []}
       ),
       do: true

  defp mix_env_call?(_), do: false

  defp narrow_deps(deps, scope) do
    Enum.map(deps, fn %Dep{only: only} = dep -> %{dep | only: narrow_only(only, scope)} end)
  end

  defp narrow_only(:all, {:include, envs}), do: envs
  defp narrow_only(only, {:include, envs}) when is_list(only), do: Enum.filter(only, &(&1 in envs))
  defp narrow_only(:all, {:exclude, excluded}), do: @known_envs -- excluded
  defp narrow_only(only, {:exclude, excluded}) when is_list(only), do: only -- excluded

  defp collect_block_vars([single], ctx), do: {ctx, single}

  defp collect_block_vars([stmt | rest], ctx) do
    ctx =
      case stmt do
        {:=, _, [{{:__lit_atom__, var}, _, c}, rhs]} when is_binary(var) and is_atom(c) ->
          %{ctx | vars: Map.put(ctx.vars, var, rhs)}

        _ ->
          ctx
      end

    collect_block_vars(rest, ctx)
  end

  # -- dependency tuples -------------------------------------------------------

  defp dep_tuple({{:__lit_atom__, name}, second}, attrs) do
    cond do
      is_binary(second) ->
        {:ok, build_dep(name, second, [])}

      (req = string_value(second, attrs)) != nil ->
        {:ok, build_dep(name, req, [])}

      non_empty_keyword?(second) ->
        {:ok, build_dep(name, nil, second)}

      true ->
        :error
    end
  end

  defp dep_tuple({:{}, _meta, [{:__lit_atom__, name}, requirement_ast, opts]}, attrs) do
    if keyword?(opts) do
      {:ok, build_dep(name, string_value(requirement_ast, attrs), opts)}
    else
      :error
    end
  end

  defp dep_tuple(_, _attrs), do: :error

  defp keyword?(list) when is_list(list) do
    Enum.all?(list, &match?({{:__lit_atom__, _}, _}, &1))
  end

  defp keyword?(_), do: false

  defp non_empty_keyword?(list) when is_list(list) and list != [], do: keyword?(list)
  defp non_empty_keyword?(_), do: false

  defp build_dep(name, requirement, opts) do
    entries = keyword_entries(opts)

    %Dep{
      name: name,
      requirement: requirement,
      path: entries |> kw_value("path") |> literal_string(),
      git:
        entries |> kw_value("git") |> literal_string() ||
          entries |> kw_value("github") |> literal_string(),
      only: only_value(kw_value(entries, "only")),
      runtime: kw_value(entries, "runtime") != false,
      optional: kw_value(entries, "optional") == true,
      in_umbrella: kw_value(entries, "in_umbrella") == true
    }
  end

  defp literal_string(value) when is_binary(value), do: value
  defp literal_string(_), do: nil

  defp only_value(nil), do: :all
  defp only_value({:__lit_atom__, env}), do: [env]

  defp only_value(other) do
    case atom_list(other) do
      {:ok, envs} -> envs
      :error -> :all
    end
  end

  defp atom_list({:sigil_w, _, [{:<<>>, _, [words]}, mods]})
       when is_binary(words) and is_list(mods) do
    if ?a in mods, do: {:ok, String.split(words)}, else: :error
  end

  defp atom_list(list) when is_list(list) do
    envs = for {:__lit_atom__, env} <- list, do: env
    if length(envs) == length(list), do: {:ok, envs}, else: :error
  end

  defp atom_list(_), do: :error
end
