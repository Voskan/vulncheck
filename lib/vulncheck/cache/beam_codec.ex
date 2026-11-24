defmodule VulnCheck.Cache.BeamCodec do
  @moduledoc false

  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary}

  @edge_kinds [
    :static_call,
    :macro_expanded,
    :behaviour_callback,
    :supervisor_child,
    :dynamic_apply,
    :dynamic_candidate,
    :imports
  ]

  @dynamic_kinds [:module_function, :function_value]

  @spec pack(ModuleSummary.t()) :: {tuple(), tuple()}
  def pack(%ModuleSummary{} = s) do
    acc = %{map: %{}, list: [], next: 0}

    {mod_id, acc} = intern(s.module, acc)
    {source_id, acc} = intern_opt(s.source_file, acc)
    {sha_id, acc} = intern_opt(s.sha256, acc)
    {pkg_id, acc} = intern_opt(s.package, acc)

    {functions, acc} =
      map_acc(s.functions, acc, fn {f, a}, a0 ->
        {fid, a1} = intern(f, a0)
        {{fid, a}, a1}
      end)

    {function_lines, acc} =
      map_acc(s.function_lines, acc, fn {{f, a}, line}, a0 ->
        {fid, a1} = intern(f, a0)
        {{{fid, a}, line}, a1}
      end)

    {exports, acc} =
      map_acc(s.exports, acc, fn {f, a}, a0 ->
        {fid, a1} = intern(f, a0)
        {{fid, a}, a1}
      end)

    {behaviours, acc} = map_acc(s.behaviours, acc, &intern/2)

    {attributes, acc} =
      map_acc(s.attributes, acc, fn {k, v}, a0 ->
        {kid, a1} = intern(k, a0)
        {{kid, v}, a1}
      end)

    {edges, acc} = map_acc(s.edges, acc, &pack_edge/2)
    {dynamic_dispatches, acc} = map_acc(s.dynamic_dispatches, acc, &pack_dynamic/2)

    {module_refs, acc} =
      map_acc(s.module_refs, acc, fn {caller, mod, file, line}, a0 ->
        {c_id, a1} = pack_mfa(caller, a0)
        {m_id, a2} = intern(mod, a1)
        {f_id, a3} = intern_opt(file, a2)
        {{c_id, m_id, f_id, line}, a3}
      end)

    {mfa_refs, acc} = map_acc(s.mfa_refs, acc, &pack_edge/2)

    {init_literals, acc} =
      map_acc(s.init_literals, acc, fn {caller, target, args, file, line}, a0 ->
        {c_id, a1} = pack_mfa(caller, a0)
        {t_id, a2} = pack_mfa(target, a1)
        {f_id, a3} = intern_opt(file, a2)
        {{c_id, t_id, args, f_id, line}, a3}
      end)

    {imports, acc} =
      map_acc(s.imports, acc, fn {m, f, a}, a0 ->
        {mid, a1} = intern(m, a0)
        {fid, a2} = intern(f, a1)
        {{mid, fid, a}, a2}
      end)

    strings = acc.list |> Enum.reverse() |> List.to_tuple()

    packed =
      {mod_id, source_id, sha_id, pkg_id, s.has_debug_info, functions, Map.new(function_lines),
       exports, behaviours, Map.new(attributes), edges, dynamic_dispatches, module_refs, mfa_refs,
       init_literals, imports}

    {strings, packed}
  end

  @spec valid?(term(), term()) :: boolean()
  def valid?(strings, packed)
      when is_tuple(strings) and is_tuple(packed) and tuple_size(packed) == 16 do
    n = tuple_size(strings)

    strings_ok? =
      n == 0 or
        Enum.all?(0..(n - 1), fn i -> is_binary(elem(strings, i)) end)

    if strings_ok? do
      {mod_id, source_id, sha_id, pkg_id, has_debug_info, functions, function_lines, exports,
       behaviours, attributes, edges, dynamic_dispatches, module_refs, mfa_refs, init_literals,
       imports} = packed

      idx?(mod_id, n) and elem(strings, mod_id) != "" and
        opt_idx?(source_id, n) and opt_idx?(sha_id, n) and opt_idx?(pkg_id, n) and
        is_boolean(has_debug_info) and
        valid_fa_list?(functions, n) and
        valid_function_lines?(function_lines, n) and
        valid_fa_list?(exports, n) and
        valid_idx_list?(behaviours, n) and
        valid_attributes?(attributes, n) and
        valid_edges?(edges, n) and
        valid_dynamic_dispatches?(dynamic_dispatches, n) and
        valid_module_refs?(module_refs, n) and
        valid_edges?(mfa_refs, n) and
        valid_init_literals?(init_literals, n) and
        valid_imports?(imports, n)
    else
      false
    end
  end

  def valid?(_strings, _packed), do: false

  @spec unpack(tuple(), tuple(), %{String.t() => String.t()}) ::
          {ModuleSummary.t(), %{String.t() => String.t()}}
  def unpack(strings, packed, pool \\ %{}) do
    {strings, pool} = pool_strings(strings, pool)

    {mod_id, source_id, sha_id, pkg_id, has_debug_info, functions, function_lines, exports,
     behaviours, attributes, edges, dynamic_dispatches, module_refs, mfa_refs, init_literals,
     imports} = packed

    summary = %ModuleSummary{
      module: elem(strings, mod_id),
      source_file: str_opt(strings, source_id),
      sha256: str_opt(strings, sha_id),
      package: str_opt(strings, pkg_id),
      has_debug_info: has_debug_info,
      functions: Enum.map(functions, fn {fid, a} -> {elem(strings, fid), a} end),
      function_lines:
        Map.new(function_lines, fn {{fid, a}, line} -> {{elem(strings, fid), a}, line} end),
      exports: Enum.map(exports, fn {fid, a} -> {elem(strings, fid), a} end),
      behaviours: Enum.map(behaviours, &elem(strings, &1)),
      attributes: Map.new(attributes, fn {kid, v} -> {elem(strings, kid), v} end),
      edges: Enum.map(edges, &unpack_edge(&1, strings)),
      dynamic_dispatches: Enum.map(dynamic_dispatches, &unpack_dynamic(&1, strings)),
      module_refs:
        Enum.map(module_refs, fn {caller, mid, fid, line} ->
          {unpack_mfa(caller, strings), elem(strings, mid), str_opt(strings, fid), line}
        end),
      mfa_refs: Enum.map(mfa_refs, &unpack_edge(&1, strings)),
      init_literals:
        Enum.map(init_literals, fn {caller, target, args, fid, line} ->
          {unpack_mfa(caller, strings), unpack_mfa(target, strings), args, str_opt(strings, fid),
           line}
        end),
      imports:
        Enum.map(imports, fn {mid, fid, a} -> {elem(strings, mid), elem(strings, fid), a} end)
    }

    {summary, pool}
  end

  # -- packing helpers ---------------------------------------------------------

  defp intern_opt(nil, acc), do: {nil, acc}
  defp intern_opt(str, acc), do: intern(str, acc)

  defp intern(str, %{map: map, list: list, next: next} = acc) when is_binary(str) do
    case Map.fetch(map, str) do
      {:ok, id} ->
        {id, acc}

      :error ->
        {next, %{map: Map.put(map, str, next), list: [str | list], next: next + 1}}
    end
  end

  defp map_acc(enum, acc, fun) do
    {rev, acc} =
      Enum.reduce(enum, {[], acc}, fn item, {items, a0} ->
        {packed, a1} = fun.(item, a0)
        {[packed | items], a1}
      end)

    {Enum.reverse(rev), acc}
  end

  defp pack_mfa(%MFA{module: m, function: f, arity: a}, acc) do
    {mid, acc} = intern(m, acc)
    {fid, acc} = intern(f, acc)
    {{mid, fid, a}, acc}
  end

  defp pack_edge(%CallEdge{from: from, to: to, file: file, line: line, kind: kind}, acc) do
    {from_id, acc} = pack_mfa(from, acc)
    {to_id, acc} = pack_mfa(to, acc)
    {file_id, acc} = intern_opt(file, acc)
    {{from_id, to_id, file_id, line, kind}, acc}
  end

  defp pack_dynamic(%DynamicCall{} = d, acc) do
    {c_id, acc} = pack_mfa(d.caller, acc)
    {km_id, acc} = intern_opt(d.known_module, acc)
    {kf_id, acc} = intern_opt(d.known_function, acc)
    {f_id, acc} = intern_opt(d.file, acc)
    {{c_id, km_id, kf_id, d.arity, d.min_arity, f_id, d.line, d.kind}, acc}
  end

  # -- unpacking helpers -------------------------------------------------------

  defp pool_strings(strings, pool) when map_size(pool) == 0 do
    list = Tuple.to_list(strings)
    {strings, Map.new(list, &{&1, &1})}
  end

  defp pool_strings(strings, pool) do
    {rev, pool} =
      strings
      |> Tuple.to_list()
      |> Enum.reduce({[], pool}, fn str, {acc, p} ->
        case Map.fetch(p, str) do
          {:ok, canonical} -> {[canonical | acc], p}
          :error -> {[str | acc], Map.put(p, str, str)}
        end
      end)

    {rev |> Enum.reverse() |> List.to_tuple(), pool}
  end

  defp str_opt(_strings, nil), do: nil
  defp str_opt(strings, idx), do: elem(strings, idx)

  defp unpack_mfa({mid, fid, a}, strings),
    do: %MFA{module: elem(strings, mid), function: elem(strings, fid), arity: a}

  defp unpack_edge({from_id, to_id, file_id, line, kind}, strings) do
    %CallEdge{
      from: unpack_mfa(from_id, strings),
      to: unpack_mfa(to_id, strings),
      file: str_opt(strings, file_id),
      line: line,
      kind: kind
    }
  end

  defp unpack_dynamic({c_id, km_id, kf_id, arity, min_arity, f_id, line, kind}, strings) do
    %DynamicCall{
      caller: unpack_mfa(c_id, strings),
      known_module: str_opt(strings, km_id),
      known_function: str_opt(strings, kf_id),
      arity: arity,
      min_arity: min_arity,
      file: str_opt(strings, f_id),
      line: line,
      kind: kind
    }
  end

  # -- validation helpers ------------------------------------------------------

  @max_literal_depth 16

  defp idx?(i, n), do: is_integer(i) and i >= 0 and i < n
  defp opt_idx?(nil, _n), do: true
  defp opt_idx?(i, n), do: idx?(i, n)

  defp proper_all?([], _fun), do: true
  defp proper_all?([head | tail], fun), do: fun.(head) and proper_all?(tail, fun)
  defp proper_all?(_improper, _fun), do: false

  defp valid_mfa?({mid, fid, a}, n), do: idx?(mid, n) and idx?(fid, n) and is_integer(a) and a >= 0
  defp valid_mfa?(_, _n), do: false

  defp valid_fa_list?(list, n) when is_list(list) do
    proper_all?(list, fn
      {fid, a} -> idx?(fid, n) and is_integer(a) and a >= 0
      _ -> false
    end)
  end

  defp valid_fa_list?(_, _n), do: false

  defp valid_function_lines?(map, n) when is_map(map) do
    Enum.all?(map, fn
      {{fid, a}, line} ->
        idx?(fid, n) and is_integer(a) and a >= 0 and is_integer(line) and line > 0

      _ ->
        false
    end)
  end

  defp valid_function_lines?(_, _n), do: false

  defp valid_idx_list?(list, n) when is_list(list), do: proper_all?(list, &idx?(&1, n))
  defp valid_idx_list?(_, _n), do: false

  defp valid_attributes?(map, n) when is_map(map) do
    Enum.all?(map, fn {k, v} -> idx?(k, n) and valid_literal_list?(v, 0) end)
  end

  defp valid_attributes?(_, _n), do: false

  defp valid_edges?(list, n) when is_list(list) do
    proper_all?(list, fn
      {from, to, file_id, line, kind} ->
        valid_mfa?(from, n) and valid_mfa?(to, n) and opt_idx?(file_id, n) and
          (is_nil(line) or (is_integer(line) and line >= 0)) and kind in @edge_kinds

      _ ->
        false
    end)
  end

  defp valid_edges?(_, _n), do: false

  defp valid_dynamic_dispatches?(list, n) when is_list(list) do
    proper_all?(list, fn
      {caller, km_id, kf_id, arity, min_arity, file_id, line, kind} ->
        valid_mfa?(caller, n) and opt_idx?(km_id, n) and opt_idx?(kf_id, n) and
          (is_nil(arity) or (is_integer(arity) and arity >= 0)) and
          is_integer(min_arity) and min_arity >= 0 and
          opt_idx?(file_id, n) and (is_nil(line) or (is_integer(line) and line >= 0)) and
          kind in @dynamic_kinds

      _ ->
        false
    end)
  end

  defp valid_dynamic_dispatches?(_, _n), do: false

  defp valid_module_refs?(list, n) when is_list(list) do
    proper_all?(list, fn
      {caller, mod_id, file_id, line} ->
        valid_mfa?(caller, n) and idx?(mod_id, n) and opt_idx?(file_id, n) and
          (is_nil(line) or (is_integer(line) and line >= 0))

      _ ->
        false
    end)
  end

  defp valid_module_refs?(_, _n), do: false

  defp valid_init_literals?(list, n) when is_list(list) do
    proper_all?(list, fn
      {caller, target, args, file_id, line} ->
        valid_mfa?(caller, n) and valid_mfa?(target, n) and valid_literal_list?(args, 0) and
          opt_idx?(file_id, n) and (is_nil(line) or (is_integer(line) and line >= 0))

      _ ->
        false
    end)
  end

  defp valid_init_literals?(_, _n), do: false

  defp valid_imports?(list, n) when is_list(list) do
    proper_all?(list, fn
      {mid, fid, a} -> idx?(mid, n) and idx?(fid, n) and is_integer(a) and a >= 0
      _ -> false
    end)
  end

  defp valid_imports?(_, _n), do: false

  defp valid_literal_list?(list, depth) when is_list(list) and depth <= @max_literal_depth do
    proper_all?(list, &valid_literal?(&1, depth + 1))
  end

  defp valid_literal_list?(_, _depth), do: false

  defp valid_literal?(_term, depth) when depth > @max_literal_depth, do: false
  defp valid_literal?(:dynamic, _depth), do: true
  defp valid_literal?(value, _depth) when is_binary(value) or is_number(value), do: true
  defp valid_literal?({:atom, name}, _depth) when is_binary(name), do: true
  defp valid_literal?({:fun, name}, _depth) when is_binary(name), do: true

  defp valid_literal?({:tuple, items}, depth) when is_list(items),
    do: valid_literal_list?(items, depth)

  defp valid_literal?({:map, pairs}, depth) when is_list(pairs) do
    proper_all?(pairs, fn
      {k, v} -> valid_literal?(k, depth + 1) and valid_literal?(v, depth + 1)
      _ -> false
    end)
  end

  defp valid_literal?(list, depth) when is_list(list), do: valid_literal_list?(list, depth)
  defp valid_literal?(_other, _depth), do: false
end
