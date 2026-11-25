defmodule VulnCheck.Entrypoints.Adapters do
  @moduledoc """
  Resolves which implementation of a pluggable adapter family is configured
  (`Tesla`, `Swoosh`, `Ecto`, `Phoenix.PubSub`), so a vulnerable adapter
  package that is merely a transitive dependency can be told apart from
  the active one.

  Sources, all read without executing code: `config/config.exs`,
  `config/<env>.exs`, `config/runtime.exs` (quoted with atom-safe
  encoding), the `configured_adapters` option and module literals of the
  project's own compiled code (`adapter Tesla.Adapter.Mint`,
  `use Ecto.Repo, adapter: ...`).
  """

  alias VulnCheck.{Config, Literal}
  alias VulnCheck.Types.{MFA, ModuleSummary, Package, Workspace}

  @families %{
    tesla: %{
      owners: ["tesla"],
      default: ["Elixir.Tesla.Adapter.Httpc"],
      adapters: %{
        "Elixir.Tesla.Adapter.Hackney" => ["hackney"],
        "Elixir.Tesla.Adapter.Mint" => ["mint", "castore"],
        "Elixir.Tesla.Adapter.Finch" => ["finch"],
        "Elixir.Tesla.Adapter.Gun" => ["gun"],
        "Elixir.Tesla.Adapter.Ibrowse" => ["ibrowse"],
        "Elixir.Tesla.Adapter.Httpc" => []
      }
    },
    swoosh: %{
      owners: ["swoosh"],
      default: ["Elixir.Swoosh.ApiClient.Hackney"],
      adapters: %{
        "Elixir.Swoosh.ApiClient.Hackney" => ["hackney"],
        "Elixir.Swoosh.ApiClient.Finch" => ["finch"],
        "Elixir.Swoosh.ApiClient.Req" => ["req"],
        "Elixir.Swoosh.Adapters.SMTP" => ["gen_smtp"],
        "Elixir.Swoosh.Adapters.Mua" => ["mua"]
      }
    },
    ecto: %{
      owners: ["ecto_sql", "ecto"],
      default: nil,
      adapters: %{
        "Elixir.Ecto.Adapters.Postgres" => ["postgrex"],
        "Elixir.Ecto.Adapters.MyXQL" => ["myxql"],
        "Elixir.Ecto.Adapters.SQLite3" => ["ecto_sqlite3", "exqlite"],
        "Elixir.Ecto.Adapters.Tds" => ["tds"]
      }
    },
    phoenix_pubsub: %{
      owners: ["phoenix_pubsub"],
      default: ["Elixir.Phoenix.PubSub.PG2"],
      adapters: %{
        "Elixir.Phoenix.PubSub.PG2" => [],
        "Elixir.Phoenix.PubSub.Redis" => ["phoenix_pubsub_redis", "redix"]
      }
    }
  }

  @adapter_keys ~w(adapter api_client)
  @trivial_config_atoms MapSet.new(~w(true false nil ok error prod dev test))
  @config_eval_calls MapSet.new([
                       {"Elixir.Code", "eval_string"},
                       {"Elixir.Code", "eval_quoted"},
                       {"Elixir.Kernel", "apply"},
                       {"erlang", "apply"},
                       {"erl_eval", "exprs"},
                       {"erl_eval", "expr"},
                       {"file", "consult"},
                       {"erlang", "binary_to_term"}
                     ])
  @config_module_builders MapSet.union(
                            @config_eval_calls,
                            MapSet.new([
                              {"Elixir.Module", "concat"},
                              {"Elixir.Module", "safe_concat"},
                              {"Elixir.String", "to_atom"},
                              {"Elixir.String", "to_existing_atom"},
                              {"Elixir.List", "to_atom"},
                              {"Elixir.List", "to_existing_atom"},
                              {"Elixir.Kernel", "binary_to_atom"},
                              {"Elixir.Kernel", "binary_to_existing_atom"},
                              {"erlang", "binary_to_atom"},
                              {"erlang", "binary_to_existing_atom"},
                              {"erlang", "list_to_atom"},
                              {"erlang", "list_to_existing_atom"},
                              {"Elixir.Plug.Crypto", "non_executable_binary_to_term"}
                            ])
                          )
  @dynamic_fun_calls MapSet.union(
                       @config_eval_calls,
                       MapSet.new([
                         {"Elixir.Function", "capture"},
                         {"erlang", "make_fun"}
                       ])
                     )

  @type result :: %{
          configured: %{atom() => [String.t()]},
          inactive: %{String.t() => String.t()},
          config_refs: [String.t()],
          config_sites: %{String.t() => {String.t(), non_neg_integer() | nil}},
          config_mfas: [{MFA.t(), String.t(), non_neg_integer() | nil}],
          untracked_fun_sources: boolean(),
          config_dynamic?: boolean(),
          config_dynamic_modules?: boolean(),
          notes: [String.t()]
        }

  @doc "Known adapter families."
  @spec families() :: map()
  def families, do: @families

  @doc """
  Resolves configured adapters and inactive adapter packages.
  """
  @spec resolve(Workspace.t(), %{String.t() => ModuleSummary.t()}, Config.t() | nil) :: result()
  def resolve(%Workspace{} = workspace, modules, config) do
    %{
      refs: config_sites,
      mfas: config_mfas,
      dynamic?: dynamic?,
      dynamic_modules?: dynamic_modules?,
      untracked_fun_sources: untracked_fun_sources,
      notes: notes
    } = read_config_details(workspace)

    config_refs = Enum.map(config_sites, &elem(&1, 0))

    code_refs =
      modules
      |> Map.values()
      |> Enum.filter(&is_nil(&1.package))
      |> Enum.flat_map(fn summary -> Enum.map(summary.module_refs, &elem(&1, 1)) end)

    extra =
      case config do
        %Config{configured_adapters: adapters} when is_map(adapters) -> adapters
        _ -> %{}
      end

    present = workspace.packages |> Map.values() |> Enum.filter(&(&1.scope == :prod))
    present_names = MapSet.new(present, & &1.name)
    referenced = MapSet.new(config_refs ++ code_refs)

    {configured, inactive, family_notes} =
      Enum.reduce(@families, {%{}, %{}, []}, fn {family, spec}, {configured, inactive, notes} ->
        if Enum.any?(spec.owners, &MapSet.member?(present_names, &1)) do
          explicit =
            spec.adapters
            |> Map.keys()
            |> Enum.filter(&MapSet.member?(referenced, &1))
            |> Kernel.++(extra |> Map.get(family, []) |> Enum.map(&normalize/1))
            |> Enum.uniq()
            |> Enum.sort()

          chosen = if explicit == [], do: spec.default, else: explicit

          cond do
            dynamic? ->
              {configured, inactive,
               ["#{family} adapter is configured dynamically; adapter packages kept" | notes]}

            is_nil(chosen) ->
              {configured, inactive, notes}

            true ->
              used = chosen |> Enum.flat_map(&Map.get(spec.adapters, &1, [])) |> MapSet.new()

              unused =
                spec.adapters
                |> Map.values()
                |> List.flatten()
                |> Enum.uniq()
                |> Enum.reject(&MapSet.member?(used, &1))
                |> Enum.filter(&MapSet.member?(present_names, &1))
                |> Enum.filter(&only_family_dependents?(&1, spec, present))

              label = "#{family} (configured: #{Enum.map_join(chosen, ", ", &display/1)})"

              {Map.put(configured, family, chosen),
               Enum.reduce(unused, inactive, &Map.put_new(&2, &1, label)), notes}
          end
        else
          {configured, inactive, notes}
        end
      end)

    %{
      configured: configured,
      inactive: inactive,
      config_refs: Enum.uniq(config_refs),
      config_sites:
        config_sites
        |> Enum.reverse()
        |> Map.new(fn {name, file, line} -> {name, {file, line}} end),
      config_mfas: Enum.uniq_by(config_mfas, &elem(&1, 0)),
      untracked_fun_sources: untracked_fun_sources,
      config_dynamic?: dynamic? or dynamic_modules?,
      config_dynamic_modules?: dynamic_modules?,
      notes: notes ++ Enum.reverse(family_notes)
    }
  end

  # An adapter package is only considered inactive when nothing but the
  # family packages (and other adapter packages) depend on it.
  defp only_family_dependents?(name, spec, packages) do
    adapter_packages = spec.adapters |> Map.values() |> List.flatten() |> MapSet.new()

    packages
    |> Enum.filter(fn %Package{deps: deps, optional_deps: optional} ->
      name in deps or name in optional
    end)
    |> Enum.all?(fn %Package{name: dependent} ->
      dependent in spec.owners or MapSet.member?(adapter_packages, dependent)
    end)
  end

  @doc """
  Reads the configuration files of the project. Returns every module alias
  mentioned in them with the file (relative to the project) and line where
  it appears, whether an adapter key had a non-literal value, and notes
  about unreadable files.
  """
  @spec read_config_files(Workspace.t()) ::
          {[{String.t(), String.t(), non_neg_integer() | nil}], boolean(), [String.t()]}
  def read_config_files(%Workspace{} = workspace) do
    details = read_config_details(workspace)
    {details.refs, details.dynamic?, details.notes}
  end

  @max_symlink_hops 32

  defp read_config_details(%Workspace{root_dir: root, env: env}) do
    expanded_root = Path.expand(root)

    real_root =
      case realpath(expanded_root) do
        {:ok, resolved} -> resolved
        :error -> expanded_root
      end

    initial = %{
      refs: [],
      mfas: [],
      dynamic?: false,
      dynamic_modules?: false,
      untracked_fun_sources: false,
      notes: [],
      visited: MapSet.new()
    }

    result =
      ["config.exs", "#{env}.exs", "runtime.exs"]
      |> Enum.uniq()
      |> Enum.map(&Path.join([expanded_root, "config", &1]))
      |> Enum.filter(&match?({:ok, _}, File.lstat(&1)))
      |> Enum.reduce(initial, fn path, acc ->
        scan_config_file(path, real_root, env, false, acc)
      end)

    Map.delete(result, :visited)
  end

  defp scan_config_file(path, real_root, env, optional?, acc) do
    case realpath(path) do
      :error ->
        %{
          acc
          | dynamic?: true,
            dynamic_modules?: true,
            untracked_fun_sources: true,
            notes:
              acc.notes ++ ["ignored import_config outside project root: #{path}; adapters kept"]
        }

      {:ok, real_target} ->
        cond do
          MapSet.member?(acc.visited, real_target) ->
            acc

          not within_root?(real_target, real_root) ->
            %{
              acc
              | dynamic?: true,
                dynamic_modules?: true,
                untracked_fun_sources: true,
                notes:
                  acc.notes ++
                    ["ignored import_config outside project root: #{path}; adapters kept"]
            }

          not regular_file?(real_target) ->
            if optional? do
              acc
            else
              relative = Path.relative_to(real_target, real_root)

              %{
                acc
                | dynamic?: true,
                  dynamic_modules?: true,
                  untracked_fun_sources: true,
                  notes: acc.notes ++ ["could not read imported config #{relative}; adapters kept"]
              }
            end

          true ->
            relative = Path.relative_to(real_target, real_root)
            acc = %{acc | visited: MapSet.put(acc.visited, real_target)}

            with {:ok, source} <- File.read(real_target),
                 {:ok, ast} <- Literal.quote_string(source, file: real_target) do
              scanned = scan(ast, env)
              sites = Enum.map(scanned.refs, fn {name, line} -> {name, relative, line} end)
              mfas = Enum.map(scanned.mfas, fn {mfa, line} -> {mfa, relative, line} end)

              acc = %{
                acc
                | refs: acc.refs ++ sites,
                  mfas: acc.mfas ++ mfas,
                  dynamic?: acc.dynamic? or scanned.dynamic?,
                  dynamic_modules?: acc.dynamic_modules? or scanned.dynamic_modules?,
                  untracked_fun_sources: acc.untracked_fun_sources or scanned.untracked_fun_sources,
                  notes: acc.notes ++ Enum.map(scanned.notes, &"#{relative}: #{&1}")
              }

              base_dir = Path.dirname(real_target)

              Enum.reduce(scanned.imports, acc, fn {target, opt?}, inner_acc ->
                scan_config_file(Path.expand(target, base_dir), real_root, env, opt?, inner_acc)
              end)
            else
              _ ->
                %{
                  acc
                  | dynamic?: true,
                    dynamic_modules?: true,
                    untracked_fun_sources: true,
                    notes: acc.notes ++ ["could not parse #{relative}; adapters kept"]
                }
            end
        end
    end
  end

  defp regular_file?(path) do
    match?({:ok, %File.Stat{type: :regular}}, File.stat(path))
  end

  defp realpath(path), do: realpath(Path.expand(path), 0)

  defp realpath(_path, hops) when hops > @max_symlink_hops, do: :error

  defp realpath(path, hops) do
    case Path.split(path) do
      [root | segments] -> resolve_segments(segments, root, hops)
      [] -> :error
    end
  end

  defp resolve_segments([], current, _hops), do: {:ok, current}

  defp resolve_segments([seg | rest], current, hops) do
    candidate = Path.join(current, seg)

    case File.lstat(candidate) do
      {:ok, %File.Stat{type: :symlink}} ->
        if hops >= @max_symlink_hops do
          :error
        else
          case File.read_link(candidate) do
            {:ok, target} ->
              next_base = Path.expand(target, current)
              next_path = Enum.reduce(rest, next_base, &Path.join(&2, &1))
              realpath(next_path, hops + 1)

            {:error, _} ->
              :error
          end
        end

      {:ok, %File.Stat{}} ->
        resolve_segments(rest, candidate, hops)

      {:error, :enoent} ->
        {:ok, Enum.reduce(rest, candidate, &Path.join(&2, &1))}

      {:error, _} ->
        :error
    end
  end

  defp within_root?(path, root) do
    normalized_root = String.trim_trailing(root, "/")
    path == normalized_root or String.starts_with?(path, normalized_root <> "/")
  end

  defp scan(ast, env) do
    acc = %{
      refs: [],
      mfas: [],
      imports: [],
      dynamic?: false,
      dynamic_modules?: false,
      untracked_fun_sources: false,
      notes: [],
      env: env,
      optional_import?: false
    }

    acc = scan_node(ast, nil, acc)

    %{
      refs: Enum.reverse(acc.refs),
      mfas: acc.mfas |> Enum.reverse() |> Enum.uniq_by(&elem(&1, 0)),
      imports: Enum.reverse(acc.imports),
      dynamic?: acc.dynamic?,
      dynamic_modules?: acc.dynamic_modules?,
      untracked_fun_sources: acc.untracked_fun_sources,
      notes: Enum.reverse(acc.notes)
    }
  end

  defp scan_node({{:__lit_atom__, "import_config"}, meta, [arg]}, line, acc) do
    line = line_from(meta, line)

    case resolve_import_path(arg, acc.env) do
      {:ok, target} ->
        %{acc | imports: [{target, acc.optional_import?} | acc.imports]}

      :dynamic ->
        acc = %{
          acc
          | dynamic?: true,
            dynamic_modules?: true,
            untracked_fun_sources: true,
            notes: ["dynamic import_config on line #{line || 0}; adapters kept" | acc.notes]
        }

        scan_node(arg, line, acc)
    end
  end

  defp scan_node({{:__lit_atom__, "if"}, meta, [cond_ast, branches]}, line, acc)
       when is_list(branches) do
    line = line_from(meta, line)
    acc = scan_node(cond_ast, line, acc)
    prev_opt = acc.optional_import?
    guard_opt? = optional_import_guard?(cond_ast)
    acc = scan_node(branches, line, %{acc | optional_import?: prev_opt or guard_opt?})
    %{acc | optional_import?: prev_opt}
  end

  defp scan_node({{:__lit_atom__, "config"}, meta, args}, line, acc) when is_list(args) do
    line = line_from(meta, line)
    acc = %{acc | dynamic?: acc.dynamic? or dynamic_adapter?(args)}

    case args do
      [_app, value] ->
        scan_node(value, line, acc)

      [_app, key, value] ->
        acc = scan_node(key, line, acc)
        scan_node(value, line, acc)

      other ->
        scan_list(other, line, acc)
    end
  end

  defp scan_node(
         {:&, meta,
          [
            {:/, _, [{{:., _, [mod_ast, {:__lit_atom__, fun}]}, _, []}, arity]}
          ]},
         line,
         acc
       )
       when is_integer(arity) and arity >= 0 do
    line = line_from(meta, line)

    case module_ref_name(mod_ast) do
      nil ->
        %{acc | untracked_fun_sources: true}

      mod ->
        mfa = %MFA{module: mod, function: fun, arity: arity}
        %{acc | mfas: [{mfa, line} | acc.mfas]}
    end
  end

  defp scan_node({:&, meta, args}, line, acc) when is_list(args) do
    acc = %{acc | untracked_fun_sources: true}
    scan_list(args, line_from(meta, line), acc)
  end

  defp scan_node({:fn, meta, clauses}, line, acc) when is_list(clauses) do
    acc = %{acc | untracked_fun_sources: true}
    scan_list(clauses, line_from(meta, line), acc)
  end

  defp scan_node({{:., meta1, [mod_ast, {:__lit_atom__, fun}]}, meta2, args}, line, acc)
       when is_list(args) do
    line = line_from(meta2, line_from(meta1, line))
    mod = module_ref_name(mod_ast)
    eval_call? = MapSet.member?(@config_eval_calls, {mod, fun})
    untracked? = eval_call? or MapSet.member?(@dynamic_fun_calls, {mod, fun})
    module_builder? = MapSet.member?(@config_module_builders, {mod, fun})

    dynamic_app_env? =
      mod == "Elixir.Application" and fun in ["put_env", "put_all_env"] and
        dynamic_adapter?(args)

    acc = %{
      acc
      | untracked_fun_sources: acc.untracked_fun_sources or untracked?,
        dynamic?: acc.dynamic? or dynamic_app_env? or eval_call?,
        dynamic_modules?: acc.dynamic_modules? or module_builder?
    }

    acc =
      if mod != nil and not MapSet.member?(@trivial_config_atoms, mod) do
        acc = %{acc | refs: [{mod, line} | acc.refs]}

        if length(args) <= 255 do
          mfa = %MFA{module: mod, function: fun, arity: length(args)}
          %{acc | mfas: [{mfa, line} | acc.mfas]}
        else
          acc
        end
      else
        scan_node(mod_ast, line, acc)
      end

    scan_list(args, line, acc)
  end

  defp scan_node({:{}, meta, [mod_ast, {:__lit_atom__, fun}, third]}, line, acc) do
    line = line_from(meta, line)
    mod = module_ref_name(mod_ast)
    arity = mfa_arity(third)

    if mod != nil and arity != nil do
      mfa = %MFA{module: mod, function: fun, arity: arity}
      acc = %{acc | mfas: [{mfa, line} | acc.mfas]}
      acc = scan_node(mod_ast, line, acc)
      scan_node(third, line, acc)
    else
      acc = scan_node(mod_ast, line, acc)
      scan_node(third, line, acc)
    end
  end

  defp scan_node({:{}, meta, elements}, line, acc) when is_list(elements) do
    scan_list(elements, line_from(meta, line), acc)
  end

  defp scan_node({:%{}, meta, pairs}, line, acc) when is_list(pairs) do
    line = line_from(meta, line)

    Enum.reduce(pairs, acc, fn
      {:|, meta2, [base, updates]}, acc ->
        line2 = line_from(meta2, line)
        acc = scan_node(base, line2, acc)
        scan_node(updates, line2, acc)

      {{:__lit_atom__, _key}, value}, acc ->
        scan_node(value, line, acc)

      {key, value}, acc ->
        acc = scan_node(key, line, acc)
        scan_node(value, line, acc)

      other, acc ->
        scan_node(other, line, acc)
    end)
  end

  defp scan_node({:__aliases__, meta, _} = node, line, acc) do
    case Literal.alias_name(node) do
      nil -> acc
      name -> %{acc | refs: [{name, line_from(meta, line)} | acc.refs]}
    end
  end

  # Local variable reference, not an atom literal.
  defp scan_node({{:__lit_atom__, _var}, _meta, ctx}, _line, acc) when is_atom(ctx), do: acc

  # Local function/macro call: do not treat call head as a module reference,
  # but track auto-imported `Kernel` eval/atom-builder BIFs (`apply/2,3`, `binary_to_atom/2`, `binary_to_existing_atom/2`).
  defp scan_node({{:__lit_atom__, fun}, meta, args}, line, acc) when is_list(args) do
    acc =
      cond do
        fun == "apply" and length(args) in [2, 3] ->
          %{acc | untracked_fun_sources: true, dynamic?: true, dynamic_modules?: true}

        fun in ["binary_to_atom", "binary_to_existing_atom"] and length(args) == 2 ->
          %{acc | dynamic_modules?: true}

        true ->
          acc
      end

    scan_list(args, line_from(meta, line), acc)
  end

  defp scan_node({:__lit_atom__, name}, line, acc) when is_binary(name) do
    if MapSet.member?(@trivial_config_atoms, name) do
      acc
    else
      %{acc | refs: [{name, line} | acc.refs]}
    end
  end

  defp scan_node(list, line, acc) when is_list(list) do
    if keyword_list?(list) do
      Enum.reduce(list, acc, fn {{:__lit_atom__, _key}, value}, acc ->
        scan_node(value, line, acc)
      end)
    else
      scan_list(list, line, acc)
    end
  end

  defp scan_node({left, right}, line, acc) do
    acc = scan_node(left, line, acc)
    scan_node(right, line, acc)
  end

  defp scan_node({_op, meta, args}, line, acc) when is_list(meta) and is_list(args) do
    scan_list(args, line_from(meta, line), acc)
  end

  defp scan_node(_other, _line, acc), do: acc

  defp scan_list(list, line, acc), do: Enum.reduce(list, acc, &scan_node(&1, line, &2))

  defp keyword_list?([]), do: false

  defp keyword_list?(list) do
    Enum.all?(list, &match?({{:__lit_atom__, _}, _}, &1))
  end

  defp module_ref_name({:__aliases__, _, _} = node), do: Literal.alias_name(node)
  defp module_ref_name({:__lit_atom__, name}) when is_binary(name), do: name
  defp module_ref_name(_), do: nil

  defp mfa_arity(arity) when is_integer(arity) and arity in 0..255, do: arity
  defp mfa_arity(args) when is_list(args) and length(args) <= 255, do: length(args)
  defp mfa_arity(_), do: nil

  defp line_from(meta, fallback) when is_list(meta), do: Keyword.get(meta, :line, fallback)
  defp line_from(_meta, fallback), do: fallback

  defp resolve_import_path(path, _env) when is_binary(path) and path != "", do: {:ok, path}

  defp resolve_import_path({:<<>>, _, parts}, env) when is_list(parts) do
    parts
    |> Enum.reduce_while({:ok, []}, fn
      part, {:ok, acc} when is_binary(part) ->
        {:cont, {:ok, [part | acc]}}

      {:"::", _, [{{:., _, [Kernel, :to_string]}, _, [expr]}, {:binary, _, _}]}, {:ok, acc} ->
        if env_expr?(expr), do: {:cont, {:ok, [Atom.to_string(env) | acc]}}, else: {:halt, :dynamic}

      {:"::", _,
       [
         {{:., _, [{:__aliases__, _, [{:__lit_atom__, "Kernel"}]}, {:__lit_atom__, "to_string"}]},
          _, [expr]},
         {{:__lit_atom__, "binary"}, _, _}
       ]},
      {:ok, acc} ->
        if env_expr?(expr), do: {:cont, {:ok, [Atom.to_string(env) | acc]}}, else: {:halt, :dynamic}

      _, _ ->
        {:halt, :dynamic}
    end)
    |> case do
      {:ok, chunks} -> {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}
      :dynamic -> :dynamic
    end
  end

  defp resolve_import_path(_other, _env), do: :dynamic

  defp env_expr?({{:__lit_atom__, "config_env"}, _, []}), do: true

  defp env_expr?(
         {{:., _, [{:__aliases__, _, [{:__lit_atom__, "Mix"}]}, {:__lit_atom__, "env"}]}, _, []}
       ),
       do: true

  defp env_expr?(_), do: false

  defp optional_import_guard?(
         {{:., _, [{:__aliases__, _, [{:__lit_atom__, mod}]}, {:__lit_atom__, fun}]}, _, _}
       )
       when (mod == "File" and fun in ["exists?", "regular?"]) or
              (mod == "Code" and fun in ["ensure_loaded?", "loaded?"]),
       do: true

  defp optional_import_guard?({op, _, [left, right]}) when op in [:and, :&&] do
    optional_import_guard?(left) or optional_import_guard?(right)
  end

  defp optional_import_guard?(_), do: false

  defp dynamic_adapter?(args) when is_list(args) do
    case args do
      [_app, {:__lit_atom__, key}, value | _] when key in @adapter_keys ->
        not literal_module?(value) or nested_dynamic_adapter?(value)

      _ ->
        Enum.any?(args, &nested_dynamic_adapter?/1)
    end
  end

  defp nested_dynamic_adapter?(list) when is_list(list) do
    Enum.any?(list, fn
      {{:__lit_atom__, key}, value} when key in @adapter_keys ->
        not literal_module?(value) or nested_dynamic_adapter?(value)

      {_key, value} ->
        nested_dynamic_adapter?(value)

      item ->
        nested_dynamic_adapter?(item)
    end)
  end

  defp nested_dynamic_adapter?({:%{}, _, pairs}) when is_list(pairs) do
    Enum.any?(pairs, fn
      {{:__lit_atom__, key}, value} when key in @adapter_keys ->
        not literal_module?(value) or nested_dynamic_adapter?(value)

      {:|, _, [base, updates]} ->
        nested_dynamic_adapter?(base) or nested_dynamic_adapter?(updates)

      {_key, value} ->
        nested_dynamic_adapter?(value)

      other ->
        nested_dynamic_adapter?(other)
    end)
  end

  defp nested_dynamic_adapter?({:%, _, [_struct, map]}), do: nested_dynamic_adapter?(map)

  defp nested_dynamic_adapter?({:__aliases__, _, _}), do: false
  defp nested_dynamic_adapter?({:__lit_atom__, _}), do: false

  defp nested_dynamic_adapter?({:{}, _, elements}) when is_list(elements),
    do: Enum.any?(elements, &nested_dynamic_adapter?/1)

  defp nested_dynamic_adapter?({_op, meta, args}) when is_list(meta) and is_list(args),
    do: Enum.any?(args, &nested_dynamic_adapter?/1)

  defp nested_dynamic_adapter?({left, right}),
    do: nested_dynamic_adapter?(left) or nested_dynamic_adapter?(right)

  defp nested_dynamic_adapter?(_), do: false

  defp literal_module?({:__aliases__, _, _} = node), do: Literal.alias_name(node) != nil
  defp literal_module?({:__lit_atom__, _}), do: true
  defp literal_module?({first, _opts}), do: literal_module?(first)
  defp literal_module?({:{}, _, [first | _]}), do: literal_module?(first)
  defp literal_module?(_), do: false

  defp normalize("Elixir." <> _ = name), do: name
  defp normalize(name) when is_binary(name), do: "Elixir." <> name
  defp normalize(name) when is_atom(name), do: Atom.to_string(name)

  defp display("Elixir." <> name), do: name
  defp display(name), do: name
end
