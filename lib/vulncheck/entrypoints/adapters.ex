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
  @dynamic_fun_calls MapSet.new([
                       {"Elixir.Function", "capture"},
                       {"erlang", "make_fun"},
                       {"erlang", "binary_to_term"},
                       {"Elixir.Code", "eval_string"},
                       {"Elixir.Code", "eval_quoted"},
                       {"erl_eval", "exprs"},
                       {"erl_eval", "expr"}
                     ])

  @type result :: %{
          configured: %{atom() => [String.t()]},
          inactive: %{String.t() => String.t()},
          config_refs: [String.t()],
          config_sites: %{String.t() => {String.t(), non_neg_integer() | nil}},
          config_mfas: [{MFA.t(), String.t(), non_neg_integer() | nil}],
          untracked_fun_sources: boolean(),
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

  defp read_config_details(%Workspace{root_dir: root, env: env}) do
    initial = %{refs: [], mfas: [], dynamic?: false, untracked_fun_sources: false, notes: []}

    ["config.exs", "#{env}.exs", "runtime.exs"]
    |> Enum.uniq()
    |> Enum.map(&Path.join([root, "config", &1]))
    |> Enum.filter(&File.regular?/1)
    |> Enum.reduce(initial, fn path, acc ->
      relative = Path.relative_to(path, root)

      with {:ok, source} <- File.read(path),
           {:ok, ast} <- Literal.quote_string(source, file: path) do
        scanned = scan(ast)
        sites = Enum.map(scanned.refs, fn {name, line} -> {name, relative, line} end)
        mfas = Enum.map(scanned.mfas, fn {mfa, line} -> {mfa, relative, line} end)

        %{
          acc
          | refs: acc.refs ++ sites,
            mfas: acc.mfas ++ mfas,
            dynamic?: acc.dynamic? or scanned.dynamic?,
            untracked_fun_sources: acc.untracked_fun_sources or scanned.untracked_fun_sources
        }
      else
        _ ->
          %{
            acc
            | dynamic?: true,
              untracked_fun_sources: true,
              notes: acc.notes ++ ["could not parse #{relative}; adapters kept"]
          }
      end
    end)
  end

  defp scan(ast) do
    acc = %{refs: [], mfas: [], dynamic?: false, untracked_fun_sources: false}
    acc = scan_node(ast, nil, acc)

    %{
      refs: Enum.reverse(acc.refs),
      mfas: acc.mfas |> Enum.reverse() |> Enum.uniq_by(&elem(&1, 0)),
      dynamic?: acc.dynamic?,
      untracked_fun_sources: acc.untracked_fun_sources
    }
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
    untracked? = MapSet.member?(@dynamic_fun_calls, {mod, fun})
    acc = %{acc | untracked_fun_sources: acc.untracked_fun_sources or untracked?}

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

  # Local function/macro call: do not treat call head as a module reference.
  defp scan_node({{:__lit_atom__, _fun}, meta, args}, line, acc) when is_list(args) do
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

  defp dynamic_adapter?(args) do
    pairs =
      case args do
        [_app, {:__lit_atom__, key}, value] when key in @adapter_keys -> [{key, value}]
        _ -> args |> List.last() |> keyword_pairs()
      end

    Enum.any?(pairs, fn {key, value} -> key in @adapter_keys and not literal_module?(value) end)
  end

  defp keyword_pairs(list) when is_list(list) do
    for {{:__lit_atom__, key}, value} <- list, do: {key, value}
  end

  defp keyword_pairs(_), do: []

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
