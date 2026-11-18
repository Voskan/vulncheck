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
  alias VulnCheck.Types.{ModuleSummary, Package, Workspace}

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

  @type result :: %{
          configured: %{atom() => [String.t()]},
          inactive: %{String.t() => String.t()},
          config_refs: [String.t()],
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
    {config_refs, dynamic?, notes} = read_config_files(workspace)

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

    present = workspace.packages |> Map.values() |> Enum.filter(&(&1.scope != :non_prod))
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
  mentioned in them, whether an adapter key had a non-literal value, and
  notes about unreadable files.
  """
  @spec read_config_files(Workspace.t()) :: {[String.t()], boolean(), [String.t()]}
  def read_config_files(%Workspace{root_dir: root, env: env}) do
    ["config.exs", "#{env}.exs", "runtime.exs"]
    |> Enum.uniq()
    |> Enum.map(&Path.join([root, "config", &1]))
    |> Enum.filter(&File.regular?/1)
    |> Enum.reduce({[], false, []}, fn path, {refs, dynamic?, notes} ->
      with {:ok, source} <- File.read(path),
           {:ok, ast} <- Literal.quote_string(source, file: path) do
        {file_refs, file_dynamic?} = scan(ast)
        {refs ++ file_refs, dynamic? or file_dynamic?, notes}
      else
        _ ->
          {refs, true, notes ++ ["could not parse #{Path.relative_to(path, root)}; adapters kept"]}
      end
    end)
  end

  defp scan(ast) do
    {_, {refs, dynamic?}} =
      Macro.prewalk(ast, {[], false}, fn
        {:__aliases__, _, _} = node, {refs, dynamic?} ->
          case Literal.alias_name(node) do
            nil -> {node, {refs, dynamic?}}
            name -> {node, {[name | refs], dynamic?}}
          end

        {{:__lit_atom__, "config"}, _, args} = node, {refs, dynamic?} when is_list(args) ->
          {node, {refs, dynamic? or dynamic_adapter?(args)}}

        node, acc ->
          {node, acc}
      end)

    {Enum.reverse(refs), dynamic?}
  end

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
