defmodule VulnCheck.Workspace.MixProject do
  @moduledoc """
  Static (non-evaluating) reader for `mix.exs` files.

  Extracts the application name, version, `apps_path` and the declared
  dependencies with their `only:`, `runtime:`, `optional:`, `path:` and
  `in_umbrella:` options. Dependency declarations built dynamically (for
  example with `if` or `++`) are still found because every literal dependency
  tuple inside the `deps` function body is collected.
  """

  alias VulnCheck.Literal

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
    functions = collect_functions(ast)
    project = project_keyword(functions)

    deps_fun = deps_function_name(project)

    {deps, parsed?} =
      case Map.get(functions, deps_fun) do
        nil ->
          inline = Enum.find_value(project, fn {key, value} -> key == "deps" && value end)

          if is_list(inline), do: {collect_deps(inline), true}, else: {[], deps_fun == nil}

        body ->
          {collect_deps(body), true}
      end

    %__MODULE__{
      file: file,
      app: project |> kw_value("app") |> atom_value(),
      version: project |> kw_value("version") |> string_value(functions),
      apps_path: project |> kw_value("apps_path") |> string_value(functions),
      deps: deps,
      deps_parsed: parsed?
    }
  end

  defp read(path) do
    case File.read(path) do
      {:ok, source} -> {:ok, source}
      {:error, reason} -> {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  # Collects `def name do body end` / `defp name, do: body` bodies by name
  # (zero-arity functions only, which is what Mix projects use).
  defp collect_functions(ast) do
    {_ast, acc} =
      Macro.prewalk(ast, %{}, fn
        {{:__lit_atom__, kind}, _meta, [head, body]} = node, acc when kind in ["def", "defp"] ->
          case {function_name(head), body_of(body)} do
            {name, body} when is_binary(name) and body != nil ->
              {node, Map.put_new(acc, name, body)}

            _ ->
              {node, acc}
          end

        {:@, _meta, [{{:__lit_atom__, name}, _, [value]}]} = node, acc ->
          {node, Map.put_new(acc, "@" <> name, value)}

        node, acc ->
          {node, acc}
      end)

    acc
  end

  defp function_name({{:__lit_atom__, name}, _meta, args}) when args in [nil, []] or is_atom(args),
    do: name

  defp function_name(_), do: nil

  defp body_of(body) when is_list(body) do
    Enum.find_value(body, fn
      {{:__lit_atom__, "do"}, value} -> value
      {:do, value} -> value
      _ -> nil
    end)
  end

  defp body_of(_), do: nil

  defp project_keyword(functions) do
    case Map.get(functions, "project") do
      list when is_list(list) -> keyword_entries(list)
      _ -> []
    end
  end

  defp keyword_entries(list) do
    for {{:__lit_atom__, key}, value} <- list, do: {key, value}
  end

  defp kw_value(entries, key) do
    case List.keyfind(entries, key, 0) do
      {^key, value} -> value
      nil -> nil
    end
  end

  defp deps_function_name(project) do
    case kw_value(project, "deps") do
      {{:__lit_atom__, name}, _meta, args} when args in [nil, []] or is_atom(args) -> name
      list when is_list(list) -> nil
      nil -> "deps"
      _ -> "deps"
    end
  end

  defp atom_value({:__lit_atom__, name}), do: name
  defp atom_value(_), do: nil

  defp string_value(value, _functions) when is_binary(value), do: value

  defp string_value({:@, _meta, [{{:__lit_atom__, name}, _, _}]}, functions) do
    case Map.get(functions, "@" <> name) do
      value when is_binary(value) -> value
      _ -> nil
    end
  end

  defp string_value(_value, _functions), do: nil

  # -- dependency collection ---------------------------------------------------

  defp collect_deps(node) do
    case dep_tuple(node) do
      {:ok, dep} ->
        [dep]

      :error ->
        children(node) |> Enum.flat_map(&collect_deps/1)
    end
  end

  defp children(list) when is_list(list), do: list
  defp children({:__lit_atom__, _}), do: []
  defp children({left, right}), do: [left, right]
  defp children({_head, _meta, args}) when is_list(args), do: args
  defp children(_), do: []

  defp dep_tuple({{:__lit_atom__, name}, second}) do
    cond do
      is_binary(second) -> {:ok, build_dep(name, second, [])}
      keyword?(second) -> {:ok, build_dep(name, nil, second)}
      true -> :error
    end
  end

  defp dep_tuple({:{}, _meta, [{:__lit_atom__, name}, requirement, opts]})
       when is_binary(requirement) do
    if keyword?(opts), do: {:ok, build_dep(name, requirement, opts)}, else: :error
  end

  defp dep_tuple(_), do: :error

  defp keyword?(list) when is_list(list) and list != [] do
    Enum.all?(list, &match?({{:__lit_atom__, _}, _}, &1))
  end

  defp keyword?(_), do: false

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

  defp only_value(list) when is_list(list) do
    envs = for {:__lit_atom__, env} <- list, do: env
    # A partially dynamic list cannot be trusted to exclude :prod.
    if length(envs) == length(list), do: envs, else: :all
  end

  # Dynamic expressions (e.g. `only: Mix.env()`) are treated as "all envs".
  defp only_value(_dynamic), do: :all
end
