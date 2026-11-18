defmodule VulnCheck.Literal do
  @moduledoc """
  Safe reader for Elixir-syntax data files (`.vulncheck.exs`, `.vulncheck.ignore`,
  `mix.lock`, `mix.exs`, `config/*.exs`).

  Files are parsed with `Code.string_to_quoted/2` and a static atom encoder, so
  **no atoms are created** and **no code is ever evaluated**. Literal values are
  converted into a neutral term representation:

    * atoms become `{:atom, "name"}` (except `nil`, `true` and `false`)
    * module aliases become `{:alias, "Elixir.Mod.Name"}`
    * tuples become `{:tuple, [elements]}`
    * maps become `{:map, [{key, value}]}` (insertion order preserved)
    * strings, numbers and lists are kept as they are

  Any other expression (function calls, variables, operators, ...) is rejected
  with `{:error, {:unsafe_expression, line, code}}` by `to_term/1`.
  """

  @type lterm ::
          {:atom, String.t()}
          | {:alias, String.t()}
          | {:tuple, [lterm()]}
          | {:map, [{lterm(), lterm()}]}
          | [lterm()]
          | binary()
          | number()
          | boolean()
          | nil

  @doc """
  Parses source into an encoded AST without creating atoms.
  """
  @spec quote_string(String.t(), keyword()) :: {:ok, Macro.t()} | {:error, String.t()}
  def quote_string(source, opts \\ []) when is_binary(source) do
    file = Keyword.get(opts, :file, "nofile")

    encoder = fn name, _meta -> {:ok, {:__lit_atom__, name}} end

    case Code.string_to_quoted(source,
           static_atoms_encoder: encoder,
           emit_warnings: false,
           file: file,
           existing_atoms_only: false
         ) do
      {:ok, ast} ->
        {:ok, ast}

      {:error, {meta, message, token}} ->
        line = if is_list(meta), do: Keyword.get(meta, :line, 0), else: meta
        {:error, "#{file}:#{line}: syntax error: #{format_message(message)}#{token}"}
    end
  rescue
    error -> {:error, "#{Keyword.get(opts, :file, "nofile")}: #{Exception.message(error)}"}
  end

  @doc """
  Parses a source string and converts it into a literal term.
  """
  @spec parse(String.t(), keyword()) :: {:ok, lterm()} | {:error, term()}
  def parse(source, opts \\ []) do
    with {:ok, ast} <- quote_string(source, opts) do
      to_term(ast)
    end
  end

  @doc """
  Reads and parses a file into a literal term.
  """
  @spec parse_file(Path.t()) :: {:ok, lterm()} | {:error, term()}
  def parse_file(path) do
    case File.read(path) do
      {:ok, source} -> parse(source, file: path)
      {:error, reason} -> {:error, {:file_error, path, reason}}
    end
  end

  @doc """
  Converts an encoded AST into a literal term, rejecting any executable code.
  """
  @spec to_term(Macro.t()) :: {:ok, lterm()} | {:error, term()}
  def to_term(ast) do
    {:ok, convert!(ast)}
  catch
    {:unsafe, line, code} -> {:error, {:unsafe_expression, line, code}}
  end

  @doc """
  Returns `true` if the encoded AST node is the given atom literal.
  """
  @spec atom?(Macro.t(), String.t()) :: boolean()
  def atom?({:__lit_atom__, name}, name), do: true
  def atom?(_, _), do: false

  @doc """
  Returns the name of an encoded atom AST node, or `nil`.
  """
  @spec atom_name(Macro.t()) :: String.t() | nil
  def atom_name({:__lit_atom__, name}) when is_binary(name), do: name
  def atom_name(_), do: nil

  @doc """
  Converts an `__aliases__` AST node into its canonical module string, or `nil`.
  """
  @spec alias_name(Macro.t()) :: String.t() | nil
  def alias_name({:__aliases__, _meta, parts}) do
    names = Enum.map(parts, &atom_name/1)

    cond do
      Enum.any?(names, &is_nil/1) -> nil
      hd(names) == "Elixir" -> Enum.join(names, ".")
      true -> "Elixir." <> Enum.join(names, ".")
    end
  end

  def alias_name(_), do: nil

  @doc """
  Looks up a key in a keyword-like literal list (`[{{:atom, key}, value}]`).
  """
  @spec kw_get(lterm(), String.t(), term()) :: term()
  def kw_get(list, key, default \\ nil)

  def kw_get(list, key, default) when is_list(list) do
    Enum.find_value(list, default, fn
      {:tuple, [{:atom, ^key}, value]} -> {:found, value}
      _ -> nil
    end)
    |> case do
      {:found, value} -> value
      other -> other
    end
  end

  def kw_get({:map, pairs}, key, default) do
    Enum.find_value(pairs, default, fn
      {{:atom, ^key}, value} -> {:found, value}
      _ -> nil
    end)
    |> case do
      {:found, value} -> value
      other -> other
    end
  end

  def kw_get(_other, _key, default), do: default

  @doc """
  Converts a literal keyword list into `[{key_string, value}]`, or `:error`.
  """
  @spec keyword_pairs(lterm()) :: {:ok, [{String.t(), lterm()}]} | :error
  def keyword_pairs(list) when is_list(list) do
    Enum.reduce_while(list, {:ok, []}, fn
      {:tuple, [{:atom, key}, value]}, {:ok, acc} -> {:cont, {:ok, [{key, value} | acc]}}
      _, _ -> {:halt, :error}
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      :error -> :error
    end
  end

  def keyword_pairs(_), do: :error

  defp convert!({:__lit_atom__, name}) when is_binary(name), do: {:atom, name}
  defp convert!(value) when is_binary(value) or is_number(value), do: value
  defp convert!(value) when value in [nil, true, false], do: value
  defp convert!(list) when is_list(list), do: Enum.map(list, &convert!/1)
  defp convert!({left, right}), do: {:tuple, [convert!(left), convert!(right)]}
  defp convert!({:{}, _meta, elements}) when is_list(elements), do: {:tuple, convert!(elements)}

  defp convert!({:%{}, _meta, pairs}) when is_list(pairs) do
    {:map, Enum.map(pairs, &convert_pair!/1)}
  end

  defp convert!({:__aliases__, meta, _parts} = node) do
    case alias_name(node) do
      nil -> unsafe!(meta, node)
      name -> {:alias, name}
    end
  end

  defp convert!({:-, _meta, [value]}) when is_number(value), do: -value
  defp convert!({:+, _meta, [value]}) when is_number(value), do: value

  defp convert!({:<<>>, meta, parts} = node) when is_list(parts) do
    if Enum.all?(parts, &is_binary/1), do: IO.iodata_to_binary(parts), else: unsafe!(meta, node)
  end

  defp convert!({_head, meta, _args} = node) when is_list(meta), do: unsafe!(meta, node)
  defp convert!(other), do: unsafe!([], other)

  defp convert_pair!({key, value}), do: {convert!(key), convert!(value)}
  defp convert_pair!(other), do: unsafe!([], other)

  defp unsafe!(meta, node) do
    throw({:unsafe, Keyword.get(meta, :line, 0), describe(node)})
  end

  defp describe(node), do: node |> render() |> String.slice(0, 120)

  # Renders an encoded AST fragment for error messages without creating atoms.
  defp render({:__lit_atom__, name}), do: ":" <> name
  defp render({:__aliases__, _meta, parts}), do: Enum.map_join(parts, ".", &render_name/1)

  defp render({{:., _, [left, right]}, _meta, args}) when is_list(args) do
    render(left) <> "." <> render_name(right) <> "(" <> render_args(args) <> ")"
  end

  defp render({{:__lit_atom__, name}, _meta, args}) when is_list(args),
    do: name <> "(" <> render_args(args) <> ")"

  defp render({{:__lit_atom__, name}, _meta, context}) when is_atom(context), do: name

  defp render({op, _meta, args}) when is_atom(op) and is_list(args),
    do: Atom.to_string(op) <> "(" <> render_args(args) <> ")"

  defp render(list) when is_list(list), do: "[" <> render_args(list) <> "]"
  defp render({left, right}), do: "{" <> render(left) <> ", " <> render(right) <> "}"
  defp render(other), do: inspect(other, limit: 5)

  defp render_args(args), do: Enum.map_join(args, ", ", &render/1)

  defp render_name({:__lit_atom__, name}), do: name
  defp render_name(other), do: render(other)

  defp format_message({prefix, suffix}) when is_binary(prefix) and is_binary(suffix),
    do: prefix <> suffix

  defp format_message(message) when is_binary(message), do: message
  defp format_message(message), do: inspect(message)
end
