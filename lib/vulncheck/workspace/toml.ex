defmodule VulnCheck.Workspace.Toml do
  @moduledoc """
  A small TOML reader covering the subset used by `gleam.toml` and Gleam's
  `manifest.toml`: tables, arrays of tables, inline tables, arrays (possibly
  spanning several lines), basic/literal strings, integers, floats and
  booleans. Keys are kept as strings.
  """

  @doc """
  Parses TOML source into a map with string keys.
  """
  @spec parse(String.t()) :: {:ok, map()} | {:error, String.t()}
  def parse(source) when is_binary(source) do
    {:ok, parse_lines(source, %{}, [])}
  catch
    {:toml_error, message} -> {:error, message}
  end

  @doc "Reads and parses a TOML file."
  @spec parse_file(Path.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_file(path) do
    case File.read(path) do
      {:ok, source} ->
        case parse(source) do
          {:ok, map} -> {:ok, map}
          {:error, message} -> {:error, "#{path}: #{message}"}
        end

      {:error, reason} ->
        {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  # `path` is the current table path; arrays of tables are addressed by
  # appending to the list stored under the last key.
  defp parse_lines(source, doc, path) do
    rest = skip_ws_and_comments(source)

    cond do
      rest == "" ->
        doc

      String.starts_with?(rest, "[[") ->
        {keys, rest} = read_header_path(binary_part(rest, 2, byte_size(rest) - 2), "]]")
        doc = append_table(doc, keys)
        parse_lines(rest, doc, {:array, keys})

      String.starts_with?(rest, "[") ->
        {keys, rest} = read_header_path(binary_part(rest, 1, byte_size(rest) - 1), "]")
        doc = ensure_table(doc, keys)
        parse_lines(rest, doc, {:table, keys})

      true ->
        {keys, rest} = read_key_path(rest)
        rest = expect(skip_inline_ws(rest), "=")
        {value, rest} = parse_value(skip_inline_ws(rest))
        doc = put_value(doc, path, keys, value)
        parse_lines(rest, doc, path)
    end
  end

  defp read_header_path(source, close) do
    rest = skip_inline_ws(source)

    if String.starts_with?(rest, close) do
      fail("empty table header")
    end

    {keys, rest} = read_key_path(rest)
    rest = skip_inline_ws(rest)
    rest = expect(rest, close)
    {keys, rest}
  end

  defp read_key_path(source) do
    {first, rest} = read_key_segment(skip_inline_ws(source))
    read_key_path_rest(rest, [first])
  end

  defp read_key_path_rest(source, acc) do
    case skip_inline_ws(source) do
      "." <> rest ->
        {segment, rest} = read_key_segment(skip_inline_ws(rest))
        read_key_path_rest(rest, [segment | acc])

      rest ->
        {Enum.reverse(acc), rest}
    end
  end

  defp read_key_segment("\"" <> rest), do: read_basic_string(rest, [])
  defp read_key_segment("'" <> rest), do: read_literal_string(rest)

  defp read_key_segment(source) do
    {key, rest} =
      take_while(source, fn c ->
        c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?_, ?-]
      end)

    if key == "", do: fail("expected key"), else: {key, rest}
  end

  defp parse_value(source) do
    case source do
      "\"\"\"" <> rest -> read_multiline(rest, "\"\"\"")
      "'''" <> rest -> read_multiline(rest, "'''")
      "\"" <> rest -> read_basic_string(rest, [])
      "'" <> rest -> read_literal_string(rest)
      "[" <> rest -> read_array(rest, [])
      "{" <> rest -> read_inline_table(rest, %{})
      _ -> read_scalar(source)
    end
  end

  defp read_basic_string(<<"\"", rest::binary>>, acc),
    do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp read_basic_string(<<"\\", c, rest::binary>>, acc) do
    char =
      case c do
        ?n -> "\n"
        ?t -> "\t"
        ?r -> "\r"
        ?" -> "\""
        ?\\ -> "\\"
        other -> <<?\\, other>>
      end

    read_basic_string(rest, [char | acc])
  end

  defp read_basic_string(<<"\n", _::binary>>, _acc), do: fail("newline in string")
  defp read_basic_string(<<c, rest::binary>>, acc), do: read_basic_string(rest, [<<c>> | acc])
  defp read_basic_string("", _acc), do: fail("unterminated string")

  defp read_literal_string(source) do
    case :binary.split(source, "'") do
      [value, rest] -> {value, rest}
      _ -> fail("unterminated literal string")
    end
  end

  defp read_multiline(source, delimiter) do
    case :binary.split(source, delimiter) do
      [value, rest] -> {String.trim_leading(value, "\n"), rest}
      _ -> fail("unterminated multi-line string")
    end
  end

  defp read_array(source, acc) do
    rest = skip_ws_and_comments(source)

    case rest do
      "]" <> rest ->
        {Enum.reverse(acc), rest}

      _ ->
        {value, rest} = parse_value(rest)
        rest = skip_ws_and_comments(rest)

        case rest do
          "," <> rest -> read_array(rest, [value | acc])
          "]" <> rest -> {Enum.reverse([value | acc]), rest}
          _ -> fail("expected ',' or ']' in array")
        end
    end
  end

  defp read_inline_table(source, acc) do
    rest = skip_inline_ws(source)

    case rest do
      "}" <> rest ->
        {acc, rest}

      _ ->
        {keys, rest} = read_key_path(rest)
        rest = expect(skip_inline_ws(rest), "=")
        {value, rest} = parse_value(skip_inline_ws(rest))
        acc = deep_put(acc, keys, value)

        case skip_inline_ws(rest) do
          "," <> rest -> read_inline_table(rest, acc)
          "}" <> rest -> {acc, rest}
          _ -> fail("expected ',' or '}' in inline table")
        end
    end
  end

  defp read_scalar(source) do
    {token, rest} =
      take_while(source, fn c -> c not in [?\s, ?\t, ?\n, ?\r, ?,, ?], ?}, ?#] end)

    value =
      cond do
        token == "true" ->
          true

        token == "false" ->
          false

        Regex.match?(~r/\A[+-]?\d[\d_]*\z/, token) ->
          token |> String.replace("_", "") |> String.to_integer()

        match?({_, ""}, Float.parse(token)) ->
          {float, ""} = Float.parse(token)
          float

        token != "" ->
          token

        true ->
          fail("expected value")
      end

    {value, rest}
  end

  defp put_value(doc, [], keys, value), do: deep_put(doc, keys, value)

  defp put_value(doc, {:table, path}, keys, value) do
    update_in_path(doc, path, fn
      nil -> deep_put(%{}, keys, value)
      map when is_map(map) -> deep_put(map, keys, value)
      _ -> fail("key #{Enum.join(path, ".")} is not a table")
    end)
  end

  defp put_value(doc, {:array, path}, keys, value) do
    update_in_path(doc, path, fn
      list when is_list(list) and list != [] ->
        List.update_at(list, -1, &deep_put(&1, keys, value))

      _ ->
        [deep_put(%{}, keys, value)]
    end)
  end

  defp append_table(doc, path) do
    update_in_path(doc, path, fn
      list when is_list(list) -> list ++ [%{}]
      nil -> [%{}]
      _ -> fail("key #{Enum.join(path, ".")} is not an array of tables")
    end)
  end

  defp ensure_table(doc, path) do
    update_in_path(doc, path, fn
      map when is_map(map) -> map
      nil -> %{}
      _ -> fail("key #{Enum.join(path, ".")} is not a table")
    end)
  end

  defp update_in_path(doc, [key], fun), do: Map.put(doc, key, fun.(Map.get(doc, key)))

  defp update_in_path(doc, [key | rest], fun) do
    child =
      case Map.get(doc, key) do
        nil -> %{}
        map when is_map(map) -> map
        list when is_list(list) and list != [] -> List.last(list)
        _ -> fail("key #{key} is not a table")
      end

    updated = update_in_path(child, rest, fun)

    case Map.get(doc, key) do
      list when is_list(list) and list != [] ->
        Map.put(doc, key, List.replace_at(list, -1, updated))

      _ ->
        Map.put(doc, key, updated)
    end
  end

  defp deep_put(map, [key], value), do: Map.put(map, key, value)

  defp deep_put(map, [key | rest], value) do
    child = Map.get(map, key, %{})
    child = if is_map(child), do: child, else: fail("key #{key} is not a table")
    Map.put(map, key, deep_put(child, rest, value))
  end

  defp expect(source, token) do
    if String.starts_with?(source, token) do
      binary_part(source, byte_size(token), byte_size(source) - byte_size(token))
    else
      fail("expected '#{token}'")
    end
  end

  defp take_while(source, fun), do: take_while(source, fun, 0)

  defp take_while(source, fun, n) do
    if n < byte_size(source) and fun.(:binary.at(source, n)) do
      take_while(source, fun, n + 1)
    else
      {binary_part(source, 0, n), binary_part(source, n, byte_size(source) - n)}
    end
  end

  defp skip_inline_ws(<<c, rest::binary>>) when c in [?\s, ?\t], do: skip_inline_ws(rest)
  defp skip_inline_ws(rest), do: rest

  defp skip_ws_and_comments(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r],
    do: skip_ws_and_comments(rest)

  defp skip_ws_and_comments(<<"#", rest::binary>>) do
    case :binary.split(rest, "\n") do
      [_comment, rest] -> skip_ws_and_comments(rest)
      [_comment] -> ""
    end
  end

  defp skip_ws_and_comments(rest), do: rest

  @spec fail(String.t()) :: no_return()
  defp fail(message), do: throw({:toml_error, message})
end
