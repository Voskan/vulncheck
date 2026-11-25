defmodule VulnCheck.ErlTerm do
  @moduledoc """
  Atom-safe reader for Erlang term files such as `.app`, `.app.src`,
  `rebar.lock` and `rebar.config`.

  `:file.consult/1` would intern every atom found in third-party files. This
  reader instead produces the same neutral representation as
  `VulnCheck.Literal`:

    * atoms become `{:atom, "name"}`
    * tuples become `{:tuple, [elements]}`
    * maps become `{:map, [{key, value}]}`
    * strings (`"..."`) and binaries (`<<"...">>`) become Elixir binaries
    * numbers and lists are kept as they are

  Only data terms are supported; funs, records with expressions and macros
  are rejected with `{:error, reason}`.
  """

  @type term_t ::
          {:atom, String.t()}
          | {:tuple, [term_t()]}
          | {:map, [{term_t(), term_t()}]}
          | [term_t()]
          | binary()
          | number()

  @doc """
  Parses all dot-terminated terms contained in `source`.
  """
  @spec parse(binary()) :: {:ok, [term_t()]} | {:error, String.t()}
  def parse(source) when is_binary(source) do
    {:ok, parse_terms(source, [])}
  catch
    {:parse_error, message} -> {:error, message}
  end

  @doc """
  Reads and parses a file of dot-terminated Erlang terms.
  """
  @spec parse_file(Path.t()) :: {:ok, [term_t()]} | {:error, String.t()}
  def parse_file(path) do
    case File.read(path) do
      {:ok, source} ->
        case parse(source) do
          {:ok, terms} -> {:ok, terms}
          {:error, message} -> {:error, "#{path}: #{message}"}
        end

      {:error, reason} ->
        {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  @doc """
  Looks up `key` in a proplist of `{:tuple, [{:atom, key}, value]}` entries.
  """
  @spec proplist_get([term_t()] | term_t(), String.t(), term()) :: term()
  def proplist_get(list, key, default \\ nil)

  def proplist_get(list, key, default) when is_list(list) do
    case Enum.find(list, &match?({:tuple, [{:atom, ^key}, _value]}, &1)) do
      {:tuple, [_key, value]} -> value
      nil -> default
    end
  end

  def proplist_get(_other, _key, default), do: default

  @doc "Extracts atom names from a list of atom terms, ignoring other terms."
  @spec atom_names(term()) :: [String.t()]
  def atom_names(list) when is_list(list) do
    for {:atom, name} <- list, do: name
  end

  def atom_names(_), do: []

  # -- parser ------------------------------------------------------------------

  @max_depth 128

  defp parse_terms(source, acc) do
    rest = skip_ws(source)

    if rest == "" do
      Enum.reverse(acc)
    else
      {term, rest} = parse_value(rest, 0)

      case skip_ws(rest) do
        "." <> rest -> parse_terms(rest, [term | acc])
        _ -> fail("expected '.' after term")
      end
    end
  end

  defp parse_value(_source, depth) when depth > @max_depth,
    do: fail("maximum nesting depth exceeded")

  defp parse_value(source, depth) do
    case skip_ws(source) do
      "{" <> rest -> parse_seq(rest, "}", fn items -> {:tuple, items} end, depth + 1)
      "[" <> rest -> parse_list(rest, depth + 1)
      "\#{" <> rest -> parse_map(rest, depth + 1)
      "<<" <> rest -> parse_binary(rest)
      "\"" <> rest -> parse_string(rest, [])
      "'" <> rest -> parse_quoted_atom(rest, [])
      "$" <> rest -> parse_char(rest)
      "-" <> rest -> parse_negative(rest, depth + 1)
      "+" <> rest -> parse_positive(rest, depth + 1)
      <<c, _::binary>> = rest when c in ?0..?9 -> parse_number(rest)
      <<c, _::binary>> = rest when c in ?a..?z -> parse_atom(rest)
      "" -> fail("unexpected end of input")
      <<c, _::binary>> -> fail("unexpected character #{inspect(<<c>>)}")
    end
  end

  defp parse_seq(source, close, wrap, depth) do
    case skip_ws(source) do
      ^close <> rest ->
        {wrap.([]), rest}

      _ ->
        {items, rest} = parse_items(source, close, [], depth)
        {wrap.(items), rest}
    end
  end

  defp parse_items(source, close, acc, depth) do
    {value, rest} = parse_value(source, depth)

    case skip_ws(rest) do
      "," <> rest ->
        parse_items(rest, close, [value | acc], depth)

      rest ->
        if String.starts_with?(rest, close) do
          {Enum.reverse([value | acc]), binary_part(rest, 1, byte_size(rest) - 1)}
        else
          fail("expected ',' or '#{close}'")
        end
    end
  end

  defp parse_list(source, depth) do
    case skip_ws(source) do
      "]" <> rest ->
        {[], rest}

      _ ->
        parse_list_items(source, [], depth)
    end
  end

  defp parse_list_items(source, acc, depth) do
    {value, rest} = parse_value(source, depth)

    case skip_ws(rest) do
      "," <> rest ->
        parse_list_items(rest, [value | acc], depth)

      "]" <> rest ->
        {Enum.reverse([value | acc]), rest}

      "|" <> rest ->
        {tail, rest} = parse_value(rest, depth)

        case skip_ws(rest) do
          "]" <> rest when is_list(tail) -> {Enum.reverse([value | acc]) ++ tail, rest}
          _ -> fail("improper list")
        end

      _ ->
        fail("expected ',' or ']'")
    end
  end

  defp parse_map(source, depth) do
    case skip_ws(source) do
      "}" <> rest -> {{:map, []}, rest}
      _ -> parse_map_items(source, [], depth)
    end
  end

  defp parse_map_items(source, acc, depth) do
    {key, rest} = parse_value(source, depth)

    rest =
      case skip_ws(rest) do
        "=>" <> rest -> rest
        _ -> fail("expected '=>' in map")
      end

    {value, rest} = parse_value(rest, depth)

    case skip_ws(rest) do
      "," <> rest -> parse_map_items(rest, [{key, value} | acc], depth)
      "}" <> rest -> {{:map, Enum.reverse([{key, value} | acc])}, rest}
      _ -> fail("expected ',' or '}' in map")
    end
  end

  defp parse_binary(source) do
    case skip_ws(source) do
      ">>" <> rest ->
        {"", rest}

      _ ->
        {segments, rest} = parse_binary_segments(source, [])
        {IO.iodata_to_binary(segments), rest}
    end
  end

  defp parse_binary_segments(source, acc) do
    {segment, rest} =
      case skip_ws(source) do
        "\"" <> rest ->
          parse_string(rest, [])

        <<c, _::binary>> = rest when c in ?0..?9 ->
          {int, rest} = parse_number(rest)
          if is_integer(int) and int in 0..255, do: {<<int>>, rest}, else: fail("bad byte")

        _ ->
          fail("unsupported binary segment")
      end

    rest = skip_segment_type(skip_ws(rest))

    case skip_ws(rest) do
      "," <> rest -> parse_binary_segments(rest, [segment | acc])
      ">>" <> rest -> {Enum.reverse([segment | acc]), rest}
      _ -> fail("expected ',' or '>>' in binary")
    end
  end

  defp skip_segment_type(rest) do
    rest =
      case rest do
        ":" <> after_colon ->
          {size, rem} = take_while(skip_ws(after_colon), &(&1 in ?0..?9 or &1 == ?_))
          if size == "", do: fail("expected binary segment size"), else: skip_ws(rem)

        other ->
          other
      end

    case rest do
      "/" <> after_slash ->
        {spec, rem} =
          take_while(after_slash, fn c ->
            c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?-, ?_, ?:]
          end)

        if spec == "", do: fail("expected binary segment type"), else: rem

      other ->
        other
    end
  end

  defp parse_string(<<"\"", rest::binary>>, acc) do
    {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}
  end

  defp parse_string(<<"\\", rest::binary>>, acc) do
    {char, rest} = parse_escape(rest)
    parse_string(rest, [char | acc])
  end

  defp parse_string(<<c::utf8, rest::binary>>, acc), do: parse_string(rest, [<<c::utf8>> | acc])
  defp parse_string(<<c, rest::binary>>, acc), do: parse_string(rest, [<<c>> | acc])
  defp parse_string("", _acc), do: fail("unterminated string")

  defp parse_quoted_atom(<<"'", rest::binary>>, acc) do
    {{:atom, acc |> Enum.reverse() |> IO.iodata_to_binary()}, rest}
  end

  defp parse_quoted_atom(<<"\\", rest::binary>>, acc) do
    {char, rest} = parse_escape(rest)
    parse_quoted_atom(rest, [char | acc])
  end

  defp parse_quoted_atom(<<c::utf8, rest::binary>>, acc),
    do: parse_quoted_atom(rest, [<<c::utf8>> | acc])

  defp parse_quoted_atom(<<_invalid, _rest::binary>>, _acc),
    do: fail("invalid utf-8 in quoted atom")

  defp parse_quoted_atom("", _acc), do: fail("unterminated quoted atom")

  defp parse_escape(<<"n", rest::binary>>), do: {"\n", rest}
  defp parse_escape(<<"t", rest::binary>>), do: {"\t", rest}
  defp parse_escape(<<"r", rest::binary>>), do: {"\r", rest}
  defp parse_escape(<<"s", rest::binary>>), do: {" ", rest}
  defp parse_escape(<<"e", rest::binary>>), do: {<<27>>, rest}
  defp parse_escape(<<"b", rest::binary>>), do: {<<8>>, rest}
  defp parse_escape(<<"d", rest::binary>>), do: {<<127>>, rest}
  defp parse_escape(<<"f", rest::binary>>), do: {<<12>>, rest}
  defp parse_escape(<<"v", rest::binary>>), do: {<<11>>, rest}

  defp parse_escape(<<"x{", rest::binary>>) do
    {hex, after_hex} = take_while(rest, &hex_digit?/1)

    case after_hex do
      "}" <> rem when hex != "" ->
        {decode_codepoint!(hex, 16), rem}

      _ ->
        fail("invalid hex escape")
    end
  end

  defp parse_escape(<<"x", a, b, rest::binary>>) do
    if hex_digit?(a) and hex_digit?(b) do
      {decode_codepoint!(<<a, b>>, 16), rest}
    else
      fail("invalid hex escape")
    end
  end

  defp parse_escape(<<"x", _::binary>>), do: fail("invalid hex escape")

  defp parse_escape(<<c, _::binary>> = rest) when c in ?0..?7 do
    {oct, rem} = take_octal(rest, 3, [])
    {decode_codepoint!(oct, 8), rem}
  end

  defp parse_escape(<<c::utf8, rest::binary>>), do: {<<c::utf8>>, rest}
  defp parse_escape(<<_invalid, _rest::binary>>), do: fail("invalid utf-8 in escape sequence")
  defp parse_escape(""), do: fail("unterminated escape")

  defp hex_digit?(c), do: c in ?0..?9 or c in ?a..?f or c in ?A..?F

  defp take_octal(<<c, rest::binary>>, max, acc) when max > 0 and c in ?0..?7,
    do: take_octal(rest, max - 1, [c | acc])

  defp take_octal(rest, _max, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}

  defp decode_codepoint!(digits, base) do
    case Integer.parse(digits, base) do
      {cp, ""} when cp in 0..0x10FFFF and cp not in 0xD800..0xDFFF -> <<cp::utf8>>
      _ -> fail("invalid character codepoint")
    end
  end

  defp parse_char(<<"\\", rest::binary>>) do
    case parse_escape(rest) do
      {<<c::utf8>>, rest} -> {c, rest}
      _ -> fail("invalid character escape")
    end
  end

  defp parse_char(<<c::utf8, rest::binary>>), do: {c, rest}
  defp parse_char(<<_invalid, _rest::binary>>), do: fail("invalid utf-8 in character literal")
  defp parse_char(""), do: fail("unterminated character literal")

  defp parse_negative(source, depth) do
    case parse_value(source, depth) do
      {n, rest} when is_number(n) -> {-n, rest}
      _ -> fail("unexpected '-'")
    end
  end

  defp parse_positive(source, depth) do
    case parse_value(source, depth) do
      {n, rest} when is_number(n) -> {n, rest}
      _ -> fail("unexpected '+'")
    end
  end

  defp parse_number(source) do
    {digits, rest} = take_while(source, &(&1 in ?0..?9 or &1 == ?_))
    digits = String.replace(digits, "_", "")

    case rest do
      "#" <> rest ->
        base =
          if digits != "" and byte_size(digits) <= 10 do
            case Integer.parse(digits) do
              {n, ""} when n in 2..36 -> n
              _ -> fail("invalid integer base")
            end
          else
            fail("invalid integer base")
          end

        {chars, rest} =
          take_while(rest, &(&1 in ?0..?9 or &1 in ?a..?z or &1 in ?A..?Z or &1 == ?_))

        chars = String.replace(chars, "_", "")

        case Integer.parse(chars, base) do
          {int, ""} -> {int, rest}
          _ -> fail("invalid based integer")
        end

      <<".", d, _::binary>> when d in ?0..?9 ->
        <<".", rest::binary>> = rest

        {frac, rest} =
          take_while(rest, &(&1 in ?0..?9 or &1 in [?e, ?E, ?-, ?+, ?_]))

        frac = String.replace(frac, "_", "")

        case Float.parse(digits <> "." <> frac) do
          {float, ""} -> {float, rest}
          _ -> fail("invalid float")
        end

      _ ->
        case Integer.parse(digits) do
          {int, ""} -> {int, rest}
          _ -> fail("invalid integer")
        end
    end
  end

  defp parse_atom(source) do
    {name, rest} =
      take_while(source, fn c ->
        c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?_, ?@]
      end)

    {{:atom, name}, rest}
  end

  defp take_while(source, fun), do: take_while(source, fun, 0)

  defp take_while(source, fun, n) do
    if n < byte_size(source) and fun.(:binary.at(source, n)) do
      take_while(source, fun, n + 1)
    else
      {binary_part(source, 0, n), binary_part(source, n, byte_size(source) - n)}
    end
  end

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)

  defp skip_ws(<<"%", rest::binary>>) do
    case :binary.split(rest, "\n") do
      [_comment, rest] -> skip_ws(rest)
      [_comment] -> ""
    end
  end

  defp skip_ws(rest), do: rest

  @spec fail(String.t()) :: no_return()
  defp fail(message), do: throw({:parse_error, message})
end
