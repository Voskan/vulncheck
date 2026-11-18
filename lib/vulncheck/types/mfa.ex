defmodule VulnCheck.Types.MFA do
  @moduledoc """
  A `Module.function/arity` reference stored entirely as strings.

  Advisory feeds and third-party `.beam` files mention thousands of module and
  function names. Converting them to atoms would let untrusted input exhaust the
  BEAM atom table, so every symbol handled by the analyzer is kept as a canonical
  string:

    * Elixir modules keep their BEAM name, e.g. `"Elixir.Plug.Conn.Query"`.
    * Erlang modules keep their plain name, e.g. `"cow_http_hd"`.

  Atoms that already exist (for example those read from compiled `.beam` chunks)
  are converted with `Atom.to_string/1`, which never creates new atoms.
  """

  @enforce_keys [:module, :function, :arity]
  defstruct [:module, :function, :arity]

  @type t :: %__MODULE__{
          module: String.t(),
          function: String.t(),
          arity: non_neg_integer()
        }

  @doc """
  Builds an MFA from a module (atom or string), function (atom or string) and arity.
  """
  @spec new(atom() | String.t(), atom() | String.t(), non_neg_integer()) :: t()
  def new(module, function, arity) when is_integer(arity) and arity >= 0 do
    %__MODULE__{
      module: normalize_module(module),
      function: normalize_function(function),
      arity: arity
    }
  end

  @doc """
  Parses a routine string as published in EEF CNA `programRoutines`, GHSA
  advisories or written by humans.

  Supported notations:

    * `'Elixir.Plug.Conn.Query':decode/4`
    * `hex_http_httpc:http_options/2` and `'cow_http_hd':parse/1`
    * `Ash.Actions.Aggregate.run/4`
    * `:cow_http_hd.parse/1`

  Returns `:error` when the string has no explicit arity or is malformed.
  No atoms are created.

      iex> VulnCheck.Types.MFA.parse_routine("'Elixir.Plug.Conn.Query':decode/4")
      {:ok, %VulnCheck.Types.MFA{module: "Elixir.Plug.Conn.Query", function: "decode", arity: 4}}

      iex> VulnCheck.Types.MFA.parse_routine("Ash.read")
      :error
  """
  @spec parse_routine(binary()) :: {:ok, t()} | :error
  def parse_routine(routine) when is_binary(routine) do
    routine = routine |> String.trim() |> String.trim("`")

    with {:ok, head, arity} <- split_arity(routine),
         {:ok, module, function} <- split_module_function(head),
         true <- valid_module?(module) and valid_function?(function) do
      {:ok, %__MODULE__{module: normalize_module(module), function: function, arity: arity}}
    else
      _ -> :error
    end
  end

  def parse_routine(_other), do: :error

  @doc """
  Normalizes a module name to its canonical BEAM string.

      iex> VulnCheck.Types.MFA.normalize_module("Plug.Conn")
      "Elixir.Plug.Conn"

      iex> VulnCheck.Types.MFA.normalize_module("'cow_http_hd'")
      "cow_http_hd"

      iex> VulnCheck.Types.MFA.normalize_module(:"Elixir.Plug.Conn")
      "Elixir.Plug.Conn"
  """
  @spec normalize_module(binary() | atom()) :: String.t()
  def normalize_module(module) when is_atom(module), do: Atom.to_string(module)

  def normalize_module(module) when is_binary(module) do
    name =
      module
      |> String.trim()
      |> unquote_name()
      |> String.trim_leading(":")
      |> unquote_name()

    cond do
      String.starts_with?(name, "Elixir.") -> name
      elixir_alias?(name) -> "Elixir." <> name
      true -> name
    end
  end

  @doc """
  Formats an MFA for humans: `Plug.Conn.Query.decode/4` or `:cow_http_hd.parse/1`.
  """
  @spec format(t()) :: String.t()
  def format(%__MODULE__{module: module, function: function, arity: arity}) do
    display_module(module) <> "." <> function <> "/" <> Integer.to_string(arity)
  end

  @doc """
  Formats a canonical module name for display (`"Plug.Conn"` or `":cowlib"`).
  """
  @spec display_module(String.t()) :: String.t()
  def display_module("Elixir." <> rest), do: rest
  def display_module(module) when is_binary(module), do: ":" <> module

  @doc """
  Returns `true` when the canonical module name belongs to an Elixir module.
  """
  @spec elixir_module?(String.t()) :: boolean()
  def elixir_module?("Elixir." <> _), do: true
  def elixir_module?(_), do: false

  @doc """
  Converts an MFA to a `{module, function, arity}` tuple of strings.
  """
  @spec to_tuple(t()) :: {String.t(), String.t(), non_neg_integer()}
  def to_tuple(%__MODULE__{module: m, function: f, arity: a}), do: {m, f, a}

  @doc """
  Orders two MFAs deterministically (module, function, arity).
  """
  @spec compare(t(), t()) :: :lt | :eq | :gt
  def compare(%__MODULE__{} = a, %__MODULE__{} = b) do
    ta = to_tuple(a)
    tb = to_tuple(b)

    cond do
      ta < tb -> :lt
      ta > tb -> :gt
      true -> :eq
    end
  end

  defp normalize_function(function) when is_atom(function), do: Atom.to_string(function)
  defp normalize_function(function) when is_binary(function), do: unquote_name(function)

  defp split_arity(routine) do
    case :binary.matches(routine, "/") do
      [] ->
        :error

      matches ->
        {pos, _} = List.last(matches)
        head = binary_part(routine, 0, pos)
        tail = binary_part(routine, pos + 1, byte_size(routine) - pos - 1)

        case Integer.parse(tail) do
          {arity, ""} when arity >= 0 and arity <= 255 -> {:ok, head, arity}
          _ -> :error
        end
    end
  end

  # Erlang notation: 'Mod':fun, mod:fun, 'Mod':'fun'
  # Elixir notation: Mod.Sub.fun, :erl_mod.fun
  defp split_module_function("'" <> _ = head) do
    case Regex.run(~r/\A'([^']+)':(.+)\z/, head) do
      [_, module, function] -> {:ok, module, unquote_name(function)}
      _ -> :error
    end
  end

  defp split_module_function(":" <> rest) do
    case Regex.run(~r/\A([a-z][A-Za-z0-9_@]*)\.(.+)\z/, rest) do
      [_, module, function] -> {:ok, module, unquote_name(function)}
      _ -> erlang_colon_split(":" <> rest)
    end
  end

  defp split_module_function(head) do
    cond do
      String.contains?(head, ":") -> erlang_colon_split(head)
      String.contains?(head, ".") -> elixir_dot_split(head)
      true -> :error
    end
  end

  defp erlang_colon_split(head) do
    case String.split(head, ":", parts: 2) do
      [module, function] when module != "" and function != "" ->
        {:ok, unquote_name(module), unquote_name(function)}

      _ ->
        :error
    end
  end

  defp elixir_dot_split(head) do
    parts = String.split(head, ".")
    {module_parts, [function]} = Enum.split(parts, -1)

    if module_parts == [] or function == "" do
      :error
    else
      {:ok, Enum.join(module_parts, "."), function}
    end
  end

  defp unquote_name("'" <> rest) do
    if String.ends_with?(rest, "'") and byte_size(rest) > 1 do
      binary_part(rest, 0, byte_size(rest) - 1)
    else
      "'" <> rest
    end
  end

  defp unquote_name(name), do: name

  defp elixir_alias?(<<first, _::binary>>) when first in ?A..?Z, do: true
  defp elixir_alias?(_), do: false

  defp valid_module?(module) do
    name = normalize_module(module)
    name != "" and Regex.match?(~r/\A[A-Za-z0-9_.@]+\z/, name)
  end

  defp valid_function?(function) do
    function != "" and Regex.match?(~r/\A[A-Za-z_][A-Za-z0-9_@]*[?!]?\z/u, function)
  end
end
