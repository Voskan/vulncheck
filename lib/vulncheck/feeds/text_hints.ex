defmodule VulnCheck.Feeds.TextHints do
  @moduledoc """
  Conservative extraction of machine-usable hints from advisory prose.

    * `symbols/1` only accepts explicit, backtick-quoted signatures with an
      arity (`` `Plug.CSRFProtection.valid_state_and_csrf_token?/2` `` or
      `` `hex_http_httpc:http_options/2` ``). Names without an arity are never
      guessed.
    * `otp_constraint/1` recognizes a small set of unambiguous phrasings that
      restrict a vulnerability to specific Erlang/OTP releases, and only in
      sentences that talk about what is affected.
  """

  alias VulnCheck.Types.MFA

  @doc """
  Extracts backtick-quoted `Module.function/arity` signatures.

      iex> VulnCheck.Feeds.TextHints.symbols("Calling `Plug.Conn.Query.decode/4` is slow, unlike `decode`.")
      [%VulnCheck.Types.MFA{module: "Elixir.Plug.Conn.Query", function: "decode", arity: 4}]
  """
  @spec symbols(String.t() | nil) :: [MFA.t()]
  def symbols(nil), do: []

  def symbols(text) when is_binary(text) do
    ~r/`([^`\s]+\/\d{1,3})`/
    |> Regex.scan(text, capture: :all_but_first)
    |> Enum.flat_map(fn [candidate] ->
      if Regex.match?(
           ~r/\A(:?'?[A-Za-z][A-Za-z0-9_.@]*'?[.:])+'?[a-z_][A-Za-z0-9_@]*[?!]?'?\/\d+\z/,
           candidate
         ) do
        case MFA.parse_routine(candidate) do
          {:ok, mfa} -> [mfa]
          :error -> []
        end
      else
        []
      end
    end)
    |> Enum.uniq()
  end

  @doc """
  Extracts an OTP runtime constraint (for `VulnCheck.Semver.otp_affected?/2`)
  from advisory prose, or `nil`.

      iex> VulnCheck.Feeds.TextHints.otp_constraint("This only affects OTP 24 and 25, where verify_none was the default.")
      "24 || 25"
      iex> VulnCheck.Feeds.TextHints.otp_constraint("Applications running on OTP 25 and earlier are vulnerable.")
      "<= 25"
      iex> VulnCheck.Feeds.TextHints.otp_constraint("Tested on OTP 26 and 27.")
      nil
  """
  @spec otp_constraint(String.t() | nil) :: String.t() | nil
  def otp_constraint(nil), do: nil

  def otp_constraint(text) when is_binary(text) do
    text
    |> String.split(~r/(?<=[.;!?])\s+|\n+/)
    |> Enum.filter(
      &Regex.match?(~r/\b(affect|vulnerab|only (on|when|with)|running on|exploitable)/i, &1)
    )
    |> Enum.find_value(&sentence_constraint/1)
  end

  defp sentence_constraint(sentence) do
    otp = ~S"(?:Erlang\/)?OTP[ -]?"

    cond do
      match =
          Regex.run(
            ~r/#{otp}(\d+)((?:\s*(?:,|and|or|&)\s*(?:#{otp})?\d+)+)(?!\s*(?:and|or)\s+(?:later|newer|above|higher))(?!\.\d)/i,
            sentence
          ) ->
        [_, first, rest] = match
        numbers = [first | Regex.scan(~r/\d+/, rest) |> List.flatten()]
        Enum.join(numbers, " || ")

      match =
          Regex.run(~r/#{otp}(\d+)\s+(?:and|or)\s+(?:earlier|older|below|lower|prior)/i, sentence) ->
        [_, n] = match
        "<= #{n}"

      match =
          Regex.run(~r/(?:before|prior to|older than|below|lower than)\s+#{otp}(\d+)/i, sentence) ->
        [_, n] = match
        "< #{n}"

      match = Regex.run(~r/#{otp}(<=|<|>=|>)\s*(\d+)/i, sentence) ->
        [_, op, n] = match
        "#{op} #{n}"

      true ->
        nil
    end
  end
end
