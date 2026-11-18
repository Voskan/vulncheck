defmodule VulnCheck.Feeds.CVSS do
  @moduledoc """
  CVSS helpers: computes CVSS v3.0/v3.1 base scores from vector strings and
  recognizes CVSS v4.0 vectors (whose score is taken from the advisory
  source when available).
  """

  @doc """
  Computes the base score of a CVSS v3.x vector.

      iex> VulnCheck.Feeds.CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      9.8
      iex> VulnCheck.Feeds.CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
      7.5
      iex> VulnCheck.Feeds.CVSS.base_score("not a vector")
      nil
  """
  @spec base_score(String.t() | nil) :: float() | nil
  def base_score("CVSS:3." <> _ = vector) do
    metrics = parse_metrics(vector)

    with {:ok, av} <- lookup(metrics, "AV", %{"N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2}),
         {:ok, ac} <- lookup(metrics, "AC", %{"L" => 0.77, "H" => 0.44}),
         {:ok, ui} <- lookup(metrics, "UI", %{"N" => 0.85, "R" => 0.62}),
         {:ok, scope} <- lookup(metrics, "S", %{"U" => :unchanged, "C" => :changed}),
         {:ok, pr} <- privileges(metrics, scope),
         {:ok, c} <- lookup(metrics, "C", cia()),
         {:ok, i} <- lookup(metrics, "I", cia()),
         {:ok, a} <- lookup(metrics, "A", cia()) do
      iss = 1 - (1 - c) * (1 - i) * (1 - a)

      impact =
        case scope do
          :unchanged -> 6.42 * iss
          :changed -> 7.52 * (iss - 0.029) - 3.25 * :math.pow(iss - 0.02, 15)
        end

      exploitability = 8.22 * av * ac * pr * ui

      cond do
        impact <= 0 -> 0.0
        scope == :unchanged -> roundup(min(impact + exploitability, 10))
        true -> roundup(min(1.08 * (impact + exploitability), 10))
      end
    else
      _ -> nil
    end
  end

  def base_score(_), do: nil

  @doc "Returns the CVSS major version of a vector string (`3` or `4`), or `nil`."
  @spec version(String.t() | nil) :: 3 | 4 | nil
  def version("CVSS:3." <> _), do: 3
  def version("CVSS:4." <> _), do: 4
  def version(_), do: nil

  defp parse_metrics(vector) do
    vector
    |> String.split("/")
    |> Enum.drop(1)
    |> Enum.flat_map(fn part ->
      case String.split(part, ":", parts: 2) do
        [k, v] -> [{k, v}]
        _ -> []
      end
    end)
    |> Map.new()
  end

  defp lookup(metrics, key, table) do
    case Map.fetch(table, Map.get(metrics, key)) do
      {:ok, value} -> {:ok, value}
      :error -> :error
    end
  end

  defp privileges(metrics, scope) do
    table =
      case scope do
        :unchanged -> %{"N" => 0.85, "L" => 0.62, "H" => 0.27}
        :changed -> %{"N" => 0.85, "L" => 0.68, "H" => 0.5}
      end

    lookup(metrics, "PR", table)
  end

  defp cia, do: %{"H" => 0.56, "L" => 0.22, "N" => 0.0}

  # CVSS v3.1 Roundup: smallest number with one decimal >= input,
  # computed on integers to avoid floating point artifacts.
  defp roundup(value) do
    int = round(value * 100_000)

    if rem(int, 10_000) == 0 do
      int / 100_000
    else
      (div(int, 10_000) + 1) / 10
    end
  end
end
