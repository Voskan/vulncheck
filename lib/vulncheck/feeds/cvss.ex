defmodule VulnCheck.Feeds.CVSS do
  @moduledoc """
  CVSS helpers: computes CVSS v3.0/v3.1 base scores and CVSS v4.0 scores
  (`VulnCheck.Feeds.CVSS.V4`) from vector strings.
  """

  alias VulnCheck.Feeds.CVSS.V4
  alias VulnCheck.Semver
  alias VulnCheck.Types.Advisory

  @type rating :: %{
          score: float(),
          vector: String.t() | nil,
          method: String.t(),
          source: String.t()
        }

  @v3_optional %{
    "E" => ~w(X U P F H),
    "RL" => ~w(X O T W U),
    "RC" => ~w(X U R C),
    "CR" => ~w(X H M L),
    "IR" => ~w(X H M L),
    "AR" => ~w(X H M L),
    "MAV" => ~w(X N A L P),
    "MAC" => ~w(X L H),
    "MPR" => ~w(X N L H),
    "MUI" => ~w(X N R),
    "MS" => ~w(X U C),
    "MC" => ~w(X N L H),
    "MI" => ~w(X N L H),
    "MA" => ~w(X N L H)
  }
  @v3_base ~w(AV AC PR UI S C I A)

  @doc """
  Computes the score of a CVSS v3.x or v4.0 vector, or `nil` when the
  vector is not valid. A v4.0 vector with Threat or Environmental metrics is
  scored with them.

      iex> VulnCheck.Feeds.CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      9.8
      iex> VulnCheck.Feeds.CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
      7.5
      iex> VulnCheck.Feeds.CVSS.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
      9.3
      iex> VulnCheck.Feeds.CVSS.base_score("not a vector")
      nil
  """
  @spec base_score(String.t() | nil) :: float() | nil
  def base_score(<<"CVSS:3.", revision, "/", metrics::binary>>) when revision in [?0, ?1] do
    with {:ok, metrics} <- parse_metrics(metrics),
         {:ok, av} <- lookup(metrics, "AV", %{"N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2}),
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

  def base_score("CVSS:4.0/" <> _ = vector), do: V4.score(vector)

  def base_score(_), do: nil

  @doc "Returns the CVSS major version of a vector string (`3` or `4`), or `nil`."
  @spec version(String.t() | nil) :: 3 | 4 | nil
  def version(vector) do
    case method(vector) do
      method when method in ["CVSSv3", "CVSSv31"] -> 3
      "CVSSv4" -> 4
      _ -> nil
    end
  end

  @doc "CycloneDX method name corresponding to the vector header."
  @spec method(term()) :: String.t() | nil
  def method("CVSS:3.0/" <> _), do: "CVSSv3"
  def method("CVSS:3.1/" <> _), do: "CVSSv31"
  def method("CVSS:4.0/" <> _), do: "CVSSv4"
  def method(_), do: nil

  @doc false
  def ratings(entries, source) when is_list(entries) do
    entries
    |> Enum.flat_map(fn
      %{"score" => value} when is_binary(value) ->
        case base_score(value) do
          score when is_number(score) -> [rating(score, value, method(value), source)]
          nil -> numeric_rating(value, source)
        end

      _ ->
        []
    end)
    |> preferred()
  end

  def ratings(_entries, _source), do: nil

  defp numeric_rating(value, source) do
    case Float.parse(value) do
      {score, ""} when score >= 0.0 and score <= 10.0 -> [rating(score, nil, "other", source)]
      _ -> []
    end
  end

  @doc false
  def published(score, vector, method, source) do
    vector_score = if method(vector) == method, do: base_score(vector)
    score = if valid_score?(score), do: score, else: vector_score

    if valid_score?(score) do
      rating(score, if(vector_score != nil, do: vector), method, source)
    end
  end

  @doc false
  def preferred(ratings) do
    ratings
    |> Enum.reject(&is_nil/1)
    |> Enum.max_by(&{method_rank(&1.method), &1.score, &1.vector || "", &1.source}, fn -> nil end)
  end

  @doc false
  def strongest(ratings) do
    ratings
    |> Enum.reject(&is_nil/1)
    |> Enum.max_by(&{&1.score, method_rank(&1.method), &1.vector || "", &1.source}, fn -> nil end)
  end

  @doc false
  def select(sources, version) do
    for source <- sources,
        version == nil or Semver.affected?(version, source.ranges, source.versions) do
      scoped =
        for {ranges, versions, rating} <- source.scoped,
            version == nil or Semver.affected?(version, ranges, versions),
            do: rating

      preferred(scoped) || source.default
    end
    |> strongest()
  end

  @doc false
  def for_version(%Advisory{cvss_ratings: []} = advisory, _version), do: advisory

  def for_version(%Advisory{} = advisory, version) do
    apply_rating(advisory, select(advisory.cvss_ratings, version), advisory.qualitative_severity)
  end

  @doc false
  def current(%Advisory{} = advisory) do
    if valid_score?(advisory.cvss_score) do
      vector = if base_score(advisory.cvss_vector) != nil, do: advisory.cvss_vector
      source = advisory.cvss_source || advisory.id
      rating(advisory.cvss_score, vector, advisory.cvss_method || method(vector) || "other", source)
    end
  end

  @doc false
  def apply_rating(advisory, nil, label) do
    %{
      advisory
      | cvss_score: nil,
        cvss_vector: nil,
        cvss_method: nil,
        cvss_source: nil,
        severity: label
    }
  end

  def apply_rating(advisory, rating, _label) do
    %{
      advisory
      | cvss_score: rating.score,
        cvss_vector: rating.vector,
        cvss_method: rating.method,
        cvss_source: rating.source,
        severity: Advisory.severity_from_score(rating.score)
    }
  end

  defp rating(score, vector, method, source),
    do: %{score: score * 1.0, vector: vector, method: method, source: source}

  defp method_rank("CVSSv4"), do: 3
  defp method_rank("CVSSv31"), do: 2
  defp method_rank("CVSSv3"), do: 1
  defp method_rank(_method), do: 0

  defp valid_score?(score), do: is_number(score) and score >= 0.0 and score <= 10.0

  defp parse_metrics(metrics) do
    metrics
    |> String.split("/")
    |> Enum.reduce_while({:ok, %{}}, fn part, {:ok, parsed} ->
      with [key, value] <- String.split(part, ":", parts: 2),
           false <- Map.has_key?(parsed, key),
           true <- key in @v3_base or value in Map.get(@v3_optional, key, []) do
        {:cont, {:ok, Map.put(parsed, key, value)}}
      else
        _ -> {:halt, :error}
      end
    end)
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
