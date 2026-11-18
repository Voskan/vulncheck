defmodule VulnCheck.Feeds.CVSS.V4 do
  @moduledoc """
  CVSS v4.0 scores computed from vector strings, following the FIRST
  CVSS v4.0 specification (section 8, "CVSS v4.0 Scoring").

  The vector is mapped to a macrovector (equivalence sets EQ1 to EQ6), whose
  score is looked up and then lowered by the mean proportional distance of
  the vector from the highest severity vectors of its macrovector. Threat
  (`E`) and Environmental metrics (`CR`, `IR`, `AR`, `MAV`, ...) are applied
  when present, so `CVSS-B`, `CVSS-BT`, `CVSS-BE` and `CVSS-BTE` vectors are
  all scored; absent or `X` values take the worst case (`E:A`, `CR:H`, ...)
  or the base value. Supplemental metrics do not affect the score.

  Every metric name and value stays a string, so vectors from feeds never
  create atoms.
  """

  # The macrovector scores, the highest severity vectors and the macrovector
  # depths below are the data of the reference implementation of the
  # specification (https://github.com/FIRSTdotorg/cvss-v4-calculator):
  #
  #   Copyright FIRST, Red Hat, and contributors
  #   SPDX-License-Identifier: BSD-2-Clause
  #
  #   Redistribution and use in source and binary forms, with or without
  #   modification, are permitted provided that the following conditions are
  #   met: (1) redistributions of source code must retain the above copyright
  #   notice, this list of conditions and the following disclaimer;
  #   (2) redistributions in binary form must reproduce the above copyright
  #   notice, this list of conditions and the following disclaimer in the
  #   documentation and/or other materials provided with the distribution.
  #   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  #   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  #   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
  #   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  #   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  #   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
  #   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  #   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  #   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  #   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  #   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  @scores %{
    "000000" => 10.0,
    "000001" => 9.9,
    "000010" => 9.8,
    "000011" => 9.5,
    "000020" => 9.5,
    "000021" => 9.2,
    "000100" => 10.0,
    "000101" => 9.6,
    "000110" => 9.3,
    "000111" => 8.7,
    "000120" => 9.1,
    "000121" => 8.1,
    "000200" => 9.3,
    "000201" => 9.0,
    "000210" => 8.9,
    "000211" => 8.0,
    "000220" => 8.1,
    "000221" => 6.8,
    "001000" => 9.8,
    "001001" => 9.5,
    "001010" => 9.5,
    "001011" => 9.2,
    "001020" => 9.0,
    "001021" => 8.4,
    "001100" => 9.3,
    "001101" => 9.2,
    "001110" => 8.9,
    "001111" => 8.1,
    "001120" => 8.1,
    "001121" => 6.5,
    "001200" => 8.8,
    "001201" => 8.0,
    "001210" => 7.8,
    "001211" => 7.0,
    "001220" => 6.9,
    "001221" => 4.8,
    "002001" => 9.2,
    "002011" => 8.2,
    "002021" => 7.2,
    "002101" => 7.9,
    "002111" => 6.9,
    "002121" => 5.0,
    "002201" => 6.9,
    "002211" => 5.5,
    "002221" => 2.7,
    "010000" => 9.9,
    "010001" => 9.7,
    "010010" => 9.5,
    "010011" => 9.2,
    "010020" => 9.2,
    "010021" => 8.5,
    "010100" => 9.5,
    "010101" => 9.1,
    "010110" => 9.0,
    "010111" => 8.3,
    "010120" => 8.4,
    "010121" => 7.1,
    "010200" => 9.2,
    "010201" => 8.1,
    "010210" => 8.2,
    "010211" => 7.1,
    "010220" => 7.2,
    "010221" => 5.3,
    "011000" => 9.5,
    "011001" => 9.3,
    "011010" => 9.2,
    "011011" => 8.5,
    "011020" => 8.5,
    "011021" => 7.3,
    "011100" => 9.2,
    "011101" => 8.2,
    "011110" => 8.0,
    "011111" => 7.2,
    "011120" => 7.0,
    "011121" => 5.9,
    "011200" => 8.4,
    "011201" => 7.0,
    "011210" => 7.1,
    "011211" => 5.2,
    "011220" => 5.0,
    "011221" => 3.0,
    "012001" => 8.6,
    "012011" => 7.5,
    "012021" => 5.2,
    "012101" => 7.1,
    "012111" => 5.2,
    "012121" => 2.9,
    "012201" => 6.3,
    "012211" => 2.9,
    "012221" => 1.7,
    "100000" => 9.8,
    "100001" => 9.5,
    "100010" => 9.4,
    "100011" => 8.7,
    "100020" => 9.1,
    "100021" => 8.1,
    "100100" => 9.4,
    "100101" => 8.9,
    "100110" => 8.6,
    "100111" => 7.4,
    "100120" => 7.7,
    "100121" => 6.4,
    "100200" => 8.7,
    "100201" => 7.5,
    "100210" => 7.4,
    "100211" => 6.3,
    "100220" => 6.3,
    "100221" => 4.9,
    "101000" => 9.4,
    "101001" => 8.9,
    "101010" => 8.8,
    "101011" => 7.7,
    "101020" => 7.6,
    "101021" => 6.7,
    "101100" => 8.6,
    "101101" => 7.6,
    "101110" => 7.4,
    "101111" => 5.8,
    "101120" => 5.9,
    "101121" => 5.0,
    "101200" => 7.2,
    "101201" => 5.7,
    "101210" => 5.7,
    "101211" => 5.2,
    "101220" => 5.2,
    "101221" => 2.5,
    "102001" => 8.3,
    "102011" => 7.0,
    "102021" => 5.4,
    "102101" => 6.5,
    "102111" => 5.8,
    "102121" => 2.6,
    "102201" => 5.3,
    "102211" => 2.1,
    "102221" => 1.3,
    "110000" => 9.5,
    "110001" => 9.0,
    "110010" => 8.8,
    "110011" => 7.6,
    "110020" => 7.6,
    "110021" => 7.0,
    "110100" => 9.0,
    "110101" => 7.7,
    "110110" => 7.5,
    "110111" => 6.2,
    "110120" => 6.1,
    "110121" => 5.3,
    "110200" => 7.7,
    "110201" => 6.6,
    "110210" => 6.8,
    "110211" => 5.9,
    "110220" => 5.2,
    "110221" => 3.0,
    "111000" => 8.9,
    "111001" => 7.8,
    "111010" => 7.6,
    "111011" => 6.7,
    "111020" => 6.2,
    "111021" => 5.8,
    "111100" => 7.4,
    "111101" => 5.9,
    "111110" => 5.7,
    "111111" => 5.7,
    "111120" => 4.7,
    "111121" => 2.3,
    "111200" => 6.1,
    "111201" => 5.2,
    "111210" => 5.7,
    "111211" => 2.9,
    "111220" => 2.4,
    "111221" => 1.6,
    "112001" => 7.1,
    "112011" => 5.9,
    "112021" => 3.0,
    "112101" => 5.8,
    "112111" => 2.6,
    "112121" => 1.5,
    "112201" => 2.3,
    "112211" => 1.3,
    "112221" => 0.6,
    "200000" => 9.3,
    "200001" => 8.7,
    "200010" => 8.6,
    "200011" => 7.2,
    "200020" => 7.5,
    "200021" => 5.8,
    "200100" => 8.6,
    "200101" => 7.4,
    "200110" => 7.4,
    "200111" => 6.1,
    "200120" => 5.6,
    "200121" => 3.4,
    "200200" => 7.0,
    "200201" => 5.4,
    "200210" => 5.2,
    "200211" => 4.0,
    "200220" => 4.0,
    "200221" => 2.2,
    "201000" => 8.5,
    "201001" => 7.5,
    "201010" => 7.4,
    "201011" => 5.5,
    "201020" => 6.2,
    "201021" => 5.1,
    "201100" => 7.2,
    "201101" => 5.7,
    "201110" => 5.5,
    "201111" => 4.1,
    "201120" => 4.6,
    "201121" => 1.9,
    "201200" => 5.3,
    "201201" => 3.6,
    "201210" => 3.4,
    "201211" => 1.9,
    "201220" => 1.9,
    "201221" => 0.8,
    "202001" => 6.4,
    "202011" => 5.1,
    "202021" => 2.0,
    "202101" => 4.7,
    "202111" => 2.1,
    "202121" => 1.1,
    "202201" => 2.4,
    "202211" => 0.9,
    "202221" => 0.4,
    "210000" => 8.8,
    "210001" => 7.5,
    "210010" => 7.3,
    "210011" => 5.3,
    "210020" => 6.0,
    "210021" => 5.0,
    "210100" => 7.3,
    "210101" => 5.5,
    "210110" => 5.9,
    "210111" => 4.0,
    "210120" => 4.1,
    "210121" => 2.0,
    "210200" => 5.4,
    "210201" => 4.3,
    "210210" => 4.5,
    "210211" => 2.2,
    "210220" => 2.0,
    "210221" => 1.1,
    "211000" => 7.5,
    "211001" => 5.5,
    "211010" => 5.8,
    "211011" => 4.5,
    "211020" => 4.0,
    "211021" => 2.1,
    "211100" => 6.1,
    "211101" => 5.1,
    "211110" => 4.8,
    "211111" => 1.8,
    "211120" => 2.0,
    "211121" => 0.9,
    "211200" => 4.6,
    "211201" => 1.8,
    "211210" => 1.7,
    "211211" => 0.7,
    "211220" => 0.8,
    "211221" => 0.2,
    "212001" => 5.3,
    "212011" => 2.4,
    "212021" => 1.4,
    "212101" => 2.4,
    "212111" => 1.2,
    "212121" => 0.5,
    "212201" => 1.0,
    "212211" => 0.3,
    "212221" => 0.1
  }

  @max_composed %{
    eq1: %{
      0 => ["AV:N/PR:N/UI:N/"],
      1 => ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
      2 => ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
    },
    eq2: %{0 => ["AC:L/AT:N/"], 1 => ["AC:H/AT:N/", "AC:L/AT:P/"]},
    eq3: %{
      {0, 0} => ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
      {0, 1} => ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
      {1, 0} => ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
      {1, 1} => [
        "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
        "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
        "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
        "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
        "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"
      ],
      {2, 1} => ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]
    },
    eq4: %{0 => ["SC:H/SI:S/SA:S/"], 1 => ["SC:H/SI:H/SA:H/"], 2 => ["SC:L/SI:L/SA:L/"]},
    eq5: %{0 => ["E:A/"], 1 => ["E:P/"], 2 => ["E:U/"]}
  }

  # Depth of each macrovector, in severity distance steps (+1).
  @max_severity %{
    eq1: %{0 => 1, 1 => 4, 2 => 5},
    eq2: %{0 => 1, 1 => 2},
    eq3eq6: %{{0, 0} => 7, {0, 1} => 6, {1, 0} => 8, {1, 1} => 8, {2, 1} => 10},
    eq4: %{0 => 6, 1 => 5, 2 => 4}
  }

  @levels %{
    "AV" => %{"N" => 0.0, "A" => 0.1, "L" => 0.2, "P" => 0.3},
    "PR" => %{"N" => 0.0, "L" => 0.1, "H" => 0.2},
    "UI" => %{"N" => 0.0, "P" => 0.1, "A" => 0.2},
    "AC" => %{"L" => 0.0, "H" => 0.1},
    "AT" => %{"N" => 0.0, "P" => 0.1},
    "VC" => %{"H" => 0.0, "L" => 0.1, "N" => 0.2},
    "VI" => %{"H" => 0.0, "L" => 0.1, "N" => 0.2},
    "VA" => %{"H" => 0.0, "L" => 0.1, "N" => 0.2},
    "SC" => %{"H" => 0.1, "L" => 0.2, "N" => 0.3},
    "SI" => %{"S" => 0.0, "H" => 0.1, "L" => 0.2, "N" => 0.3},
    "SA" => %{"S" => 0.0, "H" => 0.1, "L" => 0.2, "N" => 0.3},
    "CR" => %{"H" => 0.0, "M" => 0.1, "L" => 0.2},
    "IR" => %{"H" => 0.0, "M" => 0.1, "L" => 0.2},
    "AR" => %{"H" => 0.0, "M" => 0.1, "L" => 0.2}
  }

  @base_metrics %{
    "AV" => ~w(N A L P),
    "AC" => ~w(L H),
    "AT" => ~w(N P),
    "PR" => ~w(N L H),
    "UI" => ~w(N P A),
    "VC" => ~w(H L N),
    "VI" => ~w(H L N),
    "VA" => ~w(H L N),
    "SC" => ~w(H L N),
    "SI" => ~w(H L N),
    "SA" => ~w(H L N)
  }

  @optional_metrics %{
    "E" => ~w(X A P U),
    "CR" => ~w(X H M L),
    "IR" => ~w(X H M L),
    "AR" => ~w(X H M L),
    "MAV" => ~w(X N A L P),
    "MAC" => ~w(X L H),
    "MAT" => ~w(X N P),
    "MPR" => ~w(X N L H),
    "MUI" => ~w(X N P A),
    "MVC" => ~w(X H L N),
    "MVI" => ~w(X H L N),
    "MVA" => ~w(X H L N),
    "MSC" => ~w(X H L N),
    "MSI" => ~w(X S H L N),
    "MSA" => ~w(X S H L N),
    "S" => ~w(X N P),
    "AU" => ~w(X N Y),
    "R" => ~w(X A U I),
    "V" => ~w(X D C),
    "RE" => ~w(X L M H),
    "U" => ~w(X Clear Green Amber Red)
  }

  @distance_metrics ~w(AV PR UI AC AT VC VI VA SC SI SA CR IR AR)

  @doc """
  Computes the score of a CVSS v4.0 vector, or `nil` when the string is not
  a valid v4.0 vector (missing or repeated metric, unknown metric or value).

      iex> VulnCheck.Feeds.CVSS.V4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
      10.0
      iex> VulnCheck.Feeds.CVSS.V4.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
      0.0
      iex> VulnCheck.Feeds.CVSS.V4.score("CVSS:4.0/AV:N")
      nil
  """
  @spec score(term()) :: float() | nil
  def score("CVSS:4.0/" <> metrics) do
    case parse(metrics) do
      {:ok, selected} -> compute(selected)
      :error -> nil
    end
  end

  def score(_other), do: nil

  @doc """
  The macrovector of a v4.0 vector: the levels of EQ1 to EQ6 as a string of
  six digits, or `nil` when the vector is not valid.

      iex> VulnCheck.Feeds.CVSS.V4.macrovector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
      "000200"
  """
  @spec macrovector(term()) :: String.t() | nil
  def macrovector("CVSS:4.0/" <> metrics) do
    case parse(metrics) do
      {:ok, selected} -> selected |> equivalence_sets() |> key()
      :error -> nil
    end
  end

  def macrovector(_other), do: nil

  @doc "Metric names and the values they accept (base metrics first)."
  @spec metrics() :: {%{String.t() => [String.t()]}, %{String.t() => [String.t()]}}
  def metrics, do: {@base_metrics, @optional_metrics}

  defp parse(metrics) do
    metrics
    |> String.split("/")
    |> Enum.reduce_while(%{}, fn part, acc ->
      with [key, value] <- String.split(part, ":", parts: 2),
           {:ok, allowed} <- allowed(key),
           true <- value in allowed,
           false <- Map.has_key?(acc, key) do
        {:cont, Map.put(acc, key, value)}
      else
        _ -> {:halt, :error}
      end
    end)
    |> case do
      :error ->
        :error

      selected ->
        if Enum.all?(Map.keys(@base_metrics), &Map.has_key?(selected, &1)),
          do: {:ok, selected},
          else: :error
    end
  end

  defp allowed(key) do
    case Map.fetch(@base_metrics, key) do
      {:ok, values} -> {:ok, values}
      :error -> Map.fetch(@optional_metrics, key)
    end
  end

  # Effective value of a metric: the worst case for unset Threat and
  # requirement metrics, the modified value when one is set.
  defp m(selected, "E"), do: x_default(Map.get(selected, "E", "X"), "A")

  defp m(selected, metric) when metric in ["CR", "IR", "AR"],
    do: x_default(Map.get(selected, metric, "X"), "H")

  defp m(selected, metric) do
    case Map.get(selected, "M" <> metric, "X") do
      "X" -> Map.get(selected, metric, "X")
      modified -> modified
    end
  end

  defp x_default("X", default), do: default
  defp x_default(value, _default), do: value

  defp compute(selected) do
    if Enum.all?(~w(VC VI VA SC SI SA), &(m(selected, &1) == "N")) do
      0.0
    else
      macro = equivalence_sets(selected)
      value = Map.fetch!(@scores, key(macro))
      d = severity_distances(selected, macro)
      {e1, e2, e3, e4, e5, e6} = macro

      current = %{
        eq1: d["AV"] + d["PR"] + d["UI"],
        eq2: d["AC"] + d["AT"],
        eq3eq6: d["VC"] + d["VI"] + d["VA"] + d["CR"] + d["IR"] + d["AR"],
        eq4: d["SC"] + d["SI"] + d["SA"]
      }

      lower = %{
        eq1: lookup({e1 + 1, e2, e3, e4, e5, e6}),
        eq2: lookup({e1, e2 + 1, e3, e4, e5, e6}),
        eq3eq6: eq3eq6_lower(macro),
        eq4: lookup({e1, e2, e3, e4 + 1, e5, e6}),
        eq5: lookup({e1, e2, e3, e4, e5 + 1, e6})
      }

      depth = %{
        eq1: @max_severity.eq1[e1] * 0.1,
        eq2: @max_severity.eq2[e2] * 0.1,
        eq3eq6: @max_severity.eq3eq6[{e3, e6}] * 0.1,
        eq4: @max_severity.eq4[e4] * 0.1
      }

      {sum, count} =
        Enum.reduce([:eq1, :eq2, :eq3eq6, :eq4, :eq5], {0.0, 0}, fn eq, {sum, count} ->
          case lower[eq] do
            nil -> {sum, count}
            # the severity distance within EQ5 is always zero
            _next when eq == :eq5 -> {sum + 0.0, count + 1}
            next -> {sum + (value - next) * (current[eq] / depth[eq]), count + 1}
          end
        end)

      mean = if count == 0, do: 0.0, else: sum / count
      (value - mean) |> max(0.0) |> min(10.0) |> round_one()
    end
  end

  # Rounds half up to one decimal, as the reference implementation does.
  defp round_one(value), do: Float.floor(value * 10 + 0.5) / 10

  defp key({e1, e2, e3, e4, e5, e6}), do: "#{e1}#{e2}#{e3}#{e4}#{e5}#{e6}"

  defp lookup(macro), do: Map.get(@scores, key(macro))

  # EQ3 and EQ6 are scored together: 00 lowers to 01 or 10 (the higher
  # score of the two; the second on ties or when the first is missing), 01
  # and 11 lower EQ3, 10 lowers EQ6.
  defp eq3eq6_lower({e1, e2, 0, e4, e5, 0}) do
    left = lookup({e1, e2, 0, e4, e5, 1})
    right = lookup({e1, e2, 1, e4, e5, 0})
    if is_number(left) and is_number(right) and left > right, do: left, else: right
  end

  defp eq3eq6_lower({e1, e2, 1, e4, e5, 0}), do: lookup({e1, e2, 1, e4, e5, 1})

  defp eq3eq6_lower({e1, e2, e3, e4, e5, 1}) when e3 in [0, 1],
    do: lookup({e1, e2, e3 + 1, e4, e5, 1})

  defp eq3eq6_lower(_macro), do: nil

  defp equivalence_sets(s) do
    {av, pr, ui} = {m(s, "AV"), m(s, "PR"), m(s, "UI")}
    {vc, vi, va} = {m(s, "VC"), m(s, "VI"), m(s, "VA")}

    eq1 =
      cond do
        av == "N" and pr == "N" and ui == "N" -> 0
        (av == "N" or pr == "N" or ui == "N") and av != "P" -> 1
        true -> 2
      end

    eq2 = if m(s, "AC") == "L" and m(s, "AT") == "N", do: 0, else: 1

    eq3 =
      cond do
        vc == "H" and vi == "H" -> 0
        vc == "H" or vi == "H" or va == "H" -> 1
        true -> 2
      end

    eq4 =
      cond do
        m(s, "MSI") == "S" or m(s, "MSA") == "S" -> 0
        m(s, "SC") == "H" or m(s, "SI") == "H" or m(s, "SA") == "H" -> 1
        true -> 2
      end

    eq5 =
      case m(s, "E") do
        "A" -> 0
        "P" -> 1
        "U" -> 2
      end

    eq6 =
      if (m(s, "CR") == "H" and vc == "H") or (m(s, "IR") == "H" and vi == "H") or
           (m(s, "AR") == "H" and va == "H"),
         do: 0,
         else: 1

    {eq1, eq2, eq3, eq4, eq5, eq6}
  end

  # Severity distances from the first highest severity vector of the
  # macrovector that the vector does not exceed (the last one when none
  # fits, as in the reference implementation).
  defp severity_distances(selected, {e1, e2, e3, e4, e5, e6}) do
    candidates =
      for a <- @max_composed.eq1[e1],
          b <- @max_composed.eq2[e2],
          c <- @max_composed.eq3[{e3, e6}],
          d <- @max_composed.eq4[e4],
          e <- @max_composed.eq5[e5],
          do: max_vector(a <> b <> c <> d <> e)

    distances =
      Enum.map(candidates, fn max ->
        Map.new(@distance_metrics, fn metric ->
          {metric, @levels[metric][m(selected, metric)] - @levels[metric][max[metric]]}
        end)
      end)

    Enum.find(distances, List.last(distances), fn distance ->
      Enum.all?(distance, fn {_metric, value} -> value >= 0 end)
    end)
  end

  defp max_vector(text) do
    text
    |> String.split("/", trim: true)
    |> Map.new(fn part ->
      [key, value] = String.split(part, ":", parts: 2)
      {key, value}
    end)
  end
end
