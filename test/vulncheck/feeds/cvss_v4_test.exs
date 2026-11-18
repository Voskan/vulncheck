defmodule VulnCheck.Feeds.CVSSV4Test do
  # Not async: the atom table is compared before and after scoring.
  use ExUnit.Case, async: false

  alias VulnCheck.Config
  alias VulnCheck.Feeds.{CVSS, OSV}
  alias VulnCheck.Feeds.CVSS.V4
  alias VulnCheck.Test.Feeds
  alias VulnCheck.Types.Advisory

  doctest VulnCheck.Feeds.CVSS.V4

  @fixture Path.expand("../../fixtures/cvss4_vectors.txt", __DIR__)

  defp reference do
    @fixture
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reject(&String.starts_with?(&1, "#"))
    |> Enum.map(fn line ->
      [vector, score] = String.split(line, " ")
      {vector, String.to_float(score)}
    end)
  end

  defp random_vector(seed) do
    :rand.seed(:exsss, {seed, seed * 7 + 1, seed * 13 + 2})
    {base, optional} = V4.metrics()
    pick = fn values -> Enum.at(values, :rand.uniform(length(values)) - 1) end

    base_parts = for {metric, values} <- Enum.sort(base), do: "#{metric}:#{pick.(values)}"

    optional_parts =
      for {metric, values} <- Enum.sort(optional),
          :rand.uniform(3) == 1,
          do: "#{metric}:#{pick.(values)}"

    "CVSS:4.0/" <> Enum.join(base_parts ++ optional_parts, "/")
  end

  describe "reference vectors" do
    test "every vector scores exactly as in the reference calculator" do
      vectors = reference()
      assert length(vectors) >= 40

      mismatches =
        for {vector, expected} <- vectors,
            V4.score(vector) != expected,
            do: {vector, expected, V4.score(vector)}

      assert mismatches == []
    end

    test "cover both ends of the scale and every level of each equivalence set" do
      vectors = reference()
      scores = Enum.map(vectors, &elem(&1, 1))
      assert 0.0 in scores
      assert 10.0 in scores

      macros = Enum.map(vectors, fn {vector, _} -> V4.macrovector(vector) end)

      levels =
        for position <- 0..5 do
          macros |> Enum.map(&String.at(&1, position)) |> Enum.uniq() |> Enum.sort()
        end

      assert levels == [
               ["0", "1", "2"],
               ["0", "1"],
               ["0", "1", "2"],
               ["0", "1", "2"],
               ["0", "1", "2"],
               ["0", "1"]
             ]
    end
  end

  describe "score/1" do
    test "any valid vector scores within the scale in steps of 0.1" do
      for seed <- 1..2_000 do
        vector = random_vector(seed)
        score = V4.score(vector)

        assert is_float(score), vector
        assert score >= 0.0 and score <= 10.0, vector
        assert Float.round(score, 1) == score, vector
      end
    end

    test "invalid input never raises and yields nil" do
      valid = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

      for input <- [
            nil,
            42,
            "",
            "CVSS:4.0/",
            "CVSS:4.0/AV:N",
            "CVSS:4.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            valid <> "/AV:L",
            valid <> "/E:Z",
            valid <> "/ZZ:Q",
            valid <> "/",
            String.replace(valid, "VC:H", "VC:S"),
            String.replace(valid, "AC:L", "AC"),
            String.replace(valid, "/SA:N", "")
          ] do
        assert V4.score(input) == nil, inspect(input)
      end

      for seed <- 1..500 do
        :rand.seed(:exsss, {seed, 3, 5})
        noise = for _ <- 1..:rand.uniform(80), into: "", do: <<Enum.random(~c"CVS:4.0/AVNLHPXE")>>
        score = V4.score("CVSS:4.0/" <> noise)
        assert score == nil or (score >= 0.0 and score <= 10.0)
      end
    end

    test "scoring creates no atoms" do
      vectors = Enum.map(1..300, &random_vector/1)
      unknown = Enum.map(1..300, &"CVSS:4.0/AV:N/AC:L/QQ#{&1}:Z#{&1}")
      Enum.each(vectors ++ unknown, &V4.score/1)

      before = :erlang.system_info(:atom_count)
      Enum.each(vectors ++ unknown, &V4.score/1)
      Enum.each(Enum.map(301..600, &"CVSS:4.0/AV:N/WW#{&1}:Y#{&1}"), &V4.score/1)
      assert :erlang.system_info(:atom_count) == before
    end

    test "threat and environmental metrics are applied, supplemental ones are not" do
      base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
      assert V4.score(base) == 10.0
      assert V4.score(base <> "/E:X") == 10.0
      assert V4.score(base <> "/E:U") == 9.1
      assert V4.score(base <> "/S:P/AU:Y/R:I/V:C/RE:H/U:Red") == 10.0
      assert V4.score(base <> "/MVI:L/MSA:S") == 9.8
    end
  end

  describe "advisory scores" do
    test "the v4.0 scale maps to qualitative severities" do
      assert Advisory.severity_from_score(0.0) == :none
      assert Advisory.severity_from_score(3.9) == :low
      assert Advisory.severity_from_score(4.0) == :medium
      assert Advisory.severity_from_score(8.9) == :high
      assert Advisory.severity_from_score(9.0) == :critical
      assert Config.severity_rank(:none) == Config.severity_rank(:low)
    end

    test "CVSS.base_score dispatches on the vector version" do
      assert CVSS.base_score("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P") ==
               5.9

      assert CVSS.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    end

    test "a v4.0 vector wins over a v3.1 vector of the same record" do
      record =
        Map.put(Feeds.osv_plug(), "severity", [
          %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"},
          %{
            "type" => "CVSS_V4",
            "score" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
          }
        ])

      assert [%Advisory{cvss_score: 6.9, severity: :medium} = advisory] = OSV.parse_record(record)
      assert advisory.cvss_vector =~ "CVSS:4.0/"
    end

    # Vectors of the OSV Hex feed whose records carry no other score.
    @feed_vectors [
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:L/E:P"
    ]

    test "an archive whose records only carry v4.0 vectors has no unknown severity" do
      records =
        @feed_vectors
        |> Enum.with_index(1)
        |> Enum.map(fn {vector, index} ->
          Feeds.osv_plug()
          |> Map.merge(%{"id" => "GHSA-test-#{index}", "aliases" => ["CVE-2026-#{index}"]})
          |> Map.put("severity", [%{"type" => "CVSS_V4", "score" => vector}])
          |> Map.delete("database_specific")
        end)

      assert {:ok, advisories} = OSV.parse_archive(Feeds.zip(records))
      assert length(advisories) == length(@feed_vectors)
      assert Enum.all?(advisories, &is_float(&1.cvss_score))
      refute Enum.any?(advisories, &(&1.severity == :unknown))
    end
  end
end
