defmodule VulnCheck.Feeds.MergeTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Feeds.{Merge, OSV}
  alias VulnCheck.Semver
  alias VulnCheck.Test.Feeds
  alias VulnCheck.Types.{Advisory, MFA, VersionRange}

  defp advisory(id, aliases, extra \\ []) do
    struct(%Advisory{id: id, aliases: aliases, package: "bandit"}, extra)
  end

  defp range(introduced, fixed), do: %VersionRange{introduced: introduced, fixed: fixed}

  defp ghsa_copy(record, ghsa, extra) do
    record
    |> Map.merge(%{"id" => ghsa, "aliases" => record["aliases"]})
    |> Map.merge(extra)
  end

  describe "merge/1" do
    test "folds the EEF and GitHub records of one CVE into one advisory" do
      eef =
        advisory("EEF-CVE-2026-39804", ["CVE-2026-39804"],
          summary: "HTTP/2 flow control bypass",
          severity: :high,
          cvss_score: 8.7,
          cvss_vector: "CVSS:4.0/AV:N",
          version_ranges: [range("0", "1.11.0")],
          fixed_versions: ["1.11.0"],
          affected_routines: [%MFA{module: "Elixir.Bandit.HTTP2", function: "recv", arity: 2}],
          symbol_source: :osv,
          cwes: ["CWE-400"],
          references: ["https://cna.erlef.org/cves/CVE-2026-39804.html"],
          modified_at: "2026-03-01T00:00:00Z",
          published_at: "2026-02-01T00:00:00Z"
        )

      ghsa =
        advisory("GHSA-frh3-6pv6-rc8j", ["CVE-2026-39804"],
          summary: "Bandit flow control",
          details: "GitHub description",
          severity: :medium,
          cvss_score: 6.5,
          version_ranges: [range("1.0.0", "1.11.0")],
          fixed_versions: ["1.11.0"],
          cwes: ["CWE-770"],
          references: [
            "https://github.com/advisories/GHSA-frh3-6pv6-rc8j",
            "https://cna.erlef.org/cves/CVE-2026-39804.html"
          ],
          modified_at: "2026-04-01T00:00:00Z",
          published_at: "2026-01-15T00:00:00Z"
        )

      assert [merged] = Merge.merge([ghsa, eef])

      assert merged.id == "EEF-CVE-2026-39804"
      assert merged.aliases == ["CVE-2026-39804", "GHSA-frh3-6pv6-rc8j"]
      assert merged.summary == "HTTP/2 flow control bypass"
      assert merged.details == "GitHub description"
      assert {merged.severity, merged.cvss_score} == {:high, 8.7}
      assert merged.cvss_vector == "CVSS:4.0/AV:N"
      assert merged.version_ranges == [range("0", "1.11.0"), range("1.0.0", "1.11.0")]
      assert merged.fixed_versions == ["1.11.0"]
      assert merged.cwes == ["CWE-400", "CWE-770"]

      assert merged.references == [
               "https://cna.erlef.org/cves/CVE-2026-39804.html",
               "https://github.com/advisories/GHSA-frh3-6pv6-rc8j"
             ]

      assert merged.affected_routines == eef.affected_routines
      assert merged.symbol_source == :osv
      assert merged.modified_at == "2026-04-01T00:00:00Z"
      assert merged.published_at == "2026-01-15T00:00:00Z"
    end

    test "is independent of input order and keeps unrelated advisories apart" do
      a = advisory("GHSA-aaaa-aaaa-aaaa", ["CVE-2026-1"])
      b = advisory("EEF-CVE-2026-1", ["CVE-2026-1"])
      c = advisory("GHSA-cccc-cccc-cccc", ["CVE-2026-2"])
      other_package = %{advisory("GHSA-dddd-dddd-dddd", ["CVE-2026-1"]) | package: "plug"}

      inputs = [a, b, c, other_package]
      expected = Merge.merge(inputs)

      for permutation <- [Enum.reverse(inputs), [c, other_package, b, a], [b, c, a, other_package]] do
        assert Merge.merge(permutation) == expected
      end

      assert Enum.map(expected, &{&1.package, &1.id}) == [
               {"bandit", "EEF-CVE-2026-1"},
               {"bandit", "GHSA-cccc-cccc-cccc"},
               {"plug", "GHSA-dddd-dddd-dddd"}
             ]
    end

    test "merges transitively and compares identifiers case-insensitively" do
      a = advisory("OSV-2026-1", ["GHSA-xxxx-yyyy-zzzz"])
      b = advisory("GHSA-XXXX-YYYY-ZZZZ", ["CVE-2026-77"])
      c = advisory("CVE-2026-77", [])

      assert [merged] = Merge.merge([a, b, c])
      assert merged.id == "CVE-2026-77"
      assert merged.aliases == ["GHSA-XXXX-YYYY-ZZZZ", "GHSA-xxxx-yyyy-zzzz", "OSV-2026-1"]
    end

    test "a record without version data keeps every version affected" do
      ranged = advisory("EEF-CVE-2026-5", ["CVE-2026-5"], version_ranges: [range("0", "2.0.0")])
      open = advisory("GHSA-open-open-open", ["CVE-2026-5"])

      assert [merged] = Merge.merge([ranged, open])
      assert Semver.affected?("1.5.0", merged)
      assert Semver.affected?("3.0.0", merged)
      assert merged.fixed_versions == ["2.0.0"]
    end

    test "falls back to the strongest qualitative severity without scores" do
      a = advisory("GHSA-a-a-a", ["CVE-2026-9"], severity: :unknown)
      b = advisory("GHSA-b-b-b", ["CVE-2026-9"], severity: :medium, cvss_vector: "CVSS:4.0/X")

      assert [merged] = Merge.merge([a, b])

      assert {merged.severity, merged.cvss_score, merged.cvss_vector} ==
               {:medium, nil, "CVSS:4.0/X"}
    end

    test "leaves single advisories untouched" do
      single = advisory("GHSA-solo-solo-solo", [], summary: "alone")
      assert Merge.merge([single]) == [single]
      assert Merge.merge([]) == []
    end
  end

  describe "OSV archive" do
    test "an archive with EEF and GitHub records of one CVE yields one advisory" do
      eef = Feeds.osv_plug()

      ghsa =
        ghsa_copy(eef, "GHSA-j43x-5hjq-rgxf", %{
          "summary" => "Plug query decoding",
          "severity" => [
            %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
          ]
        })

      assert {:ok, advisories} = OSV.parse_archive(Feeds.zip([ghsa, eef, Feeds.osv_ash()]))

      plug = Enum.filter(advisories, &(&1.package == "plug"))
      assert [%Advisory{id: "EEF-CVE-2026-54892"} = merged] = plug
      assert merged.aliases == ["CVE-2026-54892", "GHSA-j43x-5hjq-rgxf"]
      assert merged.summary == eef["summary"]
      assert merged.cvss_score == 7.5
      assert merged.severity == :high

      ids = Enum.flat_map(advisories, &[&1.id | &1.aliases])
      assert length(ids) == length(Enum.uniq(ids))
    end
  end
end
