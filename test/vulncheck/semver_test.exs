defmodule VulnCheck.SemverTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Semver
  alias VulnCheck.Types.{Advisory, VersionRange}

  doctest VulnCheck.Semver

  # CVE-2026-54892 (plug): five patched release branches.
  @plug_osv_ranges [
    %{
      "type" => "SEMVER",
      "events" => [
        %{"introduced" => "1.15.0"},
        %{"fixed" => "1.15.5"},
        %{"introduced" => "1.16.0"},
        %{"fixed" => "1.16.4"},
        %{"introduced" => "1.17.0"},
        %{"fixed" => "1.17.2"},
        %{"introduced" => "1.18.0"},
        %{"fixed" => "1.18.3"},
        %{"introduced" => "1.19.0-rc.0"},
        %{"fixed" => "1.19.3"}
      ]
    }
  ]

  defp plug_advisory do
    ranges = Semver.from_osv_ranges(@plug_osv_ranges)

    %Advisory{
      id: "EEF-CVE-2026-54892",
      package: "plug",
      version_ranges: ranges,
      fixed_versions: Semver.fixed_versions(ranges)
    }
  end

  describe "compare/2" do
    test "orders SemVer versions including pre-releases and build metadata" do
      assert Semver.compare("1.19.0-rc.0", "1.19.0-rc.1") == :lt
      assert Semver.compare("1.19.0-rc.1", "1.19.0") == :lt
      assert Semver.compare("1.19.0-alpha", "1.19.0-alpha.1") == :lt
      assert Semver.compare("1.19.0-alpha.beta", "1.19.0-beta") == :lt
      assert Semver.compare("1.19.0-rc.2", "1.19.0-rc.10") == :lt
      assert Semver.compare("1.19.0-1", "1.19.0-alpha") == :lt
      assert Semver.compare("1.0.0+build.1", "1.0.0+build.2") == :eq
      assert Semver.compare("v1.2.3", "1.2.3") == :eq
      assert Semver.compare("1.10.0", "1.9.9") == :gt
    end

    test "handles non-SemVer Erlang and OTP versions" do
      assert Semver.compare("0.8", "0.8.0") == :eq
      assert Semver.compare("2.10.1.2", "2.10.1") == :gt
      assert Semver.compare("2.10.1.2", "2.10.2") == :lt
      assert Semver.compare("27", "26.2.5") == :gt
      assert Semver.compare("25.3.2.12", "25.3.2.9") == :gt
      assert Semver.valid?("27")
      refute Semver.valid?("1.x")
      refute Semver.valid?("1.0-")
      refute Semver.valid?(nil)

      assert Semver.sort(["1.10.0", "1.2", "1.9.9", "1.2.0-rc.1"]) ==
               ["1.2.0-rc.1", "1.2", "1.9.9", "1.10.0"]
    end

    test "falls back to string comparison for unparseable input" do
      assert Semver.compare("abc", "abd") == :lt
    end
  end

  describe "OSV ranges" do
    test "multi-branch backports for CVE-2026-54892" do
      advisory = plug_advisory()
      assert length(advisory.version_ranges) == 5

      refute Semver.affected?("1.14.9", advisory)
      assert Semver.affected?("1.15.0", advisory)
      refute Semver.affected?("1.15.5", advisory)
      assert Semver.affected?("1.16.1", advisory)
      assert Semver.affected?("1.16.2", advisory)
      refute Semver.affected?("1.16.4", advisory)
      assert Semver.affected?("1.19.0-rc.1", advisory)
      assert Semver.affected?("1.19.2", advisory)
      refute Semver.affected?("1.19.3", advisory)
      refute Semver.affected?("1.20.0", advisory)
    end

    test "recommends the fix of the installed release branch" do
      advisory = plug_advisory()
      assert Semver.recommended_fix("1.16.2", advisory) == "1.16.4"
      assert Semver.recommended_fix("1.15.1", advisory) == "1.15.5"
      assert Semver.recommended_fix("1.19.0-rc.1", advisory) == "1.19.3"
      assert advisory.fixed_versions == ["1.15.5", "1.16.4", "1.17.2", "1.18.3", "1.19.3"]
    end

    test "only recommends releases outside all known affected intervals and versions" do
      advisory = %Advisory{
        id: "A",
        package: "p",
        version_ranges: [
          %VersionRange{introduced: "1.0.0", fixed: "1.2.0"},
          %VersionRange{introduced: "1.1.0", fixed: "1.3.0"}
        ]
      }

      assert Semver.recommended_fix("1.1.5", advisory) == "1.3.0"
      assert Semver.recommended_fix("1.1.5", %{advisory | affected_versions: ["1.3.0"]}) == nil
      assert Semver.recommended_fix("1.3.0", advisory) == nil
      assert Semver.recommended_fix("unknown", advisory) == nil
    end

    test "an OSV limit is exclusive and does not invent a fix" do
      [range] =
        Semver.from_osv_ranges([
          %{"type" => "SEMVER", "events" => [%{"introduced" => "1.0.0"}, %{"limit" => "2.0.0"}]}
        ])

      assert Semver.in_range?("1.9.9", range)
      refute Semver.in_range?("2.0.0", range)
      assert Semver.fixed_versions([range]) == []
      assert Semver.in_range?("99.0.0", %{range | limit: "unknown"})
    end

    test "introduced 0, last_affected, open-ended and unsorted events" do
      [range] =
        Semver.from_osv_ranges([
          %{
            "type" => "ECOSYSTEM",
            "events" => [%{"introduced" => "0"}, %{"last_affected" => "2.8"}]
          }
        ])

      assert range == %VersionRange{introduced: "0", last_affected: "2.8"}
      assert Semver.in_range?("0.1.0", range)
      assert Semver.in_range?("2.8.0", range)
      refute Semver.in_range?("2.8.1", range)

      [open] = Semver.from_osv_ranges([%{"events" => [%{"introduced" => "3.0.0"}]}])
      assert Semver.in_range?("99.0.0", open)
      refute Semver.in_range?("2.9.9", open)

      unsorted =
        Semver.from_osv_ranges([
          %{
            "type" => "SEMVER",
            "events" => [
              %{"fixed" => "2.0.1"},
              %{"introduced" => "2.0.0"},
              %{"fixed" => "1.0.5"},
              %{"introduced" => "0"}
            ]
          },
          %{"type" => "GIT", "events" => [%{"introduced" => "abc"}]},
          %{"type" => "SEMVER"}
        ])

      assert unsorted == [
               %VersionRange{introduced: "0", fixed: "1.0.5"},
               %VersionRange{introduced: "2.0.0", fixed: "2.0.1"}
             ]

      assert Semver.from_osv_ranges(nil) == []
    end

    test "explicit affected versions and fail-safe defaults" do
      explicit = %Advisory{id: "X", package: "p", affected_versions: ["1.0.0", "1.0.1"]}
      assert Semver.affected?("1.0.1", explicit)
      refute Semver.affected?("1.0.2", explicit)

      unbounded = %Advisory{id: "Y", package: "p"}
      assert Semver.affected?("5.0.0", unbounded)
      assert Semver.affected?("garbage", plug_advisory())
    end

    test "recommended_fix falls back to declared fixed versions" do
      advisory = %Advisory{
        id: "Z",
        package: "p",
        version_ranges: [%VersionRange{introduced: "0", last_affected: "1.2.0"}],
        fixed_versions: ["1.3.0", "1.2.5"]
      }

      assert Semver.recommended_fix("1.1.0", advisory) == "1.2.5"
      assert Semver.recommended_fix("1.1.0", %Advisory{id: "N", package: "p"}) == nil
    end
  end

  describe "CVE 5.1 versions" do
    test "lessThan, lessThanOrEqual, exact and unaffected entries" do
      ranges =
        Semver.from_cve_versions([
          %{
            "version" => "1.16.0",
            "lessThan" => "1.16.4",
            "status" => "affected",
            "versionType" => "semver"
          },
          %{"version" => "0", "lessThanOrEqual" => "1.14.9", "status" => "affected"},
          %{"version" => "2.0.0", "status" => "affected"},
          %{"version" => "3.0.0", "lessThan" => "*", "status" => "affected"},
          %{"version" => "1.16.4", "status" => "unaffected"},
          %{"status" => "affected"}
        ])

      assert [
               %VersionRange{introduced: "1.16.0", fixed: "1.16.4"},
               %VersionRange{introduced: "0", last_affected: "1.14.9"},
               %VersionRange{introduced: "2.0.0", last_affected: "2.0.0"},
               %VersionRange{introduced: "3.0.0", fixed: "*"},
               %VersionRange{}
             ] = ranges

      [a, b, c, d, _] = ranges
      assert Semver.in_range?("1.16.2", a)
      refute Semver.in_range?("1.16.4", a)
      assert Semver.in_range?("1.14.9", b)
      assert Semver.in_range?("2.0.0", c)
      refute Semver.in_range?("2.0.1", c)
      assert Semver.in_range?("4.0.0", d)
      assert Semver.from_cve_versions(nil) == []
    end

    test "handles numbered status changes and wildcards without treating them as fixes" do
      versions = [
        %{
          "version" => "1.0.0",
          "versionType" => "semver",
          "lessThan" => "1.*",
          "status" => "affected",
          "changes" => [
            %{"at" => "1.4.0", "status" => "unaffected"},
            %{"at" => "1.8.0", "status" => "affected"}
          ]
        },
        %{"version" => "other", "versionType" => "git", "status" => "affected"}
      ]

      ranges = Semver.from_cve_affected(%{"defaultStatus" => "unaffected", "versions" => versions})
      advisory = %Advisory{id: "A", package: "p", version_ranges: ranges}
      assert Semver.affected?("1.3.9", advisory)
      refute Semver.affected?("1.4.0", advisory)
      assert Semver.affected?("1.8.0", advisory)
      refute Semver.affected?("2.0.0-rc.1", advisory)
      assert Semver.fixed_versions(ranges) == []

      assert Semver.from_cve_affected(%{"defaultStatus" => "unknown", "versions" => versions}) == [
               %VersionRange{}
             ]
    end
  end

  describe "otp_affected?/2" do
    test "EEF-CVE-2026-103502 style constraint" do
      assert Semver.otp_affected?("25", "<= 25")
      assert Semver.otp_affected?("24", "<= 25")
      refute Semver.otp_affected?("27", "<= 25")
      refute Semver.otp_affected?("26.2.5", "<= 25")
    end

    test "conjunctions, disjunctions and exact matches" do
      assert Semver.otp_affected?("24", ">= 24 and <= 25")
      refute Semver.otp_affected?("23", ">= 24 and <= 25")
      assert Semver.otp_affected?("25", "24 || 25")
      refute Semver.otp_affected?("26", "24 || 25")
      assert Semver.otp_affected?("25.3", "OTP 24 or OTP 25")
      assert Semver.otp_affected?("25", "< 26")
      refute Semver.otp_affected?("26", "< 26")
      assert Semver.otp_affected?("27", "> 26")
      assert Semver.otp_affected?("26.1", "== 26")
      assert Semver.otp_affected?("26", "!= 25")
      assert Semver.otp_affected?("26.2", ">= 26.1")
      refute Semver.otp_affected?("26.0", ">= 26.1")
      assert Semver.otp_affected?("26.2", "~> 26.1")
      assert Semver.otp_affected?("27", ">= 24, <= 27")
    end

    test "fails safe on missing or unparseable constraints" do
      assert Semver.otp_affected?("27", nil)
      assert Semver.otp_affected?("27", "sometimes")
      assert Semver.otp_affected?("27", "")
      assert Semver.otp_affected?("not-a-release", "<= 25")
      assert Semver.otp_affected?("26", ">= 27 and")
    end

    test "an incomplete OTP release can satisfy a more precise boundary" do
      assert Semver.otp_affected?("27", ">= 27.3")
      assert Semver.otp_affected?("27.3", "== 27.3.4")
      assert Semver.otp_affected?("27.3", "!= 27.3.4")
      refute Semver.otp_affected?("26", ">= 27.3")
      refute Semver.otp_affected?("28", "< 27.3")
    end
  end
end
