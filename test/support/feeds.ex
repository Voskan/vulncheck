defmodule VulnCheck.Test.Feeds do
  @moduledoc false
  # Realistic OSV and CVE 5.1 records (shapes taken from osv.dev and
  # cna.erlef.org) used by offline tests.

  def osv_ash do
    %{
      "schema_version" => "1.6.0",
      "id" => "EEF-CVE-2026-101028",
      "aliases" => ["CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"],
      "summary" => "Ash.count, Ash.exists and Ash.aggregate skip related resources' read policies",
      "details" =>
        "Aggregate queries built through `Ash.count/2` did not apply the read policies " <>
          "of related resources.",
      "published" => "2026-03-02T10:00:00Z",
      "modified" => "2026-03-04T12:00:00Z",
      "severity" => [
        %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
      ],
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => "ash", "purl" => "pkg:hex/ash"},
          "ranges" => [
            %{
              "type" => "SEMVER",
              "events" => [%{"introduced" => "3.0.0"}, %{"fixed" => "3.34.6"}]
            }
          ],
          "ecosystem_specific" => nil,
          "database_specific" => %{"source" => "https://cna.erlef.org/cves/CVE-2026-101028.json"}
        }
      ],
      "references" => [
        %{"type" => "ADVISORY", "url" => "https://cna.erlef.org/cves/CVE-2026-101028.html"},
        %{"type" => "FIX", "url" => "https://github.com/ash-project/ash/commit/abc"}
      ],
      "database_specific" => %{"cwe_ids" => ["CWE-863"]}
    }
  end

  def osv_plug do
    %{
      "id" => "EEF-CVE-2026-54892",
      "aliases" => ["CVE-2026-54892"],
      "summary" => "Quadratic-time nested parameter decoding in Plug.Conn.Query",
      "details" => "Deeply nested query strings cause quadratic decoding time.",
      "published" => "2026-02-10T00:00:00Z",
      "modified" => "2026-02-11T00:00:00Z",
      "severity" => [
        %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"}
      ],
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => "plug"},
          "ranges" => [
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
                %{"introduced" => "1.19.0"},
                %{"fixed" => "1.19.3"}
              ]
            }
          ]
        }
      ],
      "references" => [
        %{"type" => "WEB", "url" => "https://cna.erlef.org/cves/CVE-2026-54892.html"}
      ]
    }
  end

  def osv_phoenix do
    %{
      "id" => "GHSA-ph0x-0000-0001",
      "aliases" => ["CVE-2026-77777"],
      "summary" => "Open redirect in Phoenix.Controller.redirect/2",
      "details" => "Fixed long ago.",
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => "phoenix"},
          "ranges" => [
            %{"type" => "ECOSYSTEM", "events" => [%{"introduced" => "0"}, %{"fixed" => "1.6.0"}]}
          ]
        }
      ],
      "database_specific" => %{"severity" => "MODERATE", "cwe_ids" => ["CWE-601"]}
    }
  end

  def osv_hex_core do
    %{
      "id" => "EEF-CVE-2026-103502",
      "aliases" => ["CVE-2026-103502"],
      "summary" => "hex_core does not verify TLS certificates on old OTP releases",
      "details" =>
        "When running on OTP 24 and 25, `hex_http_httpc:http_options/2` falls back to " <>
          "verify_none. This only affects OTP 24 and 25.",
      "severity" => [
        %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}
      ],
      "affected" => [
        %{
          "package" => %{"ecosystem" => "Hex", "name" => "hex_core"},
          "ranges" => [
            %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "0.10.3"}]}
          ]
        }
      ]
    }
  end

  def osv_withdrawn do
    %{"id" => "GHSA-gone", "withdrawn" => "2026-01-01T00:00:00Z", "affected" => []}
  end

  def cve_record(cve, package, routines, opts \\ []) do
    versions = Keyword.get(opts, :versions, [])

    modules =
      Keyword.get_lazy(opts, :modules, fn ->
        routines |> Enum.map(fn r -> r |> String.split(":") |> hd() end) |> Enum.uniq()
      end)

    metrics =
      case Keyword.get(opts, :cvss) do
        nil ->
          []

        {score, vector} ->
          [
            %{
              "cvssV3_1" => %{
                "baseScore" => score,
                "vectorString" => vector,
                "baseSeverity" => "HIGH"
              }
            }
          ]
      end

    %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.1",
      "cveMetadata" => %{"cveId" => cve, "assignerShortName" => "EEF", "state" => "PUBLISHED"},
      "containers" => %{
        "cna" => %{
          "affected" => [
            %{
              "collectionURL" => "https://repo.hex.pm",
              "defaultStatus" => if(versions == [], do: "unknown", else: "unaffected"),
              "modules" => modules,
              "packageName" => package,
              "packageURL" => "pkg:hex/#{package}",
              "programRoutines" => Enum.map(routines, &%{"name" => &1}),
              "versions" => versions
            }
          ],
          "descriptions" => [%{"lang" => "en", "value" => Keyword.get(opts, :description, "")}],
          "metrics" => metrics,
          "problemTypes" => [
            %{
              "descriptions" => [
                %{"cweId" => Keyword.get(opts, :cwe, "CWE-400"), "lang" => "en", "type" => "CWE"}
              ]
            }
          ]
        }
      }
    }
  end

  def zip(records) do
    files =
      Enum.map(records, fn record ->
        {String.to_charlist(record["id"] <> ".json"), JSON.encode!(record)}
      end)

    {:ok, {_name, binary}} = :zip.create(~c"all.zip", files, [:memory])
    binary
  end
end
