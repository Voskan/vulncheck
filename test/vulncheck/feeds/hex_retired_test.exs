defmodule VulnCheck.Feeds.HexRetiredTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Config
  alias VulnCheck.Feeds.{HexRetired, Store}
  alias VulnCheck.Test.{Feeds, Tmp}
  alias VulnCheck.Types.{Advisory, Finding, Package, Retirement, Workspace}

  doctest VulnCheck.Feeds.HexRetired

  defmodule FakeHex do
    @moduledoc false
    @behaviour VulnCheck.HTTP

    @packages %{
      "plug_crypto" => %{
        "name" => "plug_crypto",
        "releases" => [
          %{"version" => "2.1.0"},
          %{
            "version" => "2.0.0",
            "retirement" => %{"reason" => "security", "message" => "Use 2.1.0+"}
          }
        ]
      },
      "jason" => %{
        "name" => "jason",
        "releases" => [
          %{"version" => "1.4.4"},
          %{"version" => "1.4.0", "retirement" => %{"reason" => "invalid", "message" => "broken"}}
        ]
      },
      "poison" => %{
        "name" => "poison",
        "releases" => [%{"version" => "3.1.0"}],
        "retirements" => %{"3.1.0" => %{"reason" => "deprecated", "message" => ""}}
      },
      "mox" => %{
        "name" => "mox",
        "releases" => [%{"version" => "1.0.0", "retirement" => %{"reason" => "weird"}}]
      }
    }

    @impl true
    def get(url, headers, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:hex_request, url, headers})
      name = url |> String.split("/") |> List.last()

      case {Map.fetch(@packages, name), List.keyfind(headers, "if-none-match", 0)} do
        {{:ok, _}, {"if-none-match", "\"" <> ^name <> "\""}} ->
          {:ok, %{status: 304, headers: %{}, body: ""}}

        {{:ok, record}, _} ->
          {:ok, %{status: 200, headers: %{"etag" => "\"#{name}\""}, body: JSON.encode!(record)}}

        {:error, _} when name == "flaky" ->
          {:error, :timeout}

        {:error, _} ->
          {:ok, %{status: 404, headers: %{}, body: "{}"}}
      end
    end
  end

  defp package(name, version, extra \\ []) do
    struct(
      %Package{name: name, hex_name: name, version: version, source: :hex, scope: :prod},
      extra
    )
  end

  defp workspace(packages, extra \\ []) do
    struct(
      %Workspace{
        root_dir: "/tmp/app",
        project_name: "app",
        project_type: :mix,
        env: :prod,
        otp_release: "27",
        packages: Map.new(packages, &{&1.name, &1})
      },
      extra
    )
  end

  defp config(extra \\ []) do
    struct(
      %Config{project_dir: Tmp.mkdir!("hex-project"), cache_dir: Tmp.mkdir!("hex-cache")},
      extra
    )
  end

  defp opts(extra \\ []) do
    Keyword.merge(
      [
        http_client: FakeHex,
        hex_api_url: "https://hex.example/api/packages/",
        http_opts: [test_pid: self()]
      ],
      extra
    )
  end

  defp drain do
    receive do
      {:hex_request, url, headers} -> [{url, headers} | drain()]
    after
      0 -> []
    end
  end

  test "a security retirement of the installed release becomes a high retired finding" do
    crypto = package("plug_crypto", "2.0.0")
    ws = workspace([crypto])

    assert {[advisory], []} = HexRetired.advisories(ws, config(), opts())

    assert %Advisory{
             id: "HEX-RETIRED-plug_crypto-2.0.0",
             severity: :high,
             retirement: %Retirement{reason: :security, message: "Use 2.1.0+", version: "2.0.0"}
           } = advisory

    assert advisory.summary == "plug_crypto 2.0.0 is retired (security): Use 2.1.0+"

    finding = HexRetired.to_finding(advisory, crypto)

    assert %Finding{verdict: :retired, reason: :package_retired, severity: :high} = finding
    assert finding.package_scope == :prod
    assert finding.reason_detail =~ "Use 2.1.0+"
    assert finding.fingerprint == Finding.fingerprint(advisory.id, "plug_crypto", :retired, nil)
    assert HexRetired.gate?(finding, config())
    refute HexRetired.gate?(finding, config(fail_on_retired: false))
    refute HexRetired.gate?(finding, config(fail_on: :none))
  end

  test "a retired older release does not flag the installed one" do
    ws = workspace([package("plug_crypto", "2.1.0"), package("jason", "1.4.4")])
    assert {[], []} = HexRetired.advisories(ws, config(), opts())
  end

  test "maps reasons to severities and supports both metadata shapes" do
    ws =
      workspace([
        package("jason", "1.4.0"),
        package("poison", "3.1.0"),
        package("mox", "1.0.0"),
        package("private_pkg", "0.1.0")
      ])

    {advisories, warnings} = HexRetired.advisories(ws, config(), opts())
    assert warnings == []

    assert Enum.map(advisories, &{&1.package, &1.retirement.reason, &1.severity}) == [
             {"jason", :invalid, :medium},
             {"mox", :other, :low},
             {"poison", :deprecated, :low}
           ]

    assert HexRetired.severity(:renamed) == :low
  end

  test "non-production retirements are annotated and gated only for security under --fail-on any" do
    dev = package("plug_crypto", "2.0.0", scope: :non_prod)
    {[advisory], _} = HexRetired.advisories(workspace([dev]), config(), opts())
    finding = HexRetired.to_finding(advisory, dev)

    assert finding.package_scope == :non_prod
    assert finding.reason_detail =~ "non-production dependency"
    refute HexRetired.gate?(finding, config())
    assert HexRetired.gate?(finding, config(fail_on: :any))
    refute HexRetired.gate?(%{finding | severity: :low}, config(fail_on: :any))
    refute HexRetired.gate?(%{finding | verdict: :reachable}, config())
  end

  test "repeated calls reuse the local cache and revalidate with the ETag" do
    ws = workspace([package("plug_crypto", "2.0.0")])
    config = config()

    assert {[_], []} = HexRetired.advisories(ws, config, opts())
    assert [{"https://hex.example/api/packages/plug_crypto", []}] = drain()

    # fresh cache: no request at all
    assert {[_], []} = HexRetired.advisories(ws, config, opts())
    assert drain() == []

    # expired cache: conditional request answered with 304
    assert {[advisory], []} = HexRetired.advisories(ws, config, opts(ttl: 0))
    assert [{_, [{"if-none-match", "\"plug_crypto\""}]}] = drain()
    assert advisory.retirement.reason == :security

    # offline with cache
    assert {[_], []} = HexRetired.advisories(ws, %{config | offline: true}, opts())
    assert drain() == []
  end

  test "reports failures without dropping other packages" do
    ws =
      workspace([
        package("plug_crypto", "2.0.0"),
        package("flaky", "1.0.0"),
        package("Bad-Name", "1.0.0"),
        %Package{name: "local", version: "0.1.0", source: :path, scope: :prod}
      ])

    {advisories, warnings} =
      HexRetired.advisories(ws, config(), opts(http_opts: [test_pid: self(), retries: 0]))

    assert [%Advisory{package: "plug_crypto"}] = advisories
    assert [warning] = warnings
    assert warning =~ "could not check Hex.pm retirement status of flaky"
    refute Enum.any?(drain(), fn {url, _} -> url =~ "Bad-Name" or url =~ "local" end)

    {[], [offline]} = HexRetired.advisories(ws, config(offline: true), opts())
    assert offline =~ "retirement status of 2 package(s) unknown"
  end

  test "lockfile hygiene flags missing checksums and unpinned production git deps" do
    sha = String.duplicate("a", 64)

    ws =
      workspace(
        [
          package("plug", "1.16.0", checksum: sha),
          package("old", "0.1.0", checksum: nil),
          %Package{
            name: "pinned",
            version: "1.0.0",
            source: :git,
            scope: :prod,
            git_ref: String.duplicate("b", 40)
          },
          %Package{name: "branchy", version: "1.0.0", source: :git, scope: :prod, git_ref: "main"},
          %Package{
            name: "devtool",
            version: "1.0.0",
            source: :git,
            scope: :non_prod,
            git_ref: "main"
          }
        ],
        lockfile: "/tmp/app/mix.lock"
      )

    assert HexRetired.hygiene(ws) == [
             "production git dependency branchy is not pinned to a full commit hash",
             "old 0.1.0 has no outer SHA-256 checksum in mix.lock; " <>
               "run `mix deps.unlock old && mix deps.get` to refresh it"
           ]

    assert HexRetired.hygiene(%{ws | lockfile: "/tmp/app/rebar.lock"}) == []
  end

  test "Store.load merges retirement advisories and honors --no-retired" do
    retired =
      JSON.encode!(%{
        "name" => "plug_crypto",
        "releases" => [%{"version" => "2.0.0", "retirement" => %{"reason" => "security"}}]
      })

    server =
      VulnCheck.Test.HTTPServer.start!(fn
        %{path: "/all.zip"} -> {200, [], Feeds.zip([Feeds.osv_plug()])}
        %{path: "/hex/plug_crypto"} -> {200, [], retired}
        _ -> {404, [], ""}
      end)

    ws = workspace([package("plug_crypto", "2.0.0", checksum: nil)], lockfile: "/tmp/app/mix.lock")
    opts = [osv_url: server.url <> "/all.zip", hex_api_url: server.url <> "/hex"]

    assert {:ok, result} = Store.load(ws, config(), opts)
    assert [%Advisory{retirement: %Retirement{reason: :security}}] = result.advisories
    assert result.stats.retired_releases == 1
    assert [hygiene] = result.warnings
    assert hygiene =~ "no outer SHA-256 checksum"

    assert {:ok, %{advisories: []}} = Store.load(ws, config(check_retired: false), opts)
    assert {:ok, %{advisories: []}} = Store.load(ws, config(), Keyword.put(opts, :retired, false))
  end
end
