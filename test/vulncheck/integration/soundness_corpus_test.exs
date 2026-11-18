defmodule VulnCheck.Integration.SoundnessCorpusTest do
  # End-to-end scans of compiled workspaces against the offline advisory
  # corpus in test/fixtures/feeds. Every reachable or daemon-exposed
  # vulnerability must be reported (no false negatives), and every
  # unreachable one must be excluded with the right reason.
  use ExUnit.Case, async: true

  import VulnCheck.Test.FixtureBuilder

  alias VulnCheck.Config
  alias VulnCheck.Report.{Markdown, SARIF}
  alias VulnCheck.Types.{Finding, MFA, TraceHop}

  defp hops(%Finding{trace: trace}), do: Enum.map(trace, &{MFA.format(&1.mfa), &1.file, &1.line})

  # -- 1. function-level precision inside a used module -----------------------

  @ash %{
    name: "ash",
    version: "3.34.2",
    ex: [
      {"lib/ash.ex",
       """
       defmodule Ash do
         def read(query, opts), do: Ash.Actions.Read.run(query, opts)

         def count(query, opts) do
           Ash.Actions.Aggregate.run(query, opts, :count, [])
         end
       end
       """},
      {"lib/ash/actions.ex",
       """
       defmodule Ash.Actions.Read do
         def run(query, _opts), do: {:ok, [query]}
       end

       defmodule Ash.Actions.Aggregate do
         def run(query, _opts, kind, _extra), do: {:ok, {kind, query}}
       end
       """}
    ]
  }

  # a patched plug release: provides the behaviour, matches no advisory
  @plug_behaviour %{
    name: "plug",
    version: "1.16.6",
    ex: [
      {"lib/plug.ex",
       """
       defmodule Plug do
         @callback init(term()) :: term()
         @callback call(term(), term()) :: term()
       end
       """}
    ]
  }

  defp ledger!(ledger_source) do
    mix_project!("ledger",
      mod: "Ledger.Application",
      applications: [:ash, :plug],
      packages: [@ash, @plug_behaviour],
      ex: [
        {"lib/ledger/application.ex",
         """
         defmodule Ledger.Application do
           use Application

           def start(_type, _args) do
             Supervisor.start_link([LedgerWeb.Endpoint], strategy: :one_for_one)
           end
         end
         """},
        {"lib/ledger_web/endpoint.ex",
         """
         defmodule LedgerWeb.Endpoint do
           @behaviour Plug

           def init(opts), do: opts
           def call(conn, _opts), do: LedgerWeb.ReportController.index(conn, %{})
         end
         """},
        {"lib/ledger_web/controllers/report_controller.ex",
         """
         defmodule LedgerWeb.ReportController do
           def index(conn, params) do
             {conn, Ledger.entries(params)}
           end
         end
         """},
        {"lib/ledger.ex", ledger_source}
      ]
    )
  end

  test "1A: a call chain into Ash.count/2 is reachable with exact file:line hops" do
    root =
      ledger!("""
      defmodule Ledger do
        def entries(params), do: count_entries(params)

        def count_entries(params) do
          Ash.count(params, actor: nil)
        end
      end
      """)

    finding = root |> scan!() |> finding!("EEF-CVE-2026-101028")

    assert finding.verdict == :reachable
    assert finding.reason == :call_chain_proven
    assert finding.target_mfa == MFA.new("Elixir.Ash.Actions.Aggregate", "run", 4)

    assert hops(finding) == [
             {"Ledger.Application.start/2", "lib/ledger/application.ex", 5},
             {"LedgerWeb.Endpoint.call/2", "lib/ledger_web/endpoint.ex", 5},
             {"LedgerWeb.ReportController.index/2",
              "lib/ledger_web/controllers/report_controller.ex", 3},
             {"Ledger.entries/1", "lib/ledger.ex", 2},
             {"Ledger.count_entries/1", "lib/ledger.ex", 5},
             {"Ash.count/2", "deps/ash/lib/ash.ex", 5},
             {"Ash.Actions.Aggregate.run/4", "deps/ash/lib/ash/actions.ex", 6}
           ]
  end

  test "1B: using only Ash.read/2 keeps the advisory unreachable" do
    root =
      ledger!("""
      defmodule Ledger do
        def entries(params), do: Ash.read(params, actor: nil)
      end
      """)

    finding = root |> scan!() |> finding!("EEF-CVE-2026-101028")

    assert finding.package_scope == :prod
    assert finding.verdict == :unreachable
    assert finding.reason == :function_not_called
    assert finding.trace == []
  end

  # -- 2. Plug.Parsers options after macro expansion ---------------------------

  @plug %{
    name: "plug",
    version: "1.16.2",
    ex: [
      {"lib/plug.ex",
       """
       defmodule Plug do
         @callback init(term()) :: term()
         @callback call(term(), term()) :: term()
       end
       """},
      {"lib/plug/parsers.ex",
       """
       defmodule Plug.Parsers do
         def init(opts) do
           for parser <- Keyword.fetch!(opts, :parsers) do
             module = Module.concat(Plug.Parsers, String.upcase(Atom.to_string(parser)))
             {module, module.init(opts)}
           end
         end

         def call(conn, parsers) do
           Enum.reduce(parsers, conn, fn {parser, opts}, acc ->
             parser.parse(acc, "application", "x", %{}, opts)
           end)
         end
       end

       defmodule Plug.Parsers.JSON do
         def init(opts), do: Keyword.get(opts, :json_decoder)
         def parse(conn, _type, _subtype, _headers, decoder), do: decoder.decode!(conn)
       end

       defmodule Plug.Parsers.MULTIPART do
         def init(opts) do
           Keyword.get(opts, :length, 8_000_000)
         end

         def parse(conn, _type, _subtype, _headers, _limit), do: conn
       end

       defmodule Plug.Parsers.URLENCODED do
         def init(opts), do: opts
         def parse(conn, _type, _subtype, _headers, _opts), do: conn
       end
       """}
    ]
  }

  @jason %{
    name: "jason",
    version: "1.4.4",
    ex: [{"lib/jason.ex", "defmodule Jason do\n  def decode!(x), do: x\nend\n"}]
  }

  defp endpoint!(parsers) do
    mix_project!("shopfront",
      mod: "Shopfront.Application",
      applications: [:plug, :jason],
      packages: [@plug, @jason],
      ex: [
        {"lib/shopfront/application.ex",
         """
         defmodule Shopfront.Application do
           def start(_type, _args) do
             Supervisor.start_link([ShopfrontWeb.Endpoint], strategy: :one_for_one)
           end
         end
         """},
        {"lib/shopfront_web/builder.ex",
         """
         defmodule ShopfrontWeb.Builder do
           defmacro __using__(opts) do
             quote do
               @behaviour Plug

               def init(opts), do: opts
               def call(conn, opts), do: plug_builder_call(conn, opts)

               defp plug_builder_call(conn, _opts) do
                 Plug.Parsers.call(conn, Plug.Parsers.init(unquote(opts)))
               end
             end
           end
         end
         """},
        {"lib/shopfront_web/endpoint.ex",
         """
         defmodule ShopfrontWeb.Endpoint do
           use ShopfrontWeb.Builder, parsers: #{inspect(parsers)}, json_decoder: Jason
         end
         """}
      ]
    )
  end

  test "2A: parsers: [:json] leaves Plug.Parsers.MULTIPART unreachable" do
    finding = endpoint!([:json]) |> scan!() |> finding!("EEF-CVE-2026-60101")

    assert finding.verdict == :unreachable
    assert finding.reason in [:function_not_called, :module_not_loaded]
  end

  test "2B: enabling :multipart reaches MULTIPART.init/1 through the generated plug_builder_call/2" do
    finding =
      endpoint!([:urlencoded, :multipart, :json]) |> scan!() |> finding!("EEF-CVE-2026-60101")

    assert finding.verdict == :reachable
    assert finding.reason == :call_chain_proven
    assert finding.target_mfa == MFA.new("Elixir.Plug.Parsers.MULTIPART", "init", 1)

    assert Enum.map(finding.trace, &MFA.format(&1.mfa)) == [
             "Shopfront.Application.start/2",
             "ShopfrontWeb.Endpoint.call/2",
             "ShopfrontWeb.Endpoint.plug_builder_call/2",
             "Plug.Parsers.init/1",
             "Plug.Parsers.MULTIPART.init/1"
           ]

    assert hops(finding) == [
             {"Shopfront.Application.start/2", "lib/shopfront/application.ex", 3},
             {"ShopfrontWeb.Endpoint.call/2", "lib/shopfront_web/endpoint.ex", 2},
             {"ShopfrontWeb.Endpoint.plug_builder_call/2", "lib/shopfront_web/endpoint.ex", 2},
             {"Plug.Parsers.init/1", "deps/plug/lib/plug/parsers.ex", 5},
             {"Plug.Parsers.MULTIPART.init/1", "deps/plug/lib/plug/parsers.ex", 22}
           ]
  end

  # -- 3. active network daemon in the supervision tree -----------------------

  test "3: a Bandit child spec keeps HTTP/2 internals potentially reachable" do
    bandit = %{
      name: "bandit",
      version: "1.5.0",
      ex: [
        {"lib/bandit.ex",
         """
         defmodule Bandit do
           def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}
           def start_link(opts), do: {:ok, spawn(fn -> Keyword.fetch!(opts, :plug) end)}
         end
         """},
        {"lib/bandit/http2.ex",
         """
         defmodule Bandit.HTTP2.Connection do
           def handle_frame(frame_module, type, flags, payload) do
             frame_module.deserialize(type, flags, payload)
           end
         end

         defmodule Bandit.HTTP2.Frame.Continuation do
           def deserialize(_type, flags, payload), do: {:ok, {flags, payload}}
         end
         """}
      ]
    }

    root =
      mix_project!("relay",
        mod: "Relay.Application",
        applications: [:bandit],
        packages: [bandit],
        ex: [
          {"lib/relay/application.ex",
           """
           defmodule Relay.Application do
             def start(_type, _args) do
               Supervisor.start_link([{Bandit, plug: Relay.Router}], strategy: :one_for_one)
             end
           end

           defmodule Relay.Router do
             def init(opts), do: opts
             def call(conn, _opts), do: conn
           end
           """}
        ]
      )

    finding = root |> scan!() |> finding!("EEF-CVE-2026-60102")

    assert finding.verdict == :potentially_reachable
    assert finding.reason == :active_network_daemon
    refute finding.verdict == :unreachable
  end

  @thousand_island %{
    name: "thousand_island",
    version: "1.3.5",
    ex: [
      {"lib/thousand_island/handler.ex",
       """
       defmodule ThousandIsland.Handler do
         @callback handle_data(term(), term(), term()) :: term()
       end
       """}
    ]
  }

  @bandit_daemon %{
    name: "bandit",
    version: "1.5.0",
    deps: [{"thousand_island", false}],
    applications: [:thousand_island],
    ex: [
      {"lib/bandit.ex",
       """
       defmodule Bandit do
         def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}
         def start_link(_opts), do: :ignore
       end
       """},
      {"lib/bandit/http2/handler.ex",
       """
       defmodule Bandit.HTTP2.Handler do
         @behaviour ThousandIsland.Handler

         def handle_data(data, _socket, state) do
           Bandit.HTTP2.Connection.handle_frame(data, state)
         end
       end

       defmodule Bandit.HTTP2.Connection do
         def handle_frame(data, state) do
           Bandit.HTTP2.Frame.Continuation.deserialize(9, 0, {data, state})
         end
       end

       defmodule Bandit.HTTP2.Frame.Continuation do
         def deserialize(_type, flags, payload), do: {:ok, {flags, payload}}
       end
       """}
    ]
  }

  test "3: a protocol handler chain starts at the child spec that starts Bandit" do
    root =
      mix_project!("relay",
        mod: "Relay.Application",
        applications: [:bandit],
        packages: [@thousand_island, @bandit_daemon],
        ex: [
          {"lib/relay/application.ex",
           """
           defmodule Relay.Application do
             def start(_type, _args) do
               Supervisor.start_link([{Bandit, plug: Relay.Router}], strategy: :one_for_one)
             end
           end
           """}
        ]
      )

    report = scan!(root)
    finding = finding!(report, "EEF-CVE-2026-60102")

    assert {finding.verdict, finding.reason} == {:reachable, :daemon_call_chain}

    assert [activation | chain] = finding.trace

    assert activation == %TraceHop{
             mfa: MFA.new("Elixir.Relay.Application", "start", 2),
             file: "lib/relay/application.ex",
             line: 3,
             kind: :daemon_activation,
             note: "starts Bandit"
           }

    assert Enum.map(chain, &{MFA.format(&1.mfa), &1.kind}) == [
             {"Bandit.HTTP2.Handler.handle_data/3", :entrypoint},
             {"Bandit.HTTP2.Connection.handle_frame/2", :static_call},
             {"Bandit.HTTP2.Frame.Continuation.deserialize/3", :static_call}
           ]

    config = %Config{format: :json}
    json = report |> VulnCheck.Report.JSON.render(config) |> JSON.decode!()
    [reported] = Enum.filter(json["findings"], &(&1["advisory_id"] == "EEF-CVE-2026-60102"))
    assert reported["reason"] == "daemon_call_chain"

    assert hd(reported["trace"]) == %{
             "mfa" => "Relay.Application.start/2",
             "file" => "lib/relay/application.ex",
             "line" => 3,
             "kind" => "daemon_activation",
             "note" => "starts Bandit"
           }

    sarif = report |> SARIF.render(config) |> JSON.decode!()

    [flow] =
      for run <- sarif["runs"],
          result <- run["results"],
          result["ruleId"] == "EEF-CVE-2026-60102",
          flow <- result["codeFlows"],
          do: flow

    [first, second | _] = hd(flow["threadFlows"])["locations"]
    assert {first["executionOrder"], first["kinds"]} == {0, ["daemon_activation"]}
    assert first["location"]["message"]["text"] == "0. Relay.Application.start/2 starts Bandit"
    assert {second["executionOrder"], second["kinds"]} == {1, ["enter"]}

    markdown = Markdown.render(report, config)

    assert markdown =~
             "| 0 | `Relay.Application.start/2` starts Bandit | `lib/relay/application.ex:3` |"
  end

  test "3: a call chain from the project wins over a shorter one from a daemon" do
    root =
      mix_project!("relay",
        mod: "Relay.Application",
        applications: [:bandit],
        packages: [@thousand_island, @bandit_daemon],
        ex: [
          {"lib/relay/application.ex",
           """
           defmodule Relay.Application do
             def start(_type, _args) do
               Relay.Frames.warm()
               Supervisor.start_link([{Bandit, plug: Relay.Router}], strategy: :one_for_one)
             end
           end

           defmodule Relay.Frames do
             def warm, do: prepare()
             defp prepare, do: decode()
             defp decode, do: Bandit.HTTP2.Frame.Continuation.deserialize(9, 0, "")
           end
           """}
        ]
      )

    finding = root |> scan!() |> finding!("EEF-CVE-2026-60102")

    assert {finding.verdict, finding.reason} == {:reachable, :call_chain_proven}
    assert hd(finding.trace).kind == :entrypoint
    assert hd(finding.trace).mfa == MFA.new("Elixir.Relay.Application", "start", 2)
    assert length(finding.trace) == 5
  end

  # -- 4. unconfigured transitive HTTP adapter ---------------------------------

  test "4: hackney under a Mint-configured Tesla is unreachable" do
    tesla = %{
      name: "tesla",
      version: "1.11.0",
      deps: [{"hackney", true}, {"mint", true}],
      optional_applications: [:hackney, :mint],
      ex: [
        {"lib/tesla.ex",
         """
         defmodule Tesla do
           def get(url) do
             adapter = Application.get_env(:tesla, :adapter, Tesla.Adapter.Httpc)
             adapter.call(%{url: url}, [])
           end
         end

         defmodule Tesla.Adapter.Httpc do
           def call(env, _opts), do: {:ok, env}
         end

         defmodule Tesla.Adapter.Hackney do
           def call(env, _opts), do: :hackney.request(:get, env.url, [], "", [])
         end

         defmodule Tesla.Adapter.Mint do
           def call(env, _opts), do: Mint.HTTP.connect(:https, env.url, 443)
         end
         """}
      ]
    }

    hackney = %{
      name: "hackney",
      version: "1.20.1",
      top_level: false,
      erl: [
        {"src/hackney.erl",
         """
         -module(hackney).
         -export([request/5]).

         request(Method, Url, _Headers, _Body, _Opts) ->
             {Method, hackney_url:parse_url(Url)}.
         """},
        {"src/hackney_url.erl",
         """
         -module(hackney_url).
         -export([parse_url/1]).

         parse_url(Url) -> {url, Url}.
         """}
      ]
    }

    mint = %{
      name: "mint",
      version: "1.6.2",
      top_level: false,
      ex: [
        {"lib/mint.ex",
         "defmodule Mint.HTTP do\n  def connect(scheme, host, port), do: {:ok, {scheme, host, port}}\nend\n"}
      ]
    }

    root =
      mix_project!("billing",
        mod: "Billing.Application",
        applications: [:tesla],
        packages: [tesla, hackney, mint],
        files: [
          {"config/config.exs", "import Config\nconfig :tesla, adapter: Tesla.Adapter.Mint\n"}
        ],
        ex: [
          {"lib/billing.ex",
           """
           defmodule Billing.Application do
             def start(_type, _args), do: Billing.Client.fetch("https://api.example.com")
           end

           defmodule Billing.Client do
             def fetch(url), do: Tesla.get(url)
           end
           """}
        ]
      )

    report = scan!(root)
    finding = finding!(report, "EEF-CVE-2026-60103")

    assert report.workspace.packages["hackney"].scope == :prod
    assert finding.verdict == :unreachable
    assert finding.reason == :adapter_not_configured
  end

  # -- 5. dev/test isolation ---------------------------------------------------

  test "5: a test-only dependency is unreachable" do
    root =
      mix_project!("catalog",
        packages: [%{name: "meck", version: "0.9.2", only: :test}],
        ex: [{"lib/catalog.ex", "defmodule Catalog do\n  def list, do: []\nend\n"}]
      )

    finding = root |> scan!() |> finding!("EEF-CVE-2026-60104")

    assert finding.package_scope == :non_prod
    assert finding.verdict == :unreachable
    assert finding.reason == :non_prod_dependency
  end

  # -- 6. OTP release gating ---------------------------------------------------

  test "6: an OTP <= 25 advisory depends on the target OTP release" do
    hex_core = %{
      name: "hex_core",
      version: "0.10.0",
      erl: [
        {"src/hex_core.erl",
         ~S"""
         -module(hex_core).
         -export([default_config/0]).

         default_config() -> #{http_adapter => {hex_http_httpc, #{}}}.
         """}
      ]
    }

    root =
      mix_project!("publisher",
        mod: "Publisher.Application",
        applications: [:hex_core],
        packages: [hex_core],
        ex: [
          {"lib/publisher.ex",
           """
           defmodule Publisher.Application do
             def start(_type, _args), do: Publisher.config()
           end

           defmodule Publisher do
             def config, do: :hex_core.default_config()
           end
           """}
        ]
      )

    modern = root |> scan!(otp_version: "27") |> finding!("EEF-CVE-2026-103502")
    assert modern.verdict == :unreachable
    assert modern.reason == :otp_version_unaffected

    legacy = root |> scan!(otp_version: "25") |> finding!("EEF-CVE-2026-103502")
    assert legacy.verdict == :reachable
    assert List.last(legacy.trace).mfa == MFA.new("hex_core", "default_config", 0)
  end

  # -- 7. soundness guards -----------------------------------------------------

  test "7A: apply/3 on a computed module is potentially reachable" do
    jose = %{
      name: "jose",
      version: "1.11.10",
      ex: [
        {"lib/jose.ex",
         """
         defmodule JOSE.JWT do
           def decode(token), do: {:jwt, token}
         end

         defmodule JOSE.JWS do
           def decode(token), do: {:jws, token}
         end
         """}
      ]
    }

    root =
      mix_project!("gateway",
        mod: "Gateway.Application",
        applications: [:jose],
        packages: [jose],
        ex: [
          {"lib/gateway.ex",
           """
           defmodule Gateway.Application do
             def start(_type, _args), do: Gateway.Token.verify("JWS", "token")
           end

           defmodule Gateway.Token do
             def verify(kind, payload) do
               dynamic_mod = Module.concat(JOSE, kind)
               apply(dynamic_mod, :decode, [payload])
             end
           end
           """}
        ]
      )

    finding = root |> scan!() |> finding!("EEF-CVE-2026-60105")

    assert finding.verdict == :potentially_reachable
    assert finding.reason == :unresolved_dynamic_dispatch

    assert finding.reason_detail =~
             "Gateway.Token.verify/2 makes a dynamic call at lib/gateway.ex:8"

    assert List.last(finding.trace).mfa == MFA.new("Elixir.Gateway.Token", "verify", 2)
  end

  test "7B: a dependency stripped of debug info is never skipped silently" do
    decimal = %{
      name: "decimal",
      version: "2.1.1",
      strip: true,
      ex: [
        {"lib/decimal.ex",
         """
         defmodule Decimal do
           def parse(string), do: Decimal.Parser.digits(string, [])
         end

         defmodule Decimal.Parser do
           def digits(string, acc), do: {string, acc}
         end
         """}
      ]
    }

    root =
      mix_project!("pricing",
        mod: "Pricing.Application",
        applications: [:decimal],
        packages: [decimal],
        ex: [
          {"lib/pricing.ex",
           """
           defmodule Pricing.Application do
             def start(_type, _args), do: Pricing.amount("12.50")
           end

           defmodule Pricing do
             def amount(input), do: Decimal.parse(input)
           end
           """}
        ]
      )

    report = scan!(root)
    finding = finding!(report, "EEF-CVE-2026-60106")

    assert report.stats.without_debug_info == 2
    assert finding.verdict == :potentially_reachable
    assert finding.reason == :missing_beam_debug_info
  end
end
