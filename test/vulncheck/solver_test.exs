defmodule VulnCheck.SolverTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Beam.{CallGraph, Loader}
  alias VulnCheck.{Config, Entrypoints, Solver}
  alias VulnCheck.Test.{Beams, Tmp}

  alias VulnCheck.Types.{
    Advisory,
    Finding,
    MFA,
    Package,
    Retirement,
    ScanReport,
    TraceHop,
    Workspace
  }

  defp ebin(root, app), do: Path.join(root, "_build/prod/lib/#{app}/ebin")
  defp mfa(m, f, a), do: MFA.new(m, f, a)

  setup_all do
    root = Tmp.mkdir!("solver-world")

    Beams.compile!(ebin(root, "sol_ash"), [
      {"ash.ex",
       """
       defmodule SolFix.Ash do
         def read(query, opts), do: SolFix.Ash.Actions.Read.run(query, opts)
         def count(query, opts), do: SolFix.Ash.Actions.Aggregate.run(query, opts, :count, [])
       end

       defmodule SolFix.Ash.Actions.Read do
         def run(query, _opts), do: query
       end

       defmodule SolFix.Ash.Actions.Aggregate do
         def run(query, _opts, _kind, _extra), do: query
       end
       """}
    ])

    Beams.write_app!(ebin(root, "sol_ash"), "sol_ash")

    Beams.compile!(ebin(root, "sol_parsers"), [
      {"parsers.ex",
       """
       defmodule SolFix.Parsers.JSON do
         def parse(body), do: body
       end

       defmodule SolFix.Parsers.MULTIPART do
         def parse(body), do: body
       end
       """}
    ])

    Beams.write_app!(ebin(root, "sol_parsers"), "sol_parsers")

    Beams.compile!(ebin(root, "sol_bandit"), [
      {"bandit.ex",
       """
       defmodule SolFix.Bandit.HTTP1 do
         def parse_request(data, state), do: {data, state}
       end
       """}
    ])

    Beams.write_app!(ebin(root, "sol_bandit"), "sol_bandit")

    Beams.compile!(ebin(root, "sol_plugin"), [
      {"plugin.ex", "defmodule SolFix.Plugin do\n  def handle(x), do: x\nend\n"}
    ])

    Beams.write_app!(ebin(root, "sol_plugin"), "sol_plugin")

    Beams.compile!(ebin(root, "sol_unused"), [
      {"unused.ex", "defmodule SolFix.Unused do\n  def go, do: :ok\nend\n"}
    ])

    Beams.write_app!(ebin(root, "sol_unused"), "sol_unused")

    Beams.compile!(ebin(root, "hackney"), [
      {"hackney.ex", "defmodule SolFix.Hackney do\n  def request(x), do: x\nend\n"}
    ])

    Beams.compile!(ebin(root, "sol_json"), [
      {"json.ex", "defmodule SolFix.Json do\n  def decode(x), do: x\nend\n"}
    ])

    Beams.write_app!(ebin(root, "sol_json"), "sol_json")

    Beams.compile!(ebin(root, "sol_legacy"), [
      {"legacy.ex",
       """
       defmodule SolFix.Legacy.Api do
         def call(x), do: SolFix.Legacy.Internal.parse(x)
       end

       defmodule SolFix.Legacy.Internal do
         def parse(x), do: x
         def other(x), do: x
       end
       """}
    ])

    for module <- ~w(Elixir.SolFix.Legacy.Api Elixir.SolFix.Legacy.Internal) do
      {:ok, _} =
        :beam_lib.strip(String.to_charlist(Path.join(ebin(root, "sol_legacy"), module <> ".beam")))
    end

    Beams.write_app!(ebin(root, "sol_legacy"), "sol_legacy")

    Beams.compile!(ebin(root, "sol_app"), [
      {"app.ex",
       """
       defmodule SolFix.Application do
         use Application

         def start(_type, _args) do
           SolFix.Worker.start_link([])
           SolFix.Endpoint.call(:conn, [])
           SolFix.Legacy.Api.call(1)
           SolFix.Json.decode("{}")
           SolFix.Dyn.run("Elixir.SolFix.Plugin", 1)
           {:ok, self()}
         end
       end

       defmodule SolFix.Worker do
         use GenServer

         def start_link(arg), do: GenServer.start_link(__MODULE__, arg)
         def init(arg), do: {:ok, arg}
         def handle_call(:read, _from, state), do: {:reply, SolFix.Ash.read(state, []), state}
       end

       defmodule SolFix.Endpoint do
         def call(conn, _opts), do: SolFix.Parsers.JSON.parse(conn)
       end

       defmodule SolFix.Dyn do
         def run(name, arg) do
           module = String.to_atom(name)
           module.handle(arg)
         end
       end
       """}
    ])

    Beams.write_app!(ebin(root, "sol_app"), "sol_app",
      applications:
        ~w(kernel stdlib elixir sol_ash sol_parsers sol_bandit sol_plugin sol_json sol_legacy)a,
      mod: "Elixir.SolFix.Application"
    )

    File.mkdir_p!(Path.join(root, "config"))

    File.write!(
      Path.join(root, "config/prod.exs"),
      "import Config\nconfig :tesla, adapter: Tesla.Adapter.Mint\n"
    )

    pkg = fn name, extra ->
      struct(
        %Package{
          name: name,
          version: "1.0.0",
          source: :hex,
          scope: :prod,
          otp_app: name,
          ebin_dir: if(File.dir?(ebin(root, name)), do: ebin(root, name))
        },
        extra
      )
    end

    packages = [
      pkg.("sol_ash", []),
      pkg.("sol_parsers", []),
      pkg.("sol_bandit", []),
      pkg.("sol_plugin", []),
      pkg.("sol_unused", []),
      pkg.("sol_json", []),
      pkg.("sol_legacy", []),
      pkg.("hackney", []),
      pkg.("mint", []),
      pkg.("tesla", optional_deps: ["hackney", "mint"]),
      pkg.("meck", scope: :non_prod),
      pkg.("hex_core", [])
    ]

    ws = %Workspace{
      root_dir: root,
      project_name: "sol_app",
      project_type: :mix,
      env: :prod,
      otp_release: "27",
      root_apps: ["sol_app"],
      root_ebin_dirs: [ebin(root, "sol_app")],
      packages: Map.new(packages, &{&1.name, &1})
    }

    %{modules: modules} = Loader.load_workspace(ws)
    {model, graph} = Entrypoints.build(ws, CallGraph.build(modules), nil)

    model = %{
      model
      | active_daemon_packages: Enum.uniq(["sol_bandit" | model.active_daemon_packages])
    }

    %{ws: ws, graph: graph, model: model}
  end

  defp solve(ctx, advisories, config \\ %Config{}) do
    Solver.solve(ctx.ws, ctx.graph, ctx.model, advisories, config)
  end

  defp one(ctx, advisory), do: ctx |> solve([advisory]) |> hd()

  defp advisory(id, package, fields \\ []) do
    struct(%Advisory{id: id, package: package, severity: :high, summary: id}, fields)
  end

  test "call_chain_proven with the shortest trace", ctx do
    finding =
      one(
        ctx,
        advisory("A-1", "sol_ash",
          affected_routines: [mfa("Elixir.SolFix.Ash.Actions.Read", "run", 2)]
        )
      )

    assert %Finding{verdict: :reachable, reason: :call_chain_proven} = finding
    assert finding.target_mfa == mfa("Elixir.SolFix.Ash.Actions.Read", "run", 2)

    assert Enum.map(finding.trace, &{MFA.format(&1.mfa), &1.kind}) == [
             {"SolFix.Application.start/2", :entrypoint},
             {"SolFix.Worker.start_link/1", :static_call},
             {"SolFix.Worker.handle_call/3", :behaviour_callback},
             {"SolFix.Ash.read/2", :static_call},
             {"SolFix.Ash.Actions.Read.run/2", :static_call}
           ]

    # each hop shows the call site inside that function; the target shows its definition
    [start, start_link, handle_call, read, run] = finding.trace
    assert {start.file, start.line} == {"_build/prod/lib/sol_app/src/app.ex", 5}
    assert {start_link.file, start_link.line} == {nil, nil}
    assert handle_call.line == 19
    assert read.line == 2
    assert {run.file, run.line} == {"_build/prod/lib/sol_ash/src/ash.ex", 7}
    assert %TraceHop{kind: :static_call} = run

    assert finding.fingerprint ==
             Finding.fingerprint("A-1", "sol_ash", :reachable, finding.target_mfa)
  end

  test "function_not_called when the package is used but not the routine", ctx do
    finding =
      one(
        ctx,
        advisory("A-2", "sol_ash",
          affected_routines: [mfa("Elixir.SolFix.Ash.Actions.Aggregate", "run", 4)]
        )
      )

    assert %Finding{verdict: :unreachable, reason: :function_not_called} = finding
    assert finding.reason_detail =~ "SolFix.Ash.Actions.Aggregate.run/4"
  end

  test "module_not_loaded for an unused parser module", ctx do
    finding =
      one(
        ctx,
        advisory("A-3", "sol_parsers", affected_modules: ["Elixir.SolFix.Parsers.MULTIPART"])
      )

    assert %Finding{verdict: :unreachable, reason: :module_not_loaded} = finding
  end

  test "module-level data on a used module stays potentially reachable", ctx do
    finding =
      one(ctx, advisory("A-4", "sol_parsers", affected_modules: ["Elixir.SolFix.Parsers.JSON"]))

    assert %Finding{verdict: :potentially_reachable, reason: :missing_symbol_granularity} = finding
    assert finding.target_mfa == mfa("Elixir.SolFix.Parsers.JSON", "parse", 1)
    assert List.last(finding.trace).mfa == finding.target_mfa
  end

  test "adapter_not_configured for an unused Tesla adapter", ctx do
    finding =
      one(
        ctx,
        advisory("A-5", "hackney", affected_routines: [mfa("Elixir.SolFix.Hackney", "request", 1)])
      )

    assert %Finding{verdict: :unreachable, reason: :adapter_not_configured} = finding
    assert finding.reason_detail =~ "Tesla.Adapter.Mint"
  end

  test "non_prod_dependency and otp_version_unaffected", ctx do
    [meck] = solve(ctx, [advisory("A-6", "meck")])

    assert %Finding{verdict: :unreachable, reason: :non_prod_dependency, package_scope: :non_prod} =
             meck

    [hex_core] = solve(ctx, [advisory("A-7", "hex_core", otp_constraints: "<= 25")])
    assert %Finding{verdict: :unreachable, reason: :otp_version_unaffected} = hex_core
    assert hex_core.reason_detail =~ "OTP 27"

    [forced] =
      solve(ctx, [advisory("A-7", "hex_core", otp_constraints: "<= 25")], %Config{otp_version: "25"})

    refute forced.reason == :otp_version_unaffected
  end

  test "otp_app_not_started for a dependency outside the boot tree", ctx do
    finding =
      one(
        ctx,
        advisory("A-8", "sol_unused", affected_routines: [mfa("Elixir.SolFix.Unused", "go", 0)])
      )

    assert %Finding{verdict: :unreachable, reason: :otp_app_not_started} = finding
  end

  test "active_network_daemon for a started daemon package", ctx do
    finding =
      one(
        ctx,
        advisory("A-9", "sol_bandit",
          affected_routines: [mfa("Elixir.SolFix.Bandit.HTTP1", "parse_request", 2)]
        )
      )

    assert %Finding{verdict: :potentially_reachable, reason: :active_network_daemon} = finding
  end

  test "unresolved_dynamic_dispatch for a computed module call", ctx do
    finding =
      one(
        ctx,
        advisory("A-10", "sol_plugin",
          affected_routines: [mfa("Elixir.SolFix.Plugin", "handle", 1)]
        )
      )

    assert %Finding{verdict: :potentially_reachable, reason: :unresolved_dynamic_dispatch} = finding
    assert finding.reason_detail =~ "SolFix.Dyn.run/2"
    assert List.last(finding.trace).mfa == mfa("Elixir.SolFix.Dyn", "run", 2)
  end

  test "missing_beam_debug_info for stripped dependencies", ctx do
    finding =
      one(
        ctx,
        advisory("A-11", "sol_legacy",
          affected_routines: [mfa("Elixir.SolFix.Legacy.Internal", "other", 1)]
        )
      )

    assert %Finding{verdict: :potentially_reachable, reason: :missing_beam_debug_info} = finding
  end

  test "missing_symbol_granularity without any symbol data", ctx do
    finding = one(ctx, advisory("A-12", "sol_json"))
    assert %Finding{verdict: :potentially_reachable, reason: :missing_symbol_granularity} = finding
    assert finding.target_mfa == mfa("Elixir.SolFix.Json", "decode", 1)

    text =
      one(
        ctx,
        advisory("A-13", "sol_json",
          affected_routines: [mfa("Elixir.SolFix.Json", "other", 1)],
          symbol_source: :text
        )
      )

    assert text.reason == :missing_symbol_granularity
  end

  test "package_retired and report ordering", ctx do
    retired =
      advisory("HEX-RETIRED-sol_ash-1.0.0", "sol_ash",
        severity: :low,
        retirement: %Retirement{package: "sol_ash", version: "1.0.0", reason: :deprecated}
      )

    findings =
      solve(ctx, [
        retired,
        advisory("A-2", "sol_ash",
          severity: :critical,
          affected_routines: [mfa("Elixir.SolFix.Ash.Actions.Aggregate", "run", 4)]
        ),
        advisory("A-12", "sol_json", severity: :low),
        advisory("A-14", "sol_json", severity: :unknown),
        advisory("A-1", "sol_ash",
          severity: :medium,
          affected_routines: [mfa("Elixir.SolFix.Ash.Actions.Read", "run", 2)]
        )
      ])

    assert Enum.map(findings, &{&1.advisory_id, &1.verdict}) == [
             {"A-1", :reachable},
             {"A-14", :potentially_reachable},
             {"A-12", :potentially_reachable},
             {"HEX-RETIRED-sol_ash-1.0.0", :retired},
             {"A-2", :unreachable}
           ]

    assert Enum.find(findings, &(&1.verdict == :retired)).reason == :package_retired
  end

  test "missing builds keep packages potentially reachable", ctx do
    ws = %{
      ctx.ws
      | packages:
          Map.put(ctx.ws.packages, "ghost", %Package{
            name: "ghost",
            version: "1.0.0",
            source: :hex,
            scope: :prod
          })
    }

    model = %{ctx.model | boot_tree_known: false}
    [finding] = Solver.solve(ws, ctx.graph, model, [advisory("A-15", "ghost")], %Config{})
    assert %Finding{verdict: :potentially_reachable, reason: :missing_beam_debug_info} = finding
    assert finding.reason_detail =~ "no compiled .beam files"

    [nil_graph] = Solver.solve(ws, nil, nil, [advisory("A-15", "ghost")], %Config{})
    assert nil_graph.verdict == :potentially_reachable
  end

  describe "should_fail?/2" do
    defp report(findings), do: %ScanReport{findings: findings}

    defp finding(verdict, severity, extra \\ []) do
      struct(
        %Finding{
          advisory_id: "X",
          package: "p",
          installed_version: "1",
          severity: severity,
          verdict: verdict,
          reason: :call_chain_proven
        },
        extra
      )
    end

    test "honors fail_on, min_severity, suppressions and policy violations" do
      reachable = finding(:reachable, :high)
      potentially = finding(:potentially_reachable, :medium)
      unreachable = finding(:unreachable, :critical)

      assert VulnCheck.should_fail?(report([potentially]), %Config{})
      refute VulnCheck.should_fail?(report([potentially]), %Config{fail_on: :reachable})
      assert VulnCheck.should_fail?(report([reachable]), %Config{fail_on: :reachable})
      refute VulnCheck.should_fail?(report([reachable]), %Config{min_severity: :critical})

      assert VulnCheck.should_fail?(report([finding(:reachable, :unknown)]), %Config{
               min_severity: :critical
             })

      refute VulnCheck.should_fail?(report([unreachable]), %Config{})
      assert VulnCheck.should_fail?(report([unreachable]), %Config{fail_on: :any})
      refute VulnCheck.should_fail?(report([reachable]), %Config{fail_on: :none})
      refute VulnCheck.should_fail?(report([%{reachable | suppressed: true}]), %Config{})

      assert VulnCheck.should_fail?(
               %{report([]) | policy_violations: ["new suppression"]},
               %Config{}
             )

      retired = finding(:retired, :high, reason: :package_retired)
      assert VulnCheck.should_fail?(report([retired]), %Config{})
      refute VulnCheck.should_fail?(report([retired]), %Config{fail_on_retired: false})
    end
  end
end
