defmodule VulnCheck.Beam.ExtractorTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Beam.{AbstractWalker, CallGraph, Loader}
  alias VulnCheck.Config
  alias VulnCheck.Test.Tmp
  alias VulnCheck.Types.{CallEdge, DynamicCall, Entrypoint, MFA, ModuleSummary, TraceHop}

  doctest VulnCheck.Beam.AbstractWalker

  @source """
  defmodule BeamFixture.Target do
    def secret_op(a, b), do: a + b
    def run(x), do: x
  end

  defmodule BeamFixture.Macros do
    defmacro double(x) do
      quote do: BeamFixture.Target.secret_op(unquote(x), unquote(x))
    end
  end

  defmodule BeamFixture.B do
    def mid(x) do
      x
      |> BeamFixture.Target.secret_op(2)
    end
  end

  defmodule BeamFixture.A do
    require BeamFixture.Macros

    def entry, do: BeamFixture.B.mid(1)
    def via_macro, do: BeamFixture.Macros.double(3)
    def capture, do: Enum.reduce([1, 2], 0, &BeamFixture.Target.secret_op/2)
    def static_apply, do: apply(BeamFixture.Target, :secret_op, [1, 2])
    def dynamic(mod, arg), do: apply(mod, :run, [arg])

    def propagated do
      target = BeamFixture.Target
      target.run(1)
    end

    def spawned, do: spawn(BeamFixture.Target, :run, [:x])
  end

  defmodule BeamFixture.Sup do
    use Supervisor

    def start_link(arg), do: Supervisor.start_link(__MODULE__, arg, name: __MODULE__)

    @impl true
    def init(_arg) do
      children = [BeamFixture.Worker, {BeamFixture.B, []}]
      Supervisor.init(children, strategy: :one_for_one)
    end
  end
  """

  @erlang """
  -module(beam_fixture_erl).
  -export([go/1, cap/0]).
  -import(lists, [reverse/1]).

  go(X) ->
      M = beam_fixture_dep,
      _ = length(X),
      _ = reverse(X),
      spawn(beam_fixture_dep, loop, [X, 1]),
      M:handle(X).

  cap() -> fun beam_fixture_dep:handle/1.
  """

  setup_all do
    root = Tmp.mkdir!("beam-project")
    ebin = Path.join(root, "_build/prod/lib/beam_fixture/ebin")
    File.mkdir_p!(ebin)
    source = Path.join(root, "lib/beam_fixture.ex")
    File.mkdir_p!(Path.dirname(source))
    File.write!(source, @source)

    # `mix test` compiles without debug info; fixtures need it like a release build.
    previous = Code.get_compiler_option(:debug_info)
    Code.put_compiler_option(:debug_info, true)

    try do
      {:ok, _modules, _diagnostics} =
        Kernel.ParallelCompiler.compile_to_path([source], ebin, return_diagnostics: true)
    after
      Code.put_compiler_option(:debug_info, previous)
    end

    erl = Path.join(root, "src/beam_fixture_erl.erl")
    File.mkdir_p!(Path.dirname(erl))
    File.write!(erl, @erlang)

    {:ok, :beam_fixture_erl} =
      :compile.file(String.to_charlist(erl), [:debug_info, {:outdir, String.to_charlist(ebin)}])

    %{root: root, ebin: ebin}
  end

  defp line_of(fragment) do
    @source
    |> String.split("\n")
    |> Enum.find_index(&String.contains?(&1, fragment))
    |> Kernel.+(1)
  end

  defp load(%{root: root, ebin: ebin}) do
    Loader.load_dirs([{nil, ebin}], root_dir: root)
  end

  defp mfa(m, f, a), do: MFA.new(m, f, a)

  test "extracts static edges with exact files and lines", ctx do
    %{modules: modules, warnings: [], stats: stats} = load(ctx)
    assert stats.analyzed == stats.beams
    assert stats.failed == 0

    graph = CallGraph.build(modules)
    target = mfa("Elixir.BeamFixture.Target", "secret_op", 2)

    edges =
      graph
      |> CallGraph.callers(target)
      |> Enum.map(&{MFA.format(&1.from), &1.file, &1.line, &1.kind})
      |> Enum.sort()

    assert edges == [
             {"BeamFixture.A.capture/0", "lib/beam_fixture.ex", line_of("def capture"),
              :static_call},
             {"BeamFixture.A.static_apply/0", "lib/beam_fixture.ex", line_of("def static_apply"),
              :dynamic_apply},
             {"BeamFixture.A.via_macro/0", "lib/beam_fixture.ex", line_of("def via_macro"),
              :static_call},
             {"BeamFixture.B.mid/1", "lib/beam_fixture.ex",
              line_of("|> BeamFixture.Target.secret_op(2)"), :static_call}
           ]

    a = modules["Elixir.BeamFixture.A"]
    assert a.source_file == "lib/beam_fixture.ex"
    assert a.has_debug_info
    assert {"entry", 0} in a.exports
    assert is_binary(a.sha256) and byte_size(a.sha256) == 64

    assert [
             %DynamicCall{
               caller: %MFA{function: "dynamic", arity: 2},
               known_module: nil,
               known_function: "run",
               arity: 1,
               file: "lib/beam_fixture.ex"
             } = dynamic
           ] = a.dynamic_dispatches

    assert dynamic.line == line_of("def dynamic")

    # constant propagation of `target = BeamFixture.Target; target.run(1)`
    assert %CallEdge{kind: :dynamic_apply, line: line} =
             Enum.find(a.edges, &(&1.from.function == "propagated"))

    assert line == line_of("target.run(1)")

    # spawn/3 triples become references
    assert Enum.any?(a.mfa_refs, &(&1.to == mfa("Elixir.BeamFixture.Target", "run", 1)))
  end

  test "reconstructs the shortest call chain", ctx do
    graph = ctx |> load() |> Map.fetch!(:modules) |> CallGraph.build()
    entry = %Entrypoint{mfa: mfa("Elixir.BeamFixture.A", "entry", 0), kind: :entrypoint}

    assert {:ok, hops} =
             CallGraph.shortest_path(graph, [entry], [
               mfa("Elixir.BeamFixture.Target", "secret_op", 2)
             ])

    assert [
             %TraceHop{
               mfa: %MFA{module: "Elixir.BeamFixture.A", function: "entry"},
               kind: :entrypoint
             },
             %TraceHop{mfa: %MFA{module: "Elixir.BeamFixture.B", function: "mid"}, line: l1},
             %TraceHop{
               mfa: %MFA{module: "Elixir.BeamFixture.Target", function: "secret_op"},
               line: l2
             }
           ] = hops

    assert l1 == line_of("def entry")
    assert l2 == line_of("|> BeamFixture.Target.secret_op(2)")

    assert CallGraph.shortest_path(graph, [mfa("Elixir.BeamFixture.Target", "run", 1)], [
             mfa("Elixir.BeamFixture.A", "entry", 0)
           ]) == :none

    assert {:ok, [%TraceHop{kind: :entrypoint}]} =
             CallGraph.shortest_path(graph, [entry], [entry.mfa])

    reachable = CallGraph.reachable(graph, [entry])
    assert mfa("Elixir.BeamFixture.Target", "secret_op", 2) in reachable
    refute mfa("Elixir.BeamFixture.Target", "run", 1) in reachable
    assert "Elixir.BeamFixture.B" in CallGraph.reachable_modules(reachable)
  end

  test "records supervisor children and behaviours", ctx do
    %{modules: modules} = load(ctx)
    sup = modules["Elixir.BeamFixture.Sup"]

    assert "Elixir.Supervisor" in sup.behaviours

    assert {_caller, %MFA{module: "Elixir.Supervisor", function: "init", arity: 2}, [children, _],
            _file, _line} =
             Enum.find(sup.init_literals, &(elem(&1, 1).function == "init"))

    assert children == [
             {:atom, "Elixir.BeamFixture.Worker"},
             {:tuple, [{:atom, "Elixir.BeamFixture.B"}, []]}
           ]

    assert Enum.any?(sup.module_refs, fn {_, mod, _, _} -> mod == "Elixir.BeamFixture.Worker" end)
  end

  test "understands Erlang modules", ctx do
    %{modules: modules} = load(ctx)
    erl = modules["beam_fixture_erl"]
    assert erl.source_file == "src/beam_fixture_erl.erl"

    targets = erl.edges |> Enum.map(&{&1.from.function, MFA.format(&1.to), &1.kind}) |> Enum.sort()

    assert {"go", ":erlang.length/1", :static_call} in targets
    assert {"go", ":lists.reverse/1", :static_call} in targets
    assert {"go", ":beam_fixture_dep.handle/1", :dynamic_apply} in targets
    assert {"cap", ":beam_fixture_dep.handle/1", :static_call} in targets
    assert Enum.any?(erl.mfa_refs, &(MFA.format(&1.to) == ":beam_fixture_dep.loop/2"))
    assert erl.dynamic_dispatches == []
  end

  test "stripped beams fall back to the imports table", ctx do
    stripped_dir = Tmp.mkdir!("beam-stripped")

    for module <- ~w(Elixir.BeamFixture.B Elixir.BeamFixture.Target) do
      File.cp!(Path.join(ctx.ebin, module <> ".beam"), Path.join(stripped_dir, module <> ".beam"))
    end

    {:ok, _} =
      :beam_lib.strip(String.to_charlist(Path.join(stripped_dir, "Elixir.BeamFixture.B.beam")))

    %{modules: modules, stats: stats} = Loader.load_dirs([{"dep", stripped_dir}])
    assert stats.without_debug_info == 1

    b = modules["Elixir.BeamFixture.B"]
    assert %ModuleSummary{has_debug_info: false, edges: [], package: "dep"} = b
    assert {"Elixir.BeamFixture.Target", "secret_op", 2} in b.imports
    assert {"mid", 1} in b.exports

    graph = CallGraph.build(modules)

    assert {:ok, [_, %TraceHop{kind: :imports}]} =
             CallGraph.shortest_path(graph, [mfa("Elixir.BeamFixture.B", "mid", 1)], [
               mfa("Elixir.BeamFixture.Target", "secret_op", 2)
             ])
  end

  test "summaries are cached by content hash without creating atoms", ctx do
    config = %Config{project_dir: ctx.root, cache_dir: Tmp.mkdir!("beam-cache")}
    path = Path.join(ctx.ebin, "Elixir.BeamFixture.A.beam")

    assert {:ok, first, :analyzed} = Loader.load_file(path, cache: config, root_dir: ctx.root)
    assert {:ok, second, :cached} = Loader.load_file(path, cache: config, root_dir: ctx.root)
    assert second == first

    # a different root yields a different cache entry (relative paths depend on it)
    assert {:ok, _, :analyzed} = Loader.load_file(path, cache: config, root_dir: "/elsewhere")

    [entry | _] = Path.wildcard(Path.join(VulnCheck.Cache.beam_dir(config), "*.etf"))

    assert {:vulncheck_beam, 1, _, %ModuleSummary{}} =
             :erlang.binary_to_term(File.read!(entry), [:safe])
  end

  test "workspace loading merges consolidated protocols and reports bad files", ctx do
    bad_dir = Tmp.mkdir!("beam-bad")
    File.write!(Path.join(bad_dir, "Elixir.Broken.beam"), "not a beam")
    consolidated = Tmp.mkdir!("beam-consolidated")

    File.cp!(
      Path.join(ctx.ebin, "Elixir.BeamFixture.B.beam"),
      Path.join(consolidated, "Elixir.BeamFixture.B.beam")
    )

    ws = %VulnCheck.Types.Workspace{
      root_dir: ctx.root,
      project_name: "beam_fixture",
      project_type: :mix,
      env: :prod,
      otp_release: "27",
      root_ebin_dirs: [ctx.ebin],
      consolidated_dirs: [consolidated],
      packages: %{
        "broken" => %VulnCheck.Types.Package{
          name: "broken",
          version: "1.0.0",
          source: :hex,
          scope: :prod,
          ebin_dir: bad_dir
        },
        "dup" => %VulnCheck.Types.Package{
          name: "dup",
          version: "1.0.0",
          source: :hex,
          scope: :prod,
          ebin_dir: consolidated
        }
      }
    }

    result = Loader.load_workspace(ws)
    assert result.modules["Elixir.BeamFixture.B"].beam_path =~ "beam-consolidated"
    assert result.modules["Elixir.BeamFixture.B"].package == nil
    assert result.stats.failed == 1
    assert Enum.any?(result.warnings, &(&1 =~ "could not read"))
    assert Enum.any?(result.warnings, &(&1 =~ "is defined in both"))
  end

  test "walks hand-written forms" do
    forms = [
      {:attribute, 1, :file, {~c"/abs/root/lib/x.ex", 1}},
      {:attribute, 1, :module, :x},
      {:attribute, 1, :behaviour, :gen_server},
      {:function, 2, :f, 1,
       [
         {:clause, 2, [{:var, 2, :M}], [],
          [
            {:call, 3, {:remote, 3, {:var, 3, :M}, {:var, 3, :F}}, []},
            {:call, 4, {:remote, 4, {:atom, 4, :erlang}, {:atom, 4, :apply}},
             [{:atom, 4, :y}, {:var, 4, :Fun}, {:var, 4, :Args}]},
            {:fun, 5, {:function, {:atom, 5, :y}, {:var, 5, :G}, {:integer, 5, 1}}},
            {:tuple, 6, [{:atom, 6, :y}, {:atom, 6, :start}, {:integer, 6, 2}]}
          ]}
       ]}
    ]

    summary = AbstractWalker.summarize(:x, forms, root_dir: "/abs/root")
    assert summary.source_file == "lib/x.ex"
    assert summary.behaviours == ["gen_server"]

    assert [
             %DynamicCall{known_module: nil, known_function: nil, arity: 0, line: 3},
             %DynamicCall{known_module: "y", known_function: nil, arity: nil, line: 4},
             %DynamicCall{known_module: "y", known_function: nil, arity: 1, line: 5}
           ] = summary.dynamic_dispatches

    assert [%CallEdge{to: %MFA{module: "y", function: "start", arity: 2}}] = summary.mfa_refs
  end
end
