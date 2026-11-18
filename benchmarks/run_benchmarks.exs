# Reproducible performance and memory benchmarks.
#
#     mix run benchmarks/run_benchmarks.exs
#     mix run benchmarks/run_benchmarks.exs --profile large --iterations 10
#     mix run benchmarks/run_benchmarks.exs --profile all --markdown
#
# A synthetic compiled workspace (Mix project, lockfile, `.app` files and
# `.beam` files with debug info) and an offline advisory cache are generated
# in a temporary directory, then every pipeline stage is timed with
# `:timer.tc/1`. The `libraries` profile measures the `.beam` summary cache
# on the Elixir and Erlang/OTP libraries installed with the running VM.
# Only the standard library is used.

defmodule VulnCheck.Bench do
  alias VulnCheck.{Config, Scanner, Solver}
  alias VulnCheck.Beam.{CallGraph, Loader}
  alias VulnCheck.Feeds.Store

  @profiles %{
    "medium" => %{packages: 80, modules: 5, functions: 10, root_modules: 20, advisories: 50},
    "large" => %{packages: 180, modules: 5, functions: 12, root_modules: 100, advisories: 120},
    "umbrella" => %{
      packages: 180,
      modules: 5,
      functions: 12,
      root_modules: 99,
      advisories: 120,
      umbrella_apps: 3
    }
  }

  @sha String.duplicate("5f", 32)

  def main(argv) do
    {opts, _args, _invalid} =
      OptionParser.parse(argv,
        strict: [profile: :string, iterations: :integer, markdown: :boolean, keep: :boolean]
      )

    iterations = Keyword.get(opts, :iterations, 10)

    profiles =
      case Keyword.get(opts, :profile, "medium") do
        "all" ->
          ["medium", "large", "umbrella", "libraries"]

        name when is_map_key(@profiles, name) or name == "libraries" ->
          [name]

        other ->
          raise ArgumentError,
                "unknown profile #{inspect(other)} (medium, large, umbrella, libraries, all)"
      end

    results =
      Enum.map(profiles, fn
        "libraries" -> run_libraries(iterations)
        name -> run_profile(name, Map.fetch!(@profiles, name), iterations, opts)
      end)

    if Keyword.get(opts, :markdown, false),
      do: IO.puts(markdown(results, iterations)),
      else: Enum.each(results, &IO.puts(text(&1)))
  end

  # -- profile -----------------------------------------------------------------

  defp run_profile(name, profile, iterations, opts) do
    root =
      Path.join(System.tmp_dir!(), "vulncheck-bench-#{name}-#{System.unique_integer([:positive])}")

    IO.puts(:stderr, "generating #{name} workspace in #{root} ...")
    {gen_us, shape} = :timer.tc(fn -> generate!(root, profile) end)
    IO.puts(:stderr, "  #{shape.beams} .beam files compiled in #{ms(gen_us)} ms")

    config = %Config{
      project_dir: root,
      cache_dir: Path.join(root, ".bench-cache"),
      offline: true,
      check_retired: false,
      env: :prod
    }

    seed_feeds!(config, profile)

    # warm-up: loads VulnCheck's own modules and fills the .beam cache
    {:ok, report} = VulnCheck.scan(config)
    {:ok, ws} = VulnCheck.Workspace.load(config)
    {:ok, feed} = Store.load(ws, config)
    loaded = Loader.load_workspace(ws, config, cache: config)
    graph = CallGraph.build(loaded.modules)
    _ = Loader.load_workspace(ws, config, cache: false)

    for format <- [:terminal, :sarif, :cyclonedx, :openvex],
        do: VulnCheck.CLI.render(report, %{config | color: false}, format)

    atoms_before = :erlang.system_info(:atom_count)

    stages = [
      {"Lockfile and configuration", fn -> {:ok, _} = VulnCheck.Workspace.load(config) end},
      {"Advisory feeds (offline cache)", fn -> {:ok, _} = Store.load(ws, config) end},
      {"Cold .beam extraction", fn -> Loader.load_workspace(ws, config, cache: false) end},
      {"Warm .beam summaries (SHA-256 cache)",
       fn -> Loader.load_workspace(ws, config, cache: config) end},
      {"Entrypoints, call graph and solver",
       fn ->
         graph = CallGraph.build(loaded.modules)
         {model, graph} = VulnCheck.Entrypoints.build(ws, graph, config)
         Solver.solve(ws, graph, model, feed.advisories, config)
       end},
      {"Reports (terminal, sarif, cyclonedx, openvex)",
       fn ->
         for format <- [:terminal, :sarif, :cyclonedx, :openvex],
             do: VulnCheck.CLI.render(report, %{config | color: false}, format)
       end},
      {"Full scan, cold .beam cache", fn -> {:ok, _} = Scanner.run(config, beam_cache: false) end},
      {"Full scan, warm cache", fn -> {:ok, _} = Scanner.run(config) end}
    ]

    timings =
      for {label, fun} <- stages do
        samples = for _ <- 1..iterations, do: sample(fun)
        {label, stats(samples)}
      end

    atoms_after = :erlang.system_info(:atom_count)
    {peak_cold, _} = peak_memory(fn -> Scanner.run(config, beam_cache: false) end)
    {peak_warm, _} = peak_memory(fn -> Scanner.run(config) end)

    unless Keyword.get(opts, :keep, false), do: File.rm_rf!(root)

    %{
      name: name,
      kind: :synthetic,
      shape:
        Map.merge(shape, %{
          modules_in_graph: map_size(graph.modules),
          edges: CallGraph.edge_count(graph),
          advisories: length(feed.advisories),
          findings: length(report.findings),
          reachable: report.summary.reachable,
          unreachable: report.summary.unreachable
        }),
      timings: timings,
      atom_delta: atoms_after - atoms_before,
      atom_count: atoms_after,
      peak_cold: peak_cold,
      peak_warm: peak_warm
    }
  end

  # -- installed libraries -----------------------------------------------------

  @libraries [
    :kernel,
    :stdlib,
    :compiler,
    :crypto,
    :inets,
    :ssl,
    :public_key,
    :elixir,
    :logger,
    :eex,
    :mix
  ]

  # Loads the installed libraries' `.beam` files with and without the summary
  # cache, one file at a time and with one worker per scheduler.
  defp run_libraries(iterations) do
    dirs =
      for app <- @libraries,
          dir = :code.lib_dir(app),
          is_list(dir),
          ebin = Path.join(dir, "ebin"),
          File.dir?(ebin),
          do: {nil, ebin}

    cache =
      Path.join(
        System.tmp_dir!(),
        "vulncheck-bench-libraries-#{System.unique_integer([:positive])}"
      )

    cached = [cache_dir: cache]
    IO.puts(:stderr, "summarizing installed libraries into #{cache} ...")
    first = Loader.load_dirs(dirs, cache: cached)
    _ = Loader.load_dirs(dirs, cache: false)

    atoms_before = :erlang.system_info(:atom_count)
    schedulers = System.schedulers_online()

    timings =
      for {label, opts} <- [
            {"Cold extraction, 1 worker", [cache: false, max_concurrency: 1]},
            {"Warm cache, 1 worker", [cache: cached, max_concurrency: 1]},
            {"Cold extraction, #{schedulers} workers", [cache: false]},
            {"Warm cache, #{schedulers} workers", [cache: cached]}
          ] do
        samples =
          for _ <- 1..iterations, do: sample(fn -> Loader.load_dirs(dirs, opts) end)

        {label, stats(samples)}
      end

    warm = Loader.load_dirs(dirs, cache: cached)
    atoms_after = :erlang.system_info(:atom_count)
    File.rm_rf!(cache)

    %{
      name: "libraries",
      kind: :libraries,
      shape: %{
        applications: length(dirs),
        beams: first.stats.beams,
        without_debug_info: first.stats.without_debug_info,
        hit_rate: div(warm.stats.cached * 100, max(warm.stats.beams, 1))
      },
      timings: timings,
      atom_delta: atoms_after - atoms_before,
      atom_count: atoms_after
    }
  end

  # -- workspace generation ----------------------------------------------------

  defp pkg(i), do: "bench_pkg_" <> String.pad_leading(Integer.to_string(i), 3, "0")
  defp mod(i), do: "BenchPkg" <> String.pad_leading(Integer.to_string(i), 3, "0")

  # Each package depends on the next one and on one seven positions ahead,
  # forming a dense acyclic dependency graph.
  defp deps(i, count), do: Enum.filter([i + 1, i + 7], &(&1 <= count))

  defp generate!(root, p) do
    File.mkdir_p!(root)
    build = Path.join(root, "_build/prod/lib")
    direct = 1..min(p.root_modules, p.packages)

    if p[:umbrella_apps] do
      File.write!(Path.join(root, "mix.exs"), """
      defmodule BenchUmbrella.MixProject do
        use Mix.Project
        def project, do: [apps_path: "apps", version: "1.0.0", deps: []]
      end
      """)
    else
      File.write!(Path.join(root, "mix.exs"), """
      defmodule BenchApp.MixProject do
        use Mix.Project
        def project, do: [app: :bench_app, version: "1.0.0", deps: deps()]
        def application, do: [mod: {BenchApp.Application, []}]
        defp deps, do: [#{Enum.map_join(direct, ", ", &~s({:#{pkg(&1)}, "~> 1.0"}))}]
      end
      """)
    end

    lock =
      Enum.map_join(1..p.packages, "\n", fn i ->
        dep_entries =
          Enum.map_join(deps(i, p.packages), ", ", fn d ->
            ~s({:#{pkg(d)}, "~> 1.0", [hex: :#{pkg(d)}, repo: "hexpm", optional: false]})
          end)

        ~s(  "#{pkg(i)}": {:hex, :#{pkg(i)}, "1.0.0", "#{@sha}", [:mix], [#{dep_entries}], "hexpm", "#{@sha}"},)
      end)

    File.write!(Path.join(root, "mix.lock"), "%{\n#{lock}\n}\n")

    package_beams =
      for i <- 1..p.packages do
        sources =
          for m <- 1..p.modules do
            calls_out =
              if m < p.modules,
                do: ["#{mod(i)}.M#{m + 1}.f1(x)"],
                else: Enum.map(deps(i, p.packages), &"#{mod(&1)}.M1.f1(x)")

            {"deps/#{pkg(i)}/lib/m#{m}.ex",
             module_source("#{mod(i)}.M#{m}", p.functions, m, calls_out, m == p.modules)}
          end

        ebin = Path.join([build, pkg(i), "ebin"])
        beams = compile!(root, ebin, sources)
        write_app!(ebin, pkg(i), Enum.map(deps(i, p.packages), &pkg/1))
        beams
      end

    root_beams =
      if apps_count = p[:umbrella_apps] do
        per_app = div(p.root_modules, apps_count)

        Enum.flat_map(1..apps_count, fn app_idx ->
          app_name = "umb_#{app_idx}"
          app_mod = "Umb#{app_idx}"
          app_dir = Path.join([root, "apps", app_name])
          File.mkdir_p!(app_dir)

          next_app = if app_idx < apps_count, do: "umb_#{app_idx + 1}", else: nil
          app_deps = if next_app, do: [{String.to_atom(next_app), in_umbrella: true}], else: []
          direct_slice = Enum.filter(direct, &(rem(&1 - 1, apps_count) + 1 == app_idx))

          File.write!(Path.join(app_dir, "mix.exs"), """
          defmodule #{app_mod}.MixProject do
            use Mix.Project
            def project, do: [app: :#{app_name}, version: "1.0.0", deps: #{inspect(app_deps ++ Enum.map(direct_slice, &{String.to_atom(pkg(&1)), "~> 1.0"}))}]
            def application, do: [mod: {#{app_mod}.Application, []}]
          end
          """)

          offset = (app_idx - 1) * per_app

          sources =
            for m <- 1..per_app do
              global_m = offset + m
              target = rem(global_m - 1, length(Enum.to_list(direct))) + 1

              cross_call =
                if next_app,
                  do: ["Umb#{app_idx + 1}.M1.f1(x)"],
                  else: []

              {"apps/#{app_name}/lib/m#{m}.ex",
               module_source(
                 "#{app_mod}.M#{m}",
                 p.functions,
                 global_m,
                 cross_call ++ ["#{mod(target)}.M1.f1(x)"],
                 false
               )}
            end

          app_source =
            {"apps/#{app_name}/lib/application.ex",
             """
             defmodule #{app_mod}.Application do
               def start(_type, _args) do
             #{Enum.map_join(1..per_app, "\n", &"    #{app_mod}.M#{&1}.f1(:start)")}
                 {:ok, self()}
               end
             end
             """}

          ebin = Path.join([build, app_name, "ebin"])
          beams = compile!(root, ebin, [app_source | sources])

          write_app!(
            ebin,
            app_name,
            List.wrap(next_app) ++ Enum.map(direct_slice, &pkg/1),
            "Elixir.#{app_mod}.Application"
          )

          beams
        end)
      else
        root_sources =
          for m <- 1..p.root_modules do
            target = rem(m - 1, length(Enum.to_list(direct))) + 1

            {"lib/bench_app/m#{m}.ex",
             module_source("BenchApp.M#{m}", p.functions, m, ["#{mod(target)}.M1.f1(x)"], false)}
          end

        app_source =
          {"lib/bench_app/application.ex",
           """
           defmodule BenchApp.Application do
             def start(_type, _args) do
           #{Enum.map_join(1..p.root_modules, "\n", &"    BenchApp.M#{&1}.f1(:start)")}
               {:ok, self()}
             end
           end
           """}

        ebin = Path.join([build, "bench_app", "ebin"])
        beams = compile!(root, ebin, [app_source | root_sources])
        write_app!(ebin, "bench_app", Enum.map(direct, &pkg/1), "Elixir.BenchApp.Application")
        beams
      end

    %{
      packages: p.packages,
      beams: Enum.sum(Enum.map(package_beams, &length/1)) + length(root_beams),
      functions: (p.packages * p.modules + p.root_modules) * (p.functions + 1)
    }
  end

  # f1 -> f2 -> ... -> fN -> calls into dependencies; the last module of a
  # package also defines `unused/1`, which nothing calls. Function bodies
  # carry the usual mix of pattern matching, closures, maps and string
  # building, so the abstract code is sized like ordinary library code.
  defp module_source(name, functions, seed, calls_out, unused?) do
    chain =
      for f <- 1..functions do
        next =
          cond do
            f < functions -> "f#{f + 1}({acc, #{seed * f}})"
            calls_out == [] -> "acc"
            true -> Enum.join(calls_out, "\n    ")
          end

        """
          def f#{f}(input) do
            acc =
              case input do
                {tag, n} when is_integer(n) and n > #{f} ->
                  %{tag: tag, n: n, label: "#{name}.f#{f}:\#{n}"}

                list when is_list(list) ->
                  list
                  |> Enum.map(fn item -> {item, :erlang.phash2(item)} end)
                  |> Enum.filter(fn {_item, hash} -> rem(hash, #{f + 1}) == 0 end)
                  |> Map.new()

                other ->
                  %{tag: :other, value: other, size: :erlang.external_size(other)}
              end

            x = Map.put(acc, :step, #{f})
            _ = String.length(inspect(x))
            #{next}
          end
        """
      end

    unused = if unused?, do: ["  def unused(x), do: {:unused, x}\n"], else: []
    "defmodule #{name} do\n" <> Enum.join(chain ++ unused, "\n") <> "end\n"
  end

  defp compile!(root, ebin, sources) do
    File.mkdir_p!(ebin)

    files =
      for {path, source} <- sources do
        full = Path.join(root, path)
        File.mkdir_p!(Path.dirname(full))
        File.write!(full, source)
        full
      end

    Code.put_compiler_option(:ignore_module_conflict, true)
    # packages are compiled one by one, before the packages they call
    Code.put_compiler_option(:no_warn_undefined, :all)

    {:ok, modules, _} =
      Kernel.ParallelCompiler.compile_to_path(files, ebin, return_diagnostics: true)

    for module <- modules do
      :code.purge(module)
      :code.delete(module)
    end

    modules
  end

  defp write_app!(ebin, app, apps, mod \\ nil) do
    mod_entry = if mod, do: ",\n  {mod, {'#{mod}', []}}", else: ""

    File.write!(Path.join(ebin, "#{app}.app"), """
    {application, #{app},
     [{vsn, "1.0.0"},
      {modules, []},
      {applications, [kernel, stdlib, elixir#{Enum.map_join(apps, "", &", #{&1}")}]}#{mod_entry}]}.
    """)
  end

  # Advisories with function-level routines: even ones target a reachable
  # function, odd ones the never-called `unused/1`.
  defp seed_feeds!(config, p) do
    feeds = Path.join(config.cache_dir, "feeds")
    File.mkdir_p!(Path.join(feeds, "cves"))
    count = min(p.advisories, p.packages)

    records =
      for i <- 1..count do
        cve = "CVE-2026-9#{String.pad_leading(Integer.to_string(i), 4, "0")}"

        routine =
          if rem(i, 2) == 0,
            do: "'Elixir.#{mod(i)}.M3':f5/1",
            else: "'Elixir.#{mod(i)}.M#{p.modules}':unused/1"

        osv = %{
          "id" => "EEF-" <> cve,
          "aliases" => [cve],
          "summary" => "Synthetic advisory #{i} for #{pkg(i)}",
          "modified" => "2026-01-01T00:00:00Z",
          "severity" => [
            %{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
          ],
          "affected" => [
            %{
              "package" => %{"ecosystem" => "Hex", "name" => pkg(i)},
              "ranges" => [
                %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "1.0.1"}]}
              ]
            }
          ]
        }

        record = %{
          "dataVersion" => "5.1",
          "cveMetadata" => %{"cveId" => cve},
          "containers" => %{
            "cna" => %{
              "affected" => [
                %{
                  "packageName" => pkg(i),
                  "programRoutines" => [%{"name" => routine}],
                  "versions" => []
                }
              ],
              "descriptions" => [%{"lang" => "en", "value" => "Synthetic advisory"}],
              "metrics" => [],
              "problemTypes" => []
            }
          }
        }

        File.write!(Path.join([feeds, "cves", cve <> ".json"]), JSON.encode!(record))
        {String.to_charlist("EEF-#{cve}.json"), JSON.encode!(osv)}
      end

    {:ok, {_, zip}} = :zip.create(~c"all.zip", records, [:memory])
    File.write!(Path.join(feeds, "osv_hex_all.zip"), zip)
  end

  # -- measurement -------------------------------------------------------------

  defp stats(samples) do
    sorted = Enum.sort(samples)
    n = length(sorted)

    %{
      median: Enum.at(sorted, div(n - 1, 2)) * 0.5 + Enum.at(sorted, div(n, 2)) * 0.5,
      p95: Enum.at(sorted, max(ceil(n * 0.95) - 1, 0)),
      min: hd(sorted),
      max: List.last(sorted)
    }
  end

  # Each sample runs in a fresh process, like a CLI invocation, so garbage
  # collection does not scan results kept alive by earlier stages.
  defp sample(fun) do
    fn -> elem(:timer.tc(fun), 0) end
    |> Task.async()
    |> Task.await(:infinity)
  end

  defp peak_memory(fun) do
    :erlang.garbage_collect()
    parent = self()
    sampler = spawn(fn -> sample(parent, :erlang.memory(:total)) end)
    result = fun.()
    send(sampler, :stop)

    receive do
      {:peak, peak} -> {peak, result}
    end
  end

  defp sample(parent, peak) do
    receive do
      :stop -> send(parent, {:peak, max(peak, :erlang.memory(:total))})
    after
      2 -> sample(parent, max(peak, :erlang.memory(:total)))
    end
  end

  # -- output ------------------------------------------------------------------

  defp ms(us), do: :erlang.float_to_binary(us / 1000, decimals: 1)
  defp mib(bytes), do: :erlang.float_to_binary(bytes / 1_048_576, decimals: 1)

  defp environment do
    [
      {"OS", os()},
      {"CPU", cpu()},
      {"Schedulers", Integer.to_string(System.schedulers_online())},
      {"Elixir", System.version()},
      {"Erlang/OTP", "#{System.otp_release()} (ERTS #{:erlang.system_info(:version)})"},
      {"VulnCheck", VulnCheck.version()}
    ]
  end

  defp os do
    {family, name} = :os.type()

    version =
      case :os.version() do
        {a, b, c} -> "#{a}.#{b}.#{c}"
        other -> to_string(other)
      end

    "#{family}/#{name} #{version} (#{:erlang.system_info(:system_architecture)})"
  end

  defp cpu do
    case :os.type() do
      {:unix, :darwin} ->
        cmd("sysctl", ["-n", "machdep.cpu.brand_string"])

      {:unix, _} ->
        File.read!("/proc/cpuinfo")
        |> then(&(Regex.run(~r/model name\s*:\s*(.+)/, &1) || [nil, "unknown"]))
        |> List.last()

      _ ->
        "unknown"
    end
  rescue
    _ -> "unknown"
  end

  defp cmd(bin, args) do
    case System.cmd(bin, args, stderr_to_stdout: true) do
      {out, 0} -> String.trim(out)
      _ -> "unknown"
    end
  end

  defp text(%{kind: :libraries} = result) do
    s = result.shape

    header =
      "Profile libraries: #{s.applications} installed applications, #{s.beams} .beam files " <>
        "(#{s.without_debug_info} without debug info), warm cache hit rate #{s.hit_rate}%"

    Enum.join([header | rows(result.timings)] ++ [atom_line(result)], "\n") <> "\n"
  end

  defp text(result) do
    s = result.shape

    header =
      "Profile #{result.name}: #{s.packages} packages, #{s.beams} .beam files, ~#{s.functions} functions, " <>
        "#{s.edges} call edges, #{s.advisories} advisories (#{s.reachable} reachable, #{s.unreachable} unreachable)"

    footer = [
      "Peak BEAM memory: cold scan #{mib(result.peak_cold)} MiB, warm scan #{mib(result.peak_warm)} MiB",
      atom_line(result)
    ]

    Enum.join([header | rows(result.timings)] ++ footer, "\n") <> "\n"
  end

  defp rows(timings) do
    Enum.map(timings, fn {label, t} ->
      String.pad_trailing(label, 48) <>
        "median #{String.pad_leading(ms(t.median), 8)} ms   p95 #{String.pad_leading(ms(t.p95), 8)} ms   " <>
        "min #{String.pad_leading(ms(t.min), 8)} ms   max #{String.pad_leading(ms(t.max), 8)} ms"
    end)
  end

  defp atom_line(result),
    do: "Atom table: #{result.atom_count} atoms, delta over measured runs: #{result.atom_delta}"

  defp markdown_rows(timings) do
    Enum.map_join(timings, "\n", fn {label, t} ->
      "| #{label} | #{ms(t.median)} | #{ms(t.p95)} | #{ms(t.min)} | #{ms(t.max)} |"
    end)
  end

  defp markdown(results, iterations) do
    env =
      [
        "| Component | Value |",
        "| :--- | :--- |" | Enum.map(environment(), fn {k, v} -> "| #{k} | #{v} |" end)
      ]

    sections =
      Enum.map(results, fn
        %{kind: :libraries, shape: s} = result ->
          """
          ### Profile `libraries`

          #{s.beams} `.beam` files of #{s.applications} installed Elixir and Erlang/OTP applications
          (#{s.without_debug_info} without debug info); warm cache hit rate #{s.hit_rate}%.

          | Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
          | :--- | ---: | ---: | ---: | ---: |
          #{markdown_rows(result.timings)}

          | Metric | Value |
          | :--- | ---: |
          | Atom delta over #{iterations} measured runs of every stage | #{result.atom_delta} |
          """

        result ->
          s = result.shape

          """
          ### Profile `#{result.name}`

          #{s.packages} packages, #{s.beams} `.beam` files, ~#{s.functions} functions, #{s.edges} call edges,
          #{s.advisories} advisories with `programRoutines` (#{s.reachable} reachable, #{s.unreachable} unreachable).

          | Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
          | :--- | ---: | ---: | ---: | ---: |
          #{markdown_rows(result.timings)}

          | Metric | Value |
          | :--- | ---: |
          | Peak BEAM memory, cold scan | #{mib(result.peak_cold)} MiB |
          | Peak BEAM memory, warm scan | #{mib(result.peak_warm)} MiB |
          | Atom delta over #{iterations} measured runs of every stage | #{result.atom_delta} |
          """
      end)

    Enum.join(
      [
        "#### Environment",
        "",
        Enum.join(env, "\n"),
        "",
        "#{iterations} measured iterations per stage after one warm-up run.",
        "" | sections
      ],
      "\n"
    )
  end
end

VulnCheck.Bench.main(System.argv())
