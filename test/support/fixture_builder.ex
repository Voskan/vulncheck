defmodule VulnCheck.Test.FixtureBuilder do
  @moduledoc false
  # Builds compiled BEAM workspaces on disk: Elixir and Erlang sources are
  # compiled with debug info into the build layout of Mix, rebar3 or Gleam,
  # next to the lockfile and `.app` files, so scans run the full pipeline.
  #
  # Packages are maps with:
  #   name, version                 lockfile entry
  #   ex / erl                      [{relative_path, source}] compiled into the package ebin
  #   applications                  `.app` applications
  #   optional_applications         `.app` optional applications
  #   deps                          [{name, optional?}] recorded in the lockfile
  #   only                          mix.exs `only:` restriction (e.g. :test); nothing is compiled
  #   runtime                       false for a mix.exs `runtime: false` dependency
  #   strip                         strip debug info from the compiled modules
  #   top_level                     listed in mix.exs deps (default true)

  alias VulnCheck.Test.{Beams, Tmp}

  @sha String.duplicate("e3", 32)
  @feeds Path.expand("../fixtures/feeds", __DIR__)

  # -- Mix ---------------------------------------------------------------------

  def mix_project!(app, opts) do
    root = Tmp.mkdir!("corpus-#{app}")
    packages = Keyword.get(opts, :packages, [])

    deps =
      packages
      |> Enum.filter(&Map.get(&1, :top_level, true))
      |> Enum.map_join(", ", fn pkg ->
        options =
          [only: Map.get(pkg, :only), runtime: Map.get(pkg, :runtime)]
          |> Enum.reject(&is_nil(elem(&1, 1)))
          |> Enum.map_join(fn {key, value} -> ", #{key}: #{inspect(value)}" end)

        ~s({:#{pkg.name}, "~> #{pkg.version}"#{options}})
      end)

    mod = Keyword.get(opts, :mod)

    Tmp.write!(root, "mix.exs", """
    defmodule #{Macro.camelize(app)}.MixProject do
      use Mix.Project

      def project, do: [app: :#{app}, version: "1.0.0", deps: deps()]

      def application, do: [#{if mod, do: "mod: {#{mod}, []}", else: ""}]

      defp deps, do: [#{deps}]
    end
    """)

    Tmp.write!(root, "mix.lock", mix_lock(packages))

    for {path, content} <- Keyword.get(opts, :files, []), do: Tmp.write!(root, path, content)

    build = Path.join(root, "_build/prod/lib")

    for pkg <- packages, is_nil(Map.get(pkg, :only)) do
      compile_package!(root, Path.join(build, pkg.name), Path.join("deps", pkg.name), pkg)
    end

    ebin = Path.join([build, app, "ebin"])
    compile_sources!(root, ebin, "", Keyword.get(opts, :ex, []), Keyword.get(opts, :erl, []))

    Beams.write_app!(ebin, app,
      applications: [:kernel, :stdlib, :elixir | Keyword.get(opts, :applications, [])],
      mod: mod && "Elixir.#{mod}"
    )

    root
  end

  defp mix_lock(packages) do
    entries =
      Enum.map_join(packages, "\n", fn pkg ->
        deps =
          pkg
          |> Map.get(:deps, [])
          |> Enum.map_join(", ", fn {dep, optional} ->
            ~s({:#{dep}, ">= 0.0.0", [hex: :#{dep}, repo: "hexpm", optional: #{optional}]})
          end)

        ~s(  "#{pkg.name}": {:hex, :#{pkg.name}, "#{pkg.version}", "#{@sha}", [:mix], [#{deps}], "hexpm", "#{@sha}"},)
      end)

    "%{\n#{entries}\n}\n"
  end

  # -- rebar3 ------------------------------------------------------------------

  def rebar_project!(app, opts) do
    root = Tmp.mkdir!("corpus-rebar-#{app}")
    packages = Keyword.get(opts, :packages, [])

    Tmp.write!(root, "rebar.config", "{deps, [#{Enum.map_join(packages, ", ", & &1.name)}]}.\n")

    locks =
      Enum.map_join(packages, ",\n ", fn pkg ->
        ~s({<<"#{pkg.name}">>,{pkg,<<"#{pkg.name}">>,<<"#{pkg.version}">>},0})
      end)

    Tmp.write!(root, "rebar.lock", ~s({"1.2.0",\n[#{locks}]}.\n[].\n))

    applications = Enum.join([:kernel, :stdlib | Keyword.get(opts, :applications, [])], ", ")
    mod = Keyword.get(opts, :mod)
    mod_entry = if mod, do: ", {mod, {#{mod}, []}}", else: ""

    Tmp.write!(root, "src/#{app}.app.src", """
    {application, #{app}, [{vsn, "1.0.0"}, {applications, [#{applications}]}#{mod_entry}]}.
    """)

    build = Path.join(root, "_build/default/lib")

    for pkg <- packages do
      compile_package!(
        root,
        Path.join(build, pkg.name),
        Path.join("_build/default/lib", pkg.name),
        pkg
      )
    end

    ebin = Path.join([build, app, "ebin"])
    compile_sources!(root, ebin, "", [], Keyword.get(opts, :erl, []))

    Beams.write_app!(ebin, app,
      applications: [:kernel, :stdlib | Keyword.get(opts, :applications, [])],
      mod: mod
    )

    root
  end

  # -- Gleam -------------------------------------------------------------------

  def gleam_project!(app, opts) do
    root = Tmp.mkdir!("corpus-gleam-#{app}")
    packages = Keyword.get(opts, :packages, [])

    Tmp.write!(root, "gleam.toml", """
    name = "#{app}"
    version = "1.0.0"

    [dependencies]
    #{Enum.map_join(packages, "\n", &~s(#{&1.name} = ">= #{&1.version}"))}
    """)

    manifest =
      Enum.map_join(packages, "\n", fn pkg ->
        ~s(  { name = "#{pkg.name}", version = "#{pkg.version}", build_tools = ["rebar3"], requirements = [], otp_app = "#{pkg.name}", source = "hex", outer_checksum = "#{String.upcase(@sha)}" },)
      end)

    Tmp.write!(root, "manifest.toml", """
    # This file was generated by Gleam
    packages = [
    #{manifest}
    ]

    [requirements]
    #{Enum.map_join(packages, "\n", &~s(#{&1.name} = { version = ">= #{&1.version}" }))}
    """)

    build = Path.join(root, "build/dev/erlang")

    for pkg <- packages do
      compile_package!(root, Path.join(build, pkg.name), Path.join("build/packages", pkg.name), pkg)
    end

    ebin = Path.join([build, app, "ebin"])

    compile_sources!(
      root,
      ebin,
      "build/dev/erlang/#{app}/_gleam_artefacts",
      [],
      Keyword.get(opts, :erl, [])
    )

    Beams.write_app!(ebin, app,
      applications: [:kernel, :stdlib | Keyword.get(opts, :applications, [])]
    )

    root
  end

  # -- compilation -------------------------------------------------------------

  defp compile_package!(root, lib_dir, source_dir, pkg) do
    ebin = Path.join(lib_dir, "ebin")

    compiled =
      compile_sources!(root, ebin, source_dir, Map.get(pkg, :ex, []), Map.get(pkg, :erl, []))

    Beams.write_app!(ebin, pkg.name,
      applications: [:kernel, :stdlib | Map.get(pkg, :applications, [])],
      optional_applications: Map.get(pkg, :optional_applications, [])
    )

    if Map.get(pkg, :strip, false) do
      {:ok, _} = :beam_lib.strip_files(Enum.map(compiled, &String.to_charlist/1))
    end
  end

  # Writes the sources below `root/source_dir` (so compiled `file`
  # attributes carry real paths) and returns the written `.beam` files.
  defp compile_sources!(root, ebin, source_dir, ex, erl) do
    File.mkdir_p!(ebin)

    ex_files = for {path, source} <- ex, do: Tmp.write!(root, Path.join(source_dir, path), source)
    modules = if ex_files == [], do: [], else: Beams.compile_files!(ex_files, ebin)

    erl_modules =
      for {path, source} <- erl do
        file = Tmp.write!(root, Path.join(source_dir, path), source)

        {:ok, module} =
          :compile.file(String.to_charlist(file), [
            :debug_info,
            :return_errors,
            outdir: String.to_charlist(ebin)
          ])

        module
      end

    Enum.map(modules ++ erl_modules, &Path.join(ebin, "#{&1}.beam"))
  end

  # -- feeds -------------------------------------------------------------------

  @doc "A cache directory seeded with the offline advisory corpus."
  def feed_cache! do
    cache = Tmp.mkdir!("corpus-cache")
    feeds = Path.join(cache, "feeds")
    File.mkdir_p!(Path.join(feeds, "cves"))

    files =
      for path <- Path.wildcard(Path.join(@feeds, "osv/*.json")) |> Enum.sort() do
        {String.to_charlist(Path.basename(path)), File.read!(path)}
      end

    {:ok, {_name, zip}} = :zip.create(~c"all.zip", files, [:memory])
    File.write!(Path.join(feeds, "osv_hex_all.zip"), zip)

    for path <- Path.wildcard(Path.join(@feeds, "cves/*.json")) do
      File.cp!(path, Path.join([feeds, "cves", Path.basename(path)]))
    end

    cache
  end

  @doc "Scans `root` offline against the advisory corpus."
  def scan!(root, opts \\ []) do
    {:ok, report} =
      VulnCheck.scan(
        root,
        Keyword.merge([cache_dir: feed_cache!(), offline: true, check_retired: false], opts)
      )

    report
  end

  @doc "The finding for `advisory_id` in a report."
  def finding!(report, advisory_id) do
    Enum.find(report.findings, &(&1.advisory_id == advisory_id)) ||
      raise "no finding for #{advisory_id} in #{inspect(Enum.map(report.findings, & &1.advisory_id))}"
  end
end
