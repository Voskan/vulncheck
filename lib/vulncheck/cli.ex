defmodule VulnCheck.CLI do
  @moduledoc """
  Command line interface shared by the `vulncheck` escript and the Mix tasks.

      vulncheck [scan] [flags]          audit the project (default command)
      vulncheck init [--force]          write a commented .vulncheck.exs
      vulncheck explain <ID> [flags]    describe an advisory and its local status
      vulncheck feeds sync|status       refresh or inspect the advisory cache
      vulncheck feeds bundle -o FILE    export the cache for offline runners

  Exit codes: `0` clean, `1` policy violation (actionable findings, retired
  releases, expired or forbidden suppressions), `2` execution error.
  """

  alias VulnCheck.{Cache, Config, Explain}
  alias VulnCheck.Entrypoints.Adapters
  alias VulnCheck.Feeds.{EefCna, OSV}
  alias VulnCheck.Report
  alias VulnCheck.Types.{Advisory, ScanReport}

  @reporters %{
    terminal: Report.Terminal,
    json: Report.JSON,
    markdown: Report.Markdown,
    sarif: Report.SARIF,
    github: Report.GitHub,
    gitlab: Report.GitLab,
    cyclonedx: Report.CycloneDX,
    openvex: Report.OpenVEX
  }

  @type exit_code :: 0 | 1 | 2

  @doc "Escript entry point."
  @spec main([String.t()]) :: no_return()
  def main(argv) do
    # escripts start with latin1 standard IO; reports contain UTF-8 text
    :io.setopts(:standard_io, encoding: :unicode)
    :io.setopts(:standard_error, encoding: :unicode)
    code = run(argv)
    System.halt(code)
  end

  @doc """
  Runs a command and returns its exit code without halting the VM.

  Options:

    * `:stdout` / `:stderr` — IO devices (default `:stdio` / `:stderr`)
    * `:cwd` — working directory used to resolve relative paths
    * `:scan_opts` — options forwarded to `VulnCheck.Scanner.run/2`
      (feed URLs, HTTP client, `:today`)
  """
  @spec run([String.t()], keyword()) :: exit_code()
  def run(argv, opts \\ []) do
    ctx = %{
      stdout: Keyword.get(opts, :stdout, :stdio),
      stderr: Keyword.get(opts, :stderr, :stderr),
      cwd: Keyword.get_lazy(opts, :cwd, &File.cwd!/0),
      scan_opts: Keyword.get(opts, :scan_opts, [])
    }

    dispatch(argv, ctx)
  end

  defp dispatch([flag | _], ctx) when flag in ["--version", "-v", "version"] do
    out(ctx, "vulncheck #{VulnCheck.version()}")
    0
  end

  defp dispatch([flag | _], ctx) when flag in ["--help", "-h", "help"] do
    out(ctx, usage())
    0
  end

  defp dispatch(["scan" | rest], ctx), do: scan(rest, ctx)
  defp dispatch(["init" | rest], ctx), do: init(rest, ctx)
  defp dispatch(["explain" | rest], ctx), do: explain(rest, ctx)
  defp dispatch(["feeds" | rest], ctx), do: feeds(rest, ctx)
  defp dispatch([], ctx), do: scan([], ctx)
  defp dispatch(["-" <> _ | _] = argv, ctx), do: scan(argv, ctx)

  defp dispatch([command | _], ctx),
    do: fail(ctx, "unknown command #{inspect(command)}; run `vulncheck --help`")

  # -- scan --------------------------------------------------------------------

  defp scan(argv, ctx) do
    if help?(argv) do
      out(ctx, usage())
      0
    else
      with {:ok, config} <- Config.from_cli_and_file(argv, cwd: ctx.cwd),
           config = adjust_color(config),
           {:ok, report} <- VulnCheck.scan(config, ctx.scan_opts),
           :ok <- write_outputs(report, config, ctx) do
        code = if VulnCheck.should_fail?(report, config), do: 1, else: 0

        if code == 1 and config.format == :terminal and is_nil(config.output) and not config.quiet do
          out(
            ctx,
            "Exit code: 1 (threshold: --fail-on #{config.fail_on}, --min-severity #{config.min_severity})"
          )
        end

        code
      else
        {:error, reason} -> fail(ctx, describe_error(reason))
      end
    end
  end

  defp adjust_color(%Config{output: output} = config) when is_binary(output),
    do: %{config | color: false}

  defp adjust_color(config), do: config

  @doc "Renders a report in the given format."
  @spec render(ScanReport.t(), Config.t(), Config.format()) :: String.t()
  def render(%ScanReport{} = report, %Config{} = config, format) do
    Map.fetch!(@reporters, format).render(report, config)
  end

  defp write_outputs(report, config, ctx) do
    primary = render(report, config, config.format)

    vex =
      cond do
        config.format == :openvex -> primary
        config.vex -> render(report, config, :openvex)
        true -> nil
      end

    artifacts =
      [
        config.sbom && {config.sbom, render(report, config, :cyclonedx)},
        config.vex && vex != "" && {config.vex, vex}
      ]
      |> Enum.filter(& &1)

    with :ok <- check_empty_vex(vex, config, ctx),
         :ok <- write_all(artifacts) do
      case {primary, config.output} do
        {"", _} -> :ok
        {content, nil} -> IO.write(ctx.stdout, content)
        {content, path} -> write_file(path, content)
      end
    end
  end

  defp check_empty_vex("", config, ctx) do
    primary_path = if config.format == :openvex, do: config.output

    if path = Enum.find([config.vex, primary_path], &(is_binary(&1) and File.exists?(&1))) do
      {:error, "no OpenVEX statements to write and the destination already exists: #{path}"}
    else
      IO.puts(ctx.stderr, "OpenVEX omitted because the scan has no statements")
    end
  end

  defp check_empty_vex(_vex, _config, _ctx), do: :ok

  defp write_all(files) do
    Enum.reduce_while(files, :ok, fn {path, data}, :ok ->
      case write_file(path, data) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp write_file(path, data) do
    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- Cache.atomic_write(path, data) do
      :ok
    else
      {:error, {:cache_write_failed, _path, reason}} -> {:error, {:write, path, reason}}
      {:error, reason} -> {:error, {:write, path, reason}}
    end
  end

  # -- init --------------------------------------------------------------------

  defp init(argv, ctx) do
    if help?(argv) do
      out(ctx, "usage: vulncheck init [--project-dir DIR] [--force]")
      0
    else
      case OptionParser.parse(argv, strict: [project_dir: :string, force: :boolean]) do
        {opts, [], []} ->
          dir = Path.expand(Keyword.get(opts, :project_dir, "."), ctx.cwd)
          path = Path.join(dir, ".vulncheck.exs")

          cond do
            not File.dir?(dir) ->
              fail(ctx, "project directory does not exist: #{dir}")

            File.exists?(path) and not Keyword.get(opts, :force, false) ->
              fail(ctx, "#{path} already exists; pass --force to overwrite it")

            true ->
              content = init_template(dir)

              case write_file(path, content) do
                :ok ->
                  out(ctx, "Wrote #{path}")
                  0

                {:error, reason} ->
                  fail(ctx, describe_error(reason))
              end
          end

        {_opts, args, invalid} ->
          fail(
            ctx,
            "invalid arguments: " <> Enum.join(args ++ Enum.map(invalid, &elem(&1, 0)), " ")
          )
      end
    end
  end

  @doc """
  Contents of a generated `.vulncheck.exs` for the project in `dir`.
  """
  @spec init_template(Path.t()) :: String.t()
  def init_template(dir) do
    config = %Config{project_dir: dir}

    {name, type, packages, adapters} =
      case VulnCheck.Workspace.load(config) do
        {:ok, ws} ->
          packages = Map.keys(ws.packages)
          adapters = Adapters.resolve(ws, %{}, config).configured
          {ws.project_name, ws.project_type, packages, {adapters, detected_families(packages)}}

        {:error, _} ->
          {Path.basename(dir), :unknown, [], {%{}, []}}
      end

    detected = frameworks(packages)
    entrypoints = release_entrypoints(dir)

    detected_line =
      case detected do
        [] -> ""
        list -> "# Detected: #{Enum.join(list, ", ")}.\n"
      end

    """
    # VulnCheck configuration for #{name} (#{type} project).
    #{detected_line}# The file is parsed as literal data and never evaluated: use atoms, strings,
    # numbers, booleans, lists, keyword lists, tuples and module names only.
    [
      # Mix environment whose dependency closure and _build/<env> artifacts are analyzed.
      env: :prod,

      # Verdict tier that fails the build: :reachable | :potentially_reachable | :any | :none
      fail_on: :potentially_reachable,

      # Minimum severity that fails the build: :low | :medium | :high | :critical
      min_severity: :low,

      # Fail when a production dependency is locked to a retired Hex release.
      fail_on_retired: true,

      # Adapters selected at runtime, used to rule out inactive adapter packages.
      # Values detected in config/*.exs are filled in; add the ones set elsewhere.
      configured_adapters: [
    #{adapter_lines(adapters, packages)}  ],

      # Functions invoked from outside the call graph (release tasks, RPC, eval scripts).
      extra_entrypoints: [
    #{entrypoint_lines(entrypoints)}  ],

      # Governed suppressions: every entry needs a reason and an expiry date.
      ignore_file: ".vulncheck.ignore",
      require_ignore_reason: true,
      require_ignore_expiry: true,

      # Advisory feed cache (nil uses $XDG_CACHE_HOME/vulncheck or ~/.cache/vulncheck).
      cache_dir: nil,
      cache_ttl_seconds: 3600
    ]
    """
  end

  defp frameworks(packages) do
    [
      {"phoenix", "Phoenix"},
      {"ash", "Ash"},
      {"tesla", "Tesla"},
      {"swoosh", "Swoosh"},
      {["ecto", "ecto_sql"], "Ecto"},
      {"oban", "Oban"},
      {"bandit", "Bandit"},
      {"plug_cowboy", "Cowboy"}
    ]
    |> Enum.filter(fn {names, _label} -> Enum.any?(List.wrap(names), &(&1 in packages)) end)
    |> Enum.map(&elem(&1, 1))
  end

  defp detected_families(packages) do
    Adapters.families()
    |> Enum.filter(fn {_family, spec} -> Enum.any?(spec.owners, &(&1 in packages)) end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  defp adapter_lines({configured, families}, packages) do
    configured_lines =
      for {family, [module | _]} <- Enum.sort(configured),
          do: "    #{family}: #{module_literal(module)},\n"

    hints =
      for family <- families, not Map.has_key?(configured, family) do
        adapters = Adapters.families() |> Map.fetch!(family) |> Map.fetch!(:adapters) |> Enum.sort()

        {example, _deps} =
          Enum.find(adapters, hd(adapters), fn {_module, deps} ->
            deps != [] and Enum.all?(deps, &(&1 in packages))
          end)

        "    # #{family}: #{module_literal(example)},\n"
      end

    case configured_lines ++ hints do
      [] -> "    # tesla: Tesla.Adapter.Mint,\n"
      lines -> Enum.join(lines)
    end
  end

  defp entrypoint_lines([]), do: "    # {MyApp.Release, :migrate, 0},\n"

  defp entrypoint_lines(entrypoints) do
    Enum.map_join(entrypoints, fn {module, function, arity} ->
      "    {#{module}, :#{function}, #{arity}},\n"
    end)
  end

  # Phoenix-style release modules (`MyApp.Release.migrate/0`) run through
  # `bin/my_app eval` and are invisible to the call graph.
  @release_functions [
    {"migrate", 0, ~r/\bdef\s+migrate(\s*\(\s*\))?\s*(do\b|,)/},
    {"rollback", 2, ~r/\bdef\s+rollback\(\s*[^,()]+,\s*[^,()]+\)/}
  ]

  defp release_entrypoints(dir) do
    for pattern <- ["lib/**/release.ex", "apps/*/lib/**/release.ex"],
        file <- Path.wildcard(Path.join(dir, pattern)),
        {:ok, source} <- [File.read(file)],
        [_, module] <- [Regex.run(~r/defmodule\s+([A-Z][\w.]*\.Release)\s+do/, source)],
        {function, arity, pattern} <- @release_functions,
        Regex.match?(pattern, source) do
      {module, function, arity}
    end
    |> Enum.uniq()
  end

  defp module_literal("Elixir." <> name), do: name
  defp module_literal(name), do: ":" <> name

  # -- explain -----------------------------------------------------------------

  defp explain(argv, ctx) do
    if help?(argv) do
      out(
        ctx,
        "usage: vulncheck explain <ADVISORY_ID> [--project-dir DIR] [--offline] [--bundle FILE]"
      )

      0
    else
      with {:ok, config} <- Config.from_cli_and_file(argv, cwd: ctx.cwd, allow_args: true),
           {:ok, id} <- single_arg(config.args, "explain requires exactly one advisory id"),
           {:ok, result} <- Explain.run(id, config, ctx.scan_opts) do
        IO.write(ctx.stdout, Explain.format(result))
        0
      else
        {:error, reason} -> fail(ctx, describe_error(reason))
      end
    end
  end

  defp single_arg([arg], _message), do: {:ok, arg}
  defp single_arg(_args, message), do: {:error, message}

  # -- feeds -------------------------------------------------------------------

  defp feeds(argv, ctx) do
    case argv do
      [sub | rest] when sub in ["sync", "status", "bundle"] ->
        if help?(rest), do: feeds_usage(ctx), else: feeds(sub, rest, ctx)

      [flag | _] when flag in ["--help", "-h"] ->
        feeds_usage(ctx)

      _ ->
        fail(ctx, "usage: vulncheck feeds sync | status | bundle --output FILE")
    end
  end

  defp feeds_usage(ctx) do
    out(ctx, """
    usage: vulncheck feeds sync                  refresh the OSV archive and CVE 5.1 records
           vulncheck feeds status                show the cache location, age and contents
           vulncheck feeds bundle --output FILE  export the cache for --offline --bundle runs\
    """)

    0
  end

  defp feeds(sub, argv, ctx) do
    case Config.from_cli_and_file(argv, cwd: ctx.cwd) do
      {:ok, config} -> feeds_command(sub, config, ctx)
      {:error, reason} -> fail(ctx, describe_error(reason))
    end
  end

  defp feeds_command("sync", %Config{offline: true}, ctx),
    do: fail(ctx, "feeds sync needs network access; drop --offline")

  defp feeds_command("sync", config, ctx) do
    opts = Keyword.put(ctx.scan_opts, :force, true)

    case OSV.load(config, opts) do
      {:ok, advisories, status} ->
        packages = advisories |> Enum.map(& &1.package) |> Enum.uniq() |> length()

        out(
          ctx,
          "OSV Hex archive: #{count_ids(advisories)} advisories for #{packages} packages (#{status})"
        )

        {records, routines, failed} = sync_records(advisories, config, ctx.scan_opts)

        out(
          ctx,
          "CVE 5.1 records: #{records} available, #{routines} with function-level routines" <>
            if(failed > 0, do: ", #{failed} unavailable", else: "")
        )

        out(ctx, "Cache: #{Cache.feeds_dir(config)}")
        0

      {:error, reason} ->
        fail(ctx, describe_error({:feeds, {:osv_feed, reason}}))
    end
  end

  defp feeds_command("status", config, ctx) do
    dir = Cache.feeds_dir(config)
    files = Cache.list_feed_files(config) |> Enum.reject(&String.ends_with?(&1, ".meta.json"))
    out(ctx, "Cache: #{dir}")

    archive = Path.join(dir, OSV.cache_file())

    case File.read(archive) do
      {:ok, zip} ->
        meta = Cache.read_meta(archive)

        advisories =
          case OSV.parse_archive(zip) do
            {:ok, list} -> count_ids(list)
            {:error, _} -> 0
          end

        out(ctx, "OSV Hex archive: #{advisories} advisories, #{format_bytes(byte_size(zip))}")
        out(ctx, "  fetched: #{format_age(meta["fetched_at_unix"])}")
        out(ctx, "  etag:    #{meta["etag"] || "none"}")
        out(ctx, "  source:  #{meta["url"] || OSV.default_url()}")

      {:error, _} ->
        out(ctx, "OSV Hex archive: not cached (run `vulncheck feeds sync`)")
    end

    cves = Enum.filter(files, &String.starts_with?(&1, "cves/"))
    with_routines = Enum.count(cves, &routines?(Path.join(dir, &1)))

    out(
      ctx,
      "CVE 5.1 records: #{length(cves)} cached, #{with_routines} with function-level routines"
    )

    retired = Enum.count(files, &String.starts_with?(&1, "hex/packages/"))
    out(ctx, "Hex package records: #{retired} cached")
    0
  end

  defp feeds_command("bundle", %Config{output: nil}, ctx),
    do: fail(ctx, "feeds bundle requires --output FILE")

  defp feeds_command("bundle", config, ctx) do
    case Cache.export_bundle(config, config.output) do
      {:ok, manifest} ->
        out(
          ctx,
          "Wrote #{config.output}: #{length(manifest["files"])} files, " <>
            "#{manifest["advisory_count"]} advisories"
        )

        0

      {:error, :empty_cache} ->
        fail(ctx, "the feed cache is empty; run `vulncheck feeds sync` first")

      {:error, reason} ->
        fail(ctx, describe_error({:bundle_export, reason}))
    end
  end

  defp sync_records(advisories, config, opts) do
    advisories
    |> Enum.flat_map(fn advisory ->
      case Advisory.cve_id(advisory) do
        nil -> []
        cve -> [{cve, advisory.modified_at}]
      end
    end)
    |> Enum.uniq_by(&elem(&1, 0))
    |> Task.async_stream(
      fn {cve, modified_at} ->
        EefCna.fetch_record(cve, config, Keyword.put(opts, :modified_at, modified_at))
      end,
      max_concurrency: 8,
      timeout: 60_000,
      on_timeout: :kill_task
    )
    |> Enum.reduce({0, 0, 0}, fn
      {:ok, {:ok, record}}, {ok, routines, failed} ->
        {ok + 1, routines + if(record_routines?(record), do: 1, else: 0), failed}

      _other, {ok, routines, failed} ->
        {ok, routines, failed + 1}
    end)
  end

  defp count_ids(advisories), do: advisories |> Enum.map(& &1.id) |> Enum.uniq() |> length()

  defp routines?(path) do
    with {:ok, data} <- File.read(path),
         {:ok, %{} = record} <- JSON.decode(data) do
      record_routines?(record)
    else
      _ -> false
    end
  end

  defp record_routines?(record) do
    affected = get_in(record, ["containers", "cna", "affected"])
    is_list(affected) and Enum.any?(affected, &match?(%{"programRoutines" => [_ | _]}, &1))
  end

  defp format_age(at) when is_integer(at) do
    seconds = max(System.os_time(:second) - at, 0)
    stamp = at |> DateTime.from_unix!() |> DateTime.to_iso8601()

    age =
      cond do
        seconds < 120 -> "#{seconds} s"
        seconds < 7200 -> "#{div(seconds, 60)} min"
        seconds < 172_800 -> "#{div(seconds, 3600)} h"
        true -> "#{div(seconds, 86_400)} days"
      end

    "#{stamp} (#{age} ago)"
  end

  defp format_age(_at), do: "unknown"

  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_bytes(bytes) when bytes < 1_048_576, do: "#{Float.round(bytes / 1024, 1)} KiB"
  defp format_bytes(bytes), do: "#{Float.round(bytes / 1_048_576, 1)} MiB"

  # -- helpers -----------------------------------------------------------------

  defp help?(argv), do: Enum.any?(argv, &(&1 in ["--help", "-h"]))

  defp out(ctx, text), do: IO.puts(ctx.stdout, text)

  defp fail(ctx, message) do
    IO.puts(ctx.stderr, "error: " <> message)
    2
  end

  @doc "Human-readable description of a scan or command error."
  @spec describe_error(term()) :: String.t()
  def describe_error(message) when is_binary(message), do: message

  def describe_error({kind, details}) when kind in [:lockfile_not_found, :unknown_project],
    do: details

  def describe_error({:feeds, :offline_cache_missing}),
    do:
      "no cached advisory feed is available offline; run `vulncheck feeds sync` " <>
        "with network access or pass --bundle FILE"

  def describe_error({:feeds, {:bundle, reason}}),
    do: "cannot import the advisory bundle: #{reason_text(reason)}"

  def describe_error({:feeds, {:osv_feed, reason}}),
    do:
      "cannot fetch the OSV advisory feed (#{reason_text(reason)}); retry, or use --offline with a cache or bundle"

  def describe_error({:feeds, reason}), do: "advisory feeds unavailable: #{reason_text(reason)}"

  def describe_error({:advisory_not_found, id}),
    do: "advisory #{id} was not found in the OSV Hex feed"

  def describe_error({:write, path, reason}), do: "cannot write #{path}: #{reason_text(reason)}"

  def describe_error({:write_baseline, path, reason}),
    do: "cannot write baseline #{path}: #{reason_text(reason)}"

  def describe_error({:bundle_export, reason}),
    do: "cannot write the bundle: #{reason_text(reason)}"

  def describe_error(other), do: inspect(other)

  defp reason_text(reason) when is_atom(reason) do
    case :file.format_error(reason) do
      ~c"unknown POSIX error" ++ _ -> Atom.to_string(reason)
      text -> List.to_string(text)
    end
  end

  defp reason_text({:invalid_bundle, reason}), do: "not a valid bundle (#{reason_text(reason)})"
  defp reason_text({:http_status, status}), do: "HTTP #{status}"
  defp reason_text({:bundle_write_failed, reason}), do: reason_text(reason)
  defp reason_text(reason) when is_binary(reason), do: reason
  defp reason_text(reason), do: inspect(reason)

  @doc "Usage text."
  @spec usage() :: String.t()
  def usage do
    """
    vulncheck #{VulnCheck.version()} — reachability-aware vulnerability audit for BEAM projects

    Usage:
      vulncheck [scan] [flags]          audit locked dependencies (default command)
      vulncheck init [--force]          write a commented .vulncheck.exs
      vulncheck explain <ID> [flags]    describe an advisory and its status in the project
      vulncheck feeds sync              refresh the OSV archive and CVE 5.1 records
      vulncheck feeds status            show cache location, age and contents
      vulncheck feeds bundle -o FILE    export the feed cache for offline runners
      vulncheck --version | --help

    Flags:
      --project-dir DIR           project to scan (default: current directory)
      --config FILE               configuration file (default: DIR/.vulncheck.exs)
      --env ENV                   prod (default) | dev | test
      -f, --format FMT            terminal | json | markdown | sarif | github | gitlab | cyclonedx | openvex
      -o, --output FILE           write the report to FILE instead of standard output
      --sbom FILE                 also write a CycloneDX 1.6 SBOM
      --vex FILE                  also write an OpenVEX v0.2.0 document
      --fail-on TIER              reachable | potentially_reachable (default) | any | none
      --min-severity SEV          low (default) | medium | high | critical
      --[no-]fail-on-retired      fail on retired Hex releases (default: on)
      --no-retired                skip the Hex retirement check
      --show-unreachable          detail unreachable advisories
      --diff REF                  show changes since REF and retain active findings without baseline evidence
      --baseline FILE             hide findings recorded in a JSON baseline
      --write-baseline FILE       record the current findings as a baseline
      --forbid-new-suppressions   fail when .vulncheck.ignore gains entries since --diff
      --ignore-file FILE          suppression file (default: .vulncheck.ignore)
      --otp-version VER           OTP release the project runs on
      --offline                   never use the network
      --bundle FILE               import an advisory bundle before scanning
      --cache-dir DIR             feed and .beam summary cache directory
      --cache-ttl SECONDS         feed freshness (default: 3600)
      --no-color                  disable ANSI colors (also NO_COLOR=1)
      -q, --quiet                 hide warnings

    Exit codes: 0 clean, 1 policy violation, 2 execution error.
    """
  end
end
