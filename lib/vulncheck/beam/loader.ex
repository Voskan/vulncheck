defmodule VulnCheck.Beam.Loader do
  @moduledoc """
  Reads compiled `.beam` files without loading them into the VM.

  Chunks are read with `:beam_lib.chunks/2`. Modules with debug info are
  summarized from their abstract code by `VulnCheck.Beam.AbstractWalker`;
  stripped modules (`:no_abstract_code`) fall back to their `:imports` table
  and are flagged with `has_debug_info: false`.

  Summaries are cached by the SHA-256 of the `.beam` contents (and the
  project root used for relative source paths), so unchanged modules are
  never analyzed twice. Files are processed in parallel.
  """

  alias VulnCheck.{Cache, Config, Semver}
  alias VulnCheck.Beam.AbstractWalker
  alias VulnCheck.Cache.BeamCodec
  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary, Workspace}
  alias VulnCheck.Workspace.AppFile

  @max_beam_bytes 64 * 1024 * 1024
  @default_beam_timeout 15_000
  @default_max_beam_files 20_000
  @default_max_heap_bytes 128 * 1024 * 1024

  # Cached summaries are decoded with `binary_to_term(bin, [:safe])`, which
  # only accepts atoms that already exist. Every atom a summary holds is
  # defined by one of these modules, and modules load lazily, so they are
  # loaded before the first decode; otherwise a fresh VM would treat its
  # first cache hits as misses.
  @summary_modules [ModuleSummary, CallEdge, DynamicCall, MFA, AbstractWalker]

  @type result :: %{
          :modules => %{String.t() => ModuleSummary.t()},
          :warnings => [String.t()],
          :artifact_issues => [{String.t() | nil, String.t()}],
          :stats => %{atom() => non_neg_integer()},
          optional(:profile_matches) => boolean()
        }

  @doc """
  Loads every module of the workspace: root applications, dependencies and
  consolidated protocols (which replace the unconsolidated ones).

  Options: `:cache` (a `VulnCheck.Config`, defaults to `config`; `false`
  disables caching), `:max_concurrency`.
  """
  @spec load_workspace(Workspace.t(), Config.t() | nil, keyword()) :: result()
  def load_workspace(%Workspace{} = workspace, config \\ nil, opts \\ []) do
    dirs =
      Enum.map(workspace.root_ebin_dirs, &{nil, &1}) ++
        (workspace.packages
         |> Map.values()
         |> Enum.filter(&is_binary(&1.ebin_dir))
         |> Enum.sort_by(& &1.name)
         |> Enum.map(&{&1.name, &1.ebin_dir}))

    opts =
      opts
      |> Keyword.put_new(:cache, config || false)
      |> Keyword.put_new(:root_dir, workspace.root_dir)
      |> then(fn o ->
        case config do
          %Config{} = cfg ->
            o
            |> Keyword.put_new(:beam_timeout, cfg.beam_timeout)
            |> Keyword.put_new(:max_beam_files, cfg.max_beam_files)
            |> Keyword.put_new(:max_beam_bytes, cfg.max_beam_bytes)
            |> Keyword.put_new(:max_beam_heap_bytes, cfg.max_beam_heap_bytes)

          _ ->
            o
        end
      end)

    result = load_dirs(dirs, opts)
    consolidated = load_dirs(Enum.map(workspace.consolidated_dirs, &{nil, &1}), opts)
    profile_issue = profile_issue(workspace)

    modules =
      Enum.reduce(consolidated.modules, result.modules, fn {name, summary}, acc ->
        package = acc |> Map.get(name, %{package: nil}) |> Map.get(:package)
        Map.put(acc, name, %{summary | package: package})
      end)

    %{
      modules: modules,
      warnings: result.warnings ++ consolidated.warnings,
      profile_matches: is_nil(profile_issue),
      artifact_issues:
        List.wrap(profile_issue) ++
          workspace_issues(workspace) ++
          result.artifact_issues ++ consolidated.artifact_issues,
      stats: Map.merge(result.stats, consolidated.stats, fn _key, a, b -> a + b end)
    }
  end

  defp profile_issue(%Workspace{build_env: profile} = ws) do
    cond do
      is_nil(profile) ->
        {nil, "no compiled build for the requested environment"}

      profile == Atom.to_string(ws.env) or (ws.project_type == :rebar3 and profile == "default") ->
        nil

      true ->
        {nil, "compiled profile #{profile} differs from requested environment #{ws.env}"}
    end
  end

  defp workspace_issues(workspace) do
    roots =
      for app <- workspace.root_apps do
        case Enum.find_value(workspace.root_ebin_dirs, fn dir ->
               if file = AppFile.read_ebin(dir, app), do: {dir, file}
             end) do
          {dir, file} -> inventory_issues(nil, dir, file)
          nil -> [{nil, "missing compiled .app for project application #{app}"}]
        end
      end

    dependencies =
      for package <- Enum.sort_by(Workspace.prod_packages(workspace), & &1.name),
          dir = package.ebin_dir,
          file =
            AppFile.read_ebin(dir, package.otp_app || package.name) ||
              AppFile.read_ebin(dir, package.name) do
        versions = compare_version(package.name, package.version, file.vsn)
        versions ++ inventory_issues(package.name, dir, file)
      end

    List.flatten(roots ++ dependencies)
  end

  defp compare_version(package, locked, built) do
    if Semver.valid?(locked) and
         (not Semver.valid?(built) or Semver.compare(locked, built) != :eq) do
      [
        {package,
         "#{package} was built at #{built || "an unknown version"}, lock specifies #{locked}"}
      ]
    else
      []
    end
  end

  defp inventory_issues(owner, dir, file) do
    expected = if file.mod, do: [file.mod | file.modules], else: file.modules
    missing = expected |> Enum.uniq() |> Enum.reject(&File.regular?(Path.join(dir, &1 <> ".beam")))

    for module <- missing,
        do: {owner, "missing compiled module #{module} listed by #{file.name}.app"}
  end

  @doc """
  Loads all `.beam` files of the given `{package_or_nil, ebin_dir}` pairs.
  When two directories define the same module, the first one wins.
  """
  @spec load_dirs([{String.t() | nil, String.t()}], keyword()) :: result()
  def load_dirs(dirs, opts \\ []) do
    Enum.each(@summary_modules, &Code.ensure_loaded!/1)

    files =
      for {package, dir} <- dirs,
          path <- dir |> Path.join("*.beam") |> Path.wildcard() |> Enum.sort(),
          do: {package, path}

    concurrency = Keyword.get(opts, :max_concurrency, System.schedulers_online())
    timeout = Keyword.get(opts, :beam_timeout, @default_beam_timeout)
    max_files = Keyword.get(opts, :max_beam_files, @default_max_beam_files)
    max_heap_bytes = Keyword.get(opts, :max_beam_heap_bytes, @default_max_heap_bytes)
    loader = Keyword.get(opts, :loader, &load_file_packed(&1, opts))
    {accepted, overflow} = Enum.split(files, max_files)

    initial = %{
      modules: %{},
      warnings: [],
      artifact_issues: [],
      stats: %{beams: 0, cached: 0, analyzed: 0, without_debug_info: 0, failed: 0}
    }

    {:ok, sup} = Task.Supervisor.start_link()

    try do
      analyzed_stream =
        sup
        |> Task.Supervisor.async_stream_nolink(
          accepted,
          fn {_package, path} ->
            if is_integer(max_heap_bytes) and max_heap_bytes > 0 do
              words = max(div(max_heap_bytes, :erlang.system_info(:wordsize)), 1)
              :erlang.process_flag(:max_heap_size, %{size: words, kill: true, error_logger: false})
            end

            loader.(path)
          end,
          max_concurrency: concurrency,
          ordered: true,
          timeout: timeout,
          on_timeout: :kill_task
        )
        |> Stream.zip(accepted)
        |> Stream.map(fn
          {{:ok, value}, {package, path}} -> {package, path, value}
          {{:exit, reason}, {package, path}} -> {package, path, {:error, {:worker_exit, reason}}}
        end)

      overflow_results =
        Stream.map(overflow, fn {package, path} ->
          {package, path, {:error, {:beam_file_limit_exceeded, max_files}}}
        end)

      {result, _pool} =
        Stream.concat(analyzed_stream, overflow_results)
        |> Enum.reduce({initial, %{}}, fn
          {package, path, {:ok, {:packed, {strings, packed}}, origin}}, {acc, pool} ->
            {summary, pool} = BeamCodec.unpack(strings, packed, pool)
            {record_summary(acc, package, path, summary, origin), pool}

          {package, path, {:ok, %ModuleSummary{} = summary, origin}}, {acc, pool} ->
            {record_summary(acc, package, path, summary, origin), pool}

          {package, path, {:error, reason}}, {acc, pool} ->
            warning = "could not read #{path}: #{inspect(reason)}"

            acc = %{
              acc
              | stats: acc.stats |> bump(:beams) |> bump(:failed),
                warnings: [warning | acc.warnings],
                artifact_issues: [{package, warning} | acc.artifact_issues]
            }

            {acc, pool}
        end)

      result
      |> Map.update!(:warnings, &Enum.reverse/1)
      |> Map.update!(:artifact_issues, &Enum.reverse/1)
    after
      if Process.alive?(sup), do: Supervisor.stop(sup, :normal)
    end
  end

  defp record_summary(acc, package, path, summary, origin) do
    summary = %{summary | package: package, beam_path: path}
    stats = acc.stats |> bump(:beams) |> bump(origin)
    stats = if summary.has_debug_info, do: stats, else: bump(stats, :without_debug_info)

    case Map.fetch(acc.modules, summary.module) do
      {:ok, existing} ->
        warning =
          "module #{summary.module} is defined in both #{existing.beam_path} and #{path}; " <>
            "using the first"

        %{
          acc
          | stats: stats,
            warnings: [warning | acc.warnings],
            artifact_issues: [
              {package, warning},
              {existing.package, warning} | acc.artifact_issues
            ]
        }

      :error ->
        %{acc | stats: stats, modules: Map.put(acc.modules, summary.module, summary)}
    end
  end

  @doc """
  Summarizes one `.beam` file. Returns `{:ok, summary, :cached | :analyzed}`.
  """
  @spec load_file(String.t(), keyword()) ::
          {:ok, ModuleSummary.t(), :cached | :analyzed} | {:error, term()}
  def load_file(path, opts \\ []) do
    case load_file_packed(path, opts) do
      {:ok, {:packed, {strings, packed}}, origin} ->
        {summary, _pool} = BeamCodec.unpack(strings, packed)
        {:ok, %{summary | beam_path: path}, origin}

      other ->
        other
    end
  end

  defp load_file_packed(path, opts) do
    max_bytes = Keyword.get(opts, :max_beam_bytes, @max_beam_bytes)

    with {:ok, %File.Stat{size: size}} <- File.stat(path),
         :ok <- if(size <= max_bytes, do: :ok, else: {:error, :beam_too_large}),
         {:ok, bytes} <- File.read(path) do
      analyze_binary_packed(bytes, Keyword.put(opts, :beam_path, path))
    end
  end

  @doc """
  Summarizes `.beam` contents held in memory.
  """
  @spec analyze_binary(binary(), keyword()) ::
          {:ok, ModuleSummary.t(), :cached | :analyzed} | {:error, term()}
  def analyze_binary(bytes, opts \\ []) when is_binary(bytes) do
    case analyze_binary_packed(bytes, opts) do
      {:ok, {:packed, {strings, packed}}, origin} ->
        {summary, _pool} = BeamCodec.unpack(strings, packed)
        {:ok, %{summary | beam_path: Keyword.get(opts, :beam_path)}, origin}

      other ->
        other
    end
  end

  defp analyze_binary_packed(bytes, opts) do
    sha = Cache.sha256(bytes)
    root = Keyword.get(opts, :root_dir)
    cache = Keyword.get(opts, :cache, false)
    key = Cache.sha256(["walker-v5", 0, sha, 0, to_string(root)])

    case cache && Cache.get_beam_packed(cache, key) do
      {:ok, pair} ->
        {:ok, {:packed, pair}, :cached}

      _ ->
        with {:ok, summary} <- summarize(bytes, root) do
          summary = %{summary | sha256: sha, beam_path: Keyword.get(opts, :beam_path)}
          if cache, do: Cache.put_beam(cache, key, %{summary | beam_path: nil})
          {:ok, summary, :analyzed}
        end
    end
  end

  defp summarize(bytes, root) do
    with {:ok, module, exports} <- chunk(bytes, :exports) do
      attributes = optional_chunk(bytes, :attributes)

      case chunk(bytes, :abstract_code) do
        {:ok, _module, {_format, forms}} when is_list(forms) ->
          {:ok,
           AbstractWalker.summarize(module, forms,
             root_dir: root,
             attributes: attributes,
             exports: exports
           )}

        _no_abstract_code ->
          {:ok,
           AbstractWalker.summarize_stripped(module,
             exports: exports,
             imports: optional_chunk(bytes, :imports),
             attributes: attributes
           )}
      end
    end
  end

  defp chunk(bytes, name) do
    case :beam_lib.chunks(bytes, [name]) do
      {:ok, {module, [{^name, data}]}} -> {:ok, module, data}
      {:error, :beam_lib, reason} -> {:error, simplify(reason)}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp optional_chunk(bytes, name) do
    case chunk(bytes, name) do
      {:ok, _module, data} when is_list(data) -> data
      _ -> []
    end
  end

  defp simplify({reason, _file_or_binary}) when is_atom(reason), do: reason
  defp simplify({reason, _file, detail}) when is_atom(reason), do: {reason, detail}
  defp simplify(reason), do: reason

  defp bump(stats, key), do: Map.update(stats, key, 1, &(&1 + 1))
end
