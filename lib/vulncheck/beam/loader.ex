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

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Beam.AbstractWalker
  alias VulnCheck.Types.{CallEdge, DynamicCall, MFA, ModuleSummary, Workspace}

  @max_beam_bytes 64 * 1024 * 1024

  # Cached summaries are decoded with `binary_to_term(bin, [:safe])`, which
  # only accepts atoms that already exist. Every atom a summary holds is
  # defined by one of these modules, and modules load lazily, so they are
  # loaded before the first decode; otherwise a fresh VM would treat its
  # first cache hits as misses.
  @summary_modules [ModuleSummary, CallEdge, DynamicCall, MFA, AbstractWalker]

  @type result :: %{
          modules: %{String.t() => ModuleSummary.t()},
          warnings: [String.t()],
          stats: %{atom() => non_neg_integer()}
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

    result = load_dirs(dirs, opts)
    consolidated = load_dirs(Enum.map(workspace.consolidated_dirs, &{nil, &1}), opts)

    modules =
      Enum.reduce(consolidated.modules, result.modules, fn {name, summary}, acc ->
        package = acc |> Map.get(name, %{package: nil}) |> Map.get(:package)
        Map.put(acc, name, %{summary | package: package})
      end)

    %{
      modules: modules,
      warnings: result.warnings ++ consolidated.warnings,
      stats: Map.merge(result.stats, consolidated.stats, fn _key, a, b -> a + b end)
    }
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

    indexed = Enum.with_index(files)

    concurrency = Keyword.get(opts, :max_concurrency, System.schedulers_online())

    initial = %{
      modules: %{},
      warnings: [],
      stats: %{beams: 0, cached: 0, analyzed: 0, without_debug_info: 0, failed: 0}
    }

    indexed
    |> Task.async_stream(
      fn {{package, path}, index} -> {index, {package, path, load_file(path, opts)}} end,
      max_concurrency: concurrency,
      ordered: false,
      timeout: :infinity
    )
    |> Enum.map(fn {:ok, value} -> value end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(&elem(&1, 1))
    |> Enum.reduce(initial, fn
      {package, path, {:ok, summary, origin}}, acc ->
        summary = %{summary | package: package, beam_path: path}
        stats = acc.stats |> bump(:beams) |> bump(origin)
        stats = if summary.has_debug_info, do: stats, else: bump(stats, :without_debug_info)

        case Map.fetch(acc.modules, summary.module) do
          {:ok, existing} ->
            warning =
              "module #{summary.module} is defined in both #{existing.beam_path} and #{path}; " <>
                "using the first"

            %{acc | stats: stats, warnings: [warning | acc.warnings]}

          :error ->
            %{acc | stats: stats, modules: Map.put(acc.modules, summary.module, summary)}
        end

      {_package, path, {:error, reason}}, acc ->
        warning = "could not read #{path}: #{inspect(reason)}"

        %{
          acc
          | stats: acc.stats |> bump(:beams) |> bump(:failed),
            warnings: [warning | acc.warnings]
        }
    end)
    |> Map.update!(:warnings, &Enum.reverse/1)
  end

  @doc """
  Summarizes one `.beam` file. Returns `{:ok, summary, :cached | :analyzed}`.
  """
  @spec load_file(String.t(), keyword()) ::
          {:ok, ModuleSummary.t(), :cached | :analyzed} | {:error, term()}
  def load_file(path, opts \\ []) do
    with {:ok, %File.Stat{size: size}} <- File.stat(path),
         :ok <- if(size <= @max_beam_bytes, do: :ok, else: {:error, :beam_too_large}),
         {:ok, bytes} <- File.read(path) do
      analyze_binary(bytes, Keyword.put(opts, :beam_path, path))
    end
  end

  @doc """
  Summarizes `.beam` contents held in memory.
  """
  @spec analyze_binary(binary(), keyword()) ::
          {:ok, ModuleSummary.t(), :cached | :analyzed} | {:error, term()}
  def analyze_binary(bytes, opts \\ []) when is_binary(bytes) do
    sha = Cache.sha256(bytes)
    root = Keyword.get(opts, :root_dir)
    cache = Keyword.get(opts, :cache, false)
    key = Cache.sha256([sha, 0, to_string(root)])

    case cache && Cache.get_beam(cache, key) do
      {:ok, %ModuleSummary{} = summary} ->
        {:ok, %{summary | beam_path: Keyword.get(opts, :beam_path)}, :cached}

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
