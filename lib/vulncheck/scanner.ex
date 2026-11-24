defmodule VulnCheck.Scanner do
  @moduledoc """
  End-to-end scan pipeline:

    1. load the workspace (lockfiles, scopes, build directories),
    2. load and enrich matching advisories (OSV, EEF CNA, Hex.pm),
    3. summarize compiled `.beam` files and build the call graph,
    4. synthesize OTP/framework entrypoints and edges,
    5. classify every advisory,
    6. apply suppressions (`.vulncheck.ignore`), `--baseline` and `--diff`,
       then any extra post-processing steps.

  Steps 3 and 4 are skipped when no advisory needs code analysis.
  """

  alias VulnCheck.{Config, Diff, Entrypoints, Ignore, Solver}
  alias VulnCheck.Beam.{CallGraph, Loader}
  alias VulnCheck.Feeds.Store
  alias VulnCheck.Types.{ScanReport, Summary}
  alias VulnCheck.Workspace

  @doc """
  Runs a scan.

  Options are passed to the feed loader (`:http_client`, `:osv_url`,
  `:cna_base_url`, `:mitre_base_url`, `:hex_api_url`, ...). In addition:

    * `:beam_cache` — `false` disables the `.beam` summary cache
    * `:ignore` — `false` skips the ignore file
    * `:today` — date used to evaluate suppression expiry
    * `:postprocess` — list of `fun(findings, report_context) -> {findings, violations, warnings}`
  """
  @spec run(Config.t(), keyword()) :: {:ok, ScanReport.t()} | {:error, term()}
  def run(%Config{} = config, opts \\ []) do
    started = System.monotonic_time(:millisecond)

    with {:ok, workspace, t_workspace} <- timed(fn -> Workspace.load(config) end),
         {:ok, feed, t_feeds} <- timed(fn -> load_feeds(workspace, config, opts) end) do
      {code, t_code} = timed_value(fn -> analyze_code(workspace, config, feed.advisories, opts) end)

      {findings, t_solve} =
        timed_value(fn ->
          Solver.solve(workspace, code.graph, code.model, feed.advisories, config)
        end)

      context = %{workspace: workspace, config: config}

      {all_findings, ignore_violations, ignore_warnings} =
        if Keyword.get(opts, :ignore, true) do
          Ignore.step(Keyword.take(opts, [:today])).(findings, context)
        else
          {findings, [], []}
        end

      {findings, violations, post_warnings} =
        config
        |> filters()
        |> Kernel.++(Keyword.get(opts, :postprocess, []))
        |> Enum.reduce(
          {all_findings, ignore_violations, ignore_warnings},
          fn step, {findings, violations, warnings} ->
            {findings, new_violations, new_warnings} = step.(findings, context)
            {findings, violations ++ new_violations, warnings ++ new_warnings}
          end
        )

      findings = Solver.sort(findings)

      report =
        %ScanReport{
          workspace: workspace,
          generated_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
          tool_version: VulnCheck.version(),
          findings: findings,
          all_findings: Solver.sort(all_findings),
          summary: Summary.from_findings(findings),
          policy_violations: violations,
          warnings:
            Enum.uniq(
              workspace.warnings ++
                feed.warnings ++
                code.warnings ++ post_warnings ++ Solver.dynamic_dispatch_warnings(findings)
            ),
          duration_ms: System.monotonic_time(:millisecond) - started,
          stats:
            feed.stats
            |> Map.merge(code.stats)
            |> Map.merge(%{
              packages: map_size(workspace.packages),
              timings_ms: %{
                workspace: t_workspace,
                feeds: t_feeds,
                code: t_code,
                solve: t_solve
              }
            })
        }

      write_baseline(report, config)
    end
  end

  defp filters(config) do
    baseline = if config.baseline, do: [Diff.baseline_step(config.baseline)], else: []
    diff = if config.diff, do: [Diff.diff_step(config.diff)], else: []
    baseline ++ diff
  end

  defp write_baseline(report, %Config{write_baseline: nil}), do: {:ok, report}

  defp write_baseline(report, %Config{write_baseline: path} = config) do
    case Diff.write_baseline(report, Path.expand(path, Config.project_root(config))) do
      :ok -> {:ok, report}
      {:error, reason} -> {:error, {:write_baseline, path, reason}}
    end
  end

  defp load_feeds(workspace, config, opts) do
    case Store.load(workspace, config, opts) do
      {:ok, feed} -> {:ok, feed}
      {:error, reason} -> {:error, {:feeds, reason}}
    end
  end

  defp analyze_code(workspace, config, advisories, opts) do
    needed? =
      Enum.any?(advisories, fn advisory ->
        is_nil(advisory.retirement) and
          match?(
            %{scope: scope} when scope in [:prod, :build_only],
            workspace.packages[advisory.package]
          )
      end)

    if needed? do
      cache = if Keyword.get(opts, :beam_cache, true), do: config, else: false
      loaded = Loader.load_workspace(workspace, config, cache: cache)
      graph = CallGraph.build(loaded.modules)
      {model, graph} = Entrypoints.build(workspace, graph, config)

      model = %{
        model
        | artifact_issues:
            loaded.artifact_issues ++ workspace.artifact_issues ++ model.artifact_issues
      }

      analysis = artifact_analysis(loaded, model, workspace)

      %{
        graph: graph,
        model: model,
        warnings: loaded.warnings ++ model.notes ++ analysis.issues,
        stats:
          Map.merge(loaded.stats, %{
            analysis: analysis,
            modules: map_size(loaded.modules),
            edges: CallGraph.edge_count(graph),
            roots: length(model.roots),
            started_otp_apps: length(model.started_otp_apps)
          })
      }
    else
      %{
        graph: nil,
        model: nil,
        warnings: [],
        stats: %{modules: 0, edges: 0, roots: 0, analysis: %{status: :not_needed, issues: []}}
      }
    end
  end

  defp artifact_analysis(loaded, model, workspace) do
    issues = model.artifact_issues |> Enum.map(&elem(&1, 1)) |> Enum.uniq()
    stripped = loaded.stats.without_debug_info

    issues =
      if stripped > 0, do: issues ++ ["#{stripped} BEAM file(s) lack debug info"], else: issues

    status =
      cond do
        map_size(loaded.modules) == 0 -> :unavailable
        not loaded.profile_matches -> :unsuitable
        issues != [] -> :partial
        true -> :complete
      end

    digest =
      if map_size(loaded.modules) > 0 do
        files =
          Enum.map(loaded.modules, fn {name, module} -> {name, module.package, module.sha256} end)

        evidence = {Enum.sort(files), model.roots, model.started_otp_apps, model.synthetic_edges}
        evidence |> :erlang.term_to_binary([:deterministic]) |> VulnCheck.Cache.sha256()
      end

    %{status: status, build_profile: workspace.build_env, issues: issues, artifact_digest: digest}
  end

  defp timed(fun) do
    {value, ms} = timed_value(fun)

    case value do
      {:ok, result} -> {:ok, result, ms}
      {:error, _} = error -> error
    end
  end

  defp timed_value(fun) do
    started = System.monotonic_time(:millisecond)
    value = fun.()
    {value, System.monotonic_time(:millisecond) - started}
  end
end
