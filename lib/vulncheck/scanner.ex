defmodule VulnCheck.Scanner do
  @moduledoc """
  End-to-end scan pipeline:

    1. load the workspace (lockfiles, scopes, build directories),
    2. load and enrich matching advisories (OSV, EEF CNA, Hex.pm),
    3. summarize compiled `.beam` files and build the call graph,
    4. synthesize OTP/framework entrypoints and edges,
    5. classify every advisory,
    6. apply post-processing steps (suppressions, baselines, ...).

  Steps 3 and 4 are skipped when no advisory needs code analysis.
  """

  alias VulnCheck.{Config, Entrypoints, Solver}
  alias VulnCheck.Beam.{CallGraph, Loader}
  alias VulnCheck.Feeds.Store
  alias VulnCheck.Types.{ScanReport, Summary}
  alias VulnCheck.Workspace

  @doc """
  Runs a scan.

  Options are passed to the feed loader (`:http_client`, `:osv_url`,
  `:cna_base_url`, `:mitre_base_url`, `:hex_api_url`, ...). In addition:

    * `:beam_cache` — `false` disables the `.beam` summary cache
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

      {findings, violations, post_warnings} =
        opts
        |> Keyword.get(:postprocess, [])
        |> Enum.reduce({findings, [], []}, fn step, {findings, violations, warnings} ->
          {findings, new_violations, new_warnings} = step.(findings, context)
          {findings, violations ++ new_violations, warnings ++ new_warnings}
        end)

      findings = Solver.sort(findings)

      {:ok,
       %ScanReport{
         workspace: workspace,
         generated_at: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
         tool_version: VulnCheck.version(),
         findings: findings,
         summary: Summary.from_findings(findings),
         policy_violations: violations,
         warnings: Enum.uniq(workspace.warnings ++ feed.warnings ++ code.warnings ++ post_warnings),
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
       }}
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
          match?(%{scope: scope} when scope != :non_prod, workspace.packages[advisory.package])
      end)

    if needed? do
      cache = if Keyword.get(opts, :beam_cache, true), do: config, else: false
      loaded = Loader.load_workspace(workspace, config, cache: cache)
      graph = CallGraph.build(loaded.modules)
      {model, graph} = Entrypoints.build(workspace, graph, config)

      %{
        graph: graph,
        model: model,
        warnings: loaded.warnings ++ model.notes,
        stats:
          Map.merge(loaded.stats, %{
            modules: map_size(loaded.modules),
            edges: CallGraph.edge_count(graph),
            roots: length(model.roots),
            started_otp_apps: length(model.started_otp_apps)
          })
      }
    else
      %{graph: nil, model: nil, warnings: [], stats: %{modules: 0, edges: 0, roots: 0}}
    end
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
