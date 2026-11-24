defmodule VulnCheck.Report.Formatter do
  @moduledoc """
  Contract of report renderers plus helpers shared by them.
  """

  alias VulnCheck.Types.{Advisory, Finding, MFA, Package, TraceHop, Workspace}

  @callback render(VulnCheck.Types.ScanReport.t(), VulnCheck.Config.t()) :: String.t()

  @reason_labels %{
    call_chain_proven: "call chain proven",
    daemon_call_chain: "called from an active network daemon",
    active_network_daemon: "active network daemon",
    unresolved_dynamic_dispatch: "unresolved dynamic dispatch",
    missing_symbol_granularity: "no function-level advisory data",
    missing_beam_debug_info: "missing .beam debug info",
    package_retired: "retired on Hex.pm",
    non_prod_dependency: "non-production dependency",
    otp_version_unaffected: "OTP version unaffected",
    otp_app_not_started: "OTP application not started",
    adapter_not_configured: "adapter not configured",
    module_not_loaded: "module not loaded",
    function_not_called: "function not called"
  }

  @doc "Identifier shown to humans: the CVE alias when there is one."
  @spec display_id(Finding.t()) :: String.t()
  def display_id(%Finding{} = finding), do: Finding.cve_id(finding) || finding.advisory_id

  @doc """
  Identifier with the other names of the vulnerability, for example
  `CVE-2026-39804 (GHSA-frh3-6pv6-rc8j)`. Identifiers that only wrap the CVE
  (such as `EEF-CVE-…`) are left out.
  """
  @spec title_id(Finding.t()) :: String.t()
  def title_id(%Finding{advisory_id: id, aliases: aliases} = finding) do
    shown = display_id(finding)

    case Enum.reject(Enum.uniq([id | aliases]), &String.contains?(&1, shown)) do
      [] -> shown
      others -> "#{shown} (#{Enum.join(others, ", ")})"
    end
  end

  @doc "Upper-case severity label."
  @spec severity_label(Advisory.severity()) :: String.t()
  def severity_label(severity), do: severity |> Atom.to_string() |> String.upcase()

  @doc "Severity with CVSS score, e.g. `HIGH · CVSS 7.5`."
  @spec severity_text(Finding.t(), String.t()) :: String.t()
  def severity_text(%Finding{} = finding, separator \\ " · ") do
    case finding.cvss_score do
      score when is_number(score) ->
        severity_label(finding.severity) <> separator <> "CVSS " <> format_score(score)

      _ ->
        severity_label(finding.severity)
    end
  end

  @doc "Formats a CVSS score with one decimal."
  @spec format_score(number()) :: String.t()
  def format_score(score), do: :erlang.float_to_binary(score / 1, decimals: 1)

  @doc "Human description of a reason code."
  @spec reason_label(Finding.reason()) :: String.t()
  def reason_label(reason), do: Map.get(@reason_labels, reason, Atom.to_string(reason))

  @doc "The specific recommended fixed release, or `nil`."
  @spec fix_text(Finding.t()) :: String.t() | nil
  def fix_text(%Finding{recommended_fix: fix}), do: fix

  @doc "Formats an MFA in Elixir or Erlang notation."
  @spec mfa(MFA.t() | nil) :: String.t() | nil
  def mfa(nil), do: nil
  def mfa(%MFA{} = mfa), do: MFA.format(mfa)

  @doc """
  Text of a trace hop: the function, followed by what an activation hop
  does (`MyApp.Application.start/2 starts Bandit`), or the note alone when
  the activation is not a function.
  """
  @spec hop(TraceHop.t()) :: String.t()
  def hop(%TraceHop{mfa: nil, note: note}), do: note || ""
  def hop(%TraceHop{mfa: mfa, note: nil}), do: MFA.format(mfa)
  def hop(%TraceHop{mfa: mfa, note: note}), do: "#{MFA.format(mfa)} #{note}"

  @doc """
  Trace hops with their step numbers. The activation hop is step 0, so the
  entrypoint is step 1 in every chain.
  """
  @spec numbered([TraceHop.t()]) :: [{TraceHop.t(), non_neg_integer()}]
  def numbered([%TraceHop{} = first | _] = hops) do
    Enum.with_index(hops, if(TraceHop.activation?(first), do: 0, else: 1))
  end

  def numbered([]), do: []

  @doc "Location of a trace hop (`file:line`), or `nil`."
  @spec location(TraceHop.t()) :: String.t() | nil
  def location(%TraceHop{file: nil}), do: nil
  def location(%TraceHop{file: file, line: nil}), do: file
  def location(%TraceHop{file: file, line: line}), do: "#{file}:#{line}"

  @doc "Findings grouped by verdict, preserving report order."
  @spec by_verdict([Finding.t()]) :: %{atom() => [Finding.t()]}
  def by_verdict(findings) do
    active = Enum.reject(findings, & &1.suppressed)

    Map.merge(
      %{reachable: [], potentially_reachable: [], retired: [], unreachable: []},
      Enum.group_by(active, & &1.verdict)
    )
  end

  @doc """
  Findings a machine-readable report emits: active actionable findings,
  plus unreachable ones when `show_unreachable` is set.
  """
  @spec reported([Finding.t()], boolean()) :: [Finding.t()]
  def reported(findings, show_unreachable) do
    Enum.filter(findings, fn finding ->
      not finding.suppressed and (finding.verdict != :unreachable or show_unreachable)
    end)
  end

  @doc """
  Returns `true` for a path inside the project's own source tree (relative,
  outside `deps/` and `_build/`).
  """
  @spec project_file?(String.t() | nil) :: boolean()
  def project_file?(file) when is_binary(file) do
    Path.type(file) == :relative and
      not String.starts_with?(file, ["deps/", "_build/", "../"]) and
      file not in ["", ".", "..", "deps", "_build"]
  end

  def project_file?(_file), do: false

  @doc """
  Relative directory prefix of `workspace.root_dir` inside the surrounding Git
  repository (or CI workspace `GITHUB_WORKSPACE` / `CI_PROJECT_DIR`), or `""`
  when the project is already at the repository root or no repository ancestor
  exists. Used by repository-level CI and SARIF reporters (`--project-dir` in
  monorepos).
  """
  @spec repo_prefix(Workspace.t() | nil) :: String.t()
  def repo_prefix(nil), do: ""

  def repo_prefix(%Workspace{root_dir: root_dir}) when is_binary(root_dir) do
    project_root = Path.expand(root_dir)

    env_repo_prefix(project_root) ||
      if File.dir?(project_root) do
        git_repo_prefix(project_root)
      else
        ""
      end
  end

  def repo_prefix(_workspace), do: ""

  @doc """
  Prepends `prefix` to a relative path `file`. Absolute paths, `nil` and empty
  prefixes are returned unchanged.
  """
  @spec prefix_path(String.t() | nil, String.t()) :: String.t() | nil
  def prefix_path(nil, _prefix), do: nil
  def prefix_path(file, ""), do: file

  def prefix_path(file, prefix) when is_binary(file) and is_binary(prefix) do
    if Path.type(file) == :relative, do: Path.join(prefix, file), else: file
  end

  defp env_repo_prefix(project_root) do
    ["GITHUB_WORKSPACE", "CI_PROJECT_DIR"]
    |> Enum.find_value(fn var ->
      case System.get_env(var) do
        base when is_binary(base) and base != "" ->
          expanded = Path.expand(base)

          if ancestor_dir?(expanded, project_root),
            do: Path.relative_to(project_root, expanded)

        _ ->
          nil
      end
    end)
  end

  defp git_repo_prefix(project_root) do
    case find_git_root(project_root) do
      nil -> ""
      ^project_root -> ""
      git_root -> Path.relative_to(project_root, git_root)
    end
  end

  defp find_git_root(dir) do
    if File.exists?(Path.join(dir, ".git")) do
      dir
    else
      parent = Path.dirname(dir)
      if parent == dir, do: nil, else: find_git_root(parent)
    end
  end

  defp ancestor_dir?(base, target) do
    normalized = String.trim_trailing(base, "/")
    target != base and String.starts_with?(target, normalized <> "/")
  end

  @doc """
  Location used to annotate a finding. Chooses the first trace hop in the
  project source tree, or the package entry in the lockfile.
  """
  @spec primary_location(Finding.t(), Workspace.t() | nil) :: {String.t(), pos_integer()}
  def primary_location(%Finding{} = finding, workspace) do
    case project_locations(finding.trace, workspace) do
      [%TraceHop{file: file, line: line} | _] -> {file, line}
      [] -> lock_location(finding, workspace)
    end
  end

  @doc "Trace hops that can be annotated in the project, with normalized paths."
  @spec project_locations([TraceHop.t()], Workspace.t() | nil) :: [TraceHop.t()]
  def project_locations(hops, workspace) do
    root = if workspace, do: Path.expand(workspace.root_dir), else: "/vulncheck-project"
    prefix = repo_prefix(workspace)

    for %TraceHop{file: file, line: line} = hop <- hops,
        is_binary(file) and file != "" and String.valid?(file),
        path = Path.relative_to(Path.expand(file, root), root),
        project_file?(path),
        do: %{
          hop
          | file: prefix_path(path, prefix),
            line: if(is_integer(line) and line > 0, do: line, else: 1)
        }
  end

  defp lock_location(_finding, nil), do: {"mix.lock", 1}

  defp lock_location(%Finding{package: name}, %Workspace{} = ws) do
    line =
      case Map.get(ws.packages, name) do
        %Package{lock_line: line} when is_integer(line) and line > 0 -> line
        _ -> 1
      end

    {prefix_path(manifest(ws), repo_prefix(ws)), line}
  end

  defp manifest(%Workspace{lockfile: lockfile, root_dir: root}) when is_binary(lockfile),
    do: Path.relative_to(Path.expand(lockfile, root), Path.expand(root))

  defp manifest(%Workspace{project_type: :rebar3}), do: "rebar.config"
  defp manifest(%Workspace{project_type: :gleam}), do: "gleam.toml"
  defp manifest(_workspace), do: "mix.exs"

  @doc "Advisory web page for a finding."
  @spec help_uri(Finding.t()) :: String.t()
  def help_uri(%Finding{verdict: :retired, package: package, installed_version: version}),
    do: "https://hex.pm/packages/#{package}/#{version}"

  def help_uri(%Finding{references: [url | _]}) when is_binary(url), do: url
  def help_uri(%Finding{advisory_id: id}), do: "https://osv.dev/vulnerability/" <> URI.encode(id)

  @doc """
  Numeric severity used by code scanning dashboards: the CVSS score or, when
  unknown, a representative score of the severity band (unknown counts as
  critical).
  """
  @spec security_severity(Finding.t()) :: String.t()
  def security_severity(%Finding{cvss_score: score}) when is_number(score), do: format_score(score)

  def security_severity(%Finding{severity: severity}) do
    case severity do
      :high -> "8.0"
      :medium -> "5.5"
      :low -> "3.0"
      :none -> "0.0"
      _ -> "9.5"
    end
  end
end
