defmodule VulnCheck.Diff do
  @moduledoc """
  Incremental reporting for pull requests.

    * Baselines (`--baseline report.json`): findings whose fingerprint is
      in a previous JSON report are hidden. Fingerprints include the
      verdict, so an advisory that moves from `unreachable` to `reachable`
      is new, and the escalation is reported.
    * Git diffs (`--diff <ref>`): keep findings tied to changed packages or
      files. Keep every actionable finding unless a baseline establishes
      that it was already known. A current witness alone cannot establish
      the verdict at the base revision.

  Both fail open: when the baseline or the Git data cannot be read, every
  finding is kept and a warning explains why.
  """

  alias VulnCheck.{Cache, Config, Git}
  alias VulnCheck.Types.{Advisory, Finding, Package, ScanReport, Workspace}
  alias VulnCheck.Workspace.{GleamManifest, MixLock, RebarLock}

  @doc """
  Serializable baseline document of a report.
  """
  @spec baseline_document(ScanReport.t()) :: map()
  def baseline_document(%ScanReport{} = report) do
    %{
      "tool" => "vulncheck",
      "tool_version" => report.tool_version,
      "generated_at" => report.generated_at,
      "findings" =>
        Enum.map(ScanReport.complete_findings(report), fn %Finding{} = f ->
          %{
            "fingerprint" => f.fingerprint,
            "advisory_id" => f.advisory_id,
            "package" => f.package,
            "verdict" => Atom.to_string(f.verdict),
            "installed_version" => f.installed_version,
            "package_scope" => Atom.to_string(f.package_scope),
            "package_identity" => package_identity(report.workspace, f.package),
            "severity" => Atom.to_string(f.severity),
            "suppressed" => f.suppressed
          }
        end)
    }
  end

  @doc "Writes the baseline of a report to `path`."
  @spec write_baseline(ScanReport.t(), Path.t()) :: :ok | {:error, term()}
  def write_baseline(%ScanReport{} = report, path) do
    Cache.atomic_write(path, JSON.encode!(baseline_document(report)))
  end

  @doc """
  Reads a baseline or a full JSON report. Entries without enough evidence to
  compare the version, severity and policy state cannot hide a finding.
  """
  @spec read_baseline(Path.t()) :: {:ok, [map()]} | {:error, String.t()}
  def read_baseline(path) do
    with {:ok, data} <- File.read(path),
         {:ok, %{"findings" => findings}} when is_list(findings) <- JSON.decode(data) do
      {:ok,
       for %{"fingerprint" => fingerprint} = entry <- findings, is_binary(fingerprint) do
         %{
           fingerprint: fingerprint,
           advisory_id: string(entry["advisory_id"]),
           package: string(entry["package"]),
           verdict: string(entry["verdict"]),
           version: entry["installed_version"],
           scope: entry["package_scope"],
           identity: entry["package_identity"],
           severity: entry["severity"],
           suppressed: entry["suppressed"]
         }
       end}
    else
      {:error, reason} when is_atom(reason) -> {:error, "#{path}: #{:file.format_error(reason)}"}
      _ -> {:error, "#{path}: not a vulncheck JSON report"}
    end
  end

  @doc """
  Hides findings present in the baseline. Returns the remaining findings and
  warnings (escalations, number of hidden findings).
  """
  @spec apply_baseline([Finding.t()], [map()], Workspace.t() | nil) :: {[Finding.t()], [String.t()]}
  def apply_baseline(findings, entries, workspace \\ nil) do
    known = Enum.group_by(entries, & &1.fingerprint)
    previous = Map.new(entries, &{{&1.advisory_id, &1.package}, &1.verdict})

    {kept, hidden} =
      Enum.split_with(findings, fn f ->
        not Enum.any?(Finding.fingerprints(f), fn fingerprint ->
          Enum.any?(Map.get(known, fingerprint, []), &same_finding?(&1, f, workspace))
        end)
      end)

    escalations =
      for %Finding{verdict: verdict} = f <- kept,
          verdict in [:reachable, :potentially_reachable],
          old = previous_verdict(previous, f),
          old in ["unreachable", "retired"] or
            (old == "potentially_reachable" and verdict == :reachable) do
        "#{f.advisory_id} (#{f.package}) escalated from #{old} to #{verdict}"
      end

    hidden_note =
      if hidden == [],
        do: [],
        else: ["#{length(hidden)} finding(s) already present in the baseline"]

    {kept, escalations ++ hidden_note}
  end

  defp same_finding?(entry, finding, workspace) do
    severity = Advisory.parse_severity(entry.severity)
    identity = package_identity(workspace, finding.package)

    entry.version == finding.installed_version and
      entry.scope == Atom.to_string(finding.package_scope) and
      entry.identity == identity and (workspace == nil or is_binary(identity)) and
      is_boolean(entry.suppressed) and entry.suppressed == finding.suppressed and
      not finding.suppression_expired and
      (severity != :unknown or entry.severity == "unknown") and
      Config.severity_rank(severity) >= Config.severity_rank(finding.severity)
  end

  defp previous_verdict(previous, %Finding{} = f) do
    Enum.find_value(Enum.uniq([f.advisory_id | f.aliases]), &previous[{&1, f.package}])
  end

  @doc "Scanner post-processing step for `--baseline`."
  @spec baseline_step(Path.t()) :: (list(), map() -> {list(), [String.t()], [String.t()]})
  def baseline_step(path) do
    fn findings, %{config: config, workspace: workspace} ->
      case read_baseline(Path.expand(path, Config.project_root(config))) do
        {:ok, entries} ->
          {kept, warnings} = apply_baseline(findings, entries, workspace)
          {kept, [], warnings}

        {:error, message} ->
          {findings, [], ["baseline ignored: #{message}"]}
      end
    end
  end

  @doc "Scanner post-processing step for `--diff <ref>`."
  @spec diff_step(String.t()) :: (list(), map() -> {list(), [String.t()], [String.t()]})
  def diff_step(ref) do
    fn findings, %{workspace: workspace, config: config} ->
      root = Config.project_root(config)

      with {:ok, changed_packages} <- changed_packages(workspace, root, ref),
           {:ok, files} <- Git.changed_files(root, ref) do
        files = MapSet.new(files)

        {kept, hidden} =
          Enum.split_with(findings, fn %Finding{} = f ->
            (Finding.active?(f) and (f.verdict != :unreachable or config.fail_on == :any)) or
              MapSet.member?(changed_packages, f.package) or
              Enum.any?(f.trace, &(is_binary(&1.file) and MapSet.member?(files, &1.file)))
          end)

        note =
          if hidden == [],
            do: [],
            else: ["#{length(hidden)} finding(s) unrelated to changes since #{ref} hidden"]

        {kept, [], note}
      else
        {:error, reason} ->
          {findings, [], ["diff against #{ref} ignored: #{inspect(reason)}"]}
      end
    end
  end

  @doc """
  Packages added or whose locked identity changed since `ref`.
  """
  @spec changed_packages(Workspace.t(), String.t(), String.t()) ::
          {:ok, MapSet.t(String.t())} | {:error, term()}
  def changed_packages(%Workspace{lockfile: lockfile, packages: packages}, root, ref) do
    relative = Path.relative_to(lockfile || "", root)

    base =
      case Git.show(root, ref, relative) do
        {:ok, content} -> parse_lock(Path.basename(relative), content)
        {:error, :not_found} -> {:ok, %{}}
        error -> error
      end

    with {:ok, base} <- base do
      changed =
        for {name, package} <- packages,
            identity(package) != identity(Map.get(base, name)),
            into: MapSet.new(),
            do: name

      {:ok, changed}
    end
  end

  @doc "Stable identity of a locked package for baseline comparisons."
  @spec package_identity(Workspace.t() | nil, String.t()) :: String.t() | nil
  def package_identity(%Workspace{packages: packages}, name) do
    case Map.get(packages, name) do
      %Package{} = package -> Cache.sha256(:erlang.term_to_binary(identity(package)))
      nil -> nil
    end
  end

  def package_identity(nil, _name), do: nil

  defp identity(nil), do: nil

  defp identity(%Package{} = package) do
    {package.source, package.hex_name, package.version, package.git_url, package.git_ref,
     package.checksum, package.inner_checksum, Enum.sort(package.deps)}
  end

  defp parse_lock("mix.lock", content), do: MixLock.parse(content)
  defp parse_lock("rebar.lock", content), do: RebarLock.parse(content)

  defp parse_lock("manifest.toml", content), do: GleamManifest.parse_manifest(content)

  defp parse_lock(other, _content), do: {:error, {:unsupported_lockfile, other}}

  defp string(value) when is_binary(value), do: value
  defp string(_), do: ""
end
