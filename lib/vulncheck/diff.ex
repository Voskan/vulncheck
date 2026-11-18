defmodule VulnCheck.Diff do
  @moduledoc """
  Incremental reporting for pull requests.

    * Baselines (`--baseline report.json`): findings whose fingerprint is
      in a previous JSON report are hidden. Fingerprints include the
      verdict, so an advisory that moves from `unreachable` to `reachable`
      is new, and the escalation is reported.
    * Git diffs (`--diff <ref>`): only findings for packages added or
      upgraded since `<ref>`, or whose witness trace passes through a
      project file changed since `<ref>`, are kept.

  Both fail open: when the baseline or the Git data cannot be read, every
  finding is kept and a warning explains why.
  """

  alias VulnCheck.{Config, Git}
  alias VulnCheck.Types.{Finding, ScanReport, Workspace}
  alias VulnCheck.Workspace.{GleamManifest, MixLock, RebarLock}

  @doc """
  Serializable baseline document of a report.
  """
  @spec baseline_document(ScanReport.t()) :: map()
  def baseline_document(%ScanReport{findings: findings} = report) do
    %{
      "tool" => "vulncheck",
      "tool_version" => report.tool_version,
      "generated_at" => report.generated_at,
      "findings" =>
        Enum.map(findings, fn %Finding{} = f ->
          %{
            "fingerprint" => f.fingerprint,
            "advisory_id" => f.advisory_id,
            "package" => f.package,
            "verdict" => Atom.to_string(f.verdict)
          }
        end)
    }
  end

  @doc "Writes the baseline of a report to `path`."
  @spec write_baseline(ScanReport.t(), Path.t()) :: :ok | {:error, term()}
  def write_baseline(%ScanReport{} = report, path) do
    File.mkdir_p!(Path.dirname(path))
    File.write(path, JSON.encode!(baseline_document(report)))
  end

  @doc """
  Reads a baseline or a full JSON report. Only `findings[].fingerprint`,
  `advisory_id`, `package` and `verdict` are used.
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
           verdict: string(entry["verdict"])
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
  @spec apply_baseline([Finding.t()], [map()]) :: {[Finding.t()], [String.t()]}
  def apply_baseline(findings, entries) do
    known = MapSet.new(entries, & &1.fingerprint)
    previous = Map.new(entries, &{{&1.advisory_id, &1.package}, &1.verdict})

    {kept, hidden} =
      Enum.split_with(findings, fn f ->
        not Enum.any?(Finding.fingerprints(f), &MapSet.member?(known, &1))
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

  defp previous_verdict(previous, %Finding{} = f) do
    Enum.find_value(Enum.uniq([f.advisory_id | f.aliases]), &previous[{&1, f.package}])
  end

  @doc "Scanner post-processing step for `--baseline`."
  @spec baseline_step(Path.t()) :: (list(), map() -> {list(), [String.t()], [String.t()]})
  def baseline_step(path) do
    fn findings, %{config: config} ->
      case read_baseline(Path.expand(path, Config.project_root(config))) do
        {:ok, entries} ->
          {kept, warnings} = apply_baseline(findings, entries)
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
  Packages added or whose locked version changed since `ref`.
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
            not match?(%{version: v} when v == package.version, Map.get(base, name)),
            into: MapSet.new(),
            do: name

      {:ok, changed}
    end
  end

  defp parse_lock("mix.lock", content), do: MixLock.parse(content)
  defp parse_lock("rebar.lock", content), do: RebarLock.parse(content)

  defp parse_lock("manifest.toml", content), do: GleamManifest.parse_manifest(content)

  defp parse_lock(other, _content), do: {:error, {:unsupported_lockfile, other}}

  defp string(value) when is_binary(value), do: value
  defp string(_), do: ""
end
