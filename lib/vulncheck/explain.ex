defmodule VulnCheck.Explain do
  @moduledoc """
  Looks up one advisory and, when the target directory is a project that
  locks the affected package, its local reachability status.

  Identifiers are matched case-insensitively against advisory ids and
  aliases; `CVE-2026-1234` also matches `EEF-CVE-2026-1234`.
  """

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Feeds.{EefCna, OSV}
  alias VulnCheck.Report.Formatter
  alias VulnCheck.Solver.RoutineScope
  alias VulnCheck.Types.{Advisory, Finding, MFA, VersionRange, Workspace}
  alias VulnCheck.Workspace.Detector

  @type local ::
          nil
          | %{workspace: Workspace.t(), findings: [Finding.t()]}
          | %{error: term()}

  @type result :: %{
          query: String.t(),
          advisories: [Advisory.t()],
          local: local(),
          warnings: [String.t()]
        }

  @doc """
  Finds the advisory `id`. Options are feed options accepted by
  `VulnCheck.Scanner.run/2` (`:osv_url`, `:cna_base_url`, `:http_client`, ...).
  """
  @spec run(String.t(), Config.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def run(id, %Config{} = config, opts \\ []) do
    with :ok <- import_bundle(config),
         {:ok, advisories} <- load(config, opts),
         {:ok, matches} <- find(advisories, id) do
      {enriched, warnings} = enrich(matches, config, opts)

      {:ok,
       %{query: id, advisories: enriched, local: local(config, opts, enriched), warnings: warnings}}
    end
  end

  defp import_bundle(%Config{bundle: nil}), do: :ok

  defp import_bundle(%Config{bundle: bundle} = config) do
    case Cache.import_bundle(bundle, config) do
      {:ok, _manifest} -> :ok
      {:error, reason} -> {:error, {:feeds, {:bundle, reason}}}
    end
  end

  defp load(config, opts) do
    case OSV.load(config, opts) do
      {:ok, advisories, _status} -> {:ok, advisories}
      {:error, :offline_cache_missing} -> {:error, {:feeds, :offline_cache_missing}}
      {:error, reason} -> {:error, {:feeds, {:osv_feed, reason}}}
    end
  end

  @doc "Advisories whose id or aliases match `id`."
  @spec find([Advisory.t()], String.t()) ::
          {:ok, [Advisory.t()]} | {:error, {:advisory_not_found, String.t()}}
  def find(advisories, id) do
    wanted = id |> String.trim() |> String.upcase()
    wanted_cve = cve(wanted)

    matches =
      Enum.filter(advisories, fn advisory ->
        identifiers = Enum.map([advisory.id | advisory.aliases], &String.upcase/1)
        wanted in identifiers or (wanted_cve != nil and Advisory.cve_id(advisory) == wanted_cve)
      end)

    if matches == [],
      do: {:error, {:advisory_not_found, id}},
      else: {:ok, Enum.sort_by(matches, & &1.package)}
  end

  defp cve(id) do
    case Regex.run(~r/(CVE-\d{4}-\d{4,})/, id) do
      [_, cve] -> cve
      _ -> nil
    end
  end

  defp enrich(advisories, config, opts) do
    Enum.map_reduce(advisories, [], fn advisory, warnings ->
      case EefCna.enrich(advisory, config, opts) do
        {:ok, enriched} ->
          {enriched, warnings}

        {:error, reason} ->
          {advisory,
           warnings ++ ["CVE 5.1 record unavailable for #{advisory.id}: #{inspect(reason)}"]}
      end
    end)
  end

  defp local(config, opts, advisories) do
    case Detector.detect(config.project_dir) do
      {:ok, _info} ->
        ids = MapSet.new(advisories, & &1.id)

        case VulnCheck.scan(config, opts) do
          {:ok, report} ->
            %{
              workspace: report.workspace,
              findings: Enum.filter(report.findings, &MapSet.member?(ids, &1.advisory_id))
            }

          {:error, reason} ->
            %{error: reason}
        end

      {:error, _kind, _details} ->
        nil
    end
  end

  @doc "Human-readable explanation."
  @spec format(result()) :: String.t()
  def format(%{advisories: advisories} = result) do
    cards = Enum.map(advisories, &card/1)
    local = format_local(result.local, advisories)
    warnings = Enum.map(result.warnings, &("warning: " <> &1))

    (cards ++ [local] ++ [Enum.join(warnings, "\n")])
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join("\n\n")
    |> Kernel.<>("\n")
  end

  defp card(%Advisory{} = a) do
    title = Advisory.cve_id(a) || a.id
    summary = if a.summary == "", do: "", else: " — " <> a.summary

    severity =
      [
        a.severity |> Atom.to_string() |> String.upcase(),
        is_number(a.cvss_score) && "CVSS " <> Formatter.format_score(a.cvss_score),
        a.cvss_vector
      ]
      |> Enum.filter(&is_binary/1)
      |> Enum.join(" · ")

    rows = [
      {"Advisory", identifiers(a)},
      {"Package", a.package},
      {"Severity", severity},
      {"CWE", Enum.join(a.cwes, ", ")},
      {"Published", a.published_at},
      {"Modified", a.modified_at},
      {"Affected", affected(a)},
      {"Fixed", Enum.join(a.fixed_versions, ", ")},
      {"OTP", a.otp_constraints},
      {"Modules", Enum.join(a.affected_modules, ", ")},
      {"Routines", routines(a)},
      {"Context", context(a)}
    ]

    body =
      rows
      |> Enum.reject(fn {_label, value} -> value in [nil, ""] end)
      |> Enum.map(fn {label, value} -> String.pad_trailing(label <> ":", 11) <> value end)

    references =
      case a.references do
        [] -> []
        refs -> ["References:" | Enum.map(refs, &("  - " <> &1))]
      end

    details =
      case String.trim(a.details) do
        "" -> []
        text -> ["Details:" | text |> String.split("\n") |> Enum.map(&("  " <> &1))]
      end

    Enum.join([title <> summary | body ++ references ++ details], "\n")
  end

  defp identifiers(%Advisory{id: id, aliases: []}), do: id

  defp identifiers(%Advisory{id: id, aliases: aliases}),
    do: "#{id} (aliases: #{Enum.join(aliases, ", ")})"

  defp affected(%Advisory{version_ranges: [], affected_versions: versions}),
    do: Enum.join(versions, ", ")

  defp affected(%Advisory{version_ranges: ranges}), do: Enum.map_join(ranges, "; ", &range/1)

  defp range(%VersionRange{} = r) do
    lower = if r.introduced in [nil, "0"], do: nil, else: ">= #{r.introduced}"

    upper =
      cond do
        r.fixed -> "< #{r.fixed}"
        r.last_affected -> "<= #{r.last_affected}"
        true -> nil
      end

    limit = if r.limit, do: "< #{r.limit} (range limit)"

    case Enum.reject([lower, upper, limit], &is_nil/1) do
      [] -> "all versions"
      parts -> Enum.join(parts, ", ")
    end
  end

  defp routines(%Advisory{affected_routines: []}), do: nil

  defp routines(%Advisory{symbol_source: source} = advisory) do
    case RoutineScope.split(advisory, [advisory.package], %{}).routines do
      [] ->
        nil

      own ->
        list = Enum.map_join(own, ", ", &MFA.format/1)
        if source, do: "#{list} (source: #{source})", else: list
    end
  end

  defp context(%Advisory{} = advisory) do
    case RoutineScope.split(advisory, [advisory.package], %{}).context_routines do
      [] ->
        nil

      routines ->
        Enum.map_join(routines, ", ", &MFA.format/1) <> " (Erlang/OTP or Elixir; not a target)"
    end
  end

  defp format_local(nil, _advisories), do: "Local project: none found in the target directory"

  defp format_local(%{error: reason}, _advisories),
    do: "Local project: scan failed (#{VulnCheck.CLI.describe_error(reason)})"

  defp format_local(%{workspace: ws, findings: findings}, advisories) do
    header = "Local project: #{ws.project_name} (#{ws.project_type}, env: #{ws.env})"

    lines =
      advisories
      |> Enum.uniq_by(& &1.package)
      |> Enum.map(fn advisory ->
        case Map.get(ws.packages, advisory.package) do
          nil ->
            "  #{advisory.package}: not locked by this project"

          package ->
            case Enum.find(findings, &(&1.package == advisory.package)) do
              nil -> "  #{advisory.package} #{package.version}: installed version is not affected"
              finding -> finding_lines(finding)
            end
        end
      end)

    Enum.join([header | lines], "\n")
  end

  defp context_line([]), do: []

  defp context_line(routines),
    do: ["  Context:   #{Enum.map_join(routines, ", ", &Formatter.mfa/1)} (outside the package)"]

  defp finding_lines(%Finding{} = f) do
    verdict = f.verdict |> Atom.to_string() |> String.upcase() |> String.replace("_", " ")
    detail = if f.reason_detail in [nil, ""], do: "", else: " (#{f.reason_detail})"
    suppressed = if f.suppressed, do: ["    Suppressed: #{f.suppression_reason}"], else: []

    trace =
      case f.trace do
        [] ->
          []

        hops ->
          ["    Trace:"] ++
            (hops
             |> Formatter.numbered()
             |> Enum.map(fn {hop, i} ->
               location = Formatter.location(hop)

               "      #{i}. #{Formatter.hop(hop)}" <>
                 if(location, do: " (#{location})", else: "")
             end))
      end

    Enum.join(
      [
        "  Installed: #{f.package} #{f.installed_version}",
        "  Verdict:   #{verdict} — #{Formatter.reason_label(f.reason)}#{detail}"
      ] ++
        if(f.target_mfa, do: ["  Target:    #{Formatter.mfa(f.target_mfa)}"], else: []) ++
        context_line(f.context_routines) ++
        suppressed ++ trace,
      "\n"
    )
  end
end
