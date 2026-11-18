defmodule VulnCheck.Feeds.Merge do
  @moduledoc """
  Folds advisories that describe the same vulnerability of the same package
  into one advisory.

  The OSV Hex feed carries both the Erlang Ecosystem Foundation record
  (`EEF-CVE-…`) and the GitHub record (`GHSA-…`) of most vulnerabilities, each
  listing the CVE identifier as an alias. Advisories of one package whose
  identifier sets (id, aliases and the CVE derived from them) overlap are
  merged transitively:

    * the canonical id is the first of `EEF-CVE-*`, `CVE-*`, `GHSA-*`, then
      any other id (ties broken alphabetically); every other identifier
      becomes an alias;
    * a version is affected when any merged record says so: ranges and
      explicit versions are united, and a record affecting every version
      contributes an open range;
    * routines, modules, CWEs and references are united; the highest CVSS
      score and severity win;
    * summary, details and OTP constraints come from the canonical record,
      falling back to the others when it has none.

  The result is deterministic for any input order.
  """

  alias VulnCheck.Semver
  alias VulnCheck.Types.{Advisory, VersionRange}

  @doc """
  Merges overlapping advisories. Advisories without overlap are returned
  unchanged; the output is sorted by package and canonical id.
  """
  @spec merge([Advisory.t()]) :: [Advisory.t()]
  def merge(advisories) when is_list(advisories) do
    advisories
    |> Enum.group_by(& &1.package)
    |> Enum.sort_by(fn {package, _} -> package end)
    |> Enum.flat_map(fn {_package, group} ->
      group
      |> components()
      |> Enum.map(&fold/1)
      |> Enum.sort_by(& &1.id)
    end)
  end

  # Connected components of advisories sharing at least one identifier.
  defp components(group) do
    indexed = Enum.with_index(group)

    owners =
      Enum.reduce(indexed, %{}, fn {advisory, index}, acc ->
        Enum.reduce(keys(advisory), acc, fn key, acc ->
          Map.update(acc, key, [index], &[index | &1])
        end)
      end)

    parents =
      owners
      |> Map.values()
      |> Enum.reduce(Map.new(indexed, fn {_, index} -> {index, index} end), fn
        [first | rest], parents -> Enum.reduce(rest, parents, &union(&2, first, &1))
      end)

    indexed
    |> Enum.group_by(fn {_advisory, index} -> root(parents, index) end, &elem(&1, 0))
    |> Map.values()
  end

  defp keys(%Advisory{} = advisory) do
    advisory |> Advisory.identifiers() |> Enum.map(&String.upcase/1)
  end

  defp root(parents, index) do
    case Map.fetch!(parents, index) do
      ^index -> index
      parent -> root(parents, parent)
    end
  end

  defp union(parents, a, b) do
    {ra, rb} = {root(parents, a), root(parents, b)}
    if ra == rb, do: parents, else: Map.put(parents, max(ra, rb), min(ra, rb))
  end

  defp fold([single]), do: single

  defp fold(members) do
    [%Advisory{} = canonical | _] = ordered = Enum.sort_by(members, &{rank(&1.id), &1.id})
    ids = ordered |> Enum.flat_map(&[&1.id | &1.aliases]) |> Enum.uniq()
    ranges = ranges(ordered)
    {score, vector} = cvss(ordered)

    %Advisory{
      canonical
      | aliases: ids |> List.delete(canonical.id) |> Enum.sort(),
        summary: first_present(ordered, & &1.summary) || "",
        details: first_present(ordered, & &1.details) || "",
        severity: severity(ordered),
        cvss_score: score,
        cvss_vector: vector,
        cwes: union_of(ordered, & &1.cwes) |> Enum.sort(),
        references: union_of(ordered, & &1.references),
        published_at:
          ordered |> Enum.map(& &1.published_at) |> Enum.reject(&is_nil/1) |> min_or_nil(),
        modified_at:
          ordered |> Enum.map(& &1.modified_at) |> Enum.reject(&is_nil/1) |> max_or_nil(),
        version_ranges: ranges,
        affected_versions: union_of(ordered, & &1.affected_versions) |> Semver.sort(),
        fixed_versions: Semver.fixed_versions(ranges),
        affected_modules: union_of(ordered, & &1.affected_modules),
        affected_routines: union_of(ordered, & &1.affected_routines),
        symbol_source: Enum.find_value(ordered, &(&1.affected_routines != [] && &1.symbol_source)),
        otp_constraints: first_present(ordered, & &1.otp_constraints),
        enriched: Enum.any?(ordered, & &1.enriched)
    }
  end

  defp rank("EEF-CVE-" <> _), do: 0
  defp rank("CVE-" <> _), do: 1
  defp rank("GHSA-" <> _), do: 2
  defp rank(_id), do: 3

  # A record without ranges or explicit versions affects every version.
  defp ranges(members) do
    members
    |> Enum.flat_map(fn
      %Advisory{version_ranges: [], affected_versions: []} -> [%VersionRange{}]
      %Advisory{version_ranges: ranges} -> ranges
    end)
    |> Enum.uniq()
  end

  defp cvss(members) do
    case members |> Enum.filter(& &1.cvss_score) |> Enum.max_by(& &1.cvss_score, fn -> nil end) do
      nil -> {nil, Enum.find_value(members, & &1.cvss_vector)}
      best -> {best.cvss_score, best.cvss_vector || Enum.find_value(members, & &1.cvss_vector)}
    end
  end

  defp severity(members) do
    members |> Enum.map(& &1.severity) |> Enum.reduce(&Advisory.max_severity/2)
  end

  defp first_present(members, fun) do
    Enum.find_value(members, fn member ->
      case fun.(member) do
        value when value in [nil, ""] -> nil
        value -> value
      end
    end)
  end

  defp union_of(members, fun), do: members |> Enum.flat_map(fun) |> Enum.uniq()

  defp min_or_nil([]), do: nil
  defp min_or_nil(list), do: Enum.min(list)

  defp max_or_nil([]), do: nil
  defp max_or_nil(list), do: Enum.max(list)
end
