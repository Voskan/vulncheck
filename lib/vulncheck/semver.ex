defmodule VulnCheck.Semver do
  @moduledoc """
  Version comparison and range matching for Hex, Erlang and OTP versions.

  `Version.parse/1` rejects many legitimate versions published by Erlang
  packages (`"2.8"`, `"1.0.2.1"`, `"25"`). This module accepts any number of
  numeric segments, compares them numerically (missing segments count as
  `0`), and follows SemVer 2.0 for pre-release identifiers
  (`1.19.0-rc.0 < 1.19.0-rc.1 < 1.19.0`) while ignoring `+build` metadata.

  It also evaluates OSV `ranges`/`versions`, CVE 5.1 `versions` and OTP
  runtime constraints such as `"<= 25"` or `">= 24 and <= 25"`.
  """

  alias VulnCheck.Types.{Advisory, VersionRange}

  @type parsed :: {[non_neg_integer()], [String.t() | non_neg_integer()]}

  @doc """
  Parses a version string into `{numeric_segments, pre_release_identifiers}`.

      iex> VulnCheck.Semver.parse("1.19.0-rc.1+build.5")
      {:ok, {[1, 19, 0], ["rc", 1]}}

      iex> VulnCheck.Semver.parse("2.8")
      {:ok, {[2, 8], []}}

      iex> VulnCheck.Semver.parse("not a version")
      :error
  """
  @spec parse(String.t()) :: {:ok, parsed()} | :error
  def parse(version) when is_binary(version) do
    version = version |> String.trim() |> String.trim_leading("v")
    [main | _build] = String.split(version, "+", parts: 2)

    {numbers, pre} =
      case String.split(main, "-", parts: 2) do
        [numbers, pre] -> {numbers, pre}
        [numbers] -> {numbers, nil}
      end

    with {:ok, segments} <- parse_segments(numbers),
         {:ok, pre_ids} <- parse_pre(pre) do
      {:ok, {segments, pre_ids}}
    end
  end

  def parse(_), do: :error

  @doc """
  Returns `true` when the string is a version this module understands.
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(version), do: match?({:ok, _}, parse(version))

  @doc """
  Compares two versions.

      iex> VulnCheck.Semver.compare("2.8", "2.8.0")
      :eq
      iex> VulnCheck.Semver.compare("27.2", "25.3.2.12")
      :gt
      iex> VulnCheck.Semver.compare("1.19.0-rc.1", "1.19.0")
      :lt

  Unparseable versions are compared as plain strings.
  """
  @spec compare(String.t(), String.t()) :: :lt | :eq | :gt
  def compare(a, b) do
    case {parse(a), parse(b)} do
      {{:ok, pa}, {:ok, pb}} -> compare_parsed(pa, pb)
      _ -> compare_terms(a, b)
    end
  end

  @doc "Sorts versions in ascending order."
  @spec sort([String.t()]) :: [String.t()]
  def sort(versions), do: Enum.sort(versions, &(compare(&1, &2) != :gt))

  @doc """
  Returns `true` when `version` lies inside the range.
  """
  @spec in_range?(String.t(), VersionRange.t()) :: boolean()
  def in_range?(version, %VersionRange{} = range) do
    lower_ok =
      range.introduced == "0" or not valid?(range.introduced) or
        compare(version, range.introduced) != :lt

    upper_ok =
      cond do
        valid?(range.fixed) -> compare(version, range.fixed) == :lt
        valid?(range.last_affected) -> compare(version, range.last_affected) != :gt
        true -> true
      end

    lower_ok and upper_ok and (not valid?(range.limit) or compare(version, range.limit) == :lt)
  end

  @doc """
  Returns `true` when the installed version is affected by the advisory.

  An advisory with neither ranges nor explicit versions is considered to
  affect every version (fail-safe). Unparseable installed versions are also
  considered affected.
  """
  @spec affected?(String.t(), Advisory.t()) :: boolean()
  def affected?(version, %Advisory{} = advisory),
    do: affected?(version, advisory.version_ranges, advisory.affected_versions)

  @doc "Checks a single source's numbered intervals and explicit versions."
  @spec affected?(String.t(), [VersionRange.t()], [String.t()]) :: boolean()
  def affected?(_version, [], []), do: true

  def affected?(version, ranges, versions) do
    cond do
      not valid?(version) ->
        true

      Enum.any?(versions, &(not valid?(&1) or compare(&1, version) == :eq)) ->
        true

      true ->
        Enum.any?(ranges, &in_range?(version, &1))
    end
  end

  @doc """
  Converts an OSV `ranges` array (decoded JSON) into version ranges.

  Each range's `events` are processed in version order: an `introduced` event
  opens an interval that the next `fixed` or `last_affected` event closes.
  A `limit` restricts the range without declaring a fixed release.
  `GIT` ranges are ignored because they cannot be compared with package
  versions.
  """
  @spec from_osv_ranges([map()] | nil) :: [VersionRange.t()]
  def from_osv_ranges(ranges) when is_list(ranges) do
    Enum.flat_map(ranges, fn
      %{"events" => events} = range when is_list(events) ->
        if Map.get(range, "type", "SEMVER") in ["SEMVER", "ECOSYSTEM"],
          do: events_to_ranges(events),
          else: []

      _ ->
        []
    end)
  end

  def from_osv_ranges(_), do: []

  @doc """
  Converts numbered CVE 5.1 `versions` entries into ranges. Affected and
  unknown segments are retained. Commit ranges require a different matcher.
  """
  @spec from_cve_versions([map()] | nil) :: [VersionRange.t()]
  def from_cve_versions(versions) when is_list(versions) do
    Enum.flat_map(versions, &cve_entry_ranges/1)
  end

  def from_cve_versions(_), do: []

  @doc "Numbered range hints for a CVE affected product. An affected or unknown default keeps the set open."
  @spec from_cve_affected(map()) :: [VersionRange.t()]
  def from_cve_affected(%{"defaultStatus" => "unaffected"} = entry),
    do: from_cve_versions(entry["versions"])

  def from_cve_affected(_entry), do: [%VersionRange{}]

  @doc """
  Collects the `fixed` versions declared by a list of ranges.
  """
  @spec fixed_versions([VersionRange.t()]) :: [String.t()]
  def fixed_versions(ranges) do
    ranges
    |> Enum.filter(fn range ->
      valid?(range.fixed) and (not valid?(range.limit) or compare(range.fixed, range.limit) != :gt)
    end)
    |> Enum.map(& &1.fixed)
    |> Enum.uniq()
    |> sort()
  end

  @doc """
  Returns the closest upgrade that fixes the advisory for the installed
  version, preferring the fix of the release branch the version belongs to.

  For `plug 1.16.2` affected by `1.16.0..<1.16.4` and `1.19.0..<1.19.3` this
  returns `"1.16.4"`, not `"1.19.3"`.
  """
  @spec recommended_fix(String.t(), Advisory.t()) :: String.t() | nil
  def recommended_fix(installed, %Advisory{} = advisory) do
    if valid?(installed) and affected?(installed, advisory) do
      branch = advisory.version_ranges |> Enum.filter(&in_range?(installed, &1)) |> fixed_versions()
      other = sort(advisory.fixed_versions ++ fixed_versions(advisory.version_ranges))

      Enum.find(branch ++ other, fn fix ->
        valid?(fix) and compare(fix, installed) == :gt and not affected?(fix, advisory)
      end)
    end
  end

  @doc """
  Evaluates an OTP runtime constraint against an OTP release.

  Supported expressions: `"< 26"`, `"<= 25"`, `">= 24 and <= 25"`,
  `"24 || 25"`, `"== 25"`, `"25"`. Comparison happens at the precision of the
  constraint, so `"<= 25"` matches OTP `25.3.2`. When the known release
  prefix matches a more precise boundary, the comparison remains open.
  A `nil` or unparseable constraint is treated as affecting every runtime.

      iex> VulnCheck.Semver.otp_affected?("27", "<= 25")
      false
      iex> VulnCheck.Semver.otp_affected?("25.3", "<= 25")
      true
  """
  @spec otp_affected?(String.t(), String.t() | nil) :: boolean()
  def otp_affected?(_otp_release, nil), do: true

  def otp_affected?(otp_release, constraints) when is_binary(constraints) do
    with {:ok, {release, _}} <- parse(otp_release),
         {:ok, disjuncts} <- parse_constraint(constraints) do
      Enum.any?(disjuncts, fn conjuncts ->
        Enum.all?(conjuncts, fn {op, segments} -> check(op, release, segments) end)
      end)
    else
      _ -> true
    end
  end

  # -- internals ---------------------------------------------------------------

  defp parse_segments(numbers) do
    parts = String.split(numbers, ".")

    if parts != [] and Enum.all?(parts, &Regex.match?(~r/\A\d+\z/, &1)) do
      {:ok, Enum.map(parts, &String.to_integer/1)}
    else
      :error
    end
  end

  defp parse_pre(nil), do: {:ok, []}
  defp parse_pre(""), do: :error

  defp parse_pre(pre) do
    ids = String.split(pre, ".")

    if Enum.all?(ids, &Regex.match?(~r/\A[0-9A-Za-z-]+\z/, &1)) do
      {:ok,
       Enum.map(ids, fn id ->
         if Regex.match?(~r/\A\d+\z/, id), do: String.to_integer(id), else: id
       end)}
    else
      :error
    end
  end

  defp compare_parsed({a_nums, a_pre}, {b_nums, b_pre}) do
    case compare_numbers(a_nums, b_nums) do
      :eq -> compare_pre(a_pre, b_pre)
      other -> other
    end
  end

  defp compare_numbers(a, b) do
    len = max(length(a), length(b))
    pad = fn list -> list ++ List.duplicate(0, len - length(list)) end
    compare_terms(pad.(a), pad.(b))
  end

  defp compare_pre([], []), do: :eq
  defp compare_pre([], _), do: :gt
  defp compare_pre(_, []), do: :lt

  defp compare_pre(a, b) do
    a
    |> Enum.zip(b)
    |> Enum.find_value(fn {x, y} ->
      case compare_identifier(x, y) do
        :eq -> nil
        other -> other
      end
    end)
    |> case do
      nil -> compare_terms(length(a), length(b))
      other -> other
    end
  end

  defp compare_identifier(x, y) when is_integer(x) and is_integer(y), do: compare_terms(x, y)
  defp compare_identifier(x, _y) when is_integer(x), do: :lt
  defp compare_identifier(_x, y) when is_integer(y), do: :gt
  defp compare_identifier(x, y), do: compare_terms(x, y)

  defp compare_terms(a, b) do
    cond do
      a < b -> :lt
      a > b -> :gt
      true -> :eq
    end
  end

  defp normalize_bound(nil), do: nil
  defp normalize_bound(value) when is_binary(value), do: String.trim(value)
  defp normalize_bound(_), do: nil

  defp cve_entry_ranges(%{"versionType" => "git"}), do: []

  defp cve_entry_ranges(%{"status" => status} = entry)
       when status in ["affected", "unaffected", "unknown"] do
    range = cve_interval(entry)

    changes =
      for %{"at" => at, "status" => next} <- List.wrap(entry["changes"]),
          next in ["affected", "unaffected", "unknown"],
          valid?(at) and in_range?(at, range),
          do: {at, next}

    {segments, current, start} =
      changes
      |> Enum.sort(fn {a, _}, {b, _} -> compare(a, b) != :gt end)
      |> Enum.reduce({[], status, range.introduced}, fn {at, next}, {segments, current, start} ->
        closed = %VersionRange{introduced: start, limit: at}
        {cve_segment(segments, current, closed), next, at}
      end)

    Enum.reverse(cve_segment(segments, current, %{range | introduced: start}))
  end

  defp cve_entry_ranges(_), do: []

  defp cve_segment(segments, "unaffected", _range), do: segments
  defp cve_segment(segments, _status, range), do: [range | segments]

  defp cve_interval(entry) do
    first = normalize_bound(entry["version"])
    upper = normalize_bound(entry["lessThan"] || entry["lessThanOrEqual"])
    wildcard_limit = cve_wildcard_limit(upper)

    cond do
      wildcard_limit -> %VersionRange{introduced: first, limit: wildcard_limit}
      is_binary(entry["lessThan"]) -> %VersionRange{introduced: first, fixed: upper}
      is_binary(entry["lessThanOrEqual"]) -> %VersionRange{introduced: first, last_affected: upper}
      is_binary(first) and first != "0" -> %VersionRange{introduced: first, last_affected: first}
      true -> %VersionRange{}
    end
  end

  defp cve_wildcard_limit(nil), do: nil

  defp cve_wildcard_limit(upper) do
    with true <- String.ends_with?(upper, ".*"),
         {:ok, segments} <- upper |> String.trim_trailing(".*") |> parse_segments() do
      {last, prefix} = List.pop_at(segments, -1)
      Enum.join(prefix ++ [last + 1], ".") <> "-0"
    else
      _ -> nil
    end
  end

  defp events_to_ranges(events) do
    limits = for %{"limit" => limit} <- events, is_binary(limit), do: limit
    limit = if Enum.all?(limits, &valid?/1), do: limits |> sort() |> List.last()

    sorted =
      events
      |> Enum.flat_map(fn
        %{"introduced" => version} when is_binary(version) -> [{:introduced, version}]
        %{"fixed" => version} when is_binary(version) -> [{:fixed, version}]
        %{"last_affected" => version} when is_binary(version) -> [{:last_affected, version}]
        _ -> []
      end)
      |> Enum.with_index()
      |> Enum.sort(fn {{_, a}, ia}, {{_, b}, ib} ->
        case event_compare(a, b) do
          :lt -> true
          :gt -> false
          :eq -> ia <= ib
        end
      end)
      |> Enum.map(&elem(&1, 0))

    {ranges, open} =
      Enum.reduce(sorted, {[], nil}, fn
        {:introduced, version}, {acc, nil} ->
          {acc, version}

        {:introduced, _version}, {acc, open} ->
          {acc, open}

        {:fixed, version}, {acc, open} when open != nil ->
          {[%VersionRange{introduced: open, fixed: version} | acc], nil}

        {:last_affected, version}, {acc, open} when open != nil ->
          {[%VersionRange{introduced: open, last_affected: version} | acc], nil}

        {_kind, _version}, {acc, nil} ->
          {acc, nil}
      end)

    ranges = if open, do: [%VersionRange{introduced: open} | ranges], else: ranges
    ranges |> Enum.map(&%{&1 | limit: limit}) |> Enum.reverse()
  end

  defp event_compare("0", "0"), do: :eq
  defp event_compare("0", _), do: :lt
  defp event_compare(_, "0"), do: :gt
  defp event_compare(a, b), do: compare(a, b)

  defp parse_constraint(constraints) do
    disjuncts =
      constraints
      |> String.split(~r/\s*(\|\||\bor\b)\s*/i)
      |> Enum.map(fn disjunct ->
        disjunct
        |> String.split(~r/\s*(&&|\band\b|,)\s*/i)
        |> Enum.map(&parse_comparison/1)
      end)

    if disjuncts != [] and
         Enum.all?(disjuncts, &(&1 != [] and Enum.all?(&1, fn c -> c != :error end))) do
      {:ok, disjuncts}
    else
      :error
    end
  end

  defp parse_comparison(text) do
    text = text |> String.trim() |> String.replace(~r/\A(otp|erlang\/otp)\s*/i, "")

    case Regex.run(~r/\A(<=|>=|==|!=|<|>|=|~>)?\s*v?(\d+(?:\.\d+)*)\z/, text) do
      [_, op, version] ->
        {:ok, {segments, []}} = parse(version)
        {normalize_op(op), segments}

      [_, version] ->
        {:ok, {segments, []}} = parse(version)
        {:==, segments}

      _ ->
        :error
    end
  end

  defp normalize_op(""), do: :==
  defp normalize_op("="), do: :==
  defp normalize_op("=="), do: :==
  defp normalize_op("!="), do: :!=
  defp normalize_op("<"), do: :<
  defp normalize_op("<="), do: :<=
  defp normalize_op(">"), do: :>
  defp normalize_op(">="), do: :>=
  defp normalize_op("~>"), do: :~>

  defp check(op, release, segments) do
    precision = min(length(release), length(segments))
    result = compare_numbers(Enum.take(release, precision), Enum.take(segments, precision))

    if result == :eq and precision < length(segments),
      do: true,
      else: compare_otp(op, result, hd(release) == hd(segments))
  end

  defp compare_otp(op, result, same_major) do
    case op do
      :== -> result == :eq
      :!= -> result != :eq
      :< -> result == :lt
      :<= -> result != :gt
      :> -> result == :gt
      :>= -> result != :lt
      :~> -> result != :lt and same_major
    end
  end
end
