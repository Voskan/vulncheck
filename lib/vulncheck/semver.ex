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
      case range.introduced do
        nil -> true
        "0" -> true
        "*" -> true
        introduced -> compare(version, introduced) != :lt
      end

    upper_ok =
      cond do
        range.fixed not in [nil, "*"] -> compare(version, range.fixed) == :lt
        range.last_affected not in [nil, "*"] -> compare(version, range.last_affected) != :gt
        true -> true
      end

    lower_ok and upper_ok
  end

  @doc """
  Returns `true` when the installed version is affected by the advisory.

  An advisory with neither ranges nor explicit versions is considered to
  affect every version (fail-safe). Unparseable installed versions are also
  considered affected.
  """
  @spec affected?(String.t(), Advisory.t()) :: boolean()
  def affected?(version, %Advisory{version_ranges: [], affected_versions: []})
      when is_binary(version),
      do: true

  def affected?(version, %Advisory{} = advisory) do
    cond do
      not valid?(version) ->
        true

      Enum.any?(advisory.affected_versions, &(compare(&1, version) == :eq)) ->
        true

      true ->
        Enum.any?(advisory.version_ranges, &in_range?(version, &1))
    end
  end

  @doc """
  Converts an OSV `ranges` array (decoded JSON) into version ranges.

  Each range's `events` are processed in version order: an `introduced` event
  opens an interval that the next `fixed` or `last_affected` event closes.
  `GIT` ranges are ignored because they cannot be compared with package
  versions.
  """
  @spec from_osv_ranges([map()] | nil) :: [VersionRange.t()]
  def from_osv_ranges(ranges) when is_list(ranges) do
    Enum.flat_map(ranges, fn
      %{"type" => "GIT"} -> []
      %{"events" => events} when is_list(events) -> events_to_ranges(events)
      _ -> []
    end)
  end

  def from_osv_ranges(_), do: []

  @doc """
  Converts CVE 5.1 `versions` entries into version ranges. Only entries with
  `"status": "affected"` produce ranges.
  """
  @spec from_cve_versions([map()] | nil) :: [VersionRange.t()]
  def from_cve_versions(versions) when is_list(versions) do
    Enum.flat_map(versions, fn
      %{"status" => "affected"} = entry ->
        introduced = normalize_bound(entry["version"])

        cond do
          is_binary(entry["lessThan"]) ->
            [%VersionRange{introduced: introduced, fixed: normalize_bound(entry["lessThan"])}]

          is_binary(entry["lessThanOrEqual"]) ->
            [
              %VersionRange{
                introduced: introduced,
                last_affected: normalize_bound(entry["lessThanOrEqual"])
              }
            ]

          is_binary(introduced) and introduced != "0" ->
            [%VersionRange{introduced: introduced, last_affected: introduced}]

          true ->
            [%VersionRange{}]
        end

      _ ->
        []
    end)
  end

  def from_cve_versions(_), do: []

  @doc """
  Collects the `fixed` versions declared by a list of ranges.
  """
  @spec fixed_versions([VersionRange.t()]) :: [String.t()]
  def fixed_versions(ranges) do
    ranges
    |> Enum.map(& &1.fixed)
    |> Enum.reject(&(&1 in [nil, "*"]))
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
    branch_fix =
      advisory.version_ranges
      |> Enum.filter(&(in_range?(installed, &1) and &1.fixed not in [nil, "*"]))
      |> Enum.map(& &1.fixed)
      |> sort()
      |> List.first()

    branch_fix ||
      (advisory.fixed_versions ++ fixed_versions(advisory.version_ranges))
      |> Enum.filter(&(valid?(&1) and compare(&1, installed) == :gt))
      |> Enum.reject(&affected?(&1, advisory))
      |> sort()
      |> List.first()
  end

  @doc """
  Evaluates an OTP runtime constraint against an OTP release.

  Supported expressions: `"< 26"`, `"<= 25"`, `">= 24 and <= 25"`,
  `"24 || 25"`, `"== 25"`, `"25"`. Comparison happens at the precision of the
  constraint, so `"<= 25"` matches OTP `25.3.2`. A `nil` or unparseable
  constraint is treated as affecting every runtime (fail-safe).

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

  defp events_to_ranges(events) do
    sorted =
      events
      |> Enum.flat_map(fn event ->
        cond do
          is_binary(event["introduced"]) -> [{:introduced, event["introduced"]}]
          is_binary(event["fixed"]) -> [{:fixed, event["fixed"]}]
          is_binary(event["last_affected"]) -> [{:last_affected, event["last_affected"]}]
          true -> []
        end
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
    Enum.reverse(ranges)
  end

  defp event_compare("0", "0"), do: :eq
  defp event_compare("0", _), do: :lt
  defp event_compare(_, "0"), do: :gt
  defp event_compare(a, b), do: compare(a, b)

  defp parse_constraint(constraints) do
    disjuncts =
      constraints
      |> String.split(~r/\s*(\|\||\bor\b)\s*/i, trim: true)
      |> Enum.map(fn disjunct ->
        disjunct
        |> String.split(~r/\s*(&&|\band\b|,)\s*/i, trim: true)
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
    truncated = Enum.take(release ++ List.duplicate(0, length(segments)), length(segments))
    result = compare_numbers(truncated, segments)

    case op do
      :== -> result == :eq
      :!= -> result != :eq
      :< -> result == :lt
      :<= -> result != :gt
      :> -> result == :gt
      :>= -> result != :lt
      :~> -> result != :lt and hd(release) == hd(segments)
    end
  end
end
