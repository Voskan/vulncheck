defmodule VulnCheck.Cache.Snapshot do
  @moduledoc false
  # Chooses the feed snapshot an offline run reads and explains the choice.
  #
  # An offline run without `--bundle` reads the most recent valid snapshot:
  # the live cache refreshed by online runs and `feeds sync`, or the snapshot
  # selected by `feeds import`. A `--bundle` run reads that bundle and is
  # compared with the live cache so that an outdated bundle is reported.

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Cache.Bundle
  alias VulnCheck.Feeds.OSV

  @type kind :: :live | :imported | :bundle
  @type info :: %{
          kind: kind(),
          dir: String.t(),
          status: :ok | {:error, term()},
          fetched_at_unix: integer() | nil,
          records: non_neg_integer() | nil
        }
  @type selection :: %{
          snapshot: kind(),
          dir: String.t(),
          reason: String.t(),
          warnings: [String.t()]
        }

  # A snapshot with fewer than this share of the other snapshot's records is
  # reported as incomplete.
  @min_record_share 0.9

  @doc "Selects the snapshot read by an offline run without `--bundle`."
  @spec select(Config.t()) :: selection()
  def select(%Config{} = config) do
    live = inspect_dir(config, :live, Cache.live_feeds_dir(config))

    case imported_dir(config) do
      :none ->
        selection(live, nil, "live cache; no snapshot was imported")

      {:error, reason} ->
        selection(live, nil, "live cache; the imported snapshot is unusable (#{reason})")

      {:ok, dir} ->
        choose(live, inspect_dir(config, :imported, dir))
    end
  end

  @doc "Describes the snapshot of a `--bundle` run, compared with the live cache."
  @spec for_bundle(Config.t(), Path.t(), Path.t()) :: selection()
  def for_bundle(%Config{} = config, dir, bundle_path) do
    bundle = inspect_dir(config, :bundle, dir)
    live = inspect_dir(config, :live, Cache.live_feeds_dir(config))
    selection(bundle, live, "--bundle #{Path.basename(bundle_path)}")
  end

  @doc "The snapshot selected by `feeds import`, if any."
  @spec imported_dir(Config.t()) :: {:ok, String.t()} | :none | {:error, String.t()}
  def imported_dir(%Config{} = config) do
    case Cache.read_limited(Bundle.pointer(config), 96) do
      {:ok, name} ->
        dir = Path.join(Bundle.root(config), name)

        cond do
          not Bundle.snapshot_name?(name) -> {:error, "invalid pointer"}
          not File.dir?(dir) -> {:error, "#{name} is missing"}
          true -> {:ok, dir}
        end

      {:error, :enoent} ->
        :none

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  @doc "Reads the OSV archive of a snapshot directory."
  @spec inspect_dir(Config.t(), kind(), String.t()) :: info()
  def inspect_dir(%Config{} = config, kind, dir) do
    scoped = %{config | feed_snapshot: dir}

    with {:ok, zip, meta} <- Cache.read_feed_entry(scoped, OSV.cache_file()),
         {:ok, records} <- OSV.record_count(zip) do
      %{
        kind: kind,
        dir: dir,
        status: :ok,
        fetched_at_unix: fetched_at(meta),
        records: records
      }
    else
      {:error, reason} ->
        %{kind: kind, dir: dir, status: {:error, reason}, fetched_at_unix: nil, records: nil}
    end
  end

  @doc "Human-readable name of a snapshot kind."
  @spec label(kind()) :: String.t()
  def label(:live), do: "live cache"
  def label(:imported), do: "imported snapshot"
  def label(:bundle), do: "--bundle snapshot"

  defp choose(%{status: :ok} = live, %{status: :ok} = imported) do
    if newer?(imported, live),
      do: selection(imported, live, "imported snapshot; it is newer than the live cache"),
      else:
        selection(live, imported, "live cache; it is at least as recent as the imported snapshot")
  end

  defp choose(%{status: :ok} = live, %{status: {:error, reason}}),
    do: selection(live, nil, "live cache; the imported snapshot is invalid (#{inspect(reason)})")

  defp choose(%{status: {:error, _}} = live, %{status: :ok} = imported) do
    reason =
      case live.status do
        {:error, :enoent} -> "imported snapshot; the live cache is empty"
        {:error, other} -> "imported snapshot; the live cache is invalid (#{inspect(other)})"
      end

    selection(imported, nil, reason)
  end

  defp choose(live, _imported), do: selection(live, nil, "live cache; no valid snapshot exists")

  defp selection(chosen, other, reason) do
    %{snapshot: chosen.kind, dir: chosen.dir, reason: reason, warnings: warnings(chosen, other)}
  end

  defp warnings(%{status: :ok} = chosen, %{status: :ok} = other) do
    older =
      if newer?(other, chosen),
        do: [
          "the #{label(chosen.kind)} (fetched #{age(chosen)}) is older than the " <>
            "#{label(other.kind)} (fetched #{age(other)})"
        ],
        else: []

    fewer =
      if chosen.records < other.records * @min_record_share,
        do: [
          "the #{label(chosen.kind)} has #{chosen.records} OSV records; " <>
            "the #{label(other.kind)} has #{other.records}"
        ],
        else: []

    older ++ fewer
  end

  defp warnings(_chosen, _other), do: []

  defp newer?(left, right), do: (left.fetched_at_unix || -1) > (right.fetched_at_unix || -1)

  defp fetched_at(%{"fetched_at_unix" => at}) when is_integer(at), do: at
  defp fetched_at(_meta), do: nil

  @doc "Relative age of a fetch time, such as `3 h ago`."
  @spec age(info() | integer() | nil) :: String.t()
  def age(%{fetched_at_unix: at}), do: age(at)

  def age(at) when is_integer(at) do
    seconds = max(System.os_time(:second) - at, 0)

    cond do
      seconds < 120 -> "#{seconds} s ago"
      seconds < 7200 -> "#{div(seconds, 60)} min ago"
      seconds < 172_800 -> "#{div(seconds, 3600)} h ago"
      true -> "#{div(seconds, 86_400)} days ago"
    end
  end

  def age(_at), do: "at an unknown time"
end
