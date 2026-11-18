defmodule VulnCheck.Cache.Bundle do
  @moduledoc false

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Feeds.{Archive, EefCna, HexRetired, OSV}

  @bundle_manifest "manifest.json"

  def root(config), do: Path.join(Cache.dir(config), "feed-bundles")
  def pointer(config), do: Path.join(Cache.dir(config), "feeds-offline.current")

  @max_bundle_bytes 100 * 1024 * 1024
  @max_tar_bytes 256 * 1024 * 1024
  @max_bundle_entries 25_000

  @doc """
  Exports a verified snapshot of the cached feeds as a compressed tar archive.
  The manifest records file digests and the age of the source entries.
  """
  @spec export_bundle(Config.t(), Path.t()) :: {:ok, map()} | {:error, term()}
  def export_bundle(%Config{} = config, out_path) do
    config = Cache.pin_feeds(config)

    with {:ok, entries} <- export_entries(config),
         {_, zip, _} <- List.keyfind(entries, OSV.cache_file(), 0) || {:error, :empty_cache},
         {:ok, advisories} <- OSV.parse_archive(zip),
         :ok <- validate_json_resources(entries) do
      manifest = %{
        "format" => "vulncheck-feeds-bundle",
        "format_version" => 2,
        "created_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
        "tool_version" => VulnCheck.version(),
        "advisory_count" => advisories |> MapSet.new(& &1.id) |> MapSet.size(),
        "files" =>
          Enum.map(entries, fn {rel, data, meta} ->
            %{
              "path" => rel,
              "sha256" => meta["sha256"],
              "size" => byte_size(data),
              "fetched_at_unix" => meta["fetched_at_unix"]
            }
          end)
      }

      tar_entries = [
        {@bundle_manifest, JSON.encode!(manifest)}
        | Enum.map(entries, fn {rel, data, _} -> {rel, data} end)
      ]

      write_bundle(out_path, tar_entries, manifest)
    end
  end

  defp export_entries(config) do
    names = Enum.filter(Cache.list_feed_files(config), &resource_name?/1)

    if length(names) >= @max_bundle_entries do
      {:error, {:archive_too_large, :entries}}
    else
      names
      |> Enum.reduce_while({[], @max_tar_bytes - @max_bundle_entries * 1_024}, fn name,
                                                                                  {entries, left} ->
        case Cache.read_feed_entry(config, name) do
          {:ok, data, meta} when byte_size(data) <= left ->
            {:cont, {[{name, data, meta} | entries], left - byte_size(data)}}

          {:ok, _data, _meta} ->
            {:halt, {:error, {:archive_too_large, :uncompressed}}}

          {:error, reason} ->
            {:halt, {:error, {:cached_feed, name, reason}}}
        end
      end)
      |> case do
        {:error, _} = error -> error
        {entries, _left} -> {:ok, Enum.reverse(entries)}
      end
    end
  end

  defp write_bundle(out_path, entries, manifest) do
    out_path = Path.expand(out_path)
    tmp = "#{out_path}.tmp.#{System.unique_integer([:positive])}.#{:os.getpid()}"
    contents = Enum.map(entries, fn {name, data} -> {String.to_charlist(name), data} end)

    with :ok <- File.mkdir_p(Path.dirname(out_path)),
         :ok <- :erl_tar.create(String.to_charlist(tmp), contents, [:compressed]),
         {:ok, %{size: size}} when size <= @max_bundle_bytes <- File.stat(tmp),
         :ok <- File.rename(tmp, out_path) do
      {:ok, manifest}
    else
      error ->
        File.rm(tmp)

        reason =
          case error do
            {:error, reason} -> reason
            _ -> {:archive_too_large, :compressed}
          end

        {:error, {:bundle_write_failed, reason}}
    end
  end

  @doc """
  Validates and atomically selects a bundle as the offline feed snapshot.
  Online scans continue to use their separate live cache.
  """
  @spec import_bundle(Path.t(), Config.t()) :: {:ok, map()} | {:error, term()}
  def import_bundle(bundle_path, %Config{} = config) do
    with {:ok, manifest, _config} <- import_bundle_snapshot(bundle_path, config),
         do: {:ok, manifest}
  end

  @doc false
  def import_bundle_snapshot(bundle_path, %Config{} = config) do
    path = Path.expand(bundle_path, Config.project_root(config))

    with {:ok, archive} <- read_bundle(path),
         {:ok, table} <- tar_table(archive),
         :ok <- validate_entries(table),
         {:ok, files} <- tar_extract(archive),
         {:ok, manifest} <- read_manifest(files),
         {:ok, entries} <- verify_manifest(manifest, files),
         :ok <- validate_bundle_osv(entries),
         :ok <- validate_json_resources(entries),
         {:ok, root} <- publish_bundle(config, entries) do
      {:ok, manifest, %{config | feed_snapshot: root, offline: true}}
    end
  end

  defp read_bundle(path) do
    with {:ok, compressed} <- Cache.read_limited(path, @max_bundle_bytes),
         {:ok, archive} <- Archive.inflate(compressed, 31, @max_tar_bytes) do
      {:ok, archive}
    else
      {:error, reason} -> {:error, {:invalid_bundle, reason}}
    end
  end

  defp tar_table(archive) do
    case :erl_tar.table({:binary, archive}, [:verbose]) do
      {:ok, table} -> {:ok, table}
      {:error, reason} -> {:error, {:invalid_bundle, reason}}
    end
  end

  defp validate_entries(table) when length(table) <= @max_bundle_entries do
    max = Cache.max_feed_bytes()

    Enum.reduce_while(table, MapSet.new(), fn {raw, type, size, _, _, _, _}, seen ->
      name = List.to_string(raw)

      cond do
        type != :regular ->
          {:halt, {:error, {:unsafe_bundle_entry, name, type}}}

        not Cache.safe_name?(name) ->
          {:halt, {:error, {:unsafe_bundle_entry, name, :path}}}

        size < 0 or size > max ->
          {:halt, {:error, {:invalid_bundle, {:entry_size, name}}}}

        MapSet.member?(seen, name) ->
          {:halt, {:error, {:invalid_bundle, {:duplicate_file, name}}}}

        true ->
          {:cont, MapSet.put(seen, name)}
      end
    end)
    |> case do
      %MapSet{} -> :ok
      error -> error
    end
  rescue
    ArgumentError -> {:error, {:invalid_bundle, :filename_encoding}}
  end

  defp validate_entries(_table), do: {:error, {:invalid_bundle, {:archive_too_large, :entries}}}

  defp tar_extract(archive) do
    case :erl_tar.extract({:binary, archive}, [:memory]) do
      {:ok, files} -> {:ok, Map.new(files, fn {name, data} -> {List.to_string(name), data} end)}
      {:error, reason} -> {:error, {:invalid_bundle, reason}}
    end
  end

  defp read_manifest(files) do
    with data when is_binary(data) <- Map.get(files, @bundle_manifest),
         {:ok,
          %{
            "format" => "vulncheck-feeds-bundle",
            "format_version" => version,
            "files" => listed,
            "created_at" => created
          } = manifest}
         when version in [1, 2] and is_list(listed) and is_binary(created) <- JSON.decode(data),
         {:ok, _time, _offset} <- DateTime.from_iso8601(created) do
      {:ok, manifest}
    else
      _ -> {:error, {:invalid_bundle, :missing_manifest}}
    end
  end

  defp verify_manifest(manifest, files) do
    with {:ok, expected} <- manifest_entries(manifest["files"]),
         actual = Map.delete(files, @bundle_manifest),
         :ok <- same_names(expected, actual),
         :ok <- verify_checksums(expected, actual),
         true <- Map.has_key?(actual, OSV.cache_file()) do
      bundle_entries(manifest["format_version"], expected, actual)
    else
      false -> {:error, {:invalid_bundle, :missing_osv_archive}}
      error -> error
    end
  end

  defp manifest_entries(entries) when length(entries) < @max_bundle_entries do
    Enum.reduce_while(entries, {:ok, %{}}, fn
      %{"path" => name, "sha256" => sha, "size" => size} = entry, {:ok, expected}
      when is_binary(name) and is_binary(sha) and is_integer(size) and size >= 0 ->
        if Cache.safe_name?(name) and name != @bundle_manifest and not Map.has_key?(expected, name) do
          {:cont, {:ok, Map.put(expected, name, entry)}}
        else
          {:halt, {:error, {:invalid_bundle, {:invalid_manifest_path, name}}}}
        end

      _, _ ->
        {:halt, {:error, {:invalid_bundle, :invalid_manifest_entry}}}
    end)
  end

  defp manifest_entries(_entries), do: {:error, {:invalid_bundle, {:archive_too_large, :entries}}}

  defp same_names(expected, files) do
    expected = MapSet.new(Map.keys(expected))
    present = MapSet.new(Map.keys(files))

    cond do
      extra = first_difference(present, expected) ->
        {:error, {:invalid_bundle, {:unlisted_file, extra}}}

      missing = first_difference(expected, present) ->
        {:error, {:invalid_bundle, {:missing_file, missing}}}

      true ->
        :ok
    end
  end

  defp first_difference(left, right),
    do: left |> MapSet.difference(right) |> Enum.min(fn -> nil end)

  defp verify_checksums(expected, actual) do
    actual
    |> Enum.sort()
    |> Enum.reduce_while(:ok, fn {name, data}, :ok ->
      entry = Map.fetch!(expected, name)

      cond do
        entry["sha256"] != Cache.sha256(data) ->
          {:halt, {:error, {:invalid_bundle, {:checksum_mismatch, name}}}}

        entry["size"] != byte_size(data) ->
          {:halt, {:error, {:invalid_bundle, {:size_mismatch, name}}}}

        true ->
          {:cont, :ok}
      end
    end)
  end

  defp bundle_entries(version, expected, actual) do
    actual
    |> Enum.sort()
    |> Enum.reduce_while({:ok, []}, fn {name, data}, {:ok, entries} ->
      cond do
        resource_name?(name) ->
          fetched = bundle_age(version, expected[name], actual)

          meta = %{
            "url" => "bundle:" <> name,
            "fetched_at_unix" => fetched,
            "sha256" => expected[name]["sha256"]
          }

          if is_nil(fetched) or (is_integer(fetched) and fetched in 0..253_402_300_799),
            do: {:cont, {:ok, [{name, data, meta} | entries]}},
            else: {:halt, {:error, {:invalid_bundle, {:invalid_fetch_time, name}}}}

        version == 1 and String.ends_with?(name, ".meta.json") and
            Map.has_key?(actual, String.trim_trailing(name, ".meta.json")) ->
          {:cont, {:ok, entries}}

        true ->
          {:halt, {:error, {:invalid_bundle, {:unknown_feed_resource, name}}}}
      end
    end)
  end

  defp bundle_age(2, entry, _files), do: entry["fetched_at_unix"]

  defp bundle_age(1, entry, files) do
    with data when is_binary(data) <- files[entry["path"] <> ".meta.json"],
         {:ok, %{"fetched_at_unix" => fetched}} when is_integer(fetched) <- JSON.decode(data) do
      fetched
    else
      _ -> nil
    end
  end

  defp resource_name?(name) do
    name == OSV.cache_file() or name =~ ~r/\Acves\/CVE-[0-9]{4}-[0-9]+\.json\z/ or
      name =~ ~r/\Ahex\/packages\/[A-Za-z0-9_][A-Za-z0-9_.-]*\.json\z/
  end

  defp validate_bundle_osv(entries) do
    {_, archive, _} = List.keyfind(entries, OSV.cache_file(), 0)

    case OSV.parse_archive(archive) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:invalid_bundle, reason}}
    end
  end

  defp validate_json_resources(entries) do
    Enum.reduce_while(entries, :ok, fn {name, data, _meta}, :ok ->
      result =
        case name do
          "cves/" <> file -> EefCna.validate_record(data, Path.rootname(file))
          "hex/packages/" <> file -> HexRetired.validate_record(data, Path.rootname(file))
          _ -> {:ok, nil}
        end

      case result do
        {:ok, _} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {:invalid_bundle, {name, reason}}}}
      end
    end)
  end

  defp publish_bundle(config, entries) do
    name = "bundle-" <> Base.encode16(:crypto.strong_rand_bytes(20), case: :lower)
    root = Path.join(root(config), name)

    results =
      Enum.reduce_while(entries, :ok, fn {rel, data, meta}, :ok ->
        case Cache.publish_entry(Path.join(root, rel), data, meta) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)

    with :ok <- results, :ok <- Cache.atomic_write(pointer(config), name) do
      {:ok, root}
    else
      {:error, reason} ->
        File.rm_rf(root)
        {:error, {:bundle_write_failed, reason}}
    end
  end
end
