defmodule VulnCheck.Cache do
  @moduledoc """
  Atomic on-disk cache for advisory feeds and analyzed `.beam` modules, plus
  air-gapped bundle export/import.

  Layout (default root: `$XDG_CACHE_HOME/vulncheck` or `~/.cache/vulncheck`):

      feeds/osv_hex_all.zip            OSV Hex archive
      feeds/osv_hex_all.zip.meta.json  etag, fetched_at_unix, sha256, url
      feeds/cves/<CVE-ID>.json         EEF CNA / MITRE CVE 5.1 records
      feeds/hex/packages/<name>.json   Hex.pm package metadata
      beam-v2/<sha256>.etf             cached module summaries

  Every write goes to a unique temporary file that is then renamed into
  place, so concurrent CI jobs sharing a cache never observe partial files.
  """

  alias VulnCheck.Config

  @beam_cache_version 2
  @bundle_manifest "manifest.json"

  @type fetch_status :: :network | :cached | :revalidated | :stale

  # -- locations ---------------------------------------------------------------

  @doc "Root cache directory for a configuration."
  @spec dir(Config.t() | keyword()) :: String.t()
  def dir(%Config{cache_dir: nil}), do: default_dir()
  def dir(%Config{cache_dir: dir} = config), do: Path.expand(dir, Config.project_root(config))
  def dir(opts) when is_list(opts), do: Keyword.get_lazy(opts, :cache_dir, &default_dir/0)

  @doc "Directory holding feed data."
  @spec feeds_dir(Config.t()) :: String.t()
  def feeds_dir(config), do: Path.join(dir(config), "feeds")

  @doc "Directory holding cached `.beam` summaries."
  @spec beam_dir(Config.t()) :: String.t()
  def beam_dir(config), do: Path.join(dir(config), "beam-v2")

  defp default_dir do
    case System.get_env("XDG_CACHE_HOME") do
      base when is_binary(base) and base != "" -> Path.join(base, "vulncheck")
      _ -> Path.join([System.user_home!(), ".cache", "vulncheck"])
    end
  end

  # -- atomic files ------------------------------------------------------------

  @doc """
  Atomically writes `data` to `path` (temporary file + rename).
  """
  @spec atomic_write(Path.t(), iodata()) :: :ok | {:error, term()}
  def atomic_write(path, data) do
    tmp = "#{path}.tmp.#{System.unique_integer([:positive])}.#{:os.getpid()}"

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(tmp, data),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, reason} ->
        File.rm(tmp)
        {:error, {:cache_write_failed, path, reason}}
    end
  end

  @doc "Reads the metadata stored next to a cached file."
  @spec read_meta(Path.t()) :: map()
  def read_meta(path) do
    with {:ok, data} <- File.read(meta_path(path)),
         {:ok, %{} = meta} <- JSON.decode(data) do
      meta
    else
      _ -> %{}
    end
  end

  defp write_meta(path, meta), do: atomic_write(meta_path(path), JSON.encode!(meta))
  defp meta_path(path), do: path <> ".meta.json"

  # -- HTTP-backed fetch -------------------------------------------------------

  @doc """
  Returns the content of `url`, cached under `feeds/<rel_path>`.

  Options:

    * `:http_client` — module implementing `VulnCheck.HTTP` (default `VulnCheck.HTTP`)
    * `:offline` — never touch the network (defaults to `config.offline`)
    * `:ttl` — freshness in seconds (defaults to `config.cache_ttl_seconds`)
    * `:immutable` — once cached, never revalidate (CVE records)
    * `:force` — revalidate even when fresh
    * `:http_opts` — options forwarded to the HTTP client

  Returns `{:ok, body, status}` where status is `:network`, `:cached`,
  `:revalidated` (HTTP 304) or `:stale` (network failed, stale copy used).
  """
  @spec fetch(String.t(), String.t(), Config.t(), keyword()) ::
          {:ok, binary(), fetch_status()} | {:error, term()}
  def fetch(url, rel_path, %Config{} = config, opts \\ []) do
    path = Path.join(feeds_dir(config), rel_path)
    offline = Keyword.get(opts, :offline, config.offline)
    cached = File.read(path)

    cond do
      offline ->
        case cached do
          {:ok, body} -> {:ok, body, :cached}
          _ -> {:error, :offline_cache_missing}
        end

      match?({:ok, _}, cached) and not Keyword.get(opts, :force, false) and
          (Keyword.get(opts, :immutable, false) or fresh?(path, opts, config)) ->
        {:ok, body} = cached
        {:ok, body, :cached}

      true ->
        refresh(url, path, cached, config, opts)
    end
  end

  defp fresh?(path, opts, config) do
    ttl = Keyword.get(opts, :ttl, config.cache_ttl_seconds)

    case read_meta(path) do
      %{"fetched_at_unix" => at} when is_integer(at) -> System.os_time(:second) - at < ttl
      _ -> false
    end
  end

  defp refresh(url, path, cached, _config, opts) do
    client = Keyword.get(opts, :http_client, VulnCheck.HTTP)
    meta = read_meta(path)

    headers =
      case {cached, meta["etag"]} do
        {{:ok, _}, etag} when is_binary(etag) -> [{"if-none-match", etag}]
        _ -> []
      end

    case client.get(url, headers, Keyword.get(opts, :http_opts, [])) do
      {:ok, %{status: 200, body: body} = response} ->
        new_meta = %{
          "url" => url,
          "etag" => Map.get(response.headers, "etag"),
          "fetched_at_unix" => System.os_time(:second),
          "sha256" => sha256(body)
        }

        with :ok <- atomic_write(path, body),
             :ok <- write_meta(path, new_meta) do
          {:ok, body, :network}
        end

      {:ok, %{status: 304}} when elem(cached, 0) == :ok ->
        {:ok, body} = cached
        :ok = write_meta(path, Map.put(meta, "fetched_at_unix", System.os_time(:second)))
        {:ok, body, :revalidated}

      {:ok, %{status: status}} ->
        fallback(cached, {:http_status, status})

      {:error, reason} ->
        fallback(cached, reason)
    end
  end

  defp fallback({:ok, body}, {:http_status, status}) when status >= 500, do: {:ok, body, :stale}
  defp fallback(_cached, {:http_status, _status} = reason), do: {:error, reason}
  defp fallback({:ok, body}, _reason), do: {:ok, body, :stale}
  defp fallback(_cached, reason), do: {:error, reason}

  @doc "Reads a cached feed file without any network access."
  @spec read_feed(Config.t(), String.t()) :: {:ok, binary()} | {:error, term()}
  def read_feed(config, rel_path), do: File.read(Path.join(feeds_dir(config), rel_path))

  @doc "Lists cached feed files (relative paths), excluding metadata."
  @spec list_feed_files(Config.t()) :: [String.t()]
  def list_feed_files(config) do
    root = feeds_dir(config)

    root
    |> Path.join("**/*")
    |> Path.wildcard(match_dot: false)
    |> Enum.filter(&File.regular?/1)
    |> Enum.reject(&String.contains?(Path.basename(&1), ".tmp."))
    |> Enum.map(&Path.relative_to(&1, root))
    |> Enum.sort()
  end

  @doc "SHA-256 hex digest of a binary."
  @spec sha256(iodata()) :: String.t()
  def sha256(data), do: :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)

  # -- .beam summary cache -----------------------------------------------------

  @doc """
  Reads a cached module summary by `.beam` SHA-256. Corrupt entries or entries
  that would require creating atoms are treated as misses.
  """
  @spec get_beam(Config.t() | keyword(), String.t()) :: {:ok, term()} | :miss
  def get_beam(config, sha) do
    path = Path.join(beam_root(config), sha <> ".etf")

    with {:ok, data} <- File.read(path),
         {:vulncheck_beam, @beam_cache_version, ^sha, summary} <- safe_decode(data) do
      {:ok, summary}
    else
      _ -> :miss
    end
  end

  @doc "Stores a module summary under its `.beam` SHA-256."
  @spec put_beam(Config.t() | keyword(), String.t(), term()) :: :ok | {:error, term()}
  def put_beam(config, sha, summary) do
    path = Path.join(beam_root(config), sha <> ".etf")

    data =
      :erlang.term_to_binary({:vulncheck_beam, @beam_cache_version, sha, summary}, [:compressed])

    atomic_write(path, data)
  end

  defp beam_root(%Config{} = config), do: beam_dir(config)
  defp beam_root(opts) when is_list(opts), do: Path.join(dir(opts), "beam-v2")

  defp safe_decode(data) do
    :erlang.binary_to_term(data, [:safe])
  rescue
    ArgumentError -> :invalid
  end

  # -- air-gapped bundles ------------------------------------------------------

  @doc """
  Exports the cached feeds into a compressed `.tar.gz` bundle with a
  `manifest.json` listing the SHA-256 of every file.
  """
  @spec export_bundle(Config.t(), Path.t()) :: {:ok, map()} | {:error, term()}
  def export_bundle(%Config{} = config, out_path) do
    root = feeds_dir(config)
    files = list_feed_files(config) |> Enum.reject(&(&1 == @bundle_manifest))

    if files == [] do
      {:error, :empty_cache}
    else
      entries =
        Enum.map(files, fn rel ->
          data = File.read!(Path.join(root, rel))
          {rel, data}
        end)

      manifest = %{
        "format" => "vulncheck-feeds-bundle",
        "format_version" => 1,
        "created_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
        "tool_version" => VulnCheck.version(),
        "advisory_count" => advisory_count(root),
        "files" =>
          Enum.map(entries, fn {rel, data} ->
            %{"path" => rel, "sha256" => sha256(data), "size" => byte_size(data)}
          end)
      }

      tar_entries =
        [{@bundle_manifest, JSON.encode!(manifest)} | entries]
        |> Enum.map(fn {name, data} -> {String.to_charlist(name), data} end)

      out_path = Path.expand(out_path)
      tmp = "#{out_path}.tmp.#{System.unique_integer([:positive])}"

      with :ok <- File.mkdir_p(Path.dirname(out_path)),
           :ok <- :erl_tar.create(String.to_charlist(tmp), tar_entries, [:compressed]),
           :ok <- File.rename(tmp, out_path) do
        {:ok, manifest}
      else
        {:error, reason} ->
          File.rm(tmp)
          {:error, {:bundle_write_failed, reason}}
      end
    end
  end

  @doc """
  Imports a bundle produced by `export_bundle/2` into the cache.

  Archives containing absolute paths, `..` segments, symlinks or other
  non-regular entries are rejected (Tar Slip protection), as are files whose
  SHA-256 does not match the manifest.
  """
  @spec import_bundle(Path.t(), Config.t()) :: {:ok, map()} | {:error, term()}
  def import_bundle(bundle_path, %Config{} = config) do
    path = String.to_charlist(Path.expand(bundle_path, Config.project_root(config)))

    with {:ok, table} <- tar_table(path),
         :ok <- validate_entries(table),
         {:ok, files} <- tar_extract(path),
         {:ok, manifest} <- read_manifest(files),
         :ok <- verify_manifest(manifest, files) do
      root = feeds_dir(config)

      Enum.each(files, fn {name, data} ->
        if name != @bundle_manifest do
          :ok = atomic_write(Path.join(root, name), data)

          :ok =
            write_meta(Path.join(root, name), %{
              "url" => "bundle:" <> name,
              "fetched_at_unix" => System.os_time(:second),
              "sha256" => sha256(data)
            })
        end
      end)

      {:ok, manifest}
    end
  end

  defp tar_table(path) do
    case :erl_tar.table(path, [:compressed, :verbose]) do
      {:ok, table} -> {:ok, table}
      {:error, reason} -> {:error, {:invalid_bundle, reason}}
    end
  end

  defp validate_entries(table) do
    Enum.reduce_while(table, :ok, fn entry, :ok ->
      {name, type} = entry_name_type(entry)

      cond do
        type != :regular -> {:halt, {:error, {:unsafe_bundle_entry, name, type}}}
        not safe_name?(name) -> {:halt, {:error, {:unsafe_bundle_entry, name, :path}}}
        true -> {:cont, :ok}
      end
    end)
  end

  defp entry_name_type({name, type, _size, _mtime, _mode, _uid, _gid}), do: {to_string(name), type}
  defp entry_name_type({name, type, _size}), do: {to_string(name), type}
  defp entry_name_type(name), do: {to_string(name), :regular}

  @doc false
  @spec safe_name?(String.t()) :: boolean()
  def safe_name?(name) do
    segments = String.split(name, "/")

    name != "" and not String.starts_with?(name, "/") and not String.contains?(name, "\\") and
      not String.contains?(name, <<0>>) and not String.match?(name, ~r/\A[A-Za-z]:/) and
      ".." not in segments and "" not in segments
  end

  defp tar_extract(path) do
    case :erl_tar.extract(path, [:compressed, :memory]) do
      {:ok, files} -> {:ok, Enum.map(files, fn {name, data} -> {to_string(name), data} end)}
      {:error, reason} -> {:error, {:invalid_bundle, reason}}
    end
  end

  defp read_manifest(files) do
    with {_, data} <- List.keyfind(files, @bundle_manifest, 0),
         {:ok, %{"format" => "vulncheck-feeds-bundle", "files" => listed} = manifest}
         when is_list(listed) <- JSON.decode(data) do
      {:ok, manifest}
    else
      _ -> {:error, {:invalid_bundle, :missing_manifest}}
    end
  end

  defp verify_manifest(manifest, files) do
    expected = Map.new(manifest["files"], fn entry -> {entry["path"], entry["sha256"]} end)

    Enum.reduce_while(files, :ok, fn
      {@bundle_manifest, _data}, :ok ->
        {:cont, :ok}

      {name, data}, :ok ->
        case Map.fetch(expected, name) do
          {:ok, sha} ->
            if sha == sha256(data),
              do: {:cont, :ok},
              else: {:halt, {:error, {:invalid_bundle, {:checksum_mismatch, name}}}}

          :error ->
            {:halt, {:error, {:invalid_bundle, {:unlisted_file, name}}}}
        end
    end)
  end

  defp advisory_count(root) do
    zip = Path.join(root, "osv_hex_all.zip")

    with {:ok, data} <- File.read(zip),
         {:ok, entries} <- :zip.list_dir(data) do
      Enum.count(entries, &match?({:zip_file, _, _, _, _, _}, &1))
    else
      _ -> 0
    end
  end
end
