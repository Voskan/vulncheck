defmodule VulnCheck.Cache do
  @moduledoc """
  Atomic on-disk cache for advisory feeds and analyzed `.beam` modules, plus
  air-gapped bundle export/import.

  Layout (default root: `$XDG_CACHE_HOME/vulncheck` or `~/.cache/vulncheck`):

      feeds/osv_hex_all.zip.entry            OSV Hex archive and metadata
      feeds/cves/<CVE-ID>.json.entry         EEF CNA / MITRE records and metadata
      feeds/hex/packages/<name>.json.entry   Hex.pm package metadata
      beam-v3/<sha256>.etf                   cached module summaries

  Every write goes to a unique temporary file that is then renamed into
  place, so concurrent CI jobs sharing a cache never observe partial files.
  """

  alias VulnCheck.Config
  alias VulnCheck.Cache.Bundle

  @beam_cache_version 3

  @type fetch_status :: :network | :cached | :revalidated | :stale

  # -- locations ---------------------------------------------------------------

  @doc "Root cache directory for a configuration."
  @spec dir(Config.t() | keyword()) :: String.t()
  def dir(%Config{cache_dir: nil}), do: default_dir()
  def dir(%Config{cache_dir: dir} = config), do: Path.expand(dir, Config.project_root(config))
  def dir(opts) when is_list(opts), do: Keyword.get_lazy(opts, :cache_dir, &default_dir/0)

  @doc "Directory holding feed data."
  @spec feeds_dir(Config.t()) :: String.t()
  def feeds_dir(%Config{feed_snapshot: root}) when is_binary(root), do: root

  def feeds_dir(%Config{offline: true} = config) do
    case read_limited(Bundle.pointer(config), 96) do
      {:ok, name} ->
        if name =~ ~r/\Abundle-[0-9a-f]{40}\z/,
          do: Path.join(Bundle.root(config), name),
          else: Path.join(Bundle.root(config), "invalid")

      {:error, :enoent} ->
        live_feeds_dir(config)

      {:error, _} ->
        Path.join(Bundle.root(config), "invalid")
    end
  end

  def feeds_dir(config), do: live_feeds_dir(config)

  @doc false
  def pin_feeds(%Config{} = config), do: %{config | feed_snapshot: feeds_dir(config)}

  defp live_feeds_dir(config), do: Path.join(dir(config), "feeds")

  @doc "Directory holding cached `.beam` summaries."
  @spec beam_dir(Config.t()) :: String.t()
  def beam_dir(config), do: Path.join(dir(config), "beam-v3")

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

  @entry_magic "VULNCHECK-FEED-1"
  @max_metadata_bytes 16_384
  @max_feed_bytes 50 * 1024 * 1024

  @doc false
  def max_feed_bytes, do: @max_feed_bytes

  @doc "Reads verified metadata stored with a cached file."
  @spec read_meta(Path.t()) :: map()
  def read_meta(path) do
    case read_entry(path) do
      {:ok, _body, meta} -> meta
      {:error, _reason} -> %{}
    end
  end

  @doc """
  Returns the body of a cached resource. For resources that affect scan
  results, use `fetch_validated/5` to validate and decode before publication.
  """
  @spec fetch(String.t(), String.t(), Config.t(), keyword()) ::
          {:ok, binary(), fetch_status()} | {:error, term()}
  def fetch(url, rel_path, config, opts \\ []) do
    with {:ok, value, status, _meta} <-
           fetch_validated(url, rel_path, config, opts, &{:ok, &1}) do
      {:ok, value, status}
    end
  end

  @doc """
  Fetches and decodes a resource, publishing its body and metadata together
  only after validation succeeds. Returns the decoded value, refresh
  status and metadata. Options include `:http_client`, `:http_opts`,
  `:offline`, `:ttl`, `:immutable`, `:force`, `:allow_stale` and `:max_age`.
  """
  @spec fetch_validated(String.t(), String.t(), Config.t(), keyword(), function()) ::
          {:ok, term(), fetch_status(), map()} | {:error, term()}
  def fetch_validated(url, rel_path, %Config{} = config, opts, validator) do
    if safe_name?(rel_path),
      do: do_fetch(url, rel_path, config, opts, validator),
      else: {:error, :invalid_cache_key}
  end

  defp do_fetch(url, rel_path, config, opts, validator) do
    offline = Keyword.get(opts, :offline, config.offline)
    path = Path.join(feeds_dir(%{config | offline: offline}), rel_path)
    opts = Keyword.put_new(opts, :ttl, config.cache_ttl_seconds)
    cached = validated_entry(path, validator)

    cond do
      offline -> cached_result(cached, Keyword.get(opts, :max_age))
      fresh?(cached, opts) -> cached_result(cached, nil)
      true -> refresh(url, path, cached, opts, validator)
    end
  end

  defp validated_entry(path, validator) do
    with {:ok, body, meta} <- read_entry(path),
         {:ok, value} <- validator.(body) do
      {:ok, value, body, meta}
    end
  end

  defp fresh?({:ok, _value, _body, meta}, opts) do
    not Keyword.get(opts, :force, false) and within_age?(meta, Keyword.get(opts, :max_age)) and
      (Keyword.get(opts, :immutable, false) or within_age?(meta, Keyword.fetch!(opts, :ttl)))
  end

  defp fresh?(_entry, _opts), do: false

  defp within_age?(_meta, nil), do: true

  defp within_age?(%{"fetched_at_unix" => at}, limit) when is_integer(at) do
    age = System.os_time(:second) - at
    age >= 0 and age < limit
  end

  defp within_age?(_meta, _limit), do: false

  defp cached_result({:ok, value, _body, meta}, limit) do
    if within_age?(meta, limit),
      do: {:ok, value, :cached, meta},
      else: {:error, {:feed_too_old, meta["fetched_at_unix"], limit}}
  end

  defp cached_result({:error, :enoent}, _limit), do: {:error, :offline_cache_missing}
  defp cached_result(error, _limit), do: error

  defp refresh(url, path, cached, opts, validator) do
    client = Keyword.get(opts, :http_client, VulnCheck.HTTP)

    headers =
      case cached do
        {:ok, _, _, %{"url" => ^url, "etag" => etag}} when is_binary(etag) ->
          [{"if-none-match", etag}]

        _ ->
          []
      end

    case client.get(url, headers, Keyword.get(opts, :http_opts, [])) do
      {:ok, %{status: 200, body: body} = response} ->
        meta = %{
          "url" => url,
          "etag" => Map.get(response.headers, "etag"),
          "fetched_at_unix" => System.os_time(:second),
          "sha256" => sha256(body)
        }

        with {:ok, value} <- validate_download(body, validator),
             :ok <- publish_entry(path, body, meta) do
          {:ok, value, :network, meta}
        else
          {:error, reason} -> fallback(cached, reason, opts)
        end

      {:ok, %{status: 304}} when headers != [] ->
        revalidate(path, cached, opts, validator)

      {:ok, %{status: status}} ->
        fallback(cached, {:http_status, status}, opts)

      {:error, reason} ->
        fallback(cached, reason, opts)
    end
  end

  defp validate_download(body, validator) when byte_size(body) <= @max_feed_bytes,
    do: validator.(body)

  defp validate_download(_body, _validator), do: {:error, {:feed_too_large, @max_feed_bytes}}

  defp revalidate(path, {:ok, value, body, meta} = cached, opts, validator) do
    case read_entry(path) do
      {:ok, _current, ^meta} ->
        updated = Map.put(meta, "fetched_at_unix", System.os_time(:second))

        case publish_entry(path, body, updated) do
          :ok -> {:ok, value, :revalidated, updated}
          {:error, reason} -> fallback(cached, reason, opts)
        end

      {:ok, current, current_meta} ->
        with {:ok, decoded} <- validator.(current) do
          cached_result({:ok, decoded, current, current_meta}, Keyword.get(opts, :max_age))
        end

      {:error, reason} ->
        fallback(cached, reason, opts)
    end
  end

  defp fallback(_cached, {:http_status, status} = reason, _opts) when status < 500,
    do: {:error, reason}

  defp fallback({:ok, value, _body, meta}, reason, opts) do
    limit = Keyword.get(opts, :max_age)

    cond do
      not Keyword.get(opts, :allow_stale, true) ->
        {:error, reason}

      within_age?(meta, limit) ->
        {:ok, value, :stale, Map.put(meta, "refresh_error", reason)}

      true ->
        {:error, {:feed_too_old, meta["fetched_at_unix"], limit}}
    end
  end

  defp fallback(_cached, reason, _opts), do: {:error, reason}

  defp read_entry(path) do
    case read_limited(entry_path(path), @max_feed_bytes + @max_metadata_bytes + 32) do
      {:ok, <<@entry_magic, size::32, rest::binary>>} when size <= @max_metadata_bytes ->
        with <<header::binary-size(^size), body::binary>> when byte_size(body) <= @max_feed_bytes <-
               rest,
             {:ok, %{"sha256" => _} = meta} <- JSON.decode(header) do
          verify_entry(body, meta)
        else
          _ -> {:error, :invalid_cache_entry}
        end

      {:ok, _} ->
        {:error, :invalid_cache_entry}

      {:error, :enoent} ->
        read_legacy_entry(path)

      error ->
        error
    end
  end

  defp read_legacy_entry(path) do
    with {:ok, body} <- read_limited(path, @max_feed_bytes) do
      meta =
        case read_limited(path <> ".meta.json", @max_metadata_bytes) do
          {:ok, data} ->
            case JSON.decode(data) do
              {:ok, %{} = meta} -> meta
              _ -> :invalid
            end

          {:error, :enoent} ->
            case File.stat(path, time: :posix) do
              {:ok, stat} -> %{"fetched_at_unix" => stat.mtime}
              _ -> %{}
            end

          _ ->
            :invalid
        end

      verify_entry(body, meta)
    end
  end

  defp verify_entry(body, %{} = meta) do
    checksum = sha256(body)

    if Map.get(meta, "sha256", checksum) == checksum,
      do: {:ok, body, Map.put(meta, "sha256", checksum)},
      else: {:error, :cache_checksum_mismatch}
  end

  defp verify_entry(_body, _meta), do: {:error, :invalid_cache_entry}

  @doc false
  def publish_entry(path, body, meta) do
    header = JSON.encode!(meta)
    atomic_write(entry_path(path), [@entry_magic, <<byte_size(header)::32>>, header, body])
  end

  defp entry_path(path), do: path <> ".entry"

  @doc false
  def read_limited(path, max) do
    with {:ok, file} <- File.open(path, [:read, :raw, :binary]) do
      try do
        case :file.read(file, max + 1) do
          {:ok, body} when byte_size(body) <= max -> {:ok, body}
          {:ok, _body} -> {:error, {:feed_too_large, max}}
          :eof -> {:ok, <<>>}
          {:error, _} = error -> error
        end
      after
        File.close(file)
      end
    end
  end

  @doc "Reads a verified cached feed file without any network access."
  @spec read_feed(Config.t(), String.t()) :: {:ok, binary()} | {:error, term()}
  def read_feed(config, rel_path) do
    with {:ok, body, _meta} <- read_feed_entry(config, rel_path), do: {:ok, body}
  end

  @doc false
  def read_feed_entry(config, rel_path) do
    if safe_name?(rel_path),
      do: read_entry(Path.join(feeds_dir(config), rel_path)),
      else: {:error, :invalid_cache_key}
  end

  @doc "Lists cached feed resources (relative paths), excluding metadata and temporary files."
  @spec list_feed_files(Config.t()) :: [String.t()]
  def list_feed_files(config) do
    root = feeds_dir(config)

    root
    |> Path.join("**/*")
    |> Path.wildcard(match_dot: false)
    |> Enum.filter(&File.regular?/1)
    |> Enum.reject(fn path ->
      String.contains?(Path.basename(path), ".tmp.") or String.ends_with?(path, ".meta.json")
    end)
    |> Enum.map(&Path.relative_to(&1, root))
    |> Enum.map(&String.trim_trailing(&1, ".entry"))
    |> Enum.uniq()
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
  defp beam_root(opts) when is_list(opts), do: Path.join(dir(opts), "beam-v3")

  defp safe_decode(data) do
    :erlang.binary_to_term(data, [:safe])
  rescue
    ArgumentError -> :invalid
  end

  # -- air-gapped bundles ------------------------------------------------------

  @doc "Exports a verified snapshot of cached feeds."
  @spec export_bundle(Config.t(), Path.t()) :: {:ok, map()} | {:error, term()}
  defdelegate export_bundle(config, path), to: Bundle

  @doc "Validates and atomically selects a bundle for offline scans."
  @spec import_bundle(Path.t(), Config.t()) :: {:ok, map()} | {:error, term()}
  defdelegate import_bundle(path, config), to: Bundle

  @doc false
  defdelegate import_bundle_snapshot(path, config), to: Bundle

  @doc false
  @spec safe_name?(String.t()) :: boolean()
  def safe_name?(name) do
    segments = String.split(name, "/")

    name != "" and String.valid?(name) and not String.starts_with?(name, "/") and
      not String.contains?(name, "\\") and not String.contains?(name, <<0>>) and
      not String.match?(name, ~r/\A[A-Za-z]:/) and not Enum.any?(segments, &(&1 in ["", ".", ".."]))
  end
end
