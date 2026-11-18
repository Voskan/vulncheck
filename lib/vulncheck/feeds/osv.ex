defmodule VulnCheck.Feeds.OSV do
  @moduledoc """
  Ingests the OSV.dev Hex ecosystem archive (`Hex/all.zip`).

  The archive is downloaded through `VulnCheck.Cache` (ETag revalidation,
  offline support), unpacked in memory with size and entry-count limits, and
  every record is converted into one `VulnCheck.Types.Advisory` per affected
  Hex package. Records of the same vulnerability (for example the EEF and
  GitHub records of one CVE) are merged by `VulnCheck.Feeds.Merge`.
  """

  alias VulnCheck.{Cache, Config, Semver}
  alias VulnCheck.Feeds.{Archive, CVSS, Merge, TextHints}
  alias VulnCheck.Types.{Advisory, MFA, VersionRange}
  alias VulnCheck.Workspace.GitUrl

  @default_url "https://osv-vulnerabilities.storage.googleapis.com/Hex/all.zip"
  @cache_file "osv_hex_all.zip"
  @max_compressed 50 * 1024 * 1024
  @max_entries 50_000
  @max_uncompressed 256 * 1024 * 1024
  @max_record_bytes 4 * 1024 * 1024
  @online_max_age 24 * 60 * 60

  @doc "Default URL of the OSV Hex archive."
  @spec default_url() :: String.t()
  def default_url, do: @default_url

  @doc "Cache path (relative to the feeds directory) of the archive."
  @spec cache_file() :: String.t()
  def cache_file, do: @cache_file

  @doc """
  Fetches (or reads from cache) and parses the OSV Hex archive.

  Options: `:osv_url`, plus every option accepted by `VulnCheck.Cache.fetch/4`.
  """
  @spec load(Config.t(), keyword()) ::
          {:ok, [Advisory.t()], Cache.fetch_status()} | {:error, term()}
  def load(%Config{} = config, opts \\ []) do
    with {:ok, advisories, status, _meta} <- load_with_metadata(config, opts),
         do: {:ok, advisories, status}
  end

  @doc false
  def load_with_metadata(%Config{} = config, opts) do
    url = Keyword.get(opts, :osv_url, @default_url)

    max_age =
      config.max_feed_age_seconds ||
        if(!Keyword.get(opts, :offline, config.offline), do: @online_max_age)

    opts = Keyword.put_new(opts, :max_age, max_age)

    Cache.fetch_validated(url, @cache_file, config, opts, &parse_archive/1)
  end

  @doc false
  def source(%{"url" => "bundle:" <> _ = url}), do: url

  def source(%{"url" => url}) when is_binary(url) do
    uri = URI.parse(url)
    %{uri | userinfo: nil, query: nil, fragment: nil} |> URI.to_string()
  end

  def source(_meta), do: "local cache"

  @doc """
  Parses an in-memory ZIP archive of OSV JSON records.
  """
  @spec parse_archive(binary()) :: {:ok, [Advisory.t()]} | {:error, term()}
  def parse_archive(zip) when is_binary(zip) and byte_size(zip) <= @max_compressed do
    with {:ok, files} <- archive_directory(zip) do
      {advisories, rejected} =
        Enum.reduce(files, {[], 0}, fn entry, {advisories, rejected} ->
          with {:ok, data} <- Archive.zip_entry(zip, entry),
               {:ok, record} <- JSON.decode(data),
               true <- valid_record?(record) do
            {Enum.reverse(parse_record(record), advisories), rejected}
          else
            _ -> {advisories, rejected + 1}
          end
        end)

      if rejected == 0,
        do: {:ok, advisories |> Enum.reverse() |> Merge.merge()},
        else: {:error, {:invalid_osv_records, rejected}}
    end
  end

  def parse_archive(_zip), do: {:error, {:archive_too_large, :compressed}}

  defp valid_record?(%{"id" => id, "withdrawn" => time})
       when is_binary(id) and id != "" and is_binary(time), do: true

  defp valid_record?(%{"id" => id, "affected" => affected})
       when is_binary(id) and id != "" and is_list(affected),
       do: Enum.all?(affected, &known_affected?/1)

  defp valid_record?(_record), do: false

  defp known_affected?(%{"package" => %{"ecosystem" => ecosystem, "name" => name}})
       when is_binary(ecosystem) and ecosystem != "" and is_binary(name) and name != "",
       do: true

  defp known_affected?(%{"ranges" => [_ | _] = ranges}),
    do: Enum.all?(ranges, &match?(%{"type" => "GIT", "repo" => repo} when is_binary(repo), &1))

  defp known_affected?(_affected), do: false

  @doc """
  Groups advisories by package name and normalized git repository slug.
  """
  @spec index([Advisory.t()]) :: %{String.t() => [Advisory.t()]}
  def index(advisories) do
    Enum.reduce(advisories, %{}, fn advisory, acc ->
      keys = Enum.uniq([advisory.package | advisory.git_repos])

      Enum.reduce(keys, acc, fn key, inner ->
        Map.update(inner, key, [advisory], &[advisory | &1])
      end)
    end)
    |> Map.new(fn {k, list} -> {k, Enum.reverse(list)} end)
  end

  @doc """
  Converts one decoded OSV record into advisories (one per affected Hex package).
  Withdrawn records produce no advisories.
  """
  @spec parse_record(map()) :: [Advisory.t()]
  def parse_record(%{"withdrawn" => withdrawn}) when is_binary(withdrawn), do: []

  def parse_record(%{"id" => id} = record) when is_binary(id) do
    default_rating = CVSS.ratings(record["severity"], id)
    database = map(record["database_specific"])
    summary = string(record["summary"])
    details = string(record["details"])

    record
    |> list("affected")
    |> Enum.filter(&(hex_package?(&1) or git_affected?(&1)))
    |> Enum.group_by(&affected_package_key/1)
    |> Enum.reject(fn {package, _entries} -> is_nil(package) end)
    |> Enum.map(fn {package, entries} ->
      blocks = Enum.map(entries, &affected_block/1)
      ranges = Enum.flat_map(blocks, & &1.ranges)
      versions = Enum.flat_map(blocks, & &1.versions)
      ranges = include_unbounded_blocks(blocks, ranges, versions)
      git_repos = blocks |> Enum.flat_map(& &1.git_repos) |> Enum.uniq()
      git_ranges = blocks |> Enum.flat_map(& &1.git_ranges) |> Enum.uniq()

      scoped_ratings =
        for {entry, block} <- Enum.zip(entries, blocks),
            rating = CVSS.ratings(entry["severity"], id),
            do: {block.ranges, block.versions, rating}

      ratings = [
        %{default: default_rating, scoped: scoped_ratings, ranges: ranges, versions: versions}
      ]

      severity = Advisory.parse_severity(database["severity"])
      modules = blocks |> Enum.flat_map(& &1.modules) |> Enum.uniq()
      routines = blocks |> Enum.flat_map(& &1.routines) |> Enum.uniq()

      %Advisory{
        id: id,
        aliases: record |> list("aliases") |> Enum.filter(&is_binary/1),
        package: package,
        source_package: package,
        summary: summary,
        details: details,
        qualitative_severity: severity,
        cvss_ratings: ratings,
        cwes: database |> Map.get("cwe_ids", []) |> List.wrap() |> Enum.filter(&is_binary/1),
        references:
          record
          |> list("references")
          |> Enum.flat_map(fn
            %{"url" => url} when is_binary(url) -> [url]
            _ -> []
          end),
        published_at: string_or_nil(record["published"]),
        modified_at: string_or_nil(record["modified"]),
        version_ranges: ranges,
        affected_versions: versions,
        fixed_versions: Semver.fixed_versions(ranges),
        affected_modules: modules,
        affected_routines: routines,
        affected_blocks: blocks,
        git_repos: git_repos,
        git_ranges: git_ranges,
        symbol_source: if(routines != [], do: :osv),
        otp_constraints:
          string_or_nil(database["otp_constraints"]) ||
            TextHints.otp_constraint(summary <> "\n" <> details)
      }
      |> CVSS.apply_rating(CVSS.select(ratings, nil), severity)
    end)
    |> Enum.sort_by(& &1.package)
  end

  def parse_record(_), do: []

  @doc "Restricts structured symbols to the affected blocks for a locked version."
  @spec scope_symbols(Advisory.t(), String.t()) :: Advisory.t()
  def scope_symbols(%Advisory{affected_blocks: []} = advisory, _version), do: advisory

  def scope_symbols(%Advisory{} = advisory, version) do
    blocks =
      Enum.filter(advisory.affected_blocks, &Semver.affected?(version, &1.ranges, &1.versions))

    modules = blocks |> Enum.flat_map(& &1.modules) |> Enum.uniq()
    routines = blocks |> Enum.flat_map(& &1.routines) |> Enum.uniq()

    %{
      advisory
      | affected_modules: modules,
        affected_routines: routines,
        symbol_source: if(routines != [], do: :osv),
        symbol_gaps:
          (routines != [] and Enum.any?(blocks, &(&1.routines == []))) or
            (modules != [] and Enum.any?(blocks, &(&1.routines == [] and &1.modules == [])))
    }
  end

  defp affected_block(entry) do
    {modules, routines} = ecosystem_symbols([entry])
    git_ranges = Semver.from_osv_git_ranges(entry["ranges"])
    git_repos = git_ranges |> Enum.map(& &1.repo) |> Enum.reject(&is_nil/1) |> Enum.uniq()

    %{
      ranges: Semver.from_osv_ranges(entry["ranges"]),
      git_ranges: git_ranges,
      versions: entry |> list("versions") |> Enum.filter(&is_binary/1),
      modules: modules,
      routines: routines,
      git_repos: git_repos
    }
  end

  defp include_unbounded_blocks(_blocks, [], []), do: []

  defp include_unbounded_blocks(blocks, ranges, _versions) do
    if Enum.any?(blocks, &(&1.ranges == [] and &1.versions == [])),
      do: [%VersionRange{} | ranges],
      else: ranges
  end

  defp hex_package?(%{"package" => %{"ecosystem" => ecosystem, "name" => name}})
       when is_binary(name),
       do: ecosystem in ["Hex", "hex"]

  defp hex_package?(_), do: false

  defp git_affected?(%{"ranges" => ranges}) when is_list(ranges) do
    Enum.any?(ranges, &match?(%{"type" => "GIT", "repo" => repo} when is_binary(repo), &1))
  end

  defp git_affected?(_), do: false

  defp affected_package_key(affected) do
    case affected |> map() |> Map.get("package") |> map() |> Map.get("name") do
      name when is_binary(name) and name != "" ->
        name

      _ ->
        affected
        |> list("ranges")
        |> Enum.find_value(fn
          %{"type" => "GIT", "repo" => repo} when is_binary(repo) -> GitUrl.repo_slug(repo)
          _ -> nil
        end)
    end
  end

  defp ecosystem_symbols(entries) do
    specifics =
      Enum.flat_map(entries, fn entry ->
        [map(entry["ecosystem_specific"]), map(entry["database_specific"])]
      end)

    routines =
      specifics
      |> Enum.flat_map(fn specific ->
        ["affected_functions", "functions", "program_routines", "programRoutines"]
        |> Enum.flat_map(&List.wrap(specific[&1]))
      end)
      |> Enum.flat_map(fn
        name when is_binary(name) -> parse_routine(name)
        %{"name" => name} when is_binary(name) -> parse_routine(name)
        _ -> []
      end)
      |> Enum.uniq()

    modules =
      specifics
      |> Enum.flat_map(&List.wrap(&1["modules"] || &1["affected_modules"]))
      |> Enum.filter(&is_binary/1)
      |> Enum.map(&MFA.normalize_module/1)
      |> Enum.uniq()

    {modules, routines}
  end

  defp parse_routine(name) do
    case MFA.parse_routine(name) do
      {:ok, mfa} -> [mfa]
      :error -> []
    end
  end

  defp archive_directory(zip) do
    case :zip.list_dir(zip) do
      {:ok, entries} ->
        files = for {:zip_file, _, _, _, _, _} = file <- entries, do: file
        sizes = Enum.map(files, &elem(elem(&1, 2), 1))
        names = Enum.map(files, &elem(&1, 1))

        cond do
          length(files) > @max_entries ->
            {:error, {:archive_too_large, :entries}}

          Enum.sum(sizes) > @max_uncompressed ->
            {:error, {:archive_too_large, :size}}

          Enum.any?(sizes, &(&1 < 0 or &1 > @max_record_bytes)) ->
            {:error, {:archive_too_large, :record}}

          length(Enum.uniq(names)) != length(names) ->
            {:error, {:invalid_archive, :duplicate_entries}}

          true ->
            records =
              files
              |> Enum.filter(&(Enum.take(elem(&1, 1), -5) == ~c".json"))
              |> Enum.sort_by(&elem(&1, 1))

            if files != [] and records == [],
              do: {:error, {:invalid_archive, :no_advisory_records}},
              else: {:ok, records}
        end

      {:error, reason} ->
        {:error, {:invalid_archive, reason}}
    end
  end

  defp list(map, key) when is_map(map) do
    case Map.get(map, key) do
      list when is_list(list) -> list
      _ -> []
    end
  end

  defp list(_map, _key), do: []

  defp map(value) when is_map(value), do: value
  defp map(_), do: %{}

  defp string(value) when is_binary(value), do: value
  defp string(_), do: ""

  defp string_or_nil(value) when is_binary(value) and value != "", do: value
  defp string_or_nil(_), do: nil
end
