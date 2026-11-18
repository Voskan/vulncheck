defmodule VulnCheck.Feeds.HexRetired do
  @moduledoc """
  Detects retired Hex.pm releases (the `mix hex.audit` check) and basic
  supply-chain hygiene problems in `mix.lock`.

  Package metadata is fetched from `https://hex.pm/api/packages/<name>`
  through `VulnCheck.Cache` (ETag revalidation, offline support), eight
  packages at a time. Retired releases become advisories with a
  `VulnCheck.Types.Retirement` attached; `to_finding/2` turns them into
  `:retired` findings.
  """

  alias VulnCheck.{Cache, Config}
  alias VulnCheck.Types.{Advisory, Finding, Package, Retirement, Workspace}

  @default_api_url "https://hex.pm/api/packages"
  @reasons %{
    "security" => :security,
    "invalid" => :invalid,
    "deprecated" => :deprecated,
    "renamed" => :renamed,
    "other" => :other
  }
  @severity %{security: :high, invalid: :medium, deprecated: :low, renamed: :low, other: :low}

  @doc "Default base URL of the Hex.pm packages API."
  @spec default_api_url() :: String.t()
  def default_api_url, do: @default_api_url

  @doc """
  Returns one advisory per locked Hex release that is retired, plus warnings.

  Options: `:hex_api_url`, `:http_client`, `:http_opts` and every other
  option accepted by `VulnCheck.Cache.fetch/4`.
  """
  @spec advisories(Workspace.t(), Config.t(), keyword()) :: {[Advisory.t()], [String.t()]}
  def advisories(%Workspace{packages: packages}, %Config{} = config, opts \\ []) do
    base = opts |> Keyword.get(:hex_api_url, @default_api_url) |> String.trim_trailing("/")

    candidates =
      packages
      |> Map.values()
      |> Enum.filter(&(&1.source == :hex and is_binary(&1.version)))
      |> Enum.filter(&valid_name?(hex_name(&1)))
      |> Enum.sort_by(& &1.name)

    candidates
    |> Task.async_stream(&{&1, fetch(&1, base, config, opts)},
      max_concurrency: 8,
      timeout: 30_000,
      on_timeout: :kill_task,
      ordered: true
    )
    |> Enum.zip(candidates)
    |> Enum.reduce({[], [], 0}, fn
      {{:ok, {package, {:ok, record}}}, _}, {advisories, warnings, offline} ->
        case retirement(record, package.version) do
          nil -> {advisories, warnings, offline}
          retirement -> {[advisory(package, retirement) | advisories], warnings, offline}
        end

      {{:ok, {_package, {:error, {:http_status, 404}}}}, _}, acc ->
        acc

      {{:ok, {_package, {:error, :offline_cache_missing}}}, _}, {advisories, warnings, offline} ->
        {advisories, warnings, offline + 1}

      {{:ok, {package, {:error, reason}}}, _}, {advisories, warnings, offline} ->
        {advisories, [fetch_warning(package, reason) | warnings], offline}

      {{:exit, reason}, package}, {advisories, warnings, offline} ->
        {advisories, [fetch_warning(package, reason) | warnings], offline}
    end)
    |> then(fn {advisories, warnings, offline} ->
      warnings =
        if offline > 0,
          do: [
            "retirement status of #{offline} package(s) unknown: no cached Hex.pm metadata (offline)"
            | warnings
          ],
          else: warnings

      {Enum.reverse(advisories), Enum.reverse(warnings)}
    end)
  end

  @doc """
  Extracts the retirement of `version` from a decoded Hex.pm package record.

  Both the `releases[].retirement` and the top-level `retirements` map shapes
  are understood.

      iex> record = %{"name" => "plug", "retirements" => %{"1.0.0" => %{"reason" => "security", "message" => "Use 1.0.1"}}}
      iex> VulnCheck.Feeds.HexRetired.retirement(record, "1.0.0")
      %VulnCheck.Types.Retirement{package: "plug", version: "1.0.0", reason: :security, message: "Use 1.0.1"}
      iex> VulnCheck.Feeds.HexRetired.retirement(record, "1.1.0")
      nil
  """
  @spec retirement(map(), String.t()) :: Retirement.t() | nil
  def retirement(record, version) when is_map(record) and is_binary(version) do
    from_releases =
      record
      |> Map.get("releases")
      |> List.wrap()
      |> Enum.find_value(fn
        %{"version" => ^version, "retirement" => %{} = info} -> info
        _ -> nil
      end)

    from_map =
      case Map.get(record, "retirements") do
        %{^version => %{} = info} -> info
        _ -> nil
      end

    case from_releases || from_map do
      nil ->
        nil

      info ->
        %Retirement{
          package: string(record["name"]),
          version: version,
          reason: Map.get(@reasons, info |> Map.get("reason") |> string(), :other),
          message: string(info["message"])
        }
    end
  end

  def retirement(_record, _version), do: nil

  @doc "Severity assigned to a retirement reason."
  @spec severity(Retirement.reason()) :: Advisory.severity()
  def severity(reason), do: Map.get(@severity, reason, :low)

  @doc """
  Converts a retirement advisory into a `:retired` finding for `package`.
  """
  @spec to_finding(Advisory.t(), Package.t()) :: Finding.t()
  def to_finding(%Advisory{retirement: %Retirement{} = retirement} = advisory, %Package{} = package) do
    scope = package.scope

    detail =
      "release #{retirement.version} of #{package.name} is retired on Hex.pm " <>
        "(#{retirement.reason})" <>
        if(retirement.message != "", do: ": #{retirement.message}", else: "") <>
        case scope do
          :non_prod -> "; non-production dependency"
          :build_only -> "; build-time only dependency"
          :prod -> ""
        end

    %Finding{
      advisory_id: advisory.id,
      package: package.name,
      installed_version: package.version,
      summary: advisory.summary,
      severity: advisory.severity,
      references: advisory.references,
      verdict: :retired,
      reason: :package_retired,
      reason_detail: detail,
      fingerprint: Finding.fingerprint(advisory.id, package.name, :retired, nil),
      package_scope: scope
    }
  end

  @doc """
  Returns `true` when a retired finding should fail the gate: production
  dependencies fail when `fail_on_retired` is set; non-production ones only
  for security retirements under `--fail-on any`.
  """
  @spec gate?(Finding.t(), Config.t()) :: boolean()
  def gate?(%Finding{verdict: :retired} = finding, %Config{} = config) do
    config.fail_on_retired and config.fail_on != :none and
      (finding.package_scope == :prod or (config.fail_on == :any and finding.severity == :high))
  end

  def gate?(_finding, _config), do: false

  @doc """
  Supply-chain hygiene warnings for `mix.lock` workspaces: Hex entries
  without an outer SHA-256 checksum and production git dependencies that
  are not pinned to a full commit hash.
  """
  @spec hygiene(Workspace.t()) :: [String.t()]
  def hygiene(%Workspace{lockfile: lockfile, packages: packages}) do
    if is_binary(lockfile) and Path.basename(lockfile) == "mix.lock" do
      packages
      |> Map.values()
      |> Enum.sort_by(& &1.name)
      |> Enum.flat_map(&hygiene_warning/1)
    else
      []
    end
  end

  defp hygiene_warning(%Package{source: :hex, checksum: checksum} = package) do
    if is_binary(checksum) and Regex.match?(~r/\A[0-9a-fA-F]{64}\z/, checksum) do
      []
    else
      [
        "#{package.name} #{package.version} has no outer SHA-256 checksum in mix.lock; " <>
          "run `mix deps.unlock #{package.name} && mix deps.get` to refresh it"
      ]
    end
  end

  defp hygiene_warning(%Package{source: :git, scope: scope, git_ref: ref} = package)
       when scope != :non_prod do
    if is_binary(ref) and Regex.match?(~r/\A([0-9a-f]{40}|[0-9a-f]{64})\z/, ref) do
      []
    else
      ["production git dependency #{package.name} is not pinned to a full commit hash"]
    end
  end

  defp hygiene_warning(_package), do: []

  defp fetch(package, base, config, opts) do
    name = hex_name(package)

    cache_opts =
      opts
      |> Keyword.take([:http_client, :offline, :ttl, :force])
      |> Keyword.put(
        :http_opts,
        Keyword.merge([timeout: 8_000, retries: 1], Keyword.get(opts, :http_opts, []))
      )

    with {:ok, record, _status, _meta} <-
           Cache.fetch_validated(
             "#{base}/#{name}",
             "hex/packages/#{name}.json",
             config,
             cache_opts,
             &validate_record(&1, name)
           ) do
      {:ok, record}
    end
  end

  @doc false
  def validate_record(body, name) do
    case JSON.decode(body) do
      {:ok, %{} = record} ->
        if (is_list(record["releases"]) or is_map(record["retirements"])) and
             Map.get(record, "name", name) == name,
           do: {:ok, Map.put_new(record, "name", name)},
           else: {:error, :invalid_package_metadata}

      _ ->
        {:error, :invalid_package_metadata}
    end
  end

  defp advisory(%Package{} = package, %Retirement{} = retirement) do
    retirement = %{retirement | package: package.name}

    %Advisory{
      id: "HEX-RETIRED-#{package.name}-#{retirement.version}",
      package: package.name,
      summary:
        "#{package.name} #{retirement.version} is retired (#{retirement.reason})" <>
          if(retirement.message != "", do: ": #{retirement.message}", else: ""),
      details: retirement.message,
      severity: severity(retirement.reason),
      references: ["https://hex.pm/packages/#{hex_name(package)}/#{retirement.version}"],
      affected_versions: [retirement.version],
      retirement: retirement
    }
  end

  defp fetch_warning(package, reason) do
    "could not check Hex.pm retirement status of #{package.name}: #{inspect(reason)}"
  end

  defp hex_name(%Package{hex_name: hex_name, name: name}), do: hex_name || name

  defp valid_name?(name), do: is_binary(name) and Regex.match?(~r/\A[a-z][a-z0-9_]{0,63}\z/, name)

  defp string(value) when is_binary(value), do: value
  defp string(_), do: ""
end
