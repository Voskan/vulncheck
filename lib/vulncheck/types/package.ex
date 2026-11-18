defmodule VulnCheck.Types.Package do
  @moduledoc """
  A locked dependency of the scanned project.

  `scope` separates the production runtime closure (`:prod`) from packages that
  are only present for development, testing or documentation (`:non_prod`)
  and packages only needed to build the production release (`:build_only`:
  declared with `runtime: false`, and their dependencies that no runtime
  dependency needs).
  """

  @type source_kind :: :hex | :git | :path | :stdlib
  @type dep_scope :: :prod | :build_only | :non_prod

  @enforce_keys [:name, :version, :source, :scope]
  defstruct [
    :name,
    :version,
    :source,
    :scope,
    :hex_name,
    :checksum,
    :inner_checksum,
    :git_ref,
    :git_url,
    :otp_app,
    :ebin_dir,
    deps: [],
    optional_deps: [],
    runtime: true,
    lock_line: nil
  ]

  @type t :: %__MODULE__{
          name: String.t(),
          version: String.t(),
          source: source_kind(),
          scope: dep_scope(),
          hex_name: String.t() | nil,
          checksum: String.t() | nil,
          inner_checksum: String.t() | nil,
          git_ref: String.t() | nil,
          git_url: String.t() | nil,
          otp_app: String.t() | nil,
          ebin_dir: String.t() | nil,
          deps: [String.t()],
          optional_deps: [String.t()],
          runtime: boolean(),
          lock_line: pos_integer() | nil
        }
end

defmodule VulnCheck.Types.Workspace do
  @moduledoc """
  The fully resolved project under audit: project type, target runtime,
  locked packages with their scopes and the compiled artifact locations.
  """

  alias VulnCheck.Types.Package

  @type project_type :: :mix | :umbrella | :rebar3 | :gleam

  @enforce_keys [:root_dir, :project_name, :project_type, :env, :otp_release]
  defstruct [
    :root_dir,
    :project_name,
    :project_version,
    :project_type,
    :env,
    :elixir_version,
    :otp_release,
    :lockfile,
    :build_dir,
    :build_env,
    root_apps: [],
    direct_deps: [],
    root_ebin_dirs: [],
    consolidated_dirs: [],
    packages: %{},
    configured_adapters: %{},
    warnings: []
  ]

  @type t :: %__MODULE__{
          root_dir: String.t(),
          project_name: String.t(),
          project_version: String.t() | nil,
          project_type: project_type(),
          env: :prod | :dev | :test,
          elixir_version: String.t() | nil,
          otp_release: String.t(),
          lockfile: String.t() | nil,
          build_dir: String.t() | nil,
          build_env: String.t() | nil,
          root_apps: [String.t()],
          direct_deps: [String.t()],
          root_ebin_dirs: [String.t()],
          consolidated_dirs: [String.t()],
          packages: %{String.t() => Package.t()},
          configured_adapters: %{atom() => [String.t()]},
          warnings: [String.t()]
        }

  @doc "Returns the packages that belong to the production closure."
  @spec prod_packages(t()) :: [Package.t()]
  def prod_packages(%__MODULE__{packages: packages}) do
    packages |> Map.values() |> Enum.filter(&(&1.scope == :prod)) |> Enum.sort_by(& &1.name)
  end

  @doc """
  Returns the packages that are excluded from the production closure
  (development, test and build-time only dependencies).
  """
  @spec non_prod_packages(t()) :: [Package.t()]
  def non_prod_packages(%__MODULE__{packages: packages}) do
    packages
    |> Map.values()
    |> Enum.filter(&(&1.scope != :prod))
    |> Enum.sort_by(& &1.name)
  end
end
