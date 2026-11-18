defmodule VulnCheck.Workspace do
  @moduledoc """
  Stage 1 of the pipeline: loads the project under audit into a
  `VulnCheck.Types.Workspace`.

  It detects the project type, parses the lockfile without evaluating code,
  computes the production dependency closure (packages reachable only from
  `:dev`/`:test` dependencies become `:non_prod`) and locates compiled `ebin`
  directories, falling back from the requested build environment to the other
  available ones.
  """

  alias VulnCheck.Config
  alias VulnCheck.Types.{Package, Workspace}

  alias VulnCheck.Workspace.{
    AppFile,
    Detector,
    GleamManifest,
    MixLock,
    MixProject,
    RebarLock
  }

  @doc """
  Loads the workspace described by `config`.
  """
  @spec load(Config.t()) :: {:ok, Workspace.t()} | {:error, term()}
  def load(%Config{} = config) do
    root = Config.project_root(config)

    case Detector.detect(root) do
      {:ok, info} ->
        load_project(info, config)

      {:error, kind, details} ->
        {:error, {kind, details}}
    end
  end

  @doc """
  Computes the set of package names reachable from `roots` through `deps`.
  """
  @spec closure(%{String.t() => Package.t()}, [String.t()]) :: MapSet.t(String.t())
  def closure(packages, roots) do
    packages
    |> do_closure(Enum.filter(roots, &Map.has_key?(packages, &1)), %{})
    |> Map.keys()
    |> MapSet.new()
  end

  defp do_closure(_packages, [], seen), do: seen

  defp do_closure(packages, [name | rest], seen) do
    if Map.has_key?(seen, name) do
      do_closure(packages, rest, seen)
    else
      deps =
        packages
        |> Map.fetch!(name)
        |> Map.get(:deps)
        |> Enum.filter(&Map.has_key?(packages, &1))

      do_closure(packages, deps ++ rest, Map.put(seen, name, true))
    end
  end

  @doc """
  Assigns `:prod` / `:non_prod` scopes. Packages reachable from production
  roots are `:prod`; packages reachable only from non-production roots are
  `:non_prod`; packages reachable from neither stay `:prod` (fail-safe).
  """
  @spec assign_scopes(%{String.t() => Package.t()}, [String.t()], [String.t()]) ::
          %{String.t() => Package.t()}
  def assign_scopes(packages, prod_roots, non_prod_roots) do
    prod = closure(packages, prod_roots)
    non_prod = closure(packages, non_prod_roots)

    Map.new(packages, fn {name, package} ->
      scope =
        cond do
          MapSet.member?(prod, name) -> :prod
          MapSet.member?(non_prod, name) -> :non_prod
          true -> :prod
        end

      {name, %{package | scope: scope}}
    end)
  end

  # -- Mix ---------------------------------------------------------------------

  defp load_project(%{type: type} = info, config) when type in [:mix, :umbrella] do
    env = Atom.to_string(config.env)

    with {:ok, locked} <- MixLock.parse_file(info.lockfile),
         {:ok, root_project} <- MixProject.parse_file(info.manifest) do
      app_projects = umbrella_projects(type, info.root, root_project)
      projects = if type == :umbrella, do: app_projects, else: [root_project]
      root_apps = projects |> Enum.map(& &1.app) |> Enum.reject(&is_nil/1) |> Enum.uniq()

      {build_env, build_dir, warnings} = choose_build(info.root, "_build", "lib", config.env)

      {prod_roots, non_prod_roots, path_packages, parsed?} =
        collect_mix_roots(projects ++ root_extra(type, root_project), env, MapSet.new(root_apps))

      root_ebins = Enum.flat_map(root_apps, &existing_ebin(build_dir, &1))

      app_roots =
        if build_env == env do
          root_ebins
          |> Enum.zip(root_apps)
          |> Enum.flat_map(fn {ebin, app} -> app_dependencies(AppFile.read_ebin(ebin, app)) end)
        else
          []
        end

      packages = Map.merge(path_packages, locked)
      direct_deps = direct_deps(prod_roots ++ non_prod_roots, packages)

      prod_roots =
        if parsed?, do: prod_roots ++ app_roots, else: Map.keys(packages)

      packages =
        packages
        |> Map.new(fn {name, package} ->
          {name, %{package | ebin_dir: first_existing_ebin(build_dir, package.otp_app || name)}}
        end)
        |> enrich_deps_from_app_files()
        |> assign_scopes(prod_roots, non_prod_roots)

      warnings =
        if parsed?,
          do: warnings,
          else:
            warnings ++
              [
                "dependencies in mix.exs are built dynamically; all locked packages are treated as :prod"
              ]

      {:ok,
       %Workspace{
         root_dir: info.root,
         project_name: project_name(type, root_project, info.root),
         project_type: type,
         env: config.env,
         elixir_version: System.version(),
         otp_release: otp_release(config),
         lockfile: info.lockfile,
         build_dir: build_dir,
         build_env: build_env,
         root_apps: root_apps,
         direct_deps: direct_deps,
         root_ebin_dirs: root_ebins,
         consolidated_dirs: consolidated_dirs(build_dir, root_apps),
         packages: packages,
         configured_adapters: config.configured_adapters,
         warnings: warnings
       }}
    end
  end

  defp load_project(%{type: :rebar3} = info, config) do
    with {:ok, locked} <- RebarLock.parse_file(info.lockfile) do
      root_apps = rebar_root_apps(info.root)

      profiles =
        if config.env == :prod,
          do: ["prod", "default"],
          else: ["default", Atom.to_string(config.env)]

      {build_env, build_dir, warnings} = choose_build_profiles(info.root, "_build", "lib", profiles)

      packages =
        locked
        |> Map.new(fn {name, package} ->
          {name, %{package | ebin_dir: first_existing_ebin(build_dir, package.otp_app || name)}}
        end)
        |> enrich_deps_from_app_files()

      {:ok,
       %Workspace{
         root_dir: info.root,
         project_name: List.first(root_apps) || Path.basename(info.root),
         project_type: :rebar3,
         direct_deps: direct_deps(dependency_sources(packages), packages),
         env: config.env,
         elixir_version: nil,
         otp_release: otp_release(config),
         lockfile: info.lockfile,
         build_dir: build_dir,
         build_env: build_env,
         root_apps: root_apps,
         root_ebin_dirs: Enum.flat_map(root_apps, &existing_ebin(build_dir, &1)),
         packages: packages,
         configured_adapters: config.configured_adapters,
         warnings: warnings
       }}
    end
  end

  defp load_project(%{type: :gleam} = info, config) do
    with {:ok, toml} <- File.read(info.manifest) |> wrap_read(info.manifest),
         {:ok, project} <- GleamManifest.parse_project(toml),
         {:ok, manifest} <- File.read(info.lockfile) |> wrap_read(info.lockfile),
         {:ok, locked} <- GleamManifest.parse_manifest(manifest) do
      profiles =
        if config.env == :prod,
          do: ["prod", "dev"],
          else: [Atom.to_string(config.env), "dev", "prod"]

      {build_env, build_dir, warnings} =
        choose_build_profiles(info.root, "build", "erlang", Enum.uniq(profiles))

      root_app = project.name || Path.basename(info.root)

      packages =
        locked
        |> Map.new(fn {name, package} ->
          {name, %{package | ebin_dir: first_existing_ebin(build_dir, package.otp_app || name)}}
        end)
        |> assign_scopes(project.dependencies, project.dev_dependencies)

      {:ok,
       %Workspace{
         root_dir: info.root,
         project_name: root_app,
         project_type: :gleam,
         env: config.env,
         elixir_version: nil,
         otp_release: otp_release(config),
         lockfile: info.lockfile,
         build_dir: build_dir,
         build_env: build_env,
         root_apps: [root_app],
         direct_deps: direct_deps(project.dependencies ++ project.dev_dependencies, packages),
         root_ebin_dirs: existing_ebin(build_dir, root_app),
         packages: packages,
         configured_adapters: config.configured_adapters,
         warnings: warnings
       }}
    end
  end

  defp direct_deps(names, packages) do
    names |> Enum.filter(&Map.has_key?(packages, &1)) |> Enum.uniq() |> Enum.sort()
  end

  # Packages no other locked package depends on.
  defp dependency_sources(packages) do
    required = packages |> Map.values() |> Enum.flat_map(& &1.deps) |> MapSet.new()
    packages |> Map.keys() |> Enum.reject(&MapSet.member?(required, &1))
  end

  defp wrap_read({:ok, content}, _path), do: {:ok, content}
  defp wrap_read({:error, reason}, path), do: {:error, "#{path}: #{:file.format_error(reason)}"}

  defp umbrella_projects(:umbrella, root, root_project) do
    apps_path = root_project.apps_path || "apps"

    root
    |> Path.join(apps_path)
    |> Path.join("*/mix.exs")
    |> Path.wildcard()
    |> Enum.sort()
    |> Enum.flat_map(fn path ->
      case MixProject.parse_file(path) do
        {:ok, project} -> [project]
        {:error, _} -> [%MixProject{file: path, deps_parsed: false}]
      end
    end)
  end

  defp umbrella_projects(_type, _root, _project), do: []

  # Umbrella roots may declare shared dependencies in the root mix.exs.
  defp root_extra(:umbrella, root_project), do: [root_project]
  defp root_extra(_type, _root_project), do: []

  defp collect_mix_roots(projects, env, sibling_apps) do
    initial = {[], [], %{}, true, MapSet.new()}

    {prod, non_prod, path_packages, parsed?, _seen} =
      Enum.reduce(projects, initial, fn project, acc ->
        collect_project(project, env, sibling_apps, :prod, acc)
      end)

    {Enum.uniq(prod), Enum.uniq(non_prod), path_packages, parsed?}
  end

  defp collect_project(project, env, siblings, inherited, {prod, non_prod, paths, parsed?, seen}) do
    parsed? = parsed? and project.deps_parsed
    seen = MapSet.put(seen, project.file)

    Enum.reduce(project.deps, {prod, non_prod, paths, parsed?, seen}, fn dep, acc ->
      {prod, non_prod, paths, parsed?, seen} = acc
      scope = if inherited == :prod and env_matches?(dep.only, env), do: :prod, else: :non_prod

      {prod, non_prod} =
        cond do
          dep.in_umbrella or MapSet.member?(siblings, dep.name) -> {prod, non_prod}
          scope == :prod -> {[dep.name | prod], non_prod}
          true -> {prod, [dep.name | non_prod]}
        end

      if dep.path do
        dep_path = Path.expand(dep.path, Path.dirname(project.file))
        mix_file = Path.join(dep_path, "mix.exs")

        cond do
          MapSet.member?(seen, mix_file) ->
            {prod, non_prod, paths, parsed?, seen}

          File.regular?(mix_file) ->
            case MixProject.parse_file(mix_file) do
              {:ok, sub} ->
                package = %Package{
                  name: dep.name,
                  version: sub.version || "0.0.0",
                  source: :path,
                  scope: scope,
                  otp_app: sub.app || dep.name,
                  deps: Enum.map(sub.deps, & &1.name),
                  runtime: dep.runtime
                }

                collect_project(
                  sub,
                  env,
                  siblings,
                  scope,
                  {prod, non_prod, Map.put(paths, dep.name, package), parsed?, seen}
                )

              {:error, _} ->
                {prod, non_prod, paths, false, seen}
            end

          true ->
            {prod, non_prod, paths, parsed?, seen}
        end
      else
        {prod, non_prod, paths, parsed?, seen}
      end
    end)
  end

  defp env_matches?(:all, _env), do: true
  defp env_matches?(envs, env), do: env in envs

  defp app_dependencies(nil), do: []
  defp app_dependencies(%AppFile{} = app), do: app.applications ++ app.included_applications

  defp enrich_deps_from_app_files(packages) do
    Map.new(packages, fn {name, package} ->
      case AppFile.read_ebin(package.ebin_dir, package.otp_app || name) do
        nil ->
          {name, package}

        app ->
          extra = Enum.filter(app_dependencies(app), &Map.has_key?(packages, &1))
          {name, %{package | deps: Enum.uniq(package.deps ++ extra)}}
      end
    end)
  end

  defp project_name(:umbrella, _project, root), do: Path.basename(root)
  defp project_name(_type, %MixProject{app: app}, root), do: app || Path.basename(root)

  defp otp_release(%Config{otp_version: nil}), do: System.otp_release()
  defp otp_release(%Config{otp_version: version}), do: version

  # -- build directories -------------------------------------------------------

  defp choose_build(root, build_root, lib, env) do
    profiles =
      [Atom.to_string(env), "prod", "dev", "test"]
      |> Enum.uniq()

    choose_build_profiles(root, build_root, lib, profiles)
  end

  defp choose_build_profiles(root, build_root, lib, [preferred | _] = profiles) do
    found =
      Enum.find(profiles, fn profile ->
        File.dir?(Path.join([root, build_root, profile, lib]))
      end)

    cond do
      found == nil ->
        {nil, nil,
         [
           "no compiled build found under #{build_root}/ (compile the project first); " <>
             "reachability analysis is limited"
         ]}

      found == preferred ->
        {found, Path.join([root, build_root, found]), []}

      true ->
        {found, Path.join([root, build_root, found]),
         ["#{build_root}/#{preferred} not found; analyzing #{build_root}/#{found} instead"]}
    end
  end

  defp existing_ebin(nil, _app), do: []

  defp existing_ebin(build_dir, app) do
    candidates = [
      Path.join([build_dir, "lib", app, "ebin"]),
      Path.join([build_dir, "erlang", app, "ebin"])
    ]

    Enum.filter(candidates, &File.dir?/1) |> Enum.take(1)
  end

  defp first_existing_ebin(build_dir, app), do: build_dir |> existing_ebin(app) |> List.first()

  defp consolidated_dirs(nil, _apps), do: []

  defp consolidated_dirs(build_dir, apps) do
    ([Path.join(build_dir, "consolidated")] ++
       Enum.map(apps, &Path.join([build_dir, "lib", &1, "consolidated"])))
    |> Enum.filter(&File.dir?/1)
  end

  # -- rebar3 ------------------------------------------------------------------

  defp rebar_root_apps(root) do
    ["src/*.app.src", "apps/*/src/*.app.src"]
    |> Enum.flat_map(&Path.wildcard(Path.join(root, &1)))
    |> Enum.sort()
    |> Enum.flat_map(fn path ->
      case AppFile.read(path) do
        {:ok, app} -> [app.name]
        _ -> [path |> Path.basename(".app.src")]
      end
    end)
    |> Enum.uniq()
  end
end
