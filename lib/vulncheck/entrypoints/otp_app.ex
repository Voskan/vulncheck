defmodule VulnCheck.Entrypoints.OtpApp do
  @moduledoc """
  Computes which OTP applications start at boot and their application
  callback modules, from the `.app` resource files of the build.

  Starting from the project's root applications, `applications` and
  `included_applications` are followed transitively. Optional applications
  only count when they are actually present in the build.
  """

  alias VulnCheck.Types.{Package, Workspace}
  alias VulnCheck.Workspace.AppFile

  @type result :: %{
          started: [String.t()],
          app_modules: %{String.t() => String.t()},
          root_has_mod: boolean(),
          boot_tree_known: boolean(),
          notes: [String.t()]
        }

  @doc """
  Walks the application tree of a workspace.

  `app_modules` maps every started application with a `mod` entry to its
  callback module.
  """
  @spec analyze(Workspace.t()) :: result()
  def analyze(%Workspace{} = workspace) do
    by_app = packages_by_app(workspace)
    root_files = Map.new(workspace.root_apps, &{&1, root_app_file(workspace, &1)})
    missing = for {app, nil} <- root_files, do: app

    {started, app_files} = walk(workspace.root_apps, root_files, by_app)

    app_modules =
      for {app, %AppFile{mod: mod}} <- app_files, is_binary(mod), into: %{}, do: {app, mod}

    notes =
      if missing == [],
        do: [],
        else: [
          "no compiled .app file for #{Enum.join(missing, ", ")}; " <>
            "treating every public function of the project as an entrypoint"
        ]

    %{
      started: Enum.sort(started),
      app_modules: app_modules,
      root_has_mod: Enum.any?(workspace.root_apps, &Map.has_key?(app_modules, &1)),
      boot_tree_known: workspace.root_apps != [] and missing == [],
      notes: notes
    }
  end

  @doc "Maps OTP application names to workspace packages."
  @spec packages_by_app(Workspace.t()) :: %{String.t() => Package.t()}
  def packages_by_app(%Workspace{packages: packages}) do
    packages
    |> Map.values()
    |> Map.new(&{&1.otp_app || &1.name, &1})
  end

  defp walk(roots, root_files, by_app) do
    walk(roots, root_files, by_app, MapSet.new(), %{})
  end

  defp walk([], _root_files, _by_app, seen, files), do: {MapSet.to_list(seen), files}

  defp walk([app | rest], root_files, by_app, seen, files) do
    if MapSet.member?(seen, app) do
      walk(rest, root_files, by_app, seen, files)
    else
      file =
        case Map.fetch(root_files, app) do
          {:ok, file} -> file
          :error -> package_app_file(Map.get(by_app, app), app)
        end

      seen = MapSet.put(seen, app)

      case file do
        %AppFile{} = file ->
          optional = MapSet.new(file.optional_applications)

          children =
            (file.applications ++ file.included_applications)
            |> Enum.reject(fn child ->
              MapSet.member?(optional, child) and not Map.has_key?(by_app, child) and
                not Map.has_key?(root_files, child)
            end)

          walk(children ++ rest, root_files, by_app, seen, Map.put(files, app, file))

        nil ->
          walk(rest, root_files, by_app, seen, files)
      end
    end
  end

  defp root_app_file(%Workspace{root_ebin_dirs: dirs}, app) do
    Enum.find_value(dirs, &AppFile.read_ebin(&1, app))
  end

  defp package_app_file(%Package{ebin_dir: ebin} = package, app) do
    AppFile.read_ebin(ebin, app) || AppFile.read_ebin(ebin, package.name)
  end

  defp package_app_file(nil, _app), do: nil
end
