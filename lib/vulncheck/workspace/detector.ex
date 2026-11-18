defmodule VulnCheck.Workspace.Detector do
  @moduledoc """
  Detects the kind of BEAM project located in a directory.

    * `:umbrella` — `mix.exs` declaring `apps_path` (or an `apps/*/mix.exs`
      layout) with a root `mix.lock`
    * `:mix` — `mix.exs` with `mix.lock`
    * `:gleam` — `gleam.toml` with `manifest.toml`
    * `:rebar3` — `rebar.config` with `rebar.lock`
  """

  alias VulnCheck.Workspace.MixProject

  @type info :: %{
          type: :mix | :umbrella | :rebar3 | :gleam,
          root: String.t(),
          lockfile: String.t(),
          manifest: String.t()
        }

  @doc """
  Detects the project type of `dir`.

  Returns `{:error, :lockfile_not_found, details}` when a project manifest is
  present without its lockfile, and `{:error, :unknown_project, details}` when
  no supported manifest exists.
  """
  @spec detect(Path.t()) ::
          {:ok, info()}
          | {:error, :lockfile_not_found | :unknown_project, String.t()}
  def detect(dir) do
    root = Path.expand(dir)
    file = &Path.join(root, &1)

    cond do
      File.regular?(file.("mix.exs")) ->
        type = if umbrella?(root), do: :umbrella, else: :mix
        with_lock(type, root, "mix.exs", "mix.lock")

      File.regular?(file.("gleam.toml")) ->
        with_lock(:gleam, root, "gleam.toml", "manifest.toml")

      File.regular?(file.("rebar.config")) ->
        with_lock(:rebar3, root, "rebar.config", "rebar.lock")

      true ->
        {:error, :unknown_project, "no mix.exs, rebar.config or gleam.toml found in #{root}"}
    end
  end

  defp with_lock(type, root, manifest, lock) do
    lockfile = Path.join(root, lock)

    if File.regular?(lockfile) do
      {:ok, %{type: type, root: root, lockfile: lockfile, manifest: Path.join(root, manifest)}}
    else
      {:error, :lockfile_not_found,
       "#{lock} not found in #{root} (fetch dependencies first, e.g. `mix deps.get`, " <>
         "`rebar3 lock` or `gleam deps download`)"}
    end
  end

  defp umbrella?(root) do
    case MixProject.parse_file(Path.join(root, "mix.exs")) do
      {:ok, %MixProject{apps_path: path}} when is_binary(path) ->
        true

      _ ->
        root |> Path.join("apps/*/mix.exs") |> Path.wildcard() |> Enum.any?() and not has_app?(root)
    end
  end

  defp has_app?(root) do
    match?(
      {:ok, %MixProject{app: app}} when is_binary(app),
      MixProject.parse_file(Path.join(root, "mix.exs"))
    )
  end
end
