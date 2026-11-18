defmodule VulnCheck.Solver.RoutineScope do
  @moduledoc """
  Splits the routines and modules named by an advisory into those that
  belong to the vulnerable package and context routines from elsewhere.

  CVE records often list functions on the vulnerable path that live outside
  the package, such as `List.delete/2` or a function of another dependency.
  Those are reachable in almost any project, so treating them as targets
  would prove nothing about the package. A module is part of the package
  when:

    * a compiled module of that name belongs to the package; or
    * no compiled module of that name exists and it is not a module of the
      Erlang/OTP or Elixir installation running the scan (unknown modules
      stay targets, so missing `.beam` files never hide an advisory).

  Modules compiled for another package or the project, and platform
  modules, are context.
  """

  alias VulnCheck.Types.{Advisory, MFA, ModuleSummary}

  @elixir_apps [:elixir, :eex, :logger, :mix, :iex, :ex_unit]
  @cache_key {__MODULE__, :platform_modules}

  @type split :: %{
          routines: [MFA.t()],
          modules: [String.t()],
          context_routines: [MFA.t()]
        }

  @doc """
  Splits `advisory`'s routines and modules for the package known by the
  names in `owners` (lockfile key and OTP application), using the compiled
  modules of the workspace (`%{module_name => ModuleSummary.t()}`; may be
  empty).
  """
  @spec split(Advisory.t(), [String.t()], %{String.t() => ModuleSummary.t()}) :: split()
  def split(%Advisory{} = advisory, owners, modules) do
    {routines, context} =
      Enum.split_with(advisory.affected_routines, &own?(&1.module, owners, modules))

    %{
      routines: routines,
      modules: Enum.filter(advisory.affected_modules, &own?(&1, owners, modules)),
      context_routines: context
    }
  end

  @doc """
  Returns the advisory restricted to the routines and modules of the
  package, and the context routines.
  """
  @spec scope(Advisory.t(), [String.t()], %{String.t() => ModuleSummary.t()}) ::
          {Advisory.t(), [MFA.t()]}
  def scope(%Advisory{} = advisory, owners, modules) do
    %{routines: routines, modules: own_modules, context_routines: context} =
      split(advisory, owners, modules)

    {%{advisory | affected_routines: routines, affected_modules: own_modules}, context}
  end

  @doc "`true` when `module` ships with the Erlang/OTP or Elixir installation."
  @spec platform_module?(String.t()) :: boolean()
  def platform_module?(module) when is_binary(module),
    do: MapSet.member?(platform_modules(), module)

  defp own?(module, owners, modules) do
    case Map.fetch(modules, module) do
      {:ok, %ModuleSummary{package: owner}} -> owner in owners
      :error -> not platform_module?(module)
    end
  end

  # Module names are read from file names, so no atoms are created.
  defp platform_modules do
    case :persistent_term.get(@cache_key, nil) do
      nil ->
        set = MapSet.new(otp_modules() ++ elixir_modules())
        :persistent_term.put(@cache_key, set)
        set

      set ->
        set
    end
  end

  defp otp_modules do
    :code.root_dir()
    |> to_string()
    |> Path.join("lib/*/ebin/*.beam")
    |> Path.wildcard()
    |> Enum.map(&Path.basename(&1, ".beam"))
  end

  # Inside an escript the Elixir applications live in the archive, so their
  # loaded specifications complement the installation directories.
  defp elixir_modules do
    Enum.flat_map(@elixir_apps, fn app ->
      listed =
        case :code.lib_dir(app) do
          dir when is_list(dir) ->
            dir
            |> to_string()
            |> Path.join("ebin/*.beam")
            |> Path.wildcard()
            |> Enum.map(&Path.basename(&1, ".beam"))

          {:error, _} ->
            []
        end

      loaded = app |> Application.spec(:modules) |> List.wrap() |> Enum.map(&Atom.to_string/1)
      listed ++ loaded
    end)
  end
end
