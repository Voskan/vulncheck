defmodule VulnCheck.Workspace.AppFile do
  @moduledoc """
  Reader for OTP application resource files (`ebin/<app>.app` and
  `src/<app>.app.src`) built on the atom-safe `VulnCheck.ErlTerm` parser.
  """

  alias VulnCheck.ErlTerm

  defstruct [
    :name,
    :vsn,
    :mod,
    applications: [],
    included_applications: [],
    optional_applications: [],
    modules: [],
    registered: []
  ]

  @type t :: %__MODULE__{
          name: String.t(),
          vsn: String.t() | nil,
          mod: String.t() | nil,
          applications: [String.t()],
          included_applications: [String.t()],
          optional_applications: [String.t()],
          modules: [String.t()],
          registered: [String.t()]
        }

  @doc "Reads and parses an application resource file."
  @spec read(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def read(path) do
    with {:ok, terms} <- ErlTerm.parse_file(path) do
      case terms do
        [{:tuple, [{:atom, "application"}, {:atom, name}, props]} | _] when is_list(props) ->
          {:ok, from_props(name, props)}

        _ ->
          {:error, "#{path}: not an application resource file"}
      end
    end
  end

  @doc """
  Reads `<ebin_dir>/<app>.app`, returning `nil` when it does not exist or is
  unreadable.
  """
  @spec read_ebin(String.t() | nil, String.t()) :: t() | nil
  def read_ebin(nil, _app), do: nil

  def read_ebin(ebin_dir, app) do
    path = Path.join(ebin_dir, app <> ".app")

    case File.regular?(path) && read(path) do
      {:ok, %__MODULE__{name: ^app} = app_file} -> app_file
      _ -> nil
    end
  end

  @doc """
  Finds and reads the single `.app` file of an `ebin` directory.
  """
  @spec find_in_ebin(String.t() | nil) :: t() | nil
  def find_in_ebin(nil), do: nil

  def find_in_ebin(ebin_dir) do
    ebin_dir
    |> Path.join("*.app")
    |> Path.wildcard()
    |> Enum.sort()
    |> Enum.find_value(fn path ->
      case read(path) do
        {:ok, app_file} -> app_file
        _ -> nil
      end
    end)
  end

  defp from_props(name, props) do
    %__MODULE__{
      name: name,
      vsn: string(ErlTerm.proplist_get(props, "vsn")),
      mod: mod(ErlTerm.proplist_get(props, "mod")),
      applications: ErlTerm.atom_names(ErlTerm.proplist_get(props, "applications", [])),
      included_applications:
        ErlTerm.atom_names(ErlTerm.proplist_get(props, "included_applications", [])),
      optional_applications:
        ErlTerm.atom_names(ErlTerm.proplist_get(props, "optional_applications", [])),
      modules: ErlTerm.atom_names(ErlTerm.proplist_get(props, "modules", [])),
      registered: ErlTerm.atom_names(ErlTerm.proplist_get(props, "registered", []))
    }
  end

  defp string(value) when is_binary(value), do: value
  defp string(_), do: nil

  defp mod({:tuple, [{:atom, module}, _args]}), do: module
  defp mod(_), do: nil
end
