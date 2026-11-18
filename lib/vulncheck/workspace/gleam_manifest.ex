defmodule VulnCheck.Workspace.GleamManifest do
  @moduledoc """
  Parser for Gleam projects: `gleam.toml` (direct `[dependencies]` and
  `[dev-dependencies]`) and `manifest.toml` (the resolved package set, either
  as an inline `packages = [...]` array or as `[[packages]]` tables).
  """

  alias VulnCheck.Types.Package
  alias VulnCheck.Workspace.Toml

  defstruct name: nil, version: nil, dependencies: [], dev_dependencies: []

  @type project :: %__MODULE__{
          name: String.t() | nil,
          version: String.t() | nil,
          dependencies: [String.t()],
          dev_dependencies: [String.t()]
        }

  @doc "Parses `gleam.toml` content."
  @spec parse_project(String.t()) :: {:ok, project()} | {:error, String.t()}
  def parse_project(content) do
    with {:ok, doc} <- Toml.parse(content) do
      {:ok,
       %__MODULE__{
         name: string(doc["name"]),
         version: string(doc["version"]),
         dependencies: table_keys(doc["dependencies"]),
         dev_dependencies: table_keys(doc["dev-dependencies"] || doc["dev_dependencies"])
       }}
    end
  end

  @doc "Parses `manifest.toml` content into `name => Package` (scope `:prod`)."
  @spec parse_manifest(String.t()) :: {:ok, %{String.t() => Package.t()}} | {:error, String.t()}
  def parse_manifest(content) do
    with {:ok, doc} <- Toml.parse(content) do
      lines = name_lines(content)

      packages =
        doc
        |> Map.get("packages", [])
        |> List.wrap()
        |> Enum.flat_map(&package(&1, lines))
        |> Map.new(&{&1.name, &1})

      {:ok, packages}
    end
  end

  defp package(%{"name" => name, "version" => version} = entry, lines)
       when is_binary(name) and is_binary(version) do
    source =
      case entry["source"] do
        "hex" -> :hex
        "git" -> :git
        "local" -> :path
        _ -> :hex
      end

    [
      %Package{
        name: name,
        hex_name: name,
        version: version,
        source: source,
        scope: :prod,
        checksum: entry |> Map.get("outer_checksum") |> downcase(),
        otp_app: string(entry["otp_app"]) || name,
        deps: entry |> Map.get("requirements", []) |> List.wrap() |> Enum.filter(&is_binary/1),
        git_url: string(entry["repo"]),
        git_ref: string(entry["commit"]),
        lock_line: Map.get(lines, name)
      }
    ]
  end

  defp package(_entry, _lines), do: []

  defp table_keys(map) when is_map(map), do: map |> Map.keys() |> Enum.sort()
  defp table_keys(_), do: []

  defp string(value) when is_binary(value), do: value
  defp string(_), do: nil

  defp downcase(value) when is_binary(value), do: String.downcase(value)
  defp downcase(_), do: nil

  defp name_lines(content) do
    content
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce(%{}, fn {line, number}, acc ->
      case Regex.run(~r/name\s*=\s*"([^"]+)"/, line) do
        [_, name] -> Map.put_new(acc, name, number)
        _ -> acc
      end
    end)
  end
end
