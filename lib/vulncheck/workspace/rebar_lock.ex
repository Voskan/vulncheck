defmodule VulnCheck.Workspace.RebarLock do
  @moduledoc """
  Parser for rebar3 `rebar.lock` files (both the legacy bare list format and
  the versioned `{"1.2.0", [...]}.` format with `pkg_hash` / `pkg_hash_ext`
  checksum sections).

  rebar3 only locks the default profile, so every locked package belongs to
  the production closure.
  """

  alias VulnCheck.ErlTerm
  alias VulnCheck.Types.Package

  @doc "Parses `rebar.lock` content into `name => Package`."
  @spec parse(String.t()) :: {:ok, %{String.t() => Package.t()}} | {:error, String.t()}
  def parse(content) do
    with {:ok, terms} <- ErlTerm.parse(content),
         {:ok, entries, extra} <- split_terms(terms) do
      hashes = hash_table(extra, "pkg_hash")
      ext_hashes = hash_table(extra, "pkg_hash_ext")
      lines = name_lines(content)

      packages =
        entries
        |> Enum.flat_map(&entry/1)
        |> Map.new(fn package ->
          checksum = Map.get(ext_hashes, package.name) || Map.get(hashes, package.name)

          {package.name,
           %{
             package
             | checksum: checksum,
               inner_checksum: Map.get(hashes, package.name),
               lock_line: Map.get(lines, package.name)
           }}
        end)

      {:ok, packages}
    end
  end

  defp split_terms([{:tuple, [version, entries]} | rest])
       when is_binary(version) and is_list(entries),
       do: {:ok, entries, List.first(rest) || []}

  defp split_terms([entries | _]) when is_list(entries), do: {:ok, entries, []}
  defp split_terms([]), do: {:ok, [], []}
  defp split_terms(_), do: {:error, "unsupported rebar.lock format"}

  @doc "Reads and parses a `rebar.lock` file."
  @spec parse_file(Path.t()) :: {:ok, %{String.t() => Package.t()}} | {:error, String.t()}
  def parse_file(path) do
    case File.read(path) do
      {:ok, content} ->
        case parse(content) do
          {:ok, packages} -> {:ok, packages}
          {:error, message} -> {:error, "#{path}: #{message}"}
        end

      {:error, reason} ->
        {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  defp entry({:tuple, [name, source, _level]}) when is_binary(name) do
    case source do
      {:tuple, [{:atom, "pkg"}, hex_name, version | _]} when is_binary(version) ->
        [
          %Package{
            name: name,
            hex_name: if(is_binary(hex_name), do: hex_name, else: name),
            version: version,
            source: :hex,
            scope: :prod,
            otp_app: name
          }
        ]

      {:tuple, [{:atom, "git"}, url, ref]} when is_binary(url) ->
        sha = git_ref(ref)

        [
          %Package{
            name: name,
            version: String.slice(sha || "0.0.0", 0, 12),
            source: :git,
            scope: :prod,
            git_url: url,
            git_ref: sha,
            otp_app: name
          }
        ]

      _ ->
        []
    end
  end

  defp entry(_), do: []

  defp git_ref({:tuple, [{:atom, kind}, value]})
       when kind in ["ref", "tag", "branch"] and is_binary(value),
       do: value

  defp git_ref(_), do: nil

  defp hash_table(extra, key) do
    extra
    |> ErlTerm.proplist_get(key, [])
    |> Enum.flat_map(fn
      {:tuple, [name, hash]} when is_binary(name) and is_binary(hash) ->
        [{name, String.downcase(hash)}]

      _ ->
        []
    end)
    |> Map.new()
  end

  defp name_lines(content) do
    content
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce(%{}, fn {line, number}, acc ->
      case Regex.run(~r/\{<<"([^"]+)">>\s*,\s*\{(pkg|git)/, line) do
        [_, name, _] -> Map.put_new(acc, name, number)
        _ -> acc
      end
    end)
  end
end
