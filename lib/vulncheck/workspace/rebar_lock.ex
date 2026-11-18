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

  @lock_entries ~r/%[^\r\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\{\s*<<\s*("(?:\\.|[^"\\])*")\s*>>\s*,\s*\{\s*(?:pkg|git)\s*,/s

  @doc "Parses `rebar.lock` content into `name => Package`."
  @spec parse(String.t(), keyword()) :: {:ok, %{String.t() => Package.t()}} | {:error, String.t()}
  def parse(content, opts \\ []) do
    with {:ok, packages, _warnings} <- parse_with_warnings(content, opts), do: {:ok, packages}
  end

  @doc "Like `parse/2`, also returning warnings for unsupported lock entries."
  @spec parse_with_warnings(String.t(), keyword()) ::
          {:ok, %{String.t() => Package.t()}, [String.t()]} | {:error, String.t()}
  def parse_with_warnings(content, opts \\ []) do
    file = Keyword.get(opts, :file, "rebar.lock")

    with {:ok, terms} <- ErlTerm.parse(content),
         {:ok, entries, extra} <- split_terms(terms) do
      hashes = hash_table(extra, "pkg_hash")
      ext_hashes = hash_table(extra, "pkg_hash_ext")
      lines = name_lines(content)

      {rev_pkgs, rev_warns} =
        Enum.reduce(entries, {[], []}, fn item, {pkgs, warns} ->
          case entry(item) do
            [%Package{} = pkg] ->
              {[pkg | pkgs], warns}

            [] ->
              label =
                case item do
                  {:tuple, [name | _]} when is_binary(name) -> name
                  other -> inspect(other)
                end

              {pkgs,
               ["unsupported entry #{label} in #{file}; dependency could not be parsed" | warns]}
          end
        end)

      packages =
        rev_pkgs
        |> Enum.reverse()
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

      {:ok, packages, Enum.reverse(rev_warns)}
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
    with {:ok, packages, _warnings} <- parse_file_with_warnings(path), do: {:ok, packages}
  end

  @doc "Reads and parses a `rebar.lock` file, also returning unsupported-entry warnings."
  @spec parse_file_with_warnings(Path.t()) ::
          {:ok, %{String.t() => Package.t()}, [String.t()]} | {:error, String.t()}
  def parse_file_with_warnings(path) do
    case File.read(path) do
      {:ok, content} ->
        case parse_with_warnings(content, file: path) do
          {:ok, packages, warnings} -> {:ok, packages, warnings}
          {:error, message} -> {:error, "#{path}: #{message}"}
        end

      {:error, reason} ->
        {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  defp entry({:tuple, [name, source, level]}) when is_binary(name) do
    lock_level = if is_integer(level) and level >= 0, do: level, else: nil

    case source do
      {:tuple, [{:atom, "pkg"}, hex_name, version | _]} when is_binary(version) ->
        [
          %Package{
            name: name,
            hex_name: if(is_binary(hex_name), do: hex_name, else: name),
            version: version,
            source: :hex,
            scope: :prod,
            otp_app: name,
            lock_level: lock_level
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
            otp_app: name,
            lock_level: lock_level
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
    @lock_entries
    |> Regex.scan(content, return: :index)
    |> Enum.reduce({%{}, 0, 1}, fn
      [_, {offset, length}], {locations, last_offset, line} when offset >= 0 ->
        prefix = binary_part(content, last_offset, offset - last_offset)
        line = line + length(:binary.matches(prefix, "\n"))
        literal = binary_part(content, offset, length)

        locations =
          case ErlTerm.parse(literal <> ".") do
            {:ok, [name]} -> Map.put_new(locations, name, line)
            _ -> locations
          end

        {locations, offset, line}

      _, acc ->
        acc
    end)
    |> elem(0)
  end
end
