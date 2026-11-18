defmodule VulnCheck.Workspace.MixLock do
  @moduledoc """
  Atom-safe parser for `mix.lock`.

  The lockfile is read with `VulnCheck.Literal` (never evaluated) and every
  supported entry format is normalized into a `VulnCheck.Types.Package`:

    * Hex 8-tuples: `{:hex, :pkg, "1.2.3", inner, managers, deps, "hexpm", outer}`
    * legacy Hex 7-, 6-, 5- and 4-tuples
    * Git dependencies: `{:git, url, sha, opts}`

  Optional sub-dependencies are only linked when the optional package itself
  is present in the lockfile, matching how Mix resolves them.
  """

  alias VulnCheck.Literal
  alias VulnCheck.Types.Package

  @doc """
  Parses `mix.lock` content into a map of `app_name => Package` (scope `:prod`
  until the workspace loader computes the real closure).
  """
  @spec parse(String.t(), keyword()) :: {:ok, %{String.t() => Package.t()}} | {:error, String.t()}
  def parse(content, opts \\ []) do
    file = Keyword.get(opts, :file, "mix.lock")

    case Literal.parse(content, file: file) do
      {:ok, {:map, entries}} ->
        lines = key_lines(content)

        packages =
          entries
          |> Enum.flat_map(fn {key, value} -> entry(key, value) end)
          |> Map.new(fn package -> {package.name, package} end)

        names = Map.keys(packages)

        packages =
          Map.new(packages, fn {name, package} ->
            present_optional = Enum.filter(package.optional_deps, &(&1 in names))

            {name,
             %{
               package
               | deps: Enum.uniq(package.deps ++ present_optional),
                 lock_line: Map.get(lines, name)
             }}
          end)

        {:ok, packages}

      {:ok, _other} ->
        {:error, "#{file}: expected a map of locked dependencies"}

      {:error, {:unsafe_expression, line, code}} ->
        {:error, "#{file}:#{line}: unexpected expression in lockfile: #{code}"}

      {:error, message} when is_binary(message) ->
        {:error, message}
    end
  end

  @doc "Reads and parses a `mix.lock` file."
  @spec parse_file(Path.t()) :: {:ok, %{String.t() => Package.t()}} | {:error, String.t()}
  def parse_file(path) do
    case File.read(path) do
      {:ok, content} -> parse(content, file: path)
      {:error, reason} -> {:error, "#{path}: #{:file.format_error(reason)}"}
    end
  end

  defp entry({:atom, app}, {:tuple, [{:atom, "hex"}, {:atom, hex_name}, version | rest]})
       when is_binary(version) do
    {inner, managers_deps} =
      case rest do
        [inner | tail] when is_binary(inner) -> {inner, tail}
        tail -> {nil, tail}
      end

    deps_list =
      case managers_deps do
        [_managers, deps | _] when is_list(deps) -> deps
        _ -> []
      end

    outer =
      case managers_deps do
        [_managers, _deps, _repo, outer | _] when is_binary(outer) -> outer
        _ -> nil
      end

    {required, optional} = split_deps(deps_list)

    [
      %Package{
        name: app,
        hex_name: hex_name,
        version: version,
        source: :hex,
        scope: :prod,
        checksum: outer,
        inner_checksum: inner,
        otp_app: app,
        deps: required,
        optional_deps: optional
      }
    ]
  end

  defp entry({:atom, app}, {:tuple, [{:atom, "git"}, url, ref | rest]})
       when is_binary(url) and is_binary(ref) do
    opts = List.first(rest) || []

    [
      %Package{
        name: app,
        version: git_version(opts, ref),
        source: :git,
        scope: :prod,
        git_ref: ref,
        git_url: url,
        otp_app: app
      }
    ]
  end

  defp entry(_key, _value), do: []

  defp git_version(opts, ref) do
    case Literal.kw_get(opts, "tag") do
      tag when is_binary(tag) -> String.trim_leading(tag, "v")
      _ -> String.slice(ref, 0, 12)
    end
  end

  defp split_deps(deps) do
    Enum.reduce(deps, {[], []}, fn
      {:tuple, [{:atom, name}, _requirement, opts]}, {req, opt} ->
        if Literal.kw_get(opts, "optional") == true do
          {req, [name | opt]}
        else
          {[name | req], opt}
        end

      {:tuple, [{:atom, name} | _]}, {req, opt} ->
        {[name | req], opt}

      _other, acc ->
        acc
    end)
    |> then(fn {req, opt} -> {Enum.reverse(req), Enum.reverse(opt)} end)
  end

  defp key_lines(content) do
    content
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce(%{}, fn {line, number}, acc ->
      case Regex.run(~r/\A\s*"?([a-z0-9_]+)"?:\s*\{/, line) do
        [_, name] -> Map.put_new(acc, name, number)
        _ -> acc
      end
    end)
  end
end
