defmodule VulnCheck.Git do
  @moduledoc """
  Minimal read-only access to the project's Git repository through the
  `git` executable.
  """

  @doc "Returns `true` when `ref` resolves to a commit."
  @spec ref?(String.t(), String.t()) :: boolean()
  def ref?(root, ref) do
    match?({:ok, _}, run(root, ["rev-parse", "--verify", "--quiet", ref <> "^{commit}"]))
  end

  @doc """
  Reads `path` (relative to `root`) as it was at `ref`. Returns
  `{:error, :not_found}` when the file did not exist there.
  """
  @spec show(String.t(), String.t(), String.t()) :: {:ok, binary()} | {:error, term()}
  def show(root, ref, path) do
    with :ok <- check_ref(root, ref) do
      case run(root, ["show", "#{ref}:./#{path}"]) do
        {:ok, content} -> {:ok, content}
        {:error, {_status, _output}} -> {:error, :not_found}
        error -> error
      end
    end
  end

  @doc """
  Files changed between `ref` and the working tree (including untracked
  files), relative to `root`.
  """
  @spec changed_files(String.t(), String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def changed_files(root, ref) do
    with :ok <- check_ref(root, ref),
         {:ok, prefix} <- run(root, ["rev-parse", "--show-prefix"]),
         {:ok, diff} <- run(root, ["diff", "--name-only", "-z", ref, "--", "."]),
         {:ok, untracked} <-
           run(root, ["ls-files", "--others", "--exclude-standard", "-z", "--", "."]) do
      prefix = String.trim_trailing(prefix, "\n")

      files =
        (paths(diff) |> Enum.map(&String.replace_prefix(&1, prefix, ""))) ++ paths(untracked)

      {:ok, files |> Enum.uniq() |> Enum.sort()}
    end
  end

  @doc """
  Picks the comparison base: the given ref, otherwise `origin/main` or
  `HEAD~1`, whichever exists first.
  """
  @spec default_base(String.t(), String.t() | nil) :: {:ok, String.t()} | {:error, term()}
  def default_base(root, nil) do
    case Enum.find(["origin/main", "HEAD~1"], &ref?(root, &1)) do
      nil -> {:error, :no_base_ref}
      ref -> {:ok, ref}
    end
  end

  def default_base(_root, ref), do: {:ok, ref}

  defp check_ref(root, ref) do
    cond do
      String.starts_with?(ref, "-") -> {:error, {:invalid_ref, ref}}
      ref?(root, ref) -> :ok
      true -> {:error, {:unknown_ref, ref}}
    end
  end

  defp run(root, args) do
    case System.find_executable("git") do
      nil ->
        {:error, :git_not_found}

      git ->
        case System.cmd(git, args, cd: root, stderr_to_stdout: true) do
          {output, 0} -> {:ok, output}
          {output, status} -> {:error, {status, String.trim(output)}}
        end
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp paths(output), do: :binary.split(output, <<0>>, [:global, :trim_all])
end
