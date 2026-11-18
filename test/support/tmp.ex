defmodule VulnCheck.Test.Tmp do
  @moduledoc false

  import ExUnit.Callbacks, only: [on_exit: 1]

  @doc """
  Creates a unique directory inside `System.tmp_dir!/0` that is removed when
  the current test finishes.
  """
  def mkdir!(prefix \\ "vulncheck-test") do
    unique = "#{prefix}-#{System.unique_integer([:positive])}-#{:erlang.phash2(make_ref())}"
    dir = Path.join(System.tmp_dir!(), unique)
    File.rm_rf!(dir)
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  @doc "Writes `content` to `path` relative to `dir`, creating parent directories."
  def write!(dir, path, content) do
    full = Path.join(dir, path)
    File.mkdir_p!(Path.dirname(full))
    File.write!(full, content)
    full
  end
end
