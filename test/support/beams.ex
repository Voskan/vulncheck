defmodule VulnCheck.Test.Beams do
  @moduledoc false
  # Compiles fixture sources into an ebin directory the way `mix compile`
  # does for a release build (with debug info) and writes `.app` files.

  def compile!(ebin, sources) when is_map(sources) or is_list(sources) do
    File.mkdir_p!(ebin)
    root = ebin |> Path.join("../src") |> Path.expand()
    File.mkdir_p!(root)

    files =
      for {name, source} <- sources do
        path = Path.join(root, name)
        File.write!(path, source)
        path
      end

    compile_files!(files, ebin)
  end

  # Compiler options are global, so concurrent test modules take turns.
  def compile_files!(files, ebin) do
    :global.trans({__MODULE__, :compile}, fn ->
      previous = Code.get_compiler_option(:debug_info)
      previous_ignore = Code.get_compiler_option(:ignore_module_conflict)
      Code.put_compiler_option(:debug_info, true)
      Code.put_compiler_option(:ignore_module_conflict, true)

      try do
        {:ok, modules, _} =
          Kernel.ParallelCompiler.compile_to_path(files, ebin, return_diagnostics: true)

        modules
      after
        Code.put_compiler_option(:debug_info, previous)
        Code.put_compiler_option(:ignore_module_conflict, previous_ignore)
      end
    end)
  end

  def write_app!(ebin, app, opts \\ []) do
    File.mkdir_p!(ebin)
    apps = Keyword.get(opts, :applications, [])
    optional = Keyword.get(opts, :optional_applications, [])
    included = Keyword.get(opts, :included_applications, [])

    mod =
      case Keyword.get(opts, :mod) do
        nil -> ""
        mod -> ",\n  {mod, {'#{mod}', []}}"
      end

    File.write!(Path.join(ebin, "#{app}.app"), """
    {application, #{app},
     [{description, "#{app}"},
      {vsn, "1.0.0"},
      {modules, []},
      {applications, [#{Enum.join(apps, ",")}]},
      {optional_applications, [#{Enum.join(optional, ",")}]},
      {included_applications, [#{Enum.join(included, ",")}]}#{mod}]}.
    """)
  end
end
