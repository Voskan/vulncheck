defmodule Mix.Tasks.Vulncheck.Init do
  @shortdoc "Generates a .vulncheck.exs configuration"

  @moduledoc """
  Writes a commented `.vulncheck.exs` tailored to the project: detected
  frameworks, adapters configured in `config/*.exs` and release entrypoints.

      mix vulncheck.init
      mix vulncheck.init --force

  An existing file is kept unless `--force` is given.
  """

  use Mix.Task

  @impl Mix.Task
  def run(argv), do: VulnCheck.Mix.exit_with(VulnCheck.CLI.run(["init" | argv]))
end
