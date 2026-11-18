defmodule VulnCheck.Mix do
  @moduledoc false

  # Exit codes must survive `mix`: a non-zero code stops the VM with that
  # status, so `echo $?` in CI sees exactly 1 or 2.
  @spec run([String.t()]) :: :ok | no_return()
  def run(argv) do
    # reports are UTF-8; under a non-UTF-8 locale standard IO starts in
    # latin1 mode and would escape every non-latin1 character
    :io.setopts(:standard_io, encoding: :unicode)
    :io.setopts(:standard_error, encoding: :unicode)
    argv |> VulnCheck.CLI.run() |> exit_with()
  end

  @spec exit_with(VulnCheck.CLI.exit_code()) :: :ok | no_return()
  def exit_with(0), do: :ok
  def exit_with(code), do: exit({:shutdown, code})
end
