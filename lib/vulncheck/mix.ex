defmodule VulnCheck.Mix do
  @moduledoc false

  # Exit codes must survive `mix`: a non-zero code stops the VM with that
  # status, so `echo $?` in CI sees exactly 1 or 2.
  @spec exit_with(VulnCheck.CLI.exit_code()) :: :ok | no_return()
  def exit_with(0), do: :ok
  def exit_with(code), do: exit({:shutdown, code})
end
