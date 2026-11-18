defmodule VulnCheck do
  @moduledoc """
  Function-level reachability vulnerability scanner for Elixir, Erlang and Gleam.

  VulnCheck matches locked dependencies against OSV.dev and EEF CNA CVE 5.1
  advisories, then proves — on compiled `.beam` call graphs enriched with OTP
  supervision roots, framework callbacks and runtime adapter configuration —
  whether the vulnerable functions can actually execute in production.
  """

  @version Mix.Project.config()[:version]

  @doc "Returns the VulnCheck version."
  @spec version() :: String.t()
  def version, do: @version
end
