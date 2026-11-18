defmodule Mix.Tasks.Vulncheck.Explain do
  @shortdoc "Describes an advisory and its reachability in the project"

  @moduledoc """
  Prints an advisory (`CVE-...`, `EEF-CVE-...` or `GHSA-...`): summary, CVSS,
  CWE, references, affected and fixed versions and function-level routines.
  When the project locks the affected package, the installed version, the
  reachability verdict and the call trace are shown as well.

      mix vulncheck.explain CVE-2026-101028
      mix vulncheck.explain GHSA-xj24-8f5c-pp5p --offline

  Accepts the scan flags of `mix vulncheck` (`--project-dir`, `--env`,
  `--offline`, `--bundle`, ...).
  """

  use Mix.Task

  @requirements ["app.config"]

  @impl Mix.Task
  def run(argv), do: VulnCheck.Mix.run(["explain" | argv])
end
