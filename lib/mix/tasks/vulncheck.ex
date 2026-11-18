defmodule Mix.Tasks.Vulncheck do
  @shortdoc "Audits dependencies for reachable vulnerabilities"

  @moduledoc """
  Audits the locked dependencies of the current project against OSV.dev and
  EEF CNA advisories and proves, on the compiled `.beam` call graph, whether
  each vulnerable function can run in production.

      mix vulncheck
      mix vulncheck --fail-on reachable --format sarif --output vulncheck.sarif
      mix vulncheck --diff origin/main --forbid-new-suppressions
      mix vulncheck --sbom sbom.cdx.json --vex vex.openvex.json

  Function-level analysis reads `_build/<env>/lib`; compile the target
  environment first (`MIX_ENV=prod mix compile`). Without a build only
  package-level verdicts are possible.

  ## Options

    * `--project-dir DIR` — project to scan (default: current directory)
    * `--config FILE` — configuration file (default: `.vulncheck.exs`)
    * `--env ENV` — `prod` (default), `dev` or `test`
    * `--format FMT` / `-f` — `terminal`, `json`, `markdown`, `sarif`,
      `github`, `gitlab`, `cyclonedx` or `openvex`
    * `--output FILE` / `-o` — write the report to a file
    * `--sbom FILE` — also write a CycloneDX 1.6 SBOM
    * `--vex FILE` — also write an OpenVEX v0.2.0 document
    * `--fail-on TIER` — `reachable`, `potentially_reachable` (default),
      `any` or `none`
    * `--min-severity SEV` — `low` (default), `medium`, `high`, `critical`
    * `--show-unreachable` — detail unreachable advisories
    * `--diff REF` — only report findings related to changes since `REF`
    * `--baseline FILE` / `--write-baseline FILE` — compare with or record
      a JSON baseline
    * `--forbid-new-suppressions` — fail when `.vulncheck.ignore` gains
      entries compared with the `--diff` base
    * `--otp-version VER` — OTP release the project runs on
    * `--offline` / `--bundle FILE` — air-gapped operation
    * `--no-color`, `--quiet`

  ## Exit codes

    * `0` — no finding at or above the thresholds
    * `1` — policy violation: actionable findings, retired releases,
      expired or forbidden suppressions
    * `2` — execution error: invalid flags or configuration, missing
      lockfile, feed unavailable offline
  """

  use Mix.Task

  @requirements ["app.config"]

  @impl Mix.Task
  def run(argv) do
    warn_missing_build(argv)
    VulnCheck.Mix.run(argv)
  end

  defp warn_missing_build(argv) do
    {opts, _args, _invalid} =
      OptionParser.parse(argv, switches: [project_dir: :string, env: :string])

    dir = Path.expand(Keyword.get(opts, :project_dir, "."))
    env = Keyword.get(opts, :env, "prod")

    if File.regular?(Path.join(dir, "mix.exs")) and
         not File.dir?(Path.join(dir, "_build/#{env}/lib")) do
      Mix.shell().info([
        :yellow,
        "warning: ",
        :reset,
        "no _build/#{env} found; run `MIX_ENV=#{env} mix compile` for function-level reachability"
      ])
    end
  end
end
