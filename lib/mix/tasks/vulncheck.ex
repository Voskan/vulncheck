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
    * `--sarif FILE` — also write a SARIF 2.1.0 report
    * `--sbom FILE` — also write a CycloneDX 1.6 SBOM
    * `--vex FILE` — also write an OpenVEX v0.2.0 document
    * `--fail-on TIER` — `reachable`, `potentially_reachable` (default),
      `any` or `none`
    * `--min-severity SEV` — `low` (default), `medium`, `high`, `critical`
    * `--[no-]fail-on-retired` — fail on retired Hex releases (default: on)
    * `--no-retired` — skip the Hex retirement check
    * `--show-unreachable` — detail unreachable advisories
    * `--diff REF` — show changes since `REF` and retain active findings without baseline evidence
    * `--baseline FILE` / `--write-baseline FILE` — compare with or record
      a JSON baseline
    * `--forbid-new-suppressions` — fail when `.vulncheck.ignore` gains
      or extends entries compared with the `--diff` base
    * `--ignore-file FILE` — suppression file (default: `.vulncheck.ignore`;
      enforce `require_ignore_reason` and `require_ignore_expiry` in `.vulncheck.exs`)
    * `--otp-version VER` — OTP release the project runs on
    * `--offline` — never use the network
    * `--bundle FILE` — read an advisory bundle for this scan (does not import into cache)
    * `--cache-dir DIR` — feed and `.beam` summary cache directory
    * `--cache-ttl SECONDS` — feed freshness (default: `3600`)
    * `--max-feed-age SECONDS` — maximum accepted age of the cached advisory archive
    * `--no-color`, `--quiet` / `-q`

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
  def run(argv), do: VulnCheck.Mix.run(argv)
end
