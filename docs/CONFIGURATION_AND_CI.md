# Configuration, Suppressions & CI/CD Guide

`vulncheck` works out of the box with zero configuration files. For team-wide policy enforcement, create a `.vulncheck.exs` file in the repository root via `mix vulncheck.init`.

---

## `.vulncheck.exs` Configuration Schema

`.vulncheck.exs` is read as literal data: it must be a keyword list of plain values (atoms, strings, numbers, booleans, module aliases, lists and tuples). Nothing in it is evaluated, unknown keys are rejected, and command-line flags override file values.

```elixir
[
  # Mix environment whose dependency closure and _build/<env> artifacts are analyzed
  env: :prod,

  # Verdict tier that fails the run (exit code 1)
  fail_on: :potentially_reachable,

  # Minimum advisory severity that fails the run
  min_severity: :low,

  # Retired Hex releases fail the run
  fail_on_retired: true,

  # Runtime adapters configured outside of compiled code
  configured_adapters: [
    tesla: Tesla.Adapter.Mint
  ],

  # Additional roots, e.g. functions called through release eval or RPC
  extra_entrypoints: [
    {MyApp.Release, :migrate, 0}
  ],

  # Suppression governance
  ignore_file: ".vulncheck.ignore",
  require_ignore_reason: true,
  require_ignore_expiry: false
]
```

| Key | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `env` | `:prod` \| `:dev` \| `:test` | `:prod` | Environment whose dependency closure and build directory are analyzed. |
| `format` | atom | `:terminal` | `:terminal`, `:json`, `:markdown`, `:sarif`, `:github`, `:gitlab`, `:cyclonedx` or `:openvex`. |
| `output` | string \| `nil` | `nil` | Write the report to this file instead of standard output. |
| `sbom` | string \| `nil` | `nil` | Also write a CycloneDX 1.6 SBOM to this file. |
| `vex` | string \| `nil` | `nil` | Also write an OpenVEX v0.2.0 document to this file. |
| `fail_on` | atom | `:potentially_reachable` | `:reachable`, `:potentially_reachable`, `:any` (also unreachable) or `:none`. |
| `min_severity` | atom | `:low` | `:low`, `:medium`, `:high` or `:critical`; findings below it never fail the run. Severity `none` (CVSS 0.0) counts as `low`, and `unknown` (no CVSS data) as `critical`. |
| `fail_on_retired` | boolean | `true` | Retired Hex releases fail the run. |
| `check_retired` | boolean | `true` | Query Hex.pm for retired releases at all. |
| `show_unreachable` | boolean | `false` | Detail unreachable advisories in terminal and Markdown output. |
| `otp_version` | string \| integer \| `nil` | running OTP | OTP release the project is deployed on, for OTP-gated advisories. |
| `offline` | boolean | `false` | Never use the network; use the cache or a bundle. |
| `bundle` | string \| `nil` | `nil` | Advisory bundle imported before the scan. |
| `configured_adapters` | keyword list | `[]` | Adapter modules per family: `tesla`, `swoosh`, `ecto`, `phoenix_pubsub`, `finch`, `req`. A family may list several modules. |
| `extra_entrypoints` | list of `{Module, :function, arity}` | `[]` | Functions treated as roots in addition to the detected ones. |
| `ignore_file` | string | `".vulncheck.ignore"` | Suppression file, relative to the project. |
| `require_ignore_reason` | boolean | `true` | Suppressions without a `reason` are rejected. |
| `require_ignore_expiry` | boolean | `false` | Suppressions without an `expires` date are rejected. |
| `forbid_new_suppressions` | boolean | `false` | Fail when the ignore file gains or extends suppressions compared with `diff`. |
| `diff` | string \| `nil` | `nil` | Git ref; only findings related to dependencies changed since it are reported. |
| `baseline` | string \| `nil` | `nil` | JSON baseline whose findings are hidden. |
| `cache_dir` | string \| `nil` | `$XDG_CACHE_HOME/vulncheck` or `~/.cache/vulncheck` | Feed and `.beam` summary cache. |
| `cache_ttl_seconds` | non-negative integer | `3600` | Age after which cached feeds are refreshed. |

`mix vulncheck.init` writes a commented file with these keys and adds hints for the frameworks and adapters it detects in the lockfile.

---

## Governed Suppressions (`.vulncheck.ignore`)

Security teams need auditable, time-bounded exceptions rather than permanent silent ignores. `.vulncheck.ignore` is a literal list of maps. Each entry needs an advisory `id` (the advisory ID or any alias such as a CVE ID), a `reason` (required unless `require_ignore_reason: false`), and optionally a `package` to narrow the match and an ISO-8601 `expires` date (required when `require_ignore_expiry: true`):

```elixir
[
  %{
    id: "CVE-2026-54892",
    package: "plug",
    reason: "WAF blocks nested query depth > 4 at Cloudflare edge; upgrade scheduled in Sprint 48",
    expires: "2027-01-31"
  }
]
```

- **Expired Suppressions Fail Loudly:** Once `Date.utc_today()` passes `expires`, the suppression becomes inactive and `vulncheck` reports an expired-exception warning alongside the finding.
- **Stale Entries Are Reported:** A suppression that no longer matches any finding produces a warning, so the file does not accumulate dead exceptions.
- **Anti-Cheat PR Guardrail (`--forbid-new-suppressions`):** Together with `--diff <ref>`, compares `.vulncheck.ignore` with its version at the base ref (e.g., `origin/main`) and fails with exit code `1` when a change adds a suppression or moves an existing expiry date later.

---

## CLI Reference

### Mix Tasks

| Command | Description |
| :--- | :--- |
| `mix vulncheck` | Run full dependency & `.beam` reachability audit. |
| `mix vulncheck.init` | Generate `.vulncheck.exs` tailored to the detected project structure. |
| `mix vulncheck.explain <ID>` | Show full CVE details, affected `programRoutines`, fixed versions, and local reachability status. |
| `mix vulncheck.feeds sync` | Force-refresh cached OSV and EEF CNA feeds. |
| `mix vulncheck.feeds status` | Print local cache location, ETag timestamps, and advisory counts. |
| `mix vulncheck.feeds bundle -o <path>` | Export self-contained `.tar.gz` advisory bundle for air-gapped CI runners. |

### Flags (`mix vulncheck` and the `vulncheck` escript)

| Flag | Meaning |
| :--- | :--- |
| `--project-dir DIR` | Project to scan (default: current directory). |
| `--config FILE` | Configuration file (default: `DIR/.vulncheck.exs`). |
| `--env ENV` | `prod` (default), `dev` or `test`. |
| `-f`, `--format FMT` | `terminal` (default), `json`, `markdown`, `sarif`, `github`, `gitlab`, `cyclonedx` or `openvex`. |
| `-o`, `--output FILE` | Write the report to a file instead of standard output. |
| `--sbom FILE` | Also write a CycloneDX 1.6 SBOM. |
| `--vex FILE` | Also write an OpenVEX v0.2.0 document. |
| `--fail-on TIER` | `reachable`, `potentially_reachable` (default), `any` or `none`. |
| `--min-severity SEV` | `low` (default), `medium`, `high` or `critical`. |
| `--[no-]fail-on-retired` | Fail on retired Hex releases (default: on). |
| `--no-retired` | Skip the Hex retirement check. |
| `--show-unreachable` | Detail unreachable advisories. |
| `--diff REF` | Only report findings related to dependencies changed since the Git ref. |
| `--baseline FILE` | Hide findings recorded in a JSON baseline. |
| `--write-baseline FILE` | Record the current findings as a baseline. |
| `--forbid-new-suppressions` | Fail when `.vulncheck.ignore` gains or extends suppressions since `--diff`. |
| `--ignore-file FILE` | Suppression file (default: `.vulncheck.ignore`). |
| `--otp-version VER` | OTP release the project runs on (default: the running VM's). |
| `--offline` | Never use the network; use the cache or `--bundle`. |
| `--bundle FILE` | Import an advisory bundle before scanning. |
| `--cache-dir DIR` | Feed and `.beam` summary cache directory. |
| `--cache-ttl SECONDS` | Feed freshness (default: `3600`). |
| `--no-color` | Disable ANSI colors (also `NO_COLOR=1`). |
| `-q`, `--quiet` | Hide warnings. |

`mix vulncheck.init` accepts `--project-dir` and `--force` (overwrite an existing file). `mix vulncheck.explain` accepts `--project-dir`, `--offline` and `--bundle`.

### Exit Codes

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Clean — zero findings at or above `--fail-on` and `--min-severity` thresholds. |
| `1` | Policy violation — actionable vulnerabilities, retired packages, or forbidden suppressions found. |
| `2` | Execution error — invalid flags or configuration, missing or unparseable lockfile, invalid ignore file, unreachable feeds without a cache, or an offline run without cached feeds. |

---

## CI/CD Recipes

### GitHub Actions (composite action)

```yaml
jobs:
  vulncheck:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # needed for diff
      - uses: erlef/setup-beam@v1
        with:
          otp-version: "27.2"
          elixir-version: "1.18"
      - uses: Voskan/vulncheck@v1
        with:
          fail-on: potentially_reachable
          diff: origin/${{ github.base_ref }}
          forbid-new-suppressions: true
          upload-sarif: true
```

The action builds the escript, compiles the project (`compile: false` skips this when an earlier step already built `_build/<env>`), caches advisory feeds between runs, writes annotations and a step summary, and fails the job with the scan's exit code. Its `exit-code` and `sarif-file` outputs are available to later steps.

### GitLab CI (Code Quality widget)

```yaml
vulncheck:
  image: hexpm/elixir:1.18.4-erlang-27.3.4.16-alpine-3.22.5
  script:
    - mix deps.get
    - MIX_ENV=prod mix compile
    - mix escript.install hex vulncheck --force
    - ~/.mix/escripts/vulncheck --format gitlab --output gl-code-quality-report.json
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

### Container image

```bash
docker build -t vulncheck https://github.com/Voskan/vulncheck.git
docker run --rm -v "$PWD:/workspace" vulncheck --format sarif --output vulncheck.sarif
```

The image runs the escript as an unprivileged user on an Erlang runtime with `git` (for `--diff`) and CA certificates. Compile the project first so `_build` is present in the mounted workspace; without it, findings fall back to package-level verdicts.

### pre-commit

```yaml
repos:
  - repo: https://github.com/Voskan/vulncheck
    rev: v1.0.0
    hooks:
      - id: vulncheck
```

The hook runs when `mix.lock`, `rebar.lock`, `manifest.toml` or `.vulncheck.ignore` change; use `vulncheck-offline` on machines without network access.
