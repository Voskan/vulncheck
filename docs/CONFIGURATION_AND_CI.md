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
| `max_feed_age_seconds` | integer \| `nil` | `nil` | OSV freshness limit. The default is 24 hours online and unlimited in explicit offline mode. |
| `beam_timeout` | positive integer | `15000` | Per-file `.beam` worker timeout in milliseconds. |
| `max_beam_files` | positive integer | `20000` | Maximum number of `.beam` files analyzed in a workspace. |
| `max_beam_bytes` | positive integer | `67108864` | Maximum `.beam` file size in bytes (64 MiB). |
| `max_beam_heap_bytes` | positive integer | `134217728` | Per-worker heap limit in bytes for `.beam` analysis (128 MiB). |
| `configured_adapters` | keyword list | `[]` | Adapter modules per family: `tesla`, `swoosh`, `ecto`, `phoenix_pubsub`, `finch`, `req`. A family may list several modules. |
| `extra_entrypoints` | list of `{Module, :function, arity}` | `[]` | Functions treated as roots in addition to the detected ones. |
| `ignore_file` | string | `".vulncheck.ignore"` | Suppression file, relative to the project. |
| `require_ignore_reason` | boolean | `true` | Suppressions without a `reason` are rejected. |
| `require_ignore_expiry` | boolean | `false` | Suppressions without an `expires` date are rejected. |
| `forbid_new_suppressions` | boolean | `false` | Fail when the ignore file gains or extends suppressions compared with `diff`. |
| `diff` | string \| `nil` | `nil` | Git ref. Keep findings related to changed packages or files and retain active findings whose prior state is unknown. |
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
- A package-specific rule takes precedence over a global rule for the same finding. Conflicting rules at the same scope leave the finding active and report a policy violation.
- A baseline can hide a finding when the earlier observation matches its locked package identity, version, scope and suppression state and had at least its current severity. Prefer refreshing baselines via `--write-baseline` when an older baseline lacks these fields.

---

## CLI Reference

### Mix Tasks

| Command | Description |
| :--- | :--- |
| `mix vulncheck` | Run full dependency & `.beam` reachability audit. |
| `mix vulncheck.init` | Generate `.vulncheck.exs` tailored to the detected project structure. |
| `mix vulncheck.explain <ID>` | Show full CVE details, affected `programRoutines`, fixed versions, and local reachability status. |
| `mix vulncheck.feeds sync` | Revalidate the OSV archive and refresh every referenced CVE record through EEF CNA or MITRE. Exit `2` signals incomplete refresh. |
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
| `--sarif FILE` | Also write a SARIF 2.1.0 report from the same scan. |
| `--sbom FILE` | Also write a CycloneDX 1.6 SBOM. |
| `--vex FILE` | Also write an OpenVEX v0.2.0 document. |
| `--fail-on TIER` | `reachable`, `potentially_reachable` (default), `any` or `none`. |
| `--min-severity SEV` | `low` (default), `medium`, `high` or `critical`. |
| `--[no-]fail-on-retired` | Fail on retired Hex releases (default: on). |
| `--no-retired` | Skip the Hex retirement check. |
| `--show-unreachable` | Detail unreachable advisories. |
| `--diff REF` | Show changes since the Git ref while retaining active findings with no baseline evidence. |
| `--baseline FILE` | Hide findings recorded in a JSON baseline. |
| `--write-baseline FILE` | Record the complete scan as a baseline before display filters. |
| `--forbid-new-suppressions` | Fail when `.vulncheck.ignore` gains or extends suppressions since `--diff`. |
| `--ignore-file FILE` | Suppression file (default: `.vulncheck.ignore`). |
| `--otp-version VER` | OTP release the project runs on (default: the running VM's). |
| `--offline` | Never use the network; use the cache or `--bundle`. |
| `--bundle FILE` | Import an advisory bundle before scanning. |
| `--cache-dir DIR` | Feed and `.beam` summary cache directory. |
| `--cache-ttl SECONDS` | Feed freshness (default: `3600`). |
| `--max-feed-age SECONDS` | Maximum accepted age of the cached OSV archive. Use `0` for live validation on every scan. |
| `--no-color` | Disable ANSI colors (also `NO_COLOR=1`). |
| `-q`, `--quiet` | Hide warnings. |

`mix vulncheck.init` accepts `--project-dir` and `--force` (overwrite an existing file). `mix vulncheck.explain` accepts `--project-dir`, `--offline` and `--bundle`.

`--bundle` selects an isolated offline snapshot for the scan. Absent records remain absent in that snapshot. The live cache remains available to online runs, and subsequent offline scans use the most recently imported snapshot. Bundle import validates the complete manifest, file digests and feed contents before selecting it. The manifest preserves source fetch times, including unknown age in older bundles.

An online scan can use a verified previous OSV archive after a failed refresh if it is within its configured age limit. A cold scan or one past the limit returns exit `2`. The native JSON `feed` object contains the source, status, age, refresh error and discarded record count. `feeds status` reports a missing archive, a validated archive or an invalid archive with exit `2`.

`explain` shows whether the installed version matches the advisory, the local reachability verdict when available, and the effect of suppressions or display filters. A missing or incomplete local scan is reported separately from an unaffected installed version. Unsupported lockfile entries, partially parsed `mix.exs` files, and profile mismatches between `_build/<env>` and `--env` are recorded as warnings and mark `analysis.status` incomplete (`partial`) so unparsed dependencies are never silently dismissed.

### Exit Codes

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Clean — zero findings at or above `--fail-on` and `--min-severity` thresholds. |
| `1` | Policy violation — findings, retired packages, expired or forbidden suppressions, or an invalid ignore policy. Reports are available. |
| `2` | Execution error — invalid flags or configuration, overlapping destinations, missing or unparseable lockfile, or unavailable feeds. |

---

## CI/CD Recipes

### GitHub Actions (composite action)

**Trusted branches (with compilation and SARIF upload):**

```yaml
on:
  push:
    branches: [main]

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
      - uses: Voskan/vulncheck@v1.0.0
        with:
          fail-on: potentially_reachable
          upload-sarif: true
```

**Pull requests (untrusted checkouts):**

By default `compile` is `"true"`, which executes the project's build tools and macros. For untrusted pull requests (such as forks), never grant `security-events: write` or secrets to a job that compiles untrusted code: run without `security-events: write` (or scan prebuilt artifacts with `compile: "false"`), and upload SARIF from a separate `workflow_run` job if needed:

```yaml
on:
  pull_request:

jobs:
  vulncheck:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: erlef/setup-beam@v1
        with:
          otp-version: "27.2"
          elixir-version: "1.18"
      - uses: Voskan/vulncheck@v1.0.0
        with:
          fail-on: potentially_reachable
          diff: origin/${{ github.base_ref }}
          forbid-new-suppressions: true
          upload-sarif: false
```

The action builds the escript, compiles the project (`compile: false` skips this for prepared artifacts), and caches advisory feeds (`~/.cache/vulncheck/feeds`). Annotations, the job summary and optional SARIF come from one scan. A policy failure records exit `1` and uploads available SARIF before enforcing the policy. Execution errors record exit `2` and skip the upload. The action provides `exit-code` and `sarif-file` outputs.

### GitLab CI (Code Quality widget)

```yaml
vulncheck:
  image: hexpm/elixir:1.18.4-erlang-27.3.4.16-alpine-3.22.5
  script:
    - mix local.hex --force --if-missing
    - mix local.rebar --force --if-missing
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

Install the `vulncheck` executable and make it available on `PATH`. The hook runs from the repository root for Mix, rebar3 and Gleam workspaces when `mix.lock`, `rebar.lock`, `manifest.toml` or `.vulncheck.ignore` changes. Use `vulncheck-offline` when the machine has no network access.
