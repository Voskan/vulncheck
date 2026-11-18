# Configuration, Suppressions & CI/CD Guide

`vulncheck` works out of the box with zero configuration files. For team-wide policy enforcement, create a `.vulncheck.exs` file in the repository root via `mix vulncheck.init`.

---

## `.vulncheck.exs` Configuration Schema

`.vulncheck.exs` is parsed as a declarative keyword list (validated strictly without executing arbitrary expressions):

```elixir
[
  # Target Mix environment whose compiled _build/<env> artifacts are inspected
  env: :prod,

  # Minimum reachability tier that causes a non-zero exit code (1):
  # :reachable | :potentially_reachable | :any
  fail_on: :potentially_reachable,

  # Minimum CVSS / advisory severity to fail on:
  # :low | :medium | :high | :critical
  min_severity: :low,

  # Whether retired Hex packages fail the check
  fail_on_retired: true,

  # Explicit runtime adapter hints (supplements automatic config/bytecode detection)
  configured_adapters: [
    tesla: Tesla.Adapter.Mint
  ],

  # Additional MFA entrypoints (e.g., functions invoked via external RPC or release eval tasks)
  extra_entrypoints: [
    {MyApp.ReleaseTasks, :migrate, 0}
  ],

  # Ignore file path and suppression governance
  ignore_file: ".vulncheck.ignore",
  require_ignore_reason: true,
  require_ignore_expiry: true,

  # Feed cache settings
  cache_dir: nil,
  cache_ttl_seconds: 3600
]
```

---

## Governed Suppressions (`.vulncheck.ignore`)

Security teams need auditable, time-bounded exceptions rather than permanent silent ignores. Each entry in `.vulncheck.ignore` requires an advisory ID, a justification, and an optional ISO-8601 expiration date:

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
- **Anti-Cheat PR Guardrail (`--forbid-new-suppressions`):** In pull request pipelines, passing `--forbid-new-suppressions` compares `.vulncheck.ignore` against the base Git ref (e.g., `origin/main`) and fails with exit code `1` if a PR attempts to add new ignore entries without security sign-off.

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

### Key Flags (`mix vulncheck` & `vulncheck` escript)

- `--format <fmt>` — `terminal` (default), `json`, `markdown`, `sarif`, `github`, `gitlab`
- `--output <file>` — Write primary report to file instead of `stdout`
- `--sbom <file>` — Emit CycloneDX 1.6 JSON SBOM alongside scan
- `--vex <file>` — Emit OpenVEX v0.2.0 reachability attestations alongside scan
- `--fail-on <tier>` — `reachable` | `potentially_reachable` (default) | `any` | `none`
- `--min-severity <sev>` — `low` (default) | `medium` | `high` | `critical`
- `--show-unreachable` — Include full details for `UNREACHABLE` advisories in terminal/markdown output
- `--diff <git-ref>` — Fail only on advisories newly introduced or newly made reachable compared to `<git-ref>`
- `--baseline <file>` — Compare findings against a saved JSON baseline fingerprint file
- `--forbid-new-suppressions` — Reject newly added `.vulncheck.ignore` entries relative to `--diff` ref
- `--otp-version <ver>` — Override target OTP release version when evaluating runtime constraints
- `--offline` — Disable all network calls; use local cache or `--bundle <path>`

### Exit Codes

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Clean — zero findings at or above `--fail-on` and `--min-severity` thresholds. |
| `1` | Policy violation — actionable vulnerabilities, retired packages, or forbidden suppressions found. |
| `2` | Execution error — invalid CLI flags, missing lockfile, unreadable `.beam` directory, or offline cache miss. |
