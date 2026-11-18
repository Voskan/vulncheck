# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Guarantees and Trust Boundaries

`vulncheck` separates **scanning** from **building** so teams can choose the trust boundary that matches their CI environment:

1. **Zero Runtime Dependencies:** `vulncheck` relies exclusively on Elixir and Erlang/OTP standard library modules (`:beam_lib`, `:digraph`, `:ets`, `:httpc`, `:ssl`, `:public_key`, `:crypto`, `:zip`, `JSON`).
2. **Strict TLS Verification:** All advisory feed downloads enforce TLS peer verification (`verify: :verify_peer`) against system root CAs (`:public_key.cacerts_get/0`) with hostname verification enabled.
3. **Static Inspection of Target Artifacts (Prebuilt Mode):** When scanning prebuilt artifacts (`compile: false` in the GitHub Action or `vulncheck` / `mix vulncheck` on an existing `_build/`), `vulncheck` inspects lockfiles (`mix.lock`, `rebar.lock`, `manifest.toml`), `.app` resource terms, and compiled `.beam` chunks (`:abstract_code`, `:imports`, `:exports`, `:attributes`) without executing target dependency code.
4. **Trusted Build Mode (`compile: true`):** Enabling compilation (`compile: true` in the GitHub Action or running `mix compile` / `rebar3 compile` / `gleam build` before scanning) executes the target project's build tools, macros, and Mix/rebar3 compilers. Use `compile: true` only on trusted checkouts. For untrusted pull requests (such as forks), do not grant `security-events: write` or repository secrets to a job that compiles untrusted code: either run the build/scan in an unprivileged workflow and upload SARIF from a separate `workflow_run` job, or scan prebuilt artifacts with `compile: false`.
5. **Resource Limits and Cache Isolation:** `.beam` analysis enforces per-file size limits (64 MiB), workspace `.beam` file count limits (20,000 files), and per-file worker timeouts (15 s), reporting any truncated or failed module as incomplete analysis. On-disk `.beam` summary caches are separated from advisory feed caches (`feeds/` vs `beam-v4/`), bounded in size, decoded with `[:safe]`, and validated against the `ModuleSummary` schema before reuse; CI workflows should cache only `feeds/`.
6. **Atom Table Invariant:** External JSON feeds and lockfiles never call `String.to_atom/1`. Warm scans that read validated `.beam` summaries add zero atoms. Cold `.beam` analysis reads module chunks via `:beam_lib.chunks/2`, which internalizes atoms present in those `.beam` chunk tables without loading or executing the modules.
7. **Soundness Over Silence:** Dynamic dispatch (`apply/3` with unresolved targets) and active OTP supervision daemons are classified conservatively as `POTENTIALLY_REACHABLE` rather than silently suppressed.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities—especially reachability false negatives, TLS bypasses, or archive extraction issues—through public GitHub issues.

Report vulnerabilities privately via GitHub Security Advisories on `github.com/Voskan/vulncheck` or by emailing **voskan1989@gmail.com** with `[SECURITY] vulncheck` in the subject line.

You can expect an initial acknowledgement within **48 hours** and a coordinated remediation timeline within **7 days**.
