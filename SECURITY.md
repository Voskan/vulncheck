# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Guarantees of VulnCheck

`vulncheck` is designed to run inside trusted build pipelines and production release gates. To minimize supply-chain risk:

1. **Zero Runtime Dependencies:** `vulncheck` relies exclusively on Elixir and Erlang/OTP standard library modules (`:beam_lib`, `:digraph`, `:ets`, `:httpc`, `:ssl`, `:public_key`, `:crypto`, `:zip`, `JSON`).
2. **Strict TLS Verification:** All advisory feed downloads enforce TLS peer verification (`verify: :verify_peer`) against system root CAs (`:public_key.cacerts_get/0`) with hostname verification enabled.
3. **No Arbitrary Code Execution on Target Artifacts:** Target projects are analyzed by inspecting lockfiles (`mix.lock`, `rebar.lock`, `manifest.toml`), `.app` resource terms, and compiled `.beam` chunks (`:abstract_code`, `:imports`, `:exports`, `:attributes`) without executing untrusted dependency code.
4. **Soundness Over Silence:** Dynamic dispatch (`apply/3` with unresolved targets) and active OTP supervision daemons are classified conservatively as `POTENTIALLY_REACHABLE` rather than silently suppressed.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities—especially reachability false negatives, TLS bypasses, or archive extraction issues—through public GitHub issues.

Report vulnerabilities privately via GitHub Security Advisories on `github.com/Voskan/vulncheck` or by emailing **voskan1989@gmail.com** with `[SECURITY] vulncheck` in the subject line.

You can expect an initial acknowledgement within **48 hours** and a coordinated remediation timeline within **7 days**.
