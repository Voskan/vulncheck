# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-18

First stable release.

### Added

- Lockfile ingestion for Mix (`mix.lock`, umbrella projects), rebar3 (`rebar.lock`) and Gleam (`manifest.toml`), with the production dependency closure separated from `:dev`/`:test`-only packages.
- Advisory data from the OSV.dev Hex feed, enriched with Erlang Ecosystem Foundation CNA CVE 5.1 records (`programRoutines`, `modules`, CVSS, CWE, OTP constraints), plus Hex.pm retirement checks. Feeds are cached with ETag revalidation, validated before publication, and can be exported to and imported from air-gapped bundles.
- CVSS v4.0 base/macrovector scoring from vector strings (FIRST specification, including Threat and Environmental metrics) and severity `none` for score `0.0`.
- Parallel `.beam` analysis of post-macro abstract code with exact `file:line` call sites, a SHA-256 keyed `beam-v4` summary cache (compact string tables and scan-local pooling), per-file/workspace resource limits, and fallbacks for modules compiled without debug info.
- Entrypoint model for OTP applications and supervision trees, Plug and Phoenix pipelines, LiveView, GenServer, GenStage, Broadway and Oban callbacks, consolidated protocols, protocol clients (`mint`, `gun`, `finch` with `incoming_data` traces), `phoenix_pubsub` / `cowboy_telemetry` daemons, and runtime-configured adapters (Tesla, Swoosh, Ecto, Req), plus `extra_entrypoints` for release tasks and RPC targets (suggested by `mix vulncheck.init`).
- Three-tier solver (`reachable`, `potentially_reachable`, `unreachable`) with `daemon_call_chain` and activation hops (`daemon_activation`, `config_activation`), shortest call-chain witnesses, OTP version gating, and `build_only` scoping for `runtime: false` dependencies.
- Git dependency URL normalization (`owner/repo`) and separation of commit ranges (`git_ranges`) from numbered SemVer ranges.
- Reports: terminal, JSON, Markdown, SARIF 2.1.0 with `codeFlows` and `--sarif` sidecar output, GitHub annotations and step summaries, GitLab Code Quality, CycloneDX 1.6 SBOM and OpenVEX v0.2.0.
- Governed suppressions in `.vulncheck.ignore` (reason, expiry, stale-entry warnings; invalid ignore files fail policy with exit `1`), JSON baselines, `--diff` against a Git ref, `--forbid-new-suppressions`, and overlapping output path validation.
- `mix vulncheck`, `mix vulncheck.init`, `mix vulncheck.explain` and `mix vulncheck.feeds`, a standalone escript, a composite GitHub Action (single-scan SARIF + `workflow_dispatch` release dry-run), pre-commit hooks (`vulncheck`), and a container image.
- Reproducible benchmarks (including `umbrella` profile), validation harness (`docs/VALIDATION.md`), and atom-table guarantees: external data never creates atoms and warm scans never re-read unchanged `.beam` files.

[Unreleased]: https://github.com/Voskan/vulncheck/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Voskan/vulncheck/releases/tag/v1.0.0
