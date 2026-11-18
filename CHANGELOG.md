# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Advisories describing the same vulnerability of a package (for example the Erlang Ecosystem Foundation and GitHub records of one CVE) are merged into one finding with all identifiers as aliases, united version ranges and symbols, and the highest CVSS score. Suppressions and baselines written for any of the identifiers keep matching.

## [1.0.0] - 2026-11-18

First stable release.

### Added

- Lockfile ingestion for Mix (`mix.lock`, umbrella projects), rebar3 (`rebar.lock`) and Gleam (`manifest.toml`), with the production dependency closure separated from `:dev`/`:test`-only packages.
- Advisory data from the OSV.dev Hex feed, enriched with Erlang Ecosystem Foundation CNA CVE 5.1 records (`programRoutines`, `modules`, CVSS, CWE, OTP constraints), plus Hex.pm retirement checks. Feeds are cached with ETag revalidation and can be exported to and imported from offline bundles.
- Parallel `.beam` analysis of post-macro abstract code with exact `file:line` call sites, a SHA-256 keyed summary cache, and fallbacks for modules compiled without debug info.
- Entrypoint model for OTP applications and supervision trees, Plug and Phoenix pipelines, LiveView, GenServer, GenStage, Broadway and Oban callbacks, consolidated protocols and runtime-configured adapters (Tesla, Swoosh, Ecto, Phoenix.PubSub, Finch, Req), plus `extra_entrypoints` for release tasks and RPC targets (suggested by `mix vulncheck.init`).
- Three-tier solver (`reachable`, `potentially_reachable`, `unreachable`) with twelve reason codes, shortest call-chain witnesses and OTP version gating. Dynamic dispatch, missing debug info and missing symbol data never produce an unreachable verdict.
- Reports: terminal, JSON, Markdown, SARIF 2.1.0 with `codeFlows`, GitHub annotations and step summaries, GitLab Code Quality, CycloneDX 1.6 SBOM and OpenVEX v0.2.0, all deterministic.
- Governed suppressions in `.vulncheck.ignore` (reason, expiry, stale-entry warnings), JSON baselines, `--diff` against a Git ref and `--forbid-new-suppressions`.
- `mix vulncheck`, `mix vulncheck.init`, `mix vulncheck.explain` and `mix vulncheck.feeds`, a standalone escript, a composite GitHub Action, pre-commit hooks and a container image.
- Reproducible benchmarks and atom-table guarantees: external data never creates atoms and warm scans never re-read unchanged `.beam` files.

[Unreleased]: https://github.com/Voskan/vulncheck/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Voskan/vulncheck/releases/tag/v1.0.0
