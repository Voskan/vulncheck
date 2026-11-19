# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-11-19

### Added

- `feeds import FILE` selects a bundle for later offline scans, and `feeds prune` removes stored bundle snapshots beyond the three most recently used ones and module caches of other schema versions. `feeds status` shows the imported snapshot and the snapshot offline scans read.
- The JSON `feed` object, the SARIF run properties and a terminal `Feed:` line record the snapshot a scan read, the reason for the choice and its advisory count.
- The real-world validation harness scores verdicts against ground-truth labels written from the dependency sources, fails on any `unreachable` verdict for a called routine and on a change of each project's noise-reduction floor, and runs in CI against a pinned advisory bundle. A sixth project combines Bandit, Plug, Tesla over Mint and an unused hackney. Against the labels, the 127 findings of the six projects have 74.0% precision and 100% recall; `docs/VALIDATION.md` lists the 27 false positives.

### Fixed

- `--bundle` no longer selects the bundle for every later offline scan. In 1.0.0, a single `--bundle` run made all later `--offline` scans read that bundle even after `feeds sync`, and `feeds status` did not show it. An offline scan now reads the more recent of the live cache and the snapshot selected by `feeds import`, and warns when its snapshot is older or holds noticeably fewer records. The selection left by 1.0.0 is ignored.
- Imported bundles no longer accumulate: each import keeps three recent snapshots, and re-importing the same bundle reuses its directory.
- The CI escript smoke test scans with a temporary cache directory, so running it locally leaves the user cache unchanged.
- Calling a function value (`callback.()`, `fun.(conn, data)`) no longer keeps every advisory with a routine of the same arity open as `unresolved_dynamic_dispatch`. A function value is a capture or closure created by analyzed code, and both are already part of the call graph. On a project with Bandit, Plug, Tesla over Mint and hackney, nine `function_not_called` verdicts that 1.0.0 reported as `potentially_reachable` are unreachable again, and framework rules such as the `Plug.Parsers` parser selection apply to the whole module again.

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

[Unreleased]: https://github.com/Voskan/vulncheck/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Voskan/vulncheck/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Voskan/vulncheck/releases/tag/v1.0.0
