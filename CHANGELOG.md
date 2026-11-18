# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New reason code `daemon_call_chain` for reachable findings whose call chain starts at a protocol handler of an active network daemon rather than at code the project runs itself. Chains from the project's own entrypoints take precedence.
- Call chains from roots the project does not call itself start with a step 0 activation hop (`daemon_activation` or `config_activation` in JSON `trace[].kind` and SARIF `threadFlowLocation.kinds`). The hop names the project function and line that starts the daemon (for example `MyApp.Application.start/2 starts Bandit`), the `.app` file whose boot tree starts it, or the configuration line that names a dependency module. JSON hops of this kind carry a `note`.

### Fixed

- `Plug.Parsers` parsers are linked to the functions named by their options (the body reader, by default `Plug.Conn.read_body/2`, and the JSON decoder) instead of being left unresolved, and a custom body reader is now reachable.
- Dynamic calls of ThousandIsland and Mint through their transport and connection modules, and the Tesla middleware stack, are resolved to the modules that can actually be there, so an unused HTTP client no longer looks reachable through them.
- `apply/3` with an open argument list only matches functions with at least the known number of arguments. The `.beam` summary cache moves to `beam-v3`.
- `Plug.Parsers` configurations in unreachable code (such as `Plug.Debugger` inside `plug` itself) no longer enable their parsers for the whole application, so multipart and urlencoded advisories of an endpoint configured with `parsers: [:json]` are unreachable again.
- Atoms converted from strings only widen the dynamic calls of the module that converts them, instead of every dynamic call in the program; module names built with `Module.concat` still widen all of them. Each dynamic call site that keeps advisories potentially reachable is now named in the report warnings.
- Routines named by an advisory that belong to Erlang/OTP, Elixir or another dependency (such as `List.delete/2`) are no longer reachability targets, so they cannot turn an advisory into a reachable finding. They are reported as `context_routines` in JSON, as `contextRoutines` in SARIF properties and as context in `explain`.
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
