# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for 1.0.0
- Multi-language BEAM lockfile ingestion (`mix.lock`, `rebar.lock`, Gleam `manifest.toml`) with umbrella project support and `:prod` vs `:dev`/`:test` environment scoping.
- Dual-source vulnerability intelligence combining OSV.dev Hex bulk feeds with Erlang Ecosystem Foundation (EEF) CNA CVE 5.1 `programRoutines` function-level metadata and Hex.pm package retirement advisories.
- Parallel `.beam` bytecode analyzer extracting Erlang Abstract Format (`:abstract_code`) post-macro call graphs with exact `file:line` call-site locations and SHA-256 incremental disk caching.
- BEAM-aware entrypoint and dispatch model covering OTP `.app` supervision trees, `Phoenix`/`Plug` pipelines, `GenServer`/`Oban`/`Broadway` behaviour callbacks, consolidated Elixir protocols, and configured runtime HTTP/DB adapters.
- Three-tier soundness-preserving reachability solver (`REACHABLE`, `POTENTIALLY_REACHABLE`, `UNREACHABLE`) with shortest-path call-chain witnesses and OTP/Elixir runtime version gating.
- Enterprise reporting and compliance outputs: ANSI Terminal, JSON, Markdown, SARIF 2.1.0 with `codeFlows`, GitHub Step Summary & Annotations, GitLab Dependency Scanning, CycloneDX 1.6 SBOM, and OpenVEX v0.2.0 (`vulnerable_code_not_in_execute_path`).
- Standalone `vulncheck` escript and Mix tasks (`mix vulncheck`, `mix vulncheck.init`, `mix vulncheck.explain`, `mix vulncheck.feeds`) plus GitHub Action (`action.yml`) and air-gapped offline bundle mode.
