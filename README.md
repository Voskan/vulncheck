# VulnCheck

[![Hex.pm](https://img.shields.io/hexpm/v/vulncheck.svg)](https://hex.pm/packages/vulncheck)
[![HexDocs](https://img.shields.io/badge/hex-docs-purple.svg)](https://hexdocs.pm/vulncheck)
[![CI](https://github.com/Voskan/vulncheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Voskan/vulncheck/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Runtime Deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](#design-highlights)

**Function-level reachability vulnerability scanner for Elixir, Erlang, and Gleam (`govulncheck` for the BEAM).**

`vulncheck` bridges the gap between lockfile dependency scanners (`mix deps.audit`, `mix hex.audit`) and what your compiled BEAM release actually executes. Instead of failing CI whenever any transitive Hex package receives a CVE, `vulncheck` pairs **OSV.dev** and **Erlang Ecosystem Foundation (EEF) CNA CVE 5.1 `programRoutines`** metadata with **post-macro `.beam` bytecode call graphs, OTP supervision roots, Plug/Phoenix pipelines, and runtime adapter configurations** to prove whether vulnerable functions are reachable in your production code.

---

## Why VulnCheck Exists

Between 2024 and 2026, annual Hex security advisories grew nearly **80x** (from single-digit annual disclosures to hundreds of structured CVEs across core packages such as `plug`, `phoenix`, `bandit`, `ash`, `mint`, `hackney`, `cowlib`, and `tesla`).

Traditional lockfile scanners suffer from two structural limitations:

1. **Package-Level Alert Fatigue:** Tools that only compare `mix.lock` versions flag an entire dependency even when the CVE affects a single optional parser, unused HTTP adapter, aggregate helper, or an older OTP runtime.
2. **Unused Official Symbol Data:** EEF CNA CVE 5.1 advisories explicitly publish affected MFA symbols under `programRoutines` (for example, `'Elixir.Plug.Conn.Query':decode/4` or `'Elixir.Ash.Actions.Aggregate':run/4`), yet existing BEAM audit tools ignore symbol-level metadata altogether.

At the same time, **a naive static call graph is unsafe on the BEAM**: HTTP servers (`Bandit`, `:cowboy`), `Plug` pipelines, `GenServer` / `Oban` callbacks, and runtime-configured HTTP adapters (`Tesla`, `Swoosh`, `Finch`) are wired via OTP supervision specs, expanded macros, and `Application` environment terms rather than direct `main()` calls. `vulncheck` models BEAM execution semantics soundly so network-exposed daemons and dynamic dispatches are never silently dismissed.

---

## Design Highlights

- **Zero Runtime Dependencies:** Built entirely on Elixir and Erlang/OTP standard libraries (`:beam_lib`, `:digraph`, `:ets`, `:httpc`, `:ssl`, `:public_key`, `:crypto`, `:zip`, `JSON`). Adding a security scanner never expands your supply-chain attack surface.
- **Post-Macro `.beam` Analysis:** Inspects compiled `:abstract_code` chunks inside `.beam` artifacts—after `use Phoenix.Router`, `plug Plug.Parsers`, `Ecto.Query`, `Ash`, and `Oban.Worker` macros have already been expanded by the compiler—preserving exact `file:line` call-site locations.
- **Dual-Feed Advisory Intelligence:** Combines the OSV.dev Hex feed with EEF CNA CVE 5.1 records (`cna.erlef.org` / MITRE CVE API) to recover exact `programRoutines` MFA targets, affected modules, and OTP runtime constraints, plus Hex.pm package retirement checks.
- **Sound Three-Tier Verdicts:**
  - `REACHABLE` — Concrete call chain from an application/OTP entrypoint to a vulnerable `Module.fun/arity` (printed with exact `file:line` hops).
  - `POTENTIALLY_REACHABLE` — Package runs as an active OTP daemon/supervisor child, participates in an unresolved `apply/3` boundary, or lacks symbol-level CVE granularity while loaded in `:prod`.
  - `UNREACHABLE` — Mathematically excluded (`function_not_called`, `module_not_loaded`, `adapter_not_configured`, `otp_app_not_started`, `non_prod_dependency`, or `otp_version_unaffected`).
- **Multi-Language BEAM Support:** Works as `mix vulncheck` inside Elixir / Umbrella projects and as a standalone `vulncheck` escript for Erlang (`rebar3`) and Gleam (`manifest.toml`) builds.
- **Compliance & CI Ready:** Outputs ANSI Terminal reports, deterministic JSON, Markdown, **SARIF 2.1.0 (`codeFlows`)**, GitHub Actions annotations & Step Summaries, GitLab Dependency Scanning JSON, **CycloneDX 1.6 SBOM**, and **OpenVEX v0.2.0** (`vulnerable_code_not_in_execute_path`).

---

## Comparison with Existing Tools

| Capability | `mix_audit` | `mix hex.audit` | `sobelow` | `vulncheck` |
| :--- | :---: | :---: | :---: | :---: |
| Lockfile version matching (`mix.lock`) | Yes | Retired only | No | **Yes (`mix.lock`, `rebar.lock`, `manifest.toml`)** |
| EEF CNA CVE 5.1 `programRoutines` MFA ingestion | No | No | No | **Yes** |
| Post-macro `.beam` call-graph reachability | No | No | No | **Yes (`file:line` call chains)** |
| OTP supervision & `Plug` / `Tesla` adapter awareness | No | No | No | **Yes (sound 3-tier model)** |
| OTP / Elixir runtime version gating | No | No | No | **Yes** |
| SARIF 2.1.0 `codeFlows` & OpenVEX / CycloneDX 1.6 | No | No | SARIF (app rules) | **Yes** |
| Air-gapped offline bundle mode | No | No | Yes | **Yes (`--offline` / `--bundle`)** |

---

## Quick Start

### Elixir / Mix Installation

Add `vulncheck` to your `mix.exs` dependencies:

```elixir
def deps do
  [
    {:vulncheck, "~> 1.0", only: [:dev, :test], runtime: false}
  ]
end
```

Compile your project (so `.beam` debug chunks are up to date) and run the audit:

```bash
mix deps.get
mix vulncheck
```

### Standalone Escript (Erlang `rebar3`, Gleam, or CI Containers)

```bash
mix escript.install hex vulncheck
vulncheck --project-dir /path/to/service
```

---

## Example Terminal Output

```text
VulnCheck 1.0.0 — BEAM Reachability Vulnerability Audit
Target: my_fintech_api (Elixir 1.18.2 / OTP 27.2, env: prod)
Lockfile: 74 prod packages (19 dev/test excluded) · Scan time: 142 ms (cached)

[REACHABLE] CVE-2026-101028 (HIGH · CVSS 7.5) — ash 3.34.2 (fix: >= 3.34.6)
  Summary: Ash.count, Ash.exists and Ash.aggregate skip related resources' read policies
  Target:  Ash.Actions.Aggregate.run/4
  Trace:
    1. MyFintechWeb.Router.call/2                 (lib/my_fintech_web/router.ex:18)
    2. MyFintechWeb.ReportController.index/2      (lib/my_fintech_web/controllers/report_controller.ex:41)
    3. MyFintech.Ledger.count_filtered_entries/2  (lib/my_fintech/ledger.ex:112)
    4. Ash.count/2 -> Ash.Actions.Aggregate.run/4 (deps/ash/lib/ash/actions/aggregate.ex:29)

[POTENTIALLY REACHABLE] CVE-2026-54892 (MEDIUM · CVSS 6.5) — plug 1.16.2 (fix: >= 1.16.4)
  Summary: Quadratic-time nested parameter decoding in Plug.Conn.Query
  Reason:  Active HTTP pipeline plug via MyFintechWeb.Endpoint (Plug.Parsers :urlencoded enabled)

Suppressed as UNREACHABLE (9 advisories — pass --show-unreachable for details):
  • 5 in hackney 1.20.1   (adapter_not_configured: Tesla configured with Tesla.Adapter.Mint)
  • 2 in plug 1.16.2      (function_not_called: Plug.Parsers :multipart disabled in Endpoint)
  • 1 in hex_core 0.10.0  (otp_version_unaffected: requires OTP <= 25; running OTP 27.2)
  • 1 in meck 0.9.2       (non_prod_dependency: restricted to :test)

Summary: 1 reachable, 1 potentially reachable, 9 unreachable (82% noise reduction)
Exit code: 1 (threshold: --fail-on potentially_reachable)
```

---

## Common CLI & CI Workflows

```bash
# Fail CI only on proven reachable vulnerabilities
mix vulncheck --fail-on reachable

# Emit SARIF 2.1.0 with full call-graph codeFlows for GitHub Code Scanning
mix vulncheck --format sarif --output vulncheck.sarif

# Generate CycloneDX 1.6 SBOM + OpenVEX v0.2.0 statements for compliance audits
mix vulncheck --sbom sbom.cdx.json --vex vex.openvex.json

# PR gate: block new reachable CVEs and forbid sneaking in new suppressions
mix vulncheck --diff origin/main --forbid-new-suppressions

# Export an air-gapped advisory bundle for isolated build networks
mix vulncheck.feeds bundle --output vulncheck-feeds.tar.gz
mix vulncheck --offline --bundle vulncheck-feeds.tar.gz
```

### GitHub Actions Integration

```yaml
name: Security
on: [push, pull_request]

jobs:
  vulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: erlef/setup-beam@v1
        with:
          otp-version: "27.2"
          elixir-version: "1.18.2"
      - uses: Voskan/vulncheck@v1
        with:
          fail-on: potentially_reachable
          upload-sarif: true
```

---

## Documentation

- [System Architecture & Pipeline Internals](docs/ARCHITECTURE.md)
- [BEAM Reachability Model & Soundness Guarantees](docs/REACHABILITY_MODEL.md)
- [Configuration, Suppressions & CI/CD Guide](docs/CONFIGURATION_AND_CI.md)
- [Output Schemas: JSON, SARIF 2.1.0, CycloneDX 1.6 & OpenVEX v0.2.0](docs/OUTPUT_FORMATS.md)
- [Performance & Memory Benchmarks](docs/BENCHMARKS.md)

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Voskan Voskanyan.
