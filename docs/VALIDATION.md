# Validation & Soundness Corpus

This document describes how VulnCheck's reachability verdicts and noise-reduction claims are validated against both an offline soundness corpus and a reproducible real-world Hex project harness.

---

## 1. Offline Soundness Corpus

The test suite includes compiled BEAM mini-projects under `test/support/` and `test/vulncheck/integration/` that exercise the core BEAM reachability scenarios without network access:

| Scenario | Expected Verdict | Reason |
| :--- | :--- | :--- |
| Direct or transitive call to vulnerable function (`Ash.count` vs `Ash.read`) | `reachable` / `unreachable` | `call_chain_proven` / `function_not_called` |
| `Plug.Parsers` configured with `parsers: [:json]` only | `unreachable` for multipart/urlencoded | `module_not_loaded` |
| Active OTP supervision daemon (`Bandit`, `Cowboy`) | `potentially_reachable` / `reachable` | `active_network_daemon` / `daemon_call_chain` |
| Unconfigured HTTP adapter (`Hackney` transitive under `Tesla + Mint`) | `unreachable` | `adapter_not_configured` |
| `:test` / `:dev` or `runtime: false` dependency not called at runtime | `unreachable` | `non_prod_dependency` |
| OTP version constraint (`<= 25`) when running on OTP 27+ | `unreachable` | `otp_version_unaffected` |
| Unresolved dynamic `apply/3` dispatch | `potentially_reachable` | `unresolved_dynamic_dispatch` |

---

## 2. Real-World Hex Validation Harness

[`benchmarks/validate_real_world.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/validate_real_world.exs) generates five pinned projects in a temporary directory, fetches and compiles them, scans them with the `vulncheck` escript, and compares the JSON output against [`benchmarks/real_world_expected.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/real_world_expected.exs):

1. **`phoenix_bandit`** — Phoenix/Plug API on Bandit with `Plug.Parsers, parsers: [:json]` (verifies parser narrowing and noise reduction > 0%).
2. **`plug_cowboy_multipart`** — Plug + Cowboy with `:urlencoded` and `:multipart` parsers enabled.
3. **`tesla_mint_hackney`** — Tesla configured with `Tesla.Adapter.Mint` and transitive `hackney` (`adapter_not_configured`).
4. **`umbrella_three_apps`** — Three-application Mix umbrella sharing `mix.lock` with cross-app calls.
5. **`rebar3_hackney`** — Erlang `rebar3` application depending on `hackney` (executed when `rebar3` is installed).

Each run records the SHA-256 of each project's lockfile, the tool versions, and the advisory feed metadata, and supports `--offline --bundle <path>` for deterministic replay against a frozen feed snapshot.

```bash
mix escript.build
mix run benchmarks/validate_real_world.exs --markdown
```

---

## 3. Umbrella Benchmark Profile

[`benchmarks/run_benchmarks.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/run_benchmarks.exs) includes an `umbrella` profile (180 packages, 3 umbrella applications with cross-app calls, 1,002 compiled `.beam` files, 120,220 call edges, 120 advisories) alongside `medium`, `large`, and `libraries`:

| Metric (`umbrella` profile) | Value |
| :--- | ---: |
| Cold full scan (median) | 476.1 ms |
| Warm full scan (median) | 397.1 ms |
| Peak BEAM memory, cold scan | 510.0 MiB |
| Peak BEAM memory, warm scan | 438.6 MiB |
| Atom delta over measured runs | 0 |

---

## 4. Scope and Limitations

* Metrics reported by the validation harness apply strictly to the covered corpus and pinned feed snapshot; missed expected findings lower recall and fail the harness.
* Dynamic `apply/3` with unresolved targets and stripped `.beam` files without debug info (`has_debug_info: false`) are treated conservatively as `potentially_reachable` so VulnCheck never produces silent false negatives.
* Git dependencies without verifiable commit history or matching upstream repository identity remain open (`git_match_status: :uncertain`) and are never marked `unreachable` by version alone.
