# Validation & Soundness Corpus

This document describes how VulnCheck's reachability verdicts and noise-reduction claims are validated against both an offline soundness corpus and a reproducible real-world Hex project harness.

---

## 1. Offline Soundness Corpus

The test suite includes compiled BEAM mini-projects under [`test/vulncheck/integration/soundness_corpus_test.exs`](https://github.com/Voskan/vulncheck/blob/main/test/vulncheck/integration/soundness_corpus_test.exs) and [`test/vulncheck/solver_test.exs`](https://github.com/Voskan/vulncheck/blob/main/test/vulncheck/solver_test.exs) that exercise the core BEAM reachability scenarios without network access:

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

[`benchmarks/validate_real_world.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/validate_real_world.exs) copies five pinned project trees from `benchmarks/real_world/` into a temporary directory, verifies each lockfile's SHA-256, builds them, scans them with the `vulncheck` escript, and compares every matched finding against [`benchmarks/real_world_expected.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/real_world_expected.exs):

1. **`phoenix_bandit`** — Plug API started under an `Application` supervisor via `Bandit` (`1.5.0`) with `Plug.Parsers, parsers: [:json]`, `plug 1.15.2`, and `jason 1.4.4`.
2. **`plug_cowboy_multipart`** — Plug (`1.15.2`) + `plug_cowboy` (`2.7.0`) started via `Plug.Cowboy` with `parsers: [:urlencoded, :multipart]`.
3. **`tesla_mint_hackney`** — Tesla (`1.8.0`) configured with `Tesla.Adapter.Mint` (`1.5.2`) and transitive `hackney` (`1.18.1`).
4. **`umbrella_three_apps`** — Three-application Mix umbrella (`core`, `api`, `worker`) sharing `mix.lock` with cross-app calls (`plug 1.15.2`).
5. **`rebar3_hackney`** — Erlang `rebar3` application calling `hackney:get/1` (`1.18.1`).

### Reference Run Results

* **Tools:** Elixir 1.20.5 / Erlang/OTP 29 / rebar 3.28.0 / VulnCheck 1.0.0
* **Advisory Bundle SHA-256:** `94d3f6eacda3b0dbb06351aff9ddc6b875ba0630d4302591fbf72ee8fb7a18f8` (80 files, 363 advisories)

| Project | Matched | Precision | Recall | Noise Reduction | Status | Lockfile SHA-256 (prefix) |
| :--- | ---: | ---: | ---: | ---: | :---: | :--- |
| `phoenix_bandit` | 25/25 | 100.0% | 100.0% | 0.0% (0/25) | PASS | `81a4445b7f50` |
| `plug_cowboy_multipart` | 17/17 | 100.0% | 100.0% | 0.0% (0/17) | PASS | `f98e580de2e1` |
| `tesla_mint_hackney` | 25/25 | 100.0% | 100.0% | 16.0% (4/25) | PASS | `ac9fd02faf1d` |
| `umbrella_three_apps` | 5/5 | 100.0% | 100.0% | 80.0% (4/5) | PASS | `551949566c7d` |
| `rebar3_hackney` | 6/6 | 100.0% | 100.0% | 0.0% (0/6) | PASS | `05ca9d5d51d0` |
| **Total** | **78/78** | **100.0%** | **100.0%** | **10.3% (8/78)** | **PASS** | — |

On `phoenix_bandit`, `bandit 1.5.0` and `hpax 0.1.2` advisories are either reachable from the started `Bandit` supervision pipeline or kept `potentially_reachable` (`active_network_daemon`), while the 3 non-proven `plug 1.15.2` advisories are conservatively kept `potentially_reachable` (`unresolved_dynamic_dispatch`) due to dynamic `apply/3` sites in `Plug`/`Bandit`, yielding 0% noise reduction on that specific dependency combination while `umbrella_three_apps` achieves 80% noise reduction and `tesla_mint_hackney` achieves 16%.

```bash
MIX_ENV=prod mix escript.build
mix run benchmarks/validate_real_world.exs --offline --bundle path/to/bundle.tar.gz --markdown
```

---

## 3. Umbrella Benchmark Profile

[`benchmarks/run_benchmarks.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/run_benchmarks.exs) includes an `umbrella` profile (180 packages, 3 umbrella applications with cross-app calls, 1,002 compiled `.beam` files, 120,220 call edges, 120 advisories) alongside `medium`, `large`, and `libraries` (10 timing iterations, 5-run median peak memory):

| Metric (`umbrella` profile) | Value |
| :--- | ---: |
| Cold full scan (median) | 506.7 ms |
| Warm full scan (median) | 409.0 ms |
| Peak BEAM memory, cold scan (median / min–max) | 375.0 MiB (374.8–375.2) |
| Peak BEAM memory, warm scan (median / min–max) | 324.8 MiB (324.3–345.7) |
| Atom delta over measured runs | 0 |

---

## 4. Scope and Limitations

* Metrics reported by the validation harness apply strictly to the covered corpus and pinned feed snapshot; missed or unexpected findings fail the harness.
* Dynamic `apply/3` with unresolved targets and stripped `.beam` files without debug info (`has_debug_info: false`) are treated conservatively as `potentially_reachable` so VulnCheck never produces silent false negatives.
* Git dependencies without verifiable commit history or matching upstream repository identity remain open (`git_match_status: :uncertain`) and are never marked `unreachable` by version alone.
