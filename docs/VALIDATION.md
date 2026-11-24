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

[`benchmarks/validate_real_world.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/validate_real_world.exs) copies six pinned project trees from `benchmarks/real_world/` into a temporary directory, verifies each lockfile's SHA-256, builds them, and scans them with the `vulncheck` escript against the pinned advisory bundle `benchmarks/feeds/validation-feeds.tar.gz`. CI runs it on every push.

1. **`phoenix_bandit`**: a Plug API started under an `Application` supervisor via `Bandit` (`1.5.0`) with `Plug.Parsers, parsers: [:json]`, `plug 1.15.2` and `jason 1.4.4`.
2. **`plug_cowboy_multipart`**: Plug (`1.15.2`) and `plug_cowboy` (`2.7.0`) started via `Plug.Cowboy` with `parsers: [:urlencoded, :multipart]`.
3. **`tesla_mint_hackney`**: a library whose public `fetch/1` calls Tesla (`1.8.0`) with `Tesla.Adapter.Mint` (`1.5.2`); `hackney` (`1.18.1`) is locked but unused.
4. **`umbrella_three_apps`**: a three-application Mix umbrella (`core`, `api`, `worker`) sharing `mix.lock` with cross-app calls (`plug 1.15.2`).
5. **`rebar3_hackney`**: an Erlang `rebar3` application whose public `fetch/1` calls `hackney:get/1` (`1.18.1`).
6. **`bandit_tesla_gateway`**: a Bandit server with `Plug.Router` and the JSON parser whose route calls Tesla over Mint, with `hackney` locked but unused and `credo` as a dev-only dependency.

### Two Independent Checks

* **Recorded verdicts.** [`real_world_expected.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/real_world_expected.exs) pins every verdict and reason VulnCheck reports. A changed, missing or new finding fails the run, so every verdict change is reviewed.
* **Ground truth.** [`real_world_ground_truth.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/real_world_ground_truth.exs) labels each project and advisory pair by reading the project code and the dependency sources at the pinned versions. The label is `called` when the project, its supervision tree or its public API reaches a vulnerable routine with default dependency settings, and `not_called` otherwise. Each label records its evidence with the dependency source path. Labels are never derived from VulnCheck output, and an unlabeled finding fails the run.

Precision and recall are computed against the labels. `reachable` and `potentially_reachable` verdicts count as positives:

| | `called` | `not_called` |
| :--- | :--- | :--- |
| `reachable`, `potentially_reachable` | true positive (TP) | false positive (FP) |
| `unreachable` | false negative (FN), fails the run | true negative (TN) |

Each project also has a noise-reduction floor, the share of `unreachable` findings measured after the function-value fix of 1.0.1. A result below the floor fails the run. A result above it also fails until the floor is raised in the same change, so an improvement is recorded and cannot be lost later.

### Reference Run Results

* **Tools:** Elixir 1.20.5 / Erlang/OTP 29 / rebar 3.28.0 / VulnCheck 1.0.2
* **Advisory bundle:** `benchmarks/feeds/validation-feeds.tar.gz`, SHA-256 `9a4bcb4d6aa5692fb6469c387e8c8c67d4814bf7447a636bdf9c4b214fec5f1f` (72 files, 363 advisories), built from the OSV Hex feed, EEF CNA CVE 5.1 records and Hex.pm package metadata of 2026-11-19

| Project | Verdicts | TP | FP | FN | TN | Precision | Recall | Noise reduction | Floor | Status |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| `phoenix_bandit` | 25/25 | 18 | 4 | 0 | 3 | 81.8% | 100.0% | 12.0% (3/25) | 12.0% | PASS |
| `plug_cowboy_multipart` | 17/17 | 9 | 8 | 0 | 0 | 52.9% | 100.0% | 0.0% (0/17) | 0.0% | PASS |
| `tesla_mint_hackney` | 25/25 | 15 | 4 | 0 | 6 | 78.9% | 100.0% | 24.0% (6/25) | 24.0% | PASS |
| `umbrella_three_apps` | 5/5 | 1 | 0 | 0 | 4 | 100.0% | 100.0% | 80.0% (4/5) | 80.0% | PASS |
| `rebar3_hackney` | 6/6 | 2 | 3 | 0 | 1 | 40.0% | 100.0% | 16.7% (1/6) | 16.7% | PASS |
| `bandit_tesla_gateway` | 49/49 | 32 | 8 | 0 | 9 | 80.0% | 100.0% | 18.4% (9/49) | 18.4% | PASS |
| **Total** | **127/127** | **77** | **27** | **0** | **23** | **74.0%** | **100.0%** | **18.1% (23/127)** | - | **PASS** |

No routine the labels mark as called is reported `unreachable`. A binary built from `0821f21`, which introduced the function-value regression fixed in 1.0.1, fails this run: its noise reduction is 0% on `phoenix_bandit`, `rebar3_hackney` and `bandit_tesla_gateway` and 16% on `tesla_mint_hackney`, below each floor.

### Verdicts the Labels Consider Not Called

The 27 false positives fall into two groups.

**`reachable` with a static call chain that does not run (11).** Each chain exists in the call graph, but a value the project never produces guards one of its hops. VulnCheck does not track these values:

| Projects | Advisory | Guard on the chain |
| :--- | :--- | :--- |
| `phoenix_bandit`, `bandit_tesla_gateway` | EEF-CVE-2026-39804, EEF-CVE-2026-42786 | Bandit switches to its WebSocket handler only after the plug calls `Plug.Conn.upgrade_adapter/3`. |
| `phoenix_bandit`, `plug_cowboy_multipart`, `bandit_tesla_gateway` | EEF-CVE-2026-56813 | `Plug.Conn.Cookies.encode/2` runs once per response cookie, and the projects set none. |
| `tesla_mint_hackney`, `bandit_tesla_gateway` | EEF-CVE-2026-48596, EEF-CVE-2026-48598 | `Tesla.Adapter.Mint` builds multipart headers only for a `%Tesla.Multipart{}` body. |
| `rebar3_hackney` | EEF-CVE-2026-47069 | `hackney_cookie:setcookie/3` runs only for a `cookie` request option. |

**Conservative `potentially_reachable` (16).** These advisories have no function-level data VulnCheck can follow, or depend on an unresolved dynamic call:

| Projects | Advisory | Reason | Why the routine does not run |
| :--- | :--- | :--- | :--- |
| `phoenix_bandit`, `bandit_tesla_gateway` | EEF-CVE-2026-110314 | `active_network_daemon` | WebSocket close handling; no plug upgrades the connection. |
| `plug_cowboy_multipart` | EEF-CVE-2026-8466 | `active_network_daemon` | Plug parses multipart bodies itself; `cowboy_req:read_part/3` is never called. |
| `plug_cowboy_multipart` | GHSA-w4f7-4cxr-rv3c, EEF-CVE-2026-43966, EEF-CVE-2026-43968, EEF-CVE-2026-43969, EEF-CVE-2026-43970, EEF-CVE-2026-43971 | `active_network_daemon` | cowlib encoders (`cow_http_struct_hd`, `cow_sse`, `cow_cookie:cookie/1`, `cow_spdy`, `cow_link`) that the server never calls. |
| `tesla_mint_hackney`, `bandit_tesla_gateway` | GHSA-vq52-99r9-h5pw, GHSA-9fm9-hp7p-53mf | `unresolved_dynamic_dispatch` | hackney is started but never sent a request. |
| `rebar3_hackney` | EEF-CVE-2026-47071 | `unresolved_dynamic_dispatch` | The SOCKS5 transport needs a `proxy` option. |
| `rebar3_hackney` | GHSA-9fm9-hp7p-53mf | `unresolved_dynamic_dispatch` | The leak follows redirects, which need `follow_redirect`. |

```bash
MIX_ENV=prod mix escript.build
mix run benchmarks/validate_real_world.exs --offline \
  --bundle benchmarks/feeds/validation-feeds.tar.gz --markdown
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

* Metrics reported by the validation harness apply strictly to the six covered projects and the pinned feed snapshot. Labels are written by reading dependency sources and can be wrong; each records its evidence so it can be checked and corrected.
* A `reachable` verdict proves a static call chain, not that the chain runs: hops guarded by runtime values, such as a WebSocket upgrade or a request option, are followed unconditionally.
* Dynamic `apply/3` with unresolved targets and stripped `.beam` files without debug info (`has_debug_info: false`) are treated conservatively as `potentially_reachable` so VulnCheck never produces silent false negatives.
* Git dependencies without verifiable commit history or matching upstream repository identity remain open (`git_match_status: :uncertain`) and are never marked `unreachable` by version alone.
