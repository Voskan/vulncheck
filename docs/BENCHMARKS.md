# Performance & Memory Benchmarks

VulnCheck runs on every pull request, so a warm scan has to stay well inside
the time budget of a CI step, and the scanner itself must never become a
denial-of-service vector against the BEAM it runs on. This page documents how
performance is measured, the numbers on a reference machine, and the
invariants enforced by the test suite.

---

## 1. Methodology

All numbers come from [`benchmarks/run_benchmarks.exs`](https://github.com/Voskan/vulncheck/blob/main/benchmarks/run_benchmarks.exs),
which uses nothing but the Elixir and Erlang/OTP standard libraries:

```bash
mix run benchmarks/run_benchmarks.exs                                # medium profile, text table
mix run benchmarks/run_benchmarks.exs --profile all --markdown       # every profile, this page's tables
mix run benchmarks/run_benchmarks.exs --profile large --iterations 20 --keep
```

The two synthetic profiles generate a complete compiled Mix workspace in a
temporary directory: `mix.exs`, `mix.lock`, one `_build/prod/lib/<app>/ebin`
per package with `.app` files and `.beam` files compiled with debug info, and
an offline advisory cache. Every package is a chain of modules whose
functions pattern-match, build maps, run closures over lists and format
strings, then call the next function or the package's dependencies. Half of
the advisories name a function on the call chain from `Application.start/2`
(reachable), and the other half name a function nothing calls (unreachable),
so the solver produces both verdicts.

| Profile | Packages | Modules | Functions (approx.) | Advisories |
| :--- | ---: | ---: | ---: | ---: |
| `medium` | 80 | 421 | 4,620 | 50 |
| `large` | 180 | 1,001 | 13,000 | 120 |
| `umbrella` | 180 | 1,002 | 12,987 | 120 |

The `libraries` profile measures the `.beam` summary cache on real code: the
`ebin` directories of the Elixir and Erlang/OTP applications installed with the
running VM (`kernel`, `stdlib`, `compiler`, `crypto`, `inets`, `ssl`,
`public_key`, `elixir`, `logger`, `eex`, `mix`).

Each stage runs once to warm up (loading VulnCheck's own modules and filling
the cache), then is timed with `:timer.tc/1` for the configured number of
iterations. Every sample runs in a fresh process, as a CLI invocation would,
so garbage collection never scans results kept alive by earlier stages.
Reported values are the median, p95, minimum and maximum. Peak memory is the
median (with min–max spread) of 5 fresh-process runs after
`:erlang.garbage_collect/0`, with `:erlang.memory(:total)` sampled every 2 ms.

| Stage | What is timed |
| :--- | :--- |
| Lockfile and configuration | Detecting the project, parsing `mix.lock` and `mix.exs`, locating build directories |
| Advisory feeds (offline cache) | Reading and parsing the cached OSV archive and CVE records |
| Cold `.beam` extraction | `:beam_lib.chunks/2` on every `.beam` plus abstract-code analysis, cache disabled |
| Warm `.beam` summaries | SHA-256 of every `.beam` and decoding its cached summary |
| Entrypoints, call graph and solver | Building the graph, resolving entrypoints, solving every advisory |
| Reports | Rendering the terminal, SARIF, CycloneDX and OpenVEX outputs |
| Full scan | `VulnCheck.Scanner.run/2` end to end, with the `.beam` cache off (cold) or on (warm) |

---

## 2. Reference results

### Environment

| Component | Value |
| :--- | :--- |
| OS | unix/darwin 27.2.0 (aarch64-apple-darwin27.0.0) |
| CPU | Apple M5 Max |
| Schedulers | 18 |
| Elixir | 1.20.5 |
| Erlang/OTP | 29 (ERTS 17.1.1) |
| VulnCheck | 1.0.3 |

10 measured iterations per stage after one warm-up run.

### Profile `medium`

80 packages, 421 `.beam` files, ~4620 functions, 42093 call edges,
50 advisories with `programRoutines` (25 reachable, 25 unreachable).

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Lockfile and configuration | 7.3 | 8.2 | 7.1 | 8.2 |
| Advisory feeds (offline cache) | 7.0 | 7.5 | 6.7 | 7.5 |
| Cold .beam extraction | 60.5 | 63.7 | 58.3 | 63.7 |
| Warm .beam summaries (SHA-256 cache) | 36.5 | 38.4 | 36.0 | 38.4 |
| Entrypoints, call graph and solver | 89.5 | 98.3 | 87.1 | 98.3 |
| Reports (terminal, sarif, cyclonedx, openvex) | 60.8 | 63.6 | 60.4 | 63.6 |
| Full scan, cold .beam cache | 149.6 | 155.6 | 145.6 | 155.6 |
| Full scan, warm cache | 120.4 | 124.0 | 116.7 | 124.0 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan (median / min–max) | 179.8 MiB (179.6–180.0) |
| Peak BEAM memory, warm scan (median / min–max) | 161.1 MiB (147.3–165.6) |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `large`

180 packages, 1001 `.beam` files, ~13000 functions, 120273 call edges,
120 advisories with `programRoutines` (60 reachable, 60 unreachable).

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Lockfile and configuration | 18.8 | 20.0 | 17.3 | 20.0 |
| Advisory feeds (offline cache) | 15.6 | 16.1 | 15.0 | 16.1 |
| Cold .beam extraction | 157.4 | 163.2 | 152.9 | 163.2 |
| Warm .beam summaries (SHA-256 cache) | 94.7 | 101.3 | 86.4 | 101.3 |
| Entrypoints, call graph and solver | 322.2 | 332.4 | 304.2 | 332.4 |
| Reports (terminal, sarif, cyclonedx, openvex) | 105.9 | 108.8 | 105.2 | 108.8 |
| Full scan, cold .beam cache | 497.5 | 504.5 | 481.6 | 504.5 |
| Full scan, warm cache | 407.5 | 424.9 | 385.6 | 424.9 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan (median / min–max) | 334.7 MiB (333.9–359.5) |
| Peak BEAM memory, warm scan (median / min–max) | 309.5 MiB (309.1–343.8) |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `umbrella`

180 packages, 1002 `.beam` files, ~12987 functions, 120220 call edges,
120 advisories with `programRoutines` (60 reachable, 60 unreachable).

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Lockfile and configuration | 18.0 | 19.1 | 17.7 | 19.1 |
| Advisory feeds (offline cache) | 15.9 | 16.8 | 15.3 | 16.8 |
| Cold .beam extraction | 154.4 | 160.4 | 150.0 | 160.4 |
| Warm .beam summaries (SHA-256 cache) | 96.2 | 102.5 | 87.6 | 102.5 |
| Entrypoints, call graph and solver | 324.5 | 402.3 | 314.4 | 402.3 |
| Reports (terminal, sarif, cyclonedx, openvex) | 112.5 | 115.5 | 111.7 | 115.5 |
| Full scan, cold .beam cache | 506.7 | 588.2 | 488.6 | 588.2 |
| Full scan, warm cache | 409.0 | 418.2 | 388.2 | 418.2 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan (median / min–max) | 375.0 MiB (374.8–375.2) |
| Peak BEAM memory, warm scan (median / min–max) | 324.8 MiB (324.3–345.7) |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `libraries`

835 `.beam` files of 11 installed Elixir and Erlang/OTP applications
(0 without debug info); warm cache hit rate 100%.

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Cold extraction, 1 worker | 956.9 | 968.3 | 946.3 | 968.3 |
| Warm cache, 1 worker | 180.9 | 192.9 | 176.5 | 192.9 |
| Cold extraction, 18 workers | 186.5 | 193.7 | 180.8 | 193.7 |
| Warm cache, 18 workers | 81.0 | 87.8 | 74.1 | 87.8 |

| Metric | Value |
| :--- | ---: |
| Atom delta over 10 measured runs of every stage | 0 |


---

## 3. Reading the numbers

* **Warm scans of a medium project take ~120 ms**, well under the 200 ms
  budget, and both `large` and 3-app `umbrella` profiles (~1,000 `.beam` files)
  complete in ~408 ms. CI time is dominated by compiling the project, not by
  the scan.
* **The summary cache pays off across both small and large modules.** On the
  installed libraries, the warm cache is about 5.3× faster than cold extraction
  on one worker and 2.3× faster with 18 workers. On the synthetic profiles,
  warm `.beam` loading is roughly 1.6× faster than cold extraction.
* **Compact v4 summary encoding keeps warm peak memory below cold extraction.**
  Cached summaries store a per-module string table and integer-indexed `MFA`
  references, and the loader unpacks them through a scan-local string pool so
  repeated module and function names share binaries across the scan. On `large`,
  median warm peak memory is 309.5 MiB (down from 823.7 MiB before v4, a 62%
  reduction) versus 334.7 MiB cold.
* **Reports and solver costs reflect full evidence generation.** Rendering four
  formats (including SARIF `codeFlows` / `relatedLocations` and CycloneDX
  `dependsOn` dependency graphs) uses iodata JSON serialization (~61 ms on
  `medium`, ~106 ms on `large`), and pre-read feed validation verifies archive
  integrity on each cache read.
* **Reports are cheap.** Rendering four formats costs a fraction of the
  analysis; writing SBOM and VEX files next to the primary report does not
  change scan times measurably.

---

## 4. Atom-table guarantees

Atoms are never garbage-collected, so a scanner that converted names from
advisories or lockfiles into atoms could exhaust the atom table (1,048,576
entries by default) and crash the VM. VulnCheck keeps every external name as
a binary:

* OSV records, CVE records, lockfiles, `.vulncheck.exs` and
  `.vulncheck.ignore` are parsed into strings and literals; nothing is
  evaluated and `String.to_atom/1` is never called on external input.
* Cached `.beam` summaries are decoded with `:erlang.binary_to_term(bin, [:safe])`.
  Every atom a summary holds is defined by VulnCheck's own modules, which are
  loaded before the first decode, so the safe decoder accepts every cache
  entry in a fresh VM while a tampered cache file that names unknown atoms is
  treated as a cache miss.
* Analyzing a `.beam` file **cold** reads its abstract code with
  `:beam_lib.chunks/2`, which interns the atoms of that compiled module (its
  module, function and literal names). This is bounded by the code that is
  actually installed in the project and happens once per changed file; warm
  runs never read chunks again.

The benchmark reports the atom-count delta over all measured iterations of
every stage, which is **0** for every profile. The test suite enforces the same
guarantees on every run:

| Invariant | Check |
| :--- | :--- |
| Parsing 500 advisories whose module and function names exist nowhere creates no atoms | `:erlang.system_info(:atom_count)` delta is exactly 0 across `OSV.parse_archive/1` and `EefCna.apply_record/2` |
| Repeated warm scans create no atoms | Atom-count delta over five full scans is exactly 0 |
| A warm cache never re-reads unchanged `.beam` files | `:beam_lib.chunks/2` call count is 0 during a warm scan and every module is a cache hit (100%) |
| A changed `.beam` is re-analyzed, unchanged ones are not | Exactly one miss after rebuilding one module |
| Cached summaries decode in a fresh VM | Every atom in summaries of the Elixir standard library belongs to the modules loaded before decoding |
