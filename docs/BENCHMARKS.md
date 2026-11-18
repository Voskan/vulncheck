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

The `libraries` profile measures the `.beam` summary cache on real code: the
`ebin` directories of the Elixir and Erlang/OTP applications installed with the
running VM (`kernel`, `stdlib`, `compiler`, `crypto`, `inets`, `ssl`,
`public_key`, `elixir`, `logger`, `eex`, `mix`).

Each stage runs once to warm up (loading VulnCheck's own modules and filling
the cache), then is timed with `:timer.tc/1` for the configured number of
iterations. Every sample runs in a fresh process, as a CLI invocation would,
so garbage collection never scans results kept alive by earlier stages.
Reported values are the median, p95, minimum and maximum. Peak memory is
`:erlang.memory(:total)` sampled every 2 ms during one cold and one warm scan.

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
| VulnCheck | 1.0.0 |

10 measured iterations per stage after one warm-up run.

### Profile `medium`

80 packages, 421 `.beam` files, ~4620 functions, 42093 call edges,
50 advisories with `programRoutines` (25 reachable, 25 unreachable).

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Lockfile and configuration | 8.0 | 9.1 | 7.8 | 9.1 |
| Advisory feeds (offline cache) | 6.6 | 7.3 | 6.4 | 7.3 |
| Cold .beam extraction | 59.1 | 61.3 | 57.4 | 61.3 |
| Warm .beam summaries (SHA-256 cache) | 37.4 | 38.8 | 35.4 | 38.8 |
| Entrypoints, call graph and solver | 88.0 | 90.8 | 87.2 | 90.8 |
| Reports (terminal, sarif, cyclonedx, openvex) | 78.6 | 80.8 | 78.1 | 80.8 |
| Full scan, cold .beam cache | 146.2 | 150.5 | 143.7 | 150.5 |
| Full scan, warm cache | 117.6 | 119.4 | 115.7 | 119.4 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan | 171.6 MiB |
| Peak BEAM memory, warm scan | 203.0 MiB |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `large`

180 packages, 1001 `.beam` files, ~13000 functions, 120273 call edges,
120 advisories with `programRoutines` (60 reachable, 60 unreachable).

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Lockfile and configuration | 16.5 | 19.2 | 16.1 | 19.2 |
| Advisory feeds (offline cache) | 15.2 | 16.0 | 14.9 | 16.0 |
| Cold .beam extraction | 152.3 | 158.2 | 149.7 | 158.2 |
| Warm .beam summaries (SHA-256 cache) | 95.5 | 100.0 | 90.3 | 100.0 |
| Entrypoints, call graph and solver | 298.4 | 314.7 | 292.7 | 314.7 |
| Reports (terminal, sarif, cyclonedx, openvex) | 120.5 | 158.2 | 119.4 | 158.2 |
| Full scan, cold .beam cache | 497.4 | 600.0 | 472.6 | 600.0 |
| Full scan, warm cache | 438.9 | 480.9 | 403.3 | 480.9 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan | 334.7 MiB |
| Peak BEAM memory, warm scan | 441.4 MiB |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `libraries`

835 `.beam` files of 11 installed Elixir and Erlang/OTP applications
(0 without debug info); warm cache hit rate 100%.

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Cold extraction, 1 worker | 922.3 | 942.9 | 910.9 | 942.9 |
| Warm cache, 1 worker | 197.1 | 219.5 | 181.6 | 219.5 |
| Cold extraction, 18 workers | 181.3 | 184.9 | 172.5 | 184.9 |
| Warm cache, 18 workers | 83.5 | 89.6 | 79.4 | 89.6 |

| Metric | Value |
| :--- | ---: |
| Atom delta over 10 measured runs of every stage | 0 |


---

## 3. Reading the numbers

* **Warm scans of a medium project take about 118 ms**, well under the
  200 ms budget, and the large profile stays under half a second (439 ms). CI
  time is dominated by compiling the project, not by the scan.
* **The summary cache pays off across both small and large modules.** On the
  installed libraries, the warm cache is about 4.7× faster than cold extraction
  on one worker and over 2× faster with 18 workers. On the synthetic profiles,
  warm `.beam` loading is roughly 1.6× faster than cold extraction.
* **Compact v4 summary encoding keeps warm peak memory bounded.** Cached
  summaries store a per-module string table and integer-indexed `MFA` references,
  and the loader unpacks them through a scan-local string pool so repeated
  module and function names share binaries across the scan. On the large profile,
  warm peak memory dropped from 823.7 MiB to 441.4 MiB (a 46% reduction).
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
