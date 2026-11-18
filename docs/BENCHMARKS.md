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
| Lockfile and configuration | 7.7 | 8.9 | 7.5 | 8.9 |
| Advisory feeds (offline cache) | 2.7 | 3.0 | 2.6 | 3.0 |
| Cold .beam extraction | 53.4 | 56.5 | 51.9 | 56.5 |
| Warm .beam summaries (SHA-256 cache) | 57.2 | 62.0 | 51.7 | 62.0 |
| Entrypoints, call graph and solver | 53.7 | 56.9 | 53.3 | 56.9 |
| Reports (terminal, sarif, cyclonedx, openvex) | 36.2 | 36.9 | 35.9 | 36.9 |
| Full scan, cold .beam cache | 121.5 | 128.9 | 119.5 | 128.9 |
| Full scan, warm cache | 130.8 | 135.0 | 126.2 | 135.0 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan | 196.0 MiB |
| Peak BEAM memory, warm scan | 284.5 MiB |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `large`

180 packages, 1001 `.beam` files, ~13000 functions, 120273 call edges,
120 advisories with `programRoutines` (60 reachable, 60 unreachable).

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Lockfile and configuration | 18.1 | 21.4 | 16.4 | 21.4 |
| Advisory feeds (offline cache) | 6.0 | 6.6 | 5.8 | 6.6 |
| Cold .beam extraction | 145.8 | 155.2 | 139.1 | 155.2 |
| Warm .beam summaries (SHA-256 cache) | 169.3 | 185.1 | 149.6 | 185.1 |
| Entrypoints, call graph and solver | 267.9 | 276.6 | 265.1 | 276.6 |
| Reports (terminal, sarif, cyclonedx, openvex) | 55.6 | 61.7 | 55.3 | 61.7 |
| Full scan, cold .beam cache | 387.2 | 392.8 | 350.4 | 392.8 |
| Full scan, warm cache | 421.3 | 448.6 | 412.9 | 448.6 |

| Metric | Value |
| :--- | ---: |
| Peak BEAM memory, cold scan | 513.4 MiB |
| Peak BEAM memory, warm scan | 823.7 MiB |
| Atom delta over 10 measured runs of every stage | 0 |

### Profile `libraries`

835 `.beam` files of 11 installed Elixir and Erlang/OTP applications
(0 without debug info); warm cache hit rate 100%.

| Stage | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: | ---: |
| Cold extraction, 1 worker | 902.8 | 907.6 | 901.2 | 907.6 |
| Warm cache, 1 worker | 221.1 | 222.2 | 220.5 | 222.2 |
| Cold extraction, 18 workers | 179.6 | 187.8 | 173.6 | 187.8 |
| Warm cache, 18 workers | 136.5 | 154.9 | 130.1 | 154.9 |

| Metric | Value |
| :--- | ---: |
| Atom delta over 10 measured runs of every stage | 0 |


---

## 3. Reading the numbers

* **Warm scans of a medium project take about 130 ms**, well under the
  200 ms budget, and the large profile stays under half a second. CI time is
  dominated by compiling the project, not by the scan.
* **The summary cache pays off where analysis is expensive.** On the installed
  libraries, whose modules are large and varied, the warm cache is about 4×
  faster than cold extraction on one worker and still faster with one worker
  per scheduler. On the synthetic profiles every function body is small and
  call-dense, so analysis costs about as much as decoding a cached summary,
  and cold and warm scans land within roughly 10% of each other.
* **Warm scans hold more memory at peak.** A summary decoded from the cache does
  not share sub-terms the way one built by the analyzer does (the same
  function reference used by many call edges is one term in memory before
  caching and many copies after decoding), so the large profile peaks around
  800 MiB warm against about 500 MiB cold. Projects of ordinary size stay
  within a few hundred MiB.
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
