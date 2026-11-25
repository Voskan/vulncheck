# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-11-25

### Fixed

#### Soundness & Data Safety
- Close `Phoenix.Controller` narrowing bypasses (`Behaviours`, `AbstractWalker`): direct external `Ctrl.action/2` calls, `&Ctrl.call/2` and `&Ctrl.action/2` function captures, dynamic atom/module builders in project code, controllers referenced via `config/*.exs` or dynamic `Application.get_env`, 4-tuple route spoofing outside `__match_route__`/`match`, mixed bare controller refs inside `__match_route__`/`match`, and unattributed controller module references in the presence of unresolved `mod.call/2` dispatch now preserve sound `:potentially_reachable` verdicts without breaking normal `Phoenix.Router` + `Bandit`/`Cowboy` precision. Salted the `.beam` summary cache key (`walker-v5`).
- Preserve full dependency scopes in `MixProject` static `mix.exs` analysis when calling `defp deps(:common)` with literal env atoms (removing erroneous narrowing to `[env_name]`), merge duplicate dependencies across branches by unioning `only:` / `runtime:` scopes, and resolve default arguments on `defp deps(env \\ Mix.env())`.
- Follow `import_config` directives (static paths and `"#{config_env()}.exs"` / `"#{Mix.env()}.exs"` templates, with cycle detection, symlink-safe realpath root containment, and optional `File.exists?` guard handling), detect nested dynamic adapter expressions (keyword lists, maps, structs, tuples, `Application.put_env` / `put_all_env`), and propagate `Code.eval_*` / dynamic atom and module constructors (`String.to_existing_atom`, `Module.concat`, `binary_to_term`, `apply`) from `config/*.exs` into `Adapters`, `Behaviours`, and `Solver`.
- Check compiled artifact issues and dynamic escapes before dismissing `:build_only` (`runtime: false`) dependencies in `Solver`, preventing false negatives when a build-only package is uncompiled or targeted by a package-level CVE.
- Isolate `vulncheck feeds sync|status|bundle|import|prune` from ambient scan-specific `.vulncheck.exs` keys (`output`, `offline`) so `feeds bundle` never overwrites the project's scan output file and `feeds sync` never fails due to `offline: true` in `.vulncheck.exs`; expand relative bundle paths in `feeds import` against `:cwd`.

#### Configuration, Baselines, Suppressions & Parsers
- Canonicalize relative file paths from `.vulncheck.exs` (`output`, `sarif`, `sbom`, `vex`, `bundle`, `cache_dir`, `baseline`) against the project root so `--project-dir` runs resolve paths consistently and overlapping output destinations are detected; accept `max_feed_age_seconds: nil` in `.vulncheck.exs`.
- Stabilize `Diff.identity/1` across pre-compile and post-compile scans by hashing lockfile `deps` (`Package.lock_deps`) rather than `.app`-enriched dependency lists.
- Match `.vulncheck.ignore` rules and baselines case-insensitively by advisory ID, alias, or CVE ID, normalize case in `Ignore.new_suppressions/2`, and report an explicit policy violation when `--forbid-new-suppressions` points to an ignore file outside the Git repository.
- Fix `Semver` pessimistic `~>` operator upper bounds for 3+ version segments (`~> 25.3.2` now enforces `< 25.4` instead of `< 26`).
- Extend `MFA.parse_routine/1` to parse Elixir/Erlang operators (`==/2`, `../2`, `..//3`), `MACRO-*` compiler-generated macro names, and single-quoted Erlang function names.
- Harden `HTTP` redirect SSRF checks to reject IPv6 zone identifiers (`%`), IPv4 multicast/reserved (`224.0.0.0/4`, `240.0.0.0/4`), IPv4-compatible IPv6 (`::a.b.c.d`), deprecated IPv6 site-local (`fec0::/10`), and IPv6 multicast (`ff00::/8`).
- Reuse `GitUrl.github_repo/1` in `CycloneDX` so non-GitHub hosts (e.g., `not-github.com`) never emit `pkg:github/` PURLs and `.GIT` suffixes are stripped case-insensitively.
- Omit `physicalLocation` when `file` is empty and clamp `startLine >= 1` in `SARIF`; merge multi-package findings sharing an `advisory_id` into combined rule metadata (`help`, `fullDescription`, `cwes`, `level`, `precision`).
- Preserve all detected adapters per family as a list in `vulncheck init` (`adapter_lines/2`), reject extra arguments after `--version`/`-v`/`version`, and parse `help?/1` via `OptionParser` so `--diff -h` / `--output -h` are not intercepted as help flags.
- Preserve full tag versions (stripping leading `v`) instead of truncating to 12 characters for `{git, Url, {tag, Tag}}` entries in `RebarLock`.
- Support leading `+`, underscores in based integers and floats, `\b`/`\d`/`\f`/`\v`/`\xHH`/`\x{HEX}`/octal escapes, and binary segment `:size`/`/type` specifiers in `ErlTerm`.
- Add `@max_depth 128`, CRLF multiline handling, strict hex validation on `\b`/`\f`/`\uXXXX`/`\UXXXXXXXX` escapes, backslash line-ending trimming, embedded quotes before closing `"""`/`'''`, and literal-string newline rejection to `Toml`.
- Escape pipes in Markdown `suppressed` and `unreachable` table cells, make `Report.GitHub.render/2` pure (moving `GITHUB_STEP_SUMMARY` writing with error warnings into `CLI.write_outputs/3`), document single-letter sigil atom bounds in `Literal`, sync documentation and `CI` OTP 28/29 matrix, and silence intentional crash logs in `ExtractorTest`.

## [1.0.2] - 2026-11-24

### Fixed

#### Soundness
- Preserve Erlang and Gleam module atoms in tuple heads and map keys (`AbstractWalker`), so Erlang supervision child specs (`{:my_erl_worker, arg}`) and dynamic `apply(mod, fun, args)` targets are no longer dropped from `module_refs`. Salted the `.beam` summary cache key (`walker-v3`) so stale `1.0.1` cache entries automatically recompute.
- Extract explicit function captures (`&Mod.fun/arity`, `&:erl_mod.fun/arity`), shorthand captures (`&Mod.fun(&1, ...)`), closure/remote calls (`fn x -> Mod.fun(x, :opt) end`), literal MFA 3-tuples, and Erlang module atoms (including 2nd-argument module keys in `config :app, :erl_mod, opts`) from `config/*.exs` into entrypoint roots (`Adapters`, `Entrypoints`), and track unparseable configs or dynamic fun creation (`Function.capture`, `:erlang.make_fun`, `:erlang.binary_to_term`, `Code.eval_*`, `:erl_eval`) via `EntrypointModel.untracked_fun_sources`.
- Treat `:erlang.binary_to_term/1,2`, `Plug.Crypto.non_executable_binary_to_term/1,2`, `Code.eval_string/1..3`, `Code.eval_quoted/1..3`, `:file.consult/1`, `:erl_eval.exprs/2..4`, and `:erl_eval.expr/2..5` as module builders in `Solver`, emit unconstrained dynamic call sites for `Code.eval_*` and `:erl_eval` in `AbstractWalker`, and include reachable `:function_value` call sites in dynamic escapes whenever `untracked_fun_sources` is true or an executable fun constructor (`:erlang.binary_to_term/1,2`, `Code.eval_*`, `:erl_eval`) is reachable (while keeping `Plug.Crypto.non_executable_binary_to_term/1,2` excluded from fun escapes).
- Run `.beam` call-graph analysis in `Scanner` when `:build_only` (`runtime: false`) dependencies have advisories, so direct runtime calls from production code into a `runtime: false` dependency are reported as `REACHABLE` instead of skipped as `:non_prod_dependency`.
- Recognize custom `Plug.Parsers` modules (implementing `@behaviour Plug.Parsers` or exporting `parse/5`) in compiled `Plug.Parsers.call/2` options and fallback `:all` parser discovery, while preserving `:dynamic_candidate` attribution.
- Wire `:gen_statem` / `GenStatem` exported arity 3 and 4 state functions (`state_functions` callback mode) and `:cowboy_rest` exported arity 2 callbacks/media-type handlers (plus `terminate/3`) as behaviour callbacks.

#### Precision & Static Parsers
- Resolve proven `Phoenix.Router` -> `Phoenix.Controller` action dispatch across direct `Controller.call(conn, :action)`, `Plug.Builder` `Controller.call(conn, Controller.init(:action))`, and Phoenix 1.7+ `__match_route__/4` `{Controller, :action}` route tuples (scoped to router match functions and 4-tuple route structures), emitting proven `:behaviour_callback` edges to routed actions while falling back soundly when custom `action/2` hooks, dynamic options, or external `apply(Controller, :call, ...)` calls are present; resolve `Phoenix.Router` plug dispatch to reachable plugs.
- Overhaul `MixProject` static `mix.exs` parsing to support multi-clause `defp deps(:prod)` / `defp deps(_)` helpers, delegated `project/0` helpers, `++`, `|>`, `Keyword.merge/2`, `List.flatten/1`, `~w(...)a` atom sigils, module attributes (`@project`, `@version`), multi-statement blocks, boolean `if`/`unless`/`case`/`cond` expressions (`==`, `!=`, `in`, `not`, `or`/`||`, `and`/`&&`) on `Mix.env()`, and 3-tuple deps with `@version` without descending into keyword options; track `Workspace.direct_deps_known` so `CycloneDX` only falls back to lockfile roots when direct dependencies are unknown.
- Make `ErlTerm.parse/1` total on malformed inputs (invalid integer bases outside `2..36`, malformed floats like `1.2e+.`, invalid UTF-8 bytes inside quoted atoms, escapes, and character literals, and terms exceeding `@max_depth 128` return `{:error, _}` instead of raising).
- Fix `Toml.parse/1` boolean prefix splitting (`true_val`), quoted dotted key paths (`"a.b".c`, `[ "x.y".z ]`), `[table.sub]` subtables under `[[array_of_tables]]`, and reject empty table headers (`[]`, `[[]]`) and empty key segments (`[a..b]`).

#### Security, Compliance & CI
- Harden `Cache.get_beam_packed/2` and `BeamCodec.valid?/2` against poisoned `.etf` files: reject compressed ETF payloads declaring uncompressed sizes above `@max_beam_unpacked_bytes` before calling `:erlang.binary_to_term/2`, handle non-tuple entries and improper lists in all validators, and validate `attributes` values and `init_literals` arguments with a depth-bounded literal check.
- Emit 1-based SARIF 2.1.0 `executionOrder` values (`>= 1` per §3.38.6) in `codeFlows` while preserving `0.` activation labels in `location.message.text`.
- Route rejected `.vulncheck.ignore` entries into `policy_violations` in `Ignore.step/1` so malformed, missing-reason, or missing/invalid-expiry rules fail with exit code `1`.
- Isolate non-GitHub hosts, strip `.git` suffixes case-insensitively, and preserve nested GitLab subgroups in `GitUrl.normalize_repo/1` (`gitlab.com/group/subgroup/repo`, `git.corp.internal/owner/repo`), plus support `pkg:gitlab/` and `pkg:bitbucket/` PURLs in `EefCna`.
- Prefix monorepo `--project-dir` paths relative to the Git repository root (`GITHUB_WORKSPACE`, `CI_PROJECT_DIR`, or nearest `.git` ancestor) in `GitHub`, `GitLab`, and `SARIF` (`locations`, `relatedLocations`, and `codeFlows`).
- Block HTTPS-to-HTTP scheme downgrades and SSRF redirects from external origins to IPv4/IPv6 loopback, unspecified (`0.0.0.0`, `::`), IPv4-mapped IPv6, `*.localhost`, link-local/cloud-metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT, and RFC 1918 / RFC 4193 private addresses in `HTTP` (`{:error, {:insecure_url, target}}`).
- Reconcile `VulnCheck.Config.adapter_families/0` with `VulnCheck.Entrypoints.Adapters` by removing unimplemented `:finch` and `:req` family keys.
- Use a UTC daily cache key (`vulncheck-feeds-<os>-<YYYY-MM-DD>`) instead of `github.run_id` in `action.yml` and `.github/workflows/ci.yml`, and populate GitHub Releases directly from the matching `CHANGELOG.md` section in `.github/workflows/release.yml`.
- Sync `vulncheck --help` (`feeds import`, `feeds prune`, `--bundle`, `--max-feed-age` alignment), `Mix.Tasks.Vulncheck` docs, `README.md`, and `docs/*.md`.

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

[Unreleased]: https://github.com/Voskan/vulncheck/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/Voskan/vulncheck/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Voskan/vulncheck/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Voskan/vulncheck/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Voskan/vulncheck/releases/tag/v1.0.0
