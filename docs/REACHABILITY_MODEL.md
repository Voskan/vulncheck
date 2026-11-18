# BEAM Reachability Model & Soundness Guarantees

A vulnerability scanner loses credibility the moment a single real production exposure is falsely hidden as "unreachable." `vulncheck` follows a **soundness-first** design tailored to Erlang/OTP, Elixir, and Gleam execution semantics.

---

## Why Go's `govulncheck` Model Cannot Be Copied Verbatim to the BEAM

In statically linked languages like Go, execution starts at `main.main()` and package `init()` functions; if a function cannot be reached through static calls or interface VTA edges from `main`, it is dead code.

On the BEAM, four runtime mechanisms invoke functions without a direct static `Mod.fun(...)` call in user modules:

1. **OTP Supervision Trees & Included Applications:** Adding `{Bandit, plug: MyAppWeb.Endpoint}` in `MyApp.Application.start/2` starts a supervision subtree inside `:bandit` and `:thousand_island` via `:supervisor` callbacks. User code never calls `Bandit.HTTP2.*` directly, yet every inbound TCP/TLS packet hits those routines.
2. **Behaviours & Process Mailboxes:** Calling `GenServer.call(pid, msg)` invokes `:gen_server.call/3`, which sends a message handled asynchronously by `TargetServer.handle_call/3`.
3. **Compile-Time Macro Expansion:** `plug Plug.Parsers, parsers: [:urlencoded, :json]` expands into generated `Plug` pipeline clauses inside the compiled `.beam` module. Reading raw `.ex` source misses the generated calls; reading `.beam` `:abstract_code` sees the exact expanded parser modules!
4. **Configuration-Driven Dynamic Adapters (`apply/3`):** Libraries like `Tesla` or `Swoosh` read an adapter module from `Application.get_env/3` or module attributes and invoke `apply(adapter, :call, [env, opts])`.

---

## Three-Tier Verdict Taxonomy

Every advisory matching a package version in the lockfile receives exactly one of three verdicts. A fourth, `RETIRED` (reason `package_retired`), reports a locked release that its maintainers retired on Hex.pm (severity follows the retirement reason: `security` is high, `invalid` medium, `deprecated` and `renamed` low); it is a package lifecycle status and is excluded from SBOM vulnerabilities and VEX statements.

### 1. `REACHABLE` (High-Confidence Proof of Execution Path)

Assigned when **both** conditions hold:
- The advisory specifies one or more target MFA symbols (`programRoutines`) or modules; **and**
- There exists a directed path in the post-macro `.beam` + behaviour-linked call graph from a production root $r \in R$ to at least one vulnerable `Module.fun/arity`.

**Output:** `vulncheck` prints the shortest witness call trace from the entrypoint in user code down to the vulnerable dependency function, with source file and line numbers at each hop.

### 2. `POTENTIALLY_REACHABLE` (Conservative Soundness Boundary)

Assigned when static non-reachability **cannot** be proven safely:
- **Network / Runtime Daemon Exposure:** The vulnerable package is an active OTP server/listener in the production application tree (`:bandit`, `:cowboy`, `:cowlib`, `:ranch`, `:thousand_island`, `:grpc`, `:plug_cowboy`) and the vulnerable module belongs to its active protocol stack.
- **Unresolved Dynamic Dispatch:** A reachable module invokes `apply(mod_var, fun_var, args)` where target module/function candidates cannot be narrowed away from the vulnerable module, and the vulnerable dependency's OTP application is loaded in `:prod`. A dynamic call can only name a module whose atom reaches it: one written in reachable code or configuration, one built with `Module.concat/1,2` or `Module.safe_concat/1,2` anywhere in reachable code (outside modules whose dynamic calls a framework rule resolves, such as `Plug.Parsers`), or one converted from a string (`String.to_atom/1`, `:erlang.binary_to_atom/2`, ...) in the module that makes the call. Each such call site that keeps advisories open is listed in the report warnings.
- **Missing Symbol Granularity:** An upstream advisory lacks `programRoutines` and module-level hints, and at least one function in the vulnerable package is reachable in `:prod`.
- **Missing `.beam` Debug Info:** A dependency `.beam` was compiled with `debug_info` stripped, preventing call-graph traversal inside that dependency.

### 3. `UNREACHABLE` (Proven Safe to Suppress in Production)

Assigned **only** when `vulncheck` establishes a concrete, auditable proof of non-execution, tagged with one of six deterministic reasons:

| Reason Code | Proof Condition | Real-World Example |
| :--- | :--- | :--- |
| `non_prod_dependency` | Package is outside the `:prod` runtime closure (`only: [:dev, :test]` or build-time only). | CVE in `meck` or `ex_doc`. |
| `otp_version_unaffected` | Advisory explicitly restricts the vulnerability to an OTP release range that excludes the target runtime (`--otp-version` or the running VM). | `EEF-CVE-2026-103502` (`hex_core` on OTP $\le$ 25 when running on OTP 27). |
| `otp_app_not_started` | Transitive dependency is neither in the `:prod` release boot tree nor referenced by any reachable module/config. | Unused transitive HTTP client pulled as optional dep. |
| `adapter_not_configured` | Package is an optional adapter (`Tesla.Adapter.Hackney`, `Swoosh.Adapters.*`) and neither project config nor `.beam` constants reference that adapter module. | `hackney` advisories when Tesla is configured with `Tesla.Adapter.Mint` or `Tesla.Adapter.Finch`. |
| `module_not_loaded` | Advisory specifies affected modules (`modules` / `programRoutines`), no dynamic `apply/3` escapes toward the package, and zero functions in the affected module are reachable. | `Plug.Parsers.MULTIPART` CVE when `Plug.Parsers` is compiled with `parsers: [:json]` only. |
| `function_not_called` | Advisory specifies exact `programRoutines` MFAs, `.beam` debug chunks are intact across the call boundary, no unresolved `apply/3` targets the module, and none of the vulnerable MFAs appear in the reachable closure. | `Ash.count/2` (`Ash.Actions.Aggregate.run/4`) CVE when app only uses `Ash.read/2` and `Ash.create/2`. |

### Routines Outside the Vulnerable Package

CVE records sometimes list functions on the vulnerable path that are not part of the vulnerable package: standard library calls such as `List.delete/2` or `Enum.map_join/3`, or functions of another dependency. Those are reachable in almost any project, so a path to them proves nothing about the package. `vulncheck` keeps only the routines and modules of the vulnerable package as targets (a module counts as part of the package when its compiled `.beam` belongs to the package, or when no compiled module of that name exists and it does not ship with Erlang/OTP or Elixir). The rest are reported as `context_routines`. When an advisory names only routines outside the package, it is evaluated at package level and `function_not_called` is never concluded from it.

---

## Handling NIFs and Erlang Modules

- **Erlang Dependencies (`:cowlib`, `:hackney`, `:gun`, `:jose`):** Because Erlang and Elixir compile to the same `.beam` `abstract_code` format, `vulncheck` traverses mixed `Elixir -> Erlang -> Elixir` call chains seamlessly without language bridges.
- **Native Implemented Functions (NIFs):** When an advisory targets a Rustler or C NIF stub (`:erlang.load_nif/2`), the Elixir/Erlang wrapper MFA in the host module serves as the reachability sink in the `.beam` call graph.
