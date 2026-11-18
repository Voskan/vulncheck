# Contributing to VulnCheck

Thank you for your interest in contributing to `vulncheck`.

## Design Principles

Before opening a pull request, please keep these architectural invariants in mind:

1. **Zero Runtime Hex Dependencies:** Do not add runtime packages to `mix.exs`. Development-only tools (`ex_doc`, `dialyxir`) must be restricted to `only: [:dev, :test], runtime: false`.
2. **Soundness First (No False Negatives):** Never mark an advisory `UNREACHABLE` unless its non-execution is proven by static `.beam` call-graph absence, inactive OTP application/adapter configuration, non-production dependency scope, or an explicit OTP/Elixir runtime version constraint. When dynamic dispatch (`apply/3`) or active OTP supervision makes static proof incomplete, classify as `POTENTIALLY_REACHABLE`.
3. **100% Offline Deterministic Tests:** Every test in `mix test` must run completely offline using local HTTP test listeners and temporary `.beam` fixtures compiled in `System.tmp_dir!/0`. No test may contact `osv.dev`, `cna.erlef.org`, or `hex.pm`.
4. **Post-Macro Bytecode Analysis:** Always analyze `.beam` chunks (`:abstract_code`) rather than raw `.ex` source strings so macro-expanded `Phoenix`, `Plug`, `Ecto`, `Ash`, and `Oban` call edges are captured accurately across Elixir, Erlang, and Gleam.

## Local Development Workflow

Prerequisites:
- **Erlang/OTP:** 27.0 or newer (compatible down to OTP 26)
- **Elixir:** 1.18 or newer

Run the full verification suite locally before submitting changes:

```bash
mix compile --warnings-as-errors
mix format --check-formatted
mix test
mix vulncheck
```

## Pull Request Checklist

- [ ] Code compiles cleanly with `--warnings-as-errors`.
- [ ] `mix format --check-formatted` passes with zero diffs.
- [ ] Every new reachability rule or parser includes both positive (`REACHABLE` / `POTENTIALLY_REACHABLE`) and negative (`UNREACHABLE`) fixture tests.
- [ ] Documentation in `README.md` and `docs/` is updated if CLI flags, configuration keys, or output schemas change.
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `perf:`, `refactor:`).
