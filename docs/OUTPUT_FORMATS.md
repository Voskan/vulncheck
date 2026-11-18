# Output Schemas: JSON, SARIF 2.1.0, CycloneDX 1.6 & OpenVEX v0.2.0

All machine-readable outputs produced by `vulncheck` use deterministic key ordering, sorted finding lists, and stable finding `fingerprint` hashes. Serialization is byte-reproducible for a fixed timestamp, while per-run metadata (`generated_at`, `duration_ms`, and SBOM/VEX document serials/timestamps) reflects the scan execution unless a fixed timestamp is supplied.

---

## 1. Native JSON Schema (`--format json`)

```json
{
  "duration_ms": 142,
  "findings": [
    {
      "advisory_id": "EEF-CVE-2026-101028",
      "aliases": [
        "CVE-2026-101028"
      ],
      "context_routines": [],
      "cvss_score": 7.5,
      "cwes": [
        "CWE-863"
      ],
      "fingerprint": "159f0146487b7b5140153f9b6a77bb94432c2ec3383d3cf47abcd1b8f6d04010",
      "fixed_versions": [
        "3.34.6"
      ],
      "installed_version": "3.34.2",
      "package": "ash",
      "package_scope": "prod",
      "reason": "call_chain_proven",
      "reason_detail": "",
      "recommended_fix": "3.34.6",
      "references": [
        "https://cna.erlef.org/cves/CVE-2026-101028.html"
      ],
      "severity": "high",
      "summary": "Ash.count, Ash.exists and Ash.aggregate skip related resources' read policies",
      "suppressed": false,
      "suppression_expired": false,
      "suppression_expires": null,
      "suppression_reason": null,
      "target_mfa": "Ash.Actions.Aggregate.run/4",
      "trace": [
        {
          "file": "lib/my_fintech_web/controllers/report_controller.ex",
          "kind": "entrypoint",
          "line": 41,
          "mfa": "MyFintechWeb.ReportController.index/2"
        },
        {
          "file": "lib/my_fintech/ledger.ex",
          "kind": "static_call",
          "line": 112,
          "mfa": "MyFintech.Ledger.count_filtered_entries/2"
        },
        {
          "file": "deps/ash/lib/ash.ex",
          "kind": "static_call",
          "line": 1184,
          "mfa": "Ash.count/2"
        },
        {
          "file": "deps/ash/lib/ash/actions/aggregate.ex",
          "kind": "static_call",
          "line": 29,
          "mfa": "Ash.Actions.Aggregate.run/4"
        }
      ],
      "verdict": "reachable"
    },
    {
      "advisory_id": "EEF-CVE-2026-103502",
      "aliases": [
        "CVE-2026-103502"
      ],
      "context_routines": [],
      "cvss_score": 5.9,
      "cwes": [],
      "fingerprint": "32cebf59e14a9377e324c49c74ac8afa420d4be22093b3ae7279d4965a75c265",
      "fixed_versions": [
        "0.10.2"
      ],
      "installed_version": "0.10.0",
      "package": "hex_core",
      "package_scope": "prod",
      "reason": "otp_version_unaffected",
      "reason_detail": "requires OTP <= 25; running OTP 27.2",
      "recommended_fix": "0.10.2",
      "references": [],
      "severity": "medium",
      "summary": "hex_core verifies registry signatures with an outdated default on old OTP releases",
      "suppressed": false,
      "suppression_expired": false,
      "suppression_expires": null,
      "suppression_reason": null,
      "target_mfa": ":hex_core.default_config/0",
      "trace": [],
      "verdict": "unreachable"
    }
  ],
  "generated_at": "2026-11-18T09:00:00Z",
  "policy_violations": [],
  "schema_version": "1.0.0",
  "summary": {
    "expired_suppressions": 0,
    "noise_reduction_percent": 50,
    "potentially_reachable": 0,
    "reachable": 1,
    "retired": 0,
    "suppressed": 0,
    "total": 2,
    "unreachable": 1
  },
  "target": {
    "elixir_version": "1.18.2",
    "env": "prod",
    "lockfile": "mix.lock",
    "non_prod_packages_count": 19,
    "otp_release": "27.2",
    "prod_packages_count": 74,
    "project_name": "my_fintech_api",
    "project_type": "mix"
  },
  "tool": {
    "name": "vulncheck",
    "version": "1.0.0"
  },
  "warnings": []
}
```

`cvss_score` and `severity` come from each source of the advisory:

- an Erlang Ecosystem Foundation CNA record gives its published score (`metrics[].cvssV4_0`, else `cvssV3_1`, else `cvssV3_0`);
- an OSV record gives the score computed from its CVSS v4.0 vector, else from its CVSS v3.1 or v3.0 vector.

Within an OSV record, valid ratings for the installed package and version take precedence over the record-wide rating. Within each scope, valid v4.0 vectors take precedence over v3.x vectors. When several sources describe one vulnerability, the highest applicable score wins. Optional JSON fields `cvss_vector`, `cvss_method` and `cvss_source` describe the selected score as one rating. A computed v4.0 score includes the Threat and Environmental metrics when the vector carries them. Scores range from 0.0 to 10.0 and map to `none`, `low`, `medium`, `high` and `critical`. `none` counts as `low` for `--min-severity`. A qualitative label is the fallback when no valid score is available. `unknown` counts as `critical` for the gate.

`trace[].kind` is how each hop was reached: `entrypoint` for the root, then `static_call`, `macro_expanded`, `behaviour_callback`, `supervisor_child`, `dynamic_apply` or `imports`. A chain whose root the project does not call itself (`reason: "daemon_call_chain"`, or a module named in the configuration) starts with a step 0 hop of kind `daemon_activation` or `config_activation`. That hop points to the project code, configuration line or `.app` file that makes the root live, and has a `note` such as `"starts Bandit"`. Its `mfa` is `null` when it points to a file rather than a function. A chain into a protocol client the project uses (`mint`, `gun`, `finch`) contains a hop of kind `incoming_data`: the client function that processes data received from the server, with the note `"processes data received by the mint client"`. Only activation and `incoming_data` hops carry `note`.

`package_scope` is `prod`, `build_only` (a `runtime: false` dependency or a package only such dependencies need) or `non_prod` (`only: [:dev, :test]`).

`context_routines` lists functions that the advisory names on the vulnerable path but that belong to Erlang/OTP, Elixir or another dependency (for example `List.delete/2` in an HTTP/2 advisory). They explain the advisory and are never used as reachability targets.

---

## 2. SARIF 2.1.0 with `codeFlows` (`--format sarif`)

Designed for **GitHub Code Scanning** (`github/codeql-action/upload-sarif`):

- Each unique advisory maps to a `reportingDescriptor` in `tool.driver.rules` with `security-severity` populated from CVSS so GitHub displays accurate `Critical` / `High` / `Medium` / `Low` badges.
- The primary location is the **first trace hop in the project's own code**, including the activation site when present. Paths are normalized relative to the project root. An entirely external trace points to the package's entry in `mix.lock`, `rebar.lock` or `manifest.toml`. GitHub workflow annotations and GitLab Code Quality use the same rule. SARIF includes the remaining project hops in `relatedLocations`.
- `codeFlows[].threadFlows[].locations` encodes the complete multi-hop call trace from entrypoint to vulnerable dependency routine. An activation hop has `executionOrder: 0` and `kinds: ["daemon_activation"]` or `["config_activation"]`; the entrypoint has `executionOrder: 1` and `kinds: ["enter"]`.
- `properties.contextRoutines` lists routines named by the advisory that live outside the vulnerable package (see `context_routines` below); they are never targets.
- `UNREACHABLE` advisories are omitted by default (or emitted with `level: "none"` when `--show-unreachable` is passed).
- `partialFingerprints.primaryLocationLineHash` carries the finding fingerprint (stable across runs), so Code Scanning tracks alerts across commits instead of reopening them.

---

## 3. OpenVEX v0.2.0 (`--vex vex.openvex.json`)

Compliance frameworks (SOC 2, PCI DSS v4.0, ISO 27001, EU CRA) increasingly require machine-verifiable **Vulnerability Exploitability eXchange (VEX)** documents explaining why unpatched transitive CVEs in an SBOM do not impact production.

`vulncheck` maps its formal verdicts directly to official OpenVEX v0.2.0 statuses and justifications:

| VulnCheck Verdict & Reason | OpenVEX `status` | OpenVEX `justification` |
| :--- | :--- | :--- |
| `REACHABLE` | `"affected"` | — (`action_statement` lists fixed version) |
| `POTENTIALLY_REACHABLE` | `"under_investigation"` | — (`status_notes` explains the reason) |
| `UNREACHABLE` (`function_not_called`, `module_not_loaded`, `adapter_not_configured`, `otp_app_not_started`) | `"not_affected"` | `"vulnerable_code_not_in_execute_path"` |
| `UNREACHABLE` (`non_prod_dependency` of a build-time only package, `runtime: false`) | `"not_affected"` | `"vulnerable_code_not_in_execute_path"` |
| `UNREACHABLE` (`non_prod_dependency` of a `:dev`/`:test` package) | `"not_affected"` | `"component_not_present"` |
| `UNREACHABLE` (`otp_version_unaffected`) | `"not_affected"` | OTP constraint in `impact_statement` |

Policy suppressions preserve the original vulnerability status in OpenVEX and CycloneDX. Both formats include the complete scan snapshot before diff and baseline filtering.

Retired Hex releases produce no VEX statements. When a scan has zero statements, the CLI reports that OpenVEX was omitted on stderr and leaves stdout or a new destination empty. An existing OpenVEX destination produces exit code `2` and preserves the file so automation can distinguish a stale artifact. The API returns `nil` from `OpenVEX.document/3` and an empty string from `OpenVEX.encode/3`. The document `@id` is derived from the content.

---

## 4. CycloneDX 1.6 SBOM (`--sbom sbom.cdx.json`)

Generates a standards-compliant CycloneDX 1.6 Bill of Materials for the BEAM release:
- Component `purl` identifiers in canonical Hex format (`pkg:hex/phoenix@1.7.18`), plus git commit refs for git dependencies.
- `scope: "required"` for `:prod` runtime packages and `scope: "excluded"` for `:dev`/`:test`-only dependencies.
- A `dependencies` graph built from the lockfile's dependency edges, with the project's direct dependencies (from `mix.exs`, `rebar.config` or `gleam.toml`) as the root component's `dependsOn`.
- `vulnerabilities[].analysis` records `exploitable` for a reachable match, `in_triage` for a potential match, and `not_affected` with `code_not_reachable`, `code_not_present` or `requires_environment` as supported by the evidence. Retired releases are omitted from the vulnerability list.
- SHA-256 component hashes from the lockfile checksums and a deterministic `serialNumber`, so identical scans produce identical SBOMs.
- The project component's reference includes the declared project version when available and a `scan_scope` digest. It identifies the dependency inventory, runtime and any analyzed compiled evidence. The VEX product uses the same identifier. CycloneDX metadata gives the build profile, evidence status and snapshot scope. The identifier covers the scanned workspace and is scoped to the supplied OTP environment. Aliases for the same package URL have distinct component references in both outputs.
