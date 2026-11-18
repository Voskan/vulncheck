# Output Schemas: JSON, SARIF 2.1.0, CycloneDX 1.6 & OpenVEX v0.2.0

All machine-readable outputs produced by `vulncheck` use deterministic key ordering and sorted finding lists so CI artifacts and baselines are byte-reproducible.

---

## 1. Native JSON Schema (`--format json`)

```json
{
  "schema_version": "1.0.0",
  "tool": {
    "name": "vulncheck",
    "version": "1.0.0"
  },
  "target": {
    "project_name": "my_fintech_api",
    "project_type": "mix",
    "env": "prod",
    "elixir_version": "1.18.2",
    "otp_release": "27",
    "prod_packages_count": 74,
    "non_prod_packages_count": 19
  },
  "summary": {
    "reachable": 1,
    "potentially_reachable": 1,
    "unreachable": 9,
    "retired": 0,
    "suppressed": 0
  },
  "findings": [
    {
      "advisory_id": "EEF-CVE-2026-101028",
      "aliases": ["CVE-2026-101028", "GHSA-xj24-8f5c-pp5p"],
      "package": "ash",
      "installed_version": "3.34.2",
      "fixed_versions": ["3.34.6"],
      "severity": "high",
      "cvss_score": 7.5,
      "verdict": "reachable",
      "reason": "call_chain_proven",
      "target_mfa": "Ash.Actions.Aggregate.run/4",
      "trace": [
        {
          "mfa": "MyFintechWeb.ReportController.index/2",
          "file": "lib/my_fintech_web/controllers/report_controller.ex",
          "line": 41
        },
        {
          "mfa": "MyFintech.Ledger.count_filtered_entries/2",
          "file": "lib/my_fintech/ledger.ex",
          "line": 112
        },
        {
          "mfa": "Ash.Actions.Aggregate.run/4",
          "file": "deps/ash/lib/ash/actions/aggregate.ex",
          "line": 29
        }
      ]
    }
  ]
}
```

---

## 2. SARIF 2.1.0 with `codeFlows` (`--format sarif`)

Designed for **GitHub Code Scanning** (`github/codeql-action/upload-sarif`):

- Each unique advisory maps to a `reportingDescriptor` in `tool.driver.rules` with `security-severity` populated from CVSS so GitHub displays accurate `Critical` / `High` / `Medium` / `Low` badges.
- `primaryLocation` points to the **first call site inside the user's own repository** (or `mix.lock` line when triggered via OTP daemon supervision), ensuring GitHub annotates pull requests directly on the relevant code.
- `codeFlows[].threadFlows[].locations` encodes the complete multi-hop call trace from entrypoint to vulnerable dependency routine.
- `UNREACHABLE` advisories are omitted by default (or emitted with `level: "none"` when `--show-unreachable` is passed).

---

## 3. OpenVEX v0.2.0 (`--vex vex.openvex.json`)

Compliance frameworks (SOC 2, PCI DSS v4.0, ISO 27001, EU CRA) increasingly require machine-verifiable **Vulnerability Exploitability eXchange (VEX)** documents explaining why unpatched transitive CVEs in an SBOM do not impact production.

`vulncheck` maps its formal verdicts directly to official OpenVEX v0.2.0 statuses and justifications:

| VulnCheck Verdict & Reason | OpenVEX `status` | OpenVEX `justification` |
| :--- | :--- | :--- |
| `REACHABLE` | `"affected"` | — (`action_statement` lists fixed version) |
| `POTENTIALLY_REACHABLE` | `"under_investigation"` | — |
| `UNREACHABLE` (`function_not_called`, `module_not_loaded`, `adapter_not_configured`, `otp_app_not_started`) | `"not_affected"` | `"vulnerable_code_not_in_execute_path"` |
| `UNREACHABLE` (`non_prod_dependency`, `otp_version_unaffected`) | `"not_affected"` | `"vulnerable_code_not_present"` |

---

## 4. CycloneDX 1.6 SBOM (`--sbom sbom.cdx.json`)

Generates a standards-compliant CycloneDX 1.6 Bill of Materials for the BEAM release:
- Component `purl` identifiers in canonical Hex format (`pkg:hex/phoenix@1.7.18`), plus git commit refs for git dependencies.
- `scope: "required"` for `:prod` runtime packages and `scope: "excluded"` for `:dev`/`:test`-only dependencies.
- Full `dependencies` graph reflecting `.app` and `mix.lock` edges, plus embedded `vulnerabilities[].analysis` blocks matching the reachability verdict.
