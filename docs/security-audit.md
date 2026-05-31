# Security Audit

Bitcoin Lifeboat's Stable release is blocked until an external security audit is
complete and every finding is remediated. Alpha and beta builds may be published
for testing, but they must keep the Alpha or Beta banner.

## Current Status

No external audit sign-off is checked in yet. That is intentional. Until the
sign-off file exists and passes the release gate, `v1.0.0` and any other public
non-alpha/beta tag cannot be released.

The release gate is `scripts/verify-release-gates.sh`. It runs in
`.github/workflows/release.yml` before build artifacts are published.

## Audit Scope

The v1.0 audit covers the parts of Lifeboat that can change a user's risk:

- Secret detection and refusal paths for seed words, xprv material, WIF keys,
  passphrases, and private descriptors.
- Descriptor parsing, checksum handling, key-origin extraction, address
  derivation, report generation, and redaction.
- PSBT file and QR flows, including mainnet validation-only behavior and the
  absence of any broadcast path for mainnet.
- HWI sidecar execution, argument handling, device fingerprint matching, and
  timeout behavior.
- Tauri capabilities, CSP, filesystem permissions, external-link handling, and
  the no-updater rule.
- Offline-by-default behavior, including the browser no-network tests and the
  absence of telemetry or crash-report upload.
- Release signing, reproducible-build scripts, SBOM publication, provenance, and
  stable-release gates.
- User-facing safety copy, translation overclaim checks, and recovery-support
  boundaries.

## Sign-Off File

Stable releases require `docs/security-audit-signoff.json`. The file is not
committed until the external audit is complete. Start from
`docs/security-audit-signoff.template.json`, then replace every example value
with the real auditor, date, scope, report hash, finding resolutions, and
explicit sign-off booleans.

Minimum shape:

```json
{
  "schema_version": "1.0.0",
  "status": "complete",
  "auditor": "Auditor name",
  "report_date": "YYYY-MM-DD",
  "scope": "Bitcoin Lifeboat v1.0 Stable release",
  "report_sha256": "sha256:<64 lowercase hex characters>",
  "findings": [
    {
      "id": "AUD-001",
      "severity": "medium",
      "resolution": "resolved",
      "fixed_in": "commit sha or pull request URL"
    }
  ],
  "signoff": {
    "all_findings_remediated": true,
    "stable_release_approved": true
  }
}
```

Every finding must be marked `resolved` or `not_applicable`. Open findings,
missing report metadata, or a missing sign-off file fail the Stable release gate.

## Placeholder Gate

Alpha and beta releases may still contain project placeholder values from
`project.config.toml`. Public non-alpha/beta releases may not. For a Stable tag,
the release gate scans all tracked files for the default placeholder tokens and
any extra placeholder-shaped tokens listed in `project.config.toml` under
`placeholders.tokens`.

## Manual Hardware Gate

Stable releases also require `docs/hardware-wallet-device-matrix.json`. Start
from `docs/hardware-wallet-device-matrix.template.json` and record passing
test-network checks for Trezor, Coldcard, BitBox02, Jade, and Ledger. The release
gate rejects missing devices, placeholder values, failed/blocked results for a
required device, invalid dates, and obvious secret-material text.

Run the gate locally before tagging:

```sh
scripts/verify-release-gates.sh --tag v1.0.0
```

Run the fixture tests for the gate itself:

```sh
scripts/verify-release-gates.sh --self-test
```

## Remediation Record

When the external report arrives, record each finding in the sign-off file and
link the fixing commit or pull request. Keep the public Markdown page concise:
scope, status, report hash, and the rule that Stable cannot ship while any
finding remains unresolved.
