# JSON Schemas

The JSON shapes below are the public contract for CLI output, desktop command
returns, and exported artifacts. Types are crate-owned serde types with
snake_case fields unless noted.

## ReadinessReport

```json
{
  "schema_version": "0.1.0",
  "app_version": "0.1.0",
  "scoring_engine_version": "0.1.0",
  "created_at": "2026-05-28T00:00:00Z",
  "mode": "readiness_check",
  "input_hash": "sha256:...",
  "report_hash": "sha256:...",
  "network": "bitcoin",
  "wallet_summary": {
    "wallet_type": "multisig",
    "script_type": "wsh(sortedmulti)",
    "threshold": 2,
    "key_count": 3,
    "has_receive_descriptor": true,
    "has_change_descriptor": true,
    "uses_multipath": true,
    "uses_taproot": false,
    "uses_miniscript": false,
    "uses_timelock": false,
    "passphrase_documented": false
  },
  "descriptors": {
    "receive": {
      "raw": "wsh(sortedmulti(...))#checksum",
      "raw_redacted": "wsh(sortedmulti(...redacted...))#checksum",
      "canonical": "wsh(sortedmulti(...))#checksum",
      "checksum_present": true,
      "checksum_valid": true,
      "parse_status": "ok"
    },
    "change": null
  },
  "keys": [
    {
      "index": 0,
      "fingerprint": "abc12345",
      "derivation_path": "m/48h/0h/0h/2h",
      "xpub": "xpub...",
      "xpub_redacted": "xpub6...XXXX",
      "key_origin_present": true
    }
  ],
  "addresses": {
    "receive_derived": [
      { "index": 0, "address": "bc1q...", "chain": "receive" }
    ],
    "change_derived": [],
    "known_address_match": {
      "provided": "bc1q...",
      "matched": true,
      "matched_at": { "index": 3, "chain": "receive" }
    }
  },
  "score": {
    "numeric": 75,
    "status": "mostly_ready",
    "headline": "Mostly Ready"
  },
  "checks": [
    {
      "code": "A1",
      "category": "descriptor_parse",
      "result": "pass",
      "title": "Descriptor parses as BIP380"
    }
  ],
  "critical_issues": [],
  "warnings": [],
  "passes": [],
  "scoring_audit": [],
  "survivability": null,
  "next_steps": [],
  "anti_actions": [],
  "next_drill_recommendation": "2027-05-28",
  "disclaimer_short": "This report is a diagnostic aid...",
  "disclaimer_long": "About this document..."
}
```

Public-safe export omits full xpub fields and redacts descriptors and address
lists. Private export returns the full report after an explicit confirmation.

## RunbookTemplate

```json
{
  "template_id": "multisig_2of3_basic",
  "template_version": "0.1.0",
  "title": "2-of-3 Multisig Recovery Runbook",
  "audience": "owner",
  "language": "en",
  "page_size": "a4",
  "sections": [
    {
      "id": "safety",
      "title": "Safety Rules",
      "body_markdown": "Never type seed words into a website..."
    }
  ],
  "blank_fields": [
    "signer_a_location",
    "signer_b_location",
    "descriptor_location"
  ]
}
```

Heir templates include blanks for the owner to complete by hand after printing.
Lifeboat does not collect signer locations as free text.

## NormalizedWalletExport

```json
{
  "source_wallet": "sparrow",
  "source_wallet_version": "2.5.1",
  "imported_at": "2026-05-28T00:00:00Z",
  "descriptors": {
    "receive": "...",
    "change": "..."
  },
  "keys": [
    {
      "index": 0,
      "fingerprint": "abc12345",
      "derivation_path": "m/48h/0h/0h/2h",
      "xpub": "xpub...",
      "key_origin_present": true
    }
  ],
  "birth_height": 815000,
  "birth_timestamp": "2024-01-15T00:00:00Z",
  "gap_limit": 20,
  "labels": [
    { "type": "addr", "ref": "bc1q...", "label": "Cold storage" }
  ],
  "wallet_type": "multisig",
  "threshold": 2,
  "key_count": 3,
  "raw_source_filename": "wallet.json"
}
```

Importers leave `imported_at` and `raw_source_filename` to the CLI or desktop
command boundary so fixture tests remain deterministic.

## DetectorReport

The detector crate returns tuple-shaped findings to Rust and Tauri callers:

```json
{
  "findings": [
    [
      {
        "bip39": {
          "language": "english",
          "word_count": 12,
          "checksum_valid": true
        }
      },
      { "start": 142, "end": 213 }
    ]
  ],
  "action": "block"
}
```

The CLI `detect-secrets --json` command emits the PRD-facing flattened shape:

```json
{
  "schema_version": "0.1.0",
  "action": "block",
  "findings": [
    {
      "kind": "bip39",
      "language": "english",
      "word_count": 12,
      "checksum_valid": true,
      "byte_range": [142, 213]
    }
  ],
  "user_facing_message": "This looks like a real Bitcoin secret. Lifeboat does not need this. Input cleared."
}
```

Byte ranges identify positions in the original input. Secret text is not copied
into the report.

## Error Boundary

`LifeboatError` serializes as:

```json
{
  "code": "E-PARSE-001",
  "severity": "user_correctable",
  "title": "Descriptor cannot be parsed",
  "description": "The text you provided is not a valid BIP380 descriptor.",
  "action": "Confirm you copied the full descriptor including any leading `wsh(`/`wpkh(`. If you're unsure, see the per-wallet export instructions.",
  "i18n_key": "errors.E-PARSE-001",
  "context": null
}
```

The chained source error is deliberately not serialized because library errors
can contain Confidential input.

