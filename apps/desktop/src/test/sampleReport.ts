import type { ReadinessReport } from "../tauri/commands";

/**
 * A representative multisig "needs attention" report (2-of-3, several warnings,
 * no critical failures) used by the `ReportViewer` and wizard test suites as the
 * §19.1 shape the Rust core returns from `audit_descriptor`. It mirrors the
 * committed `fixtures/reports/multisig_2of3_*` shape; all values are inert
 * test-network data. Test-only — it is imported by `*.test.tsx`, never by the app.
 */
export const sampleReport: ReadinessReport = {
  schema_version: "0.1.0",
  app_version: "0.1.0",
  scoring_engine_version: "0.1.0",
  created_at: "2024-01-15T00:00:00Z",
  mode: "readiness_check",
  input_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  report_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  network: "testnet",
  wallet_summary: {
    wallet_type: "multisig",
    script_type: "wsh(sortedmulti)",
    threshold: 2,
    key_count: 3,
    has_receive_descriptor: true,
    has_change_descriptor: false,
    uses_multipath: false,
    uses_taproot: false,
    uses_miniscript: false,
    uses_timelock: false,
    passphrase_documented: true,
  },
  descriptors: {
    receive: {
      raw: "wsh(sortedmulti(2,...))#c2yhzrq7",
      raw_redacted: "wsh(sortedmulti(2,...))#c2yhzrq7",
      canonical: "wsh(sortedmulti(2,...))#aluz0gpy",
      checksum_present: true,
      checksum_valid: true,
      parse_status: "ok",
    },
    change: null,
  },
  keys: [
    {
      index: 0,
      fingerprint: "4ba43603",
      derivation_path: "m/48h/1h/0h/2h",
      xpub_redacted: "tpubDD...vjkz",
      key_origin_present: true,
    },
    {
      index: 1,
      fingerprint: "6e37edb9",
      derivation_path: "m/48h/1h/0h/2h",
      xpub_redacted: "tpubDE...UaZJ",
      key_origin_present: true,
    },
    {
      index: 2,
      fingerprint: "8dfc9b34",
      derivation_path: "m/48h/1h/0h/2h",
      xpub_redacted: "tpubDE...LwYq",
      key_origin_present: true,
    },
  ],
  addresses: {
    receive_derived: [
      { index: 0, address: "tb1qexamplereceiveaddress0", chain: "receive" },
      { index: 1, address: "tb1qexamplereceiveaddress1", chain: "receive" },
    ],
    change_derived: [],
    known_address_match: null,
  },
  score: { numeric: 64, status: "needs_attention", headline: "Needs Attention" },
  checks: [
    { code: "A1", category: "descriptor_parse", result: "pass", title: "Descriptor parses as BIP380" },
    { code: "E2", category: "change_descriptor", result: "warn", title: "Change descriptor present" },
    { code: "F1", category: "network", result: "unknown", title: "Network determinable from descriptor" },
    { code: "F2", category: "network", result: "unknown", title: "User confirmed network" },
  ],
  critical_issues: [],
  warnings: [
    {
      code: "W-NO-CHANGE-DESC",
      title: "Change descriptor missing",
      description:
        "A complete recovery backup should include both receive and change descriptors.",
      recommended_fix: "Export both descriptors from your wallet software.",
    },
    {
      code: "W-NO-KNOWN-ADDRESS",
      title: "No known address provided",
      description: "You did not provide a known address to compare against the derived range.",
      recommended_fix: "Re-run the check and paste one address you know belongs to this wallet.",
    },
  ],
  passes: [
    { code: "P-DESC-PARSEABLE", title: "Descriptor parsed successfully" },
    { code: "P-CHECKSUM-VALID", title: "Descriptor checksum is valid" },
    { code: "P-THRESHOLD-CLEAR", title: "Multisig threshold identified as 2-of-3" },
  ],
  scoring_audit: [
    { code: "W-NO-CHANGE-DESC", impact: -15, running_score: 85 },
    { code: "W-NO-KNOWN-ADDRESS", impact: -10, running_score: 75 },
  ],
  survivability: {
    tested: true,
    lose_1_signer: "ok",
    lose_2_signers: "fail_expected_for_2of3",
    lose_descriptor_only: "ok_if_xpubs_retained",
  },
  next_steps: [
    { priority: 1, action: "Export your change descriptor.", effort: "5 min" },
    { priority: 2, action: "Provide one known address from this wallet to compare.", effort: "2 min" },
  ],
  anti_actions: [
    "Do not email the descriptor.",
    "Do not store the descriptor in cloud notes apps.",
    "Do not photograph this report and send it on chat.",
  ],
  next_drill_recommendation: "2024-07-15",
  disclaimer_short:
    "This report is a diagnostic aid. It is not legal, tax, financial, or security advice. Bitcoin Lifeboat cannot guarantee that any wallet is recoverable.",
  disclaimer_long: "About this document. This document reflects only the information you provided.",
};
