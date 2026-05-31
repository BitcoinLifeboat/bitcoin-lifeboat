import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test as base } from "@playwright/test";

import { sampleReport } from "../../src/test/sampleReport";

const localProtocols = new Set(["http:", "ws:"]);
const localHosts = new Set(["127.0.0.1", "localhost", "::1"]);

const settings = {
  version: 1,
  theme: "system",
  language: "en",
  diagnostics_enabled: false,
  show_advanced_details: false,
  text_scale: "normal",
};

const reportArtifact = {
  format: "json_pretty",
  redaction: "public-safe",
  mime_type: "application/json",
  suggested_filename: "bitcoin-lifeboat-readiness-public-safe.json",
  content: "{\n  \"schema_version\": \"0.1.0\"\n}\n",
};

const multisigPolicyDot = `digraph miniscript_policy {
  graph [rankdir=TB];
  node [shape=box, style="rounded", fontname="monospace"];
  edge [fontname="monospace"];
  n0 [label="thresh(2 of 3)"];
  n1 [label="key 1"];
  n0 -> n1;
  n2 [label="key 2"];
  n0 -> n2;
  n3 [label="key 3"];
  n0 -> n3;
}
`;

const lianaPolicyDot = `digraph miniscript_policy {
  graph [rankdir=TB];
  node [shape=box, style="rounded", fontname="monospace"];
  edge [fontname="monospace"];
  n0 [label="thresh(1 of 2)"];
  n1 [label="key 1"];
  n0 -> n1;
  n2 [label="thresh(2 of 2)"];
  n0 -> n2;
  n3 [label="key 2"];
  n2 -> n3;
  n4 [label="older(65535)"];
  n2 -> n4;
}
`;

const lianaRecoveryDot = `digraph liana_recovery_tree {
  graph [rankdir=TB];
  node [shape=box, style="rounded", fontname="monospace"];
  edge [fontname="monospace"];
  n0 [label="Liana recovery tree"];
  n1 [label="Primary path\\n1 key\\navailable now"];
  n0 -> n1;
  n2 [label="Recovery path 1\\n1 key\\nafter 65,535 blocks (~455 days)"];
  n0 -> n2;
}
`;

const lianaRecoveryTree = {
  dot: lianaRecoveryDot,
  paths: [
    {
      index: 1,
      label: "Primary path",
      kind: "primary",
      key_count: 1,
      relative_timelocks: [],
      absolute_timelocks: [],
    },
    {
      index: 2,
      label: "Recovery path 1",
      kind: "recovery",
      key_count: 1,
      relative_timelocks: [
        {
          unit: "blocks",
          value: 65535,
          estimated_minutes: 655350,
          estimated_days: 455,
        },
      ],
      absolute_timelocks: [],
    },
  ],
};

const runbookMarkdown =
  "# Heir Recovery Plan\n\n" +
  "Signer A is kept at: ______________________\n\n" +
  "Trusted helper: ______________________\n";

const familyReceiptArtifact = {
  schema_version: "0.1.0",
  format: "pdf",
  redaction: "public-safe",
  mime_type: "application/pdf",
  suggested_filename: "bitcoin-lifeboat-family-drill-receipt.pdf",
  receipt_hash: `sha256:${"8".repeat(64)}`,
  content: [37, 80, 68, 70],
};

const practiceStarts = {
  regtest: {
    network: "regtest",
    receive_address: "bcrt1qpracticeaddress0000000000000000000000000000000",
    receive_index: 0,
    faucet_url: null,
    funding_hint_sat: 125000,
    send_amount_sat: 60000,
    fee_rate_sat_vb: 2,
  },
  signet: {
    network: "signet",
    receive_address: "tb1qpracticeaddress000000000000000000000000000000000",
    receive_index: 0,
    faucet_url: "https://faucet.mutinynet.com/",
    funding_hint_sat: 125000,
    send_amount_sat: 60000,
    fee_rate_sat_vb: 2,
  },
};

const practiceSendResults = {
  regtest: {
    network: "regtest",
    receive_address: practiceStarts.regtest.receive_address,
    receive_index: 0,
    funding_amount_sat: 125000,
    recipient_address: "bcrt1qrecipient00000000000000000000000000000000000",
    amount_sat: 60000,
    fee_rate_sat_vb: 2,
    unsigned_psbt_base64: "cHNidP8BAHECAAAA",
    signed_psbt_base64: "cHNidP8BAHECAAAAsigned",
    finalized_txid: "1111111111111111111111111111111111111111111111111111111111111111",
    transaction_hex: "020000000001",
    input_total_sat: 125000,
    output_total_sat: 123456,
    fee_sat: 1544,
    finalized: true,
    broadcast_available: false,
  },
  signet: {
    network: "signet",
    receive_address: practiceStarts.signet.receive_address,
    receive_index: 0,
    funding_amount_sat: 125000,
    recipient_address: "tb1qrecipient000000000000000000000000000000000000",
    amount_sat: 60000,
    fee_rate_sat_vb: 2,
    unsigned_psbt_base64: "cHNidP8BAHECAAAA",
    signed_psbt_base64: "cHNidP8BAHECAAAAsigned",
    finalized_txid: "2222222222222222222222222222222222222222222222222222222222222222",
    transaction_hex: "020000000001signet",
    input_total_sat: 125000,
    output_total_sat: 123456,
    fee_sat: 1544,
    finalized: true,
    broadcast_available: true,
  },
};

const practiceDrillSave = {
  path: "/home/user/.local/share/lifeboat/drills/11111111-1111-4111-8111-111111111111.json",
  record: {
    schema_version: "0.1.0",
    drill_id: "11111111-1111-4111-8111-111111111111",
    scenario: "DS-9",
    scenario_title: "I want to test a PSBT signing workflow",
    started_at: "2026-05-30T20:00:00Z",
    completed_at: "2026-05-30T20:00:00Z",
    result: "pass",
    wallet_type: "practice_singlesig",
    steps: [{ step: "finalize_psbt", result: "pass" }],
    report_hash: `sha256:${"0".repeat(64)}`,
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"1".repeat(64)}`,
      signature: "signature",
    },
  },
};

const filePsbtFinalize = {
  network: "regtest",
  txid: practiceSendResults.regtest.finalized_txid,
  transaction_hex: practiceSendResults.regtest.transaction_hex,
  inspection: {
    version: 0,
    network: "regtest",
    input_count: 1,
    output_count: 2,
    input_total_sat: 125000,
    output_total_sat: 123456,
    fee_sat: 1544,
    fee_rate_sat_vb: 2,
    txid: practiceSendResults.regtest.finalized_txid,
    finalized: true,
    inputs: [
      {
        index: 0,
        previous_output: `${"0".repeat(64)}:0`,
        sequence: 4294967293,
        amount_sat: 125000,
        has_witness_utxo: true,
        has_non_witness_utxo: false,
        finalized: true,
      },
    ],
    outputs: [
      {
        index: 0,
        amount_sat: 60000,
        script_pubkey: "0014",
        address: practiceSendResults.regtest.recipient_address,
      },
    ],
  },
};

const mainnetFilePsbtValidate = {
  network: "mainnet",
  txid: "4444444444444444444444444444444444444444444444444444444444444444",
  finalized: true,
  broadcast_available: false,
  inspection: {
    ...filePsbtFinalize.inspection,
    network: "mainnet",
    txid: "4444444444444444444444444444444444444444444444444444444444444444",
  },
};

const qrFrameSet = {
  format: "ur",
  frame_count: 1,
  frames: [
    {
      index: 1,
      total: 1,
      payload: "ur:psbt/oyadgdaemw",
      svg: "<svg width=\"320\" height=\"320\" xmlns=\"http://www.w3.org/2000/svg\"></svg>",
    },
  ],
};

const qrDecodeComplete = {
  status: "complete",
  received_count: 1,
  parts_left: 0,
  psbt_base64: practiceSendResults.regtest.signed_psbt_base64,
};

const disasterQuestionnaireResult = {
  schema_version: "0.1.0",
  scenario: "DS-5",
  scenario_title: "I have my descriptor but not all signers",
  started_at: "2026-05-30T20:10:00Z",
  result: "pass",
  wallet_type: "multisig_2of3",
  steps: [
    { step: "descriptor_parse", result: "pass" },
    { step: "derive_expected_addresses", result: "pass" },
    { step: "known_address_match", result: "pass" },
    { step: "multisig_quorum", result: "pass" },
    { step: "available_signers_meet_quorum", result: "pass" },
    { step: "descriptor_backup_available", result: "pass" },
    { step: "signer_locations_known", result: "pass" },
    { step: "user_did_not_stop", result: "pass" },
  ],
  report_hash: `sha256:${"0".repeat(64)}`,
};

const disasterQuestionnaireSave = {
  path: "/home/user/.local/share/lifeboat/drills/22222222-2222-4222-8222-222222222222.json",
  record: {
    ...disasterQuestionnaireResult,
    drill_id: "22222222-2222-4222-8222-222222222222",
    completed_at: "2026-05-30T20:12:00Z",
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"1".repeat(64)}`,
      signature: "signature",
    },
  },
};

const missingSignerResult = {
  schema_version: "0.1.0",
  scenario: "DS-13",
  scenario_title: "Missing signer interactive drill",
  started_at: "2026-05-30T20:30:00Z",
  result: "pass",
  wallet_type: "multisig_2of3",
  network: "regtest",
  threshold: 2,
  key_count: 3,
  lost_signer_index: 2,
  remaining_signer_indexes: [1, 3],
  signatures_required: 2,
  recovery_possible: true,
  required_materials: [
    { kind: "descriptor_backup", signer_index: null },
    { kind: "coordinator_wallet", signer_index: null },
    { kind: "practice_funds", signer_index: null },
    { kind: "remaining_signer", signer_index: 1 },
    { kind: "remaining_signer", signer_index: 3 },
  ],
  steps: [
    { step: "descriptor_parse", result: "pass" },
    { step: "multisig_quorum", result: "pass" },
    { step: "lost_signer_in_range", result: "pass" },
    { step: "remaining_quorum_available", result: "pass" },
    { step: "practice_chain_selected", result: "pass" },
    { step: "user_did_not_stop", result: "pass" },
  ],
  report_hash: `sha256:${"6".repeat(64)}`,
};

const missingSignerSave = {
  path: "/home/user/.local/share/lifeboat/drills/66666666-6666-4666-8666-666666666666.json",
  record: {
    ...missingSignerResult,
    drill_id: "66666666-6666-4666-8666-666666666666",
    completed_at: "2026-05-30T20:32:00Z",
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"7".repeat(64)}`,
      signature: "signature",
    },
  },
};

const disasterSigningStart = {
  schema_version: "0.1.0",
  scenario: "DS-9",
  scenario_title: "I want to test a PSBT signing workflow",
  started_at: "2026-05-30T21:00:00Z",
  network: "regtest",
  transport: "qr",
  wallet_type: "practice_singlesig",
  required_signatures: 1,
  receive_address: "bcrt1qds9receive000000000000000000000000000000000",
  destination_address: "bcrt1qds9destination000000000000000000000000000000",
  amount_sat: 60000,
  fee_rate_sat_vb: 2,
  unsigned_psbt_base64: practiceSendResults.regtest.unsigned_psbt_base64,
};

const disasterSigningResult = {
  schema_version: "0.1.0",
  scenario: "DS-9",
  scenario_title: "I want to test a PSBT signing workflow",
  started_at: disasterSigningStart.started_at,
  result: "pass",
  wallet_type: "practice_singlesig",
  network: "regtest",
  transport: "qr",
  required_signatures: 1,
  finalized_txid: practiceSendResults.regtest.finalized_txid,
  steps: [
    { step: "psbt_created", result: "pass" },
    { step: "required_quorum_signed", result: "pass" },
    { step: "psbt_finalized", result: "pass" },
    { step: "valid_transaction", result: "pass" },
    { step: "destination_confirmed_on_device", result: "pass" },
    { step: "destination_output_matches", result: "pass" },
    { step: "user_did_not_stop", result: "pass" },
  ],
  report_hash: `sha256:${"2".repeat(64)}`,
};

const disasterSigningSave = {
  path: "/home/user/.local/share/lifeboat/drills/33333333-3333-4333-8333-333333333333.json",
  record: {
    ...disasterSigningResult,
    drill_id: "33333333-3333-4333-8333-333333333333",
    completed_at: "2026-05-30T21:12:00Z",
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"3".repeat(64)}`,
      signature: "signature",
    },
  },
};

const hardwareSigningStart = {
  schema_version: "0.1.0",
  scenario: "DS-8",
  scenario_title: "I need to verify my hardware wallet can still sign",
  started_at: "2026-05-30T22:00:00Z",
  network: "regtest",
  transport: "hwi",
  wallet_type: "practice_singlesig",
  required_signatures: 1,
  receive_address: "bcrt1qhardwaredrillreceive000000000000000000000",
  destination_address: "bcrt1qhardwaredrilldestination000000000000000000",
  amount_sat: 60000,
  fee_rate_sat_vb: 2,
  unsigned_psbt_base64: practiceSendResults.regtest.unsigned_psbt_base64,
};

const hardwareDevice = {
  device_type: "trezor",
  supported_kind: "trezor",
  model: "trezor_safe_5",
  path: "trezor-path",
  fingerprint: "a1b2c3d4",
  needs_pin_sent: false,
  needs_passphrase_sent: false,
  status_message: null,
  warnings: [],
};

const hardwareSigningResult = {
  ...disasterSigningResult,
  scenario: "DS-8",
  scenario_title: "I need to verify my hardware wallet can still sign",
  started_at: hardwareSigningStart.started_at,
  transport: "hwi",
};

const hardwareSigningSave = {
  path: "/home/user/.local/share/lifeboat/drills/44444444-4444-4444-8444-444444444444.json",
  record: {
    ...hardwareSigningResult,
    drill_id: "44444444-4444-4444-8444-444444444444",
    completed_at: "2026-05-30T22:12:00Z",
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"4".repeat(64)}`,
      signature: "signature",
    },
  },
};

export const blockedPracticeMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

function isAllowedHarnessUrl(raw: string): boolean {
  if (raw === "about:blank" || raw.startsWith("data:") || raw.startsWith("blob:")) {
    return true;
  }

  try {
    const url = new URL(raw);
    return localProtocols.has(url.protocol) && localHosts.has(url.hostname);
  } catch {
    return false;
  }
}

export const test = base.extend({
  page: async ({ page }, use) => {
    const externalRequests: string[] = [];

    await page.route("**/*", (route) => {
      const url = route.request().url();
      if (isAllowedHarnessUrl(url)) {
        void route.continue();
        return;
      }
      externalRequests.push(url);
      void route.abort("blockedbyclient");
    });

    await page.addInitScript(
      ({
        mockReport,
        mockSettings,
        mockReportArtifact,
        mockMultisigPolicyDot,
        mockLianaPolicyDot,
        mockLianaRecoveryTree,
        mockRunbookMarkdown,
        mockFamilyReceiptArtifact,
        mockPracticeStarts,
        mockPracticeSendResults,
        mockPracticeDrillSave,
        mockFilePsbtFinalize,
        mockMainnetFilePsbtValidate,
        mockQrFrameSet,
        mockQrDecodeComplete,
        mockDisasterQuestionnaireResult,
        mockDisasterQuestionnaireSave,
        mockMissingSignerResult,
        mockMissingSignerSave,
        mockDisasterSigningStart,
        mockDisasterSigningResult,
        mockDisasterSigningSave,
        mockHardwareSigningStart,
        mockHardwareDevice,
        mockHardwareSigningResult,
        mockHardwareSigningSave,
        mockBlockedPracticeMnemonic,
      }) => {
        const textBytes = (text: string): number[] =>
          Array.from(new TextEncoder().encode(text));

        window.__lifeboatE2e = {
          invocations: [],
          saves: [],
        };

        window.__TAURI_INTERNALS__ = {
          invoke: async (cmd: string, args?: unknown) => {
            window.__lifeboatE2e.invocations.push({ cmd, args: args ?? {} });

            switch (cmd) {
              case "load_settings":
                return mockSettings;
              case "save_settings":
              case "clear_all_data":
              case "open_external_link":
              case "save_export":
                if (cmd === "save_export") {
                  window.__lifeboatE2e.saves.push(args ?? {});
                }
                return null;
              case "get_app_info":
                return {
                  name: "Bitcoin Lifeboat",
                  version: "0.1.0",
                  license: "MIT",
                  repository: "https://github.com/__GH_ORG__/bitcoin-lifeboat",
                  homepage: "https://bitcoinlifeboat.org",
                };
              case "detect_sensitive_input": {
                const input = args as { input?: string };
                if (input.input === mockBlockedPracticeMnemonic) {
                  return {
                    findings: [
                      [
                        { bip39: { language: "english", word_count: 24, checksum_valid: true } },
                        { start: 0, end: mockBlockedPracticeMnemonic.length },
                      ],
                    ],
                    action: "block",
                  };
                }
                return { findings: [], action: "allow" };
              }
              case "audit_descriptor":
                return mockReport;
              case "render_miniscript_policy_dot": {
                const input = args as { descriptor?: string };
                return input.descriptor?.includes("or_d(")
                  ? mockLianaPolicyDot
                  : mockMultisigPolicyDot;
              }
              case "render_liana_recovery_tree":
                {
                  const input = args as { currentBlockHeight?: number | null };
                  const countdown =
                    typeof input.currentBlockHeight === "number"
                      ? {
                          current_block_height: input.currentBlockHeight,
                          active_in_blocks: 65535,
                          active_at_block: input.currentBlockHeight + 65535,
                        }
                      : undefined;
                  return {
                    ...mockLianaRecoveryTree,
                    paths: [
                      mockLianaRecoveryTree.paths[0],
                      {
                        ...mockLianaRecoveryTree.paths[1],
                        countdown,
                      },
                    ],
                  };
                }
              case "generate_report":
                return mockReportArtifact;
              case "generate_runbook": {
                const input = args as { input?: { template?: string; format?: string; redaction?: string } };
                const format = input.input?.format === "markdown" ? "markdown" : "pdf";
                return {
                  template: input.input?.template ?? "heir-singlesig-basic",
                  format,
                  redaction: input.input?.redaction ?? "public-safe",
                  mime_type: format === "pdf" ? "application/pdf" : "text/markdown",
                  suggested_filename: `bitcoin-lifeboat-heir.${format === "pdf" ? "pdf" : "md"}`,
                  content: textBytes(mockRunbookMarkdown),
                };
              }
              case "generate_family_drill_receipt":
                return mockFamilyReceiptArtifact;
              case "start_practice_drill": {
                const input = args as { network?: "regtest" | "signet" };
                return input.network === "signet" ? mockPracticeStarts.signet : mockPracticeStarts.regtest;
              }
              case "run_practice_send_drill":
                {
                  const input = args as { input?: { network?: "regtest" | "signet" } };
                  return input.input?.network === "signet"
                    ? mockPracticeSendResults.signet
                    : mockPracticeSendResults.regtest;
                }
              case "broadcast_signet_transaction": {
                const input = args as { input?: { endpoint?: "mutinynet" | "sprovoost" } };
                return {
                  network: "signet",
                  endpoint: input.input?.endpoint ?? "mutinynet",
                  endpoint_url: "https://mutinynet.com/api/tx",
                  txid: mockPracticeSendResults.signet.finalized_txid,
                };
              }
              case "save_practice_drill_result":
                return mockPracticeDrillSave;
              case "plugin:dialog|open":
                return "/tmp/lifeboat-e2e-signed.psbt";
              case "read_psbt_file":
                return mockPracticeSendResults.regtest.signed_psbt_base64;
              case "finalize_file_psbt":
                return mockFilePsbtFinalize;
              case "validate_mainnet_file_psbt":
                return mockMainnetFilePsbtValidate;
              case "encode_psbt_qr_frames":
                return mockQrFrameSet;
              case "capture_psbt_qr_payloads":
                return ["ur:psbt/signed/lpada"];
              case "decode_psbt_qr_payloads":
                return mockQrDecodeComplete;
              case "run_disaster_questionnaire_drill":
                return mockDisasterQuestionnaireResult;
              case "save_disaster_questionnaire_drill_result":
                return mockDisasterQuestionnaireSave;
              case "run_missing_signer_drill":
                return mockMissingSignerResult;
              case "save_missing_signer_drill_result":
                return mockMissingSignerSave;
              case "start_disaster_signing_drill":
                {
                  const input = args as { input?: { scenario?: string; transport?: string } };
                  return input.input?.scenario === "DS-8" || input.input?.transport === "hwi"
                    ? mockHardwareSigningStart
                    : mockDisasterSigningStart;
                }
              case "complete_disaster_signing_drill":
                {
                  const input = args as { input?: { scenario?: string; transport?: string } };
                  return input.input?.scenario === "DS-8" || input.input?.transport === "hwi"
                    ? mockHardwareSigningResult
                    : mockDisasterSigningResult;
                }
              case "save_disaster_signing_drill_result":
                {
                  const input = args as { result?: { scenario?: string; transport?: string } };
                  return input.result?.scenario === "DS-8" || input.result?.transport === "hwi"
                    ? mockHardwareSigningSave
                    : mockDisasterSigningSave;
                }
              case "enumerate_hwi_devices":
                return [mockHardwareDevice];
              case "sign_hwi_psbt":
                return {
                  fingerprint: mockHardwareDevice.fingerprint,
                  psbt_base64: mockPracticeSendResults.regtest.signed_psbt_base64,
                };
              case "verify_hwi_xpubs":
                return [];
              case "plugin:dialog|save":
                return "/tmp/bitcoin-lifeboat-e2e-export";
              default:
                throw new Error(`Unhandled Tauri command in E2E mock: ${cmd}`);
            }
          },
          transformCallback: () => 1,
          unregisterCallback: () => undefined,
          convertFileSrc: (path: string) => path,
        };
        window.isTauri = true;
      },
      {
        mockReport: sampleReport,
        mockSettings: settings,
        mockReportArtifact: reportArtifact,
        mockMultisigPolicyDot: multisigPolicyDot,
        mockLianaPolicyDot: lianaPolicyDot,
        mockLianaRecoveryTree: lianaRecoveryTree,
        mockRunbookMarkdown: runbookMarkdown,
        mockFamilyReceiptArtifact: familyReceiptArtifact,
        mockPracticeStarts: practiceStarts,
        mockPracticeSendResults: practiceSendResults,
        mockPracticeDrillSave: practiceDrillSave,
        mockFilePsbtFinalize: filePsbtFinalize,
        mockMainnetFilePsbtValidate: mainnetFilePsbtValidate,
        mockQrFrameSet: qrFrameSet,
        mockQrDecodeComplete: qrDecodeComplete,
        mockDisasterQuestionnaireResult: disasterQuestionnaireResult,
        mockDisasterQuestionnaireSave: disasterQuestionnaireSave,
        mockMissingSignerResult: missingSignerResult,
        mockMissingSignerSave: missingSignerSave,
        mockDisasterSigningStart: disasterSigningStart,
        mockDisasterSigningResult: disasterSigningResult,
        mockDisasterSigningSave: disasterSigningSave,
        mockHardwareSigningStart: hardwareSigningStart,
        mockHardwareDevice: hardwareDevice,
        mockHardwareSigningResult: hardwareSigningResult,
        mockHardwareSigningSave: hardwareSigningSave,
        mockBlockedPracticeMnemonic: blockedPracticeMnemonic,
      },
    );

    await use(page);

    expect(externalRequests, "no non-loopback browser requests").toEqual([]);
  },
});

export { expect } from "@playwright/test";

export async function completeOnboarding(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Bitcoin Lifeboat" })).toBeVisible();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("I understand.").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Skip" }).click();
  await expect(page.getByRole("heading", { name: "Home" })).toBeVisible();
}

export async function expectNoAxeViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();

  const violations = results.violations.map(
    (violation) =>
      `${violation.id} (${violation.impact ?? "n/a"}): ${violation.help} - ${violation.nodes
        .map((node) => node.html)
        .join(", ")}`,
  );
  expect(violations).toEqual([]);
}

export async function invokedCommands(page: Page): Promise<string[]> {
  return page.evaluate(() => window.__lifeboatE2e.invocations.map((entry) => entry.cmd));
}
