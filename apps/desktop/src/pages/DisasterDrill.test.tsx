import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import DisasterDrill from "./DisasterDrill";

const detectMock = vi.hoisted(() => vi.fn());
const runMock = vi.hoisted(() => vi.fn());
const saveMock = vi.hoisted(() => vi.fn());
const runMultisigMock = vi.hoisted(() => vi.fn());
const saveMultisigMock = vi.hoisted(() => vi.fn());
const runMissingSignerMock = vi.hoisted(() => vi.fn());
const saveMissingSignerMock = vi.hoisted(() => vi.fn());
const startSigningMock = vi.hoisted(() => vi.fn());
const completeSigningMock = vi.hoisted(() => vi.fn());
const saveSigningMock = vi.hoisted(() => vi.fn());
const showSaveDialogMock = vi.hoisted(() => vi.fn());
const showOpenDialogMock = vi.hoisted(() => vi.fn());
const saveExportMock = vi.hoisted(() => vi.fn());
const readPsbtFileMock = vi.hoisted(() => vi.fn());
const encodeQrMock = vi.hoisted(() => vi.fn());
const captureQrMock = vi.hoisted(() => vi.fn());
const decodeQrMock = vi.hoisted(() => vi.fn());
const validateMainnetFilePsbtMock = vi.hoisted(() => vi.fn());

vi.mock("../tauri/commands", () => ({
  capturePsbtQrPayloads: captureQrMock,
  completeDisasterSigningDrill: completeSigningMock,
  detectSensitiveInput: detectMock,
  decodePsbtQrPayloads: decodeQrMock,
  encodePsbtQrFrames: encodeQrMock,
  readPsbtFile: readPsbtFileMock,
  runDisasterQuestionnaireDrill: runMock,
  runMissingSignerDrill: runMissingSignerMock,
  runMultisigSurvivabilityDrill: runMultisigMock,
  saveDisasterSigningDrillResult: saveSigningMock,
  saveExport: saveExportMock,
  saveDisasterQuestionnaireDrillResult: saveMock,
  saveMissingSignerDrillResult: saveMissingSignerMock,
  saveMultisigSurvivabilityDrillResult: saveMultisigMock,
  showOpenDialog: showOpenDialogMock,
  showSaveDialog: showSaveDialogMock,
  startDisasterSigningDrill: startSigningMock,
  validateMainnetFilePsbt: validateMainnetFilePsbtMock,
}));

const ds5Result = {
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

const saveResult = {
  path: "/home/user/.local/share/lifeboat/drills/22222222-2222-4222-8222-222222222222.json",
  record: {
    ...ds5Result,
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

const multisigSurvivabilityResult = {
  schema_version: "0.1.0",
  template_id: "multisig-2of3",
  scenario: "DS-11",
  scenario_title: "2-of-3 multisig survivability simulation",
  started_at: "2026-05-30T20:20:00Z",
  result: "fail",
  wallet_type: "multisig_2of3",
  readiness_status: "needs_attention",
  readiness_headline: "Needs Attention",
  readiness_score: 64,
  survivability: {
    tested: true,
    lose_1_signer: "ok",
    lose_2_signers: "fail_expected_for_2of3",
    lose_descriptor_only: "ok_if_xpubs_retained",
  },
  steps: [
    { step: "descriptor_parse", result: "pass" },
    { step: "template_matches_descriptor", result: "pass" },
    { step: "readiness_status_available", result: "pass" },
    { step: "lose_1_signer_survives", result: "pass" },
    { step: "lose_2_signers_survives", result: "fail" },
    { step: "lose_descriptor_backup_survives", result: "pass" },
    { step: "user_did_not_stop", result: "pass" },
  ],
  report_hash: `sha256:${"5".repeat(64)}`,
};

const multisigSaveResult = {
  path: "/home/user/.local/share/lifeboat/drills/55555555-5555-4555-8555-555555555555.json",
  record: {
    ...multisigSurvivabilityResult,
    drill_id: "55555555-5555-4555-8555-555555555555",
    completed_at: "2026-05-30T20:22:00Z",
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"6".repeat(64)}`,
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
  report_hash: `sha256:${"7".repeat(64)}`,
};

const missingSignerSaveResult = {
  path: "/home/user/.local/share/lifeboat/drills/77777777-7777-4777-8777-777777777777.json",
  record: {
    ...missingSignerResult,
    drill_id: "77777777-7777-4777-8777-777777777777",
    completed_at: "2026-05-30T20:32:00Z",
    signature: {
      algorithm: "ed25519-v1",
      public_key: "public",
      payload_sha256: `sha256:${"8".repeat(64)}`,
      signature: "signature",
    },
  },
};

const signingStart = {
  schema_version: "0.1.0",
  scenario: "DS-9",
  scenario_title: "I want to test a PSBT signing workflow",
  started_at: "2026-05-30T21:00:00Z",
  network: "regtest",
  transport: "file",
  wallet_type: "practice_singlesig",
  required_signatures: 1,
  receive_address: "bcrt1qreceivepractice",
  destination_address: "bcrt1qdestinationpractice",
  amount_sat: 60000,
  fee_rate_sat_vb: 2,
  unsigned_psbt_base64: "cHNidP8unsigned",
};

const signingResult = {
  schema_version: "0.1.0",
  scenario: "DS-9",
  scenario_title: "I want to test a PSBT signing workflow",
  started_at: "2026-05-30T21:00:00Z",
  result: "pass",
  wallet_type: "practice_singlesig",
  network: "regtest",
  transport: "file",
  required_signatures: 1,
  finalized_txid: "2".repeat(64),
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

const signingSaveResult = {
  path: "/home/user/.local/share/lifeboat/drills/33333333-3333-4333-8333-333333333333.json",
  record: {
    ...signingResult,
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

const mainnetFilePsbtResult = {
  network: "mainnet",
  txid: "4".repeat(64),
  finalized: true,
  broadcast_available: false,
  inspection: {
    version: 0,
    network: "mainnet",
    input_count: 1,
    output_count: 2,
    input_total_sat: 125000,
    output_total_sat: 123456,
    fee_sat: 1544,
    fee_rate_sat_vb: 2,
    txid: "4".repeat(64),
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
        address: "bc1qmainnetdestination00000000000000000000000",
      },
    ],
  },
};

const blockedMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

describe("Disaster Drill questionnaire (US-076)", () => {
  beforeEach(() => {
    detectMock.mockReset();
    runMock.mockReset();
    saveMock.mockReset();
    runMultisigMock.mockReset();
    saveMultisigMock.mockReset();
    runMissingSignerMock.mockReset();
    saveMissingSignerMock.mockReset();
    startSigningMock.mockReset();
    completeSigningMock.mockReset();
    saveSigningMock.mockReset();
    showSaveDialogMock.mockReset();
    showOpenDialogMock.mockReset();
    saveExportMock.mockReset();
    readPsbtFileMock.mockReset();
    encodeQrMock.mockReset();
    captureQrMock.mockReset();
    decodeQrMock.mockReset();
    validateMainnetFilePsbtMock.mockReset();
    detectMock.mockResolvedValue({ findings: [], action: "allow" });
    runMock.mockResolvedValue(ds5Result);
    saveMock.mockResolvedValue(saveResult);
    runMultisigMock.mockResolvedValue(multisigSurvivabilityResult);
    saveMultisigMock.mockResolvedValue(multisigSaveResult);
    runMissingSignerMock.mockResolvedValue(missingSignerResult);
    saveMissingSignerMock.mockResolvedValue(missingSignerSaveResult);
    startSigningMock.mockResolvedValue(signingStart);
    completeSigningMock.mockResolvedValue(signingResult);
    saveSigningMock.mockResolvedValue(signingSaveResult);
    showSaveDialogMock.mockResolvedValue("/tmp/ds9-unsigned.psbt");
    showOpenDialogMock.mockResolvedValue("/tmp/ds9-signed.psbt");
    saveExportMock.mockResolvedValue(undefined);
    readPsbtFileMock.mockResolvedValue("cHNidP8signed");
    encodeQrMock.mockResolvedValue({
      format: "ur",
      frame_count: 1,
      frames: [{ index: 1, total: 1, payload: "ur:psbt/unsigned", svg: "<svg />" }],
    });
    captureQrMock.mockResolvedValue(["ur:psbt/signed"]);
    decodeQrMock.mockResolvedValue({
      status: "complete",
      received_count: 1,
      parts_left: null,
      psbt_base64: "cHNidP8signed",
    });
    validateMainnetFilePsbtMock.mockResolvedValue(mainnetFilePsbtResult);
  });

  it("runs DS-5 through the Rust command seam and saves only after opt-in", async () => {
    render(<DisasterDrill />);

    fireEvent.click(screen.getByRole("button", { name: "Use sample descriptor" }));
    fireEvent.click(screen.getByRole("button", { name: "Run questionnaire drill" }));

    await waitFor(() => expect(runMock).toHaveBeenCalled());
    expect(detectMock).toHaveBeenCalledTimes(2);
    expect(runMock).toHaveBeenCalledWith({
      scenario: "DS-5",
      descriptor: expect.stringContaining("wsh(sortedmulti(2,"),
      network: "testnet",
      known_address: "tb1q8ke5xqhsyqydxk9jkkrn83f6ltp7edst4xv2ar2xlqdry2g8588qpqjjdj",
      available_signers: 2,
      user_stopped: false,
      answers: {
        descriptor_backup_available: "yes",
        recovery_materials_available: "unsure",
        wallet_software_documented: "unsure",
        passphrase_documented: "unsure",
        gap_limit_or_birthdate_documented: "unsure",
        signer_locations_known: "yes",
      },
    });

    expect(screen.getByRole("heading", { name: "Drill passed for this scenario" })).toBeTruthy();
    expect(screen.getByText("Available signers meet the threshold")).toBeTruthy();
    expect(saveMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save this drill result" }));

    await waitFor(() => expect(saveMock).toHaveBeenCalledWith(ds5Result));
    expect(screen.getByText(`Saved locally: ${saveResult.path}`)).toBeTruthy();
  });

  it("runs a 2-of-3 multisig survivability template and saves only after opt-in", async () => {
    render(<DisasterDrill />);

    fireEvent.click(screen.getByRole("radio", { name: /MS-2OF3: 2-of-3 multisig/ }));
    fireEvent.click(screen.getByRole("button", { name: "Use sample descriptor" }));
    fireEvent.click(screen.getByRole("button", { name: "Run survivability simulation" }));

    await waitFor(() => expect(runMultisigMock).toHaveBeenCalled());
    expect(runMultisigMock).toHaveBeenCalledWith({
      template: "multisig-2of3",
      descriptor: expect.stringContaining("wsh(sortedmulti(2,"),
      network: "testnet",
      known_address: "tb1q8ke5xqhsyqydxk9jkkrn83f6ltp7edst4xv2ar2xlqdry2g8588qpqjjdj",
      user_stopped: false,
    });
    expect(screen.getByRole("heading", {
      name: "At least one simulated multisig loss falls below threshold",
    })).toBeTruthy();
    expect(screen.getByText("Needs Attention")).toBeTruthy();
    expect(screen.getByText("Lose 2 signers")).toBeTruthy();
    expect(screen.getAllByText("Below threshold").length).toBeGreaterThan(0);
    expect(screen.getByText("Descriptor backup loss is recoverable from retained xpubs")).toBeTruthy();
    expect(saveMultisigMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save this drill result" }));

    await waitFor(() => expect(saveMultisigMock).toHaveBeenCalledWith(multisigSurvivabilityResult));
    expect(screen.getByText(`Saved locally: ${multisigSaveResult.path}`)).toBeTruthy();
  });

  it("runs a missing-signer drill for signer 2 of a 2-of-3 and saves only after opt-in", async () => {
    render(<DisasterDrill />);

    fireEvent.click(screen.getByRole("radio", { name: /MS-MISSING: Missing signer drill/ }));
    fireEvent.click(screen.getByRole("button", { name: "Use sample descriptor" }));
    fireEvent.click(screen.getByRole("button", { name: "Run missing-signer drill" }));

    await waitFor(() => expect(runMissingSignerMock).toHaveBeenCalled());
    expect(runMissingSignerMock).toHaveBeenCalledWith({
      descriptor: expect.stringContaining("wsh(sortedmulti(2,"),
      network: "regtest",
      lost_signer_index: 2,
      user_stopped: false,
    });
    expect(
      screen.getByRole("heading", {
        name: "Recovery remains possible with the remaining signers",
      }),
    ).toBeTruthy();
    expect(screen.getByText("Signer 1, Signer 3")).toBeTruthy();
    expect(screen.getByText("Signer 1 device or seed backup")).toBeTruthy();
    expect(screen.getByText("Signer 3 device or seed backup")).toBeTruthy();
    expect(screen.getByText("Remaining signers meet the threshold")).toBeTruthy();
    expect(saveMissingSignerMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save this drill result" }));

    await waitFor(() => expect(saveMissingSignerMock).toHaveBeenCalledWith(missingSignerResult));
    expect(screen.getByText(`Saved locally: ${missingSignerSaveResult.path}`)).toBeTruthy();
  });

  it("blocks secret-looking descriptor text before running the drill command", async () => {
    detectMock.mockResolvedValue({
      action: "block",
      findings: [
        [
          { bip39: { language: "english", word_count: 12, checksum_valid: true } },
          { start: 0, end: blockedMnemonic.length },
        ],
      ],
    });
    render(<DisasterDrill />);

    fireEvent.change(screen.getByRole("textbox", { name: "Output descriptor" }), {
      target: { value: blockedMnemonic },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run questionnaire drill" }));

    const dialog = await screen.findByRole("alertdialog", {
      name: "This looks like a real Bitcoin secret",
    });
    expect(within(dialog).getByText("a 12-word BIP39 seed phrase")).toBeTruthy();
    expect(screen.getByRole("textbox", { name: "Output descriptor" })).toHaveValue("");
    expect(runMock).not.toHaveBeenCalled();
  });

  it("runs DS-9 through the file signing command seam and saves only after opt-in", async () => {
    render(<DisasterDrill />);

    fireEvent.click(screen.getByRole("radio", { name: /DS-9: I want to test a PSBT/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start signing drill" }));

    await waitFor(() => expect(startSigningMock).toHaveBeenCalledWith({
      scenario: "DS-9",
      network: "regtest",
      transport: "file",
    }));
    expect(screen.getByText("bcrt1qdestinationpractice")).toBeTruthy();

    fireEvent.click(screen.getByLabelText("I verified this destination address on the signing device."));
    fireEvent.click(screen.getByRole("button", { name: "Save unsigned PSBT" }));
    await waitFor(() => expect(saveExportMock).toHaveBeenCalled());
    expect(screen.getByText("Unsigned PSBT saved: /tmp/ds9-unsigned.psbt")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Import signed PSBT" }));
    await waitFor(() => expect(completeSigningMock).toHaveBeenCalledWith({
      scenario: "DS-9",
      network: "regtest",
      transport: "file",
      started_at: "2026-05-30T21:00:00Z",
      signed_psbt_base64: "cHNidP8signed",
      expected_destination_address: "bcrt1qdestinationpractice",
      expected_amount_sat: 60000,
      destination_confirmed: true,
      user_stopped: false,
    }));
    expect(screen.getByRole("heading", { name: "Signing drill passed" })).toBeTruthy();
    expect(screen.getByText("Required quorum signed the PSBT")).toBeTruthy();
    expect(saveSigningMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save this drill result" }));

    await waitFor(() => expect(saveSigningMock).toHaveBeenCalledWith(signingResult));
    expect(screen.getByText(`Saved locally: ${signingSaveResult.path}`)).toBeTruthy();
  });

  it("requires a session acknowledgement before validating a mainnet PSBT file", async () => {
    render(<DisasterDrill />);

    fireEvent.click(screen.getByRole("radio", { name: /DS-9: I want to test a PSBT/ }));
    fireEvent.click(screen.getByRole("radio", { name: /Mainnet file/ }));

    const importButton = screen.getByRole("button", { name: "Import mainnet PSBT" });
    expect(importButton).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Start signing drill" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Broadcast/ })).toBeNull();

    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I want to sign a mainnet PSBT in the file-based flow/,
      }),
    );
    fireEvent.click(importButton);

    await waitFor(() => expect(showOpenDialogMock).toHaveBeenCalledTimes(1));
    expect(readPsbtFileMock).toHaveBeenCalledWith("/tmp/ds9-signed.psbt");
    expect(validateMainnetFilePsbtMock).toHaveBeenCalledWith({
      psbt_base64: "cHNidP8signed",
    });
    expect(startSigningMock).not.toHaveBeenCalled();
    expect(completeSigningMock).not.toHaveBeenCalled();
    expect(screen.getByText("Mainnet PSBT validated from: /tmp/ds9-signed.psbt")).toBeTruthy();
    expect(screen.getByText("No broadcast was made or offered.")).toBeTruthy();
    expect(screen.getByText(mainnetFilePsbtResult.txid)).toBeTruthy();
  });
});
