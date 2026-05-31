import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import PracticeMode, { DEFAULT_PRACTICE_MNEMONIC } from "./PracticeMode";

const detectMock = vi.hoisted(() => vi.fn());
const startMock = vi.hoisted(() => vi.fn());
const sendMock = vi.hoisted(() => vi.fn());
const broadcastMock = vi.hoisted(() => vi.fn());
const saveMock = vi.hoisted(() => vi.fn());
const openExternalMock = vi.hoisted(() => vi.fn());
const saveExportMock = vi.hoisted(() => vi.fn());
const saveDialogMock = vi.hoisted(() => vi.fn());
const openDialogMock = vi.hoisted(() => vi.fn());
const readPsbtFileMock = vi.hoisted(() => vi.fn());
const finalizeFilePsbtMock = vi.hoisted(() => vi.fn());
const encodePsbtQrFramesMock = vi.hoisted(() => vi.fn());
const capturePsbtQrPayloadsMock = vi.hoisted(() => vi.fn());
const decodePsbtQrPayloadsMock = vi.hoisted(() => vi.fn());

vi.mock("../tauri/commands", () => ({
  broadcastSignetTransaction: broadcastMock,
  capturePsbtQrPayloads: capturePsbtQrPayloadsMock,
  decodePsbtQrPayloads: decodePsbtQrPayloadsMock,
  detectSensitiveInput: detectMock,
  encodePsbtQrFrames: encodePsbtQrFramesMock,
  finalizeFilePsbt: finalizeFilePsbtMock,
  startPracticeDrill: startMock,
  runPracticeSendDrill: sendMock,
  openExternalLink: openExternalMock,
  readPsbtFile: readPsbtFileMock,
  saveExport: saveExportMock,
  savePracticeDrillResult: saveMock,
  showOpenDialog: openDialogMock,
  showSaveDialog: saveDialogMock,
}));

const REAL_LOOKING_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

function detectorReport(action: "allow" | "warn" | "block") {
  return {
    action,
    findings:
      action === "block"
        ? [
            [
              { bip39: { language: "english", word_count: 24, checksum_valid: true } },
              { start: 0, end: REAL_LOOKING_MNEMONIC.length },
            ],
          ]
        : [],
  };
}

const regtestStart = {
  network: "regtest",
  receive_address: "bcrt1qpracticeaddress0000000000000000000000000000000",
  receive_index: 0,
  faucet_url: null,
  funding_hint_sat: 125000,
  send_amount_sat: 60000,
  fee_rate_sat_vb: 2,
};

const signetStart = {
  network: "signet",
  receive_address: "tb1qpracticeaddress000000000000000000000000000000000",
  receive_index: 0,
  faucet_url: "https://faucet.mutinynet.com/",
  funding_hint_sat: 125000,
  send_amount_sat: 60000,
  fee_rate_sat_vb: 2,
};

const sendResult = {
  network: "regtest",
  receive_address: regtestStart.receive_address,
  receive_index: 0,
  funding_amount_sat: 125000,
  recipient_address: "bcrt1qrecipient00000000000000000000000000000000000",
  amount_sat: 60000,
  fee_rate_sat_vb: 2,
  unsigned_psbt_base64: "cHNidP8BAHECAAAA",
  signed_psbt_base64: "cHNidP8BAHECAAAAsigned",
  finalized_txid: "1".repeat(64),
  transaction_hex: "020000000001",
  input_total_sat: 125000,
  output_total_sat: 123456,
  fee_sat: 1544,
  finalized: true,
  broadcast_available: false,
};

const signetSendResult = {
  ...sendResult,
  network: "signet",
  receive_address: signetStart.receive_address,
  recipient_address: "tb1qrecipient000000000000000000000000000000000000",
  finalized_txid: "2".repeat(64),
  transaction_hex: "020000000001signet",
  broadcast_available: true,
};

const broadcastResult = {
  network: "signet",
  endpoint: "mutinynet",
  endpoint_url: "https://mutinynet.com/api/tx",
  txid: signetSendResult.finalized_txid,
};

const saveResult = {
  path: "/home/example/.local/share/lifeboat/drills/11111111-1111-4111-8111-111111111111.json",
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

const filePsbtFinalizeResult = {
  network: "regtest",
  txid: sendResult.finalized_txid,
  transaction_hex: sendResult.transaction_hex,
  inspection: {
    version: 0,
    network: "regtest",
    input_count: 1,
    output_count: 2,
    input_total_sat: 125000,
    output_total_sat: 123456,
    fee_sat: 1544,
    fee_rate_sat_vb: 2,
    txid: sendResult.finalized_txid,
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
        address: sendResult.recipient_address,
      },
    ],
  },
};

const qrFrameSet = {
  format: "ur",
  frame_count: 2,
  frames: [
    {
      index: 1,
      total: 2,
      payload: "ur:psbt/1-2/lpadax",
      svg: "<svg width=\"320\" height=\"320\"></svg>",
    },
    {
      index: 2,
      total: 2,
      payload: "ur:psbt/2-2/lpaday",
      svg: "<svg width=\"320\" height=\"320\"></svg>",
    },
  ],
};

const qrDecodeComplete = {
  status: "complete",
  received_count: 1,
  parts_left: 0,
  psbt_base64: sendResult.signed_psbt_base64,
};

function bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

function pasteIntoPracticeField(text: string): void {
  fireEvent.paste(screen.getByRole("textbox", { name: "Practice seed words" }), {
    clipboardData: {
      getData: () => text,
    },
  });
}

describe("Practice Mode guarded seed field (US-067)", () => {
  beforeEach(() => {
    detectMock.mockReset();
    startMock.mockReset();
    sendMock.mockReset();
    broadcastMock.mockReset();
    saveMock.mockReset();
    openExternalMock.mockReset();
    saveExportMock.mockReset();
    saveDialogMock.mockReset();
    openDialogMock.mockReset();
    readPsbtFileMock.mockReset();
    finalizeFilePsbtMock.mockReset();
    encodePsbtQrFramesMock.mockReset();
    capturePsbtQrPayloadsMock.mockReset();
    decodePsbtQrPayloadsMock.mockReset();
    detectMock.mockResolvedValue(detectorReport("allow"));
    startMock.mockResolvedValue(regtestStart);
    sendMock.mockResolvedValue(sendResult);
    broadcastMock.mockResolvedValue(broadcastResult);
    saveMock.mockResolvedValue(saveResult);
    openExternalMock.mockResolvedValue(undefined);
    saveExportMock.mockResolvedValue(undefined);
    saveDialogMock.mockResolvedValue("/tmp/lifeboat-regtest-unsigned.psbt");
    openDialogMock.mockResolvedValue("/tmp/lifeboat-regtest-signed.psbt");
    readPsbtFileMock.mockResolvedValue(sendResult.signed_psbt_base64);
    finalizeFilePsbtMock.mockResolvedValue(filePsbtFinalizeResult);
    encodePsbtQrFramesMock.mockResolvedValue(qrFrameSet);
    capturePsbtQrPayloadsMock.mockResolvedValue(["ur:psbt/signed/lpada"]);
    decodePsbtQrPayloadsMock.mockResolvedValue(qrDecodeComplete);
  });

  it("pre-fills the only BIP39 seed field with the canonical documented test mnemonic", () => {
    render(<PracticeMode />);

    const field = screen.getByRole("textbox", { name: "Practice seed words" });
    expect(field).toHaveValue(DEFAULT_PRACTICE_MNEMONIC);
    expect(field).toHaveClass("border-status-needs-attention");
    expect(screen.getByText("PRACTICE-ONLY")).toBeTruthy();
  });

  it("runs the detector on paste before accepting the documented practice mnemonic", async () => {
    render(<PracticeMode />);

    pasteIntoPracticeField(DEFAULT_PRACTICE_MNEMONIC);

    await waitFor(() => expect(detectMock).toHaveBeenCalledWith(DEFAULT_PRACTICE_MNEMONIC));
    expect(screen.getByText("Documented practice seed loaded.")).toBeTruthy();
    expect(screen.getByRole("textbox", { name: "Practice seed words" })).toHaveValue(
      DEFAULT_PRACTICE_MNEMONIC,
    );
  });

  it("hard-blocks a checksum-valid mnemonic that is not the documented practice seed", async () => {
    detectMock.mockResolvedValue(detectorReport("block"));
    render(<PracticeMode />);

    pasteIntoPracticeField(REAL_LOOKING_MNEMONIC);

    await screen.findByRole("alertdialog", {
      name: "Practice Mode blocked that seed phrase",
    });
    expect(
      screen.getByText(
        "This looks like a real mnemonic, not a practice one. Practice Mode only accepts the documented test seeds. See practice-seeds.md.",
      ),
    ).toBeTruthy();
    expect(screen.getByRole("textbox", { name: "Practice seed words" })).toHaveValue(
      DEFAULT_PRACTICE_MNEMONIC,
    );
  });

  it("does not dismiss the hard-block dialog with Escape", async () => {
    detectMock.mockResolvedValue(detectorReport("block"));
    render(<PracticeMode />);

    pasteIntoPracticeField(REAL_LOOKING_MNEMONIC);
    const dialog = await screen.findByRole("alertdialog");
    fireEvent.keyDown(dialog, { key: "Escape" });

    expect(screen.getByRole("alertdialog")).toBeTruthy();
  });

  it("runs the regtest receive/send drill through the Rust command seam", async () => {
    render(<PracticeMode />);

    fireEvent.click(screen.getByRole("button", { name: "Start receive step" }));

    await waitFor(() => expect(startMock).toHaveBeenCalledWith("regtest"));
    expect(screen.getByText(regtestStart.receive_address)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Create, sign, finalize" }));

    await waitFor(() =>
      expect(sendMock).toHaveBeenCalledWith({
        network: "regtest",
        funding_amount_sat: 125000,
        amount_sat: 60000,
        fee_rate_sat_vb: 2,
      }),
    );
    expect(screen.getByRole("heading", { name: "Drill result" })).toBeTruthy();
    expect(screen.getByText(sendResult.finalized_txid)).toBeTruthy();
    expect(screen.getByText("No broadcast was made. Signet broadcast is unavailable for regtest.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save this drill result" })).toBeTruthy();
    expect(saveMock).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Broadcast on Signet" })).toBeNull();
    expect(broadcastMock).not.toHaveBeenCalled();
  });

  it("saves a completed drill only after the user explicitly opts in", async () => {
    render(<PracticeMode />);

    fireEvent.click(screen.getByRole("button", { name: "Start receive step" }));
    await waitFor(() => expect(startMock).toHaveBeenCalledWith("regtest"));
    fireEvent.click(screen.getByRole("button", { name: "Create, sign, finalize" }));
    await waitFor(() => expect(sendMock).toHaveBeenCalled());

    expect(saveMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save this drill result" }));

    await waitFor(() => expect(saveMock).toHaveBeenCalledWith(sendResult));
    expect(screen.getByText(`Saved locally: ${saveResult.path}`)).toBeTruthy();
  });

  it("round-trips unsigned and signed PSBT files through the dialog-scoped flow", async () => {
    render(<PracticeMode />);

    fireEvent.click(screen.getByRole("button", { name: "Start receive step" }));
    await waitFor(() => expect(startMock).toHaveBeenCalledWith("regtest"));
    fireEvent.click(screen.getByRole("button", { name: "Create, sign, finalize" }));
    await waitFor(() => expect(sendMock).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Save unsigned PSBT" }));

    await waitFor(() => expect(saveDialogMock).toHaveBeenCalledTimes(1));
    expect(saveExportMock).toHaveBeenCalledWith(
      "/tmp/lifeboat-regtest-unsigned.psbt",
      bytes(`${sendResult.unsigned_psbt_base64}\n`),
    );
    expect(
      screen.getByText("Unsigned PSBT saved: /tmp/lifeboat-regtest-unsigned.psbt"),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Import signed PSBT" }));

    await waitFor(() => expect(openDialogMock).toHaveBeenCalledTimes(1));
    expect(readPsbtFileMock).toHaveBeenCalledWith("/tmp/lifeboat-regtest-signed.psbt");
    expect(finalizeFilePsbtMock).toHaveBeenCalledWith({
      network: "regtest",
      psbt_base64: sendResult.signed_psbt_base64,
    });
    expect(screen.getByText("Signed PSBT validated and finalized.")).toBeTruthy();
    expect(screen.getByText("Imported from: /tmp/lifeboat-regtest-signed.psbt")).toBeTruthy();
    expect(screen.getAllByText(sendResult.finalized_txid).length).toBeGreaterThan(0);
  });

  it("displays animated PSBT QR frames and scans a signed QR PSBT back through Rust", async () => {
    render(<PracticeMode />);

    fireEvent.click(screen.getByRole("button", { name: "Start receive step" }));
    await waitFor(() => expect(startMock).toHaveBeenCalledWith("regtest"));
    fireEvent.click(screen.getByRole("button", { name: "Create, sign, finalize" }));
    await waitFor(() => expect(sendMock).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Generate QR frames" }));

    await waitFor(() =>
      expect(encodePsbtQrFramesMock).toHaveBeenCalledWith({
        format: "ur",
        psbt_base64: sendResult.unsigned_psbt_base64,
      }),
    );
    expect(screen.getByRole("img", { name: "Unsigned PSBT QR frame 1 of 2" })).toBeTruthy();
    expect(screen.getByText("Frame 1 of 2")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Scan camera frame" }));

    await waitFor(() => expect(capturePsbtQrPayloadsMock).toHaveBeenCalledWith(0));
    expect(decodePsbtQrPayloadsMock).toHaveBeenCalledWith({
      format: "ur",
      payloads: ["ur:psbt/signed/lpada"],
    });
    expect(finalizeFilePsbtMock).toHaveBeenCalledWith({
      network: "regtest",
      psbt_base64: sendResult.signed_psbt_base64,
    });
    expect(screen.getByText("Signed QR PSBT validated and finalized.")).toBeTruthy();
  });

  it("shows the Signet faucet link and opens it only through the external-link command", async () => {
    startMock.mockResolvedValue(signetStart);
    render(<PracticeMode />);

    fireEvent.click(screen.getByRole("radio", { name: /Signet/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start receive step" }));

    await waitFor(() => expect(startMock).toHaveBeenCalledWith("signet"));
    expect(screen.getByText(signetStart.receive_address)).toBeTruthy();
    expect(screen.getByText("Lifeboat does not call the faucet.", { exact: false })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Open Signet faucet" }));

    await waitFor(() => expect(openExternalMock).toHaveBeenCalledWith(signetStart.faucet_url));
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("gates Signet broadcast behind an endpoint confirmation", async () => {
    startMock.mockResolvedValue(signetStart);
    sendMock.mockResolvedValue(signetSendResult);
    render(<PracticeMode />);

    fireEvent.click(screen.getByRole("radio", { name: /Signet/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start receive step" }));
    await waitFor(() => expect(startMock).toHaveBeenCalledWith("signet"));

    fireEvent.click(screen.getByRole("button", { name: "Create, sign, finalize" }));
    await waitFor(() =>
      expect(sendMock).toHaveBeenCalledWith({
        network: "signet",
        funding_amount_sat: 125000,
        amount_sat: 60000,
        fee_rate_sat_vb: 2,
      }),
    );
    expect(
      screen.getByText("Network call to https://mutinynet.com/api/tx only after confirmation."),
    ).toBeTruthy();
    expect(broadcastMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Broadcast on Signet" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Confirm Signet broadcast" });
    expect(within(dialog).getByText("Network call to")).toBeTruthy();
    expect(within(dialog).getByText("https://mutinynet.com/api/tx")).toBeTruthy();
    expect(
      within(dialog).getByText("Network: SIGNET. Mainnet broadcast is not available in Bitcoin Lifeboat."),
    ).toBeTruthy();
    expect(broadcastMock).not.toHaveBeenCalled();

    fireEvent.click(within(dialog).getByRole("button", { name: "Broadcast on Signet" }));

    await waitFor(() =>
      expect(broadcastMock).toHaveBeenCalledWith({
        network: "signet",
        transaction_hex: signetSendResult.transaction_hex,
        endpoint: "mutinynet",
      }),
    );
    expect(screen.getByText(`Signet broadcast accepted: ${signetSendResult.finalized_txid}`)).toBeTruthy();
  });
});
