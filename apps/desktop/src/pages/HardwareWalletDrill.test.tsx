import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import HardwareWalletDrill from "./HardwareWalletDrill";

const startMock = vi.hoisted(() => vi.fn());
const completeMock = vi.hoisted(() => vi.fn());
const saveResultMock = vi.hoisted(() => vi.fn());
const enumerateMock = vi.hoisted(() => vi.fn());
const signHwiMock = vi.hoisted(() => vi.fn());
const showSaveDialogMock = vi.hoisted(() => vi.fn());
const showOpenDialogMock = vi.hoisted(() => vi.fn());
const saveExportMock = vi.hoisted(() => vi.fn());
const readPsbtFileMock = vi.hoisted(() => vi.fn());
const encodeQrMock = vi.hoisted(() => vi.fn());
const captureQrMock = vi.hoisted(() => vi.fn());
const decodeQrMock = vi.hoisted(() => vi.fn());

vi.mock("../tauri/commands", () => ({
  capturePsbtQrPayloads: captureQrMock,
  completeDisasterSigningDrill: completeMock,
  decodePsbtQrPayloads: decodeQrMock,
  encodePsbtQrFrames: encodeQrMock,
  enumerateHwiDevices: enumerateMock,
  readPsbtFile: readPsbtFileMock,
  saveDisasterSigningDrillResult: saveResultMock,
  saveExport: saveExportMock,
  showOpenDialog: showOpenDialogMock,
  showSaveDialog: showSaveDialogMock,
  signHwiPsbt: signHwiMock,
  startDisasterSigningDrill: startMock,
}));

const startResult = {
  schema_version: "0.1.0",
  scenario: "DS-8",
  scenario_title: "I need to verify my hardware wallet can still sign",
  started_at: "2026-05-30T22:00:00Z",
  network: "regtest",
  transport: "hwi",
  wallet_type: "practice_singlesig",
  required_signatures: 1,
  receive_address: "bcrt1qhardwaredrillreceive",
  destination_address: "bcrt1qhardwaredrilldestination",
  amount_sat: 60000,
  fee_rate_sat_vb: 2,
  unsigned_psbt_base64: "cHNidP8unsigned",
};

const hwiDevice = {
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

const drillResult = {
  schema_version: "0.1.0",
  scenario: "DS-8",
  scenario_title: "I need to verify my hardware wallet can still sign",
  started_at: startResult.started_at,
  result: "pass",
  wallet_type: "practice_singlesig",
  network: "regtest",
  transport: "hwi",
  required_signatures: 1,
  finalized_txid: "5".repeat(64),
  steps: [
    { step: "psbt_created", result: "pass" },
    { step: "required_quorum_signed", result: "pass" },
    { step: "psbt_finalized", result: "pass" },
    { step: "valid_transaction", result: "pass" },
    { step: "destination_confirmed_on_device", result: "pass" },
    { step: "destination_output_matches", result: "pass" },
    { step: "user_did_not_stop", result: "pass" },
  ],
  report_hash: `sha256:${"4".repeat(64)}`,
};

describe("Hardware Wallet Drill (US-086)", () => {
  beforeEach(() => {
    startMock.mockReset();
    completeMock.mockReset();
    saveResultMock.mockReset();
    enumerateMock.mockReset();
    signHwiMock.mockReset();
    showSaveDialogMock.mockReset();
    showOpenDialogMock.mockReset();
    saveExportMock.mockReset();
    readPsbtFileMock.mockReset();
    encodeQrMock.mockReset();
    captureQrMock.mockReset();
    decodeQrMock.mockReset();

    startMock.mockResolvedValue(startResult);
    enumerateMock.mockResolvedValue([hwiDevice]);
    signHwiMock.mockResolvedValue({ fingerprint: "a1b2c3d4", psbt_base64: "cHNidP8signed" });
    completeMock.mockResolvedValue(drillResult);
    saveResultMock.mockResolvedValue({
      path: "/home/user/.local/share/lifeboat/drills/hardware.json",
      record: {
        ...drillResult,
        drill_id: "44444444-4444-4444-8444-444444444444",
        completed_at: "2026-05-30T22:05:00Z",
        signature: {
          algorithm: "ed25519-v1",
          public_key: "public",
          payload_sha256: `sha256:${"6".repeat(64)}`,
          signature: "signature",
        },
      },
    });
    showSaveDialogMock.mockResolvedValue("/tmp/hardware-unsigned.psbt");
    showOpenDialogMock.mockResolvedValue("/tmp/hardware-signed.psbt");
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
      parts_left: 0,
      psbt_base64: "cHNidP8signed",
    });
  });

  it("runs the HWI sidecar signing path and saves only after opt-in", async () => {
    render(<HardwareWalletDrill />);

    expect(screen.getByText("Device detected is not wallet recoverable.")).toBeTruthy();

    fireEvent.click(screen.getByRole("radio", { name: /HWI sidecar/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start hardware drill" }));

    await waitFor(() =>
      expect(startMock).toHaveBeenCalledWith({
        scenario: "DS-8",
        network: "regtest",
        transport: "hwi",
      }),
    );
    expect(screen.getByText("bcrt1qhardwaredrilldestination")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Check connected devices" }));
    await waitFor(() => expect(enumerateMock).toHaveBeenCalledTimes(1));
    expect(screen.getByText("trezor_safe_5 (a1b2c3d4)")).toBeTruthy();

    fireEvent.click(
      screen.getByLabelText("I verified this destination address on the signing device."),
    );
    fireEvent.click(screen.getByRole("button", { name: "Sign with HWI sidecar" }));

    await waitFor(() =>
      expect(signHwiMock).toHaveBeenCalledWith({
        fingerprint: "a1b2c3d4",
        psbt_base64: "cHNidP8unsigned",
        chain: "regtest",
        device_type: "trezor",
        device_path: "trezor-path",
      }),
    );
    await waitFor(() =>
      expect(completeMock).toHaveBeenCalledWith({
        scenario: "DS-8",
        network: "regtest",
        transport: "hwi",
        started_at: startResult.started_at,
        signed_psbt_base64: "cHNidP8signed",
        expected_destination_address: "bcrt1qhardwaredrilldestination",
        expected_amount_sat: 60000,
        destination_confirmed: true,
        user_stopped: false,
      }),
    );
    expect(screen.getByRole("heading", { name: "Hardware drill passed" })).toBeTruthy();
    expect(screen.getByText("Required quorum signed the PSBT")).toBeTruthy();
    expect(saveResultMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Save this drill result" }));

    await waitFor(() => expect(saveResultMock).toHaveBeenCalledWith(drillResult));
    expect(screen.getByText(/Saved locally:/)).toBeTruthy();
  });

  it("renders file and QR controls without invoking HWI", async () => {
    render(<HardwareWalletDrill />);

    fireEvent.click(screen.getByRole("button", { name: "Start hardware drill" }));
    await waitFor(() => expect(startMock).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: "Save unsigned PSBT" })).toBeTruthy();

    fireEvent.click(screen.getByRole("radio", { name: /QR/ }));
    fireEvent.click(screen.getByRole("button", { name: "Start hardware drill" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Generate QR frames" })).toBeTruthy(),
    );
    expect(screen.getByRole("button", { name: "Scan camera frame" })).toBeTruthy();
    expect(signHwiMock).not.toHaveBeenCalled();
  });
});
