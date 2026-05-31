import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import HeirWalkthrough from "./HeirWalkthrough";

const generateReceiptMock = vi.hoisted(() => vi.fn());
const saveExportMock = vi.hoisted(() => vi.fn());
const showSaveDialogMock = vi.hoisted(() => vi.fn());

vi.mock("../tauri/commands", () => ({
  generateFamilyDrillReceipt: generateReceiptMock,
  saveExport: saveExportMock,
  showSaveDialog: showSaveDialogMock,
}));

const nextButton = () => screen.getByRole("button", { name: "Next" });
const doneCheckbox = () => screen.getByRole("checkbox", { name: /I did this step/ });

describe("Heir-side walkthrough (US-095/US-096)", () => {
  beforeEach(() => {
    generateReceiptMock.mockReset();
    saveExportMock.mockReset();
    showSaveDialogMock.mockReset();
    generateReceiptMock.mockResolvedValue({
      schema_version: "0.1.0",
      format: "pdf",
      redaction: "public-safe",
      mime_type: "application/pdf",
      suggested_filename: "bitcoin-lifeboat-family-drill-receipt.pdf",
      receipt_hash: `sha256:${"8".repeat(64)}`,
      content: [37, 80, 68, 70],
    });
    showSaveDialogMock.mockResolvedValue("/tmp/family-drill-receipt.pdf");
    saveExportMock.mockResolvedValue(undefined);
  });

  it("shows progress checkmarks, plain word expansions, and repeated anti-scam copy", async () => {
    const user = userEvent.setup();
    render(<HeirWalkthrough />);

    expect(screen.getByRole("heading", { level: 1, name: "Run Heir Drill" })).toBeTruthy();
    expect(screen.getByRole("complementary", { name: "Heir drill progress" })).toBeTruthy();
    expect(screen.getByText("Practice packet")).toBeTruthy();
    expect(screen.getByText(/The folder the owner gave you/)).toBeTruthy();
    expect(screen.getByText("Test coins")).toBeTruthy();
    expect(screen.getAllByText(/we will never contact you/)).toHaveLength(3);

    await user.click(doneCheckbox());
    const startProgress = screen.getByRole("button", { name: /Start with care/ });
    expect(within(startProgress).getByText("Done")).toBeTruthy();

    await user.click(nextButton());
    expect(screen.getByRole("heading", { level: 2, name: "Find the packet" })).toBeTruthy();
    expect(screen.getByText("Practice wallet")).toBeTruthy();
    expect(screen.getByText(/manifest\.json and wallet\/practice-wallet\.json/)).toBeTruthy();
  });

  it("surfaces contextual stop conditions on each step", async () => {
    const user = userEvent.setup();
    render(<HeirWalkthrough />);

    expect(screen.getAllByText(/asks for real seed words/).length).toBeGreaterThan(0);

    await user.click(nextButton());
    expect(screen.getByText(/packet ID does not match/)).toBeTruthy();

    await user.click(nextButton());
    expect(screen.getByText(/mainnet, real bitcoin, or a red mainnet warning/)).toBeTruthy();

    await user.click(nextButton());
    expect(screen.getByText(/address on the device is not the one you chose/)).toBeTruthy();

    await user.click(nextButton());
    expect(screen.getByText(/rushes you, asks for money/)).toBeTruthy();
  });

  it("tracks the confidence checklist and final done state", async () => {
    const user = userEvent.setup();
    render(<HeirWalkthrough />);

    for (let index = 0; index < 5; index += 1) {
      await user.click(doneCheckbox());
      if (index < 4) {
        await user.click(nextButton());
      }
    }

    expect(screen.getByText("Keep going until the steps and checks are done.")).toBeTruthy();

    for (const label of [
      "I found the packet folder and the practice wallet file.",
      "I can explain why this drill uses fake bitcoin only.",
      "I know real seed words never go into this app or any web site.",
      "I know to stop if anyone calls, texts, or emails about this drill.",
    ]) {
      await user.click(screen.getByRole("checkbox", { name: label }));
    }

    expect(
      screen.getByText(
        "You finished the walkthrough. Save or print the family receipt when that step is ready.",
      ),
    ).toBeTruthy();
  });

  it("exports a public-safe family receipt PDF from the checklist", async () => {
    const user = userEvent.setup();
    render(<HeirWalkthrough />);

    for (let index = 0; index < 5; index += 1) {
      await user.click(doneCheckbox());
      if (index < 4) {
        await user.click(nextButton());
      }
    }

    for (const label of [
      "I found the packet folder and the practice wallet file.",
      "I can explain why this drill uses fake bitcoin only.",
      "I know real seed words never go into this app or any web site.",
      "I know to stop if anyone calls, texts, or emails about this drill.",
    ]) {
      await user.click(screen.getByRole("checkbox", { name: label }));
    }

    await user.click(screen.getByRole("button", { name: "Save receipt PDF" }));

    expect(generateReceiptMock).toHaveBeenCalledWith({
      packet_id: null,
      network: null,
      completed_steps: ["start", "packet", "wallet", "send", "result"],
      confidence_checks: ["packet", "fake_bitcoin", "real_seeds", "contact"],
      user_stopped: false,
    });
    expect(showSaveDialogMock).toHaveBeenCalledWith({
      defaultPath: "bitcoin-lifeboat-family-drill-receipt.pdf",
      filters: [{ name: "PDF", extensions: ["pdf"] }],
    });
    expect(saveExportMock).toHaveBeenCalledWith("/tmp/family-drill-receipt.pdf", [
      37, 80, 68, 70,
    ]);
    expect(await screen.findByText(`Receipt saved. Hash: sha256:${"8".repeat(64)}`)).toBeTruthy();
  });
});
