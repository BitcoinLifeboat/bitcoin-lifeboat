import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import HeirRunbook from "./HeirRunbook";
import type {
  DetectedSecret,
  DetectorReport,
  RunbookArtifact,
  RunbookFormat,
  RunbookGenerationInput,
} from "../tauri/commands";

// US-053 reuses the US-052 runbook plumbing: it calls the Rust core to render the
// heir runbook and to screen the optional descriptor pre-fill for secrets. Mock the
// typed client so the jsdom suite drives the preview / export / Block paths without
// touching the real IPC bridge.
const { generateRunbookMock, detectMock, saveExportMock, saveDialogMock } = vi.hoisted(() => ({
  generateRunbookMock: vi.fn(),
  detectMock: vi.fn(),
  saveExportMock: vi.fn(),
  saveDialogMock: vi.fn(),
}));
vi.mock("../tauri/commands", () => ({
  generateRunbook: generateRunbookMock,
  detectSensitiveInput: detectMock,
  saveExport: saveExportMock,
  showSaveDialog: saveDialogMock,
}));

// A preview with a labeled blank line — the §9.4 "fill in by hand" field the heir
// flow is built around (so a test can assert the blanks reach the preview).
const PREVIEW_MD =
  "HEIR RECOVERY PLAN — 2-of-3 Multisig\n\nSigner A is kept at: ______________________";

function bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

/** A fake runbook artifact whose content decodes to {@link PREVIEW_MD}. */
function artifact(format: RunbookFormat): RunbookArtifact {
  return {
    template: "heir-multisig-2of3",
    format,
    redaction: "public-safe",
    mime_type: format === "pdf" ? "application/pdf" : "text/markdown",
    suggested_filename: `heir-multisig-2of3-public-safe.${format === "pdf" ? "pdf" : "md"}`,
    content: bytes(PREVIEW_MD),
  };
}

function detectorReport(action: DetectorReport["action"], secret?: DetectedSecret): DetectorReport {
  const findings: DetectorReport["findings"] =
    secret === undefined ? [] : [[secret, { start: 0, end: 1 }]];
  return { findings, action };
}

const nextButton = () => screen.getByRole("button", { name: "Next" });
const descriptorField = () => screen.getByLabelText("Output descriptor") as HTMLTextAreaElement;
const exportButton = () => screen.getByRole("button", { name: "Export runbook" });
const privateToggle = () =>
  screen.getByRole("checkbox", { name: "Private mode (reveals xpubs)" }) as HTMLInputElement;

/** Advance the guided flow from step 1 to the step-3 review/export screen. */
async function goToReview(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(nextButton()); // → step 2 (wallet details)
  await user.click(nextButton()); // → step 3 (preview + export)
}

describe("Create Heir Runbook (US-053)", () => {
  beforeEach(() => {
    generateRunbookMock.mockReset();
    generateRunbookMock.mockImplementation((input: RunbookGenerationInput) =>
      Promise.resolve(artifact(input.format)),
    );
    detectMock.mockReset();
    detectMock.mockResolvedValue(detectorReport("allow"));
    saveExportMock.mockReset();
    saveExportMock.mockResolvedValue(undefined);
    saveDialogMock.mockReset();
    saveDialogMock.mockResolvedValue("/tmp/heir-runbook.pdf");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("step 1 offers the heir recovery plans", () => {
    render(<HeirRunbook />);
    expect(
      screen.getByRole("radio", { name: "One hardware wallet, no passphrase" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("radio", { name: "One hardware wallet, with a passphrase" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("radio", { name: "2-of-3 multisig (any two of three keys)" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("radio", { name: "3-of-5 multisig (any three of five keys)" }),
    ).toBeTruthy();
    expect(screen.getByRole("radio", { name: "Liana timelock inheritance plan" })).toBeTruthy();
    // The flow has not yet asked for any descriptor (step 1 is the plan chooser).
    expect(screen.queryByLabelText("Output descriptor")).toBeNull();
  });

  it("step 2 warns to record WHERE materials are, not WHAT, and never to write secrets", async () => {
    const user = userEvent.setup();
    render(<HeirRunbook />);

    await user.click(nextButton());

    expect(screen.getByText("Write WHERE each item is — never WHAT it is.")).toBeTruthy();
    expect(
      screen.getByText(/Never write your seed words, private keys, or passphrase/),
    ).toBeTruthy();
    // The only fill input is the optional, screened descriptor — there is no field
    // for a seed, passphrase, or a free-text location (§9.5).
    expect(descriptorField()).toBeTruthy();
  });

  it("blocks a pasted secret in the descriptor pre-fill and clears the field (§13.5 / §22.7)", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(
      detectorReport("block", {
        bip39: { language: "english", word_count: 12, checksum_valid: true },
      }),
    );
    render(<HeirRunbook />);
    await user.click(nextButton());

    fireEvent.paste(descriptorField(), {
      clipboardData: { getData: () => "twelve fake bip39 words that the mock will block" },
    });

    // The §22.7 dialog names only the CATEGORY, never the secret's characters.
    expect(await screen.findByText("This looks like a real Bitcoin secret")).toBeTruthy();
    expect(screen.getByText(/a 12-word BIP39 seed phrase/)).toBeTruthy();
    expect(detectMock).toHaveBeenCalledWith("twelve fake bip39 words that the mock will block");

    // The field was cleared and the secret was never sent to the runbook engine.
    expect(descriptorField().value).toBe("");
    const sentSecret = generateRunbookMock.mock.calls.some((call) => {
      const input = call[0] as RunbookGenerationInput;
      return typeof input.descriptor === "string" && input.descriptor.includes("twelve fake");
    });
    expect(sentSecret).toBe(false);

    await user.click(screen.getByRole("button", { name: "I understand" }));
    expect(screen.queryByText("This looks like a real Bitcoin secret")).toBeNull();
  });

  it("pre-fills the heir plan from a pasted clean descriptor", async () => {
    const user = userEvent.setup();
    render(<HeirRunbook />);
    await user.click(nextButton());

    const clean = "wpkh([00000000/84h/1h/0h]tpubSAMPLEWATCHONLY/0/*)";
    fireEvent.paste(descriptorField(), { clipboardData: { getData: () => clean } });

    expect(
      await screen.findByText("Descriptor applied. The wallet details are filled in below."),
    ).toBeTruthy();

    // The applied descriptor reaches the core's preview on the review step.
    await user.click(nextButton());
    await waitFor(() =>
      expect(generateRunbookMock).toHaveBeenCalledWith(
        expect.objectContaining({ descriptor: clean, format: "markdown" }),
      ),
    );
  });

  it("previews a heir 2-of-3 plan with blank fields and exports public-safe PDF by default", async () => {
    const user = userEvent.setup();
    render(<HeirRunbook />);

    // §31.2: choose the 2-of-3 multisig heir plan, then walk to the review step.
    await user.click(screen.getByRole("radio", { name: "2-of-3 multisig (any two of three keys)" }));
    await goToReview(user);

    // The preview shows the §9.4 labeled blank field for hand-completion.
    expect(await screen.findByText(/Signer A is kept at:/)).toBeTruthy();
    await waitFor(() =>
      expect(generateRunbookMock).toHaveBeenCalledWith(
        expect.objectContaining({
          template: "heir-multisig-2of3",
          descriptor: null,
          redaction: "public-safe",
          format: "markdown",
        }),
      ),
    );

    // Export: PDF public-safe by default, via the OS save dialog + save_export.
    await user.click(exportButton());
    await screen.findByText("Runbook saved.");
    expect(generateRunbookMock).toHaveBeenCalledWith(
      expect.objectContaining({
        template: "heir-multisig-2of3",
        redaction: "public-safe",
        format: "pdf",
      }),
    );
    expect(saveDialogMock).toHaveBeenCalledTimes(1);
    expect(saveExportMock).toHaveBeenCalledWith("/tmp/heir-runbook.pdf", bytes(PREVIEW_MD));
  });

  it("requires the §9.5 confirmation before exporting in private mode", async () => {
    const user = userEvent.setup();
    render(<HeirRunbook />);
    await goToReview(user);
    await screen.findByText(/Signer A is kept at:/);

    // Flipping the toggle opens the §9.5 dialog with the verbatim xpub warning.
    await user.click(privateToggle());
    const dialog = screen.getByRole("alertdialog");
    expect(
      within(dialog).getByText(
        "This export contains your wallet's public-key material. xpubs reveal your full transaction history. Only store this where you store your seed backups.",
      ),
    ).toBeTruthy();

    // Confirming switches to private; the export then runs in private mode.
    await user.click(screen.getByRole("button", { name: "I understand, use private mode" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();

    await user.click(exportButton());
    await screen.findByText("Runbook saved.");
    expect(generateRunbookMock).toHaveBeenCalledWith(
      expect.objectContaining({ redaction: "private", format: "pdf" }),
    );
  });

  it("keeps public-safe when the §9.5 confirmation is cancelled", async () => {
    const user = userEvent.setup();
    render(<HeirRunbook />);
    await goToReview(user);

    await user.click(privateToggle());
    await user.click(screen.getByRole("button", { name: "Keep public-safe" }));

    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(privateToggle().checked).toBe(false);

    await user.click(exportButton());
    await screen.findByText("Runbook saved.");
    expect(generateRunbookMock).toHaveBeenCalledWith(
      expect.objectContaining({ redaction: "public-safe" }),
    );
  });
});
