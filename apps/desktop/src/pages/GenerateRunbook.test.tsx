import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import GenerateRunbook from "./GenerateRunbook";
import type {
  DetectedSecret,
  DetectorReport,
  RunbookArtifact,
  RunbookFormat,
  RunbookGenerationInput,
} from "../tauri/commands";

// US-052 calls the Rust core to render runbooks and to screen the optional
// descriptor pre-fill for secrets. Mock the typed client so the jsdom suite drives
// the preview / export / Block paths without touching the real IPC bridge.
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

const PREVIEW_MD = "# Sample Recovery Runbook\n\nStep 1. Gather your materials.";

function bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

/** A fake runbook artifact whose content decodes to {@link PREVIEW_MD}. */
function artifact(format: RunbookFormat): RunbookArtifact {
  return {
    template: "singlesig-basic",
    format,
    redaction: "public-safe",
    mime_type: format === "pdf" ? "application/pdf" : "text/markdown",
    suggested_filename: `singlesig-basic-public-safe.${format === "pdf" ? "pdf" : "md"}`,
    content: bytes(PREVIEW_MD),
  };
}

function detectorReport(action: DetectorReport["action"], secret?: DetectedSecret): DetectorReport {
  const findings: DetectorReport["findings"] =
    secret === undefined ? [] : [[secret, { start: 0, end: 1 }]];
  return { findings, action };
}

const templateSelect = () => screen.getByLabelText("Runbook template") as HTMLSelectElement;
const descriptorField = () => screen.getByLabelText("Output descriptor") as HTMLTextAreaElement;
const exportButton = () => screen.getByRole("button", { name: "Export runbook" });
const privateToggle = () =>
  screen.getByRole("checkbox", { name: "Private mode (reveals xpubs)" }) as HTMLInputElement;

describe("Generate Runbook (US-052)", () => {
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
    saveDialogMock.mockResolvedValue("/tmp/runbook.pdf");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("lists owner + heir templates and live-previews the default template", async () => {
    render(<GenerateRunbook />);

    // The default template's Markdown preview is rendered by the core.
    expect(await screen.findByText(/Sample Recovery Runbook/)).toBeTruthy();
    await waitFor(() =>
      expect(generateRunbookMock).toHaveBeenCalledWith(
        expect.objectContaining({
          template: "singlesig-basic",
          descriptor: null,
          redaction: "public-safe",
          format: "markdown",
        }),
      ),
    );

    // Both template families are offered in the chooser.
    expect(screen.getByRole("option", { name: "Singlesig recovery" })).toBeTruthy();
    expect(screen.getByRole("option", { name: "Heir plan — 2-of-3 multisig" })).toBeTruthy();
    expect(screen.getByRole("option", { name: "Liana timelock runbook" })).toBeTruthy();
    expect(screen.getByRole("option", { name: "Meetup workshop kit" })).toBeTruthy();
  });

  it("previews and exports a 2-of-3 multisig runbook (public-safe PDF by default)", async () => {
    const user = userEvent.setup();
    render(<GenerateRunbook />);
    await screen.findByText(/Sample Recovery Runbook/);

    // Choosing the 2-of-3 template regenerates the live preview through the core.
    await user.selectOptions(templateSelect(), "multisig-2of3");
    await waitFor(() =>
      expect(generateRunbookMock).toHaveBeenCalledWith(
        expect.objectContaining({ template: "multisig-2of3", format: "markdown" }),
      ),
    );

    // Export: PDF public-safe by default, via the OS save dialog + save_export.
    await user.click(exportButton());
    await screen.findByText("Runbook saved.");
    expect(generateRunbookMock).toHaveBeenCalledWith(
      expect.objectContaining({
        template: "multisig-2of3",
        redaction: "public-safe",
        format: "pdf",
      }),
    );
    expect(saveDialogMock).toHaveBeenCalledTimes(1);
    expect(saveExportMock).toHaveBeenCalledWith("/tmp/runbook.pdf", bytes(PREVIEW_MD));
  });

  it("requires the §9.5 confirmation before exporting in private mode", async () => {
    const user = userEvent.setup();
    render(<GenerateRunbook />);
    await screen.findByText(/Sample Recovery Runbook/);

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
    render(<GenerateRunbook />);
    await screen.findByText(/Sample Recovery Runbook/);

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

  it("blocks a pasted secret in the descriptor pre-fill and clears the field (§13.5 / §22.7)", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(
      detectorReport("block", {
        bip39: { language: "english", word_count: 12, checksum_valid: true },
      }),
    );
    render(<GenerateRunbook />);
    await screen.findByText(/Sample Recovery Runbook/);

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

  it("pre-fills the runbook from a pasted clean descriptor", async () => {
    render(<GenerateRunbook />);
    await screen.findByText(/Sample Recovery Runbook/);

    const clean = "wpkh([00000000/84h/1h/0h]tpubSAMPLEWATCHONLY/0/*)";
    fireEvent.paste(descriptorField(), { clipboardData: { getData: () => clean } });

    expect(
      await screen.findByText("Descriptor applied. The wallet details are filled in below."),
    ).toBeTruthy();
    await waitFor(() =>
      expect(generateRunbookMock).toHaveBeenCalledWith(
        expect.objectContaining({ descriptor: clean, format: "markdown" }),
      ),
    );
  });
});
