import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import ReadinessCheck from "./ReadinessCheck";
import ReadinessWizard from "./ReadinessWizard";
import { useSessionStore } from "../store/session";
import { sampleReport } from "../test/sampleReport";
import type { DetectedSecret, DetectorReport } from "../tauri/commands";

// The wizard screens descriptor input (US-049) and, at the review step (US-050),
// generates the readiness report — both through the Rust core. Mock the typed
// client so the jsdom suite drives Block / Warn / Allow verdicts and returns a
// fixed report, never touching the real IPC bridge.
const {
  detectMock,
  auditMock,
  generateMock,
  policyDotMock,
  lianaTreeMock,
  saveExportMock,
  saveDialogMock,
} = vi.hoisted(() => ({
  detectMock: vi.fn(),
  auditMock: vi.fn(),
  generateMock: vi.fn(),
  policyDotMock: vi.fn(),
  lianaTreeMock: vi.fn(),
  saveExportMock: vi.fn(),
  saveDialogMock: vi.fn(),
}));
vi.mock("../tauri/commands", () => ({
  detectSensitiveInput: detectMock,
  auditDescriptor: auditMock,
  generateReport: generateMock,
  renderMiniscriptPolicyDot: policyDotMock,
  renderLianaRecoveryTree: lianaTreeMock,
  saveExport: saveExportMock,
  showSaveDialog: saveDialogMock,
}));

function report(
  action: DetectorReport["action"],
  secret?: DetectedSecret,
): DetectorReport {
  const findings: DetectorReport["findings"] =
    secret === undefined ? [] : [[secret, { start: 0, end: 1 }]];
  return { findings, action };
}

// i18n is initialized by src/test/setup.ts. The wizard uses useNavigate, so it
// needs a Router; the "/" route renders a sentinel so a "Save and quit"
// navigation is observable.
function renderWizard(defaultWalletType?: "singlesig" | "multisig" | "liana" | "unsure") {
  return render(
    <MemoryRouter
      initialEntries={["/readiness-check"]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Routes>
        <Route
          path="/readiness-check"
          element={<ReadinessWizard defaultWalletType={defaultWalletType ?? null} />}
        />
        <Route path="/" element={<div>HOME SENTINEL</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

const nextButton = () => screen.getByRole("button", { name: "Next" });
const H1_TEXT = "I have at least two physical copies of my recovery materials.";
const H2_RE = /I can name where each signer is located/;

// Walk a singlesig-default wizard from step 1 to step 6 (the recovery questions),
// choosing the minimal required input along the way.
async function advanceToRecoveryStep(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(nextButton()); // 1 -> 2
  await user.click(screen.getByRole("radio", { name: "Paste a descriptor" }));
  await user.click(nextButton()); // 2 -> 3
  await user.click(screen.getByRole("button", { name: "Use sample descriptor" }));
  await user.click(nextButton()); // 3 -> 4
  await user.click(nextButton()); // 4 -> 5
  await user.click(nextButton()); // 5 -> 6
}

// Walk a singlesig-default wizard all the way to the export step (8), using the
// trusted sample descriptor so step 3 advances without a real detector call.
async function gotoExportStep(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await advanceToRecoveryStep(user); // step 6
  await user.click(nextButton()); // 6 -> 7 (review)
  await user.click(nextButton()); // 7 -> 8 (export)
}

// Reach step 3 (the descriptor import) with the "paste" input method chosen.
async function gotoStep3(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(nextButton()); // 1 -> 2
  await user.click(screen.getByRole("radio", { name: "Paste a descriptor" }));
  await user.click(nextButton()); // 2 -> 3
}

const descriptorField = () => screen.getByLabelText("Output descriptor") as HTMLTextAreaElement;
const BLOCK_TITLE = "This looks like a real Bitcoin secret";
const MULTISIG_DOT = `digraph miniscript_policy {
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
const LIANA_RECOVERY_DOT = `digraph liana_recovery_tree {
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
const LIANA_RECOVERY_TREE = {
  dot: LIANA_RECOVERY_DOT,
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

function lianaTreeForCurrentBlock(currentBlockHeight?: number | null) {
  const countdown =
    typeof currentBlockHeight === "number"
      ? {
          current_block_height: currentBlockHeight,
          active_in_blocks: 65535,
          active_at_block: currentBlockHeight + 65535,
        }
      : undefined;
  return {
    ...LIANA_RECOVERY_TREE,
    paths: [
      LIANA_RECOVERY_TREE.paths[0],
      {
        ...LIANA_RECOVERY_TREE.paths[1],
        countdown,
      },
    ],
  };
}

describe("Readiness Check wizard (§22.8)", () => {
  beforeEach(() => {
    detectMock.mockReset();
    detectMock.mockResolvedValue(report("allow"));
    auditMock.mockReset();
    auditMock.mockResolvedValue(sampleReport);
    generateMock.mockReset();
    generateMock.mockResolvedValue({
      format: "json_pretty",
      redaction: "public-safe",
      mime_type: "application/json",
      suggested_filename: "bitcoin-lifeboat-readiness-public-safe.json",
      content: "{}",
    });
    policyDotMock.mockReset();
    policyDotMock.mockResolvedValue(MULTISIG_DOT);
    lianaTreeMock.mockReset();
    lianaTreeMock.mockImplementation((_descriptor: string, currentBlockHeight?: number | null) =>
      Promise.resolve(lianaTreeForCurrentBlock(currentBlockHeight)),
    );
    saveExportMock.mockReset();
    saveExportMock.mockResolvedValue(undefined);
    saveDialogMock.mockReset();
    saveDialogMock.mockResolvedValue("/tmp/readiness.json");
  });

  afterEach(() => {
    useSessionStore.getState().reset();
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("shows a 'Step N of 8' indicator and gates Next on the wallet-type choice", async () => {
    const user = userEvent.setup();
    renderWizard(); // no default: wallet type starts unselected

    expect(screen.getByText("Step 1 of 8")).toBeTruthy();
    // No Back on the first step; Next is disabled until a wallet type is picked.
    expect(screen.queryByRole("button", { name: "Back" })).toBeNull();
    expect(nextButton()).toBeDisabled();

    await user.click(screen.getByRole("radio", { name: "Single-signature (one key)" }));
    expect(nextButton()).toBeEnabled();

    await user.click(nextButton());
    expect(screen.getByText("Step 2 of 8")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByText("Step 1 of 8")).toBeTruthy();
  });

  it("loads a clearly-marked [ SAMPLE ] descriptor and gates Next on a descriptor (step 3)", async () => {
    const user = userEvent.setup();
    renderWizard("singlesig");

    await user.click(nextButton()); // 1 -> 2
    await user.click(screen.getByRole("radio", { name: "Paste a descriptor" }));
    await user.click(nextButton()); // 2 -> 3

    expect(screen.getByText("Step 3 of 8")).toBeTruthy();
    // The descriptor is required: Next is disabled until one is present.
    expect(nextButton()).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Use sample descriptor" }));

    // The sample descriptor (a documented test-network wpkh fixture) is loaded.
    expect(screen.getByDisplayValue(/wpkh\(/)).toBeTruthy();
    expect(screen.getByText("[ SAMPLE ]")).toBeTruthy();
    expect(nextButton()).toBeEnabled();
  });

  it("walks all eight steps with the sample to the Finish step", async () => {
    const user = userEvent.setup();
    renderWizard("singlesig");

    await advanceToRecoveryStep(user); // now on step 6
    expect(screen.getByText("Step 6 of 8")).toBeTruthy();
    await user.click(nextButton()); // 6 -> 7 (review)
    expect(screen.getByText("Step 7 of 8")).toBeTruthy();
    await user.click(nextButton()); // 7 -> 8 (export)

    expect(screen.getByText("Step 8 of 8")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Finish" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
  });

  it("records each unconfirmed recovery question as a warning, and clears it once confirmed", async () => {
    const user = userEvent.setup();
    renderWizard("singlesig");

    await advanceToRecoveryStep(user); // step 6
    // Leave everything unanswered, then review.
    await user.click(nextButton()); // 6 -> 7

    // An applicable, unconfirmed question is listed as a warning…
    expect(screen.getByText(H1_TEXT)).toBeTruthy();
    // …while the multisig-only questions do not apply to a singlesig wallet.
    expect(screen.queryByText(H2_RE)).toBeNull();

    // Confirm H1 with "Yes" and the warning disappears.
    await user.click(screen.getByRole("button", { name: "Back" })); // 7 -> 6
    const h1Group = screen.getByRole("group", { name: H1_TEXT });
    await user.click(within(h1Group).getByRole("radio", { name: "Yes" }));
    await user.click(nextButton()); // 6 -> 7

    expect(screen.queryByText(H1_TEXT)).toBeNull();
  });

  it("treats the multisig-only questions as applicable when the wallet is multisig", async () => {
    const user = userEvent.setup();
    renderWizard("multisig");

    await user.click(nextButton()); // 1 -> 2
    await user.click(screen.getByRole("radio", { name: "Paste a descriptor" }));
    await user.click(nextButton()); // 2 -> 3
    await user.click(screen.getByRole("button", { name: "Use sample descriptor" }));
    await user.click(nextButton()); // 3 -> 4
    await user.click(nextButton()); // 4 -> 5
    await user.click(nextButton()); // 5 -> 6

    // H2 is answerable (not marked "Not applicable") for a multisig wallet.
    const h2Group = screen.getByRole("group", { name: H2_RE });
    expect(within(h2Group).getByRole("radio", { name: "Yes" })).toBeTruthy();

    await user.click(nextButton()); // 6 -> 7
    expect(screen.getByText(H2_RE)).toBeTruthy(); // now warns
  });

  it("renders the Rust-returned 2-of-3 policy DOT on the review step", async () => {
    const user = userEvent.setup();
    renderWizard("multisig");

    await advanceToRecoveryStep(user);
    await user.click(nextButton()); // 6 -> 7

    expect(await screen.findByText("Policy tree")).toBeTruthy();
    expect(await screen.findByText("thresh(2 of 3)")).toBeTruthy();
    expect(screen.getByText("key 3")).toBeTruthy();
    expect(policyDotMock).toHaveBeenCalledWith(expect.stringContaining("sortedmulti(2"));
  });

  it("loads the Liana sample and renders its recovery path tree", async () => {
    const user = userEvent.setup();
    renderWizard("liana");

    await advanceToRecoveryStep(user);
    await user.click(nextButton()); // 6 -> 7

    expect(await screen.findByText("Recovery path tree")).toBeTruthy();
    expect(screen.getAllByText("Primary path")).toHaveLength(2);
    expect(screen.getAllByText("Recovery path 1")).toHaveLength(2);
    expect(screen.getByText("after 65,535 blocks (~455 days)")).toBeTruthy();
    expect(
      screen.getByText("Recovery path activates after 65,535 blocks, about 455 days."),
    ).toBeTruthy();
    expect(lianaTreeMock).toHaveBeenCalledWith(expect.stringContaining("or_d("), null);

    await user.type(screen.getByLabelText("Current block height"), "840000");
    expect(
      await screen.findByText(
        "Based on current block 840,000, recovery path is active in 65,535 blocks.",
      ),
    ).toBeTruthy();
    expect(lianaTreeMock).toHaveBeenCalledWith(expect.stringContaining("or_d("), 840000);
    expect(policyDotMock).not.toHaveBeenCalled();
  });

  it("'Save and quit' exits to Home and clears Confidential session data without persisting", async () => {
    const user = userEvent.setup();
    // Pre-seed Confidential data as if an earlier step had written it.
    useSessionStore.getState().setDescriptor("wpkh([00000000/84h/0h/0h]xpubCONFIDENTIAL/0/*)");
    renderWizard("singlesig");

    await user.click(screen.getByRole("button", { name: "Save and quit" }));

    expect(screen.getByText("HOME SENTINEL")).toBeTruthy();
    expect(useSessionStore.getState().descriptor).toBeNull();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("ReadinessCheck renders the wizard with a single-signature default", () => {
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <ReadinessCheck />
      </MemoryRouter>,
    );

    expect(screen.getByRole("heading", { level: 1, name: "Run a Readiness Check" })).toBeTruthy();
    expect(screen.getByText("Step 1 of 8")).toBeTruthy();
    expect(screen.getByRole("radio", { name: "Single-signature (one key)" })).toBeChecked();
  });

  // ── US-049: descriptor import + sensitive-input block dialog (§13.5 / §22.7) ──

  it("blocks a pasted secret: screens it, shows the §22.7 dialog, and clears the field", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(
      report("block", { bip39: { language: "english", word_count: 12, checksum_valid: true } }),
    );
    renderWizard("singlesig");
    await gotoStep3(user);

    // Paste a (fake) secret. The detector runs BEFORE the text is processed.
    fireEvent.paste(descriptorField(), {
      clipboardData: { getData: () => "twelve fake bip39 words that the mock will block" },
    });

    // §22.7 dialog appears, naming only the CATEGORY (never the secret content).
    expect(await screen.findByText(BLOCK_TITLE)).toBeTruthy();
    expect(screen.getByText(/a 12-word BIP39 seed phrase/)).toBeTruthy();
    expect(detectMock).toHaveBeenCalledWith(
      "twelve fake bip39 words that the mock will block",
    );

    // The field was cleared and nothing was committed to the session store.
    expect(descriptorField().value).toBe("");
    expect(useSessionStore.getState().descriptor).toBeNull();

    // Only "I understand" closes it.
    await user.click(screen.getByRole("button", { name: "I understand" }));
    expect(screen.queryByText(BLOCK_TITLE)).toBeNull();
  });

  it("imports a clean descriptor from a file and commits it to the session store on Next", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(report("allow"));
    renderWizard("singlesig");
    await gotoStep3(user);

    const content = "wpkh([00000000/84h/1h/0h]tpubSAMPLEWATCHONLY/0/*)";
    const file = new File([content], "wallet.txt", { type: "text/plain" });
    fireEvent.change(screen.getByLabelText("Descriptor file"), { target: { files: [file] } });

    // The file content lands in the field after a clean screen.
    expect(await screen.findByDisplayValue(content)).toBeTruthy();
    expect(detectMock).toHaveBeenCalledWith(content);
    expect(screen.queryByText(BLOCK_TITLE)).toBeNull();

    // Next commits the screened descriptor to the session store and advances.
    await user.click(nextButton());
    expect(await screen.findByText("Step 4 of 8")).toBeTruthy();
    expect(useSessionStore.getState().descriptor).toBe(content);
  });

  it("blocks a dropped file that contains secret material (§17.1 drag-and-drop)", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(report("block", { xprv: { kind: "xprv", network: "mainnet" } }));
    renderWizard("singlesig");
    await gotoStep3(user);

    const file = new File(["xprv9sFAKEprivatekeymaterial"], "key.txt", { type: "text/plain" });
    // Drop bubbles from the textarea to the wrapper's onDrop handler.
    fireEvent.drop(descriptorField(), { dataTransfer: { files: [file] } });

    expect(await screen.findByText(BLOCK_TITLE)).toBeTruthy();
    expect(screen.getByText(/an extended private key/)).toBeTruthy();
    expect(descriptorField().value).toBe("");
    expect(useSessionStore.getState().descriptor).toBeNull();
  });

  it("screens text typed straight into the field when Next is pressed", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(report("block", "raw_hex_priv_key"));
    renderWizard("singlesig");
    await gotoStep3(user);

    // Typing does not screen per keystroke; the Next gate catches it.
    await user.type(descriptorField(), "deadbeef-typed-secret");
    expect(detectMock).not.toHaveBeenCalled();

    await user.click(nextButton());
    expect(await screen.findByText(BLOCK_TITLE)).toBeTruthy();
    expect(screen.getByText("Step 3 of 8")).toBeTruthy(); // did not advance
    expect(descriptorField().value).toBe("");
  });

  it("warns on an unconfirmed Warn finding and gates Next until the override is ticked", async () => {
    const user = userEvent.setup();
    detectMock.mockResolvedValue(
      report("warn", { bip39: { language: "english", word_count: 12, checksum_valid: false } }),
    );
    renderWizard("singlesig");
    await gotoStep3(user);

    fireEvent.paste(descriptorField(), { clipboardData: { getData: () => "suspicious looking text" } });

    // No hard block; instead the §13.5.7 inline override appears and gates Next.
    const override = await screen.findByRole("checkbox", { name: "I confirm this is not a real secret" });
    expect(screen.queryByText(BLOCK_TITLE)).toBeNull();
    expect(nextButton()).toBeDisabled();

    await user.click(override);
    expect(nextButton()).toBeEnabled();

    await user.click(nextButton());
    expect(await screen.findByText("Step 4 of 8")).toBeTruthy();
    expect(useSessionStore.getState().descriptor).toBe("suspicious looking text");
  });

  it("exports JSON in public-safe mode by default via the save dialog and save_export (§22.8 step 8)", async () => {
    const user = userEvent.setup();
    renderWizard("singlesig");
    await gotoExportStep(user);
    expect(screen.getByText("Step 8 of 8")).toBeTruthy();

    await user.click(screen.getByRole("radio", { name: "JSON" }));
    await user.click(screen.getByRole("button", { name: "Export" }));

    // The save succeeds: generate_report ran in the default public-safe mode, the OS
    // save dialog opened, and the chosen path was written via save_export.
    await screen.findByText("Report saved.");
    expect(generateMock).toHaveBeenCalledWith(
      expect.objectContaining({ redaction: "public-safe" }),
      "json_pretty",
    );
    expect(saveDialogMock).toHaveBeenCalledTimes(1);
    expect(saveExportMock).toHaveBeenCalledTimes(1);
  });

  it("requires the §9.5 confirmation before an export switches to private mode", async () => {
    const user = userEvent.setup();
    renderWizard("singlesig");
    await gotoExportStep(user);

    // The private toggle is offered for Markdown / JSON (not the PDF print path).
    await user.click(screen.getByRole("radio", { name: "Markdown" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();

    // Flipping the toggle opens the §9.5 dialog with the verbatim xpub warning.
    await user.click(screen.getByRole("checkbox", { name: "Private mode (reveals xpubs)" }));
    const dialog = screen.getByRole("alertdialog");
    expect(
      within(dialog).getByText(
        "This export contains your wallet's public-key material. xpubs reveal your full transaction history. Only store this where you store your seed backups.",
      ),
    ).toBeTruthy();

    // Confirming enables private mode; the export then runs in private.
    await user.click(screen.getByRole("button", { name: "I understand, use private mode" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Export" }));
    await screen.findByText("Report saved.");
    expect(generateMock).toHaveBeenCalledWith(
      expect.objectContaining({ redaction: "private" }),
      "markdown",
    );
  });

  it("keeps public-safe when the §9.5 confirmation is cancelled", async () => {
    const user = userEvent.setup();
    renderWizard("singlesig");
    await gotoExportStep(user);

    await user.click(screen.getByRole("radio", { name: "JSON" }));
    await user.click(screen.getByRole("checkbox", { name: "Private mode (reveals xpubs)" }));
    await user.click(screen.getByRole("button", { name: "Keep public-safe" }));

    expect(screen.queryByRole("alertdialog")).toBeNull();
    const toggle = screen.getByRole("checkbox", {
      name: "Private mode (reveals xpubs)",
    }) as HTMLInputElement;
    expect(toggle.checked).toBe(false);

    await user.click(screen.getByRole("button", { name: "Export" }));
    await screen.findByText("Report saved.");
    expect(generateMock).toHaveBeenCalledWith(
      expect.objectContaining({ redaction: "public-safe" }),
      "json_pretty",
    );
  });

  it("exports PDF through the OS print dialog (§17.7.4 print-to-PDF), not save_export", async () => {
    const printSpy = vi.spyOn(window, "print").mockImplementation(() => undefined);
    const user = userEvent.setup();
    renderWizard("singlesig");
    await gotoExportStep(user);

    // PDF is the default; it shows the public-safe note instead of the private toggle.
    expect(screen.queryByRole("checkbox", { name: "Private mode (reveals xpubs)" })).toBeNull();

    // The print button enables once the report is ready, then prints — no save_export.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Print / Save as PDF" })).toBeEnabled(),
    );
    await user.click(screen.getByRole("button", { name: "Print / Save as PDF" }));
    expect(printSpy).toHaveBeenCalledTimes(1);
    expect(generateMock).not.toHaveBeenCalled();
    expect(saveDialogMock).not.toHaveBeenCalled();
  });
});
