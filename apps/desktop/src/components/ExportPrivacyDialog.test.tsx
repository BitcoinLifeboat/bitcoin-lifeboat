import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ExportPrivacyDialog from "./ExportPrivacyDialog";

// The §9.5 NORMATIVE private-export warning, verbatim (PRD §9.5). Stored under an
// i18n key and rendered by the dialog; a copy edit that breaks it byte-for-byte
// fails this assertion.
const WARNING =
  "This export contains your wallet's public-key material. xpubs reveal your full transaction history. Only store this where you store your seed backups.";

describe("ExportPrivacyDialog (§9.5 private-export confirmation)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing when closed", () => {
    const { container } = render(
      <ExportPrivacyDialog open={false} onConfirm={() => undefined} onCancel={() => undefined} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("shows the verbatim §9.5 xpub warning and both actions when open", () => {
    render(<ExportPrivacyDialog open onConfirm={() => undefined} onCancel={() => undefined} />);
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.getByText(WARNING)).toBeTruthy();
    expect(screen.getByRole("button", { name: "I understand, use private mode" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Keep public-safe" })).toBeTruthy();
  });

  it("confirms private mode (and only that) when the confirm button is clicked", async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const user = userEvent.setup();
    render(<ExportPrivacyDialog open onConfirm={onConfirm} onCancel={onCancel} />);

    await user.click(screen.getByRole("button", { name: "I understand, use private mode" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("cancels to the safe public-safe default via the Cancel button and via Escape", async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const user = userEvent.setup();
    render(<ExportPrivacyDialog open onConfirm={onConfirm} onCancel={onCancel} />);

    await user.click(screen.getByRole("button", { name: "Keep public-safe" }));
    expect(onCancel).toHaveBeenCalledTimes(1);

    // Escape also cancels — unlike the §22.7 block dialog, the fallback here (staying
    // public-safe) is the safe state, so Escape is honored rather than swallowed.
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    expect(onCancel).toHaveBeenCalledTimes(2);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
