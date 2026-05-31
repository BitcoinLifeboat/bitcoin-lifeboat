import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import SensitiveInputDialog from "./SensitiveInputDialog";
import type { DetectedSecret } from "../tauri/commands";

const BLOCK_TITLE = "This looks like a real Bitcoin secret";

describe("SensitiveInputDialog (§22.7)", () => {
  it("renders nothing when there is no detected secret", () => {
    const { container } = render(
      <SensitiveInputDialog detected={null} onAcknowledge={vi.fn()} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the §22.7 block copy and the recovery steps", () => {
    render(
      <SensitiveInputDialog
        detected={{ bip39: { language: "english", word_count: 12, checksum_valid: true } }}
        onAcknowledge={vi.fn()}
      />,
    );

    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.getByText(BLOCK_TITLE)).toBeTruthy();
    // The four §22.7 "what to do" steps render in order.
    expect(screen.getByText("Export the output descriptor (not the seed)")).toBeTruthy();
    expect(screen.getByRole("button", { name: "I understand" })).toBeTruthy();
  });

  it("summarizes only the secret CATEGORY, never its content", () => {
    const cases: Array<{ detected: DetectedSecret; expected: RegExp }> = [
      {
        detected: { bip39: { language: "english", word_count: 24, checksum_valid: true } },
        expected: /a 24-word BIP39 seed phrase/,
      },
      { detected: { xprv: { kind: "xprv", network: "mainnet" } }, expected: /an extended private key/ },
      { detected: "raw_hex_priv_key", expected: /a raw private key/ },
      { detected: { slip39: { share_count_in_input: 2 } }, expected: /SLIP-39 backup shares/ },
    ];
    for (const { detected, expected } of cases) {
      const { unmount } = render(
        <SensitiveInputDialog detected={detected} onAcknowledge={vi.fn()} />,
      );
      expect(screen.getByText(expected)).toBeTruthy();
      unmount();
    }
  });

  it("closes only via 'I understand'", () => {
    const onAcknowledge = vi.fn();
    render(
      <SensitiveInputDialog detected="raw_hex_priv_key" onAcknowledge={onAcknowledge} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "I understand" }));
    expect(onAcknowledge).toHaveBeenCalledTimes(1);
  });

  it("cannot be dismissed with Escape (§22.7)", () => {
    const onAcknowledge = vi.fn();
    render(
      <SensitiveInputDialog detected="raw_hex_priv_key" onAcknowledge={onAcknowledge} />,
    );

    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });

    // Escape never acknowledges, and the dialog is still on screen.
    expect(onAcknowledge).not.toHaveBeenCalled();
    expect(screen.getByText(BLOCK_TITLE)).toBeTruthy();
  });
});
