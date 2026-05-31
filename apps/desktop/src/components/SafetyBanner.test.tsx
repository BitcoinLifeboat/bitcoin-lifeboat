import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { SafetyBanner } from "./SafetyBanner";

// i18n is initialized by src/test/setup.ts before these render.
describe("SafetyBanner (§22.6)", () => {
  it("renders the verbatim §22.6 safety copy", () => {
    render(<SafetyBanner />);
    expect(
      screen.getByText("Do not paste seed words, private keys, or passphrases."),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "This mode needs only your public wallet metadata (descriptor, xpubs, derivation paths).",
      ),
    ).toBeInTheDocument();
  });

  it("is not dismissible (no close control)", () => {
    render(<SafetyBanner />);
    expect(screen.queryByRole("button")).toBeNull();
  });
});
