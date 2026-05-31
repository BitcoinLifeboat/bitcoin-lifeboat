import { afterEach, describe, expect, it } from "vitest";

import { applyTextScale } from "./theme";

// §15.5 item 7 — large-text mode scales the whole UI by setting the root font
// size, so all rem-based Tailwind sizing grows together at 1x / 1.5x / 2x.
describe("applyTextScale (§15.5 large-text mode)", () => {
  afterEach(() => {
    document.documentElement.style.removeProperty("font-size");
  });

  it("sets the root font size to the percentage for each scale", () => {
    applyTextScale("normal");
    expect(document.documentElement.style.fontSize).toBe("100%");

    applyTextScale("large");
    expect(document.documentElement.style.fontSize).toBe("150%");

    applyTextScale("larger");
    expect(document.documentElement.style.fontSize).toBe("200%");
  });
});
