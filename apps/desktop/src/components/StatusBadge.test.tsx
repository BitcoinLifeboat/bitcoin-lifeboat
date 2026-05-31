import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { StatusBadge, type ReadinessStatus } from "./StatusBadge";

// i18n is initialized by src/test/setup.ts before these render.
const CASES: { status: ReadinessStatus; label: string; colorClass: string }[] = [
  { status: "ready", label: "Ready", colorClass: "text-status-ready" },
  { status: "mostly_ready", label: "Mostly Ready", colorClass: "text-status-mostly-ready" },
  {
    status: "needs_attention",
    label: "Needs Attention",
    colorClass: "text-status-needs-attention",
  },
  { status: "not_ready", label: "Not Ready", colorClass: "text-status-not-ready" },
  {
    status: "cannot_determine",
    label: "Cannot Determine",
    colorClass: "text-status-cannot-determine",
  },
];

describe("StatusBadge (§22.3)", () => {
  it("renders all five badges with the exact §22.3 label and status color", () => {
    for (const { status, label, colorClass } of CASES) {
      const { unmount } = render(<StatusBadge status={status} />);
      const badge = screen.getByText(label);
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass(colorClass);
      // White background keeps the AA-on-white status colors valid in both modes.
      expect(badge).toHaveClass("bg-white");
      unmount();
    }
  });

  it("conveys status with an icon, not by color alone (§22.3)", () => {
    const { container } = render(<StatusBadge status="ready" />);
    // The badge carries an SVG icon (shape) alongside its text + color.
    expect(container.querySelector("svg")).not.toBeNull();
  });
});
