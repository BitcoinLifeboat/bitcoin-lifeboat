import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { ReportViewer } from "./ReportViewer";
import { sampleReport } from "../test/sampleReport";

function renderReport(): void {
  render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <ReportViewer report={sampleReport} />
    </MemoryRouter>,
  );
}

describe("ReportViewer (§22.5 / §15.10 / §15.8)", () => {
  it("renders the six §22.5 section affordances", () => {
    renderReport();

    // 1. Plain-English summary (one sentence) with the headline + numeric score.
    expect(screen.getByText(/score 64 out of 100/)).toBeTruthy();
    // 2. Status badge — its label also appears in the summary, so allow >1 match.
    expect(screen.getAllByText("Needs Attention").length).toBeGreaterThan(0);
    // 3. "Show technical details" expander, DEFAULT CLOSED (no `open` attribute).
    const toggle = screen.getByText("Show technical details");
    expect(toggle.closest("details")).not.toHaveAttribute("open");
    // 4. Action-oriented recommended-fix block (one per warning).
    expect(screen.getAllByText("Recommended fix:").length).toBeGreaterThan(0);
    // 5. "Learn more" link to the in-app docs (the /learn screen).
    expect(screen.getByRole("link", { name: "Learn more" })).toHaveAttribute("href", "/learn");
    // 6. "Copy explanation" button.
    expect(screen.getByRole("button", { name: "Copy explanation" })).toBeTruthy();
  });

  it("presents the §15.10 sections in document order and always includes §15.8", () => {
    renderReport();

    const order = [
      "What passed",
      "What needs attention",
      "What failed",
      "What is missing",
      "What to do next",
      "What NOT to do",
      "When to run this again",
      "Disclaimer",
      "Version and report hash",
    ];
    const body = document.body.textContent ?? "";
    let previous = -1;
    for (const heading of order) {
      const index = body.indexOf(heading);
      expect(index).toBeGreaterThan(previous);
      previous = index;
    }

    // §15.8 verbatim section is present on every report.
    expect(screen.getByText(/What this report CANNOT tell you/)).toBeTruthy();
  });

  it("renders report content: passes, warnings + fixes, empty criticals, steps, anti-actions", () => {
    renderReport();

    expect(screen.getByText("Descriptor parsed successfully")).toBeTruthy(); // a pass
    expect(screen.getByText("Change descriptor missing")).toBeTruthy(); // a warning title
    expect(screen.getByText("No critical failures.")).toBeTruthy(); // empty criticals
    expect(screen.getByText(/Export your change descriptor/)).toBeTruthy(); // a next step
    expect(screen.getByText("Do not email the descriptor.")).toBeTruthy(); // an anti-action
  });

  it("copies a plain-text explanation to the clipboard (§22.5)", () => {
    const writeText = vi.fn();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    renderReport();

    fireEvent.click(screen.getByRole("button", { name: "Copy explanation" }));

    expect(writeText).toHaveBeenCalledTimes(1);
    expect(String(writeText.mock.calls[0]?.[0])).toContain("Status: Needs Attention");
  });
});
