import axe from "axe-core";
import { expect } from "vitest";

/**
 * Run axe-core against a rendered container and assert zero WCAG 2.2 AA
 * violations (§15.5 / NFR-A11Y-1, NFR-A11Y-4).
 *
 * This jsdom check is the RUNNABLE SUBSTITUTE for the §27 / NFR-A11Y-4 "axe-core
 * runs in the E2E suite" gate while the native Tauri webview + Playwright E2E
 * cannot run in this sandbox (US-057 adds the real-browser run); the SAME WCAG
 * rule set runs in both places.
 *
 * jsdom performs no layout and has no canvas, so axe's `color-contrast` check
 * cannot measure rendered pixels — it is disabled here. Contrast is instead held
 * by the WCAG-AA-verified color tokens in `tailwind.config.js` (each documented
 * as 4.5:1 on white) and re-verified by the real-browser E2E run.
 */
export async function expectNoAxeViolations(container: HTMLElement): Promise<void> {
  const results = await axe.run(container, {
    runOnly: {
      type: "tag",
      values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
    },
    rules: {
      // Disabled in jsdom (no layout/canvas); see the doc comment above.
      "color-contrast": { enabled: false },
    },
  });

  // Map to readable "rule: help" lines so a failure names the exact violation(s)
  // and the offending markup rather than dumping the whole axe result object.
  const violations = results.violations.map(
    (v) => `${v.id} (${v.impact ?? "n/a"}): ${v.help} — ${v.nodes.map((n) => n.html).join(", ")}`,
  );
  expect(violations).toEqual([]);
}
