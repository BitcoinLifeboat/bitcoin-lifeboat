import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

import "@testing-library/jest-dom/vitest";
import "../i18n";

// jsdom starts from a blank document; mirror index.html so page-level
// accessibility checks (axe `html-has-lang` / `document-title`, §15.5) reflect
// the real app shell rather than jsdom's empty defaults.
document.documentElement.lang = "en";
document.title = "Bitcoin Lifeboat";

// Unmount any React trees rendered during a test so suites stay isolated.
afterEach(() => {
  cleanup();
});
