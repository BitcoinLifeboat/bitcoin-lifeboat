import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import App from "./App";
import { usePrefsStore } from "./store/prefs";

// i18n is initialized by src/test/setup.ts before these render.
describe("App scaffold", () => {
  // The §22.1 app shell only renders once onboarding is complete (§15.2);
  // these tests cover the post-onboarding app, so dismiss the flow first.
  beforeEach(() => {
    usePrefsStore.setState({ onboardingComplete: true });
  });
  afterEach(() => {
    usePrefsStore.setState({ onboardingComplete: false });
  });

  it("renders the primary navigation with all ten destinations", () => {
    render(<App />);

    expect(screen.getByRole("navigation", { name: "Primary" })).toBeTruthy();
    for (const label of [
      "Home",
      "Run a Readiness Check",
      "Audit Multisig Setup",
      "Create Heir Runbook",
      "Run Heir Drill",
      "Generate Runbook",
      "Disaster Drill",
      "Hardware Wallet Drill",
      "Learn",
      "Settings",
    ]) {
      expect(screen.getByRole("link", { name: label })).toBeTruthy();
    }
  });

  it("shows the Home screen by default", () => {
    render(<App />);
    // The Home <h1> (distinct from the nav link of the same name).
    expect(screen.getByRole("heading", { level: 1, name: "Home" })).toBeTruthy();
  });

  it("shows the §15.2 onboarding flow (not the app shell) on first launch", () => {
    usePrefsStore.setState({ onboardingComplete: false });
    render(<App />);

    // Onboarding Screen 1 is shown; the primary nav is not.
    expect(screen.getByRole("heading", { level: 1, name: "Bitcoin Lifeboat" })).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Primary" })).toBeNull();
  });
});
