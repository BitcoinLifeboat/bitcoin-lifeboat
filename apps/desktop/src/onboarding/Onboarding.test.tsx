import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Onboarding from "./Onboarding";
import { usePrefsStore } from "../store/prefs";

/**
 * §15.2 first-launch flow. The key gated behaviors per the story:
 *   - Screen 2 requires the "I understand." checkbox before Continue is enabled.
 *   - Screens are skippable only AFTER Screen 2.
 *   - Finishing (or skipping) sets the Public `onboardingComplete` pref.
 */
describe("Onboarding flow (§15.2)", () => {
  beforeEach(() => {
    usePrefsStore.setState({ onboardingComplete: false });
  });
  afterEach(() => {
    usePrefsStore.setState({ onboardingComplete: false });
  });

  it("opens on Screen 1 (Welcome) with the §15.7 'not a wallet' paragraph", () => {
    render(<Onboarding />);

    expect(screen.getByRole("heading", { level: 1, name: "Bitcoin Lifeboat" })).toBeTruthy();
    expect(
      screen.getByText(/Bitcoin Lifeboat helps you test whether your Bitcoin recovery plan/),
    ).toBeTruthy();
    // §15.7 canonical paragraph.
    expect(
      screen.getByText(/is not a wallet, not a custody service, not a seed phrase manager/),
    ).toBeTruthy();
    // No way to skip yet — only after Screen 2.
    expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();
  });

  it("Screen 2 disables Continue until 'I understand.' is checked", async () => {
    const user = userEvent.setup();
    render(<Onboarding />);

    await user.click(screen.getByRole("button", { name: "Continue" }));

    // Screen 2 — the four promises are shown.
    expect(
      screen.getByRole("heading", { name: "Before we start, our four promises:" }),
    ).toBeTruthy();
    expect(screen.getByText("We never ask for your real seed phrase.")).toBeTruthy();
    expect(screen.getByText("We never claim your funds are safe.")).toBeTruthy();

    // Continue is gated by the checkbox, and skipping is still unavailable.
    const checkbox = screen.getByRole("checkbox", { name: "I understand." });
    expect(checkbox).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();

    await user.click(checkbox);
    expect(checkbox).toBeChecked();
    expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByRole("heading", { name: "What do you want to do?" })).toBeTruthy();
  });

  it("makes screens skippable only after Screen 2", async () => {
    const user = userEvent.setup();
    render(<Onboarding />);

    // Screen 1: no skip.
    expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // Screen 2: still no skip.
    expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();
    await user.click(screen.getByRole("checkbox", { name: "I understand." }));
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // Screen 3: skip is now available.
    expect(screen.getByRole("button", { name: "Skip" })).toBeTruthy();
  });

  it("skipping from Screen 3 completes onboarding", async () => {
    const user = userEvent.setup();
    render(<Onboarding />);

    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("checkbox", { name: "I understand." }));
    await user.click(screen.getByRole("button", { name: "Continue" }));

    expect(usePrefsStore.getState().onboardingComplete).toBe(false);
    await user.click(screen.getByRole("button", { name: "Skip" }));
    expect(usePrefsStore.getState().onboardingComplete).toBe(true);
  });

  it("a real-wallet-audit goal shows Screen 4 (Mode Confirmation) then completes", async () => {
    const user = userEvent.setup();
    render(<Onboarding />);

    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("checkbox", { name: "I understand." }));
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // Screen 3: Continue is disabled until a goal is chosen.
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    await user.click(screen.getByRole("radio", { name: "Check my backup plan" }));
    expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // Screen 4 (Mode Confirmation) — secret-paste guidance.
    expect(screen.getByText("This mode uses public wallet metadata only.")).toBeTruthy();
    expect(screen.getByText("Seed words / mnemonic")).toBeTruthy();
    expect(
      screen.getByText(/Lifeboat will detect it, refuse to process it, and clear the field/),
    ).toBeTruthy();

    expect(usePrefsStore.getState().onboardingComplete).toBe(false);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(usePrefsStore.getState().onboardingComplete).toBe(true);
  });

  it("a non-audit goal (Practice Mode / CLI) skips Screen 4 and completes after Screen 3", async () => {
    const user = userEvent.setup();
    render(<Onboarding />);

    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("checkbox", { name: "I understand." }));
    await user.click(screen.getByRole("button", { name: "Continue" }));

    await user.click(screen.getByRole("radio", { name: /Learn how recovery works/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // No Mode Confirmation screen; onboarding is complete.
    expect(screen.queryByText("This mode uses public wallet metadata only.")).toBeNull();
    expect(usePrefsStore.getState().onboardingComplete).toBe(true);
  });

  it("Back returns to the previous screen and preserves the checkbox", async () => {
    const user = userEvent.setup();
    render(<Onboarding />);

    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("checkbox", { name: "I understand." }));
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // On Screen 3, go back to Screen 2; the acknowledgement is still checked.
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("checkbox", { name: "I understand." })).toBeChecked();
  });
});
