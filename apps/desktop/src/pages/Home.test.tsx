import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Home from "./Home";

// i18n is initialized by src/test/setup.ts before these render. Home renders
// <Link>s, so it needs a Router context; MemoryRouter keeps the test isolated.
function renderHome() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Home />
    </MemoryRouter>,
  );
}

describe("Home dashboard cards (§22.2)", () => {
  it("renders the task cards in the expected order", () => {
    renderHome();

    const titles = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
    expect(titles).toEqual([
      "Check My Backup Plan",
      "Audit My Multisig Setup",
      "Create a Family Drill / Heir Runbook",
      "Run Heir Drill",
      "Print a Recovery Runbook",
      "Test a Hardware Wallet",
      "Practice Recovery Safely",
    ]);
  });

  it("links all active cards to their flow routes", () => {
    renderHome();

    expect(screen.getByRole("link", { name: /Check My Backup Plan/ })).toHaveAttribute(
      "href",
      "/readiness-check",
    );
    expect(screen.getByRole("link", { name: /Audit My Multisig Setup/ })).toHaveAttribute(
      "href",
      "/audit-multisig",
    );
    expect(screen.getByRole("link", { name: /Create a Family Drill \/ Heir Runbook/ })).toHaveAttribute(
      "href",
      "/heir-runbook",
    );
    expect(screen.getByRole("link", { name: /Run Heir Drill/ })).toHaveAttribute(
      "href",
      "/heir-walkthrough",
    );
    expect(screen.getByRole("link", { name: /Print a Recovery Runbook/ })).toHaveAttribute(
      "href",
      "/generate-runbook",
    );
    expect(screen.getByRole("link", { name: /Test a Hardware Wallet/ })).toHaveAttribute(
      "href",
      "/hardware-wallet-drill",
    );
    expect(screen.getByRole("link", { name: /Practice Recovery Safely/ })).toHaveAttribute(
      "href",
      "/practice-mode",
    );
  });

  it("shows a time estimate and required-materials hint on each active card", () => {
    renderHome();

    const backup = screen.getByRole("link", { name: /Check My Backup Plan/ });
    expect(within(backup).getByText("~5 minutes")).toBeTruthy();
    expect(within(backup).getByText("You'll need: your wallet descriptor")).toBeTruthy();

    const multisig = screen.getByRole("link", { name: /Audit My Multisig Setup/ });
    expect(within(multisig).getByText("~10 minutes")).toBeTruthy();
    expect(within(multisig).getByText("You'll need: your multisig descriptor")).toBeTruthy();

    const hardware = screen.getByRole("link", { name: /Test a Hardware Wallet/ });
    expect(within(hardware).getByText("~10 minutes")).toBeTruthy();
    expect(within(hardware).getByText("You'll need: a test signer or emulator")).toBeTruthy();
  });

  it("renders a one-sentence description on every card", () => {
    renderHome();

    expect(
      screen.getByText(
        "Test whether you could recover your single-signature wallet from its backup.",
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        "Rehearse a full recovery on a disposable test network with no real funds involved.",
      ),
    ).toBeTruthy();
    expect(
      screen.getByText("Follow a plain checklist with a practice packet and fake bitcoin only."),
    ).toBeTruthy();
  });

  it("enables the Practice card in v0.2", () => {
    renderHome();

    expect(screen.getByRole("heading", { level: 2, name: "Practice Recovery Safely" })).toBeTruthy();
    const practice = screen.getByRole("link", { name: /Practice Recovery Safely/ });
    expect(within(practice).getByText("~5 minutes")).toBeTruthy();
    expect(within(practice).getByText("Uses a documented test seed only")).toBeTruthy();
  });

  it("renders exactly six navigable cards", () => {
    renderHome();
    expect(screen.getAllByRole("link")).toHaveLength(7);
  });
});
