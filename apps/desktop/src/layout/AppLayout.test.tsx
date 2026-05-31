import { afterEach, describe, expect, it } from "vitest";
import { act, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import AppLayout from "./AppLayout";
import { usePrefsStore } from "../store/prefs";
import { useSessionStore } from "../store/session";

// i18n is initialized by src/test/setup.ts before these render. Render AppLayout
// over a few stub child routes so the §22.4/§22.6 banner wiring can be exercised
// per-route in isolation.
function renderAt(path: string) {
  return render(
    <MemoryRouter
      initialEntries={[path]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<div>home content</div>} />
          <Route path="readiness-check" element={<div>wizard content</div>} />
          <Route path="disaster-drill" element={<div>disaster drill content</div>} />
          <Route path="settings" element={<div>settings content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("AppLayout wallet-data chrome (§22.4/§22.6)", () => {
  // The session network is a module singleton; reset it so each test starts at
  // the default (mainnet).
  afterEach(() => {
    useSessionStore.getState().reset();
  });

  it("shows the network and safety banners on a wallet-data route", () => {
    renderAt("/readiness-check");
    // Network banner (defaults to mainnet) + verbatim safety banner are present.
    expect(screen.getByRole("status")).toHaveTextContent("MAINNET");
    expect(
      screen.getByText("Do not paste seed words, private keys, or passphrases."),
    ).toBeInTheDocument();
  });

  it("shows the network and safety banners on the disaster drill route", () => {
    renderAt("/disaster-drill");
    expect(screen.getByRole("status")).toHaveTextContent("MAINNET");
    expect(
      screen.getByText("Do not paste seed words, private keys, or passphrases."),
    ).toBeInTheDocument();
  });

  it("recolors the network banner when the session network changes (§22.4)", () => {
    renderAt("/readiness-check");
    expect(screen.getByRole("status")).toHaveClass("bg-network-mainnet");

    act(() => {
      useSessionStore.getState().setNetwork("signet");
    });
    expect(screen.getByRole("status")).toHaveClass("bg-network-signet");
  });

  it("hides both banners on screens that do not handle wallet data", () => {
    renderAt("/settings");
    expect(screen.queryByRole("status")).toBeNull();
    expect(
      screen.queryByText("Do not paste seed words, private keys, or passphrases."),
    ).toBeNull();
  });

  it("hides both banners on the Home dashboard", () => {
    renderAt("/");
    expect(screen.queryByRole("status")).toBeNull();
    expect(
      screen.queryByText("Do not paste seed words, private keys, or passphrases."),
    ).toBeNull();
  });
});

describe("AppLayout accessibility chrome (§15.5)", () => {
  afterEach(() => {
    useSessionStore.getState().reset();
    usePrefsStore.setState({ textScale: "normal" });
    document.documentElement.style.removeProperty("font-size");
  });

  it("renders a skip-to-content link that targets the main landmark", () => {
    renderAt("/");
    const skip = screen.getByRole("link", { name: "Skip to main content" });
    expect(skip).toHaveAttribute("href", "#main-content");
    // The target exists and is the page's <main> region.
    expect(document.getElementById("main-content")?.tagName).toBe("MAIN");
  });

  it("applies the large-text scale from prefs to the document root", () => {
    usePrefsStore.setState({ textScale: "larger" });
    renderAt("/");
    expect(document.documentElement.style.fontSize).toBe("200%");
  });
});
