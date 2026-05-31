import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Settings from "./Settings";
import i18n from "../i18n";
import { usePrefsStore } from "../store/prefs";
import * as commands from "../tauri/commands";

// The Settings page is the single consumer of the §22.11 settings + About
// commands. Mock the IPC seam so the jsdom suite never touches the real bridge
// (mirrors the pattern other component tests use). i18n is initialized by
// src/test/setup.ts before these render.
vi.mock("../tauri/commands", () => ({
  getAppInfo: vi.fn().mockResolvedValue({
    name: "Bitcoin Lifeboat",
    version: "0.1.0-test",
    license: "MIT",
    repository: "https://github.com/example-org/bitcoin-lifeboat",
    homepage: "https://bitcoinlifeboat.org",
  }),
  openExternalLink: vi.fn().mockResolvedValue(undefined),
  saveSettings: vi.fn().mockResolvedValue(undefined),
  clearAllData: vi.fn().mockResolvedValue(undefined),
  loadSettings: vi.fn().mockResolvedValue(undefined),
}));

const mocked = vi.mocked(commands);

describe("Settings page (§22.11 / US-054)", () => {
  afterEach(async () => {
    usePrefsStore.setState({
      theme: "system",
      language: "en",
      diagnosticsEnabled: false,
      showAdvancedDetails: false,
      textScale: "normal",
    });
    await i18n.changeLanguage("en");
    document.documentElement.lang = "en";
    document.documentElement.style.removeProperty("font-size");
    vi.clearAllMocks();
  });

  it("changes the theme and persists it to the settings file", async () => {
    const user = userEvent.setup();
    render(<Settings />);

    await user.click(screen.getByRole("radio", { name: "Dark" }));

    expect(usePrefsStore.getState().theme).toBe("dark");
    expect(mocked.saveSettings).toHaveBeenCalled();
    const calls = mocked.saveSettings.mock.calls;
    const saved = calls[calls.length - 1]?.[0];
    expect(saved).toMatchObject({ theme: "dark", diagnostics_enabled: false });
  });

  it("changes the §15.5 text size, applying and persisting the scale", async () => {
    const user = userEvent.setup();
    render(<Settings />);

    await user.click(screen.getByRole("radio", { name: "Large (1.5×)" }));

    expect(usePrefsStore.getState().textScale).toBe("large");
    expect(document.documentElement.style.fontSize).toBe("150%");
    expect(mocked.saveSettings).toHaveBeenCalled();
    const calls = mocked.saveSettings.mock.calls;
    const saved = calls[calls.length - 1]?.[0];
    expect(saved).toMatchObject({ text_scale: "large" });
  });

  it("defaults diagnostic logging to OFF and persists when enabled", async () => {
    const user = userEvent.setup();
    render(<Settings />);

    const toggle = screen.getByRole("checkbox", { name: /diagnostic logging/i });
    expect(toggle).not.toBeChecked();

    await user.click(toggle);
    expect(usePrefsStore.getState().diagnosticsEnabled).toBe(true);
    expect(mocked.saveSettings).toHaveBeenCalled();
  });

  it("switches languages, rerenders translated labels, and persists the locale", async () => {
    const user = userEvent.setup();
    render(<Settings />);

    await user.selectOptions(screen.getByRole("combobox", { name: "Language" }), "es");

    expect(usePrefsStore.getState().language).toBe("es");
    expect(document.documentElement.lang).toBe("es");
    expect(screen.getByRole("heading", { name: "Tema" })).toBeInTheDocument();
    const calls = mocked.saveSettings.mock.calls;
    const saved = calls[calls.length - 1]?.[0];
    expect(saved).toMatchObject({ language: "es" });
  });

  it("shows the version and opens the GitHub releases page in the OS browser", async () => {
    const user = userEvent.setup();
    render(<Settings />);

    expect(await screen.findByText("0.1.0-test")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /releases/i }));
    expect(mocked.openExternalLink).toHaveBeenCalledWith(
      "https://github.com/example-org/bitcoin-lifeboat/releases",
    );
  });

  it("clears all local data after a confirmation step", async () => {
    const user = userEvent.setup();
    usePrefsStore.setState({ theme: "dark", diagnosticsEnabled: true });
    render(<Settings />);

    await user.click(screen.getByRole("button", { name: /clear all local data/i }));
    await user.click(screen.getByRole("button", { name: /^yes/i }));

    expect(mocked.clearAllData).toHaveBeenCalled();
    await waitFor(() => expect(usePrefsStore.getState().theme).toBe("system"));
    expect(usePrefsStore.getState().diagnosticsEnabled).toBe(false);
  });

  it("exposes no control that unlocks seed entry or bypasses safety", () => {
    render(<Settings />);
    expect(screen.queryByText(/seed/i)).toBeNull();
    expect(screen.queryByText(/private key/i)).toBeNull();
  });
});
