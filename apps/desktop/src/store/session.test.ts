import { afterEach, describe, expect, it, vi } from "vitest";

import { usePrefsStore } from "./prefs";
import { useSessionStore } from "./session";

/**
 * Enforces the §13 / §22.11 invariant: Confidential session data never reaches
 * web storage. If a future change wraps the session store in the `persist`
 * middleware — or any code writes a descriptor/address to localStorage — these
 * tests fail. The settings story (US-054) persists Public prefs to the Tauri
 * settings file, also NOT to web storage; the last case guards that too.
 */
describe("session store never persists Confidential data to web storage", () => {
  afterEach(() => {
    useSessionStore.getState().reset();
    usePrefsStore.setState({ theme: "system", language: "en" });
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("leaves localStorage and sessionStorage empty after holding a descriptor and report", () => {
    useSessionStore
      .getState()
      .setDescriptor("wpkh([00000000/84h/0h/0h]xpubCONFIDENTIAL/0/*)#ab12cd34");
    useSessionStore.getState().setKnownAddress("bc1qConfidentialKnownAddress");
    useSessionStore.getState().setReport({ score: { numeric: 42 } });
    useSessionStore
      .getState()
      .setDerivedAddresses([{ index: 0, address: "bc1qConfidentialDerived", chain: "receive" }]);

    // The data is readable from the in-memory store...
    expect(useSessionStore.getState().descriptor).toContain("xpubCONFIDENTIAL");
    // ...but nothing was written to web storage.
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("never calls Storage.setItem when Confidential data changes", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");

    useSessionStore.getState().setDescriptor("tr([deadbeef/86h/0h/0h]xpubCONFIDENTIAL/0/*)");
    useSessionStore.getState().setKnownAddress("bc1pConfidential");
    useSessionStore.getState().setReport({ leak: "xpubCONFIDENTIAL" });

    expect(setItem).not.toHaveBeenCalled();
  });

  it("does not write Public prefs to web storage either (prefs persist via the settings file)", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");

    usePrefsStore.getState().setTheme("dark");
    usePrefsStore.getState().setLanguage("es");

    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
