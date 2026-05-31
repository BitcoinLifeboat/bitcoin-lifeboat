import { create } from "zustand";

import type { Settings, TextScaleSetting } from "../tauri/commands";

export type ThemePreference = "system" | "light" | "dark";

/** The §15.5 large-text accessibility scale (alias of the wire type). */
export type TextScale = TextScaleSetting;

/** Mirrors the Rust `desktop_commands::SETTINGS_SCHEMA_VERSION`. */
export const SETTINGS_SCHEMA_VERSION = 1;

/**
 * Public, non-confidential preferences (§22.11 Settings).
 *
 * Only Public-classified preferences live here, and they persist ONLY via the
 * Tauri-managed settings file (US-054 — `tauri/commands` `loadSettings`/
 * `saveSettings`), NEVER browser web storage (enforced by `store/session.test`).
 * The store stays pure: setters only update in-memory state. The Settings screen
 * calls `saveSettings` after a change, and `main.tsx` calls `applySettings` once
 * at startup with the loaded file. The store must never hold Confidential data.
 *
 * `onboardingComplete` is the §15.2 first-launch flag (Public, but NOT part of
 * the persisted settings-file schema — it resets each launch by design).
 */
export interface PrefsState {
  theme: ThemePreference;
  language: string;
  diagnosticsEnabled: boolean;
  showAdvancedDetails: boolean;
  textScale: TextScale;
  onboardingComplete: boolean;
  setTheme: (theme: ThemePreference) => void;
  setLanguage: (language: string) => void;
  setDiagnosticsEnabled: (diagnosticsEnabled: boolean) => void;
  setShowAdvancedDetails: (showAdvancedDetails: boolean) => void;
  setTextScale: (textScale: TextScale) => void;
  setOnboardingComplete: (onboardingComplete: boolean) => void;
  /** Replace the persisted Public prefs from a loaded settings file (startup
   *  hydration). Pure: it only sets in-memory state. */
  applySettings: (settings: Settings) => void;
}

export const usePrefsStore = create<PrefsState>((set) => ({
  theme: "system",
  language: "en",
  diagnosticsEnabled: false,
  showAdvancedDetails: false,
  textScale: "normal",
  onboardingComplete: false,
  setTheme: (theme) => set({ theme }),
  setLanguage: (language) => set({ language }),
  setDiagnosticsEnabled: (diagnosticsEnabled) => set({ diagnosticsEnabled }),
  setShowAdvancedDetails: (showAdvancedDetails) => set({ showAdvancedDetails }),
  setTextScale: (textScale) => set({ textScale }),
  setOnboardingComplete: (onboardingComplete) => set({ onboardingComplete }),
  applySettings: (settings) =>
    set({
      theme: settings.theme,
      language: settings.language,
      diagnosticsEnabled: settings.diagnostics_enabled,
      showAdvancedDetails: settings.show_advanced_details,
      textScale: settings.text_scale,
    }),
}));

/**
 * Build the persisted §22.11 settings DTO (snake_case) from the current store
 * state. The schema is exactly the Public fields — never Confidential data.
 */
export function toSettings(state: PrefsState): Settings {
  return {
    version: SETTINGS_SCHEMA_VERSION,
    theme: state.theme,
    language: state.language,
    diagnostics_enabled: state.diagnosticsEnabled,
    show_advanced_details: state.showAdvancedDetails,
    text_scale: state.textScale,
  };
}
