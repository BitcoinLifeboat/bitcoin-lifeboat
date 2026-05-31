import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";
import i18n, { normalizeLocale } from "./i18n";
import "./styles.css";
import { loadSettings } from "./tauri/commands";
import { usePrefsStore } from "./store/prefs";
import { applyTextScale, applyTheme } from "./theme/theme";

const root = document.getElementById("root");
if (!root) {
  throw new Error("root element missing from index.html");
}

// Hydrate the §22.11 Public preferences from the Tauri settings file at startup
// (best-effort: a first launch or a read failure just keeps the in-memory
// defaults). Never reads web storage.
void loadSettings()
  .then((settings) => {
    const language = normalizeLocale(settings.language);
    usePrefsStore.getState().applySettings({ ...settings, language });
    applyTheme(settings.theme);
    applyTextScale(settings.text_scale);
    void i18n.changeLanguage(language);
  })
  .catch(() => {
    /* first launch or read failure: keep in-memory defaults */
  });

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
