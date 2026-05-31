import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import de from "./de.json";
import en from "./en.json";
import es from "./es.json";
import fr from "./fr.json";

export interface SupportedLocale {
  code: string;
  labelKey: string;
}

export const SUPPORTED_LOCALES: SupportedLocale[] = [
  { code: "en", labelKey: "pages.settings.language.english" },
  { code: "es", labelKey: "pages.settings.language.spanish" },
  { code: "de", labelKey: "pages.settings.language.german" },
  { code: "fr", labelKey: "pages.settings.language.french" },
];

const SUPPORTED_LOCALE_CODES = new Set(SUPPORTED_LOCALES.map((locale) => locale.code));

const resources = {
  en: { translation: en },
  es: { translation: es },
  de: { translation: de },
  fr: { translation: fr },
};

export function normalizeLocale(language: string | null | undefined): string {
  const primary = (language ?? "en").split("-")[0]?.toLowerCase() ?? "en";
  return SUPPORTED_LOCALE_CODES.has(primary) ? primary : "en";
}

export function applyDocumentLanguage(language: string): void {
  if (typeof document === "undefined") return;
  document.documentElement.lang = normalizeLocale(language);
}

/**
 * Synchronous i18n bootstrap.
 *
 * Resources are bundled at build time (no network backend — the app makes no
 * network requests by default), so `init` resolves immediately and components
 * can call `t()` on first render. Community translations are bundled here too;
 * no runtime backend or network fetch is used. All user-facing copy must come
 * from these keys; no hardcoded strings in components.
 */
void i18n.use(initReactI18next).init({
  resources,
  lng: "en",
  fallbackLng: "en",
  supportedLngs: SUPPORTED_LOCALES.map((locale) => locale.code),
  nonExplicitSupportedLngs: true,
  returnNull: false,
  interpolation: {
    // React already escapes interpolated values.
    escapeValue: false,
  },
});

i18n.on("languageChanged", applyDocumentLanguage);
applyDocumentLanguage(i18n.language);

export default i18n;
