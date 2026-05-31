import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { PageScaffold } from "./PageScaffold";
import { usePrefsStore, toSettings, type ThemePreference, type TextScale } from "../store/prefs";
import { applyTextScale, applyTheme } from "../theme/theme";
import {
  clearAllData,
  getAppInfo,
  openExternalLink,
  saveSettings,
  type AppInfo,
} from "../tauri/commands";
import i18n, { SUPPORTED_LOCALES, normalizeLocale } from "../i18n";

const THEME_OPTIONS: ThemePreference[] = ["system", "light", "dark"];
const TEXT_SCALE_OPTIONS: TextScale[] = ["normal", "large", "larger"];

/** Settings: theme, language, display/diagnostics toggles, clear data, and an
 *  About panel (US-054 / §22.11). Only Public preferences are exposed — there is
 *  no control that unlocks seed entry or bypasses a safety warning. */
export default function Settings(): JSX.Element {
  const { t } = useTranslation();
  const theme = usePrefsStore((s) => s.theme);
  const textScale = usePrefsStore((s) => s.textScale);
  const language = usePrefsStore((s) => s.language);
  const diagnosticsEnabled = usePrefsStore((s) => s.diagnosticsEnabled);
  const showAdvancedDetails = usePrefsStore((s) => s.showAdvancedDetails);

  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [confirmingClear, setConfirmingClear] = useState(false);
  const [clearStatus, setClearStatus] = useState<"idle" | "done" | "error">("idle");

  useEffect(() => {
    let active = true;
    getAppInfo()
      .then((info) => {
        if (active) setAppInfo(info);
      })
      .catch(() => {
        if (active) setAppInfo(null);
      });
    return () => {
      active = false;
    };
  }, []);

  // Persist the current Public prefs to the settings file (never web storage).
  // Best-effort: a failure leaves the app working from in-memory state.
  function persist(): void {
    void saveSettings(toSettings(usePrefsStore.getState())).catch(() => {
      /* best-effort persistence */
    });
  }

  function onThemeChange(next: ThemePreference): void {
    usePrefsStore.getState().setTheme(next);
    applyTheme(next);
    persist();
  }

  function onTextScaleChange(next: TextScale): void {
    usePrefsStore.getState().setTextScale(next);
    applyTextScale(next);
    persist();
  }

  function onLanguageChange(next: string): void {
    const language = normalizeLocale(next);
    usePrefsStore.getState().setLanguage(language);
    void i18n.changeLanguage(language);
    persist();
  }

  function onDiagnosticsChange(next: boolean): void {
    usePrefsStore.getState().setDiagnosticsEnabled(next);
    persist();
  }

  function onAdvancedChange(next: boolean): void {
    usePrefsStore.getState().setShowAdvancedDetails(next);
    persist();
  }

  function onClearAllData(): void {
    clearAllData()
      .then(() => {
        usePrefsStore.getState().applySettings({
          version: 1,
          theme: "system",
          language: "en",
          diagnostics_enabled: false,
          show_advanced_details: false,
          text_scale: "normal",
        });
        applyTheme("system");
        applyTextScale("normal");
        void i18n.changeLanguage("en");
        setClearStatus("done");
      })
      .catch(() => setClearStatus("error"))
      .finally(() => setConfirmingClear(false));
  }

  const releasesUrl = appInfo ? `${appInfo.repository}/releases` : null;

  return (
    <PageScaffold titleKey="pages.settings.title" bodyKey="pages.settings.body">
      <div className="mt-6 space-y-8">
        <section aria-labelledby="settings-theme-heading">
          <h2 id="settings-theme-heading" className="text-lg font-medium">
            {t("pages.settings.theme.label")}
          </h2>
          <div className="mt-2 flex gap-4">
            {THEME_OPTIONS.map((option) => (
              <label key={option} className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="theme"
                  value={option}
                  checked={theme === option}
                  onChange={() => onThemeChange(option)}
                />
                {t(`pages.settings.theme.options.${option}`)}
              </label>
            ))}
          </div>
        </section>

        <section aria-labelledby="settings-text-size-heading">
          <h2 id="settings-text-size-heading" className="text-lg font-medium">
            {t("pages.settings.textSize.label")}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {t("pages.settings.textSize.help")}
          </p>
          <div className="mt-2 flex gap-4">
            {TEXT_SCALE_OPTIONS.map((option) => (
              <label key={option} className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="text-scale"
                  value={option}
                  checked={textScale === option}
                  onChange={() => onTextScaleChange(option)}
                />
                {t(`pages.settings.textSize.options.${option}`)}
              </label>
            ))}
          </div>
        </section>

        <section aria-labelledby="settings-language-heading">
          <h2 id="settings-language-heading" className="text-lg font-medium">
            {t("pages.settings.language.label")}
          </h2>
          <select
            className="mt-2 rounded border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-600 dark:bg-slate-800"
            aria-label={t("pages.settings.language.label")}
            value={language}
            onChange={(e) => onLanguageChange(e.target.value)}
          >
            {SUPPORTED_LOCALES.map((locale) => (
              <option key={locale.code} value={locale.code}>
                {t(locale.labelKey)}
              </option>
            ))}
          </select>
        </section>

        <section aria-labelledby="settings-display-heading">
          <h2 id="settings-display-heading" className="text-lg font-medium">
            {t("pages.settings.display.label")}
          </h2>
          <label className="mt-2 flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showAdvancedDetails}
              onChange={(e) => onAdvancedChange(e.target.checked)}
            />
            {t("pages.settings.advanced.label")}
          </label>
          <label className="mt-2 flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={diagnosticsEnabled}
              onChange={(e) => onDiagnosticsChange(e.target.checked)}
            />
            {t("pages.settings.diagnostics.label")}
          </label>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {t("pages.settings.diagnostics.help")}
          </p>
        </section>

        <section aria-labelledby="settings-clear-heading">
          <h2 id="settings-clear-heading" className="text-lg font-medium">
            {t("pages.settings.clearData.label")}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {t("pages.settings.clearData.help")}
          </p>
          {confirmingClear ? (
            <div className="mt-2 flex items-center gap-3">
              <span className="text-sm">{t("pages.settings.clearData.confirm")}</span>
              <button
                type="button"
                className="rounded bg-red-600 px-3 py-1 text-sm text-white"
                onClick={onClearAllData}
              >
                {t("pages.settings.clearData.confirmYes")}
              </button>
              <button
                type="button"
                className="rounded border border-slate-300 px-3 py-1 text-sm dark:border-slate-600"
                onClick={() => setConfirmingClear(false)}
              >
                {t("pages.settings.clearData.cancel")}
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="mt-2 rounded border border-red-600 px-3 py-1 text-sm text-red-700 dark:text-red-400"
              onClick={() => {
                setClearStatus("idle");
                setConfirmingClear(true);
              }}
            >
              {t("pages.settings.clearData.button")}
            </button>
          )}
          {clearStatus === "done" && (
            <p className="mt-2 text-sm text-green-700 dark:text-green-400">
              {t("pages.settings.clearData.done")}
            </p>
          )}
          {clearStatus === "error" && (
            <p className="mt-2 text-sm text-red-700 dark:text-red-400">
              {t("pages.settings.clearData.error")}
            </p>
          )}
        </section>

        <section aria-labelledby="settings-about-heading">
          <h2 id="settings-about-heading" className="text-lg font-medium">
            {t("pages.settings.about.label")}
          </h2>
          {appInfo ? (
            <dl className="mt-2 space-y-1 text-sm">
              <div className="flex gap-2">
                <dt className="text-slate-500 dark:text-slate-400">
                  {t("pages.settings.about.version")}
                </dt>
                <dd>{appInfo.version}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-slate-500 dark:text-slate-400">
                  {t("pages.settings.about.license")}
                </dt>
                <dd>{appInfo.license}</dd>
              </div>
            </dl>
          ) : (
            <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              {t("pages.settings.about.unavailable")}
            </p>
          )}
          {releasesUrl && (
            <button
              type="button"
              className="mt-3 rounded bg-brand px-3 py-1 text-sm text-white"
              onClick={() => {
                void openExternalLink(releasesUrl).catch(() => {
                  /* allowlist refusal or no browser: leave the UI unchanged */
                });
              }}
            >
              {t("pages.settings.about.releases")}
            </button>
          )}
        </section>
      </div>
    </PageScaffold>
  );
}
