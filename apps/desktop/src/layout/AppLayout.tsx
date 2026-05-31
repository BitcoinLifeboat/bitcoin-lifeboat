import { useEffect } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";

import { NetworkBanner } from "../components/NetworkBanner";
import { SafetyBanner } from "../components/SafetyBanner";
import { usePrefsStore } from "../store/prefs";
import { useSessionStore } from "../store/session";
import { applyTextScale, applyTheme } from "../theme/theme";

interface NavItem {
  to: string;
  labelKey: string;
}

// §22.1 primary navigation, in order.
const NAV_ITEMS: NavItem[] = [
  { to: "/", labelKey: "nav.home" },
  { to: "/readiness-check", labelKey: "nav.readinessCheck" },
  { to: "/audit-multisig", labelKey: "nav.auditMultisig" },
  { to: "/heir-runbook", labelKey: "nav.heirRunbook" },
  { to: "/heir-walkthrough", labelKey: "nav.heirWalkthrough" },
  { to: "/generate-runbook", labelKey: "nav.generateRunbook" },
  { to: "/disaster-drill", labelKey: "nav.disasterDrill" },
  { to: "/hardware-wallet-drill", labelKey: "nav.hardwareWalletDrill" },
  { to: "/learn", labelKey: "nav.learn" },
  { to: "/settings", labelKey: "nav.settings" },
];

// §22.4/§22.6: routes that handle real wallet data show the network and safety
// banners. Home (no descriptors), Learn (Practice Mode, v0.2), and Settings do
// not handle wallet data, so they show neither.
const WALLET_DATA_PATHS = new Set([
  "/readiness-check",
  "/audit-multisig",
  "/heir-runbook",
  "/generate-runbook",
  "/disaster-drill",
  "/hardware-wallet-drill",
]);

function navLinkClass({ isActive }: { isActive: boolean }): string {
  return [
    "block rounded px-3 py-2 text-sm",
    isActive
      ? "bg-brand text-white"
      : "text-slate-700 hover:bg-slate-200 dark:text-slate-200 dark:hover:bg-slate-800",
  ].join(" ");
}

/** App frame: §22.1 sidebar navigation plus the routed screen via <Outlet>. On
 *  wallet-data screens it also shows the §22.4 network banner and §22.6 safety
 *  banner across the top of the content area. */
export default function AppLayout(): JSX.Element {
  const { t } = useTranslation();
  const theme = usePrefsStore((state) => state.theme);
  const textScale = usePrefsStore((state) => state.textScale);
  const network = useSessionStore((state) => state.network);
  const location = useLocation();
  const showWalletChrome = WALLET_DATA_PATHS.has(location.pathname);

  // Keep the <html> dark class in sync with the chosen theme (§22.10).
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Keep the §15.5 large-text scale applied to the root as the preference changes.
  useEffect(() => {
    applyTextScale(textScale);
  }, [textScale]);

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-900 dark:text-slate-100">
      {/* §15.5 / WCAG 2.4.1: a keyboard skip link, the first focusable element,
          lets keyboard and screen-reader users jump past the nav to the page. */}
      <a
        href="#main-content"
        className="sr-only rounded bg-brand px-3 py-2 text-sm font-medium text-white focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50"
      >
        {t("a11y.skipToContent")}
      </a>
      <nav
        aria-label={t("a11y.primaryNavigation")}
        className="w-60 shrink-0 border-r border-slate-200 p-4 dark:border-slate-700"
      >
        <div className="mb-6">
          <p className="text-lg font-semibold">{t("app.name")}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t("app.tagline")}</p>
        </div>
        <ul className="space-y-1">
          {NAV_ITEMS.map((item) => (
            <li key={item.to}>
              <NavLink to={item.to} end={item.to === "/"} className={navLinkClass}>
                {t(item.labelKey)}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <main id="main-content" tabIndex={-1} className="flex flex-1 flex-col outline-none">
        {showWalletChrome && (
          <>
            <NetworkBanner network={network} />
            <SafetyBanner />
          </>
        )}
        <div className="flex-1 p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
