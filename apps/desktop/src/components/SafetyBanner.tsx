import { useTranslation } from "react-i18next";

import { AlertTriangleIcon } from "./icons";

/**
 * §22.6 safety banner. A persistent, non-dismissible reminder shown in every
 * real-wallet mode (at the top of the input area) that this tool needs only
 * public wallet metadata — never seed words, private keys, or passphrases. It
 * has no dismiss control by design. Copy is verbatim §22.6 via i18n keys.
 */
export function SafetyBanner(): JSX.Element {
  const { t } = useTranslation();
  return (
    <div
      role="note"
      className="flex items-start gap-3 border-y border-status-needs-attention/40 bg-status-needs-attention/10 px-4 py-3 text-slate-800 dark:text-slate-100"
    >
      <AlertTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-status-needs-attention" />
      <div>
        <p className="font-medium">{t("banners.safety.warning")}</p>
        <p className="text-sm text-slate-600 dark:text-slate-300">{t("banners.safety.detail")}</p>
      </div>
    </div>
  );
}
