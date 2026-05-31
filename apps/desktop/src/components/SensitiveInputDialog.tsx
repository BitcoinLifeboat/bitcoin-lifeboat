import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import type { DetectedSecret } from "../tauri/commands";
import { XCircleIcon } from "./icons";

/**
 * §22.7 Sensitive-Input Block Dialog.
 *
 * Shown when the §13.5 detector returns `Block` for pasted/loaded input. It is a
 * hard stop: the dialog CANNOT be dismissed with Escape — only the "I understand"
 * button closes it (§22.7). The detected secret's CONTENT is never displayed; the
 * only thing shown about it is a category derived from the leak-free
 * {@link DetectedSecret} discriminant (e.g. "a 12-word BIP39 seed phrase"), never
 * its characters. By the time this renders the caller has already cleared the
 * field (§13.5.7), so closing the dialog returns the user to an empty input.
 *
 * Presentational only — it owns no detector logic. Render it whenever `detected`
 * is non-null; pass `null` to hide it.
 */

interface SensitiveInputDialogProps {
  /** The recognized secret to summarize, or `null` to render nothing. */
  detected: DetectedSecret | null;
  /** Called when the user clicks "I understand" (the only way to close). */
  onAcknowledge: () => void;
}

/**
 * The i18n key (and interpolation count, for BIP39) for a short, NON-secret
 * category phrase describing the detected secret (§22.7 "What we detected").
 * Reads only the discriminant + non-secret metadata (e.g. word count) — never
 * the secret's own characters.
 */
function describeSecret(detected: DetectedSecret): { key: string; count?: number } {
  const base = "dialogs.sensitiveInput.detected";
  if (typeof detected === "string") {
    return { key: detected === "raw_hex_priv_key" ? `${base}.rawHex` : `${base}.generic` };
  }
  if ("bip39" in detected) {
    return { key: `${base}.bip39`, count: detected.bip39.word_count };
  }
  if ("wif" in detected) {
    return { key: `${base}.wif` };
  }
  if ("xprv" in detected) {
    return { key: `${base}.xprv` };
  }
  if ("slip39" in detected) {
    return { key: `${base}.slip39` };
  }
  if ("codex32" in detected) {
    return { key: `${base}.codex32` };
  }
  return { key: `${base}.generic` };
}

const STEP_KEYS = ["step1", "step2", "step3", "step4"] as const;

export default function SensitiveInputDialog({
  detected,
  onAcknowledge,
}: SensitiveInputDialogProps): JSX.Element | null {
  const { t } = useTranslation();
  const acknowledgeRef = useRef<HTMLButtonElement>(null);

  // Move focus to the only actionable control as soon as the block appears, so
  // keyboard users land on "I understand" and screen readers announce the dialog.
  useEffect(() => {
    if (detected !== null) {
      acknowledgeRef.current?.focus();
    }
  }, [detected]);

  if (detected === null) {
    return null;
  }

  const summary = describeSecret(detected);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/70 p-4"
      // §22.7: the dialog cannot be dismissed by Escape. Swallow it here so no
      // ancestor can interpret Escape as "close" — only "I understand" closes.
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
        }
      }}
    >
      <div
        role="alertdialog"
        aria-modal={true}
        aria-labelledby="sensitive-input-title"
        aria-describedby="sensitive-input-body"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg bg-white p-6 shadow-xl dark:bg-slate-800"
      >
        <div className="flex items-start gap-3">
          <XCircleIcon className="mt-0.5 h-7 w-7 shrink-0 text-status-not-ready" />
          <h2
            id="sensitive-input-title"
            className="text-lg font-semibold text-slate-900 dark:text-slate-100"
          >
            {t("dialogs.sensitiveInput.title")}
          </h2>
        </div>

        <div id="sensitive-input-body" className="mt-4 space-y-3 text-sm text-slate-700 dark:text-slate-200">
          <p>{t("dialogs.sensitiveInput.body1")}</p>
          <p>{t("dialogs.sensitiveInput.body2")}</p>
          <p>
            <span className="font-medium text-slate-900 dark:text-slate-100">
              {t("dialogs.sensitiveInput.detectedLabel")}
            </span>{" "}
            {summary.count === undefined ? t(summary.key) : t(summary.key, { count: summary.count })}
          </p>
        </div>

        <div className="mt-4">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {t("dialogs.sensitiveInput.whatToDo")}
          </h3>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-200">
            {STEP_KEYS.map((key) => (
              <li key={key}>{t(`dialogs.sensitiveInput.${key}`)}</li>
            ))}
          </ol>
        </div>

        <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
          {t("dialogs.sensitiveInput.help")}
        </p>

        <div className="mt-6 flex justify-end">
          <button
            ref={acknowledgeRef}
            type="button"
            onClick={onAcknowledge}
            className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg"
          >
            {t("dialogs.sensitiveInput.acknowledge")}
          </button>
        </div>
      </div>
    </div>
  );
}
