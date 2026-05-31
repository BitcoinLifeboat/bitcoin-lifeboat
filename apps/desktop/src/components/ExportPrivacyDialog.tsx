import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { AlertTriangleIcon } from "./icons";

/**
 * §9.5 / §14.3 Private-export confirmation dialog.
 *
 * Switching an export from the default `public-safe` mode to `private` reveals the
 * wallet's xpubs (full key material). Per §9.5 that switch requires an explicit
 * toggle AND this confirmation, which states verbatim what private mode exposes.
 *
 * Unlike the §22.7 sensitive-input block (a hard stop that swallows Escape), this
 * dialog's fallback is the SAFE state: cancelling — via the Cancel button, the
 * backdrop, or Escape — keeps the share-safe `public-safe` mode. Only the explicit
 * confirm button switches to private. Presentational only: render it whenever
 * `open` is true; it owns no export logic. The §9.5 "single-button" requirement is
 * met by the single confirm action; the Cancel affordance only returns to the safer
 * default, so it never lets the user skip the warning to reach private mode.
 */

interface ExportPrivacyDialogProps {
  /** Whether the dialog is shown (true once the user flips the private toggle). */
  open: boolean;
  /** Confirm: switch the export to private mode. */
  onConfirm: () => void;
  /** Cancel / dismiss: keep the safe `public-safe` mode. */
  onCancel: () => void;
}

export default function ExportPrivacyDialog({
  open,
  onConfirm,
  onCancel,
}: ExportPrivacyDialogProps): JSX.Element | null {
  const { t } = useTranslation();
  const confirmRef = useRef<HTMLButtonElement>(null);

  // Focus the confirm button when the dialog opens so keyboard users land on the
  // action they just requested (and a screen reader announces the alertdialog).
  useEffect(() => {
    if (open) {
      confirmRef.current?.focus();
    }
  }, [open]);

  if (!open) {
    return null;
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/70 p-4"
      // Clicking the backdrop cancels back to the safe default.
      onClick={onCancel}
      // Escape cancels to the safe `public-safe` mode. The fallback here is safe,
      // so — unlike the §22.7 block dialog — Escape is honored, not swallowed.
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          onCancel();
        }
      }}
    >
      <div
        role="alertdialog"
        aria-modal={true}
        aria-labelledby="export-privacy-title"
        aria-describedby="export-privacy-body"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg bg-white p-6 shadow-xl dark:bg-slate-800"
        // Keep clicks inside the panel from bubbling to the backdrop's cancel.
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start gap-3">
          <AlertTriangleIcon className="mt-0.5 h-7 w-7 shrink-0 text-status-needs-attention" />
          <h2
            id="export-privacy-title"
            className="text-lg font-semibold text-slate-900 dark:text-slate-100"
          >
            {t("dialogs.exportPrivacy.title")}
          </h2>
        </div>

        <div
          id="export-privacy-body"
          className="mt-4 space-y-3 text-sm text-slate-700 dark:text-slate-200"
        >
          <p>{t("dialogs.exportPrivacy.warning")}</p>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="rounded px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            {t("dialogs.exportPrivacy.cancel")}
          </button>
          <button
            ref={confirmRef}
            type="button"
            onClick={onConfirm}
            className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg"
          >
            {t("dialogs.exportPrivacy.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
