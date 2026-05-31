import { useEffect, useState } from "react";
import type { ClipboardEvent } from "react";
import { useTranslation } from "react-i18next";

import ExportPrivacyDialog from "../components/ExportPrivacyDialog";
import SensitiveInputDialog from "../components/SensitiveInputDialog";
import {
  detectSensitiveInput,
  generateRunbook,
  saveExport,
  showSaveDialog,
} from "../tauri/commands";
import type { DetectedSecret, RedactionMode, RunbookFormat } from "../tauri/commands";

/**
 * §31.2 guided "Create a Family / Heir Runbook" flow (US-053).
 *
 * The dedicated, step-by-step way to produce an inheritance recovery plan a
 * non-technical heir can follow. It walks the owner through three steps:
 *   1. Choose a heir recovery plan (a `HeirTemplate`).
 *   2. (Optional) pre-fill the wallet details from a watch-only descriptor, and
 *      read the §9.4 / §9.5 guidance on signer locations.
 *   3. Preview the plan — with labeled blanks the owner completes by hand — and
 *      export it, public-safe by default.
 *
 * Like the standalone runbook generator (US-052), the frontend runs NO Bitcoin
 * logic (§13.7 / §20): it picks a template and (optionally) hands a descriptor to
 * the Rust core, which screens it for secrets, parses it, and renders the
 * deterministic runbook ({@link generateRunbook}). It REUSES that command and the
 * detect-before-process screening flow rather than re-implementing them.
 *
 * SAFETY (§9.4 / §9.5): this flow NEVER accepts a seed phrase, passphrase value,
 * private key, or a free-text signer location. The only fill input is the optional
 * watch-only descriptor (public wallet metadata, still screened). Locations,
 * helper/lawyer contacts, and the like stay as labeled BLANK fields the owner fills
 * in by hand AFTER printing — so those details never touch the computer. The
 * exported plan is public-safe by default; switching to `private` (which reveals
 * xpubs) is gated behind the §9.5 confirmation dialog.
 */

/** The §9.4 heir-recovery runbook templates (`HeirTemplate::name()` in the core),
 *  the subset written for a non-technical heir. The meetup-workshop and
 *  business-treasury education templates are offered by the standalone generator
 *  (US-052), not this inheritance flow. */
const HEIR_TEMPLATES = [
  "heir-singlesig-basic",
  "heir-singlesig-passphrase",
  "heir-multisig-2of3",
  "heir-multisig-3of5",
  "liana-timelock",
] as const;

const EXPORT_FORMATS: RunbookFormat[] = ["pdf", "markdown"];

const TOTAL_STEPS = 3;
const TEMPLATE_STEP = 1;
const DETAILS_STEP = 2;
const REVIEW_STEP = 3;

// §22.9 sample descriptors — the committed, documented test-network fixtures (tpub,
// never mainnet), shared with the Readiness Check wizard and the runbook generator.
// Inert sample strings: no parsing happens in the frontend. The multisig sample
// pre-fills a multisig plan's signer table; the singlesig sample the simpler plans.
const SAMPLE_SINGLESIG =
  "wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/0/*)#r6yctejg";
const SAMPLE_MULTISIG =
  "wsh(sortedmulti(2,[4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/0/*,[6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/0/*,[8dfc9b34/48'/1'/0'/2']tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq/0/*))#c2yhzrq7";
const SAMPLE_LIANA =
  "wsh(or_d(pk([4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/<0;1>/*),and_v(v:pkh([6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/<0;1>/*),older(65535))))#d3zjscz4";

const primaryButton =
  "rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg " +
  "disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "rounded px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 " +
  "disabled:cursor-not-allowed disabled:opacity-50 dark:text-slate-200 dark:hover:bg-slate-800";
const optionLabel =
  "flex cursor-pointer items-center gap-3 rounded border border-slate-200 p-3 " +
  "hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-700";

/** Pick the committed test descriptor that best matches the selected plan. */
function sampleForTemplate(template: string): string {
  if (template === "liana-timelock") {
    return SAMPLE_LIANA;
  }
  if (template.includes("multisig")) {
    return SAMPLE_MULTISIG;
  }
  return SAMPLE_SINGLESIG;
}

/** Decode the runbook engine's UTF-8 byte array into the Markdown preview text. */
function decodeContent(content: number[]): string {
  return new TextDecoder().decode(new Uint8Array(content));
}

export default function HeirRunbook(): JSX.Element {
  const { t } = useTranslation();

  const [step, setStep] = useState(TEMPLATE_STEP);
  const [template, setTemplate] = useState<string>(HEIR_TEMPLATES[0]);

  // `descriptor` is the editable field text; `appliedDescriptor` is the screened,
  // safe-to-send value the preview/export actually use ("" = none, blank template).
  const [descriptor, setDescriptor] = useState("");
  const [appliedDescriptor, setAppliedDescriptor] = useState("");
  const [redaction, setRedaction] = useState<RedactionMode>("public-safe");
  const [exportFormat, setExportFormat] = useState<RunbookFormat>("pdf");

  // §13.5 secret screening of the optional descriptor pre-fill (US-049 pattern).
  const [blockedSecret, setBlockedSecret] = useState<DetectedSecret | null>(null);
  const [warnFinding, setWarnFinding] = useState<DetectedSecret | null>(null);
  const [warnConfirmed, setWarnConfirmed] = useState(false);
  const [screening, setScreening] = useState(false);

  // §9.5 private-export confirmation gate.
  const [privacyDialogOpen, setPrivacyDialogOpen] = useState(false);

  // Live Markdown preview (regenerated by the core whenever the inputs change).
  const [previewText, setPreviewText] = useState("");
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState(false);

  // PDF / Markdown export to a dialog-chosen path.
  const [exporting, setExporting] = useState(false);
  const [exportStatus, setExportStatus] = useState<"idle" | "saved" | "cancelled" | "error">(
    "idle",
  );

  const descriptorApplied = appliedDescriptor !== "" && appliedDescriptor === descriptor;

  /**
   * §13.5 screen `candidate` BEFORE it is used to pre-fill. On `Block` the field is
   * cleared and the §22.7 dialog opens (the candidate is never applied); on `Warn`
   * the (public) text stays but is not applied until the inline override is ticked;
   * on `Allow` the descriptor is applied and the preview regenerates with it.
   */
  async function importCandidate(candidate: string): Promise<void> {
    if (candidate.trim() === "") {
      return;
    }
    setScreening(true);
    setExportStatus("idle");
    // The screened text is dropped the instant the detector returns (§13.5.9).
    let input = candidate;
    try {
      const report = await detectSensitiveInput(input);
      input = "";
      const finding: DetectedSecret = report.findings[0]?.[0] ?? "none";
      if (report.action === "block") {
        setDescriptor("");
        setAppliedDescriptor("");
        setWarnFinding(null);
        setWarnConfirmed(false);
        setBlockedSecret(finding);
        return;
      }
      // A watch-only descriptor is public metadata — safe to keep in the field.
      setDescriptor(candidate);
      if (report.action === "warn") {
        setWarnFinding(finding);
        setWarnConfirmed(false);
        setAppliedDescriptor("");
      } else {
        setWarnFinding(null);
        setWarnConfirmed(false);
        setAppliedDescriptor(candidate);
      }
    } finally {
      setScreening(false);
    }
  }

  /** Paste: screen the would-be field value BEFORE it lands (§13.5). */
  function handlePaste(event: ClipboardEvent<HTMLTextAreaElement>): void {
    event.preventDefault();
    const pasted = event.clipboardData.getData("text");
    const target = event.currentTarget;
    const start = target.selectionStart ?? descriptor.length;
    const end = target.selectionEnd ?? descriptor.length;
    void importCandidate(descriptor.slice(0, start) + pasted + descriptor.slice(end));
  }

  /** Manual typing: update the field but un-apply it, so the preview reverts to the
   *  blank template until the user re-screens it via "Use this descriptor". */
  function editDescriptor(value: string): void {
    setDescriptor(value);
    setAppliedDescriptor("");
    setWarnFinding(null);
    setWarnConfirmed(false);
    setExportStatus("idle");
  }

  /** §22.9 sample: our own watch-only test-network fixture — trusted, so it is
   *  applied without a detector call. */
  function loadSample(): void {
    const sample = sampleForTemplate(template);
    setDescriptor(sample);
    setAppliedDescriptor(sample);
    setBlockedSecret(null);
    setWarnFinding(null);
    setWarnConfirmed(false);
    setExportStatus("idle");
  }

  function clearDescriptor(): void {
    setDescriptor("");
    setAppliedDescriptor("");
    setWarnFinding(null);
    setWarnConfirmed(false);
    setExportStatus("idle");
  }

  /** §13.5.7 inline override for a `Warn` finding: ticking it applies the (public)
   *  descriptor; un-ticking reverts to the blank template. */
  function confirmWarn(checked: boolean): void {
    setWarnConfirmed(checked);
    setAppliedDescriptor(checked ? descriptor : "");
  }

  // Live preview: only on the review step, regenerate the runbook Markdown whenever
  // the template, applied descriptor, or mode changes. The core screens + parses the
  // descriptor and returns the rendered runbook bytes; we decode them to show the
  // preview. The PDF export uses the same content, so this faithfully represents it.
  useEffect(() => {
    if (step !== REVIEW_STEP) {
      return;
    }
    let cancelled = false;
    setPreviewLoading(true);
    setPreviewError(false);
    generateRunbook({
      template,
      descriptor: appliedDescriptor === "" ? null : appliedDescriptor,
      redaction,
      format: "markdown",
    })
      .then((artifact) => {
        if (!cancelled) {
          setPreviewText(decodeContent(artifact.content));
          setPreviewLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPreviewText("");
          setPreviewError(true);
          setPreviewLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [step, template, appliedDescriptor, redaction]);

  // §9.5 export mode: turning ON private opens the confirmation; it only takes
  // effect on confirm. Turning it OFF returns to the safe default with no dialog.
  function onTogglePrivate(turnOn: boolean): void {
    setExportStatus("idle");
    if (turnOn) {
      setPrivacyDialogOpen(true);
    } else {
      setRedaction("public-safe");
    }
  }

  function confirmPrivate(): void {
    setRedaction("private");
    setPrivacyDialogOpen(false);
  }

  function cancelPrivate(): void {
    // Keep the safe default; the toggle reflects `redaction`, so it stays unchecked.
    setPrivacyDialogOpen(false);
  }

  /**
   * Export the runbook: render it in the chosen format + mode via the core, open the
   * OS save dialog, and write the bytes through `save_export`. The runbook PDF is a
   * real backend document, so both formats go through this one path (US-052).
   */
  async function runExport(): Promise<void> {
    setExporting(true);
    setExportStatus("idle");
    try {
      const artifact = await generateRunbook({
        template,
        descriptor: appliedDescriptor === "" ? null : appliedDescriptor,
        redaction,
        format: exportFormat,
      });
      const extension = exportFormat === "pdf" ? "pdf" : "md";
      const path = await showSaveDialog({
        defaultPath: artifact.suggested_filename,
        filters: [
          {
            name: t(`pages.heirRunbook.format.${exportFormat}`),
            extensions: [extension],
          },
        ],
      });
      if (path === null) {
        setExportStatus("cancelled");
        return;
      }
      // The artifact content is already a byte array — write it verbatim.
      await saveExport(path, artifact.content);
      setExportStatus("saved");
    } catch {
      setExportStatus("error");
    } finally {
      setExporting(false);
    }
  }

  const stepTitleKey =
    step === TEMPLATE_STEP
      ? "pages.heirRunbook.steps.template"
      : step === DETAILS_STEP
        ? "pages.heirRunbook.steps.details"
        : "pages.heirRunbook.steps.review";

  return (
    <section className="mx-auto max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">
        {t("pages.heirRunbook.title")}
      </h1>
      <p className="mt-2 text-slate-600 dark:text-slate-300">{t("pages.heirRunbook.body")}</p>

      <p className="mt-6 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {t("pages.heirRunbook.step", { current: step, total: TOTAL_STEPS })} — {t(stepTitleKey)}
      </p>

      {/* Step 1 — choose a heir recovery plan. */}
      {step === TEMPLATE_STEP && (
        <div className="mt-4">
          <h2
            id="heir-template-heading"
            className="text-base font-semibold text-slate-900 dark:text-slate-100"
          >
            {t("pages.heirRunbook.template.heading")}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {t("pages.heirRunbook.template.help")}
          </p>
          <div role="radiogroup" aria-labelledby="heir-template-heading" className="mt-4 space-y-2">
            {HEIR_TEMPLATES.map((id) => (
              <label key={id} className={optionLabel}>
                <input
                  type="radio"
                  name="heir-template"
                  value={id}
                  className="h-4 w-4"
                  checked={template === id}
                  onChange={() => {
                    setTemplate(id);
                    setExportStatus("idle");
                  }}
                />
                <span className="text-slate-800 dark:text-slate-100">
                  {t(`pages.heirRunbook.template.options.${id}`)}
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* Step 2 — optional descriptor pre-fill + §9.4 / §9.5 signer-location guidance. */}
      {step === DETAILS_STEP && (
        <div className="mt-4">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            {t("pages.heirRunbook.descriptor.heading")}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {t("pages.heirRunbook.descriptor.help")}
          </p>
          <label
            htmlFor="heir-descriptor"
            className="mt-3 block text-sm font-medium text-slate-700 dark:text-slate-200"
          >
            {t("pages.heirRunbook.descriptor.label")}
          </label>
          <textarea
            id="heir-descriptor"
            value={descriptor}
            onChange={(event) => editDescriptor(event.target.value)}
            onPaste={handlePaste}
            rows={3}
            spellCheck={false}
            placeholder={t("pages.heirRunbook.descriptor.placeholder")}
            className="mt-2 w-full rounded border border-slate-300 bg-white p-3 font-mono text-sm text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
          />
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button type="button" onClick={loadSample} className={secondaryButton}>
              {t("pages.heirRunbook.descriptor.useSample")}
            </button>
            <button
              type="button"
              onClick={() => void importCandidate(descriptor)}
              disabled={screening || descriptor.trim() === "" || descriptorApplied}
              className={secondaryButton}
            >
              {t("pages.heirRunbook.descriptor.apply")}
            </button>
            <button
              type="button"
              onClick={clearDescriptor}
              disabled={descriptor === "" && appliedDescriptor === ""}
              className={secondaryButton}
            >
              {t("pages.heirRunbook.descriptor.clear")}
            </button>
          </div>
          {screening && (
            <p role="status" className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              {t("pages.heirRunbook.descriptor.screening")}
            </p>
          )}
          {!screening && descriptorApplied && warnFinding === null && (
            <p className="mt-2 text-sm text-status-ready">
              {t("pages.heirRunbook.descriptor.applied")}
            </p>
          )}
          {warnFinding !== null && (
            <div className="mt-3 rounded border border-status-needs-attention/40 bg-status-needs-attention/10 p-3">
              <p className="text-sm text-slate-700 dark:text-slate-200">
                {t("pages.heirRunbook.descriptor.warnNote")}
              </p>
              <label className="mt-2 flex items-center gap-2 text-sm text-slate-800 dark:text-slate-100">
                <input
                  type="checkbox"
                  className="h-4 w-4"
                  checked={warnConfirmed}
                  onChange={(event) => confirmWarn(event.target.checked)}
                />
                {t("pages.heirRunbook.descriptor.warnConfirm")}
              </label>
            </div>
          )}

          {/* §9.4 / §9.5 signer-location guidance: the app never captures the seed,
              passphrase, or a free-text location — those are labeled blanks the
              owner hand-completes after printing. */}
          <div className="mt-6 rounded border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.heirRunbook.locations.heading")}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.heirRunbook.locations.intro")}
            </p>
            <p className="mt-3 text-sm font-semibold text-slate-800 dark:text-slate-100">
              {t("pages.heirRunbook.locations.rule")}
            </p>
            <p className="mt-2 text-sm text-status-not-ready">
              {t("pages.heirRunbook.locations.neverSeed")}
            </p>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.heirRunbook.locations.byHand")}
            </p>
          </div>
        </div>
      )}

      {/* Step 3 — preview (blank fields for hand-completion) + export. */}
      {step === REVIEW_STEP && (
        <div className="mt-4">
          {/* Export mode (§9.5 / §17.7): public-safe by default; private is gated. */}
          <fieldset>
            <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">
              {t("pages.heirRunbook.mode.label")}
            </legend>
            <label className="mt-2 flex items-center gap-2 text-sm text-slate-800 dark:text-slate-100">
              <input
                type="checkbox"
                className="h-4 w-4"
                checked={redaction === "private"}
                onChange={(event) => onTogglePrivate(event.target.checked)}
              />
              {t("pages.heirRunbook.mode.privateToggle")}
            </label>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {redaction === "private"
                ? t("pages.heirRunbook.mode.privateActive")
                : t("pages.heirRunbook.mode.publicSafeActive")}
            </p>
          </fieldset>

          {/* Export format (PDF / Markdown). */}
          <fieldset className="mt-6">
            <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">
              {t("pages.heirRunbook.format.label")}
            </legend>
            <div className="mt-2 space-y-2">
              {EXPORT_FORMATS.map((format) => (
                <label key={format} className={optionLabel}>
                  <input
                    type="radio"
                    name="heir-format"
                    value={format}
                    className="h-4 w-4"
                    checked={exportFormat === format}
                    onChange={() => {
                      setExportFormat(format);
                      setExportStatus("idle");
                    }}
                  />
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(`pages.heirRunbook.format.${format}`)}
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          {/* Export action + status. */}
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void runExport()}
              disabled={exporting}
              className={primaryButton}
            >
              {exporting
                ? t("pages.heirRunbook.export.exporting")
                : t("pages.heirRunbook.export.button")}
            </button>
            {exportStatus !== "idle" && (
              <p
                role="status"
                className={`text-sm ${
                  exportStatus === "error"
                    ? "text-status-not-ready"
                    : "text-slate-600 dark:text-slate-300"
                }`}
              >
                {t(`pages.heirRunbook.export.status.${exportStatus}`)}
              </p>
            )}
          </div>
          {redaction === "public-safe" && (
            <p className="mt-3 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {t("pages.heirRunbook.export.publicSafeNote")}
            </p>
          )}

          {/* Live preview (Markdown rendering, with the blank fields visible). */}
          <div className="mt-8 border-t border-slate-200 pt-6 dark:border-slate-700">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.heirRunbook.preview.heading")}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.heirRunbook.preview.help")}
            </p>
            {previewLoading && (
              <p role="status" className="mt-3 text-sm text-slate-500 dark:text-slate-400">
                {t("pages.heirRunbook.preview.loading")}
              </p>
            )}
            {previewError && (
              <p className="mt-3 text-sm text-status-not-ready">
                {t("pages.heirRunbook.preview.error")}
              </p>
            )}
            {!previewError && previewText !== "" && (
              <pre
                aria-label={t("pages.heirRunbook.preview.heading")}
                className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded border border-slate-200 bg-slate-50 p-4 font-mono text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
              >
                {previewText}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* Step navigation. */}
      <div className="mt-8 flex items-center justify-between border-t border-slate-200 pt-6 dark:border-slate-700">
        <div>
          {step > TEMPLATE_STEP && (
            <button
              type="button"
              onClick={() => setStep((current) => Math.max(TEMPLATE_STEP, current - 1))}
              className={secondaryButton}
            >
              {t("pages.heirRunbook.back")}
            </button>
          )}
        </div>
        <div>
          {step < REVIEW_STEP && (
            <button
              type="button"
              onClick={() => setStep((current) => Math.min(REVIEW_STEP, current + 1))}
              className={primaryButton}
            >
              {t("pages.heirRunbook.next")}
            </button>
          )}
        </div>
      </div>

      <SensitiveInputDialog detected={blockedSecret} onAcknowledge={() => setBlockedSecret(null)} />
      <ExportPrivacyDialog
        open={privacyDialogOpen}
        onConfirm={confirmPrivate}
        onCancel={cancelPrivate}
      />
    </section>
  );
}
