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
 * §17.8 / §31.x standalone Runbook generator (US-052).
 *
 * The CLI-free way to produce a recovery / inheritance runbook: choose one of the
 * bundled templates, optionally pre-fill the wallet details from a watch-only
 * descriptor, pick the export mode + format, watch a live Markdown preview, and
 * export through the OS save dialog.
 *
 * The frontend runs NO Bitcoin logic (§13.7 / §20): it only picks a template and
 * (optionally) hands a descriptor to the Rust core, which screens it, parses it,
 * and renders the deterministic runbook ({@link generateRunbook}). A pasted secret
 * is caught by the §13.5 detector BEFORE it is used (and again in the core) — the
 * §22.7 block dialog appears and the field is cleared. Per §9.5 the app never
 * accepts seed / passphrase / location free-text; those stay as printed blanks the
 * owner completes by hand, so the only fill input is the optional descriptor.
 *
 * Switching the export to `private` mode reveals the full descriptor and device
 * models, so it is gated behind the §9.5 confirmation dialog — exactly like the
 * report export (US-051). The dedicated, guided heir flow (§31.2) is US-053.
 */

/** Owner recovery runbook template ids (`OwnerTemplate::name()` in the core). */
const OWNER_TEMPLATES = [
  "singlesig-basic",
  "singlesig-passphrase",
  "multisig-2of3",
  "multisig-3of5",
] as const;

/** Heir / education runbook template ids (`HeirTemplate::name()` in the core). */
const HEIR_TEMPLATES = [
  "heir-singlesig-basic",
  "heir-singlesig-passphrase",
  "heir-multisig-2of3",
  "heir-multisig-3of5",
  "liana-timelock",
  "meetup-workshop",
  "business-treasury",
] as const;

const EXPORT_FORMATS: RunbookFormat[] = ["pdf", "markdown"];

// §22.9 sample descriptors — the committed, documented test-network fixtures (tpub,
// never mainnet), shared with the Readiness Check wizard. Inert sample strings: no
// parsing happens in the frontend. The multisig sample pre-fills a multisig
// template's signer table; the singlesig sample the simpler templates.
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

/** Pick the committed test descriptor that best matches the selected template. */
function sampleForTemplate(template: string): string {
  if (template === "liana-timelock") {
    return SAMPLE_LIANA;
  }
  if (template.includes("multisig") || template === "business-treasury") {
    return SAMPLE_MULTISIG;
  }
  return SAMPLE_SINGLESIG;
}

/** Decode the runbook engine's UTF-8 byte array into the Markdown preview text. */
function decodeContent(content: number[]): string {
  return new TextDecoder().decode(new Uint8Array(content));
}

export default function GenerateRunbook(): JSX.Element {
  const { t } = useTranslation();

  const [template, setTemplate] = useState<string>(OWNER_TEMPLATES[0]);
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

  // Markdown / PDF export to a dialog-chosen path.
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

  // Live preview: regenerate the runbook Markdown whenever the template, applied
  // descriptor, or mode changes. The core screens + parses the descriptor and
  // returns the rendered runbook bytes; we decode them to show the preview. PDF
  // export uses the same content, so the Markdown preview faithfully represents it.
  useEffect(() => {
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
  }, [template, appliedDescriptor, redaction]);

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
   * OS save dialog, and write the bytes through `save_export`. Unlike a report, the
   * runbook PDF is a real backend document, so both formats go through this path.
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
            name: t(`pages.generateRunbook.format.${exportFormat}`),
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

  return (
    <section className="mx-auto max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">
        {t("pages.generateRunbook.title")}
      </h1>
      <p className="mt-2 text-slate-600 dark:text-slate-300">{t("pages.generateRunbook.body")}</p>

      {/* Template chooser (all MVP templates, grouped by family). */}
      <div className="mt-6">
        <label
          htmlFor="runbook-template"
          className="block text-sm font-medium text-slate-700 dark:text-slate-200"
        >
          {t("pages.generateRunbook.templateLabel")}
        </label>
        <select
          id="runbook-template"
          value={template}
          onChange={(event) => {
            setTemplate(event.target.value);
            setExportStatus("idle");
          }}
          className="mt-2 w-full rounded border border-slate-300 bg-white p-2.5 text-sm text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
        >
          <optgroup label={t("pages.generateRunbook.templateGroups.owner")}>
            {OWNER_TEMPLATES.map((id) => (
              <option key={id} value={id}>
                {t(`pages.generateRunbook.templates.${id}`)}
              </option>
            ))}
          </optgroup>
          <optgroup label={t("pages.generateRunbook.templateGroups.heir")}>
            {HEIR_TEMPLATES.map((id) => (
              <option key={id} value={id}>
                {t(`pages.generateRunbook.templates.${id}`)}
              </option>
            ))}
          </optgroup>
        </select>
      </div>

      {/* Optional descriptor pre-fill (the only "fill" input; §9.5 keeps everything
          else as printed blanks). */}
      <div className="mt-6">
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          {t("pages.generateRunbook.descriptor.heading")}
        </h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
          {t("pages.generateRunbook.descriptor.help")}
        </p>
        <label
          htmlFor="runbook-descriptor"
          className="mt-3 block text-sm font-medium text-slate-700 dark:text-slate-200"
        >
          {t("pages.generateRunbook.descriptor.label")}
        </label>
        <textarea
          id="runbook-descriptor"
          value={descriptor}
          onChange={(event) => editDescriptor(event.target.value)}
          onPaste={handlePaste}
          rows={3}
          spellCheck={false}
          placeholder={t("pages.generateRunbook.descriptor.placeholder")}
          className="mt-2 w-full rounded border border-slate-300 bg-white p-3 font-mono text-sm text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
        />
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button type="button" onClick={loadSample} className={secondaryButton}>
            {t("pages.generateRunbook.descriptor.useSample")}
          </button>
          <button
            type="button"
            onClick={() => void importCandidate(descriptor)}
            disabled={screening || descriptor.trim() === "" || descriptorApplied}
            className={secondaryButton}
          >
            {t("pages.generateRunbook.descriptor.apply")}
          </button>
          <button
            type="button"
            onClick={clearDescriptor}
            disabled={descriptor === "" && appliedDescriptor === ""}
            className={secondaryButton}
          >
            {t("pages.generateRunbook.descriptor.clear")}
          </button>
        </div>
        {screening && (
          <p role="status" className="mt-2 text-sm text-slate-500 dark:text-slate-400">
            {t("pages.generateRunbook.descriptor.screening")}
          </p>
        )}
        {!screening && descriptorApplied && warnFinding === null && (
          <p className="mt-2 text-sm text-status-ready">
            {t("pages.generateRunbook.descriptor.applied")}
          </p>
        )}
        {warnFinding !== null && (
          <div className="mt-3 rounded border border-status-needs-attention/40 bg-status-needs-attention/10 p-3">
            <p className="text-sm text-slate-700 dark:text-slate-200">
              {t("pages.generateRunbook.descriptor.warnNote")}
            </p>
            <label className="mt-2 flex items-center gap-2 text-sm text-slate-800 dark:text-slate-100">
              <input
                type="checkbox"
                className="h-4 w-4"
                checked={warnConfirmed}
                onChange={(event) => confirmWarn(event.target.checked)}
              />
              {t("pages.generateRunbook.descriptor.warnConfirm")}
            </label>
          </div>
        )}
        <p className="mt-3 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
          {t("pages.generateRunbook.descriptor.blankNote")}
        </p>
      </div>

      {/* Export mode (§9.5 / §17.7): public-safe by default; private is gated. */}
      <fieldset className="mt-6">
        <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">
          {t("pages.generateRunbook.mode.label")}
        </legend>
        <label className="mt-2 flex items-center gap-2 text-sm text-slate-800 dark:text-slate-100">
          <input
            type="checkbox"
            className="h-4 w-4"
            checked={redaction === "private"}
            onChange={(event) => onTogglePrivate(event.target.checked)}
          />
          {t("pages.generateRunbook.mode.privateToggle")}
        </label>
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          {redaction === "private"
            ? t("pages.generateRunbook.mode.privateActive")
            : t("pages.generateRunbook.mode.publicSafeActive")}
        </p>
      </fieldset>

      {/* Export format (PDF / Markdown). */}
      <fieldset className="mt-6">
        <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">
          {t("pages.generateRunbook.format.label")}
        </legend>
        <div className="mt-2 space-y-2">
          {EXPORT_FORMATS.map((format) => (
            <label key={format} className={optionLabel}>
              <input
                type="radio"
                name="runbook-format"
                value={format}
                className="h-4 w-4"
                checked={exportFormat === format}
                onChange={() => {
                  setExportFormat(format);
                  setExportStatus("idle");
                }}
              />
              <span className="text-slate-800 dark:text-slate-100">
                {t(`pages.generateRunbook.format.${format}`)}
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
            ? t("pages.generateRunbook.export.exporting")
            : t("pages.generateRunbook.export.button")}
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
            {t(`pages.generateRunbook.export.status.${exportStatus}`)}
          </p>
        )}
      </div>

      {/* Live preview (Markdown rendering of the current selection). */}
      <div className="mt-8 border-t border-slate-200 pt-6 dark:border-slate-700">
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          {t("pages.generateRunbook.preview.heading")}
        </h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
          {t("pages.generateRunbook.preview.help")}
        </p>
        {previewLoading && (
          <p role="status" className="mt-3 text-sm text-slate-500 dark:text-slate-400">
            {t("pages.generateRunbook.preview.loading")}
          </p>
        )}
        {previewError && (
          <p className="mt-3 text-sm text-status-not-ready">
            {t("pages.generateRunbook.preview.error")}
          </p>
        )}
        {!previewError && previewText !== "" && (
          <pre
            aria-label={t("pages.generateRunbook.preview.heading")}
            className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded border border-slate-200 bg-slate-50 p-4 font-mono text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
          >
            {previewText}
          </pre>
        )}
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
