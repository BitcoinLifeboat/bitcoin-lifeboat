import { useEffect, useRef, useState } from "react";
import type { ChangeEvent, ClipboardEvent, DragEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";

import ExportPrivacyDialog from "../components/ExportPrivacyDialog";
import { PolicyTree } from "../components/PolicyTree";
import { ReportViewer } from "../components/ReportViewer";
import SensitiveInputDialog from "../components/SensitiveInputDialog";
import { useSessionStore } from "../store/session";
import {
  auditDescriptor,
  detectSensitiveInput,
  generateReport,
  renderLianaRecoveryTree,
  renderMiniscriptPolicyDot,
  saveExport,
  showSaveDialog,
} from "../tauri/commands";
import type {
  DetectedSecret,
  LianaRecoveryPath,
  LianaRecoveryTree,
  ReadinessReport,
  RedactionMode,
  ReportFormat,
} from "../tauri/commands";

/**
 * §22.8 Readiness Check wizard — the 8-step guided audit.
 *
 *   1. Choose wallet type        5. Passphrase-exists (Y/N, never the value)
 *   2. Choose input method       6. 9 recovery-completeness questions
 *   3. Paste or load descriptor  7. Review
 *   4. Known receive address     8. Export
 *
 * US-048 built the wizard SHELL (step navigation, the "Step N of 8" indicator,
 * Back / Next, "Save and quit", the §22.9 sample link, and capture of the
 * recovery answers — each unconfirmed answer is surfaced as a warning, §9.1
 * "each skip = warning"). US-049 wires step 3: descriptor import via paste, file
 * picker, and drag-and-drop (§17.1), each screened by the §13.5 sensitive-input
 * detector BEFORE the text is kept. A `Block` verdict shows the §22.7 full-screen
 * dialog and clears the field; only on a clean screen is the descriptor committed
 * to the session store. US-050 wires step 7: the §19.1 report viewer. US-051 wires
 * step 8: export as PDF (the §17.7.4 print-to-PDF path), Markdown, or JSON, in the
 * default public-safe mode or — behind the §9.5 confirmation — private mode. The
 * frontend still runs NO Bitcoin logic itself; it calls the Rust core through the
 * typed {@link detectSensitiveInput} / {@link auditDescriptor} / {@link generateReport}
 * client.
 *
 * The wizard is a reusable component so the §22.11 "Audit Multisig" screen
 * (US-053) can render the same flow with a multisig-first default.
 */

type WalletType = "singlesig" | "multisig" | "liana" | "unsure";
type InputMethod = "paste" | "file" | "sample";
type Answer = "yes" | "no" | "unsure";

/** §22.8 step 8 export formats. "pdf" is the §17.7.4 print-to-PDF path; "markdown"
 *  and "json" go through the Rust `generate_report` → save-dialog → `save_export`
 *  flow. */
type ExportChoice = "pdf" | "markdown" | "json";

/** A §9.1 recovery-completeness question. `multisigOnly` questions are not
 *  applicable to a single-signature wallet (so they never count as a warning
 *  there). */
interface RecoveryQuestion {
  id: string;
  multisigOnly: boolean;
}

const RECOVERY_QUESTIONS: RecoveryQuestion[] = [
  { id: "h1", multisigOnly: false },
  { id: "h2", multisigOnly: true },
  { id: "h3", multisigOnly: true },
  { id: "h4", multisigOnly: false },
  { id: "h5", multisigOnly: false },
  { id: "h6", multisigOnly: false },
  { id: "h7", multisigOnly: false },
  { id: "h8", multisigOnly: false },
  { id: "h9", multisigOnly: false },
];

const WALLET_TYPES: WalletType[] = ["singlesig", "multisig", "liana", "unsure"];
const INPUT_METHODS: InputMethod[] = ["paste", "file", "sample"];
const ANSWERS: Answer[] = ["yes", "no", "unsure"];
const EXPORT_CHOICES: ExportChoice[] = ["pdf", "markdown", "json"];

// §22.9 sample descriptors. These are the committed, documented test-network
// fixtures (tpub, never mainnet) so the user can experience the flow before
// pasting their own data. They are inert sample strings — no parsing happens in
// the frontend.
const SAMPLE_SINGLESIG =
  "wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/0/*)#r6yctejg";
const SAMPLE_MULTISIG =
  "wsh(sortedmulti(2,[4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/0/*,[6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/0/*,[8dfc9b34/48'/1'/0'/2']tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq/0/*))#c2yhzrq7";
const SAMPLE_LIANA =
  "wsh(or_d(pk([4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/<0;1>/*),and_v(v:pkh([6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/<0;1>/*),older(65535))))#d3zjscz4";

const TOTAL_STEPS = 8;

const primaryButton =
  "rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg " +
  "disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "rounded px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 " +
  "dark:text-slate-200 dark:hover:bg-slate-800";
const optionLabel =
  "flex cursor-pointer items-center gap-3 rounded border border-slate-200 p-3 " +
  "hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-700";

/**
 * Read a user-selected or dropped file's text. Uses `FileReader` (universally
 * supported — including the system WebView and jsdom) rather than `Blob.text()`,
 * which some older WebKitGTK builds lack. The file is one the user explicitly
 * chose, so this needs no Tauri fs capability.
 */
function readFileText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error("could not read the file"));
    reader.readAsText(file);
  });
}

function SectionHeading({ children }: { children: string }): JSX.Element {
  return <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{children}</h2>;
}

function HelpText({ children }: { children: string }): JSX.Element {
  return <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{children}</p>;
}

function OptionalBadge({ label }: { label: string }): JSX.Element {
  return (
    <span className="rounded-full bg-slate-200 px-2.5 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-300">
      {label}
    </span>
  );
}

interface ReadinessWizardProps {
  /** Pre-selected wallet type for the first step. The §22.11 Audit Multisig
   *  screen (US-053) renders this same wizard with "multisig". */
  defaultWalletType?: WalletType | null;
  /** Localized title key for the routed screen hosting the wizard. */
  titleKey?: string;
}

export default function ReadinessWizard({
  defaultWalletType = null,
  titleKey = "pages.readinessCheck.title",
}: ReadinessWizardProps): JSX.Element {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const resetSession = useSessionStore((state) => state.reset);
  const commitDescriptorToSession = useSessionStore((state) => state.setDescriptor);

  const [step, setStep] = useState(1);
  const [walletType, setWalletType] = useState<WalletType | null>(defaultWalletType);
  const [inputMethod, setInputMethod] = useState<InputMethod | null>(null);
  const [descriptor, setDescriptor] = useState("");
  const [sampleLoaded, setSampleLoaded] = useState(false);
  const [knownAddress, setKnownAddress] = useState("");
  const [passphraseExists, setPassphraseExists] = useState<boolean | null>(null);
  const [answers, setAnswers] = useState<Record<string, Answer>>({});

  // §22.8 step 7 (US-050): the §19.1 readiness report rendered by <ReportViewer>.
  // Generated by the Rust core when the user reaches the review (or export) step;
  // kept in local state only (Confidential — dropped on unmount).
  const [report, setReport] = useState<ReadinessReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState(false);

  // US-088: redacted GraphViz DOT from the Rust Miniscript visualizer, rendered
  // as a policy tree by <PolicyTree>. The frontend never parses descriptors.
  const [policyDot, setPolicyDot] = useState<string | null>(null);
  const [lianaRecoveryTree, setLianaRecoveryTree] = useState<LianaRecoveryTree | null>(null);
  const [currentBlockHeight, setCurrentBlockHeight] = useState("");
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyError, setPolicyError] = useState(false);

  // §22.8 step 8 (US-051) export controls.
  // - `exportChoice`: PDF (print path) / Markdown / JSON.
  // - `redaction`: §17.7 share-safe `public-safe` (default) vs `private`; switching
  //   to private is gated by the §9.5 confirmation dialog.
  // - `privacyDialogOpen`: the §9.5 dialog is shown while true.
  // - `exporting` / `exportStatus`: in-flight + result of a Markdown/JSON save.
  const [exportChoice, setExportChoice] = useState<ExportChoice>("pdf");
  const [redaction, setRedaction] = useState<RedactionMode>("public-safe");
  const [privacyDialogOpen, setPrivacyDialogOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportStatus, setExportStatus] = useState<"idle" | "saved" | "cancelled" | "error">(
    "idle",
  );

  // §13.5 secret-screening state for step 3 (US-049).
  // - `blockedSecret`: the §22.7 dialog is open while this is non-null.
  // - `warnFinding`: a `Warn`-level finding pending the §13.5.7 override.
  // - `screenedClean`: the current descriptor text already passed an `Allow`
  //   screen, so the Next gate need not re-screen it.
  // - `screening`: a detector call is in flight (disables Next).
  const [blockedSecret, setBlockedSecret] = useState<DetectedSecret | null>(null);
  const [warnFinding, setWarnFinding] = useState<DetectedSecret | null>(null);
  const [warnConfirmed, setWarnConfirmed] = useState(false);
  const [screenedClean, setScreenedClean] = useState(false);
  const [screening, setScreening] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const sampleDescriptor =
    walletType === "multisig"
      ? SAMPLE_MULTISIG
      : walletType === "liana"
        ? SAMPLE_LIANA
        : SAMPLE_SINGLESIG;

  // §9.1 "each skip = warning": a recovery question that applies to this wallet
  // type but is not confirmed (anything other than "Yes") is recorded as a
  // warning. The authoritative scoring still happens in the Rust core; this is
  // the wizard's preview of what the report will flag.
  function isApplicable(question: RecoveryQuestion): boolean {
    return !(question.multisigOnly && walletType === "singlesig");
  }
  const unconfirmed = RECOVERY_QUESTIONS.filter(
    (question) => isApplicable(question) && answers[question.id] !== "yes",
  );

  /** §22.9 sample: our own watch-only, test-network fixture — trusted, so it is
   *  not screened. */
  function loadSample(): void {
    setDescriptor(sampleDescriptor);
    setSampleLoaded(true);
    setScreenedClean(true);
    setWarnFinding(null);
    setWarnConfirmed(false);
  }

  /** Manual typing: update the field but mark it un-screened so the Next gate
   *  re-runs the detector (a typed-in secret must still be caught). */
  function editDescriptor(value: string): void {
    setDescriptor(value);
    setSampleLoaded(false);
    setScreenedClean(false);
    setWarnFinding(null);
    setWarnConfirmed(false);
  }

  /**
   * §13.5 / §17.1 import screen: run the Rust detector on `candidate` BEFORE the
   * app keeps it. On `Block` the field is cleared and the §22.7 dialog opens; the
   * candidate is NEVER stored. On `Warn` the (public) text is kept but the §13.5.7
   * override gates Next. On `Allow` the text is kept and marked screened-clean.
   * Used by the paste / file / drag-and-drop handlers.
   */
  async function importCandidate(candidate: string): Promise<void> {
    if (candidate.trim() === "") {
      return;
    }
    setScreening(true);
    // The variable passed to the detector is overwritten the instant it returns
    // (§13.5.9): the screened text is never retained in JS beyond the call.
    let input = candidate;
    try {
      const report = await detectSensitiveInput(input);
      input = "";
      const finding: DetectedSecret = report.findings[0]?.[0] ?? "none";
      if (report.action === "block") {
        setDescriptor("");
        setSampleLoaded(false);
        setScreenedClean(false);
        setWarnFinding(null);
        setWarnConfirmed(false);
        setBlockedSecret(finding);
        return;
      }
      // An output descriptor is public metadata — safe to keep in the field.
      setDescriptor(candidate);
      setSampleLoaded(false);
      if (report.action === "warn") {
        setWarnFinding(finding);
        setWarnConfirmed(false);
        setScreenedClean(false);
      } else {
        setWarnFinding(null);
        setWarnConfirmed(false);
        setScreenedClean(true);
      }
    } finally {
      setScreening(false);
    }
  }

  /** Paste handler: screen the would-be field value BEFORE it lands (§13.5). */
  function handlePaste(event: ClipboardEvent<HTMLTextAreaElement>): void {
    event.preventDefault();
    const pasted = event.clipboardData.getData("text");
    const target = event.currentTarget;
    const start = target.selectionStart ?? descriptor.length;
    const end = target.selectionEnd ?? descriptor.length;
    void importCandidate(descriptor.slice(0, start) + pasted + descriptor.slice(end));
  }

  /** File-picker handler: read the chosen file's text and screen it (§17.1). */
  async function handleFile(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    // Reset the input so picking the same file again still fires a change.
    event.target.value = "";
    if (file) {
      await importCandidate(await readFileText(file));
    }
  }

  /** Drag-and-drop handler: read the dropped file's text and screen it (§17.1). */
  async function handleDrop(event: DragEvent<HTMLDivElement>): Promise<void> {
    event.preventDefault();
    setDragOver(false);
    const file = event.dataTransfer.files?.[0];
    if (file) {
      await importCandidate(await readFileText(file));
    }
  }

  function setAnswer(id: string, answer: Answer): void {
    setAnswers((current) => ({ ...current, [id]: answer }));
  }

  function clearAnswer(id: string): void {
    setAnswers((current) => {
      const next = { ...current };
      delete next[id];
      return next;
    });
  }

  // Required input gates Next; the optional steps (4–6) and the terminal steps
  // (7–8) never block. On step 3 an in-flight screen, or a `Warn` awaiting the
  // §13.5.7 override, also blocks Next.
  const nextDisabled =
    screening ||
    (step === 1 && walletType === null) ||
    (step === 2 && inputMethod === null) ||
    (step === 3 && descriptor.trim() === "") ||
    (step === 3 && warnFinding !== null && !warnConfirmed);

  /** The step-3 descriptor can advance without a fresh detector call when it is a
   *  trusted sample, already screened clean, or a `Warn` the user has overridden. */
  function canCommitDescriptorWithoutScreen(): boolean {
    return sampleLoaded || screenedClean || (warnFinding !== null && warnConfirmed);
  }

  function advanceStep(): void {
    setStep((current) => Math.min(TOTAL_STEPS, current + 1));
  }

  /**
   * Step-3 Next gate: re-screen the descriptor unless it is already trusted
   * (catches text typed straight into the field), then commit it to the session
   * store BEHIND the detector (§13.5) before advancing. `Block` opens the §22.7
   * dialog and clears the field; an unconfirmed `Warn` shows the inline override.
   */
  async function screenThenAdvance(): Promise<void> {
    setScreening(true);
    let input = descriptor;
    try {
      const report = await detectSensitiveInput(input);
      input = ""; // §13.5.9: overwrite the screened text right after the call.
      const finding: DetectedSecret = report.findings[0]?.[0] ?? "none";
      if (report.action === "block") {
        setDescriptor("");
        setScreenedClean(false);
        setWarnFinding(null);
        setWarnConfirmed(false);
        setBlockedSecret(finding);
        return;
      }
      if (report.action === "warn") {
        setWarnFinding(finding);
        setWarnConfirmed(false);
        return; // user must tick the override, then press Next again
      }
      setScreenedClean(true);
      commitDescriptorToSession(descriptor);
      advanceStep();
    } finally {
      setScreening(false);
    }
  }

  function goNext(): void {
    if (nextDisabled) {
      return;
    }
    if (step === 3) {
      if (canCommitDescriptorWithoutScreen()) {
        commitDescriptorToSession(descriptor);
        advanceStep();
      } else {
        void screenThenAdvance();
      }
      return;
    }
    advanceStep();
  }

  function goBack(): void {
    setStep((current) => Math.max(1, current - 1));
  }

  // §22.8 steps 7–8 / US-050+US-051: generate the readiness report from the
  // (already detector-screened) descriptor when the user reaches the review step,
  // and keep it available on the export step (the §17.7.4 print region renders it).
  // The descriptor is public wallet metadata; the Rust core still screens it and
  // returns only the leak-free §19.1 report — no Bitcoin logic runs here.
  useEffect(() => {
    if ((step !== 7 && step !== 8) || descriptor.trim() === "") {
      return;
    }
    let cancelled = false;
    setReportLoading(true);
    setReportError(false);
    auditDescriptor({
      descriptor,
      known_address: knownAddress.trim() === "" ? null : knownAddress,
    })
      .then((result) => {
        if (!cancelled) {
          setReport(result);
          setReportLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setReport(null);
          setReportError(true);
          setReportLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [step, descriptor, knownAddress]);

  const formatNumber = (value: number): string => new Intl.NumberFormat("en-US").format(value);

  const parseCurrentBlockHeight = (value: string): number | null => {
    const trimmed = value.trim();
    if (trimmed === "") {
      return null;
    }
    const parsed = Number(trimmed);
    return Number.isInteger(parsed) && parsed >= 0 && parsed <= 4_294_967_295 ? parsed : null;
  };

  const currentBlockHeightArg = parseCurrentBlockHeight(currentBlockHeight);

  const lianaPathTimeLabel = (path: LianaRecoveryPath): string => {
    const relative = path.relative_timelocks[0];
    if (relative !== undefined) {
      if (relative.unit === "blocks") {
        return t("policyTree.liana.relativeBlocks", {
          blocks: formatNumber(relative.value),
          days: formatNumber(relative.estimated_days),
        });
      }
      return t("policyTree.liana.relativeTime", {
        intervals: formatNumber(relative.value),
        days: formatNumber(relative.estimated_days),
      });
    }
    const absolute = path.absolute_timelocks[0];
    if (absolute !== undefined) {
      if (absolute.unit === "height") {
        return t("policyTree.liana.absoluteHeight", {
          height: formatNumber(absolute.value),
        });
      }
      return t("policyTree.liana.absoluteTimestamp", {
        timestamp: formatNumber(absolute.value),
      });
    }
    return t("policyTree.liana.availableNow");
  };

  const lianaPathCountdownLabel = (path: LianaRecoveryPath): string | null => {
    const countdown = path.countdown;
    if (countdown === undefined || countdown === null) {
      return null;
    }
    if (countdown.active_in_blocks === 0) {
      return t("policyTree.liana.countdownNow", {
        height: formatNumber(countdown.current_block_height),
      });
    }
    return t("policyTree.liana.countdownBlocks", {
      height: formatNumber(countdown.current_block_height),
      blocks: formatNumber(countdown.active_in_blocks),
    });
  };

  // US-088/091: render the policy tree from Rust-returned DOT on the review step.
  // This is independent from report generation so a report error does not hide a
  // descriptor policy that the core can still visualize. Liana uses the US-091
  // recovery-path extractor; other wallet types use the generic policy DOT.
  useEffect(() => {
    if (step !== 7 || descriptor.trim() === "") {
      return;
    }
    let cancelled = false;
    setPolicyLoading(true);
    setPolicyError(false);
    setPolicyDot(null);
    setLianaRecoveryTree(null);

    const renderTree =
      walletType === "liana"
        ? renderLianaRecoveryTree(descriptor, currentBlockHeightArg).then((tree) => {
            if (!cancelled) {
              setLianaRecoveryTree(tree);
              setPolicyDot(tree.dot);
            }
          })
        : renderMiniscriptPolicyDot(descriptor).then((dot) => {
            if (!cancelled) {
              setPolicyDot(dot);
            }
          });

    renderTree
      .then(() => {
        if (!cancelled) {
          setPolicyLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPolicyDot(null);
          setLianaRecoveryTree(null);
          setPolicyError(true);
          setPolicyLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [step, descriptor, walletType, currentBlockHeightArg]);

  // §22.8 step 8 (US-051): the export mode toggle. Turning ON private opens the
  // §9.5 confirmation; private only takes effect when the user confirms. Turning it
  // OFF returns to the safe `public-safe` default with no dialog.
  function onTogglePrivate(turnOn: boolean): void {
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
   * §22.8 step 8 export. PDF uses the §17.7.4 print-to-PDF path — it prints the
   * public-safe report region (`.lifeboat-print-area`) via the OS print dialog, so
   * it never carries xpubs and needs no backend PDF. Markdown / JSON call the Rust
   * `generate_report` (which applies `redaction`, §17.7) and write the rendered text
   * to an OS-save-dialog path through `save_export`.
   */
  async function runExport(): Promise<void> {
    if (exportChoice === "pdf") {
      // The print region renders a public-safe report; the OS dialog saves it as PDF.
      window.print();
      return;
    }
    const format: ReportFormat = exportChoice === "markdown" ? "markdown" : "json_pretty";
    const extension = exportChoice === "markdown" ? "md" : "json";
    setExporting(true);
    setExportStatus("idle");
    let content = "";
    try {
      const artifact = await generateReport(
        {
          descriptor,
          known_address: knownAddress.trim() === "" ? null : knownAddress,
          redaction,
        },
        format,
      );
      content = artifact.content;
      const path = await showSaveDialog({
        defaultPath: artifact.suggested_filename,
        filters: [
          {
            name: t(`pages.readinessCheck.wizard.export.format.${exportChoice}`),
            extensions: [extension],
          },
        ],
      });
      if (path === null) {
        setExportStatus("cancelled");
        return;
      }
      await saveExport(path, Array.from(new TextEncoder().encode(content)));
      setExportStatus("saved");
    } catch {
      setExportStatus("error");
    } finally {
      content = ""; // do not retain the (possibly private) rendered text in JS.
      setExporting(false);
    }
  }

  /** §22.8 "Save and quit": exit cleanly without persisting Confidential data.
   *  Component state (descriptor, known address, answers) is dropped on unmount;
   *  resetSession() clears anything later steps may write to the session store.
   */
  function saveAndQuit(): void {
    resetSession();
    navigate("/");
  }

  return (
    <section aria-label={t(titleKey)} className="mx-auto max-w-2xl">
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">
        {t(titleKey)}
      </h1>
      <p className="mt-1 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {t("pages.readinessCheck.wizard.stepIndicator", { current: step, total: TOTAL_STEPS })}
      </p>

      <div className="mt-6">
        {step === 1 && (
          <div>
            <SectionHeading>{t("pages.readinessCheck.wizard.walletType.title")}</SectionHeading>
            <HelpText>{t("pages.readinessCheck.wizard.walletType.help")}</HelpText>
            <div role="radiogroup" aria-label={t("pages.readinessCheck.wizard.walletType.title")} className="mt-4 space-y-2">
              {WALLET_TYPES.map((type) => (
                <label key={type} className={optionLabel}>
                  <input
                    type="radio"
                    name="wallet-type"
                    value={type}
                    className="h-4 w-4"
                    checked={walletType === type}
                    onChange={() => setWalletType(type)}
                  />
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(`pages.readinessCheck.wizard.walletType.${type}`)}
                  </span>
                </label>
              ))}
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <SectionHeading>{t("pages.readinessCheck.wizard.inputMethod.title")}</SectionHeading>
            <HelpText>{t("pages.readinessCheck.wizard.inputMethod.help")}</HelpText>
            <div role="radiogroup" aria-label={t("pages.readinessCheck.wizard.inputMethod.title")} className="mt-4 space-y-2">
              {INPUT_METHODS.map((method) => (
                <label key={method} className={optionLabel}>
                  <input
                    type="radio"
                    name="input-method"
                    value={method}
                    className="h-4 w-4"
                    checked={inputMethod === method}
                    onChange={() => setInputMethod(method)}
                  />
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(`pages.readinessCheck.wizard.inputMethod.${method}`)}
                  </span>
                </label>
              ))}
            </div>
          </div>
        )}

        {step === 3 && (
          <div>
            <SectionHeading>{t("pages.readinessCheck.wizard.descriptor.title")}</SectionHeading>
            <HelpText>{t("pages.readinessCheck.wizard.descriptor.help")}</HelpText>
            <p className="mt-3 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
              {t("pages.readinessCheck.wizard.descriptor.fileNote")}
            </p>
            <div className="mt-4 flex items-center justify-between">
              <label htmlFor="descriptor-input" className="text-sm font-medium text-slate-700 dark:text-slate-200">
                {t("pages.readinessCheck.wizard.descriptor.label")}
              </label>
              <button type="button" onClick={loadSample} className="text-sm font-medium text-brand hover:underline">
                {t("pages.readinessCheck.wizard.useSample")}
              </button>
            </div>
            {/* The textarea doubles as the drag-and-drop target (§17.1). A drop
                anywhere over it bubbles to this wrapper's handler. */}
            <div
              onDrop={(event) => void handleDrop(event)}
              onDragOver={(event) => {
                event.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              className={`mt-2 rounded ${dragOver ? "ring-2 ring-brand" : ""}`}
            >
              <textarea
                id="descriptor-input"
                value={descriptor}
                onChange={(event) => editDescriptor(event.target.value)}
                onPaste={handlePaste}
                rows={4}
                spellCheck={false}
                placeholder={t("pages.readinessCheck.wizard.descriptor.placeholder")}
                className="w-full rounded border border-slate-300 bg-white p-3 font-mono text-sm text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
              />
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className={secondaryButton}
              >
                {t("pages.readinessCheck.wizard.descriptor.chooseFile")}
              </button>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                {t("pages.readinessCheck.wizard.descriptor.fileHint")}
              </span>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.json,.bed,.descriptor"
                onChange={(event) => void handleFile(event)}
                aria-label={t("pages.readinessCheck.wizard.descriptor.fileInputLabel")}
                className="hidden"
              />
            </div>
            {screening && (
              <p role="status" className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                {t("pages.readinessCheck.wizard.descriptor.screening")}
              </p>
            )}
            {warnFinding !== null && (
              <div className="mt-3 rounded border border-status-needs-attention/40 bg-status-needs-attention/10 p-3">
                <p className="text-sm text-slate-700 dark:text-slate-200">
                  {t("pages.readinessCheck.wizard.descriptor.warnNote")}
                </p>
                <label className="mt-2 flex items-center gap-2 text-sm text-slate-800 dark:text-slate-100">
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={warnConfirmed}
                    onChange={(event) => setWarnConfirmed(event.target.checked)}
                  />
                  {t("pages.readinessCheck.wizard.descriptor.warnConfirm")}
                </label>
              </div>
            )}
            {sampleLoaded && (
              <p className="mt-2 flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <span className="rounded bg-status-needs-attention/15 px-2 py-0.5 font-mono text-xs font-semibold text-status-needs-attention">
                  {t("pages.readinessCheck.wizard.sampleBadge")}
                </span>
                {t("pages.readinessCheck.wizard.sampleNote")}
              </p>
            )}
          </div>
        )}

        {step === 4 && (
          <div>
            <div className="flex items-center gap-3">
              <SectionHeading>{t("pages.readinessCheck.wizard.knownAddress.title")}</SectionHeading>
              <OptionalBadge label={t("pages.readinessCheck.wizard.optionalBadge")} />
            </div>
            <HelpText>{t("pages.readinessCheck.wizard.knownAddress.help")}</HelpText>
            <label htmlFor="known-address-input" className="mt-4 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {t("pages.readinessCheck.wizard.knownAddress.label")}
            </label>
            <input
              id="known-address-input"
              type="text"
              value={knownAddress}
              onChange={(event) => setKnownAddress(event.target.value)}
              spellCheck={false}
              placeholder={t("pages.readinessCheck.wizard.knownAddress.placeholder")}
              className="mt-2 w-full rounded border border-slate-300 bg-white p-3 font-mono text-sm text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
            />
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t("pages.readinessCheck.wizard.knownAddress.skipNote")}
            </p>
          </div>
        )}

        {step === 5 && (
          <div>
            <div className="flex items-center gap-3">
              <SectionHeading>{t("pages.readinessCheck.wizard.passphrase.title")}</SectionHeading>
              <OptionalBadge label={t("pages.readinessCheck.wizard.optionalBadge")} />
            </div>
            <HelpText>{t("pages.readinessCheck.wizard.passphrase.help")}</HelpText>
            <div role="radiogroup" aria-label={t("pages.readinessCheck.wizard.passphrase.title")} className="mt-4 space-y-2">
              <label className={optionLabel}>
                <input
                  type="radio"
                  name="passphrase-exists"
                  className="h-4 w-4"
                  checked={passphraseExists === true}
                  onChange={() => setPassphraseExists(true)}
                />
                <span className="text-slate-800 dark:text-slate-100">
                  {t("pages.readinessCheck.wizard.passphrase.yes")}
                </span>
              </label>
              <label className={optionLabel}>
                <input
                  type="radio"
                  name="passphrase-exists"
                  className="h-4 w-4"
                  checked={passphraseExists === false}
                  onChange={() => setPassphraseExists(false)}
                />
                <span className="text-slate-800 dark:text-slate-100">
                  {t("pages.readinessCheck.wizard.passphrase.no")}
                </span>
              </label>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t("pages.readinessCheck.wizard.passphrase.skipNote")}
            </p>
          </div>
        )}

        {step === 6 && (
          <div>
            <SectionHeading>{t("pages.readinessCheck.wizard.recovery.title")}</SectionHeading>
            <HelpText>{t("pages.readinessCheck.wizard.recovery.help")}</HelpText>
            <div className="mt-4 space-y-4">
              {RECOVERY_QUESTIONS.map((question) => {
                const applicable = isApplicable(question);
                const questionText = t(`pages.readinessCheck.wizard.recovery.questions.${question.id}`);
                const selected = answers[question.id];
                return (
                  <fieldset
                    key={question.id}
                    className="rounded border border-slate-200 p-3 dark:border-slate-700"
                  >
                    <legend className="flex items-center gap-2 px-1 text-sm text-slate-800 dark:text-slate-100">
                      <span>{questionText}</span>
                      {question.multisigOnly && (
                        <span className="rounded bg-slate-200 px-1.5 py-0.5 text-xs text-slate-600 dark:bg-slate-700 dark:text-slate-300">
                          {t("pages.readinessCheck.wizard.recovery.multisigOnly")}
                        </span>
                      )}
                    </legend>
                    {applicable ? (
                      <div className="mt-1 flex flex-wrap items-center gap-3">
                        {ANSWERS.map((answer) => (
                          <label key={answer} className="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-200">
                            <input
                              type="radio"
                              name={`recovery-${question.id}`}
                              value={answer}
                              className="h-4 w-4"
                              checked={selected === answer}
                              onChange={() => setAnswer(question.id, answer)}
                            />
                            {t(`pages.readinessCheck.wizard.recovery.answer${answer.charAt(0).toUpperCase()}${answer.slice(1)}`)}
                          </label>
                        ))}
                        {selected !== undefined && (
                          <button
                            type="button"
                            onClick={() => clearAnswer(question.id)}
                            className="text-xs font-medium text-slate-500 hover:underline dark:text-slate-400"
                          >
                            {t("pages.readinessCheck.wizard.recovery.clear")}
                          </button>
                        )}
                        {selected !== "yes" && (
                          <span className="text-xs font-medium text-status-needs-attention">
                            {t("pages.readinessCheck.wizard.recovery.willWarn")}
                          </span>
                        )}
                      </div>
                    ) : (
                      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                        {t("pages.readinessCheck.wizard.recovery.notApplicable")}
                      </p>
                    )}
                  </fieldset>
                );
              })}
            </div>
          </div>
        )}

        {step === 7 && (
          <div>
            <SectionHeading>{t("pages.readinessCheck.wizard.review.title")}</SectionHeading>
            <HelpText>{t("pages.readinessCheck.wizard.review.help")}</HelpText>
            <dl className="mt-4 space-y-3 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-slate-500 dark:text-slate-400">
                  {t("pages.readinessCheck.wizard.review.walletTypeLabel")}
                </dt>
                <dd className="text-right text-slate-800 dark:text-slate-100">
                  {walletType
                    ? t(`pages.readinessCheck.wizard.walletType.${walletType}`)
                    : t("pages.readinessCheck.wizard.review.notProvided")}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-500 dark:text-slate-400">
                  {t("pages.readinessCheck.wizard.review.descriptorLabel")}
                </dt>
                <dd className="text-right text-slate-800 dark:text-slate-100">
                  {descriptor.trim() === ""
                    ? t("pages.readinessCheck.wizard.review.descriptorMissing")
                    : sampleLoaded
                      ? t("pages.readinessCheck.wizard.review.descriptorSample")
                      : t("pages.readinessCheck.wizard.review.descriptorProvided")}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-500 dark:text-slate-400">
                  {t("pages.readinessCheck.wizard.review.knownAddressLabel")}
                </dt>
                <dd className="text-right text-slate-800 dark:text-slate-100">
                  {knownAddress.trim() === ""
                    ? t("pages.readinessCheck.wizard.review.notProvided")
                    : t("pages.readinessCheck.wizard.review.descriptorProvided")}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-slate-500 dark:text-slate-400">
                  {t("pages.readinessCheck.wizard.review.passphraseLabel")}
                </dt>
                <dd className="text-right text-slate-800 dark:text-slate-100">
                  {passphraseExists === null
                    ? t("pages.readinessCheck.wizard.review.notProvided")
                    : passphraseExists
                      ? t("pages.readinessCheck.wizard.review.passphraseYes")
                      : t("pages.readinessCheck.wizard.review.passphraseNo")}
                </dd>
              </div>
            </dl>
            <div className="mt-6">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t("pages.readinessCheck.wizard.review.warningsHeading")}
              </h3>
              {unconfirmed.length === 0 ? (
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                  {t("pages.readinessCheck.wizard.review.noWarnings")}
                </p>
              ) : (
                <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-status-needs-attention">
                  {unconfirmed.map((question) => (
                    <li key={question.id}>
                      {t(`pages.readinessCheck.wizard.recovery.questions.${question.id}`)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="mt-8 border-t border-slate-200 pt-6 dark:border-slate-700">
              {reportLoading && (
                <p role="status" className="text-sm text-slate-500 dark:text-slate-400">
                  {t("pages.readinessCheck.wizard.review.generating")}
                </p>
              )}
              {reportError && (
                <p className="text-sm text-status-not-ready">
                  {t("pages.readinessCheck.wizard.review.reportError")}
                </p>
              )}
              {report !== null && <ReportViewer report={report} />}
            </div>
            <div className="mt-8 border-t border-slate-200 pt-6 dark:border-slate-700">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                {t(walletType === "liana" ? "policyTree.lianaTitle" : "policyTree.title")}
              </h3>
              {policyLoading && (
                <p role="status" className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                  {t("policyTree.loading")}
                </p>
              )}
              {policyError && (
                <p className="mt-2 text-sm text-status-not-ready">
                  {t("policyTree.error")}
                </p>
              )}
              {walletType === "liana" && (
                <label className="mt-3 block max-w-xs text-sm font-medium text-slate-700 dark:text-slate-200">
                  {t("policyTree.liana.currentBlockLabel")}
                  <input
                    type="number"
                    min="0"
                    step="1"
                    inputMode="numeric"
                    value={currentBlockHeight}
                    onChange={(event) => setCurrentBlockHeight(event.currentTarget.value)}
                    placeholder={t("policyTree.liana.currentBlockPlaceholder")}
                    className="mt-1 block w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                </label>
              )}
              {policyDot !== null && (
                <div className="mt-3">
                  <PolicyTree dot={policyDot} />
                </div>
              )}
              {lianaRecoveryTree !== null && (
                <ul className="mt-4 space-y-3">
                  {lianaRecoveryTree.paths.map((path) => {
                    const countdownLabel = lianaPathCountdownLabel(path);
                    return (
                      <li key={path.index} className="border-l-2 border-brand-500 pl-3">
                        <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                          {path.label}
                        </p>
                        <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                          {t("policyTree.liana.keyCount", { count: path.key_count })}
                        </p>
                        <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                          {lianaPathTimeLabel(path)}
                        </p>
                        {countdownLabel !== null && (
                          <p className="mt-1 text-xs font-medium text-slate-800 dark:text-slate-100">
                            {countdownLabel}
                          </p>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        )}

        {step === 8 && (
          <div>
            <SectionHeading>{t("pages.readinessCheck.wizard.export.title")}</SectionHeading>
            <HelpText>{t("pages.readinessCheck.wizard.export.help")}</HelpText>

            {/* Format selector (§22.8: PDF / Markdown / JSON). */}
            <fieldset className="mt-6">
              <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">
                {t("pages.readinessCheck.wizard.export.format.label")}
              </legend>
              <div className="mt-2 space-y-2">
                {EXPORT_CHOICES.map((choice) => (
                  <label key={choice} className={optionLabel}>
                    <input
                      type="radio"
                      name="export-format"
                      value={choice}
                      className="h-4 w-4"
                      checked={exportChoice === choice}
                      onChange={() => {
                        setExportChoice(choice);
                        setExportStatus("idle");
                      }}
                    />
                    <span className="text-slate-800 dark:text-slate-100">
                      {t(`pages.readinessCheck.wizard.export.format.${choice}`)}
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            {/* Export mode (§9.5): public-safe by default. Private requires the
                confirmation dialog and is unavailable for the PDF print path, which
                always renders the public-safe summary (no xpubs). */}
            <fieldset className="mt-6">
              <legend className="text-sm font-medium text-slate-700 dark:text-slate-200">
                {t("pages.readinessCheck.wizard.export.mode.label")}
              </legend>
              {exportChoice === "pdf" ? (
                <p className="mt-2 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {t("pages.readinessCheck.wizard.export.pdfNote")}
                </p>
              ) : (
                <label className="mt-2 flex items-center gap-2 text-sm text-slate-800 dark:text-slate-100">
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={redaction === "private"}
                    onChange={(event) => onTogglePrivate(event.target.checked)}
                  />
                  {t("pages.readinessCheck.wizard.export.privateToggle")}
                </label>
              )}
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                {redaction === "private" && exportChoice !== "pdf"
                  ? t("pages.readinessCheck.wizard.export.mode.privateActive")
                  : t("pages.readinessCheck.wizard.export.mode.publicSafeActive")}
              </p>
            </fieldset>

            {/* Export action. */}
            <div className="mt-6 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => void runExport()}
                disabled={exporting || (exportChoice === "pdf" && report === null)}
                className={primaryButton}
              >
                {exportChoice === "pdf"
                  ? t("pages.readinessCheck.wizard.export.printButton")
                  : t("pages.readinessCheck.wizard.export.button")}
              </button>
              {exportChoice === "pdf" && report === null && (
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  {t("pages.readinessCheck.wizard.export.needReport")}
                </span>
              )}
            </div>

            {/* Status line for a Markdown / JSON save. */}
            {exportStatus !== "idle" && (
              <p
                role="status"
                className={`mt-3 text-sm ${
                  exportStatus === "error"
                    ? "text-status-not-ready"
                    : "text-slate-600 dark:text-slate-300"
                }`}
              >
                {t(`pages.readinessCheck.wizard.export.status.${exportStatus}`)}
              </p>
            )}

            {/* §17.7.4 print-only, public-safe report. Hidden on screen; the OS print
                dialog inks only this region (see styles.css). */}
            {report !== null && (
              <div className="lifeboat-print-area">
                <ReportViewer report={report} hideTechnicalDetails />
              </div>
            )}
          </div>
        )}
      </div>

      <div className="mt-8 flex items-center justify-between border-t border-slate-200 pt-4 dark:border-slate-700">
        <div>
          {step > 1 && (
            <button type="button" onClick={goBack} className={secondaryButton}>
              {t("pages.readinessCheck.wizard.back")}
            </button>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={saveAndQuit}
            className={secondaryButton}
            title={t("pages.readinessCheck.wizard.saveAndQuitNote")}
          >
            {t("pages.readinessCheck.wizard.saveAndQuit")}
          </button>
          {step < TOTAL_STEPS ? (
            <button type="button" onClick={goNext} disabled={nextDisabled} className={primaryButton}>
              {t("pages.readinessCheck.wizard.next")}
            </button>
          ) : (
            <button type="button" onClick={saveAndQuit} className={primaryButton}>
              {t("pages.readinessCheck.wizard.finish")}
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
