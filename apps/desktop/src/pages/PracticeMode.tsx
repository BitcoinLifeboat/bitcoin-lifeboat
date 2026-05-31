import { useEffect, useRef, useState, type ClipboardEvent } from "react";
import { useTranslation } from "react-i18next";

import { AlertTriangleIcon, XCircleIcon } from "../components/icons";
import PracticeQrExchange from "./PracticeQrExchange";
import {
  broadcastSignetTransaction,
  detectSensitiveInput,
  finalizeFilePsbt,
  openExternalLink,
  readPsbtFile,
  runPracticeSendDrill,
  saveExport,
  savePracticeDrillResult,
  showOpenDialog,
  showSaveDialog,
  startPracticeDrill,
  type DetectedSecret,
  type DetectorReport,
  type FilePsbtFinalizeResult,
  type PracticeDrillNetwork,
  type PracticeDrillStart,
  type PracticeSendDrillResult,
  type SignetBroadcastEndpoint,
  type SignetBroadcastResult,
} from "../tauri/commands";

export const DEFAULT_PRACTICE_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const DOCUMENTED_TEST_MNEMONICS = [DEFAULT_PRACTICE_MNEMONIC];
const SIGNET_BROADCAST_ENDPOINT: SignetBroadcastEndpoint = "mutinynet";
const SIGNET_BROADCAST_ENDPOINT_URL = "https://mutinynet.com/api/tx";

type PasteStatus = "idle" | "checking" | "accepted" | "ignored" | "error";
type DrillStatus = "idle" | "starting" | "ready" | "sending" | "complete" | "error";
type FaucetStatus = "idle" | "opening" | "opened" | "error";
type BroadcastStatus = "idle" | "confirming" | "broadcasting" | "complete" | "error";
type SaveStatus = "idle" | "saving" | "saved" | "error";
type UnsignedPsbtFileStatus = "idle" | "saving" | "saved" | "cancelled" | "error";
type SignedPsbtFileStatus = "idle" | "importing" | "finalized" | "cancelled" | "error";

function normalizeMnemonic(input: string): string {
  return input.trim().toLowerCase().split(/\s+/u).join(" ");
}

function isDocumentedPracticeMnemonic(input: string): boolean {
  const normalized = normalizeMnemonic(input);
  return DOCUMENTED_TEST_MNEMONICS.includes(normalized);
}

function isChecksumValidBip39(secret: DetectedSecret): boolean {
  return typeof secret !== "string" && "bip39" in secret && secret.bip39.checksum_valid;
}

function hasChecksumValidMnemonic(report: DetectorReport): boolean {
  return report.findings.some(([secret]) => isChecksumValidBip39(secret));
}

function utf8Bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

function firstDialogPath(path: string | string[] | null): string | null {
  if (Array.isArray(path)) {
    return path[0] ?? null;
  }
  return path;
}

interface PracticeSeedBlockDialogProps {
  open: boolean;
  onAcknowledge: () => void;
}

function PracticeSeedBlockDialog({
  open,
  onAcknowledge,
}: PracticeSeedBlockDialogProps): JSX.Element | null {
  const { t } = useTranslation();
  const acknowledgeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open) {
      acknowledgeRef.current?.focus();
    }
  }, [open]);

  if (!open) {
    return null;
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/70 p-4"
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
        aria-labelledby="practice-seed-block-title"
        aria-describedby="practice-seed-block-body"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg bg-white p-6 shadow-xl dark:bg-slate-800"
      >
        <div className="flex items-start gap-3">
          <XCircleIcon className="mt-0.5 h-7 w-7 shrink-0 text-status-not-ready" />
          <h2
            id="practice-seed-block-title"
            className="text-lg font-semibold text-slate-900 dark:text-slate-100"
          >
            {t("dialogs.practiceSeedBlock.title")}
          </h2>
        </div>
        <div id="practice-seed-block-body" className="mt-4 space-y-3 text-sm text-slate-700 dark:text-slate-200">
          <p>{t("dialogs.practiceSeedBlock.body")}</p>
          <p>{t("dialogs.practiceSeedBlock.action")}</p>
        </div>
        <div className="mt-6 flex justify-end">
          <button
            ref={acknowledgeRef}
            type="button"
            onClick={onAcknowledge}
            className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg"
          >
            {t("dialogs.practiceSeedBlock.acknowledge")}
          </button>
        </div>
      </div>
    </div>
  );
}

interface SignetBroadcastDialogProps {
  open: boolean;
  endpointUrl: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

function SignetBroadcastDialog({
  open,
  endpointUrl,
  busy,
  onCancel,
  onConfirm,
}: SignetBroadcastDialogProps): JSX.Element | null {
  const { t } = useTranslation();
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open) {
      confirmRef.current?.focus();
    }
  }, [open]);

  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/70 p-4">
      <div
        role="alertdialog"
        aria-modal={true}
        aria-labelledby="signet-broadcast-title"
        aria-describedby="signet-broadcast-body"
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg bg-white p-6 shadow-xl dark:bg-slate-800"
      >
        <div className="flex items-start gap-3">
          <AlertTriangleIcon className="mt-0.5 h-7 w-7 shrink-0 text-network-signet" />
          <h2
            id="signet-broadcast-title"
            className="text-lg font-semibold text-slate-900 dark:text-slate-100"
          >
            {t("dialogs.signetBroadcast.title")}
          </h2>
        </div>
        <div id="signet-broadcast-body" className="mt-4 space-y-3 text-sm text-slate-700 dark:text-slate-200">
          <p>{t("dialogs.signetBroadcast.body")}</p>
          <p>
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {t("dialogs.signetBroadcast.networkCall")}
            </span>{" "}
            <code className="break-all rounded bg-slate-100 px-1.5 py-1 font-mono text-xs text-slate-900 dark:bg-slate-900 dark:text-slate-100">
              {endpointUrl}
            </code>
          </p>
          <p className="font-semibold text-slate-900 dark:text-slate-100">
            {t("dialogs.signetBroadcast.network")}
          </p>
        </div>
        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:border-brand hover:text-brand disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-600 dark:text-slate-200"
          >
            {t("dialogs.signetBroadcast.cancel")}
          </button>
          <button
            ref={confirmRef}
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="rounded bg-network-signet px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-network-signet/80 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy
              ? t("dialogs.signetBroadcast.broadcasting")
              : t("dialogs.signetBroadcast.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function PracticeMode(): JSX.Element {
  const { t } = useTranslation();
  const [mnemonic, setMnemonic] = useState(DEFAULT_PRACTICE_MNEMONIC);
  const [pasteStatus, setPasteStatus] = useState<PasteStatus>("idle");
  const [blockOpen, setBlockOpen] = useState(false);
  const [drillNetwork, setDrillNetwork] = useState<PracticeDrillNetwork>("regtest");
  const [drillStatus, setDrillStatus] = useState<DrillStatus>("idle");
  const [faucetStatus, setFaucetStatus] = useState<FaucetStatus>("idle");
  const [broadcastStatus, setBroadcastStatus] = useState<BroadcastStatus>("idle");
  const [saveStatus, setSaveStatus] = useState<SaveStatus>("idle");
  const [unsignedPsbtFileStatus, setUnsignedPsbtFileStatus] =
    useState<UnsignedPsbtFileStatus>("idle");
  const [signedPsbtFileStatus, setSignedPsbtFileStatus] =
    useState<SignedPsbtFileStatus>("idle");
  const [savedRecordPath, setSavedRecordPath] = useState<string | null>(null);
  const [unsignedPsbtPath, setUnsignedPsbtPath] = useState<string | null>(null);
  const [signedPsbtPath, setSignedPsbtPath] = useState<string | null>(null);
  const [drillStart, setDrillStart] = useState<PracticeDrillStart | null>(null);
  const [sendResult, setSendResult] = useState<PracticeSendDrillResult | null>(null);
  const [filePsbtResult, setFilePsbtResult] = useState<FilePsbtFinalizeResult | null>(null);
  const [broadcastResult, setBroadcastResult] = useState<SignetBroadcastResult | null>(null);
  const drillBadgeClass =
    drillNetwork === "signet" ? "bg-network-signet text-slate-900" : "bg-network-regtest text-white";

  function handleSeedPaste(event: ClipboardEvent<HTMLTextAreaElement>): void {
    event.preventDefault();
    const pasted = event.clipboardData.getData("text/plain");
    void screenPastedSeed(pasted);
  }

  async function screenPastedSeed(pasted: string): Promise<void> {
    const normalized = normalizeMnemonic(pasted);
    if (normalized.length === 0) {
      setPasteStatus("idle");
      return;
    }

    setPasteStatus("checking");
    try {
      let input = pasted;
      const report = await detectSensitiveInput(input);
      input = "";

      if (isDocumentedPracticeMnemonic(normalized)) {
        setMnemonic(DEFAULT_PRACTICE_MNEMONIC);
        setPasteStatus("accepted");
        return;
      }

      if (hasChecksumValidMnemonic(report) || report.action === "block") {
        setMnemonic(DEFAULT_PRACTICE_MNEMONIC);
        setPasteStatus("idle");
        setBlockOpen(true);
        return;
      }

      setMnemonic(DEFAULT_PRACTICE_MNEMONIC);
      setPasteStatus("ignored");
    } catch {
      setMnemonic(DEFAULT_PRACTICE_MNEMONIC);
      setPasteStatus("error");
    }
  }

  function selectDrillNetwork(network: PracticeDrillNetwork): void {
    setDrillNetwork(network);
    setDrillStatus("idle");
    setFaucetStatus("idle");
    setBroadcastStatus("idle");
    setSaveStatus("idle");
    setUnsignedPsbtFileStatus("idle");
    setSignedPsbtFileStatus("idle");
    setSavedRecordPath(null);
    setUnsignedPsbtPath(null);
    setSignedPsbtPath(null);
    setDrillStart(null);
    setSendResult(null);
    setFilePsbtResult(null);
    setBroadcastResult(null);
  }

  async function handleStartDrill(): Promise<void> {
    setDrillStatus("starting");
    setFaucetStatus("idle");
    setBroadcastStatus("idle");
    setSaveStatus("idle");
    setUnsignedPsbtFileStatus("idle");
    setSignedPsbtFileStatus("idle");
    setSavedRecordPath(null);
    setUnsignedPsbtPath(null);
    setSignedPsbtPath(null);
    setSendResult(null);
    setFilePsbtResult(null);
    setBroadcastResult(null);
    try {
      const start = await startPracticeDrill(drillNetwork);
      setDrillStart(start);
      setDrillStatus("ready");
    } catch {
      setDrillStart(null);
      setDrillStatus("error");
    }
  }

  async function handleOpenFaucet(): Promise<void> {
    if (!drillStart?.faucet_url) {
      return;
    }
    setFaucetStatus("opening");
    try {
      await openExternalLink(drillStart.faucet_url);
      setFaucetStatus("opened");
    } catch {
      setFaucetStatus("error");
    }
  }

  async function handleRunSendDrill(): Promise<void> {
    const start = drillStart;
    if (!start) {
      return;
    }
    setDrillStatus("sending");
    setSendResult(null);
    setBroadcastStatus("idle");
    setBroadcastResult(null);
    setSaveStatus("idle");
    setUnsignedPsbtFileStatus("idle");
    setSignedPsbtFileStatus("idle");
    setSavedRecordPath(null);
    setUnsignedPsbtPath(null);
    setSignedPsbtPath(null);
    setFilePsbtResult(null);
    try {
      const result = await runPracticeSendDrill({
        network: drillNetwork,
        funding_amount_sat: start.funding_hint_sat,
        amount_sat: start.send_amount_sat,
        fee_rate_sat_vb: start.fee_rate_sat_vb,
      });
      setSendResult(result);
      setDrillStatus("complete");
    } catch {
      setDrillStatus("error");
    }
  }

  async function handleSaveUnsignedPsbt(): Promise<void> {
    const result = sendResult;
    if (!result || unsignedPsbtFileStatus === "saving") {
      return;
    }

    setUnsignedPsbtFileStatus("saving");
    setUnsignedPsbtPath(null);
    try {
      const path = await showSaveDialog({
        title: t("pages.practiceMode.drill.fileExchange.saveTitle"),
        defaultPath: `lifeboat-${result.network}-unsigned.psbt`,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      if (!path) {
        setUnsignedPsbtFileStatus("cancelled");
        return;
      }
      await saveExport(path, utf8Bytes(`${result.unsigned_psbt_base64}\n`));
      setUnsignedPsbtPath(path);
      setUnsignedPsbtFileStatus("saved");
    } catch {
      setUnsignedPsbtFileStatus("error");
    }
  }

  async function handleImportSignedPsbt(): Promise<void> {
    const result = sendResult;
    if (!result || signedPsbtFileStatus === "importing") {
      return;
    }

    setSignedPsbtFileStatus("importing");
    setSignedPsbtPath(null);
    setFilePsbtResult(null);
    try {
      const selected = await showOpenDialog({
        title: t("pages.practiceMode.drill.fileExchange.openTitle"),
        multiple: false,
        directory: false,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      const path = firstDialogPath(selected);
      if (!path) {
        setSignedPsbtFileStatus("cancelled");
        return;
      }
      const psbtBase64 = await readPsbtFile(path);
      const finalized = await finalizeFilePsbt({
        network: result.network,
        psbt_base64: psbtBase64,
      });
      setSignedPsbtPath(path);
      setFilePsbtResult(finalized);
      setSignedPsbtFileStatus("finalized");
    } catch {
      setSignedPsbtFileStatus("error");
    }
  }

  async function handleSaveDrillResult(): Promise<void> {
    const result = sendResult;
    if (!result || saveStatus === "saving") {
      return;
    }
    setSaveStatus("saving");
    setSavedRecordPath(null);
    try {
      const saved = await savePracticeDrillResult(result);
      setSavedRecordPath(saved.path);
      setSaveStatus("saved");
    } catch {
      setSaveStatus("error");
    }
  }

  function handleRequestBroadcast(): void {
    if (sendResult?.network !== "signet" || !sendResult.broadcast_available) {
      return;
    }
    setBroadcastStatus("confirming");
  }

  async function handleConfirmBroadcast(): Promise<void> {
    const result = sendResult;
    if (result?.network !== "signet" || !result.broadcast_available) {
      return;
    }

    setBroadcastStatus("broadcasting");
    setBroadcastResult(null);
    try {
      const broadcast = await broadcastSignetTransaction({
        network: "signet",
        transaction_hex: result.transaction_hex,
        endpoint: SIGNET_BROADCAST_ENDPOINT,
      });
      setBroadcastResult(broadcast);
      setBroadcastStatus("complete");
    } catch {
      setBroadcastStatus("error");
    }
  }

  return (
    <section className="mx-auto max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">
        {t("pages.practiceMode.title")}
      </h1>
      <p className="mt-2 text-slate-600 dark:text-slate-300">
        {t("pages.practiceMode.body")}
      </p>

      <div className="mt-6 rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <div className="flex flex-wrap items-center gap-3">
          <span className="rounded bg-status-needs-attention px-2 py-1 text-xs font-bold uppercase text-slate-950">
            {t("pages.practiceMode.practiceOnly")}
          </span>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            {t("pages.practiceMode.practiceOnlyHelp")}
          </p>
        </div>

        <label
          htmlFor="practice-seed"
          className="mt-5 block text-sm font-medium text-slate-900 dark:text-slate-100"
        >
          {t("pages.practiceMode.seed.label")}
        </label>
        <p id="practice-seed-help" className="mt-1 text-sm text-slate-600 dark:text-slate-300">
          {t("pages.practiceMode.seed.help")}
        </p>
        <textarea
          id="practice-seed"
          aria-describedby="practice-seed-help practice-seed-status"
          className="mt-3 min-h-28 w-full resize-none rounded-lg border-2 border-status-needs-attention bg-status-needs-attention/10 p-4 font-mono text-sm leading-6 text-slate-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-status-needs-attention dark:text-slate-100"
          value={mnemonic}
          readOnly={true}
          spellCheck={false}
          onPaste={handleSeedPaste}
        />

        <div id="practice-seed-status" className="mt-3 min-h-5 text-sm" aria-live="polite">
          {pasteStatus === "checking" && (
            <p className="text-slate-600 dark:text-slate-300">
              {t("pages.practiceMode.seed.checking")}
            </p>
          )}
          {pasteStatus === "accepted" && (
            <p className="text-status-ready">{t("pages.practiceMode.seed.accepted")}</p>
          )}
          {pasteStatus === "ignored" && (
            <p className="text-status-needs-attention">
              {t("pages.practiceMode.seed.ignored")}
            </p>
          )}
          {pasteStatus === "error" && (
            <p className="text-status-not-ready">{t("pages.practiceMode.seed.error")}</p>
          )}
        </div>

        <div className="mt-5 flex items-start gap-3 rounded border border-status-needs-attention/40 bg-status-needs-attention/10 p-3">
          <AlertTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-status-needs-attention" />
          <p className="text-sm text-slate-700 dark:text-slate-200">
            {t("pages.practiceMode.warning")}
          </p>
        </div>
      </div>

      <div className="mt-6 rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.practiceMode.drill.title")}
            </h2>
            <p className="mt-1 max-w-2xl text-sm text-slate-600 dark:text-slate-300">
              {t("pages.practiceMode.drill.body")}
            </p>
          </div>
          <span
            className={`inline-flex self-start rounded px-2 py-1 text-xs font-semibold uppercase ${drillBadgeClass}`}
          >
            {t(`pages.practiceMode.drill.network.badge.${drillNetwork}`)}
          </span>
        </div>

        <fieldset className="mt-5">
          <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
            {t("pages.practiceMode.drill.network.label")}
          </legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {(["regtest", "signet"] satisfies PracticeDrillNetwork[]).map((network) => (
              <label
                key={network}
                className={[
                  "cursor-pointer rounded-lg border p-3 text-sm",
                  drillNetwork === network
                    ? "border-brand bg-brand/10 text-slate-900 dark:text-slate-100"
                    : "border-slate-200 text-slate-700 hover:border-brand dark:border-slate-700 dark:text-slate-200",
                ].join(" ")}
              >
                <span className="flex gap-3">
                  <input
                    type="radio"
                    name="practice-drill-network"
                    value={network}
                    checked={drillNetwork === network}
                    onChange={() => selectDrillNetwork(network)}
                    className="mt-1 h-4 w-4 shrink-0 accent-brand"
                  />
                  <span>
                    <span className="block font-semibold">
                      {t(`pages.practiceMode.drill.network.${network}.title`)}
                    </span>
                    <span className="mt-1 block text-slate-600 dark:text-slate-300">
                      {t(`pages.practiceMode.drill.network.${network}.body`)}
                    </span>
                  </span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => void handleStartDrill()}
            disabled={drillStatus === "starting" || drillStatus === "sending"}
            className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
          >
            {drillStatus === "starting"
              ? t("pages.practiceMode.drill.starting")
              : t("pages.practiceMode.drill.start")}
          </button>
          <p className="min-h-5 text-sm text-slate-600 dark:text-slate-300" aria-live="polite">
            {drillStatus === "error" && (
              <span className="text-status-not-ready">
                {t("pages.practiceMode.drill.error")}
              </span>
            )}
          </p>
        </div>

        {drillStart && (
          <div className="mt-5 space-y-4">
            <div className="rounded border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900">
              <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {t("pages.practiceMode.drill.receive.label")}
              </p>
              <code className="mt-2 block break-all rounded bg-white p-3 font-mono text-sm text-slate-900 dark:bg-slate-800 dark:text-slate-100">
                {drillStart.receive_address}
              </code>
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                {t("pages.practiceMode.drill.receive.index", {
                  index: drillStart.receive_index,
                })}
              </p>
            </div>

            {drillStart.faucet_url && (
              <div className="rounded border border-network-signet/50 bg-network-signet/10 p-4">
                <h3 className="text-sm font-semibold text-slate-900">
                  {t("pages.practiceMode.drill.faucet.title")}
                </h3>
                <p className="mt-1 text-sm text-slate-700">
                  {t("pages.practiceMode.drill.faucet.body")}
                </p>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={() => void handleOpenFaucet()}
                    disabled={faucetStatus === "opening"}
                    className="rounded border border-brand px-3 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {faucetStatus === "opening"
                      ? t("pages.practiceMode.drill.faucet.opening")
                      : t("pages.practiceMode.drill.faucet.open")}
                  </button>
                  <p className="min-h-5 text-sm" aria-live="polite">
                    {faucetStatus === "opened" && (
                      <span className="text-status-ready">
                        {t("pages.practiceMode.drill.faucet.opened")}
                      </span>
                    )}
                    {faucetStatus === "error" && (
                      <span className="text-status-not-ready">
                        {t("pages.practiceMode.drill.faucet.error")}
                      </span>
                    )}
                  </p>
                </div>
              </div>
            )}

            <div className="rounded border border-slate-200 p-4 dark:border-slate-700">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t("pages.practiceMode.drill.send.title")}
              </h3>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                {t("pages.practiceMode.drill.send.body")}
              </p>
              <button
                type="button"
                onClick={() => void handleRunSendDrill()}
                disabled={drillStatus === "sending" || drillStatus === "starting"}
                className="mt-3 rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {drillStatus === "sending"
                  ? t("pages.practiceMode.drill.send.sending")
                  : t("pages.practiceMode.drill.send.run")}
              </button>
            </div>
          </div>
        )}

        {sendResult && (
          <div className="mt-5 rounded border border-status-ready/50 bg-status-ready/10 p-4">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.practiceMode.drill.result.title")}
            </h3>
            <dl className="mt-3 space-y-2 text-sm text-slate-700 dark:text-slate-200">
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.practiceMode.drill.result.sent")}
                </dt>
                <dd className="mt-1 break-all">
                  {t("pages.practiceMode.drill.result.sentValue", {
                    amount: sendResult.amount_sat,
                    address: sendResult.recipient_address,
                  })}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.practiceMode.drill.result.fee")}
                </dt>
                <dd>{t("pages.practiceMode.drill.result.feeValue", { fee: sendResult.fee_sat })}</dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.practiceMode.drill.result.txid")}
                </dt>
                <dd className="break-all font-mono">{sendResult.finalized_txid}</dd>
              </div>
            </dl>
            <p className="mt-3 text-sm text-slate-700 dark:text-slate-200">
              {t("pages.practiceMode.drill.result.psbt")}
            </p>
            <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
              {sendResult.network === "signet" && sendResult.broadcast_available
                ? t("pages.practiceMode.drill.result.broadcastReady")
                : t("pages.practiceMode.drill.result.noBroadcast")}
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-status-ready/30 pt-4">
              <button
                type="button"
                onClick={() => void handleSaveDrillResult()}
                disabled={saveStatus === "saving" || saveStatus === "saved"}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {saveStatus === "saving"
                  ? t("pages.practiceMode.drill.save.saving")
                  : t("pages.practiceMode.drill.save.button")}
              </button>
              <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                {saveStatus === "saved" && savedRecordPath && (
                  <span className="break-all">
                    {t("pages.practiceMode.drill.save.saved", {
                      path: savedRecordPath,
                    })}
                  </span>
                )}
                {saveStatus === "error" && (
                  <span className="text-status-not-ready">
                    {t("pages.practiceMode.drill.save.error")}
                  </span>
                )}
              </p>
            </div>
            {sendResult.network === "signet" && sendResult.broadcast_available && (
              <div className="mt-4 rounded border border-network-signet/50 bg-network-signet/10 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-network-signet px-2 py-1 text-xs font-bold text-slate-950">
                    {t("pages.practiceMode.drill.broadcast.badge")}
                  </span>
                  <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {t("pages.practiceMode.drill.broadcast.title")}
                  </p>
                </div>
                <p className="mt-2 text-sm text-slate-700 dark:text-slate-200">
                  {t("pages.practiceMode.drill.broadcast.endpoint", {
                    endpoint: SIGNET_BROADCAST_ENDPOINT_URL,
                  })}
                </p>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={handleRequestBroadcast}
                    disabled={broadcastStatus === "broadcasting" || broadcastStatus === "complete"}
                    className="rounded bg-network-signet px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-network-signet/80 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {t("pages.practiceMode.drill.broadcast.button")}
                  </button>
                  <p className="min-h-5 text-sm" aria-live="polite">
                    {broadcastStatus === "error" && (
                      <span className="text-status-not-ready">
                        {t("pages.practiceMode.drill.broadcast.error")}
                      </span>
                    )}
                    {broadcastStatus === "complete" && broadcastResult && (
                      <span className="font-medium text-slate-900 dark:text-slate-100">
                        {t("pages.practiceMode.drill.broadcast.complete", {
                          txid: broadcastResult.txid,
                        })}
                      </span>
                    )}
                  </p>
                </div>
              </div>
            )}
            <div className="mt-4 border-t border-status-ready/30 pt-4">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t("pages.practiceMode.drill.fileExchange.title")}
              </h3>
              <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                {t("pages.practiceMode.drill.fileExchange.body")}
              </p>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => void handleSaveUnsignedPsbt()}
                  disabled={unsignedPsbtFileStatus === "saving"}
                  className="rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {unsignedPsbtFileStatus === "saving"
                    ? t("pages.practiceMode.drill.fileExchange.savingUnsigned")
                    : t("pages.practiceMode.drill.fileExchange.saveUnsigned")}
                </button>
                <button
                  type="button"
                  onClick={() => void handleImportSignedPsbt()}
                  disabled={signedPsbtFileStatus === "importing"}
                  className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {signedPsbtFileStatus === "importing"
                    ? t("pages.practiceMode.drill.fileExchange.importingSigned")
                    : t("pages.practiceMode.drill.fileExchange.importSigned")}
                </button>
              </div>
              <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                {unsignedPsbtFileStatus === "saved" && unsignedPsbtPath && (
                  <p className="break-all">
                    {t("pages.practiceMode.drill.fileExchange.savedUnsigned", {
                      path: unsignedPsbtPath,
                    })}
                  </p>
                )}
                {unsignedPsbtFileStatus === "cancelled" && (
                  <p>{t("pages.practiceMode.drill.fileExchange.saveCancelled")}</p>
                )}
                {unsignedPsbtFileStatus === "error" && (
                  <p className="text-status-not-ready">
                    {t("pages.practiceMode.drill.fileExchange.saveError")}
                  </p>
                )}
                {signedPsbtFileStatus === "cancelled" && (
                  <p>{t("pages.practiceMode.drill.fileExchange.importCancelled")}</p>
                )}
                {signedPsbtFileStatus === "error" && (
                  <p className="text-status-not-ready">
                    {t("pages.practiceMode.drill.fileExchange.importError")}
                  </p>
                )}
                {signedPsbtFileStatus === "finalized" && filePsbtResult && (
                  <div>
                    <p className="font-medium text-slate-900 dark:text-slate-100">
                      {t("pages.practiceMode.drill.fileExchange.finalized")}
                    </p>
                    {signedPsbtPath && (
                      <p className="mt-1 break-all">
                        {t("pages.practiceMode.drill.fileExchange.importedPath", {
                          path: signedPsbtPath,
                        })}
                      </p>
                    )}
                    <dl className="mt-2 grid gap-2 sm:grid-cols-3">
                      <div>
                        <dt className="font-medium text-slate-900 dark:text-slate-100">
                          {t("pages.practiceMode.drill.fileExchange.txid")}
                        </dt>
                        <dd className="break-all font-mono text-xs">{filePsbtResult.txid}</dd>
                      </div>
                      <div>
                        <dt className="font-medium text-slate-900 dark:text-slate-100">
                          {t("pages.practiceMode.drill.fileExchange.fee")}
                        </dt>
                        <dd>
                          {t("pages.practiceMode.drill.fileExchange.feeValue", {
                            fee: filePsbtResult.inspection.fee_sat,
                          })}
                        </dd>
                      </div>
                      <div>
                        <dt className="font-medium text-slate-900 dark:text-slate-100">
                          {t("pages.practiceMode.drill.fileExchange.feeRate")}
                        </dt>
                        <dd>
                          {t("pages.practiceMode.drill.fileExchange.feeRateValue", {
                            feeRate: filePsbtResult.inspection.fee_rate_sat_vb,
                          })}
                        </dd>
                      </div>
                    </dl>
                  </div>
                )}
              </div>
            </div>
            <PracticeQrExchange
              key={`${sendResult.network}:${sendResult.unsigned_psbt_base64}`}
              sendResult={sendResult}
            />
          </div>
        )}
      </div>

      <PracticeSeedBlockDialog open={blockOpen} onAcknowledge={() => setBlockOpen(false)} />
      <SignetBroadcastDialog
        open={broadcastStatus === "confirming" || broadcastStatus === "broadcasting"}
        endpointUrl={SIGNET_BROADCAST_ENDPOINT_URL}
        busy={broadcastStatus === "broadcasting"}
        onCancel={() => setBroadcastStatus("idle")}
        onConfirm={() => void handleConfirmBroadcast()}
      />
    </section>
  );
}
