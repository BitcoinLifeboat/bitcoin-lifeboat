import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { AlertTriangleIcon, CheckCircleIcon, XCircleIcon } from "../components/icons";
import { PageScaffold } from "./PageScaffold";
import {
  capturePsbtQrPayloads,
  completeDisasterSigningDrill,
  decodePsbtQrPayloads,
  encodePsbtQrFrames,
  enumerateHwiDevices,
  readPsbtFile,
  saveDisasterSigningDrillResult,
  saveExport,
  showOpenDialog,
  showSaveDialog,
  signHwiPsbt,
  startDisasterSigningDrill,
  type DisasterSigningDrillResult,
  type DisasterSigningStartResult,
  type DisasterSigningTransport,
  type DrillResultSaveOutcome,
  type HwiChain,
  type HwiDevice,
  type PracticeDrillNetwork,
  type PsbtQrDecodeResult,
  type PsbtQrFormat,
  type PsbtQrFrameSet,
} from "../tauri/commands";

const NETWORKS: PracticeDrillNetwork[] = ["regtest", "signet"];
const TRANSPORTS: DisasterSigningTransport[] = ["file", "qr", "hwi"];
const QR_FORMATS: PsbtQrFormat[] = ["ur", "bbqr"];
const STEP_LABEL_KEYS: Record<string, string> = {
  psbt_created: "pages.hardwareWalletDrill.steps.psbtCreated",
  required_quorum_signed: "pages.hardwareWalletDrill.steps.requiredQuorumSigned",
  psbt_finalized: "pages.hardwareWalletDrill.steps.psbtFinalized",
  valid_transaction: "pages.hardwareWalletDrill.steps.validTransaction",
  destination_confirmed_on_device: "pages.hardwareWalletDrill.steps.destinationConfirmed",
  destination_output_matches: "pages.hardwareWalletDrill.steps.destinationOutputMatches",
  user_did_not_stop: "pages.hardwareWalletDrill.steps.userDidNotStop",
};

function utf8Bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

function firstDialogPath(path: string | string[] | null): string | null {
  if (Array.isArray(path)) {
    return path[0] ?? null;
  }
  return path;
}

function svgDataUrl(svg: string): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function mergePayloads(existing: string[], incoming: string[]): string[] {
  const merged = [...existing];
  for (const payload of incoming) {
    const trimmed = payload.trim();
    if (trimmed.length > 0 && !merged.includes(trimmed)) {
      merged.push(trimmed);
    }
  }
  return merged;
}

function networkToHwiChain(network: PracticeDrillNetwork): HwiChain {
  return network === "signet" ? "signet" : "regtest";
}

function selectedNetwork(value: string): PracticeDrillNetwork {
  return value === "signet" ? "signet" : "regtest";
}

function selectedTransport(value: string): DisasterSigningTransport {
  switch (value) {
    case "qr":
      return "qr";
    case "hwi":
      return "hwi";
    case "file":
    default:
      return "file";
  }
}

function deviceKey(device: HwiDevice): string {
  return [device.fingerprint ?? "", device.path ?? "", device.device_type].join("|");
}

function deviceLabel(device: HwiDevice): string {
  const model = device.model ?? device.device_type;
  const fingerprint = device.fingerprint ?? "no-fingerprint";
  return `${model} (${fingerprint})`;
}

export default function HardwareWalletDrill(): JSX.Element {
  const { t } = useTranslation();
  const [network, setNetwork] = useState<PracticeDrillNetwork>("regtest");
  const [transport, setTransport] = useState<DisasterSigningTransport>("file");
  const [qrFormat, setQrFormat] = useState<PsbtQrFormat>("ur");
  const [destinationConfirmed, setDestinationConfirmed] = useState(false);
  const [userStopped, setUserStopped] = useState(false);
  const [startStatus, setStartStatus] =
    useState<"idle" | "starting" | "ready" | "error">("idle");
  const [start, setStart] = useState<DisasterSigningStartResult | null>(null);
  const [fileStatus, setFileStatus] =
    useState<"idle" | "saving" | "saved" | "importing" | "imported" | "cancelled" | "error">(
      "idle",
    );
  const [filePath, setFilePath] = useState<string | null>(null);
  const [qrEncodeStatus, setQrEncodeStatus] =
    useState<"idle" | "encoding" | "ready" | "error">("idle");
  const [qrScanStatus, setQrScanStatus] =
    useState<"idle" | "scanning" | "incomplete" | "complete" | "no_payload" | "error">("idle");
  const [qrFrameSet, setQrFrameSet] = useState<PsbtQrFrameSet | null>(null);
  const [qrFrameIndex, setQrFrameIndex] = useState(0);
  const [qrPayloads, setQrPayloads] = useState<string[]>([]);
  const [qrDecodeProgress, setQrDecodeProgress] = useState<PsbtQrDecodeResult | null>(null);
  const [deviceStatus, setDeviceStatus] =
    useState<"idle" | "checking" | "ready" | "empty" | "error">("idle");
  const [devices, setDevices] = useState<HwiDevice[]>([]);
  const [selectedDeviceKey, setSelectedDeviceKey] = useState<string | null>(null);
  const [hwiSignStatus, setHwiSignStatus] =
    useState<"idle" | "signing" | "signed" | "error">("idle");
  const [completeStatus, setCompleteStatus] =
    useState<"idle" | "completing" | "complete" | "error">("idle");
  const [result, setResult] = useState<DisasterSigningDrillResult | null>(null);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveOutcome, setSaveOutcome] = useState<DrillResultSaveOutcome | null>(null);

  const visibleQrFrame = qrFrameSet?.frames[qrFrameIndex] ?? null;
  const selectedDevice = useMemo(
    () => devices.find((device) => deviceKey(device) === selectedDeviceKey) ?? null,
    [devices, selectedDeviceKey],
  );
  const hwiCanSign =
    start !== null &&
    selectedDevice !== null &&
    selectedDevice.fingerprint !== null &&
    selectedDevice.supported_kind !== null &&
    hwiSignStatus !== "signing";

  function resetExchange(): void {
    setStartStatus("idle");
    setStart(null);
    setFileStatus("idle");
    setFilePath(null);
    setQrEncodeStatus("idle");
    setQrScanStatus("idle");
    setQrFrameSet(null);
    setQrFrameIndex(0);
    setQrPayloads([]);
    setQrDecodeProgress(null);
    setHwiSignStatus("idle");
    setCompleteStatus("idle");
    setResult(null);
    setSaveStatus("idle");
    setSaveOutcome(null);
    setDestinationConfirmed(false);
    setUserStopped(false);
  }

  function resetResultOnly(): void {
    setCompleteStatus("idle");
    setResult(null);
    setSaveStatus("idle");
    setSaveOutcome(null);
  }

  async function handleStart(): Promise<void> {
    resetExchange();
    setStartStatus("starting");
    try {
      const started = await startDisasterSigningDrill({
        scenario: "DS-8",
        network,
        transport,
      });
      setStart(started);
      setStartStatus("ready");
    } catch {
      setStartStatus("error");
    }
  }

  async function completeWithSignedPsbt(signedPsbtBase64: string): Promise<void> {
    if (start === null) {
      return;
    }
    setCompleteStatus("completing");
    setResult(null);
    setSaveStatus("idle");
    setSaveOutcome(null);
    try {
      const completed = await completeDisasterSigningDrill({
        scenario: "DS-8",
        network: start.network,
        transport,
        started_at: start.started_at,
        signed_psbt_base64: signedPsbtBase64,
        expected_destination_address: start.destination_address,
        expected_amount_sat: start.amount_sat,
        destination_confirmed: destinationConfirmed,
        user_stopped: userStopped,
      });
      setResult(completed);
      setCompleteStatus("complete");
    } catch {
      setCompleteStatus("error");
    }
  }

  async function handleSaveUnsigned(): Promise<void> {
    if (start === null) {
      return;
    }
    setFileStatus("saving");
    setFilePath(null);
    try {
      const path = await showSaveDialog({
        title: t("pages.hardwareWalletDrill.file.saveTitle"),
        defaultPath: `lifeboat-hardware-${network}-unsigned.psbt`,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      if (!path) {
        setFileStatus("cancelled");
        return;
      }
      await saveExport(path, utf8Bytes(`${start.unsigned_psbt_base64}\n`));
      setFilePath(path);
      setFileStatus("saved");
    } catch {
      setFileStatus("error");
    }
  }

  async function handleImportSignedFile(): Promise<void> {
    if (start === null) {
      return;
    }
    setFileStatus("importing");
    setFilePath(null);
    try {
      const selected = await showOpenDialog({
        title: t("pages.hardwareWalletDrill.file.openTitle"),
        multiple: false,
        directory: false,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      const path = firstDialogPath(selected);
      if (!path) {
        setFileStatus("cancelled");
        return;
      }
      const psbtBase64 = await readPsbtFile(path);
      setFilePath(path);
      await completeWithSignedPsbt(psbtBase64);
      setFileStatus("imported");
    } catch {
      setFileStatus("error");
      setCompleteStatus("error");
    }
  }

  async function handleGenerateQr(): Promise<void> {
    if (start === null) {
      return;
    }
    setQrEncodeStatus("encoding");
    setQrScanStatus("idle");
    setQrFrameSet(null);
    setQrFrameIndex(0);
    setQrPayloads([]);
    setQrDecodeProgress(null);
    try {
      const frames = await encodePsbtQrFrames({
        format: qrFormat,
        psbt_base64: start.unsigned_psbt_base64,
      });
      setQrFrameSet(frames);
      setQrEncodeStatus("ready");
    } catch {
      setQrEncodeStatus("error");
    }
  }

  async function decodeQrPayloads(nextPayloads: string[]): Promise<void> {
    const decoded = await decodePsbtQrPayloads({ format: qrFormat, payloads: nextPayloads });
    setQrDecodeProgress(decoded);
    if (decoded.status !== "complete" || decoded.psbt_base64 === null) {
      setQrScanStatus("incomplete");
      return;
    }
    await completeWithSignedPsbt(decoded.psbt_base64);
    setQrScanStatus("complete");
  }

  async function handleScanQr(): Promise<void> {
    if (qrFrameSet === null) {
      return;
    }
    setQrScanStatus("scanning");
    try {
      const scanned = await capturePsbtQrPayloads(0);
      if (scanned.length === 0) {
        setQrScanStatus("no_payload");
        return;
      }
      const nextPayloads = mergePayloads(qrPayloads, scanned);
      setQrPayloads(nextPayloads);
      await decodeQrPayloads(nextPayloads);
    } catch {
      setQrScanStatus("error");
      setCompleteStatus("error");
    }
  }

  async function handleCheckDevices(): Promise<void> {
    setDeviceStatus("checking");
    setDevices([]);
    setSelectedDeviceKey(null);
    try {
      const found = await enumerateHwiDevices();
      setDevices(found);
      setSelectedDeviceKey(found[0] === undefined ? null : deviceKey(found[0]));
      setDeviceStatus(found.length === 0 ? "empty" : "ready");
    } catch {
      setDeviceStatus("error");
    }
  }

  async function handleHwiSign(): Promise<void> {
    if (!hwiCanSign || start === null || selectedDevice === null) {
      return;
    }
    const fingerprint = selectedDevice.fingerprint;
    const supportedKind = selectedDevice.supported_kind;
    if (fingerprint === null || supportedKind === null) {
      return;
    }
    setHwiSignStatus("signing");
    resetResultOnly();
    try {
      const signed = await signHwiPsbt({
        fingerprint,
        psbt_base64: start.unsigned_psbt_base64,
        chain: networkToHwiChain(network),
        device_type: supportedKind,
        device_path: selectedDevice.path,
      });
      setHwiSignStatus("signed");
      await completeWithSignedPsbt(signed.psbt_base64);
    } catch {
      setHwiSignStatus("error");
      setCompleteStatus("error");
    }
  }

  async function handleSaveResult(): Promise<void> {
    if (result === null) {
      return;
    }
    setSaveStatus("saving");
    try {
      const saved = await saveDisasterSigningDrillResult(result);
      setSaveOutcome(saved);
      setSaveStatus("saved");
    } catch {
      setSaveStatus("error");
    }
  }

  return (
    <PageScaffold
      titleKey="pages.hardwareWalletDrill.title"
      bodyKey="pages.hardwareWalletDrill.body"
    >
      <div className="mt-6 space-y-6">
        <section className="rounded border border-status-needs-attention/60 bg-status-needs-attention/10 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-status-needs-attention" />
            <div className="text-sm text-slate-800 dark:text-slate-100">
              <p className="font-semibold">{t("pages.hardwareWalletDrill.note.title")}</p>
              <p className="mt-1">{t("pages.hardwareWalletDrill.note.body")}</p>
            </div>
          </div>
        </section>

        <section className="rounded border border-slate-200 p-4 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            {t("pages.hardwareWalletDrill.setup.heading")}
          </h2>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <fieldset>
              <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {t("pages.hardwareWalletDrill.network.label")}
              </legend>
              <div className="mt-2 space-y-2">
                {NETWORKS.map((item) => (
                  <label
                    key={item}
                    className="flex cursor-pointer items-start gap-3 rounded border border-slate-200 p-3 text-sm hover:border-brand dark:border-slate-700"
                  >
                    <input
                      type="radio"
                      name="hardware-drill-network"
                      value={item}
                      checked={network === item}
                      onChange={(event) => {
                        setNetwork(selectedNetwork(event.currentTarget.value));
                        resetExchange();
                      }}
                      className="mt-1 h-4 w-4 accent-brand"
                    />
                    <span>
                      <span className="block font-semibold text-slate-900 dark:text-slate-100">
                        {t(`pages.hardwareWalletDrill.network.${item}.title`)}
                      </span>
                      <span className="mt-1 block text-slate-600 dark:text-slate-300">
                        {t(`pages.hardwareWalletDrill.network.${item}.body`)}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            <fieldset>
              <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {t("pages.hardwareWalletDrill.transport.label")}
              </legend>
              <div className="mt-2 space-y-2">
                {TRANSPORTS.map((item) => (
                  <label
                    key={item}
                    className="flex cursor-pointer items-start gap-3 rounded border border-slate-200 p-3 text-sm hover:border-brand dark:border-slate-700"
                  >
                    <input
                      type="radio"
                      name="hardware-drill-transport"
                      value={item}
                      checked={transport === item}
                      onChange={(event) => {
                        setTransport(selectedTransport(event.currentTarget.value));
                        resetExchange();
                      }}
                      className="mt-1 h-4 w-4 accent-brand"
                    />
                    <span>
                      <span className="block font-semibold text-slate-900 dark:text-slate-100">
                        {t(`pages.hardwareWalletDrill.transport.${item}.title`)}
                      </span>
                      <span className="mt-1 block text-slate-600 dark:text-slate-300">
                        {t(`pages.hardwareWalletDrill.transport.${item}.body`)}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void handleStart()}
              disabled={startStatus === "starting"}
              className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
            >
              {startStatus === "starting"
                ? t("pages.hardwareWalletDrill.actions.starting")
                : t("pages.hardwareWalletDrill.actions.start")}
            </button>
            <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
              {startStatus === "error" && (
                <span className="text-status-not-ready">
                  {t("pages.hardwareWalletDrill.actions.startError")}
                </span>
              )}
            </p>
          </div>
        </section>

        {start !== null && (
          <section className="rounded border border-slate-200 bg-slate-50 p-4 text-sm dark:border-slate-700 dark:bg-slate-900">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.hardwareWalletDrill.package.heading")}
            </h2>
            <dl className="mt-3 grid gap-3 md:grid-cols-2">
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.hardwareWalletDrill.package.destination")}
                </dt>
                <dd className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-200">
                  {start.destination_address}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.hardwareWalletDrill.package.amount")}
                </dt>
                <dd className="mt-1 text-slate-700 dark:text-slate-200">
                  {t("pages.hardwareWalletDrill.package.amountValue", {
                    amount: start.amount_sat,
                  })}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.hardwareWalletDrill.package.network")}
                </dt>
                <dd className="mt-1 text-slate-700 dark:text-slate-200">
                  {t(`pages.hardwareWalletDrill.network.${network}.title`)}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.hardwareWalletDrill.package.transport")}
                </dt>
                <dd className="mt-1 text-slate-700 dark:text-slate-200">
                  {t(`pages.hardwareWalletDrill.transport.${transport}.title`)}
                </dd>
              </div>
            </dl>
            <label className="mt-4 flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
              <input
                type="checkbox"
                checked={destinationConfirmed}
                onChange={(event) => {
                  setDestinationConfirmed(event.currentTarget.checked);
                  resetResultOnly();
                }}
                className="mt-0.5 h-4 w-4 accent-brand"
              />
              <span>{t("pages.hardwareWalletDrill.confirmDestination")}</span>
            </label>
            <label className="mt-3 flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
              <input
                type="checkbox"
                checked={userStopped}
                onChange={(event) => {
                  setUserStopped(event.currentTarget.checked);
                  resetResultOnly();
                }}
                className="mt-0.5 h-4 w-4 accent-brand"
              />
              <span>{t("pages.hardwareWalletDrill.userStopped")}</span>
            </label>
          </section>
        )}

        {start !== null && transport === "file" && (
          <section className="rounded border border-slate-200 p-4 dark:border-slate-700">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.hardwareWalletDrill.file.heading")}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.hardwareWalletDrill.file.help")}
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => void handleSaveUnsigned()}
                disabled={fileStatus === "saving"}
                className="rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {fileStatus === "saving"
                  ? t("pages.hardwareWalletDrill.file.saving")
                  : t("pages.hardwareWalletDrill.file.save")}
              </button>
              <button
                type="button"
                onClick={() => void handleImportSignedFile()}
                disabled={fileStatus === "importing"}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {fileStatus === "importing"
                  ? t("pages.hardwareWalletDrill.file.importing")
                  : t("pages.hardwareWalletDrill.file.import")}
              </button>
            </div>
            <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
              {fileStatus === "saved" && filePath !== null && (
                <p className="break-all">
                  {t("pages.hardwareWalletDrill.file.saved", { path: filePath })}
                </p>
              )}
              {fileStatus === "imported" && filePath !== null && (
                <p className="break-all">
                  {t("pages.hardwareWalletDrill.file.imported", { path: filePath })}
                </p>
              )}
              {fileStatus === "cancelled" && <p>{t("pages.hardwareWalletDrill.file.cancelled")}</p>}
              {fileStatus === "error" && (
                <p className="text-status-not-ready">
                  {t("pages.hardwareWalletDrill.file.error")}
                </p>
              )}
            </div>
          </section>
        )}

        {start !== null && transport === "qr" && (
          <section className="rounded border border-slate-200 p-4 dark:border-slate-700">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.hardwareWalletDrill.qr.heading")}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.hardwareWalletDrill.qr.help")}
            </p>
            <fieldset className="mt-3">
              <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {t("pages.hardwareWalletDrill.qr.format.label")}
              </legend>
              <div className="mt-2 flex flex-wrap gap-2">
                {QR_FORMATS.map((item) => (
                  <label
                    key={item}
                    className="inline-flex cursor-pointer items-center gap-2 rounded border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:border-brand dark:border-slate-700 dark:text-slate-200"
                  >
                    <input
                      type="radio"
                      name="hardware-drill-qr-format"
                      value={item}
                      checked={qrFormat === item}
                      onChange={() => {
                        setQrFormat(item);
                        setQrEncodeStatus("idle");
                        setQrScanStatus("idle");
                      }}
                      className="h-4 w-4 accent-brand"
                    />
                    {t(`pages.hardwareWalletDrill.qr.format.${item}`)}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => void handleGenerateQr()}
                disabled={qrEncodeStatus === "encoding"}
                className="rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {qrEncodeStatus === "encoding"
                  ? t("pages.hardwareWalletDrill.qr.generating")
                  : t("pages.hardwareWalletDrill.qr.generate")}
              </button>
              <button
                type="button"
                onClick={() => void handleScanQr()}
                disabled={qrFrameSet === null || qrScanStatus === "scanning"}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {qrScanStatus === "scanning"
                  ? t("pages.hardwareWalletDrill.qr.scanning")
                  : t("pages.hardwareWalletDrill.qr.scan")}
              </button>
            </div>

            {visibleQrFrame !== null && (
              <div className="mt-4 grid gap-4 md:grid-cols-[minmax(0,16rem)_1fr]">
                <div>
                  <div className="flex aspect-square w-full max-w-64 items-center justify-center rounded border border-slate-200 bg-white p-3 dark:border-slate-700">
                    <img
                      src={svgDataUrl(visibleQrFrame.svg)}
                      alt={t("pages.hardwareWalletDrill.qr.alt", {
                        index: visibleQrFrame.index,
                        total: visibleQrFrame.total,
                      })}
                      className="h-full w-full"
                    />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        setQrFrameIndex((current) =>
                          current === 0 ? visibleQrFrame.total - 1 : current - 1,
                        )
                      }
                      className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:border-brand hover:text-brand dark:border-slate-600 dark:text-slate-200"
                    >
                      {t("pages.hardwareWalletDrill.qr.previous")}
                    </button>
                    <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                      {t("pages.hardwareWalletDrill.qr.frame", {
                        index: visibleQrFrame.index,
                        total: visibleQrFrame.total,
                      })}
                    </p>
                    <button
                      type="button"
                      onClick={() =>
                        setQrFrameIndex((current) => (current + 1) % visibleQrFrame.total)
                      }
                      className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:border-brand hover:text-brand dark:border-slate-600 dark:text-slate-200"
                    >
                      {t("pages.hardwareWalletDrill.qr.next")}
                    </button>
                  </div>
                </div>
                <div className="min-w-0 text-sm text-slate-700 dark:text-slate-200">
                  <p>{t("pages.hardwareWalletDrill.qr.instructions")}</p>
                  <code className="mt-2 block max-h-28 overflow-auto break-all rounded bg-slate-100 p-3 font-mono text-xs text-slate-900 dark:bg-slate-900 dark:text-slate-100">
                    {visibleQrFrame.payload}
                  </code>
                </div>
              </div>
            )}

            <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
              {qrEncodeStatus === "error" && (
                <p className="text-status-not-ready">{t("pages.hardwareWalletDrill.qr.error")}</p>
              )}
              {qrScanStatus === "no_payload" && <p>{t("pages.hardwareWalletDrill.qr.noPayload")}</p>}
              {qrScanStatus === "incomplete" && qrDecodeProgress !== null && (
                <p>
                  {t("pages.hardwareWalletDrill.qr.incomplete", {
                    count: qrDecodeProgress.received_count,
                  })}
                </p>
              )}
              {qrScanStatus === "error" && (
                <p className="text-status-not-ready">
                  {t("pages.hardwareWalletDrill.qr.scanError")}
                </p>
              )}
            </div>
          </section>
        )}

        {start !== null && transport === "hwi" && (
          <section className="rounded border border-slate-200 p-4 dark:border-slate-700">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.hardwareWalletDrill.hwi.heading")}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.hardwareWalletDrill.hwi.help")}
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => void handleCheckDevices()}
                disabled={deviceStatus === "checking"}
                className="rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {deviceStatus === "checking"
                  ? t("pages.hardwareWalletDrill.hwi.checking")
                  : t("pages.hardwareWalletDrill.hwi.check")}
              </button>
              <button
                type="button"
                onClick={() => void handleHwiSign()}
                disabled={!hwiCanSign}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {hwiSignStatus === "signing"
                  ? t("pages.hardwareWalletDrill.hwi.signing")
                  : t("pages.hardwareWalletDrill.hwi.sign")}
              </button>
            </div>

            <div className="mt-3 min-h-5 space-y-3 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
              {deviceStatus === "empty" && <p>{t("pages.hardwareWalletDrill.hwi.empty")}</p>}
              {deviceStatus === "error" && (
                <p className="text-status-not-ready">{t("pages.hardwareWalletDrill.hwi.error")}</p>
              )}
              {hwiSignStatus === "error" && (
                <p className="text-status-not-ready">
                  {t("pages.hardwareWalletDrill.hwi.signError")}
                </p>
              )}
              {hwiSignStatus === "signed" && (
                <p className="font-medium text-status-ready">
                  {t("pages.hardwareWalletDrill.hwi.signed")}
                </p>
              )}
            </div>

            {devices.length > 0 && (
              <fieldset className="mt-4">
                <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.hardwareWalletDrill.hwi.deviceLabel")}
                </legend>
                <div className="mt-2 space-y-2">
                  {devices.map((device) => {
                    const key = deviceKey(device);
                    return (
                      <label
                        key={key}
                        className="flex cursor-pointer items-start gap-3 rounded border border-slate-200 p-3 text-sm hover:border-brand dark:border-slate-700"
                      >
                        <input
                          type="radio"
                          name="hardware-drill-device"
                          value={key}
                          checked={selectedDeviceKey === key}
                          onChange={() => setSelectedDeviceKey(key)}
                          className="mt-1 h-4 w-4 accent-brand"
                        />
                        <span className="min-w-0">
                          <span className="block break-all font-semibold text-slate-900 dark:text-slate-100">
                            {deviceLabel(device)}
                          </span>
                          <span className="mt-1 block break-all text-slate-600 dark:text-slate-300">
                            {device.path ?? t("pages.hardwareWalletDrill.hwi.noPath")}
                          </span>
                          {device.supported_kind === null && (
                            <span className="mt-1 block text-status-needs-attention">
                              {t("pages.hardwareWalletDrill.hwi.unsupported")}
                            </span>
                          )}
                          {device.warnings.map((warning) => (
                            <span
                              key={`${warning.code}-${warning.title}`}
                              className="mt-1 block text-status-needs-attention"
                            >
                              {warning.code}: {warning.title}
                            </span>
                          ))}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>
            )}
          </section>
        )}

        {completeStatus === "error" && (
          <p className="text-sm text-status-not-ready">
            {t("pages.hardwareWalletDrill.actions.completeError")}
          </p>
        )}

        {result !== null && (
          <section
            aria-labelledby="hardware-drill-result-heading"
            className={`rounded border p-4 ${
              result.result === "pass"
                ? "border-status-ready/50 bg-status-ready/10"
                : "border-status-not-ready/50 bg-status-not-ready/10"
            }`}
          >
            <div className="flex items-start gap-3">
              {result.result === "pass" ? (
                <CheckCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-ready" />
              ) : (
                <XCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-not-ready" />
              )}
              <div>
                <h2
                  id="hardware-drill-result-heading"
                  className="text-lg font-semibold text-slate-900 dark:text-slate-100"
                >
                  {result.result === "pass"
                    ? t("pages.hardwareWalletDrill.results.pass")
                    : t("pages.hardwareWalletDrill.results.fail")}
                </h2>
                {result.finalized_txid !== "" && (
                  <p className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-200">
                    {result.finalized_txid}
                  </p>
                )}
              </div>
            </div>

            <ul className="mt-4 space-y-2">
              {result.steps.map((item) => (
                <li
                  key={item.step}
                  className="flex items-center justify-between gap-3 rounded bg-white px-3 py-2 text-sm dark:bg-slate-900"
                >
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(STEP_LABEL_KEYS[item.step] ?? "pages.hardwareWalletDrill.steps.unknown")}
                  </span>
                  <span
                    className={`rounded px-2 py-1 text-xs font-semibold ${
                      item.result === "pass"
                        ? "bg-status-ready text-white"
                        : "bg-status-not-ready text-white"
                    }`}
                  >
                    {t(`pages.hardwareWalletDrill.results.step.${item.result}`)}
                  </span>
                </li>
              ))}
            </ul>

            <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-700">
              <button
                type="button"
                onClick={() => void handleSaveResult()}
                disabled={saveStatus === "saving" || saveStatus === "saved"}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {saveStatus === "saving"
                  ? t("pages.hardwareWalletDrill.save.saving")
                  : t("pages.hardwareWalletDrill.save.button")}
              </button>
              <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                {saveStatus === "saved" && saveOutcome !== null && (
                  <span className="break-all">
                    {t("pages.hardwareWalletDrill.save.saved", { path: saveOutcome.path })}
                  </span>
                )}
                {saveStatus === "error" && (
                  <span className="text-status-not-ready">
                    {t("pages.hardwareWalletDrill.save.error")}
                  </span>
                )}
              </p>
            </div>
          </section>
        )}
      </div>
    </PageScaffold>
  );
}
