import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { CameraIcon, QrCodeIcon } from "../components/icons";
import {
  capturePsbtQrPayloads,
  decodePsbtQrPayloads,
  encodePsbtQrFrames,
  finalizeFilePsbt,
  type FilePsbtFinalizeResult,
  type PracticeSendDrillResult,
  type PsbtQrDecodeResult,
  type PsbtQrFormat,
  type PsbtQrFrameSet,
} from "../tauri/commands";

const QR_FORMATS: PsbtQrFormat[] = ["ur", "bbqr"];

type EncodeStatus = "idle" | "encoding" | "ready" | "error";
type ScanStatus = "idle" | "scanning" | "incomplete" | "finalized" | "no_payload" | "error";

interface PracticeQrExchangeProps {
  sendResult: PracticeSendDrillResult;
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

export default function PracticeQrExchange({
  sendResult,
}: PracticeQrExchangeProps): JSX.Element {
  const { t } = useTranslation();
  const [format, setFormat] = useState<PsbtQrFormat>("ur");
  const [encodeStatus, setEncodeStatus] = useState<EncodeStatus>("idle");
  const [scanStatus, setScanStatus] = useState<ScanStatus>("idle");
  const [frameSet, setFrameSet] = useState<PsbtQrFrameSet | null>(null);
  const [frameIndex, setFrameIndex] = useState(0);
  const [payloads, setPayloads] = useState<string[]>([]);
  const [decodeProgress, setDecodeProgress] = useState<PsbtQrDecodeResult | null>(null);
  const [qrResult, setQrResult] = useState<FilePsbtFinalizeResult | null>(null);
  const visibleFrame = frameSet?.frames[frameIndex] ?? null;

  useEffect(() => {
    if (!frameSet || frameSet.frames.length <= 1) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      setFrameIndex((current) => (current + 1) % frameSet.frames.length);
    }, 900);

    return () => window.clearInterval(timer);
  }, [frameSet]);

  function resetScan(): void {
    setPayloads([]);
    setDecodeProgress(null);
    setQrResult(null);
    setScanStatus("idle");
  }

  function selectFormat(nextFormat: PsbtQrFormat): void {
    setFormat(nextFormat);
    setFrameSet(null);
    setFrameIndex(0);
    setEncodeStatus("idle");
    resetScan();
  }

  async function handleGenerateFrames(): Promise<void> {
    setEncodeStatus("encoding");
    setFrameSet(null);
    setFrameIndex(0);
    resetScan();
    try {
      const frames = await encodePsbtQrFrames({
        format,
        psbt_base64: sendResult.unsigned_psbt_base64,
      });
      setFrameSet(frames);
      setEncodeStatus("ready");
    } catch {
      setEncodeStatus("error");
    }
  }

  async function decodeWithPayloads(nextPayloads: string[]): Promise<void> {
    const decoded = await decodePsbtQrPayloads({ format, payloads: nextPayloads });
    setDecodeProgress(decoded);

    if (decoded.status !== "complete" || !decoded.psbt_base64) {
      setScanStatus("incomplete");
      return;
    }

    const finalized = await finalizeFilePsbt({
      network: sendResult.network,
      psbt_base64: decoded.psbt_base64,
    });
    setQrResult(finalized);
    setScanStatus("finalized");
  }

  async function handleScanCameraFrame(): Promise<void> {
    setScanStatus("scanning");
    try {
      const scanned = await capturePsbtQrPayloads(0);
      if (scanned.length === 0) {
        setScanStatus("no_payload");
        return;
      }
      const nextPayloads = mergePayloads(payloads, scanned);
      setPayloads(nextPayloads);
      await decodeWithPayloads(nextPayloads);
    } catch {
      setScanStatus("error");
    }
  }

  return (
    <div className="mt-4 border-t border-status-ready/30 pt-4">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
        {t("pages.practiceMode.drill.qrExchange.title")}
      </h3>
      <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
        {t("pages.practiceMode.drill.qrExchange.body")}
      </p>

      <fieldset className="mt-3">
        <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
          {t("pages.practiceMode.drill.qrExchange.format.label")}
        </legend>
        <div className="mt-2 flex flex-wrap gap-2">
          {QR_FORMATS.map((option) => (
            <label
              key={option}
              className={[
                "inline-flex cursor-pointer items-center gap-2 rounded border px-3 py-2 text-sm",
                format === option
                  ? "border-brand bg-brand/10 text-slate-900 dark:text-slate-100"
                  : "border-slate-200 text-slate-700 hover:border-brand dark:border-slate-700 dark:text-slate-200",
              ].join(" ")}
            >
              <input
                type="radio"
                name="qr-psbt-format"
                value={option}
                checked={format === option}
                onChange={() => selectFormat(option)}
                className="h-4 w-4 accent-brand"
              />
              <span>{t(`pages.practiceMode.drill.qrExchange.format.${option}`)}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void handleGenerateFrames()}
          disabled={encodeStatus === "encoding"}
          className="inline-flex items-center gap-2 rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <QrCodeIcon className="h-4 w-4" />
          {encodeStatus === "encoding"
            ? t("pages.practiceMode.drill.qrExchange.generating")
            : t("pages.practiceMode.drill.qrExchange.generate")}
        </button>
        <button
          type="button"
          onClick={() => void handleScanCameraFrame()}
          disabled={!frameSet || scanStatus === "scanning"}
          className="inline-flex items-center gap-2 rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
        >
          <CameraIcon className="h-4 w-4" />
          {scanStatus === "scanning"
            ? t("pages.practiceMode.drill.qrExchange.scanning")
            : t("pages.practiceMode.drill.qrExchange.scan")}
        </button>
      </div>

      {visibleFrame && (
        <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,18rem)_1fr]">
          <div>
            <div className="flex aspect-square w-full max-w-72 items-center justify-center rounded border border-slate-200 bg-white p-3 dark:border-slate-700">
              <img
                src={svgDataUrl(visibleFrame.svg)}
                alt={t("pages.practiceMode.drill.qrExchange.alt", {
                  index: visibleFrame.index,
                  total: visibleFrame.total,
                })}
                className="h-full w-full"
              />
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() =>
                  setFrameIndex((current) =>
                    current === 0 ? visibleFrame.total - 1 : current - 1,
                  )
                }
                className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:border-brand hover:text-brand dark:border-slate-600 dark:text-slate-200"
              >
                {t("pages.practiceMode.drill.qrExchange.previous")}
              </button>
              <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {t("pages.practiceMode.drill.qrExchange.frame", {
                  index: visibleFrame.index,
                  total: visibleFrame.total,
                })}
              </p>
              <button
                type="button"
                onClick={() => setFrameIndex((current) => (current + 1) % visibleFrame.total)}
                className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:border-brand hover:text-brand dark:border-slate-600 dark:text-slate-200"
              >
                {t("pages.practiceMode.drill.qrExchange.next")}
              </button>
            </div>
          </div>
          <div className="min-w-0 text-sm text-slate-700 dark:text-slate-200">
            <p>{t("pages.practiceMode.drill.qrExchange.instructions")}</p>
            <code className="mt-2 block max-h-28 overflow-auto break-all rounded bg-slate-100 p-3 font-mono text-xs text-slate-900 dark:bg-slate-900 dark:text-slate-100">
              {visibleFrame.payload}
            </code>
          </div>
        </div>
      )}

      <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
        {encodeStatus === "ready" && frameSet && (
          <p>
            {t("pages.practiceMode.drill.qrExchange.generated", {
              count: frameSet.frame_count,
            })}
          </p>
        )}
        {encodeStatus === "error" && (
          <p className="text-status-not-ready">
            {t("pages.practiceMode.drill.qrExchange.generateError")}
          </p>
        )}
        {scanStatus === "no_payload" && (
          <p>{t("pages.practiceMode.drill.qrExchange.noPayload")}</p>
        )}
        {scanStatus === "incomplete" && decodeProgress && (
          <p>
            {t("pages.practiceMode.drill.qrExchange.incomplete", {
              count: decodeProgress.received_count,
              remaining:
                decodeProgress.parts_left ??
                t("pages.practiceMode.drill.qrExchange.unknownRemaining"),
            })}
          </p>
        )}
        {scanStatus === "error" && (
          <p className="text-status-not-ready">
            {t("pages.practiceMode.drill.qrExchange.scanError")}
          </p>
        )}
        {scanStatus === "finalized" && qrResult && (
          <div>
            <p className="font-medium text-slate-900 dark:text-slate-100">
              {t("pages.practiceMode.drill.qrExchange.finalized")}
            </p>
            <dl className="mt-2 grid gap-2 sm:grid-cols-3">
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.practiceMode.drill.fileExchange.txid")}
                </dt>
                <dd className="break-all font-mono text-xs">{qrResult.txid}</dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.practiceMode.drill.fileExchange.fee")}
                </dt>
                <dd>
                  {t("pages.practiceMode.drill.fileExchange.feeValue", {
                    fee: qrResult.inspection.fee_sat,
                  })}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.practiceMode.drill.fileExchange.feeRate")}
                </dt>
                <dd>
                  {t("pages.practiceMode.drill.fileExchange.feeRateValue", {
                    feeRate: qrResult.inspection.fee_rate_sat_vb,
                  })}
                </dd>
              </div>
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}
