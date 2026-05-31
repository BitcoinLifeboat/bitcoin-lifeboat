import { useState } from "react";
import { useTranslation } from "react-i18next";

import { AlertTriangleIcon, CheckCircleIcon, HelpCircleIcon } from "../components/icons";
import {
  generateFamilyDrillReceipt,
  saveExport,
  showSaveDialog,
} from "../tauri/commands";
import type { FamilyDrillConfidenceCheck } from "../tauri/commands";
import { PageScaffold } from "./PageScaffold";

const STEP_IDS = ["start", "packet", "wallet", "send", "result"] as const;
type StepId = (typeof STEP_IDS)[number];

const STEP_TERMS: Record<StepId, string[]> = {
  start: ["packet", "testCoins"],
  packet: ["practiceWallet"],
  wallet: ["import", "address"],
  send: ["sign", "testNetwork"],
  result: ["receipt"],
};

const STEP_STOPS: Record<StepId, string[]> = {
  start: ["secretRequest", "contacted"],
  packet: ["missingFiles", "wrongPacket"],
  wallet: ["mainnet", "payFee"],
  send: ["realBitcoin", "newAddress", "secretRequest"],
  result: ["unsure", "pressure"],
};

const CONFIDENCE_IDS = ["packet", "fakeBitcoin", "realSeeds", "contact"] as const;
type ConfidenceId = (typeof CONFIDENCE_IDS)[number];

const CONFIDENCE_RECEIPT_IDS: Record<ConfidenceId, FamilyDrillConfidenceCheck> = {
  packet: "packet",
  fakeBitcoin: "fake_bitcoin",
  realSeeds: "real_seeds",
  contact: "contact",
};

const stepButtonBase =
  "flex w-full items-center gap-3 rounded border p-3 text-left text-sm transition " +
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-brand";
const activeStepButton =
  "border-brand bg-brand/10 text-slate-950 dark:border-brand dark:bg-brand/20 dark:text-slate-50";
const inactiveStepButton =
  "border-slate-200 bg-white text-slate-700 hover:border-brand dark:border-slate-700 " +
  "dark:bg-slate-800 dark:text-slate-200";
const primaryButton =
  "rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg " +
  "disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "rounded px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 " +
  "disabled:cursor-not-allowed disabled:opacity-50 dark:text-slate-200 dark:hover:bg-slate-800";

function nextStepId(step: StepId): StepId {
  const index = STEP_IDS.indexOf(step);
  return STEP_IDS[Math.min(index + 1, STEP_IDS.length - 1)];
}

function previousStepId(step: StepId): StepId {
  const index = STEP_IDS.indexOf(step);
  return STEP_IDS[Math.max(index - 1, 0)];
}

export default function HeirWalkthrough(): JSX.Element {
  const { t } = useTranslation();
  const [currentStep, setCurrentStep] = useState<StepId>("start");
  const [completedSteps, setCompletedSteps] = useState<Record<StepId, boolean>>({
    start: false,
    packet: false,
    wallet: false,
    send: false,
    result: false,
  });
  const [confidence, setConfidence] = useState<Record<ConfidenceId, boolean>>({
    packet: false,
    fakeBitcoin: false,
    realSeeds: false,
    contact: false,
  });
  const [receiptStatus, setReceiptStatus] =
    useState<"idle" | "saving" | "saved" | "cancelled" | "error">("idle");
  const [receiptHash, setReceiptHash] = useState<string | null>(null);

  const currentIndex = STEP_IDS.indexOf(currentStep);
  const allStepsDone = STEP_IDS.every((step) => completedSteps[step]);
  const confidenceDone = CONFIDENCE_IDS.every((item) => confidence[item]);

  function setStepDone(step: StepId, done: boolean): void {
    setCompletedSteps((state) => ({ ...state, [step]: done }));
    setReceiptStatus("idle");
    setReceiptHash(null);
  }

  function setConfidenceDone(item: ConfidenceId, done: boolean): void {
    setConfidence((state) => ({ ...state, [item]: done }));
    setReceiptStatus("idle");
    setReceiptHash(null);
  }

  async function saveReceipt(): Promise<void> {
    setReceiptStatus("saving");
    setReceiptHash(null);
    try {
      const artifact = await generateFamilyDrillReceipt({
        packet_id: null,
        network: null,
        completed_steps: STEP_IDS.filter((step) => completedSteps[step]),
        confidence_checks: CONFIDENCE_IDS.filter((item) => confidence[item]).map(
          (item) => CONFIDENCE_RECEIPT_IDS[item],
        ),
        user_stopped: false,
      });
      const path = await showSaveDialog({
        defaultPath: artifact.suggested_filename,
        filters: [
          {
            name: t("pages.heirWalkthrough.receiptExport.fileType"),
            extensions: ["pdf"],
          },
        ],
      });
      if (path === null) {
        setReceiptStatus("cancelled");
        return;
      }
      await saveExport(path, artifact.content);
      setReceiptHash(artifact.receipt_hash);
      setReceiptStatus("saved");
    } catch {
      setReceiptStatus("error");
    }
  }

  return (
    <PageScaffold titleKey="pages.heirWalkthrough.title" bodyKey="pages.heirWalkthrough.body">
      <div className="mt-5 rounded border border-status-needs-attention/60 bg-status-needs-attention/10 p-4 text-sm text-slate-800 dark:border-status-needs-attention dark:bg-slate-800 dark:text-slate-100">
        <div className="flex gap-3">
          <AlertTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-status-needs-attention" />
          <p>{t("pages.heirWalkthrough.scamReminder")}</p>
        </div>
      </div>

      <div className="mt-6 grid gap-5 lg:grid-cols-[17rem_1fr]">
        <aside aria-label={t("pages.heirWalkthrough.progress.label")} className="space-y-3">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {t("pages.heirWalkthrough.progress.heading")}
          </h2>
          <ol className="space-y-2">
            {STEP_IDS.map((step, index) => {
              const done = completedSteps[step];
              const active = step === currentStep;
              return (
                <li key={step}>
                  <button
                    type="button"
                    aria-current={active ? "step" : undefined}
                    onClick={() => setCurrentStep(step)}
                    className={[stepButtonBase, active ? activeStepButton : inactiveStepButton].join(
                      " ",
                    )}
                  >
                    <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-current bg-white text-xs font-semibold dark:bg-slate-900">
                      {done ? (
                        <CheckCircleIcon className="h-5 w-5" />
                      ) : (
                        <span>{index + 1}</span>
                      )}
                    </span>
                    <span>
                      <span className="block font-medium">
                        {t(`pages.heirWalkthrough.steps.${step}.title`)}
                      </span>
                      <span className="block text-xs text-slate-700 dark:text-slate-200">
                        {done
                          ? t("pages.heirWalkthrough.progress.done")
                          : t("pages.heirWalkthrough.progress.notDone")}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </aside>

        <section
          aria-labelledby="heir-walkthrough-step-title"
          className="rounded border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800"
        >
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">
            {t("pages.heirWalkthrough.stepCount", {
              current: currentIndex + 1,
              total: STEP_IDS.length,
            })}
          </p>
          <h2
            id="heir-walkthrough-step-title"
            className="mt-1 text-xl font-semibold text-slate-950 dark:text-slate-50"
          >
            {t(`pages.heirWalkthrough.steps.${currentStep}.title`)}
          </h2>
          <p className="mt-3 text-slate-700 dark:text-slate-200">
            {t(`pages.heirWalkthrough.steps.${currentStep}.body`)}
          </p>

          <div className="mt-5 rounded border border-slate-200 p-4 dark:border-slate-700">
            <div className="flex items-center gap-2">
              <HelpCircleIcon className="h-5 w-5 text-brand" />
              <h3 className="font-semibold text-slate-900 dark:text-slate-100">
                {t("pages.heirWalkthrough.terms.heading")}
              </h3>
            </div>
            <dl className="mt-3 space-y-2 text-sm">
              {STEP_TERMS[currentStep].map((term) => (
                <div key={term}>
                  <dt className="font-medium text-slate-900 dark:text-slate-100">
                    {t(`pages.heirWalkthrough.terms.${term}.term`)}
                  </dt>
                  <dd className="text-slate-600 dark:text-slate-300">
                    {t(`pages.heirWalkthrough.terms.${term}.meaning`)}
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          <div className="mt-5 rounded border border-status-not-ready/60 bg-status-not-ready/10 p-4 dark:border-status-not-ready dark:bg-slate-900">
            <div className="flex items-center gap-2">
              <AlertTriangleIcon className="h-5 w-5 text-status-not-ready" />
              <h3 className="font-semibold text-slate-900 dark:text-slate-100">
                {t("pages.heirWalkthrough.stop.heading")}
              </h3>
            </div>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-200">
              {STEP_STOPS[currentStep].map((stop) => (
                <li key={stop}>{t(`pages.heirWalkthrough.stop.items.${stop}`)}</li>
              ))}
            </ul>
          </div>

          <label className="mt-5 flex items-start gap-3 rounded border border-slate-200 p-3 text-sm dark:border-slate-700">
            <input
              type="checkbox"
              className="mt-1 h-4 w-4 accent-brand"
              checked={completedSteps[currentStep]}
              onChange={(event) => setStepDone(currentStep, event.currentTarget.checked)}
            />
            <span>
              <span className="block font-medium text-slate-900 dark:text-slate-100">
                {t("pages.heirWalkthrough.markDone.label")}
              </span>
              <span className="text-slate-600 dark:text-slate-300">
                {t("pages.heirWalkthrough.markDone.help")}
              </span>
            </span>
          </label>

          <div className="mt-5 flex justify-between gap-3">
            <button
              type="button"
              className={secondaryButton}
              disabled={currentIndex === 0}
              onClick={() => setCurrentStep(previousStepId(currentStep))}
            >
              {t("pages.heirWalkthrough.back")}
            </button>
            <button
              type="button"
              className={primaryButton}
              disabled={currentIndex === STEP_IDS.length - 1}
              onClick={() => setCurrentStep(nextStepId(currentStep))}
            >
              {t("pages.heirWalkthrough.next")}
            </button>
          </div>
        </section>
      </div>

      <section
        aria-labelledby="heir-confidence-title"
        className="mt-6 rounded border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800"
      >
        <h2 id="heir-confidence-title" className="text-lg font-semibold">
          {t("pages.heirWalkthrough.confidence.heading")}
        </h2>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
          {t("pages.heirWalkthrough.confidence.body")}
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {CONFIDENCE_IDS.map((item) => (
            <label
              key={item}
              className="flex items-start gap-3 rounded border border-slate-200 p-3 text-sm dark:border-slate-700"
            >
              <input
                type="checkbox"
                className="mt-1 h-4 w-4 accent-brand"
                checked={confidence[item]}
                onChange={(event) => setConfidenceDone(item, event.currentTarget.checked)}
              />
              <span>{t(`pages.heirWalkthrough.confidence.items.${item}`)}</span>
            </label>
          ))}
        </div>
        <p
          className="mt-4 rounded bg-slate-100 p-3 text-sm text-slate-700 dark:bg-slate-900 dark:text-slate-200"
          role="status"
        >
          {allStepsDone && confidenceDone
            ? t("pages.heirWalkthrough.confidence.ready")
            : t("pages.heirWalkthrough.confidence.keepGoing")}
        </p>
        <p className="mt-3 text-sm font-medium text-slate-800 dark:text-slate-100">
          {t("pages.heirWalkthrough.finalScamReminder")}
        </p>
        <div className="mt-5 border-t border-slate-200 pt-4 dark:border-slate-700">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            {t("pages.heirWalkthrough.receiptExport.heading")}
          </h3>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {t("pages.heirWalkthrough.receiptExport.body")}
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void saveReceipt()}
              disabled={receiptStatus === "saving"}
              className={primaryButton}
            >
              {receiptStatus === "saving"
                ? t("pages.heirWalkthrough.receiptExport.saving")
                : t("pages.heirWalkthrough.receiptExport.button")}
            </button>
            {receiptStatus !== "idle" && receiptStatus !== "saving" && (
              <p
                role="status"
                className={`text-sm ${
                  receiptStatus === "error"
                    ? "text-status-not-ready"
                    : "text-slate-600 dark:text-slate-300"
                }`}
              >
                {receiptStatus === "saved"
                  ? t("pages.heirWalkthrough.receiptExport.status.saved", {
                      hash: receiptHash,
                    })
                  : t(`pages.heirWalkthrough.receiptExport.status.${receiptStatus}`)}
              </p>
            )}
          </div>
        </div>
      </section>
    </PageScaffold>
  );
}
