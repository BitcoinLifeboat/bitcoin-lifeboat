import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { usePrefsStore } from "../store/prefs";
import { applyTheme } from "../theme/theme";

/**
 * §15.2 first-launch flow (NORMATIVE). Five screens, with verbatim copy:
 *   1. Welcome (+ the §15.7 "not a wallet" paragraph)
 *   2. Safety Promise — the "I understand." checkbox is required to advance
 *   3. Goal
 *   4. Mode Confirmation — shown only for real-wallet-audit goals
 *   5. Home Dashboard (the routed app; reached once onboarding completes)
 *
 * Screens are skippable only AFTER Screen 2, i.e. once the safety promise is
 * acknowledged. Completion flips the Public `onboardingComplete` pref, which the
 * App gate watches to swap onboarding for the main app. All copy comes from i18n
 * keys — no hardcoded strings (the frontend is a thin presentation layer).
 */

/** A Screen 3 goal. Real-wallet-audit goals advance to the Screen 4 mode
 *  confirmation; Practice Mode and CLI tools finish onboarding directly. */
interface GoalOption {
  id: string;
  labelKey: string;
  requiresModeConfirmation: boolean;
}

const GOALS: GoalOption[] = [
  { id: "check-backup", labelKey: "onboarding.goal.checkBackup", requiresModeConfirmation: true },
  { id: "audit-multisig", labelKey: "onboarding.goal.auditMultisig", requiresModeConfirmation: true },
  { id: "heir-runbook", labelKey: "onboarding.goal.heirRunbook", requiresModeConfirmation: true },
  {
    id: "generate-runbook",
    labelKey: "onboarding.goal.generateRunbook",
    requiresModeConfirmation: true,
  },
  { id: "learn", labelKey: "onboarding.goal.learn", requiresModeConfirmation: false },
  { id: "cli", labelKey: "onboarding.goal.cli", requiresModeConfirmation: false },
];

// §15.2 is a five-screen flow; Screen 5 is the Home dashboard (the routed app).
const TOTAL_SCREENS = 5;
const WELCOME_STEP = 1;
const SAFETY_STEP = 2;
const GOAL_STEP = 3;
const MODE_STEP = 4;

const PROMISE_KEYS = [
  "onboarding.safety.promise1",
  "onboarding.safety.promise2",
  "onboarding.safety.promise3",
  "onboarding.safety.promise4",
];

const DO_NOT_PASTE_KEYS = [
  "onboarding.mode.doNotPasteSeed",
  "onboarding.mode.doNotPastePrivateKeys",
  "onboarding.mode.doNotPasteXprv",
  "onboarding.mode.doNotPastePassphrases",
];

const primaryButton =
  "rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg " +
  "disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "rounded px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 " +
  "dark:text-slate-200 dark:hover:bg-slate-800";

export default function Onboarding(): JSX.Element {
  const { t } = useTranslation();
  const theme = usePrefsStore((state) => state.theme);
  const setOnboardingComplete = usePrefsStore((state) => state.setOnboardingComplete);

  const [step, setStep] = useState(WELCOME_STEP);
  const [understood, setUnderstood] = useState(false);
  const [goalId, setGoalId] = useState<string | null>(null);

  // Respect the OS/theme preference even on first launch (Settings is only
  // reachable after onboarding, so the value is "system" here in practice).
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const selectedGoal = GOALS.find((goal) => goal.id === goalId) ?? null;
  // §15.2: skippable only after Screen 2.
  const canSkip = step > SAFETY_STEP;
  const continueDisabled =
    (step === SAFETY_STEP && !understood) || (step === GOAL_STEP && selectedGoal === null);

  function finish(): void {
    setOnboardingComplete(true);
  }

  function goNext(): void {
    switch (step) {
      case WELCOME_STEP:
        setStep(SAFETY_STEP);
        return;
      case SAFETY_STEP:
        if (understood) {
          setStep(GOAL_STEP);
        }
        return;
      case GOAL_STEP:
        if (!selectedGoal) {
          return;
        }
        if (selectedGoal.requiresModeConfirmation) {
          setStep(MODE_STEP);
        } else {
          finish();
        }
        return;
      default:
        // Screen 4 (mode confirmation) is the last onboarding screen → Home.
        finish();
    }
  }

  function goBack(): void {
    setStep((current) => Math.max(WELCOME_STEP, current - 1));
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-6 text-slate-900 dark:bg-slate-900 dark:text-slate-100">
      <section
        aria-label={t("onboarding.common.ariaLabel")}
        className="w-full max-w-xl rounded-lg border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-700 dark:bg-slate-800"
      >
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {t("onboarding.common.step", { current: step, total: TOTAL_SCREENS })}
        </p>

        <div className="mt-4">
          {step === WELCOME_STEP && (
            <div>
              <h1 className="text-3xl font-semibold">{t("onboarding.welcome.title")}</h1>
              <p className="mt-4 text-slate-700 dark:text-slate-200">
                {t("onboarding.welcome.intro")}
              </p>
              <div className="mt-4 space-y-1 text-slate-700 dark:text-slate-200">
                <p>{t("onboarding.welcome.notWallet")}</p>
                <p>{t("onboarding.welcome.notCustody")}</p>
                <p>{t("onboarding.welcome.notSeed")}</p>
              </div>
              <p className="mt-6 text-sm text-slate-600 dark:text-slate-300">
                {t("onboarding.welcome.notAWallet")}
              </p>
            </div>
          )}

          {step === SAFETY_STEP && (
            <div>
              <h1 className="text-2xl font-semibold">{t("onboarding.safety.heading")}</h1>
              <ol className="mt-4 list-decimal space-y-2 pl-6 text-slate-700 dark:text-slate-200">
                {PROMISE_KEYS.map((key) => (
                  <li key={key}>{t(key)}</li>
                ))}
              </ol>
              <label className="mt-6 flex items-center gap-3 text-slate-800 dark:text-slate-100">
                <input
                  type="checkbox"
                  className="h-4 w-4"
                  checked={understood}
                  onChange={(event) => setUnderstood(event.target.checked)}
                />
                <span>{t("onboarding.safety.understand")}</span>
              </label>
            </div>
          )}

          {step === GOAL_STEP && (
            <div>
              <h1 id="onboarding-goal-heading" className="text-2xl font-semibold">
                {t("onboarding.goal.heading")}
              </h1>
              <div
                role="radiogroup"
                aria-labelledby="onboarding-goal-heading"
                className="mt-4 space-y-2"
              >
                {GOALS.map((goal) => (
                  <label
                    key={goal.id}
                    className="flex cursor-pointer items-center gap-3 rounded border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-700"
                  >
                    <input
                      type="radio"
                      name="onboarding-goal"
                      value={goal.id}
                      className="h-4 w-4"
                      checked={goalId === goal.id}
                      onChange={() => setGoalId(goal.id)}
                    />
                    <span className="text-slate-800 dark:text-slate-100">{t(goal.labelKey)}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {step === MODE_STEP && (
            <div>
              <h1 className="text-2xl font-semibold">{t("onboarding.mode.intro")}</h1>
              <p className="mt-2 text-slate-700 dark:text-slate-200">
                {t("onboarding.mode.publicMetadata")}
              </p>
              <p className="mt-6 font-medium text-slate-800 dark:text-slate-100">
                {t("onboarding.mode.doNotPaste")}
              </p>
              <ul className="mt-2 list-disc space-y-1 pl-6 text-slate-700 dark:text-slate-200">
                {DO_NOT_PASTE_KEYS.map((key) => (
                  <li key={key}>{t(key)}</li>
                ))}
              </ul>
              <p className="mt-6 text-sm text-slate-600 dark:text-slate-300">
                {t("onboarding.mode.detect")}
              </p>
            </div>
          )}
        </div>

        <div className="mt-8 flex items-center justify-between">
          <div>
            {step > WELCOME_STEP && (
              <button type="button" onClick={goBack} className={secondaryButton}>
                {t("onboarding.common.back")}
              </button>
            )}
          </div>
          <div className="flex items-center gap-3">
            {canSkip && (
              <button type="button" onClick={finish} className={secondaryButton}>
                {t("onboarding.common.skip")}
              </button>
            )}
            <button
              type="button"
              onClick={goNext}
              disabled={continueDisabled}
              className={primaryButton}
            >
              {t("onboarding.common.continue")}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
