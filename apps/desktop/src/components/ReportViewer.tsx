import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

import { StatusBadge } from "./StatusBadge";
import type { ReadinessReport } from "../tauri/commands";

/**
 * §22.5 / §15.10 / §15.8 Report viewer (US-050).
 *
 * Renders a §19.1 `ReadinessReport` (the `auditDescriptor` result) as the in-app
 * readiness report. The first layer is plain English (§15.9): a one-sentence
 * summary, the §22.3 status badge, and the §15.10 sections in order — what
 * passed, needs attention, failed, is missing, what to do next, what NOT to do,
 * when to run again, the §15.6 short disclaimer, and the Lifeboat version + report
 * hash. Technical detail (descriptor, checks, hashes) sits behind a
 * default-closed "Show technical details" expander (§15.9). Every report also
 * reproduces the verbatim §15.8 "What this report cannot tell you" block.
 *
 * Presentational only — it takes a report and renders it; it runs no Bitcoin
 * logic and makes no IPC calls (the caller fetches the report via
 * `auditDescriptor`). All copy comes from i18n keys; it never claims a wallet is
 * "safe" (§16.8 — the core lints the report text it authors).
 */

interface ReportViewerProps {
  report: ReadinessReport;
  /**
   * Omit the "Show technical details" expander, which renders the full canonical
   * descriptor (xpub-bearing). The §17.7.4 print-to-PDF path sets this so a printed
   * report stays public-safe (no key material) regardless of redaction mode; the
   * on-screen viewer leaves it `false` and keeps the expander. Defaults to `false`.
   */
  hideTechnicalDetails?: boolean;
}

/** Build the plain text the §22.5 "Copy explanation" button puts on the clipboard:
 *  the headline, the section bullets, the disclaimer, and the version line, so the
 *  user can paste a self-contained summary. */
function buildExplanation(report: ReadinessReport): string {
  const lines: string[] = [`Status: ${report.score.headline} (score ${report.score.numeric}/100)`];
  const block = (heading: string, items: string[]): void => {
    if (items.length > 0) {
      lines.push("", `${heading}:`, ...items.map((item) => `- ${item}`));
    }
  };
  block("What passed", report.passes.map((p) => p.title));
  block("What needs attention", report.warnings.map((w) => `${w.title} — ${w.recommended_fix}`));
  block("What failed", report.critical_issues.map((c) => c.title));
  block("What to do next", report.next_steps.map((s) => `${s.priority}. ${s.action} (${s.effort})`));
  lines.push(
    "",
    report.disclaimer_short,
    "",
    `Bitcoin Lifeboat ${report.app_version} — ${report.report_hash}`,
  );
  return lines.join("\n");
}

/** Copy the explanation to the OS clipboard if the API is available (it is in the
 *  Tauri webview; guarded so jsdom / older webviews degrade quietly). */
function copyExplanation(report: ReadinessReport): void {
  const clipboard = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
  if (clipboard?.writeText) {
    void clipboard.writeText(buildExplanation(report));
  }
}

function ReportSection({ title, children }: { title: string; children: ReactNode }): JSX.Element {
  return (
    <section>
      <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {title}
      </h3>
      <div className="mt-2">{children}</div>
    </section>
  );
}

function EmptyNote({ children }: { children: string }): JSX.Element {
  return <p className="text-sm text-slate-500 dark:text-slate-400">{children}</p>;
}

function TechRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}): JSX.Element {
  return (
    <div className="flex flex-wrap gap-2">
      <span className="font-medium text-slate-900 dark:text-slate-100">{label}</span>
      <span className={mono ? "break-all font-mono text-xs" : ""}>{value}</span>
    </div>
  );
}

export function ReportViewer({
  report,
  hideTechnicalDetails = false,
}: ReportViewerProps): JSX.Element {
  const { t } = useTranslation();
  const { score } = report;
  const missingChecks = report.checks.filter((check) => check.result === "unknown");

  return (
    <section aria-label={t("report.ariaLabel")} className="space-y-8">
      {/* §22.5: plain-English summary, status badge, copy + learn-more affordances. */}
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
            {t("report.title")}
          </h2>
          <StatusBadge status={score.status} />
        </div>
        <p className="text-slate-700 dark:text-slate-200">
          {t("report.summary", {
            headline: score.headline,
            numeric: score.numeric,
            warnings: report.warnings.length,
            criticals: report.critical_issues.length,
          })}
        </p>
        <div className="flex flex-wrap items-center gap-4">
          <button
            type="button"
            onClick={() => copyExplanation(report)}
            className="rounded bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-fg"
          >
            {t("report.copyExplanation")}
          </button>
          <Link to="/learn" className="text-sm font-medium text-brand hover:underline">
            {t("report.learnMore")}
          </Link>
        </div>
      </header>

      {/* §15.10 (2) What passed */}
      <ReportSection title={t("report.sections.passed")}>
        {report.passes.length === 0 ? (
          <EmptyNote>{t("report.none.passed")}</EmptyNote>
        ) : (
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-200">
            {report.passes.map((item) => (
              <li key={item.code}>{item.title}</li>
            ))}
          </ul>
        )}
      </ReportSection>

      {/* §15.10 (3) What needs attention — each warning carries the §22.5 fix block */}
      <ReportSection title={t("report.sections.needsAttention")}>
        {report.warnings.length === 0 ? (
          <EmptyNote>{t("report.none.needsAttention")}</EmptyNote>
        ) : (
          <ul className="space-y-4">
            {report.warnings.map((warning) => (
              <li
                key={warning.code}
                className="rounded border border-status-needs-attention/40 p-3"
              >
                <p className="font-medium text-slate-900 dark:text-slate-100">{warning.title}</p>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                  {warning.description}
                </p>
                <p className="mt-2 text-sm text-slate-800 dark:text-slate-100">
                  <span className="font-medium">{t("report.recommendedFix")}</span>{" "}
                  {warning.recommended_fix}
                </p>
              </li>
            ))}
          </ul>
        )}
      </ReportSection>

      {/* §15.10 (4) What failed */}
      <ReportSection title={t("report.sections.failed")}>
        {report.critical_issues.length === 0 ? (
          <EmptyNote>{t("report.none.failed")}</EmptyNote>
        ) : (
          <ul className="space-y-4">
            {report.critical_issues.map((issue) => (
              <li key={issue.code} className="rounded border border-status-not-ready/40 p-3">
                <p className="font-medium text-status-not-ready">{issue.title}</p>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                  {issue.description}
                </p>
              </li>
            ))}
          </ul>
        )}
      </ReportSection>

      {/* §15.10 (5) What is missing — checks the core could not determine */}
      <ReportSection title={t("report.sections.missing")}>
        {missingChecks.length === 0 ? (
          <EmptyNote>{t("report.none.missing")}</EmptyNote>
        ) : (
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-200">
            {missingChecks.map((check) => (
              <li key={check.code}>{check.title}</li>
            ))}
          </ul>
        )}
      </ReportSection>

      {/* §15.10 (6) What to do next — prioritized, action-oriented */}
      <ReportSection title={t("report.sections.nextSteps")}>
        {report.next_steps.length === 0 ? (
          <EmptyNote>{t("report.none.needsAttention")}</EmptyNote>
        ) : (
          <ol className="space-y-2">
            {[...report.next_steps]
              .sort((a, b) => a.priority - b.priority)
              .map((step) => (
                <li key={step.priority} className="text-sm text-slate-700 dark:text-slate-200">
                  <span className="font-medium text-slate-900 dark:text-slate-100">
                    {step.action}
                  </span>{" "}
                  <span className="text-slate-500 dark:text-slate-400">
                    ({t("report.effortLabel")} {step.effort})
                  </span>
                </li>
              ))}
          </ol>
        )}
      </ReportSection>

      {/* §15.10 (7) What NOT to do */}
      <ReportSection title={t("report.sections.antiActions")}>
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-200">
          {report.anti_actions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      </ReportSection>

      {/* §15.10 (8) When to run this again */}
      <ReportSection title={t("report.sections.runAgain")}>
        <p className="text-sm text-slate-700 dark:text-slate-200">
          {report.next_drill_recommendation ?? t("report.runAgainUnknown")}
        </p>
      </ReportSection>

      {/* §22.5 (3) / §15.9 technical details, default-closed. Omitted from the
          §17.7.4 print-to-PDF rendering so a printed report stays public-safe
          (the canonical descriptor below is xpub-bearing). */}
      {!hideTechnicalDetails && (
      <details className="rounded border border-slate-200 dark:border-slate-700">
        <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-slate-800 dark:text-slate-100">
          {t("report.technical.toggle")}
        </summary>
        <div className="space-y-3 px-3 pb-3 text-sm text-slate-700 dark:text-slate-200">
          <TechRow label={t("report.technical.walletType")} value={report.wallet_summary.wallet_type} />
          <TechRow
            label={t("report.technical.scriptType")}
            value={report.wallet_summary.script_type}
          />
          {report.network !== null && (
            <TechRow label={t("report.technical.network")} value={report.network} />
          )}
          {report.descriptors.receive !== null && (
            <div>
              <p className="font-medium text-slate-900 dark:text-slate-100">
                {t("report.technical.descriptor")}
              </p>
              <p className="mt-1 break-all font-mono text-xs">
                {report.descriptors.receive.canonical}
              </p>
            </div>
          )}
          <div>
            <p className="font-medium text-slate-900 dark:text-slate-100">
              {t("report.technical.checks")}
            </p>
            <ul className="mt-1 space-y-0.5">
              {report.checks.map((check) => (
                <li key={check.code} className="font-mono text-xs">
                  {check.code} [{check.result}] {check.title}
                </li>
              ))}
            </ul>
          </div>
          <TechRow label={t("report.technical.inputHash")} value={report.input_hash} mono />
        </div>
      </details>
      )}

      {/* §15.10 (9) Disclaimer */}
      <ReportSection title={t("report.sections.disclaimer")}>
        <p className="whitespace-pre-line text-sm text-slate-600 dark:text-slate-300">
          {report.disclaimer_short}
        </p>
      </ReportSection>

      {/* §15.10 (10) Lifeboat version + report hash */}
      <ReportSection title={t("report.sections.version")}>
        <dl className="space-y-1 text-sm text-slate-600 dark:text-slate-300">
          <div className="flex flex-wrap gap-2">
            <dt className="font-medium">{t("report.appVersionLabel")}</dt>
            <dd>{report.app_version}</dd>
          </div>
          <div className="flex flex-wrap gap-2">
            <dt className="font-medium">{t("report.reportHashLabel")}</dt>
            <dd className="break-all font-mono text-xs">{report.report_hash}</dd>
          </div>
        </dl>
      </ReportSection>

      {/* §15.8 — verbatim, on every report */}
      <section
        aria-label={t("report.cannotTellLabel")}
        className="rounded border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800"
      >
        <p className="whitespace-pre-line text-sm text-slate-700 dark:text-slate-200">
          {t("report.cannotTell")}
        </p>
      </section>
    </section>
  );
}
