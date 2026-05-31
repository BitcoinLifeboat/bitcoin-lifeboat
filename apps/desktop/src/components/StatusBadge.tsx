import { useTranslation } from "react-i18next";

import { AlertTriangleIcon, CheckCircleIcon, HelpCircleIcon, XCircleIcon } from "./icons";

/**
 * §22.3 readiness status. Each of the five badges conveys status three ways at
 * once — text label, icon shape, and color — so status is never communicated by
 * color alone (§22.3 / accessibility). The status colors are the
 * WCAG-AA-verified (4.5:1 on white) tokens from tailwind.config.js, so the badge
 * keeps a white background in both light and dark mode to preserve that verified
 * contrast.
 *
 * The status discriminants match the Rust core's `ReadinessStatus` serialization
 * (snake_case), so the report viewer (US-050) can pass `report.score.status`
 * straight through.
 */
export type ReadinessStatus =
  | "ready"
  | "mostly_ready"
  | "needs_attention"
  | "not_ready"
  | "cannot_determine";

type BadgeIcon = (props: { className?: string }) => JSX.Element;

interface BadgeVisual {
  labelKey: string;
  /** Full literal Tailwind classes (border + text); written out so Tailwind's
   *  content scanner keeps them — never build these dynamically. */
  classes: string;
  Icon: BadgeIcon;
}

const STATUS_VISUALS: Record<ReadinessStatus, BadgeVisual> = {
  ready: {
    labelKey: "status.ready",
    classes: "border-status-ready text-status-ready",
    Icon: CheckCircleIcon,
  },
  mostly_ready: {
    labelKey: "status.mostlyReady",
    classes: "border-status-mostly-ready text-status-mostly-ready",
    Icon: CheckCircleIcon,
  },
  needs_attention: {
    labelKey: "status.needsAttention",
    classes: "border-status-needs-attention text-status-needs-attention",
    Icon: AlertTriangleIcon,
  },
  not_ready: {
    labelKey: "status.notReady",
    classes: "border-status-not-ready text-status-not-ready",
    Icon: XCircleIcon,
  },
  cannot_determine: {
    labelKey: "status.cannotDetermine",
    classes: "border-status-cannot-determine text-status-cannot-determine",
    Icon: HelpCircleIcon,
  },
};

export function StatusBadge({ status }: { status: ReadinessStatus }): JSX.Element {
  const { t } = useTranslation();
  const visual = STATUS_VISUALS[status];
  const Icon = visual.Icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border bg-white px-2.5 py-1 text-sm font-medium ${visual.classes}`}
    >
      <Icon className="h-4 w-4" />
      {t(visual.labelKey)}
    </span>
  );
}
