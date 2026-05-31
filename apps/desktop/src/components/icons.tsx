import type { ReactNode } from "react";

/**
 * Small inline SVG icon set.
 *
 * Kept dependency-free (no icon package) and decorative: every icon is
 * `aria-hidden`, so the adjacent text carries the meaning. Icons stroke with
 * `currentColor`, so the caller controls color via a Tailwind `text-*` class.
 * Shared here because later screens reuse them (e.g. the §22.2 dashboard cards
 * and, going forward, the §22.3 status badges).
 */

interface IconProps {
  className?: string;
}

/** Common SVG chrome so each icon only declares its paths. */
function Icon({ className, children }: { className?: string; children: ReactNode }): JSX.Element {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={true}
    >
      {children}
    </svg>
  );
}

/** Open book — "Check My Backup Plan". */
export function BookIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M12 6c-1.6-1.2-3.6-2-6-2-1 0-2 .1-2.8.3v13C4 17.1 5 17 6 17c2.4 0 4.4.8 6 2" />
      <path d="M12 6c1.6-1.2 3.6-2 6-2 1 0 2 .1 2.8.3v13C20 17.1 19 17 18 17c-2.4 0-4.4.8-6 2" />
      <path d="M12 6v13" />
    </Icon>
  );
}

/** Shield — "Audit My Multisig Setup". */
export function ShieldIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M12 3l7 2.5v5.5c0 4.2-2.9 7.4-7 9-4.1-1.6-7-4.8-7-9V5.5z" />
    </Icon>
  );
}

/** Two figures — "Create a Family Drill / Heir Runbook". */
export function FamilyIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <circle cx="8.5" cy="8" r="2.6" />
      <circle cx="16.5" cy="9" r="2.1" />
      <path d="M3.5 19a5 5 0 0 1 10 0" />
      <path d="M14.5 19a4 4 0 0 1 6.5-3.1" />
    </Icon>
  );
}

/** Printer — "Print a Recovery Runbook". */
export function PrinterIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M7 9V4h10v5" />
      <path d="M7 17H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2" />
      <path d="M7 14h10v6H7z" />
    </Icon>
  );
}

/** Play triangle — "Practice Recovery Safely" (disabled in the MVP). */
export function PlayIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M8 5.5v13l11-6.5z" />
    </Icon>
  );
}

/** QR blocks — PSBT QR exchange. */
export function QrCodeIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M4 4h6v6H4z" />
      <path d="M14 4h6v6h-6z" />
      <path d="M4 14h6v6H4z" />
      <path d="M14 14h2v2h-2z" />
      <path d="M18 14h2v6h-2z" />
      <path d="M14 18h2v2h-2z" />
    </Icon>
  );
}

/** Camera — capture one QR frame. */
export function CameraIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M5 8h3l1.5-2h5L16 8h3a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z" />
      <circle cx="12" cy="13.5" r="3" />
    </Icon>
  );
}

/** Check mark in a circle — the Ready and Mostly Ready status badges (§22.3). */
export function CheckCircleIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8.4 12.4l2.4 2.4 4.8-5.4" />
    </Icon>
  );
}

/** Exclamation in a triangle — the safety banner (§22.6) and the Needs
 *  Attention status badge (§22.3). */
export function AlertTriangleIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <path d="M12 4.5l8 14.5H4z" />
      <path d="M12 10v4" />
      <path d="M12 17h.01" />
    </Icon>
  );
}

/** Cross in a circle — the Not Ready status badge (§22.3). */
export function XCircleIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.2 9.2l5.6 5.6" />
      <path d="M14.8 9.2l-5.6 5.6" />
    </Icon>
  );
}

/** Question mark in a circle — the Cannot Determine status badge (§22.3). */
export function HelpCircleIcon({ className }: IconProps): JSX.Element {
  return (
    <Icon className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.6 9.5a2.4 2.4 0 1 1 3.2 2.3c-.8.3-1.3.9-1.3 1.7v.4" />
      <path d="M12 17h.01" />
    </Icon>
  );
}
