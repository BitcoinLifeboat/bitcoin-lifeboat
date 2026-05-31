import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";

import { PageScaffold } from "./PageScaffold";
import { BookIcon, FamilyIcon, PlayIcon, PrinterIcon, ShieldIcon } from "../components/icons";

type CardIcon = (props: { className?: string }) => JSX.Element;

interface DashboardCard {
  id: string;
  /** Route for an active card; `null` marks a not-yet-available (disabled) card. */
  to: string | null;
  icon: CardIcon;
  /** i18n key prefix: `${base}.title`, `.description`, `.time`, `.materials`. */
  base: string;
}

// §22.2 plus the v0.4 hardware drill card. Practice Mode remains the only route
// with a BIP39 seed field.
const CARDS: DashboardCard[] = [
  {
    id: "check-backup",
    to: "/readiness-check",
    icon: BookIcon,
    base: "pages.home.cards.checkBackup",
  },
  {
    id: "audit-multisig",
    to: "/audit-multisig",
    icon: ShieldIcon,
    base: "pages.home.cards.auditMultisig",
  },
  {
    id: "heir-runbook",
    to: "/heir-runbook",
    icon: FamilyIcon,
    base: "pages.home.cards.heirRunbook",
  },
  {
    id: "heir-walkthrough",
    to: "/heir-walkthrough",
    icon: FamilyIcon,
    base: "pages.home.cards.heirWalkthrough",
  },
  {
    id: "print-runbook",
    to: "/generate-runbook",
    icon: PrinterIcon,
    base: "pages.home.cards.printRunbook",
  },
  {
    id: "hardware-wallet-drill",
    to: "/hardware-wallet-drill",
    icon: ShieldIcon,
    base: "pages.home.cards.hardwareWalletDrill",
  },
  { id: "practice", to: "/practice-mode", icon: PlayIcon, base: "pages.home.cards.practice" },
];

const cardBase =
  "flex h-full flex-col rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800";
const activeCard =
  cardBase +
  " transition hover:border-brand hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-brand";
const disabledCard = cardBase + " opacity-70";

/** Shared card content: icon, title, one-sentence description, and the §22.2
 *  time + required-materials hints. */
function CardContent({ card }: { card: DashboardCard }): JSX.Element {
  const { t } = useTranslation();
  const CardIconComponent = card.icon;
  return (
    <>
      <span className="inline-flex h-11 w-11 items-center justify-center rounded-lg bg-brand/10 text-brand">
        <CardIconComponent className="h-6 w-6" />
      </span>
      <h2 className="mt-3 text-lg font-semibold text-slate-900 dark:text-slate-100">
        {t(`${card.base}.title`)}
      </h2>
      <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
        {t(`${card.base}.description`)}
      </p>
      <div className="mt-3 space-y-0.5 text-xs text-slate-500 dark:text-slate-400">
        <p>{t(`${card.base}.time`)}</p>
        <p>{t(`${card.base}.materials`)}</p>
      </div>
    </>
  );
}

/**
 * Home dashboard (§22.2 Screen 5). Renders the task cards in their expected
 * order; each active card navigates into its flow. No Bitcoin logic runs here — cards
 * are pure navigation.
 */
export default function Home(): JSX.Element {
  return (
    <PageScaffold titleKey="pages.home.title" bodyKey="pages.home.body">
      <ul className="mt-6 grid gap-4 sm:grid-cols-2">
        {CARDS.map((card) => (
          <li key={card.id}>
            {card.to === null ? (
              <div className={disabledCard} aria-disabled={true}>
                <CardContent card={card} />
              </div>
            ) : (
              <Link to={card.to} className={activeCard}>
                <CardContent card={card} />
              </Link>
            )}
          </li>
        ))}
      </ul>
    </PageScaffold>
  );
}
