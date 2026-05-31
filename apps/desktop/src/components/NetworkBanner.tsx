import { useTranslation } from "react-i18next";

import type { WalletNetwork } from "../store/session";

/**
 * §22.4 network banner (NORMATIVE). A non-dismissible bar across the top of every
 * screen that handles wallet data, color-coded by network so the user can never
 * confuse which chain they are on: MAINNET red, TESTNET/SIGNET yellow, REGTEST
 * gray. It has no dismiss control by design, and because the color and label are
 * driven purely by the `network` prop it recolors the instant the network
 * changes (the §22.4 requirement) — no animation, no local state.
 *
 * The vocabulary mirrors the Rust core's `Network` serialization, where mainnet
 * serializes as "bitcoin"; this banner is the single place that maps it to the
 * MAINNET label and the red color.
 */

interface NetworkVisual {
  /** i18n key for the §22.4 uppercase label (MAINNET / TESTNET / …). */
  labelKey: string;
  /** Full literal Tailwind classes (background + text). Written out in full so
   *  Tailwind's content scanner keeps them — never build these dynamically.
   *  Text color is chosen per network for WCAG-AA contrast on its fill: white on
   *  the red/gray fills, dark on the amber (testnet/signet) fill. */
  classes: string;
}

const NETWORK_VISUALS: Record<WalletNetwork, NetworkVisual> = {
  bitcoin: { labelKey: "banners.network.mainnet", classes: "bg-network-mainnet text-white" },
  testnet: { labelKey: "banners.network.testnet", classes: "bg-network-testnet text-slate-900" },
  signet: { labelKey: "banners.network.signet", classes: "bg-network-signet text-slate-900" },
  regtest: { labelKey: "banners.network.regtest", classes: "bg-network-regtest text-white" },
};

export function NetworkBanner({ network }: { network: WalletNetwork }): JSX.Element {
  const { t } = useTranslation();
  const visual = NETWORK_VISUALS[network];
  return (
    // role="status" announces the change to assistive tech the instant the
    // network recolors; there is intentionally no dismiss control.
    <div
      role="status"
      className={`w-full px-4 py-1.5 text-center text-sm font-semibold uppercase tracking-wider ${visual.classes}`}
    >
      {t(visual.labelKey)}
    </div>
  );
}
