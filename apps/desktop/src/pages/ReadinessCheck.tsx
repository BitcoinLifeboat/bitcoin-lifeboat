import ReadinessWizard from "./ReadinessWizard";

/**
 * Readiness Check screen (§22.8). Renders the 8-step wizard with a
 * single-signature-first default. The §22.11 Audit Multisig screen (US-053)
 * renders the same <ReadinessWizard> with a multisig default.
 */
export default function ReadinessCheck(): JSX.Element {
  return <ReadinessWizard defaultWalletType="singlesig" />;
}
