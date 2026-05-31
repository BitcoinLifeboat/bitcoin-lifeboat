import ReadinessWizard from "./ReadinessWizard";

/** Multisig audit (the readiness wizard with multisig-first defaults; §22.11). */
export default function AuditMultisig(): JSX.Element {
  return (
    <ReadinessWizard defaultWalletType="multisig" titleKey="pages.auditMultisig.title" />
  );
}
