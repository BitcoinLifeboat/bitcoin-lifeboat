# Roadmap

The canonical product plan is [`docs/PRD-v2.md`](docs/PRD-v2.md). This roadmap is
the short public view of that plan.

## v0.1 MVP

- Rust core for descriptor audit, secret detection, readiness scoring, reports,
  runbooks, and CLI workflows.
- Locked-down Tauri desktop shell with onboarding, readiness check, export flows,
  bundled docs, and no default network activity.
- Documentation site, governance files, CI, security checks, release workflow,
  and the v0.1 acceptance gate.

## v0.2 Signet drill engine

- Disposable Signet/regtest practice wallets.
- PSBT v0/v2 lifecycle.
- Guarded Practice Mode with documented test mnemonic only.
- Drill records and questionnaire-based disaster drills.

## v0.3 and v0.4 hardware-wallet drills

- File and QR PSBT exchange.
- Signing disaster drills.
- Optional out-of-process HWI sidecar for USB devices with fingerprint checks.

## v0.5 multisig and Liana depth

- Multisig survivability simulation.
- Missing-signer drills.
- Miniscript policy visualization.
- Liana timelock recovery-path countdowns.

## v0.6 to v1.0 recovery-day release

- Interactive heir mode.
- Community translation workflow.
- Reproducible builds.
- Security-audit gate.
- Public Bitcoin Recovery Day launch.

