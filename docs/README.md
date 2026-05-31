# Bitcoin Lifeboat Documentation

Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase
manager, not an inheritance legal service, and not a recovery company. It is a
free, open-source diagnostic tool that helps you test whether your recovery
plan works.

The first rule is simple: Bitcoin Lifeboat does not need your real seed phrase.
Never type real recovery words into Bitcoin Lifeboat, a website, chat, email, or
support form. Lifeboat works with watch-only wallet metadata such as output
descriptors, xpubs, fingerprints, and known receive addresses.

## Start Here

- [Safety model](safety-model.md) explains what Lifeboat accepts, what it
  rejects, and what to do if you accidentally paste secret material.
- [Mission](mission.md) explains what Lifeboat is, what it is not, and the four
  public promises.
- [User guide](user-guide.md) walks through the readiness check and runbook flow.
- [Download and verify signatures](download-verify-signature.md) explains how to
  check release artifacts before running them.
- [Wallet compatibility](wallet-compatibility.md) explains how supported wallets
  export the metadata Lifeboat needs.
- [Descriptor audit](descriptor-audit.md) explains output descriptors, xpubs,
  checksums, and address matching.
- [Scoring](scoring.md) explains the readiness checks and score weights.
- [Heir mode](heir-mode.md) explains owner-created runbooks for family,
  executors, and trusted helpers.
- [Practice seeds](practice-seeds.md) lists the documented test mnemonic accepted
  by Practice Mode.
- [PSBT drills](psbt-drills.md) explains PSBT inspection, validation, and drill
  records.
- [Hardware Wallet Drill](hardware-wallet-drill.md) explains file, QR, and HWI
  signing rehearsals plus the manual device matrix.
- [Signet practice](signet-practice.md) explains the network boundary for
  opt-in Signet drills.
- [Multisig and Liana drills](multisig-liana-drills.md) explains survivability
  drills, missing-signer rehearsals, Liana policy trees, countdowns, and the
  timelock runbook.
- [Bitcoin Recovery Day](recovery-day.md) links the launch kit: workshop deck,
  organizer guide, demo descriptors, heir packet template, and press kit.

## Reference Docs

- [Architecture](architecture.md)
- [Developer guide](developer-guide.md)
- [CLI reference](cli-reference.md)
- [JSON schemas](json-schemas.md)
- [Error codes](error-codes.md)
- [Threat model](threat-model.md)
- [Reproducible builds](reproducible-builds.md)
- [Security audit](security-audit.md)
- [v0.1 MVP acceptance verification](acceptance-v0.1.md)
- [Configuration](CONFIGURATION.md)

The canonical product specification remains [PRD-v2.md](PRD-v2.md). The shorter
documents in this directory are the shipped user, safety, and developer docs.

## Versioning

Docs are versioned with releases. The desktop app embeds a subset for offline
reading, and the docs site publishes the same Markdown files with release
history. Do not fetch docs at runtime from inside the app.
