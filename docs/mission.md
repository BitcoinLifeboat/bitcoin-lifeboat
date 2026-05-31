# Mission

Bitcoin Lifeboat is a local-first diagnostic, rehearsal, and education tool for Bitcoin recovery readiness.

It helps you test whether the recovery materials you already have are complete for the scenarios Lifeboat can check: descriptors, xpubs, fingerprints, derivation paths, known receive addresses, reports, runbooks, and drills with test funds.

Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase manager, not an inheritance legal service, and not a recovery company. It is a free, open-source diagnostic tool that helps you test whether your recovery plan works.

## The Four Promises

1. We never ask for your real seed phrase.
2. We never connect to the internet without your action.
3. We never persist your wallet metadata.
4. We never claim your funds are safe.

These promises are implementation rules, not slogans. They affect the app design, CLI behavior, exports, docs, tests, and release gates.

## What Lifeboat Checks

Lifeboat checks whether wallet metadata parses, whether descriptors include the information needed for recovery, whether derived addresses match an address you recognize, and whether reports and runbooks can be exported without exposing more than you chose to include.

It does not prove that a backup card exists, that a hardware wallet powers on, that a legal document is valid, or that a person can complete a recovery under stress. Those require drills, in-person checks, and trusted offline help.

## Who It Is For

Lifeboat is for self-custody users who want to rehearse before a failure. That includes singlesig users, multisig coordinators, families writing heir instructions, and developers who need deterministic tooling for wallet metadata.

Start with the [safety model](safety-model.md), then follow the [user guide](user-guide.md).
