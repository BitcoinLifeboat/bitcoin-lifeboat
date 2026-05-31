# Multisig and Liana Drills

Lifeboat can rehearse advanced recovery setups without becoming a wallet
coordinator. The drill screens use watch-only descriptors, public signer
metadata, fake-fund practice wallets, and local runbook generation. They do not
ask for seed words, passphrases, private keys, or signer locations.

## Multisig Survivability

The multisig drill checks what happens when one signer is unavailable, two
signers are unavailable, or the descriptor backup is missing. For a 2-of-3 or
3-of-5 setup, Lifeboat reports which scenarios still meet the signing threshold
and which ones require missing material.

The drill result is a public summary. It records the template, outcome, required
material categories, and a signed local record. It does not store descriptors,
xpubs, addresses, PSBTs, transaction hex, signer locations, or seed material.

## Missing-Signer Rehearsal

The missing-signer drill lets you choose a signer index and rehearse the plan
with that signer removed. Lifeboat tells you which signer numbers remain, how
many signatures are still required, and which records an heir or operator must
find before attempting recovery.

Use this drill after replacing a device, changing where backups are stored, or
updating who can help with recovery.

## Liana Recovery Tree

For Liana-style timelock descriptors, Lifeboat renders a redacted policy tree.
The tree names the primary path and any timelocked recovery paths, but it does
not print descriptors, xpubs, fingerprints, addresses, or key material.

When you enter a current block height, Lifeboat also computes when block-height
recovery paths become active. Relative locks such as `older(65535)` are shown in
blocks and approximate days. Absolute locks such as `after(900000)` are shown as
the target block and remaining blocks.

Lifeboat does not look up the current block height for you. Type it from a
source you trust, then write the value in the printed runbook during a drill.

## Liana Timelock Runbook

The `liana-timelock` runbook template is for inheritance-style Liana setups. It
covers:

- The normal owner path.
- The timelocked recovery path.
- How to check whether the recovery path is active.
- Blank fields for primary-path and recovery-path materials.
- Blank fields for trusted helpers, reviewers, block height, and next drill date.

Public-safe mode hides the descriptor. Private mode includes the full descriptor
and should be stored with the same care as the rest of the recovery package.

## Boundaries

These drills do not coordinate mainnet spending. Mainnet PSBT support is
file-only validation. Lifeboat never broadcasts on mainnet, never contacts a
wallet service automatically, and never promises that a recovery will work.

If a result surprises you, stop and confirm it with your wallet software,
hardware signers, and a trusted offline expert before moving funds.
