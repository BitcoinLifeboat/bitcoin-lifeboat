# User Guide

This guide covers the MVP recovery-readiness flow: import watch-only wallet metadata, run checks, read the report, and export a runbook.

## Before You Start

Do not enter real seed words, SLIP-39 shares, passphrases, xprv keys, WIF keys, or raw private keys. Lifeboat needs watch-only metadata such as descriptors, xpubs, fingerprints, derivation paths, and a known receive address.

If you are not sure what a field expects, stop and read the [safety model](safety-model.md).

## Run A Readiness Check

1. Export a descriptor or wallet metadata file from your wallet coordinator. See [wallet compatibility](wallet-compatibility.md) for supported paths.
2. Open the Readiness Check flow.
3. Paste the descriptor or import the supported file.
4. Add a known receive address if you have one. Lifeboat derives addresses from the descriptor and checks whether one matches.
5. Answer the backup and runbook questions honestly. Unknown is better than guessing.
6. Review the report status, failures, warnings, missing information, and next steps.
7. Export the report in public-safe mode unless you intentionally need a private export.

Public-safe exports redact descriptor and xpub details by default. Private exports require confirmation because xpubs can reveal wallet history.

## Create A Recovery Runbook

1. Choose the runbook template that matches the wallet setup.
2. Optionally provide a descriptor so Lifeboat can fill in the wallet summary and signer table.
3. Keep locations, seed storage details, passphrase hints, and contact instructions as blanks to fill in by hand after printing.
4. Export the runbook as PDF or Markdown.
5. Store printed copies where your recovery plan says they belong.

Do not store a runbook beside every signer, backup, or device unless that is part of your threat model. A runbook can reveal enough structure to make a theft or coercion attempt easier.

## What To Do If A Check Fails

Read the failed checks first. Critical failures mean Lifeboat could not confirm the tested scenario from the information provided.

Common fixes include exporting the full descriptor again, adding the change descriptor, documenting the wallet software and derivation path, matching a known receive address, or creating a printed recovery runbook.

Do not move funds based only on a report. If a result surprises you, use your wallet software, hardware signer, or a trusted offline expert to confirm the next step.

## Run It Again

Run the check after wallet changes, signer replacement, descriptor export changes, new heir instructions, or a recovery drill. Even without changes, review the plan at least once a year.

For multisig and Liana setups, use the deep-drill flows after the basic readiness check. Survivability drills test missing-signer scenarios. The Liana view shows the primary path, timelocked recovery paths, and optional block-height countdowns for a current height you enter by hand.
