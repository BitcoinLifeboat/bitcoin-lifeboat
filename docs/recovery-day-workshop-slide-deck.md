# Recovery Day Workshop Slide Deck

This deck is a presenter outline. It is written for a 60- to 90-minute meetup
where participants run Lifeboat on their own machines and keep wallet metadata
under their own control.

## Slide 1: Bitcoin Recovery Day

Once a year, run a recovery drill.

Today's goal is practice, not emergency recovery. Participants check whether they
can find the wallet metadata, devices, addresses, and runbooks needed for a real
recovery.

## Slide 2: What Lifeboat Is

Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase
manager, not an inheritance legal service, and not a recovery company. It is a
free, open-source diagnostic tool that helps you test whether your recovery plan
works.

## Slide 3: What Not To Bring

Do not bring seed words, passphrases, private keys, wallet passwords, or a live
emergency into the room.

Bring watch-only metadata when you already know how to export it. If you do not,
use the sample descriptors in the live demo page.

## Slide 4: The Recovery Plan Surface

A real plan is more than seed words. It includes wallet type, descriptors, known
receive addresses, signer locations, passphrase instructions, software notes,
and someone who can follow the steps.

## Slide 5: Descriptors In Plain English

A descriptor tells wallet software how to find addresses for a wallet. It is not
a seed phrase, but it can reveal wallet structure and xpubs, so participants
should treat their own descriptor as private.

## Slide 6: Demo Path

Use the sample descriptors. Run a Readiness Check, compare a known address,
export a public-safe report, and open the runbook template.

No one should type or display real wallet material during the demo.

## Slide 7: Reading The Result

The result is a diagnosis. It can show missing metadata, unclear wallet type,
checksum problems, address mismatches, incomplete backups, and drill gaps.

A passing result is not a promise about a future emergency.

## Slide 8: Fixing Gaps

Write down each gap. Fix it later in private. Common next steps include
re-exporting a descriptor, printing a runbook, labeling devices, separating
backup locations, and running a practice PSBT flow.

## Slide 9: Multisig And Liana

Multisig users should rehearse missing-signer cases. Liana users should check
the recovery tree and timelock countdown with a current block height they enter
by hand.

## Slide 10: Family And Heirs

Heirs need plain instructions, not jargon. Owners can generate practice packets
with disposable test-wallet material and ask heirs to complete the walkthrough
without using the owner's real wallet.

## Slide 11: Verifying The App

Download from the official release channel and verify the signed checksums before
running an installer. The release page publishes `SHA256SUMS`,
`SHA256SUMS.minisig`, cosign bundles, and verification instructions.

## Slide 12: Annual Habit

Pick a date, run the drill, update the runbook, and schedule the next one.

Recovery Day works best when participants leave with a short private action list
instead of a public confession about their wallet setup.
