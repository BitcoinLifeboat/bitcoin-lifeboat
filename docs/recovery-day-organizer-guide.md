# Recovery Day Meetup Organizer Guide

This guide is for hosts running a Bitcoin Recovery Day workshop in a meetup room,
office, library, or family setting. Keep the event focused on practice with
watch-only metadata and test wallets.

## Event Shape

Recommended format:

- 10 minutes: safety boundary and "not a wallet" explanation.
- 15 minutes: descriptor and runbook overview.
- 20 minutes: public demo using sample descriptors.
- 30 minutes: quiet participant work.
- 15 minutes: private action-list writing and next-drill scheduling.

For a shorter session, skip the participant work block and run only the public
demo.

## Room Setup

- Use a room where people can sit with laptop screens away from the main camera.
- Keep projector demos on sample descriptors only.
- Provide printed copies of the [Safety model](safety-model.md), [Download and
  verify signatures](download-verify-signature.md), and [Live demo descriptors](recovery-day-live-demo-descriptors.md).
- Tell participants before the event not to bring seed words or passphrases.
- If the venue records talks, stop recording before any participant work starts.

## Roles

- Lead facilitator: runs the deck and demo.
- Privacy monitor: watches for accidental screen sharing or photography of wallet
  metadata.
- Help desk volunteer: answers app questions without taking custody of files.
- Exit-path volunteer: helps participants pause if they discover a serious
  recovery gap.

No volunteer should ask to see seed words, passphrases, private keys, or a live
wallet balance.

## Demo Script

1. Open the public launch site from the configured docs domain.
2. Show the download-verification page before opening the app.
3. Open the sample singlesig descriptor from the live demo page.
4. Run the Readiness Check and compare the known address.
5. Export a public-safe report.
6. Open a runbook template and point out the blank fields.
7. Repeat with the 2-of-3 multisig sample if time allows.

Use the sample descriptor page for every public projection. Do not ask a
participant to put their own descriptor on the projector.

## Participant Work Block

Ask participants to work quietly through these questions:

- Can I find my watch-only wallet export?
- Can I identify the wallet type and signer count?
- Can I compare at least one known receive address?
- Do I have a printed runbook?
- Does someone else know where the runbook is?
- What one thing should I fix this week?

The action list belongs to the participant. Do not collect it.

## If Someone Pastes A Real Secret

1. Stop the exercise for that person.
2. Ask them to close the app and preserve no screenshots.
3. Point them to [Safety model](safety-model.md#what-to-do-after-accidental-secret-entry).
4. Do not copy, photograph, or troubleshoot the secret in public.
5. Encourage them to get private help from a trusted expert before making any
   wallet move.

## After The Meetup

- Share links to the launch kit and download-verification page.
- Ask participants to schedule their next drill.
- Record only aggregate feedback, such as "people wanted more wallet-export
  instructions." Do not record wallet types tied to names.
- Update the local meetup notes with any wording that confused participants.
