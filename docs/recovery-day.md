# Bitcoin Recovery Day

Bitcoin Recovery Day is a community practice day for self-custody users. The
goal is to rehearse recovery before an emergency, using descriptors, test
wallets, public-safe reports, and printed runbooks.

Once a year, run a recovery drill.

The kit below is meant for meetups, educators, and families. It keeps the event
local-first: no seed phrase collection, no central upload of wallet files, and no
real-funds live recovery.

## Launch Kit

- [Workshop slide deck](recovery-day-workshop-slide-deck.md) gives facilitators a
  12-slide outline for a 60- to 90-minute session.
- [Meetup organizer guide](recovery-day-organizer-guide.md) covers room setup,
  privacy boundaries, volunteer roles, and incident handling.
- [Live demo descriptors](recovery-day-live-demo-descriptors.md) provides
  testnet-only descriptors and addresses for public demonstrations.
- [Heir drill packet template](recovery-day-heir-drill-packet-template.md) gives
  owners a printable outline for a practice packet that contains only test-wallet
  material.
- [Press kit](recovery-day-press-kit.md) includes short descriptions, event copy,
  and official-link guidance.

The public site publishes these pages through the configured docs host in
`project.config.toml`. Stable public launch is still blocked by
`scripts/verify-release-gates.sh` until the audit sign-off exists and every
configured placeholder token has been replaced.

## Participant Checklist

Before the event:

- Install Bitcoin Lifeboat from the official release channel.
- Bring a watch-only descriptor or a supported wallet export.
- Bring a known receive address for address comparison.
- Do not bring seed words into shared rooms, chat, email, or support forms.
- Use test wallets or fake funds for live demonstrations.

During the event:

- Run a Readiness Check.
- Export a public-safe report.
- Generate or review a recovery runbook.
- Write down gaps to fix later at home.
- Do not photograph other participants' wallet metadata.

After the event:

- Re-export descriptors if the report says metadata is missing.
- Print updated runbooks if needed.
- Store reports and runbooks according to their privacy level.
- Schedule the next drill.

## Organizer Checklist

- Prepare a local-only setup. Do not require participants to upload wallet files.
- Use sample descriptors for demos.
- Make clear that real seed phrases are not part of the event.
- Keep a quiet area for private work.
- Have printed explanations of descriptors, xpubs, and public-safe exports.
- Have a plan for participants who discover a serious recovery gap.

## What Facilitators Should Not Do

- Do not ask to see seed phrases.
- Do not ask for passphrases.
- Do not collect wallet exports centrally.
- Do not promise that a passing report means a real emergency will go smoothly.
- Do not recommend moving funds during a public workshop.

## Public Materials

Use these docs as the base handouts:

- [Safety model](safety-model.md)
- [Descriptor audit](descriptor-audit.md)
- [Wallet compatibility](wallet-compatibility.md)
- [Scoring](scoring.md)
- [Heir mode](heir-mode.md)
- [Download and verify signatures](download-verify-signature.md)

Community translations should preserve the seed-handling warning and the "not a
wallet" language.
