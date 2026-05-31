# Staying safe

These are the safety rules behind everything Bitcoin Lifeboat does. Read them
once; they apply far beyond this app.

## Never enter your seed phrase online

Your seed phrase is the master backup of your coins. Anyone who learns it can
take everything. Never type it into a website, a browser extension, a chat, or an
app — including this one. A real recovery is done on an offline wallet or
hardware device, not on a web page.

## Why Lifeboat never asks for a seed

Bitcoin Lifeboat has no field for a seed phrase in any normal flow. It works
entirely from **public** wallet information, so there is nothing secret for it to
leak, log, or store. This is a deliberate design choice: a tool that never sees
your secret cannot lose it.

If you ever paste seed words or a private key by accident, the app detects the
shape of the secret, stops, clears the field, and warns you. It does not save or
display what you pasted. If this happens, assume the clipboard and screen may
have been exposed: move the funds to a freshly generated wallet whose seed has
never touched an online device.

## Public metadata vs. private secrets

- **Public**: addresses, xpubs, descriptors, fingerprints. These let software
  *find* your coins but not *spend* them.
- **Private**: seed phrases, passphrases, and private keys. These let someone
  *spend* your coins.

Lifeboat only ever handles the public side. Even so, public data deserves care.

## What public metadata can still reveal

An xpub or descriptor exposes your entire address history and balance to anyone
who holds it. It cannot move your coins, but it destroys your privacy. Keep
descriptors and xpubs as private as you reasonably can, and prefer the
**public-safe** export mode. See [What an xpub reveals](xpub).

## Store runbooks safely

A recovery runbook points at where your keys and backups live. Treat the
completed runbook like a spare key:

- Keep printed copies in separate, access-controlled places (a home safe, a bank
  box, a trusted relative).
- Never email it, photograph it to the cloud, or store it in plain text on an
  internet-connected computer.
- Write *where* things are kept, never *what* the secret is. The runbook
  templates give you labeled blank lines for exactly this.

## Rehearse with fake funds

The only way to know a plan works is to walk through it. From v0.2, Lifeboat lets
you rehearse a full recovery on **Signet**, a test network with worthless coins,
so a mistake costs nothing. Practice the steps your heirs would take, end to end.

## When the Readiness Check fails

A failing result is good news found early. Work through the prioritized "what to
do next" list in your report, fix one item at a time, and run the check again.
The aim is for your heirs to be able to rebuild the wallet without your help.

## Getting expert help without getting scammed

If you need a professional, be careful:

- No honest helper ever needs your seed phrase. A request for it is a scam, full
  stop.
- Prefer well-known, reviewed open-source wallets and established service
  providers over a stranger in a direct message.
- Be suspicious of anyone who contacts *you* first, especially "support" staff in
  social media replies.

## The "$5 wrench" attack

Software cannot defend against physical coercion — the so-called "$5 wrench
attack", where someone simply threatens you until you hand over your keys.
Lifeboat does not help here. Strategies like multisig with geographically
separate keys, decoy wallets, and discretion about your holdings are outside what
this tool can test.

## Verify your download is real

Before you trust any release, confirm it is the genuine one: check the published
signatures and hashes against the release page. The full step-by-step
verification guide is on the project website:
<https://bitcoinlifeboat.org/docs/>.
