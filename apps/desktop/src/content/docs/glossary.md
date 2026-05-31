# Glossary

Plain-English definitions of the words Bitcoin Lifeboat uses. Terms are listed
alphabetically.

**Address** — A short string of letters and numbers that someone sends bitcoin
to. A wallet makes a new one for almost every payment.

**Change address** — When you spend part of a coin, the leftover comes back to a
fresh address your wallet controls, called a change address. A recovery plan
that ignores change can miss part of your balance.

**Checksum** — An 8-character code at the end of a descriptor. It does not add
security; it catches typos. If one character is wrong, the descriptor will not
load, which warns you that something was copied incorrectly.

**Cosigner** — In a multisig wallet, one of the several keys that together
control the coins. Each cosigner is usually a separate device or person.

**Derivation path** — The route from your master key to a specific key, written
like `84h/0h/0h`. Different wallet types use different standard paths.

**Descriptor** — The recipe that tells software how your wallet turns keys into
addresses. See [What a descriptor is](descriptors).

**Fingerprint** — A short 8-character label for a master key, used to tell keys
apart. It is not secret on its own.

**Hardware wallet** — A small dedicated device that stores keys and signs
transactions without exposing the keys to your computer.

**Miniscript** — A structured way to write more advanced spending rules (for
example, "two of these three keys, or one key after a year") that software can
analyze.

**Multisig** — Short for multi-signature. A wallet that needs several keys to
approve a spend, such as "2 of 3". It removes any single point of failure but
adds setup you must record carefully.

**Output descriptor** — Another name for a descriptor.

**Passphrase** — An extra word or phrase added on top of a seed phrase (sometimes
called the "25th word"). If you use one and do not record that it exists, an heir
with the seed phrase still cannot rebuild the wallet.

**PSBT** — Partially Signed Bitcoin Transaction. A standard file format for a
transaction that is being passed between devices to collect signatures. Used in
the drill features from v0.2 onward.

**Public-safe** — The default export mode. It hides full xpubs and shows only one
sample address, so a document can be shared without leaking your history.

**Readiness Check** — Lifeboat's main feature: it reads your wallet's public
description and reports whether the recovery plan looks complete.

**Runbook** — A printable, step-by-step recovery guide for you or your heirs,
with blanks you fill in by hand.

**Seed phrase** — The list of 12 or 24 words that backs up a wallet's keys. It is
the most sensitive secret you own. **Never type it into any website or app**,
including this one. See [Staying safe](safety).

**Signet** — A test network that behaves like Bitcoin but uses worthless coins.
It lets you rehearse a recovery for real without risking funds. Used from v0.2.

**Single-signature** — A wallet controlled by one key. Simpler than multisig, but
that one key is a single point of failure.

**Watch-only** — A copy of a wallet that can see addresses and balances but holds
no private keys, so it cannot spend. Exporting watch-only data is how you share a
wallet's shape with Lifeboat without sharing secrets.

**xpub** — Extended public key. Public, but sensitive: it exposes your whole
address history. See [What an xpub reveals](xpub).
