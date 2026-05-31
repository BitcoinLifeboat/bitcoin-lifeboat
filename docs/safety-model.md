# Safety Model

Bitcoin Lifeboat is built around a hard boundary: it uses watch-only metadata
and refuses secret material.

## What Lifeboat Accepts

Lifeboat can use:

- Output descriptors.
- Extended public keys such as xpub, ypub, zpub, tpub, upub, and vpub.
- Master fingerprints and derivation paths.
- Known receive addresses used for comparison.
- Wallet export files from supported coordinators.
- Public preferences such as theme and language.

These items can still reveal wallet history or structure. Lifeboat treats
descriptors, xpubs, fingerprints, paths, derived addresses, labels, and signer
location notes as Confidential data. Public-safe exports redact them by default.

## What Lifeboat Rejects

Do not enter:

- BIP39 seed phrases.
- SLIP-39 shares.
- codex32 secrets.
- WIF private keys.
- xprv, yprv, zprv, tprv, uprv, or vprv keys.
- Passphrase values.
- Raw private-key hex.

The sensitive-input detector runs before import, parse, export parsing, CLI
processing, and desktop command processing. When it detects a real secret shape,
the input is refused and the secret content is not returned in the report.

## If You Accidentally Paste a Real Secret

1. Stop using that field immediately.
2. Let Lifeboat clear the input if the block dialog appears.
3. Close and restart Lifeboat if you are concerned about webview memory.
4. If the computer, clipboard manager, screen recorder, or app build is not
   trusted, treat the secret as exposed to that environment.
5. Use your wallet software or hardware wallet process to move to a new backup
   setup if you decide rotation is needed. Do not rely on Lifeboat for that move.
6. Re-export a watch-only descriptor or wallet export, then run the check again.

For high-value wallets, get help from someone you already trust offline. Do not
share seed words with anyone who contacts you first.

## Data Classes

| Class | Examples | Default treatment |
| --- | --- | --- |
| Public | Wallet type label, script type, app version | May appear in logs and public docs |
| Confidential | Descriptor, xpub, fingerprint, derived address, label | Never logged, held only as needed, redacted in public-safe export |
| Secret | Seed phrase, private key, passphrase, SLIP-39 share | Rejected before processing |

Public-safe is the default export mode. Private export is available only after an
explicit confirmation because xpubs can reveal past and future addresses.

## Local-First Defaults

The MVP makes no automatic network calls. It has no telemetry, no analytics, no
crash-report upload, and no auto-updater. External help links open in the
operating-system browser after Rust checks the allowlist.

Reports and runbooks are exported only when you choose a destination. Descriptor
inputs are not persisted by default. Diagnostic logs are off by default and must
not include Confidential or Secret data.

## What Lifeboat Cannot Cover

Lifeboat cannot verify the physical location of hardware wallets, backup cards,
paper copies, or legal documents. It cannot protect you from coercion, social
engineering, a malicious operating system, or a compromised release artifact.

Use full-disk encryption for machines that handle sensitive wallet metadata.
Verify release signatures when available, and download releases only from the
official project channels listed by the project maintainers.

