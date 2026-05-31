# Security Policy

## Placeholder notice

**TODO: REPLACE BEFORE PUBLIC RELEASE — see docs/CONFIGURATION.md**

This repository still uses placeholder maintainer PGP values from
`project.config.toml`. Pre-alpha development can continue with placeholders, but
public non-alpha/beta releases are blocked until the fingerprint and public key
block are replaced.

## The four promises

1. **We never ask for your real seed phrase.** The app has no field for entering
   a real BIP39/SLIP-39 mnemonic in normal use.
2. **We never connect to the internet without your action.** No telemetry, no
   auto-update, no remote calls by default.
3. **We never persist your wallet metadata.** Imports stay in memory; you choose
   where to export.
4. **We never claim your funds are safe.** Reports are diagnostic aids, not
   guarantees of recovery.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from this repository's **Security**
tab. Open **Advisories**, then choose **Report a vulnerability**. Do not file
public issues, discussions, or pull requests for suspected vulnerabilities.

Do not include seed words, passphrases, private keys, wallet backup files, or
real wallet descriptors in a report. Use redacted examples or testnet/regtest
fixtures whenever possible.

Please include:

- The affected version, commit, or release artifact.
- The operating system and install method.
- Steps to reproduce using non-secret test data.
- Any relevant logs after removing descriptors, xpubs, addresses, fingerprints,
  names, locations, and other wallet metadata.

We aim to acknowledge new reports within 7 days and follow a 90-day coordinated
disclosure window. Pre-v1.0 has no bug bounty program. Public advisories will use
GitHub Security Advisories and the project website feed.

## Release verification key

- Fingerprint: `__MAINTAINER_PGP_FINGERPRINT__`
- Configured key block file: `__MAINTAINER_PGP_KEY_BLOCK__`
- Minisign public key: published in each GitHub Release before assets are
  uploaded. The release workflow refuses to publish without the
  `MINISIGN_PUBLIC_KEY` repository variable and matching `MINISIGN_PRIVATE_KEY`
  secret.

Current placeholder key block value:

```text
__MAINTAINER_PGP_KEY_BLOCK__
```

This is not a usable release verification key. Replace it with the configured
public key block before any public non-alpha/beta release.

## Security-sensitive changes

Two-maintainer review is required for pull requests touching the descriptor
parser, sensitive-input detector, release pipeline, Tauri capabilities, or CSP.
The concrete path rules live in [`CODEOWNERS`](CODEOWNERS).

Maintainer pushes must use signed Git commits once branch protection is enabled.
