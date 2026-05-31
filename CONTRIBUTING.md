# Contributing

Bitcoin Lifeboat is built around one trust boundary: user recovery material must
stay local, private, and out of normal app inputs. Treat every contribution
through that lens.

## Before you start

- Read [`docs/PRD-v2.md`](docs/PRD-v2.md) for the canonical requirements.
- Check nearby `CLAUDE.md` files before changing a module.
- Use testnet, signet, or regtest data only. Do not add mainnet wallet fixtures.
- Do not include real descriptors, xpubs, fingerprints, addresses, seed words,
  passphrases, private keys, signer locations, or personal wallet metadata.

## Developer Certificate of Origin

This project uses the Developer Certificate of Origin, not a CLA. Sign every
commit:

```sh
git commit -s
```

The sign-off means you certify that you wrote the contribution or have the right
to submit it under the project license.

## Code style

- Keep Bitcoin logic in Rust core crates. The React frontend must not parse
  descriptors, derive addresses, detect secrets, score readiness, or do crypto.
- Use typed errors from `error-taxonomy`; do not invent ad hoc error strings.
- Keep confidential data out of logs and default persistence.
- Preserve deterministic report/runbook output.
- Do not add network behavior, telemetry, auto-update, analytics, or broader
  Tauri capabilities without a PRD-backed story.
- Avoid `unwrap()` and `panic!()` outside tests.

Run the core gate before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Frontend stories also run the checks documented in `apps/desktop/CLAUDE.md`.

## Review process

Pull requests should include:

- A short summary of the change.
- The story, issue, or PRD section it implements.
- The exact checks run locally.
- Screenshots or test notes for UI changes.
- Any security, privacy, or determinism impact.

Security-sensitive paths require two-maintainer review through `CODEOWNERS`.
Those paths include the descriptor parser, sensitive-input detector, release
pipeline, Tauri capabilities, and CSP.

## Anonymization checklist

Before committing fixtures, logs, screenshots, reports, or runbooks:

- Replace wallet data with fixed testnet/signet/regtest fixtures.
- Remove xpubs, descriptors, addresses, fingerprints, signer names, and signer
  locations unless the file is an intentional non-secret test fixture.
- Confirm no seed words, passphrases, private keys, wallet backup files, or
  secret shares are present.
- Prefer generated deterministic fixtures over copied user material.

## Community conduct

Be direct, technical, and respectful. Security reports belong in
[`SECURITY.md`](SECURITY.md), not public issues.

