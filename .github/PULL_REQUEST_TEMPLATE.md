## Summary

- 

## Story or PRD section

- 

## Checks run

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Frontend checks, if applicable

## Safety and privacy checklist

- [ ] No real seed words, passphrases, private keys, wallet backups, signer
      locations, or personal wallet metadata.
- [ ] No new network behavior, telemetry, analytics, or auto-update path.
- [ ] No new Tauri capability or CSP change unless required by the PRD/story.
- [ ] Confidential data is not logged or persisted by default.
- [ ] Report/runbook output remains deterministic.
- [ ] Commits are signed off with `git commit -s`.

## Review notes

Call out descriptor parser, sensitive-input detector, release, capability, or
CSP changes so CODEOWNERS review is visible.

