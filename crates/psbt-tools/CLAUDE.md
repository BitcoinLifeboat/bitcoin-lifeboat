# psbt-tools

Root-workspace PSBT helpers for the `lifeboat` CLI. This crate must stay on the
root Rust 1.78 toolchain and must not depend on BDK.

Use this crate for file-level PSBT operations that need no wallet state:

- import BIP174 v0 base64
- import BIP370 v2 base64 through the local raw-map adapter
- inspect input/output counts, lifecycle, UTXO presence, fee data, and outputs
- extract transaction hex only when every input is finalized

Do not move practice-wallet create/sign/finalize logic here. That belongs in the
detached `crates/psbt-drill` workspace with `signet-lab` and Rust 1.85.

The BIP370 adapter mirrors the `psbt-drill` raw-map approach because
rust-bitcoin rejects v2 on normal decode and plain `Psbt::serialize()` writes a
v0-style map. Keep v2 import/export covered by `fixtures/psbt/bip370_updated_v2.txt`.
