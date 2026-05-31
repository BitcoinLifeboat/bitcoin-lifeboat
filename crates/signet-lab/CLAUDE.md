# signet-lab — notes for future iterations

`signet-lab` is a detached workspace because `bdk_wallet 3.0.0` requires Rust
1.85.0 while the core workspace remains pinned to Rust 1.78.0. Run its Rust
commands from `crates/signet-lab`, not from the repo root:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

This crate is the only approved home for the `bdk_wallet` dependency. Do not add
BDK to `lifeboat-core` or the core audit/reporting crates.

`psbt-drill` is the paired detached drill crate that may also use the BDK wallet
stack. It should borrow the in-memory wallet through `DisposableWallet::wallet`
/ `wallet_mut` and keep this crate's no-persistence/no-logging guarantees.

Wallets are created with `Wallet::create(...).network(...).create_wallet_no_persist()`.
That keeps practice wallets in memory; no descriptor, xprv, address index, or
chain state is persisted by this layer.

Regtest node work lives in `src/regtest.rs`. Keep the two-step safety boundary:
cache `bitcoind` through `BitcoindCache::ensure_bitcoind` only with
`DownloadApproval::ExplicitUserRequest`, then launch it with
`RegtestConfig::bitcoind_args()` so RPC stays on `127.0.0.1` and peer discovery,
listening, DNS seeds, fixed seeds, UPnP, NAT-PMP, and automatic outbound peers
stay disabled. Do not add a Rust TLS/HTTP client casually here: `ureq`'s current
TLS tree raised the crate past Rust 1.85 during US-068, so the production
downloader uses a user-triggered system `curl` subprocess instead.
