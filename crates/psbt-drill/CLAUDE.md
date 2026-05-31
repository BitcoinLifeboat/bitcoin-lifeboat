# psbt-drill — notes for future iterations

`psbt-drill` is a detached Rust 1.85 workspace because it uses the same
`bdk_wallet 3.0.0` stack as `signet-lab`. Run its gate from this directory:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

Keep PSBT v0 lifecycle logic here: create/import/inspect/sign/finalize. The root
core workspace remains Rust 1.78 and must not grow a BDK dependency.

Use `signet_lab::DisposableWallet` for practice-wallet operations. Test funding
should apply an in-memory BDK update with synthetic regtest transactions; do not
spawn bitcoind or make faucet/network calls in unit tests.

US-071 promotes that funding pattern into `apply_local_funding_update` plus
`start_receive_send_drill` / `run_receive_send_drill`. These helpers support both
regtest and Signet address/PSBT flows. The Signet faucet URL is instruction-only
for the UI to open through the external browser command.

US-072 adds the separately gated Signet broadcast path. Keep it Signet-only by
type: `SignetBroadcastInput` accepts `PracticeDrillNetwork` and
`SignetBroadcastEndpoint`, whose variants are only public Signet Esplora hosts
(`mutinynet` / `sprovoost`). Mainnet broadcast is impossible because there is no
mainnet network or endpoint variant. Production broadcast uses
`SystemCurlBroadcaster` (`curl --data-binary @-` to Esplora `POST /tx`) to avoid a
Rust TLS dependency; unit tests must inject a fake `SignetBroadcaster` and never
make network calls. The helper validates transaction hex locally and checks the
returned txid matches the transaction before reporting success.

PSBT v2 (BIP370) support is a local adapter in this crate. rust-bitcoin
0.32.100 still rejects `PSBT_GLOBAL_VERSION = 2` during normal decode and its
plain `Psbt::serialize()` writes an invalid hybrid if `psbt.version = 2`, so
v2 imports must go through the raw-map BIP370 parser and v2 exports must go
through `export_psbt_v2_base64` / `PsbtDrill::to_base64`. Use
`to_bip174_base64` only when a legacy v0 export is explicitly required.

US-075 local DrillResult history lives here because it records outcomes from the
BDK-backed practice drill. Keep saving explicit: `run_receive_send_drill` must
not write files, and the desktop calls `save_practice_drill_result` only after a
user clicks "Save this drill result." Records contain only the §19.5 public
summary fields plus an Ed25519 signature envelope; do not add PSBTs, tx hex,
descriptors, xpubs, or addresses to drill-history JSON. The per-install signing
key is a local random key under the Lifeboat data directory, while records go
under `lifeboat/drills/*.json`.

US-076 questionnaire-only disaster drills (DS-1..DS-6) reuse the same signed
DrillResult history boundary. `run_disaster_questionnaire_drill` is side-effect
free: it screens descriptor/address input, parses and derives in Rust, evaluates
questionnaire pass/fail, and returns an unsaved public summary. Only
`save_disaster_questionnaire_drill_result` writes, and it rejects unsupported
scenario/step/wallet-type strings so a compromised webview cannot persist
descriptors, xpubs, addresses, signer locations, or seed/passphrase material in
drill-history records.

US-078 file-based PSBT exchange also belongs here. `read_psbt_file` accepts both
Lifeboat's base64-text `.psbt` files and raw binary PSBT files from external
signers, returning base64 for the normal importer. `finalize_file_psbt` validates
through the existing import/inspect path, extracts already-finalized PSBTs without
wallet ownership, and otherwise finalizes with the deterministic practice wallet.
Keep the desktop wrapper thin and do not add USB/HWI or network behavior here.

US-082 DS-7..DS-10 signing disaster drills are a two-step contract:
`start_disaster_signing_drill` creates an unsigned practice PSBT for file/QR
transport, and `complete_disaster_signing_drill` accepts a signed PSBT plus the
user's device destination confirmation. A malformed or under-signed PSBT returns
a failing drill result, not an automatic save. Only
`save_disaster_signing_drill_result` writes, and saved records must stay public:
no PSBT base64, transaction hex, destination address, receive address, xpub, or
descriptor text in DrillResult JSON.

US-086 adds `hwi` as a public signing transport. `psbt-drill` still only starts
and completes the drill; HWI enumeration and `signtx` live in `hwi-bridge`.
Saved DrillResult transport validation must allow `file`, `qr`, and `hwi`.

US-083 mainnet PSBT handling is validation-only. Use
`validate_mainnet_file_psbt` to import and inspect a mainnet PSBT with
`Network::Bitcoin`; it must not sign, finalize with the practice wallet, extract
transaction hex, or broadcast. Keep `SignetBroadcastInput.network` on
`PracticeDrillNetwork` so `"mainnet"` cannot deserialize into the broadcast
command at all.

US-089 multisig survivability drills are no-signing templates in this crate,
not frontend logic. `run_multisig_survivability_drill` screens descriptor/address
input, checks the selected `multisig-2of3` or `multisig-3of5` template against
the parsed M-of-N descriptor, reuses `readiness_score::compute_survivability`,
and returns only public readiness status plus survivability verdicts. Save via
`save_multisig_survivability_drill_result`; the signed DrillResult payload must
stay public (scenario, wallet type, steps, hash), with no descriptor, xpub,
address, signer location, PSBT, or transaction hex.

US-090 missing-signer drills are also no-signing, Signet/regtest-only rehearsals
in this crate. `run_missing_signer_drill` screens the descriptor, parses M-of-N,
removes the selected 1-based signer index, and returns public facts only:
threshold/key count, remaining signer numbers, practice chain, material
categories, and pass/fail steps. Save through `save_missing_signer_drill_result`;
the signed DrillResult payload stays schema/title/steps/hash only and must not
persist descriptors, xpubs, fingerprints, addresses, signer locations, PSBTs, or
transaction hex.

US-094 heir drill packets also live here because they use disposable BDK practice
wallets. `generate_heir_drill_packet` must create a fresh regtest/Signet wallet
without accepting user wallet material, then return exactly the export files:
`manifest.json`, `README-heir-drill.md`, and `wallet/practice-wallet.json`. The
wallet file may contain disposable test-only private descriptors so the heir-side
app can import it later, but the manifest must state `contains_real_user_material:
false` and `includes_disposable_private_material: true`. `write_heir_drill_packet`
writes into a new `bitcoin-lifeboat-heir-drill-<uuid>` directory and marks the
wallet file as a secret file on Unix.

US-096 family drill receipts are public-safe PDF artifacts generated here through
`runbook-engine`'s pure-Rust `printpdf` path. `generate_family_drill_receipt`
accepts only enum checklist/confidence values, an optional UUID packet id, and an
optional practice network. Do not accept descriptors, xpubs, addresses, PSBTs,
transaction hex, seed text, wallet-file contents, or arbitrary notes in the
receipt input.
