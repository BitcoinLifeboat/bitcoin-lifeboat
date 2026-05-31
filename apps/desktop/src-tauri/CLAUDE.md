# src-tauri — Tauri 2 desktop shell (learnings for M2 stories)

This is the Rust side of the desktop app. Read this before touching the Tauri
config, capabilities, or commands.

## Detached workspace + toolchain (US-041)

- `src-tauri/Cargo.toml` has its **own `[workspace]` table** → it is a separate
  Cargo workspace, like `fuzz/`. The repo root also lists it under
  `exclude = [...]`. The core gate `cargo {build,clippy,test} --workspace` run
  from the repo root (Rust **1.78**) never compiles this tree — keep it that way.
- This dir pins its own toolchain via `rust-toolchain.toml`
  (**channel 1.86.0**). Tauri 2.11 / wry 0.55 / tao 0.35 need newer than the
  core MSRV (1.78). The bump is **scoped here only** — never raise the root
  `rust-toolchain.toml` or the core crates' `rust-version` to satisfy Tauri.
- Resolution caveat: the lock contains a few **wasi-only** crates (`wasip2`,
  `wit-bindgen`, …) that want Rust ≥ 1.87. They are *not* compiled for the
  `x86_64-unknown-linux-gnu` host, so 1.86.0 builds the host target. If a real
  build on a prereq-equipped host ever errors on a 1.87 requirement, bump
  `channel` here (1.87.0+) — not the core toolchain.

## Capabilities ↔ plugins coupling (§13.7) — IMPORTANT

`capabilities/default.json` is desktop-only (`linux` / `macOS` / `windows`) and
references the `dialog:` / `fs:` / `os:` / `process:` permission namespaces.
US-080 also allows only the camera plugin's `camera:allow-take-picture` command
for mobile camera capture in `capabilities/mobile.json` (`iOS` / `android`);
do not add `camera:allow-record-video`. US-084 adds `shell:allow-execute`,
scoped to the single HWI sidecar path `binaries/hwi-lifeboat`; keep shell
open/spawn/kill/stdin permissions out. Those namespaces only exist if the
matching plugin is a dependency **and** is registered in `lib.rs`:

```rust
.plugin(tauri_plugin_dialog::init())
.plugin(tauri_plugin_fs::init())
.plugin(tauri_plugin_os::init())
.plugin(tauri_plugin_process::init())
.plugin(tauri_plugin_shell::init())
#[cfg(mobile)]
.plugin(tauri_plugin_camera::init())
```

If you add a permission to the capability file, add+register its plugin too, or
`tauri::generate_context!()` fails at build with "permission not found". Adding a
plugin is the **only** sanctioned way to widen capabilities, and it must be the
minimal namespace the story needs — never a broad grant. `core:*` permissions
need no plugin (built into Tauri). The current `tauri-plugin-camera` crate is
mobile-only, so its dependency and registration stay behind `cfg(mobile)`;
desktop QR camera capture uses the `qr-psbt` `camera` feature and `nokhwa`.

Note: opening external links (US-043) is intentionally **not** a capability — there
is no shell/open or opener permission. `open_external_link` launches the OS
browser from the trusted Rust core (`std::process::Command`) only after the
build-time allowlist passes, so the webview cannot use shell for links. Do not
"fix" this by adding shell open or an opener permission; it would fail the
security gate and widen the webview surface.

## CSP lives in the config, not a builder (§13.8)

The strict CSP is `tauri.conf.json → app.security.csp`. In Tauri 2 the
declarative config field **is** the supported mechanism (Tauri injects it into
the served assets); there is no separate stable runtime `with_csp` builder. A
config field is also exactly what the NFR-SEC-8 CI lint targets. Do not hand-edit
`index.html` to add a CSP. The §13.8 string is the production policy; if a future
`tauri dev` run needs HMR, relax the CSP in a dev-only config override, never in
the committed production CSP.

## No auto-updater, ever (§13.10)

Never add `tauri-plugin-updater` or a `plugins.updater` config block. "Check for
updates" opens the OS browser via the allowlisted `open_external_link` command
(US-043), never an in-app fetch.

## The runnable security gate

`../scripts/verify-capabilities.mjs` (`npm run verify:security`) asserts the
exact §13.7 set, the exact §13.8 CSP, and the no-updater posture. It needs no
system libs, so it runs in CI and in sandboxes where `cargo build` cannot link.
**Run it after any change to `capabilities/` or the CSP.** A later CI story
should wire it into the pipeline (NFR-SEC-7/8).

## Building needs desktop system libraries

`cargo build` links webkit2gtk-4.1 + GTK 3 (via the `*-sys` crates' pkg-config
probes: `gtk+-3.0`, `webkit2gtk-4.1`, `libsoup-3.0`, `javascriptcoregtk-4.1`,
`atk`, …). Install the `-dev` packages (see `../README.md`) before building. In a
sandbox without them (or without sudo), the build stops at the first `*-sys`
build script (`atk-sys`/`gtk-sys`) — the JS security gate + frontend `tsc` still
verify the security-relevant deliverables; the GUI link step is environment-only.

## Commands live in `desktop-commands`, not here (US-042) — IMPORTANT

The §21.3 command **logic** lives in the repo-root crate `crates/desktop-commands`
(a GUI-agnostic library, no `tauri` dep). `src/commands.rs` holds only the thin
`#[tauri::command] pub async fn`s, each delegating to a `desktop_commands::*`
function (full-path the call so it doesn't collide with the same-named wrapper).
Why split it out: this crate can't even **build** without the webkit2gtk/GTK
system libs (see above), so any logic + tests buried here are unrunnable in CI's
fast lane and in sandboxes. Putting the logic in `desktop-commands` means it builds
and is fully tested under `cargo test --workspace` (Rust 1.78) — that's where the
integration tests for these commands live. Keep this crate a wrapper-only shell.

- **Errors:** commands return `Result<T, LifeboatError>` verbatim (§21.3).
  `error-taxonomy` gives `LifeboatError` a **leak-free** `serde::Serialize`
  (stable code + catalog text + i18n key + secret-free `context`; the chained
  `source` is NEVER serialized), which is exactly what Tauri needs (`E: Serialize`).
  Don't invent a separate boundary error type.
- **Secrets:** never wrap input by hand. `desktop-commands` screens every pasted
  string via `detect_secret(SecretString)` **before** parsing; only a
  `DetectorReport` (discriminants + byte ranges) crosses back to JS (§13.5.8).
- **Determinism:** `audit_descriptor`'s wrapper reads the clock
  (`desktop_commands::now_iso8601()`) + `env!("CARGO_PKG_VERSION")` and passes them
  in, so the report engine stays pure (§19/§27).
- **Registration:** add each command to BOTH `src/commands.rs` and the
  `tauri::generate_handler![…]` list in `lib.rs`.
- **M3 drill commands:** BDK-backed Practice Mode commands cannot live in the root
  Rust 1.78 `desktop-commands` crate. Keep their logic in the detached Rust 1.85
  drill crates (`psbt-drill` / `signet-lab`) and make `src-tauri` a thin wrapper
  over those tested helpers.

## What's here vs. what's next

- US-041: shell only — locked-down capabilities, CSP, no updater, empty `main`
  window.
- US-042 (done): descriptor/detector/derive/checksum commands — thin wrappers over
  `desktop-commands` (see above).
- US-043 (done): `generate_report` / `generate_runbook` / `parse_wallet_export` /
  `save_export` / `open_external_link` / `get_app_info`. How the split landed:
  - `generate_report` / `generate_runbook` / `parse_wallet_export` / `save_export`
    delegate **fully** to `desktop-commands` — the file read/write uses `std::fs` by
    path (no `AppHandle`/scope needed), so it stays testable under the core gate.
    `save_export` writes to the path the JS save-dialog already chose.
  - `open_external_link` is the **only** wrapper that does real IO here: it calls
    `desktop_commands::check_external_link(&url)?` (the allowlist decision, built
    from `project.config.toml`, tested in `desktop-commands`), then launches the OS
    browser via a plain per-OS `std::process::Command` (`spawn_browser`) — **no**
    Tauri shell/opener plugin. This is deliberate: §13.7 grants the webview no such
    capability and `verify-capabilities.mjs` enforces the set exactly, so opening a
    link is a trusted-core action on a pre-vetted, single, non-shell argument (a
    compromised webview can at most ask to open one of our own allowlisted URLs).
    Launch failure → `E-INTERNAL-001`.
  - `get_app_info` wraps the infallible `desktop_commands::app_info(APP_VERSION)` in
    `Ok(...)` for §21.3 signature uniformity.
- US-071 (done): `start_practice_drill` and `run_practice_send_drill` delegate to
  `psbt-drill`. They create local receive/send drill summaries and never broadcast;
  Signet faucet opening still goes through `open_external_link`.
- US-072 (done): `broadcast_signet_transaction` also delegates to `psbt-drill`.
  Keep `src-tauri` as a thin wrapper: the Signet-only endpoint list, transaction
  hex validation, curl transport, and no-mainnet guarantee live in `psbt-drill`.
  Do not add a Tauri `http`, `shell`, or `opener` plugin for this path.
- US-075 (done): `save_practice_drill_result` is another thin wrapper over
  `psbt-drill`. It resolves the Lifeboat data directory there, stamps the boundary
  time here, and does not require any new webview fs capability; the frontend never
  receives direct write access to the drill-history directory.
- US-076 (done): `run_disaster_questionnaire_drill` and
  `save_disaster_questionnaire_drill_result` are thin wrappers over `psbt-drill`.
  Keep descriptor screening, address derivation, questionnaire pass/fail, and
  DrillResult public-summary validation in that crate; `src-tauri` only supplies
  the boundary timestamp and data directory.
- US-089 (done): `run_multisig_survivability_drill` and
  `save_multisig_survivability_drill_result` follow the same wrapper rule. The
  2-of-3 / 3-of-5 template matching, §16.6 survivability model, readiness status,
  and DrillResult validation live in `psbt-drill`; `src-tauri` only stamps time
  and resolves the data directory.
- US-090 (done): `run_missing_signer_drill` and
  `save_missing_signer_drill_result` are the same thin wrapper pattern. The
  selected signer index, remaining quorum calculation, required-material
  categories, and public DrillResult validation live in `psbt-drill`; this crate
  only stamps time and resolves the data directory.
- US-078 (done): `read_psbt_file` and `finalize_file_psbt` are thin wrappers over
  `psbt-drill`. The UI still uses only `dialog:allow-open` / `dialog:allow-save`
  plus the existing dialog-chosen write path; do not widen capabilities for
  file-based PSBT exchange. USB/HWI starts in later stories, not here.
- US-094 (done): `write_heir_drill_packet` is the same thin wrapper pattern. The
  disposable regtest/Signet wallet, manifest, instructions, and file-writing
  rules live in `psbt-drill`; `src-tauri` only stamps the boundary timestamp and
  passes the owner-selected output directory. Do not add webview Bitcoin logic or
  new capabilities for this export path.
- US-096 (done): `generate_family_drill_receipt` is a thin wrapper over
  `psbt-drill`. This crate stamps the boundary time/version and returns the
  public-safe PDF artifact; the receipt content, redaction rules, and no-secret
  input contract stay in `psbt-drill`. No new Tauri capability is needed because
  the UI writes the returned bytes through the existing dialog-selected
  `save_export` path.
- US-081 (done): `encode_psbt_qr_frames`, `decode_psbt_qr_payloads`, and
  `capture_psbt_qr_payloads` expose `qr-psbt` UR/BBQr transport to Practice Mode.
  They return Rust-rendered SVG frames and decoded payload progress; React must
  not add QR or PSBT parsing libraries. Desktop camera capture goes through the
  `qr-psbt` `camera` feature (`nokhwa`) and does not require a new broad Tauri
  capability beyond the existing mobile-only camera take-picture permission.
- US-084 (done): HWI is packaged as a sidecar at `bundle.externalBin:
  ["binaries/hwi-lifeboat"]`. The only shell permission is
  `shell:allow-execute` with a sidecar scope whose `name` matches that exact
  string. Do not add in-process USB/HID dependencies to `src-tauri`; subprocess
  behavior lives in the root `crates/hwi-bridge` crate and maps a missing sidecar
  to `E-DEP-002`.
- US-085 (done): `enumerate_hwi_devices`, `read_hwi_xpub`, and
  `verify_hwi_xpubs` are thin wrappers over `hwi-bridge`. Keep the HWI selector
  logic, fingerprint matching, xpub comparison, and
  `W-DEVICE-FIRMWARE-UNSUPPORTED` warning in Rust; React should only render the
  returned status.
- US-086 (done): `sign_hwi_psbt` is also a thin wrapper over `hwi-bridge`.
  React may choose a returned HWI device and request signing, but the subprocess
  `signtx` call, PSBT output parsing, and leak-free errors stay in Rust.
