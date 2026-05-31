//! Bitcoin Lifeboat desktop shell (US-041).
//!
//! This crate is intentionally minimal: it stands up the Tauri 2 runtime with
//! the locked-down capability set (`capabilities/default.json`, PRD §13.7) and
//! the strict Content-Security-Policy (`tauri.conf.json` →
//! `app.security.csp`, PRD §13.8), and launches a single empty window labelled
//! `main`.
//!
//! Security invariants enforced here and in the config — do NOT relax without an
//! explicit security review (§13.7 / §13.8 / §13.10):
//!
//! * **No auto-updater** (§13.10). The app never makes a network request on its
//!   own; a future "check for updates" affordance opens the OS browser via the
//!   allowlisted `open_external_link` command (US-043), not an in-app fetch.
//! * **Minimal plugins.** Only `dialog`, `fs`, `os`, `process`, the HWI sidecar
//!   `shell:allow-execute` path, and the mobile `camera` take-picture path are
//!   registered — exactly the namespaces the §13.7 capability file scopes. No
//!   `http`, shell open/spawn/kill/stdin, `clipboard-manager`, `notification`,
//!   `global-shortcut`, `webview:create`, `process:spawn`, or camera
//!   video-recording capability exists.
//! * **All Bitcoin logic stays in Rust core crates.** The webview never derives
//!   addresses, parses descriptors, or touches secrets. The §21.3 commands
//!   ([`commands`], wired below) are thin wrappers that delegate to the
//!   GUI-agnostic `desktop-commands` crate; this crate adds no Bitcoin logic of
//!   its own. US-042 added the descriptor/detector/derive/checksum commands;
//!   US-043 adds the report/runbook/import/save/link/app-info tranche (all wired
//!   in [`run`] below). The only IO this crate performs is the OS-browser launch
//!   in `commands::open_external_link`, and only after the link allowlist passes.

mod commands;

/// Builds and runs the desktop application.
///
/// Returns a [`tauri::Error`] if the runtime fails to initialise (an
/// unrecoverable startup error); the caller in `main.rs` reports it and exits
/// non-zero. No `unwrap`/`expect`/`panic!` is used, per the workspace invariant.
pub fn run() -> tauri::Result<()> {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_shell::init());

    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_camera::init());

    builder
        .invoke_handler(tauri::generate_handler![
            commands::audit_descriptor,
            commands::derive_addresses,
            commands::compare_address,
            commands::detect_sensitive_input,
            commands::validate_checksum,
            commands::compute_checksum,
            commands::render_miniscript_policy_dot,
            commands::render_liana_recovery_tree,
            commands::generate_report,
            commands::generate_runbook,
            commands::start_practice_drill,
            commands::run_practice_send_drill,
            commands::broadcast_signet_transaction,
            commands::save_practice_drill_result,
            commands::run_disaster_questionnaire_drill,
            commands::save_disaster_questionnaire_drill_result,
            commands::run_multisig_survivability_drill,
            commands::save_multisig_survivability_drill_result,
            commands::run_missing_signer_drill,
            commands::save_missing_signer_drill_result,
            commands::start_disaster_signing_drill,
            commands::complete_disaster_signing_drill,
            commands::save_disaster_signing_drill_result,
            commands::read_psbt_file,
            commands::finalize_file_psbt,
            commands::validate_mainnet_file_psbt,
            commands::write_heir_drill_packet,
            commands::generate_family_drill_receipt,
            commands::encode_psbt_qr_frames,
            commands::decode_psbt_qr_payloads,
            commands::capture_psbt_qr_payloads,
            commands::enumerate_hwi_devices,
            commands::read_hwi_xpub,
            commands::sign_hwi_psbt,
            commands::verify_hwi_xpubs,
            commands::parse_wallet_export,
            commands::save_export,
            commands::open_external_link,
            commands::get_app_info,
            commands::load_settings,
            commands::save_settings,
            commands::clear_all_data,
        ])
        .run(tauri::generate_context!())
}
