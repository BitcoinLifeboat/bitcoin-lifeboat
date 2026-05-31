// Prevents an extra console window on Windows in release builds. The real entry
// point lives in the library crate (`bitcoin_lifeboat_lib::run`).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(err) = bitcoin_lifeboat_lib::run() {
        // No Confidential/Secret data is in scope during startup, so this bare
        // message is safe. A failed GUI bootstrap is unrecoverable; exit non-zero
        // rather than panic (honors the workspace no-panic invariant).
        eprintln!("fatal: could not start Bitcoin Lifeboat: {err}");
        std::process::exit(1);
    }
}
