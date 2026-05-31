//! Bitcoin Core `listdescriptors` importer (PRD §17.12, §24.2).
//!
//! Parses the JSON object returned by `bitcoin-cli listdescriptors`, selects the
//! `active=true` entries, and splits them into a receive (`internal=false`) and
//! change (`internal=true`) descriptor, using the latest active `timestamp` as
//! the wallet birth-time hint.
//!
//! ## Version gating
//! `listdescriptors` output carries **no** version field, so the Bitcoin Core
//! version is supplied out-of-band by the caller (the RPC
//! `getnetworkinfo.subversion`, e.g. `"/Satoshi:30.0.0/"`, or the user). 30.x is
//! refused with the §17.12 message; 29.x and other majors proceed.

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    analyze_descriptor, classify, core_major_version, extract_keys, guard_input, unix_to_iso8601,
    NormalizedWalletExport, WalletDescriptors,
};

/// The §17.12 message surfaced when a Bitcoin Core 30.x export is refused.
const CORE_30X_MESSAGE: &str =
    "Bitcoin Core 30.x has known wallet bugs; please use 29.x or wait for 30.2+";

/// A `listdescriptors` result object. Strict (`deny_unknown_fields`) so any
/// unexpected key is refused rather than silently ignored (PRD §17.9).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreListDescriptors {
    /// Present in real output; accepted by strict parsing but not used here.
    #[allow(dead_code)]
    #[serde(default)]
    wallet_name: Option<String>,
    descriptors: Vec<CoreDescriptorEntry>,
}

/// A single descriptor entry from `listdescriptors`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreDescriptorEntry {
    /// The output descriptor with its BIP380 checksum.
    desc: String,
    /// Unix time (integer) or the literal `"now"` for a fresh descriptor; only
    /// integer timestamps contribute to the birth hint.
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
    /// Whether this descriptor is currently active.
    active: bool,
    /// `false` = receive (external), `true` = change (internal). Present on
    /// active entries; defaults to receive when absent.
    #[serde(default)]
    internal: Option<bool>,
    // The following are present in real `listdescriptors` output and accepted by
    // strict parsing, but the importer does not use them.
    #[allow(dead_code)]
    #[serde(default)]
    range: Option<[i64; 2]>,
    #[allow(dead_code)]
    #[serde(default)]
    next: Option<i64>,
    #[allow(dead_code)]
    #[serde(default)]
    next_index: Option<i64>,
}

/// Import a Bitcoin Core `listdescriptors` JSON export (PRD §17.12).
///
/// `core_version` is the Bitcoin Core version learned out-of-band (see the
/// module docs); pass `None` when it is unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` for content that is not valid `listdescriptors` JSON, or for
///   a Bitcoin Core 30.x export (with the §17.12 message attached as context).
/// - `E-PARSE-005` when a selected descriptor carries private-key material — the
///   export is refused before any normalized value is built.
pub fn import_bitcoin_core(
    content: &str,
    core_version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    // Refuse Bitcoin Core 30.x (known wallet bugs, §17.12 / §24.2) before parsing.
    if core_version.and_then(core_major_version) == Some(30) {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(CORE_30X_MESSAGE)
        );
    }

    let listed: CoreListDescriptors = serde_json::from_str(content).map_err(|e| {
        // Report only the structural location, never the content (descriptors
        // and xpubs are confidential and must not leak into errors/logs).
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "not valid Bitcoin Core listdescriptors JSON (at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;

    // Select active descriptors: first non-internal = receive, first internal =
    // change. Track the latest active integer timestamp as the birth hint.
    let mut receive: Option<String> = None;
    let mut change: Option<String> = None;
    let mut latest_ts: Option<i64> = None;

    for entry in &listed.descriptors {
        if !entry.active {
            continue;
        }
        if entry.internal.unwrap_or(false) {
            change.get_or_insert_with(|| entry.desc.clone());
        } else {
            receive.get_or_insert_with(|| entry.desc.clone());
        }
        if let Some(ts) = entry.timestamp.as_ref().and_then(serde_json::Value::as_i64) {
            latest_ts = Some(latest_ts.map_or(ts, |cur| cur.max(ts)));
        }
    }

    // Refuse private-key material in either selected descriptor before storing
    // it; tolerate other parse problems (the analysis layer reports those).
    let receive_parsed = match &receive {
        Some(d) => analyze_descriptor(d)?,
        None => None,
    };
    let change_parsed = match &change {
        Some(d) => analyze_descriptor(d)?,
        None => None,
    };

    // Key origins / wallet type come from the receive descriptor (change shares
    // the same keys); fall back to change if only it is present.
    let primary = receive_parsed.as_ref().or(change_parsed.as_ref());
    let keys = primary.map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = primary.map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "bitcoin_core".to_string(),
        source_wallet_version: core_version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors { receive, change },
        keys,
        birth_height: None,
        birth_timestamp: latest_ts.map(unix_to_iso8601),
        gap_limit: None,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}
