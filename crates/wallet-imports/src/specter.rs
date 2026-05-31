//! Specter Desktop wallet JSON importer (PRD §17.9, §24.2).
//!
//! Specter's "Wallet > Settings > Export" produces a small JSON object:
//! `{ "label", "blockheight", "descriptor", "devices": [{ "type", "label" }] }`.
//! The `descriptor` is the receive (external) output descriptor with its BIP380
//! checksum (single-path `/0/*`); Specter does not export the change branch
//! (cryptoadvance/specter-desktop#2494), so `change` is left unset unless a newer
//! export supplies an explicit `change_descriptor`. `blockheight` is the wallet
//! birth-block hint. Key origins and quorum are reused from descriptor-audit.

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    analyze_descriptor, classify, extract_keys, guard_input, NormalizedWalletExport,
    WalletDescriptors,
};

/// A Specter wallet export object. Strict (`deny_unknown_fields`) so an
/// unexpected key is refused rather than silently ignored (PRD §17.9).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecterWallet {
    /// The receive (external) output descriptor with its checksum.
    descriptor: String,
    /// Wallet birth-block height hint.
    #[serde(default)]
    blockheight: Option<u64>,
    /// Some Specter versions export the change descriptor separately; accept it.
    #[serde(default)]
    change_descriptor: Option<String>,
    /// Some versions name the receive descriptor `recv_descriptor`; accept it as
    /// the receive descriptor when `descriptor` is the combined/legacy field.
    #[serde(default)]
    recv_descriptor: Option<String>,
    // The following are present in real Specter output and accepted by strict
    // parsing, but the importer does not use them.
    #[allow(dead_code)]
    #[serde(default)]
    label: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    devices: Option<serde_json::Value>,
}

/// Import a Specter Desktop wallet JSON export (PRD §17.9, §24.2).
///
/// `version` is the Specter version learned out-of-band (it is not in the export
/// file); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` for content that is not valid Specter wallet JSON.
/// - `E-PARSE-005` when the descriptor carries private-key material — the export
///   is refused before any normalized value is built.
pub fn import_specter(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let wallet: SpecterWallet = serde_json::from_str(content).map_err(|e| {
        // Report only the structural location, never the content (descriptors and
        // xpubs are confidential and must not leak into errors/logs).
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "not valid Specter wallet JSON (at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;

    // The receive descriptor is `recv_descriptor` when present, else `descriptor`.
    let receive = wallet.recv_descriptor.unwrap_or(wallet.descriptor);
    let change = wallet.change_descriptor;

    // Refuse private-key material in either descriptor before storing it; tolerate
    // other parse problems (the analysis layer reports those as C-DESC-PARSE-FAIL).
    let receive_parsed = analyze_descriptor(&receive)?;
    if let Some(c) = &change {
        analyze_descriptor(c)?;
    }

    // Key origins / wallet type come from the receive descriptor (change shares
    // the same keys).
    let keys = receive_parsed
        .as_ref()
        .map(extract_keys)
        .unwrap_or_default();
    let (wallet_type, threshold, key_count) =
        receive_parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "specter".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys,
        birth_height: wallet.blockheight,
        birth_timestamp: None,
        gap_limit: None,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}
