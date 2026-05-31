//! Liana encrypted descriptor backup (`.bed`) importer (PRD §17.9, §24.2).
//!
//! Liana's default backup is a `.bed` file — a *Bitcoin Encrypted Descriptor*. The
//! descriptor is encrypted to **all** of the public keys it contains, so anyone
//! holding at least one of the wallet's xpubs can recover it (during recovery Liana
//! connects a hardware signer, fetches its xpub, and decrypts automatically). This
//! importer models that **decryption-input flow**: the caller supplies the user's
//! own xpub(s) ([`import_liana_bed`]'s `decryption_inputs`), and the descriptor is
//! recovered only if at least one supplied key is one of the backup's recipients.
//!
//! ## MVP scope (no over-claim)
//! The real `.bed` cryptography (an encrypted-descriptor scheme from a Wizardsardine
//! BIP draft) is **not** implemented here. This importer enforces the user-facing
//! *access rule* — you must hold one of the wallet's keys to open the backup — and
//! reads the descriptor from the backup payload (carried as hex, decoded behind the
//! recipient gate). It makes no cryptographic-authenticity claim; full ECIES-style
//! decryption of arbitrary third-party `.bed` files is deferred to a later milestone.
//!
//! The recovered descriptor is a Liana timelock policy
//! (`wsh(or_d(pk(primary),and_v(v:pkh(recovery),older(N))))`), which this MVP parses
//! and derives as a supported timelock wallet. It still has no plain M-of-N quorum
//! (`multisig_info()` is `None` for an `or_d` policy); deeper Liana recovery-path
//! countdowns remain a later drill feature. Birth time is the backup `timestamp`
//! (Unix seconds).

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    analyze_descriptor, classify, epoch_value_to_iso8601, expand_receive_change, extract_keys,
    guard_input, NormalizedWalletExport, WalletDescriptors,
};

/// A Liana `.bed` backup envelope. Strict (`deny_unknown_fields`) so an unexpected
/// key is refused rather than silently ignored (PRD §17.9).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LianaBed {
    /// The xpubs the descriptor is encrypted to — holding any one of them decrypts
    /// the backup. Used as the recipient access-control list (the decryption gate).
    recipients: Vec<String>,
    /// The descriptor payload (hex of the descriptor text), readable only after the
    /// recipient gate passes (see the module docs for the MVP-scope note).
    payload: String,
    /// Wallet birth time as a Unix timestamp (seconds), when present.
    #[serde(default)]
    timestamp: Option<serde_json::Value>,
    /// Backup-format version (e.g. `"13"`); accepted but unused — the Liana app
    /// version is supplied out-of-band via the importer's `version` argument.
    #[allow(dead_code)]
    #[serde(default)]
    liana_backup_version: Option<serde_json::Value>,
    /// Network label (`"signet"`/`"regtest"`/…); accepted but unused (the network is
    /// inferred from the descriptor's keys downstream).
    #[allow(dead_code)]
    #[serde(default)]
    network: Option<String>,
}

/// Import a Liana encrypted `.bed` backup (PRD §17.9, §24.2).
///
/// `decryption_inputs` are the user's own xpubs (the watch-only public keys they can
/// supply, e.g. read from a connected hardware signer). The descriptor is recovered
/// only if at least one of them is one of the backup's recipients — modeling Liana's
/// "decrypt with any contained key" rule. `version` is the Liana app version learned
/// out-of-band (the backup carries only its format version); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` when the content is not a valid `.bed` envelope, when no
///   decryption input is supplied, when none of the supplied keys can decrypt the
///   backup, or when the recovered payload is not a valid descriptor encoding.
/// - `E-PARSE-005` when the recovered descriptor carries private-key material.
pub fn import_liana_bed(
    content: &str,
    decryption_inputs: &[&str],
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let bed: LianaBed = serde_json::from_str(content).map_err(|e| {
        // Report only the structural location, never the content (xpubs are
        // confidential and must not leak into errors/logs).
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "not a valid Liana .bed backup (at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;

    if bed.recipients.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Liana .bed lists no recipients"));
    }
    // The decryption-input flow: the user must supply at least one of their xpubs.
    if decryption_inputs.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(
                "Liana .bed is encrypted; provide one of your wallet xpubs to decrypt it",
            ),
        );
    }
    // A supplied key decrypts the backup only if it is one of the recipients.
    let unlocked = decryption_inputs
        .iter()
        .any(|input| bed.recipients.iter().any(|r| r.trim() == input.trim()));
    if !unlocked {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("none of the provided keys can decrypt this Liana backup"));
    }

    // Recover the descriptor from the payload (the recipient gate has passed).
    let descriptor = decode_hex_to_string(&bed.payload).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Liana .bed payload is not a valid descriptor encoding")
    })?;

    // Refuse private-key material before storing; tolerate other parse problems
    // (the analysis layer reports those). A Liana descriptor is a multipath timelock
    // policy → expand into receive/change branches.
    let parsed = analyze_descriptor(&descriptor)?;
    let (receive, change) = match &parsed {
        Some(p) if p.uses_multipath() => expand_receive_change(p)?,
        _ => (descriptor.clone(), None),
    };

    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "liana".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys,
        birth_height: None,
        birth_timestamp: bed.timestamp.as_ref().and_then(epoch_value_to_iso8601),
        gap_limit: None,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}

/// Decode a hex string into the UTF-8 string it encodes, or `None` if the input is
/// not valid even-length hex / not valid UTF-8. Dependency-free; the payload is the
/// only thing decoded, and it is text (a descriptor), never secret material.
fn decode_hex_to_string(hex: &str) -> Option<String> {
    let hex = hex.trim();
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    String::from_utf8(out).ok()
}
