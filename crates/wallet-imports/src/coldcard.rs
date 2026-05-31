//! Coldcard wallet-export importers (PRD §17.9, §24.2).
//!
//! Coldcard offers two watch-only export formats this module handles:
//!
//! - **Generic Wallet Export JSON** ([`import_coldcard_json`]) — a *singlesig*
//!   export listing each standard account branch (`bip44`/`bip49`/`bip84`/`bip86`)
//!   with its origin `deriv` path and account `xpub`, alongside the master
//!   fingerprint (`xfp`). Like Sparrow, it carries no ready-made descriptor string,
//!   so the importer **assembles** the receive (`/0/*`) and change (`/1/*`)
//!   descriptors from `[xfp/deriv]xpub` and the script type implied by the chosen
//!   branch, then normalizes any SLIP-132 key and computes a BIP380 checksum.
//! - **Descriptor file (+ optional `.sig`)** ([`import_coldcard_descriptor`]) — a
//!   text file containing the output descriptor (singlesig or multisig). Comment
//!   lines (`#…`) are ignored; the `/**` multipath shorthand is rewritten to
//!   `/<0;1>/*` and expanded into receive/change. The accompanying `.sig` is a
//!   signed-message attestation over the file; it is accepted for API completeness
//!   but **not** cryptographically verified in the MVP (descriptor authenticity is
//!   confirmed by the user's known-address comparison, a later analysis step — the
//!   importer makes no authenticity claim).
//!
//! Watch-only safety: neither export declares private-key fields, and any descriptor
//! carrying extended/raw private material is refused with `E-PARSE-005` before it can
//! be stored (see [`analyze_descriptor`](crate::analyze_descriptor)).

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    analyze_descriptor, classify, extract_keys, guard_input, parse_descriptor_file,
    strip_master_prefix, NormalizedWalletExport, WalletDescriptors,
};

/// A Coldcard "Generic Wallet Export" JSON object. Strict (`deny_unknown_fields`)
/// so an unexpected key is refused rather than silently ignored (PRD §17.9). Only
/// the master fingerprint and the chosen account branch's `deriv`/`xpub` are read.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdcardExport {
    /// Master key fingerprint (8 hex; Coldcard emits it uppercase).
    xfp: String,
    #[serde(default)]
    bip44: Option<ColdcardBranch>,
    #[serde(default)]
    bip49: Option<ColdcardBranch>,
    #[serde(default)]
    bip84: Option<ColdcardBranch>,
    #[serde(default)]
    bip86: Option<ColdcardBranch>,
    // The following are present in real Coldcard output and accepted by strict
    // parsing, but the importer does not use them.
    #[allow(dead_code)]
    #[serde(default)]
    chain: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    account: Option<serde_json::Value>,
    /// Master (root) xpub at `m`; accepted but unused (the account branch carries
    /// the account xpub the descriptor needs).
    #[allow(dead_code)]
    #[serde(default)]
    xpub: Option<String>,
    /// Multisig account branches (`bip48_1` = P2SH-P2WSH, `bip48_2` = P2WSH).
    /// Accepted but unused: a multisig wallet needs its co-signers, so it is
    /// imported via the descriptor file or BSMS, not this singlesig export.
    #[allow(dead_code)]
    #[serde(default, rename = "bip48_1")]
    bip48_1: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "bip48_2")]
    bip48_2: Option<serde_json::Value>,
}

/// One account branch of a Coldcard generic export. Only `deriv` (origin path) and
/// `xpub` (account key) are read; the rest are accepted-but-unused real fields.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdcardBranch {
    /// Origin derivation path to the account, e.g. `m/84'/1'/0'`.
    deriv: String,
    /// The account-level extended public key.
    xpub: String,
    #[allow(dead_code)]
    #[serde(default)]
    name: Option<String>,
    /// Fingerprint of the account-level key (not the master); unused.
    #[allow(dead_code)]
    #[serde(default)]
    xfp: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    desc: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    first: Option<String>,
    /// SLIP-132 variant of `xpub` (e.g. `vpub`); unused (the standard `xpub` is read).
    #[allow(dead_code)]
    #[serde(default, rename = "_pub")]
    slip132_pub: Option<String>,
}

/// The single-sig script wrapper implied by the chosen Coldcard account branch.
#[derive(Clone, Copy)]
enum Wrapper {
    /// BIP44 → `pkh(KEY)`.
    Pkh,
    /// BIP49 → `sh(wpkh(KEY))`.
    ShWpkh,
    /// BIP84 → `wpkh(KEY)`.
    Wpkh,
    /// BIP86 → `tr(KEY)`.
    Tr,
}

/// Import a Coldcard "Generic Wallet Export" JSON (singlesig) (PRD §17.9, §24.2).
///
/// The export lists every standard account branch; the importer picks the most
/// modern, widely supported script type present — native segwit (`bip84`), then
/// taproot (`bip86`), then nested segwit (`bip49`), then legacy (`bip44`) — and
/// assembles the receive/change descriptors from it. `version` is the Coldcard
/// firmware version learned out-of-band (it is not in the export); pass `None`.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` for content that is not a valid Coldcard generic export, or that
///   contains no supported singlesig account branch.
/// - `E-PARSE-005` if an assembled descriptor carries private-key material (a
///   watch-only export cannot reach this; the check is defensive).
pub fn import_coldcard_json(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let export: ColdcardExport = serde_json::from_str(content).map_err(|e| {
        // Report only the structural location, never the content (xpubs are
        // confidential and must not leak into errors/logs).
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "not valid Coldcard generic export JSON (at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;

    // Prefer the most modern widely supported script type present.
    let (branch, wrapper) = if let Some(b) = &export.bip84 {
        (b, Wrapper::Wpkh)
    } else if let Some(b) = &export.bip86 {
        (b, Wrapper::Tr)
    } else if let Some(b) = &export.bip49 {
        (b, Wrapper::ShWpkh)
    } else if let Some(b) = &export.bip44 {
        (b, Wrapper::Pkh)
    } else {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Coldcard export has no supported singlesig account branch"));
    };

    let receive = assemble(wrapper, &export.xfp, &branch.deriv, &branch.xpub, "0")?;
    let change = assemble(wrapper, &export.xfp, &branch.deriv, &branch.xpub, "1")?;

    // Key origins / wallet type come from the receive descriptor (change shares the
    // same key). Refuse private-key material before storing; tolerate other parse
    // problems (the analysis layer reports those).
    let parsed = analyze_descriptor(&receive)?;
    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "coldcard".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change: Some(change),
        },
        keys,
        // Coldcard exports carry no wallet birth height/time (§24.2).
        birth_height: None,
        birth_timestamp: None,
        gap_limit: None,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}

/// Assemble one chain's singlesig descriptor from a Coldcard account branch: build
/// `[fingerprint/path]xpub/{chain}/*`, wrap per the script type, normalize any
/// SLIP-132 key, and (re)compute the BIP380 checksum. The fingerprint is lowercased
/// (Coldcard emits it uppercase; descriptors use lowercase hex).
fn assemble(
    wrapper: Wrapper,
    master_fingerprint: &str,
    deriv: &str,
    xpub: &str,
    chain: &str,
) -> Result<String, LifeboatError> {
    let fingerprint = master_fingerprint.trim().to_lowercase();
    let path = strip_master_prefix(deriv);
    let origin = if path.is_empty() {
        format!("[{fingerprint}]")
    } else {
        format!("[{fingerprint}/{path}]")
    };
    let key = format!("{origin}{}/{chain}/*", xpub.trim());
    let body = match wrapper {
        Wrapper::Pkh => format!("pkh({key})"),
        Wrapper::ShWpkh => format!("sh(wpkh({key}))"),
        Wrapper::Wpkh => format!("wpkh({key})"),
        Wrapper::Tr => format!("tr({key})"),
    };
    let normalized = descriptor_audit::normalize_slip132(&body)?;
    descriptor_audit::compute_checksum(normalized.descriptor())
}

/// Import a Coldcard descriptor-file export (singlesig or multisig) (PRD §17.9).
///
/// Comment lines (`#…`) and blank lines are ignored. A single descriptor line may be
/// a BIP389 multipath (`<0;1>` or the `/**` shorthand), which is expanded into
/// receive/change; two descriptor lines are taken as receive then change. `sig` is
/// the optional `.sig` attestation — accepted for API completeness but not verified
/// in the MVP (see the module docs). `version` is supplied out-of-band.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` when no descriptor line is present, or more than two are.
/// - `E-PARSE-005` when a descriptor carries private-key material.
pub fn import_coldcard_descriptor(
    content: &str,
    sig: Option<&str>,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;
    // The signature is intentionally not verified in the MVP; accepted for the
    // file-pair API. Touching it documents the parameter is deliberately unused.
    let _ = sig;

    // Coldcard and Passport share the descriptor-file shape (comments, `/**`
    // shorthand, one multipath line or a receive/change pair) — see the shared helper.
    let (receive, change, parsed) = parse_descriptor_file(content)?;

    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "coldcard".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys,
        birth_height: None,
        birth_timestamp: None,
        gap_limit: None,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}
