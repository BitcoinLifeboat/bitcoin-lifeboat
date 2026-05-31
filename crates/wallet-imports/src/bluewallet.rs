//! BlueWallet vault importer (PRD §17.9, §24.2) — Tier-2 workaround.
//!
//! BlueWallet exports a multisig "vault" in the widely-shared **Coldcard multisig
//! setup** text format (the same plaintext coordination format Coldcard, Sparrow,
//! Specter, and Nunchuk understand). It is a small line-oriented file:
//!
//! ```text
//! # BlueWallet Multisig setup file
//! # this file may contain private information
//! #
//! Name: My Vault
//! Policy: 2 of 3
//! Derivation: m/48'/1'/0'/2'
//! Format: P2WSH
//!
//! 4ba43603: tpub...
//! 6e37edb9: tpub...
//! 8dfc9b34: tpub...
//! ```
//!
//! This is the literal "Coldcard-style text parser" of US-027: comment lines
//! (`#…`) and blanks are dropped; the `Policy:` line gives the `M`-of-`N` quorum;
//! `Derivation:` is the BIP48 origin path shared by every cosigner; `Format:`
//! selects the script type; and each `<8-hex fingerprint>: <xpub>` line is one
//! cosigner. The importer assembles `wsh(sortedmulti(M, …))` (or the `sh(wsh(…))`
//! / `sh(…)` wrappers) from those parts — reusing the shared
//! [`assemble_sortedmulti`](crate::assemble_sortedmulti) helper — so the result is
//! byte-identical to a descriptor written by any other tool sharing these keys.
//!
//! ## Documented as a Tier-2 workaround
//! BlueWallet has no first-class output-descriptor export, so this importer reads
//! its coordination file as a best-effort path; the user still confirms a known
//! address afterwards. Only watch-only public keys appear in the file — and an
//! xpub carrying private-key material is refused (`E-PARSE-005`) before storage.

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    assemble_sortedmulti, classify, extract_keys, guard_input, strip_master_prefix, MultisigScript,
    NormalizedWalletExport, WalletDescriptors,
};

/// Import a BlueWallet multisig vault export (PRD §17.9, §24.2).
///
/// `version` is the BlueWallet app version learned out-of-band (the file carries
/// none); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` when the content is not a recognizable multisig setup file
///   (missing `Policy:` / `Derivation:` / `Format:`, an unparseable policy, an
///   unsupported `Format:`, or a cosigner count that disagrees with the policy).
///   A well-formed file whose assembled descriptor merely fails to parse for a
///   non-secret reason is *tolerated* (kept raw; the analysis layer reports it).
/// - `E-PARSE-005` when a cosigner key carries private-key material.
pub fn import_bluewallet(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let mut policy: Option<String> = None;
    let mut derivation: Option<String> = None;
    let mut format: Option<String> = None;
    // (fingerprint, xpub) in file order — sortedmulti preserves written order.
    let mut cosigners: Vec<(String, String)> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Every meaningful line is `key: value` (a header field or a cosigner).
        let (key, value) = line.split_once(':').ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("multisig setup line is not `key: value`")
        })?;
        let (key, value) = (key.trim(), value.trim());

        if is_fingerprint(key) {
            cosigners.push((key.to_lowercase(), value.to_string()));
        } else {
            match key.to_ascii_lowercase().as_str() {
                "policy" => policy = Some(value.to_string()),
                "derivation" => derivation = Some(value.to_string()),
                "format" => format = Some(value.to_string()),
                // `Name:` and any other header field are accepted but unused.
                _ => {}
            }
        }
    }

    let policy = policy.ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig setup file has no Policy line")
    })?;
    let derivation = derivation.ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig setup file has no Derivation line")
    })?;
    let format = format.ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig setup file has no Format line")
    })?;

    let (m, n) = parse_policy(&policy)?;
    if cosigners.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig setup file has no cosigner keys"));
    }
    if cosigners.len() as u32 != n {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("cosigner count does not match the policy N"));
    }
    let script = parse_format(&format)?;

    // Build each `[fingerprint/origin-path]xpub` key (the Derivation line is the
    // shared BIP48 origin path for every cosigner).
    let origin_path = strip_master_prefix(&derivation);
    let keys: Vec<String> = cosigners
        .iter()
        .map(|(fp, xpub)| {
            if origin_path.is_empty() {
                format!("[{fp}]{xpub}")
            } else {
                format!("[{fp}/{origin_path}]{xpub}")
            }
        })
        .collect();

    let (receive, change, parsed) = assemble_sortedmulti(script, m, &keys)?;
    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "bluewallet".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys,
        // The multisig setup file carries no birth height/time (§24.2).
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

/// Whether `s` is an 8-character hex master fingerprint (vs. a header keyword).
fn is_fingerprint(s: &str) -> bool {
    s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a `Policy:` value (`"2 of 3"`) into `(M, N)`. Tolerant of surrounding
/// words/punctuation: the first two integers found are taken as `M` then `N`.
///
/// # Errors
/// `E-INPUT-003` when fewer than two integers are present or the quorum is not
/// `1 ≤ M ≤ N`.
fn parse_policy(value: &str) -> Result<(u32, u32), LifeboatError> {
    let nums: Vec<u32> = value
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse().ok())
        .collect();
    match nums.as_slice() {
        [m, n] if *m >= 1 && m <= n => Ok((*m, *n)),
        _ => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Policy line is not a valid `M of N`")),
    }
}

/// Map a `Format:` value to the multisig script wrapper.
///
/// # Errors
/// `E-INPUT-003` for a script type this importer does not assemble.
fn parse_format(value: &str) -> Result<MultisigScript, LifeboatError> {
    match value.to_ascii_uppercase().replace('_', "-").as_str() {
        "P2WSH" => Ok(MultisigScript::P2wsh),
        "P2SH-P2WSH" | "P2WSH-P2SH" => Ok(MultisigScript::P2shP2wsh),
        "P2SH" => Ok(MultisigScript::P2sh),
        _ => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("unsupported multisig Format")),
    }
}
