//! Electrum multisig importer (PRD §17.9, §24.2) — Tier-2 workaround.
//!
//! Electrum stores a multisig wallet as a JSON file whose cosigner keystores use
//! dynamic `x1/`, `x2/`, … keys and whose script type is encoded in each cosigner's
//! BIP48 derivation path — a shape that does not map cleanly onto the strict
//! `deny_unknown_fields` JSON recipe the other importers use. Electrum also has no
//! first-class output-descriptor export. So, like Coldcard's descriptor file, this
//! is a **Coldcard-style line-oriented text parser** over a documented Tier-2
//! workaround layout that carries Electrum's own vocabulary:
//!
//! ```text
//! # Electrum multisig wallet export (watch-only)
//! wallet_type: 2of3
//! [4ba43603/48'/1'/0'/2']tpub...
//! [6e37edb9/48'/1'/0'/2']tpub...
//! [8dfc9b34/48'/1'/0'/2']tpub...
//! ```
//!
//! `wallet_type: NofM` is Electrum's real quorum field (`"2of3"` ⇒ 2-of-3); each
//! remaining non-comment line is one cosigner key expression in standard
//! `[fingerprint/origin-path]xpub` form. The script type is inferred from the
//! shared BIP48 path's `script_type'` index (`2'` ⇒ P2WSH, `1'` ⇒ P2SH-P2WSH,
//! `0'` ⇒ P2SH; anything else defaults to P2WSH, the modern Electrum multisig
//! default). The receive/change descriptors are assembled with the shared
//! [`assemble_sortedmulti`](crate::assemble_sortedmulti) helper.
//!
//! ## Documented as a Tier-2 workaround
//! This is a best-effort import path; the user confirms a known address afterwards.
//! Only watch-only keys are read, and a key carrying private-key material is
//! refused (`E-PARSE-005`) before storage.

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    assemble_sortedmulti, classify, extract_keys, guard_input, MultisigScript,
    NormalizedWalletExport, WalletDescriptors,
};

/// Import an Electrum multisig wallet export (PRD §17.9, §24.2).
///
/// `version` is the Electrum version learned out-of-band (the file carries none);
/// pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` when the content has no `wallet_type:` line, an unparseable
///   `wallet_type`, no cosigner keys, or a key count that disagrees with the
///   declared `N`. A recognized file whose assembled descriptor fails to parse for
///   a non-secret reason is *tolerated* (kept raw; the analysis layer reports it).
/// - `E-PARSE-005` when a cosigner key carries private-key material.
pub fn import_electrum(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let mut wallet_type: Option<String> = None;
    let mut keys: Vec<String> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = strip_field(line, "wallet_type") {
            wallet_type = Some(rest.to_string());
        } else {
            // Every other non-comment line is one cosigner key expression.
            keys.push(line.to_string());
        }
    }

    let wallet_type = wallet_type.ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Electrum export has no wallet_type line")
    })?;
    let (m, n) = parse_wallet_type(&wallet_type)?;
    if keys.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Electrum export has no cosigner keys"));
    }
    if keys.len() as u32 != n {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("cosigner count does not match wallet_type N"));
    }

    let script = infer_bip48_script(&keys[0]);
    let (receive, change, parsed) = assemble_sortedmulti(script, m, &keys)?;
    let out_keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_kind, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "electrum".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys: out_keys,
        // Electrum's text export carries no birth height/time here (§24.2).
        birth_height: None,
        birth_timestamp: None,
        gap_limit: None,
        labels: Vec::new(),
        wallet_type: wallet_kind,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}

/// If `line` is `<field>: <value>` (case-insensitive on the field), return the
/// trimmed value. Used to pick out the `wallet_type:` header line.
fn strip_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    key.trim().eq_ignore_ascii_case(field).then(|| value.trim())
}

/// Parse Electrum's `wallet_type` (`"2of3"`) into `(M, N)`.
///
/// # Errors
/// `E-INPUT-003` when the value is not `<M>of<N>` with `1 ≤ M ≤ N`.
fn parse_wallet_type(value: &str) -> Result<(u32, u32), LifeboatError> {
    let err = || {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("wallet_type is not a valid `MofN` multisig quorum")
    };
    let (m, n) = value.split_once("of").ok_or_else(err)?;
    let m: u32 = m.trim().parse().map_err(|_| err())?;
    let n: u32 = n.trim().parse().map_err(|_| err())?;
    if m >= 1 && m <= n {
        Ok((m, n))
    } else {
        Err(err())
    }
}

/// Infer the multisig script type from a cosigner key's BIP48 origin path.
///
/// A BIP48 path is `m/48'/coin'/account'/script_type'`; the final hardened index
/// selects the script (`0'` P2SH, `1'` P2SH-P2WSH, `2'` P2WSH). Only a genuine
/// BIP48 origin (`48'` purpose, four hardened levels) is trusted; anything else
/// defaults to P2WSH (the modern Electrum multisig default).
fn infer_bip48_script(key: &str) -> MultisigScript {
    let origin = key
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(origin, _)| origin);
    let Some(origin) = origin else {
        return MultisigScript::P2wsh;
    };
    // origin = "fingerprint/48'/coin'/account'/script_type'"
    let segments: Vec<&str> = origin.split('/').collect();
    // [fingerprint, purpose, coin, account, script_type] = 5 segments for BIP48.
    if segments.len() == 5 && strip_hardened(segments[1]) == Some(48) {
        match strip_hardened(segments[4]) {
            Some(0) => MultisigScript::P2sh,
            Some(1) => MultisigScript::P2shP2wsh,
            _ => MultisigScript::P2wsh,
        }
    } else {
        MultisigScript::P2wsh
    }
}

/// Parse a hardened derivation index (`"48'"` or `"48h"`) into its number.
fn strip_hardened(segment: &str) -> Option<u32> {
    segment.trim_end_matches(['\'', 'h']).parse().ok()
}
