//! Nunchuk BSMS (BIP129) importer (PRD §17.9, §24.2).
//!
//! BSMS — Bitcoin Secure Multisig Setup ([BIP129]) — is the multisig coordination
//! format Nunchuk exports ("Wallet > More > Export wallet config > BSMS"). The
//! final "descriptor record" is a small line-oriented text file:
//!
//! ```text
//! BSMS 1.0
//! <descriptor template, using the /** multipath placeholder + a checksum>
//! <path restrictions, e.g. /0/*,/1/*>
//! <first address, for the user to verify>
//! ```
//!
//! The importer validates the `BSMS` version header, rewrites the descriptor
//! template's `/**` shorthand to `/<0;1>/*` (BIP129 defines them as equivalent),
//! and expands it into receive/change descriptors. The path-restrictions and
//! first-address lines are informational here — the first address is *not* verified
//! against the descriptor (that is the later known-address comparison step, which
//! does not require a network at import time); the importer makes no such claim.
//!
//! [BIP129]: https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    analyze_descriptor, classify, expand_receive_change, extract_keys, guard_input,
    normalize_multipath_shorthand, NormalizedWalletExport, WalletDescriptors,
};

/// Import a Nunchuk BSMS (BIP129) wallet config (PRD §17.9, §24.2).
///
/// `version` is the Nunchuk app version learned out-of-band (the BSMS `1.0` header
/// is the format-spec version, not the wallet version); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` when the content is not a valid BSMS record (missing the `BSMS`
///   version header, or no descriptor line). A descriptor that fails to parse for a
///   non-secret reason is *tolerated* (kept raw; the analysis layer reports it).
/// - `E-PARSE-005` when the descriptor template carries private-key material.
pub fn import_nunchuk_bsms(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    // BSMS is line-positional; collect the non-blank lines in order.
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    // Line 1 must be the BSMS version header (`BSMS <version>`). Accept any version
    // token (only 1.0 is defined today) but require the marker so a non-BSMS file
    // is rejected rather than misread.
    match lines.first() {
        Some(first) if first.split_whitespace().next() == Some("BSMS") => {}
        _ => {
            return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("not a BSMS record (missing BSMS version header)"))
        }
    }

    // Line 2 is the descriptor template (with the `/**` placeholder + checksum).
    let template = lines.get(1).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BSMS record has no descriptor template")
    })?;
    // Lines 3 (path restrictions) and 4 (first address) are informational; BSMS
    // wallets always restrict to /0/* and /1/*, which the `/**` expansion produces.

    // Rewrite the `/**` shorthand to `/<0;1>/*` (dropping the now-stale checksum),
    // then expand into receive/change with fresh checksums.
    let normalized = normalize_multipath_shorthand(template);
    let parsed = analyze_descriptor(&normalized)?;
    let (receive, change) = match &parsed {
        Some(p) => expand_receive_change(p)?,
        // A template that fails to parse for a non-secret reason is tolerated: keep
        // the (normalized) descriptor as the receive branch and let the analysis
        // layer report the parse failure.
        None => (normalized.clone(), None),
    };

    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "nunchuk".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys,
        // BSMS carries no wallet birth height/time (§24.2).
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
