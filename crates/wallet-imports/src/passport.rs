//! Foundation Passport Core descriptor-file importer (PRD §17.9, §24.2).
//!
//! Passport Core exports a watch-only output descriptor as a text file (and QR in
//! v0.3 — file only in the MVP). The file is the same shape Coldcard's descriptor
//! export uses: comment lines (`#…`) and blanks are ignored, a single line may be a
//! multipath descriptor (`<0;1>` or the `/**` shorthand) expanded into
//! receive/change, and two lines are taken as receive then change. The shared
//! [`parse_descriptor_file`](crate::parse_descriptor_file) helper does the parsing;
//! this importer only labels the result as `source_wallet = "passport"`.

use error_taxonomy::LifeboatError;

use crate::{
    classify, extract_keys, guard_input, parse_descriptor_file, NormalizedWalletExport,
    WalletDescriptors,
};

/// Import a Passport Core descriptor-file export (singlesig or multisig) (PRD §17.9).
///
/// `version` is the Passport firmware version learned out-of-band (it is not in the
/// file); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` when no descriptor line is present, or more than two are.
/// - `E-PARSE-005` when a descriptor carries private-key material.
pub fn import_passport(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;
    let (receive, change, parsed) = parse_descriptor_file(content)?;

    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "passport".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change,
        },
        keys,
        // Passport descriptor exports carry no birth or gap-limit hint (§24.2).
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
