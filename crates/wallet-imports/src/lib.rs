//! `wallet-imports` — wallet-export importers.
//!
//! Parses watch-only wallet exports (Bitcoin Core, Sparrow, Specter, Coldcard,
//! Nunchuk, Liana, Jade, Passport, plus the Tier-2 Electrum and BlueWallet
//! workarounds) into one shared [`NormalizedWalletExport`] (PRD §17.9, §19.3) that
//! the rest of the analyzer consumes. US-023 lands the shared type, the file
//! guards, and the Bitcoin Core `listdescriptors` importer; later stories
//! (US-024+) add the remaining wallets and, in US-027, the [`detect_format`] /
//! [`import_auto`] content-sniffing front door behind `parse-export --format auto`.
//!
//! ## Invariants
//! - **Size + format guards (§17.9).** Every importer rejects content larger
//!   than [`MAX_EXPORT_SIZE_BYTES`] before parsing, and parses with `serde_json`
//!   in strict mode (`deny_unknown_fields`) so unexpected input is refused, not
//!   silently accepted.
//! - **Never store secrets.** A descriptor carrying extended/raw private-key
//!   material is refused with `E-PARSE-005` *before* it can be stored in or
//!   surfaced from a [`NormalizedWalletExport`] (see [`analyze_descriptor`]).
//!   Other parse problems are tolerated: the raw descriptor is kept and the
//!   analysis layer reports them (e.g. `C-DESC-PARSE-FAIL`).
//! - **JS-boundary type.** [`NormalizedWalletExport`] crosses the Tauri→JS
//!   boundary (the `parse_wallet_export` command, §19.3), so it and its nested
//!   types are crate-owned `serde` types with `snake_case` fields — never
//!   rust-bitcoin types. Key origins, wallet type, and quorum are extracted by
//!   reusing `descriptor-audit` facts, then mapped into these owned types.
//! - **No clock.** The importer leaves [`NormalizedWalletExport::imported_at`]
//!   and [`raw_source_filename`](NormalizedWalletExport::raw_source_filename)
//!   unset (the caller — CLI US-036 / Tauri US-042 — stamps them), so importing
//!   is deterministic and testable.

use descriptor_audit::ParsedDescriptor;
use error_taxonomy::{ErrorCode, LifeboatError};

mod bitcoin_core;
mod bluewallet;
mod coldcard;
mod electrum;
mod jade;
mod liana;
mod nunchuk;
mod passport;
mod sparrow;
mod specter;
pub use bitcoin_core::import_bitcoin_core;
pub use bluewallet::import_bluewallet;
pub use coldcard::{import_coldcard_descriptor, import_coldcard_json};
pub use electrum::import_electrum;
pub use jade::import_jade;
pub use liana::import_liana_bed;
pub use nunchuk::import_nunchuk_bsms;
pub use passport::import_passport;
pub use sparrow::import_sparrow;
pub use specter::import_specter;

/// Maximum accepted wallet-export size, in bytes (PRD §17.9: files < 10 MB).
pub const MAX_EXPORT_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// The normalized result of importing any supported wallet export (PRD §19.3).
///
/// One importer per wallet produces this shared shape; downstream analysis reads
/// it without caring which wallet it came from. All fields are owned `serde`
/// types so the value can cross the Tauri→JS boundary unchanged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NormalizedWalletExport {
    /// The originating wallet, e.g. `"bitcoin_core"`, `"sparrow"`.
    pub source_wallet: String,
    /// The wallet software version, when known.
    pub source_wallet_version: Option<String>,
    /// RFC 3339 timestamp of import — set by the caller, not the importer.
    pub imported_at: Option<String>,
    /// The receive and (optional) change output descriptors.
    pub descriptors: WalletDescriptors,
    /// Per-key origin information extracted from the descriptor(s).
    pub keys: Vec<WalletKey>,
    /// Wallet birth block height, when the export provides one.
    pub birth_height: Option<u64>,
    /// Wallet birth time as an RFC 3339 UTC timestamp, when the export provides
    /// one (Bitcoin Core / Liana export a Unix time; Sparrow an ISO date).
    pub birth_timestamp: Option<String>,
    /// Address-gap limit, when the export provides one.
    pub gap_limit: Option<u32>,
    /// Address/transaction labels, when the export provides them.
    pub labels: Vec<WalletLabel>,
    /// `"singlesig"` or `"multisig"`, when determinable from the descriptor.
    pub wallet_type: Option<String>,
    /// Multisig threshold `M`, for `M`-of-`N` wallets.
    pub threshold: Option<u32>,
    /// Multisig key count `N`, for `M`-of-`N` wallets.
    pub key_count: Option<u32>,
    /// The source filename — set by the caller, not the importer.
    pub raw_source_filename: Option<String>,
}

/// The receive and (optional) change output descriptors of a wallet (PRD §19.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WalletDescriptors {
    /// The external/receive descriptor (Bitcoin Core `internal=false`).
    pub receive: Option<String>,
    /// The internal/change descriptor (Bitcoin Core `internal=true`).
    pub change: Option<String>,
}

/// Per-key origin information (PRD §19.3 `keys`, mirroring the §19.1 report
/// `keys[]` shape minus the report-layer redaction handled in US-030).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WalletKey {
    /// The key's position in the descriptor, counting from 0.
    pub index: u32,
    /// Master fingerprint as 8 lowercase hex characters, or `None` if absent.
    pub fingerprint: Option<String>,
    /// Origin derivation path in `m/84h/1h/0h` form, or `None` if absent.
    pub derivation_path: Option<String>,
    /// The extended public key (`xpub`/`tpub`/…), or `None` for a raw pubkey.
    pub xpub: Option<String>,
    /// Whether a complete origin (fingerprint **and** non-empty path) is present.
    pub key_origin_present: bool,
}

/// An address or transaction label carried by a wallet export (PRD §19.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalletLabel {
    /// The label target kind, e.g. `"addr"`, `"tx"`.
    #[serde(rename = "type")]
    pub label_type: String,
    /// The thing being labeled (an address, txid, …).
    #[serde(rename = "ref")]
    pub reference: String,
    /// The human-readable label text.
    pub label: String,
}

/// Reject empty or oversized export content before any parsing (PRD §17.9).
///
/// # Errors
/// `E-INPUT-001` when the content is blank; `E-INPUT-002` when it exceeds
/// [`MAX_EXPORT_SIZE_BYTES`].
pub(crate) fn guard_input(content: &str) -> Result<(), LifeboatError> {
    if content.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    if content.len() > MAX_EXPORT_SIZE_BYTES {
        return Err(LifeboatError::new(ErrorCode::InputTooLarge));
    }
    Ok(())
}

/// Parse a descriptor for analysis, refusing **only** private-key material.
///
/// Returns `Ok(Some(parsed))` on success and `Ok(None)` for a descriptor that
/// fails to parse for a *non-secret* reason — the raw descriptor is still stored
/// and the analysis layer reports the failure (`C-DESC-PARSE-FAIL`). Returns
/// `Err` exclusively when the descriptor carries extended/raw private keys
/// (`E-PARSE-005`), which must never be stored in or surfaced from an export.
pub(crate) fn analyze_descriptor(desc: &str) -> Result<Option<ParsedDescriptor>, LifeboatError> {
    match descriptor_audit::parse_descriptor(desc) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(e) if e.code() == ErrorCode::ContainsPrivateKey => Err(e),
        Err(_) => Ok(None),
    }
}

/// Map a parsed descriptor's key origins into the owned [`WalletKey`] list.
pub(crate) fn extract_keys(parsed: &ParsedDescriptor) -> Vec<WalletKey> {
    parsed
        .key_origins()
        .into_iter()
        .map(|ko| WalletKey {
            index: ko.index() as u32,
            fingerprint: ko.fingerprint_hex(),
            derivation_path: if ko.has_derivation_path() {
                ko.derivation_path_display()
            } else {
                None
            },
            xpub: ko.xpub().map(str::to_owned),
            key_origin_present: ko.key_origin_present(),
        })
        .collect()
}

/// Classify a parsed descriptor's wallet type and quorum (PRD §19.3).
///
/// Returns `(wallet_type, threshold, key_count)`: `"multisig"` with `M`/`N` for
/// multisig, `"singlesig"` with no quorum for singlesig, `"timelock"` for
/// supported Liana-style Miniscript policies, and all-`None` for a shape this
/// importer layer does not yet classify (such as Taproot key-path).
pub(crate) fn classify(parsed: &ParsedDescriptor) -> (Option<String>, Option<u32>, Option<u32>) {
    if let Some(ms) = parsed.multisig_info() {
        (
            Some("multisig".to_string()),
            Some(ms.threshold() as u32),
            Some(ms.key_count() as u32),
        )
    } else if parsed.is_singlesig() {
        (Some("singlesig".to_string()), None, None)
    } else if parsed.uses_timelock() {
        (Some("timelock".to_string()), None, None)
    } else {
        (None, None, None)
    }
}

/// Strip a leading `m/` (or bare `m`) master marker from a derivation path,
/// leaving the origin path used inside a descriptor's `[fingerprint/path]`. Shared
/// by the keystore-/account-based assemblers (Sparrow, Coldcard).
pub(crate) fn strip_master_prefix(path: &str) -> &str {
    let path = path.trim();
    if path == "m" || path == "M" {
        return "";
    }
    path.strip_prefix("m/")
        .or_else(|| path.strip_prefix("M/"))
        .unwrap_or(path)
}

/// Normalize the `/**` multipath shorthand (used by BIP129 BSMS and some Coldcard
/// descriptor exports) to the BIP389 `/<0;1>/*` form rust-miniscript parses.
///
/// `/**` is defined as equivalent to `/<0;1>/*`. A `#checksum` on a `/**` template
/// is computed over the shorthand and is invalidated by the rewrite, so any trailing
/// checksum is dropped — [`expand_receive_change`] recomputes a fresh checksum on
/// each expanded branch. A descriptor that does not use `/**` is returned trimmed
/// and otherwise unchanged (its checksum, if present, stays valid).
pub(crate) fn normalize_multipath_shorthand(descriptor: &str) -> String {
    let d = descriptor.trim();
    if d.contains("/**") {
        let body = d.split_once('#').map_or(d, |(body, _)| body);
        body.replace("/**", "/<0;1>/*")
    } else {
        d.to_string()
    }
}

/// Expand a parsed descriptor into its receive (`/0/*`) and change (`/1/*`)
/// single-path descriptor strings, each carrying a freshly computed BIP380
/// checksum.
///
/// A BIP389 multipath (`<0;1>`) descriptor yields both branches in written order —
/// index 0 is receive, index 1 is change (US-009). A single-path descriptor yields
/// `(itself, None)`. Reused by the importers whose source is one multipath
/// descriptor (Coldcard descriptor file, Nunchuk BSMS).
pub(crate) fn expand_receive_change(
    parsed: &ParsedDescriptor,
) -> Result<(String, Option<String>), LifeboatError> {
    let mut branches = parsed.expand_multipath()?.into_iter();
    let receive = branches
        .next()
        .ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("descriptor expanded to no derivation branches")
        })?
        .to_string();
    let change = branches.next().map(|d| d.to_string());
    Ok((receive, change))
}

/// The script wrapper of an `M`-of-`N` multisig descriptor (PRD §17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MultisigScript {
    /// Native segwit `wsh(sortedmulti(…))` (BIP48 `script_type` `2'`).
    P2wsh,
    /// Nested segwit `sh(wsh(sortedmulti(…)))` (BIP48 `script_type` `1'`).
    P2shP2wsh,
    /// Legacy `sh(sortedmulti(…))` (BIP48 `script_type` `0'`).
    P2sh,
}

/// Assemble an `M`-of-`N` `sortedmulti` descriptor from cosigner key expressions,
/// returning the expanded `(receive, change, parsed)` triple.
///
/// `keys` are `[fingerprint/origin-path]xpub` expressions in cosigner order (the
/// caller is responsible for that order; `sortedmulti` preserves the written
/// order). A BIP389 multipath `<0;1>` body is assembled, any SLIP-132 keys are
/// normalized to `xpub`/`tpub`, a fresh BIP380 checksum is computed, and the
/// descriptor is expanded into its receive (`/0/*`) and change (`/1/*`) branches.
/// Shared by the multisig setup-file importers (BlueWallet, Electrum).
///
/// # Errors
/// `E-PARSE-005` when a key carries private-key material (refused before storage);
/// `E-PARSE-001` / `E-INPUT-*` if checksum computation rejects the body. A
/// descriptor that fails to parse for any other reason is *tolerated*: `parsed` is
/// `None` and the multipath body is returned as the receive branch.
pub(crate) fn assemble_sortedmulti(
    script: MultisigScript,
    threshold: u32,
    keys: &[String],
) -> Result<(String, Option<String>, Option<ParsedDescriptor>), LifeboatError> {
    let multipath_keys: Vec<String> = keys.iter().map(|k| format!("{k}/<0;1>/*")).collect();
    let inner = format!("sortedmulti({threshold},{})", multipath_keys.join(","));
    let body = match script {
        MultisigScript::P2wsh => format!("wsh({inner})"),
        MultisigScript::P2shP2wsh => format!("sh(wsh({inner}))"),
        MultisigScript::P2sh => format!("sh({inner})"),
    };
    // Normalize any SLIP-132 keys (Vpub/Upub/… → tpub/xpub) and (re)compute the
    // BIP380 checksum over the assembled body.
    let normalized = descriptor_audit::normalize_slip132(&body)?;
    let multipath = descriptor_audit::compute_checksum(normalized.descriptor())?;

    let parsed = analyze_descriptor(&multipath)?;
    match &parsed {
        Some(p) => {
            let (receive, change) = expand_receive_change(p)?;
            Ok((receive, change, parsed))
        }
        // Tolerate a non-secret parse failure: keep the multipath body as receive.
        None => Ok((multipath, None, parsed)),
    }
}

/// Parse a text descriptor-file export into receive / optional-change / parsed
/// descriptor. Shared by the descriptor-file importers (Coldcard descriptor file,
/// Passport). Comment lines (`#…`) and blanks are dropped, the `/**` multipath
/// shorthand is normalized, then: one line is taken as a descriptor (a multipath one
/// expands into receive/change, a single-path one is the receive branch as written),
/// and two lines are taken as receive then change. Assumes [`guard_input`] has run.
///
/// Refuses private-key material in any line (`E-PARSE-005`); a descriptor that fails
/// to parse for a non-secret reason is tolerated (kept raw, `parsed` is `None`).
///
/// # Errors
/// `E-INPUT-003` when no descriptor line is present, or more than two are.
pub(crate) fn parse_descriptor_file(
    content: &str,
) -> Result<(String, Option<String>, Option<ParsedDescriptor>), LifeboatError> {
    let lines: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(normalize_multipath_shorthand)
        .collect();

    match lines.as_slice() {
        [] => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("descriptor file contains no descriptor")),
        [only] => {
            // One line: a multipath descriptor expands into receive/change; a
            // single-path descriptor is the receive branch as written.
            let parsed = analyze_descriptor(only)?;
            match &parsed {
                Some(p) if p.uses_multipath() => {
                    let (receive, change) = expand_receive_change(p)?;
                    Ok((receive, change, parsed))
                }
                _ => Ok((only.clone(), None, parsed)),
            }
        }
        [recv, chg] => {
            // Two lines: explicit receive then change. Refuse private material in
            // both; key origins come from the receive descriptor.
            let parsed = analyze_descriptor(recv)?;
            analyze_descriptor(chg)?;
            Ok((recv.clone(), Some(chg.clone()), parsed))
        }
        _ => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("descriptor file has more than two descriptor lines")),
    }
}

/// Convert a Unix timestamp (seconds since the epoch) to an RFC 3339 / ISO 8601
/// UTC string, `YYYY-MM-DDTHH:MM:SSZ`. Deterministic and dependency-free.
pub(crate) fn unix_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Howard Hinnant's `civil_from_days` algorithm (public domain): convert a day
/// count relative to 1970-01-01 into `(year, month, day)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (year + i64::from(month <= 2), month as u32, day)
}

/// Threshold separating an epoch in **seconds** from one in **milliseconds**.
/// `1e11` seconds is the year 5138, and `1e11` ms is 1973-03 — so any realistic
/// wallet birth time (≥ 2009) is below this as seconds and above it as ms.
const EPOCH_MILLIS_THRESHOLD: i64 = 100_000_000_000;

/// Interpret a JSON birth-time value as an RFC 3339 / ISO 8601 UTC string.
///
/// Accepts a number (Unix epoch in seconds **or** milliseconds — Sparrow exports
/// a Java `Date`, i.e. milliseconds) or a string (an integer epoch, or a value
/// that already looks like an ISO 8601 date/datetime, which is passed through).
/// Returns `None` for anything that is neither, so `birth_timestamp` is always an
/// ISO string or absent — never an opaque locale-formatted date. Reusable by any
/// importer carrying an epoch birth time (Liana).
pub(crate) fn epoch_value_to_iso8601(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => n.as_i64().map(epoch_to_iso8601),
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else if let Ok(raw) = trimmed.parse::<i64>() {
                Some(epoch_to_iso8601(raw))
            } else if looks_like_iso8601_date(trimmed) {
                Some(trimmed.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Convert a Unix epoch that may be in seconds or milliseconds to an ISO 8601
/// UTC string, normalizing milliseconds down to seconds first.
fn epoch_to_iso8601(raw: i64) -> String {
    let secs = if raw.abs() >= EPOCH_MILLIS_THRESHOLD {
        raw / 1000
    } else {
        raw
    };
    unix_to_iso8601(secs)
}

/// Minimal structural check that a string opens with an ISO 8601 calendar date
/// (`YYYY-MM-DD…`). Used only to decide whether to pass a string birth time
/// through unchanged; full validation is unnecessary (downstream never parses it).
fn looks_like_iso8601_date(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 10
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
}

/// Extract the major version from a Bitcoin Core version string. Accepts a plain
/// `"30.0.0"` / `"v30.1"` and the RPC `getnetworkinfo.subversion` form
/// `"/Satoshi:30.0.0/"`. Returns `None` when no leading integer is found.
pub(crate) fn core_major_version(version: &str) -> Option<u32> {
    let tail = version.rsplit(':').next().unwrap_or(version);
    let digits: String = tail
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(|c: &char| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// A wallet-export format recognized by [`detect_format`] (PRD §17.9, §24.2).
///
/// This is the set of formats the content sniffer can identify *unambiguously*.
/// The Coldcard descriptor-file and Passport exports are the same text shape
/// (both parsed by [`parse_descriptor_file`]), so they share one
/// [`DescriptorFile`](WalletFormat::DescriptorFile) variant — auto-detect cannot,
/// and need not, tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletFormat {
    /// Bitcoin Core `listdescriptors` JSON.
    BitcoinCore,
    /// Sparrow keystore-based wallet JSON.
    Sparrow,
    /// Specter wallet-settings JSON.
    Specter,
    /// Blockstream Jade registered-multisig JSON.
    Jade,
    /// Liana `.bed` encrypted-descriptor JSON envelope.
    Liana,
    /// Coldcard Generic Wallet Export JSON (singlesig).
    ColdcardJson,
    /// A descriptor-file text export (Coldcard descriptor file / Passport).
    DescriptorFile,
    /// Nunchuk BSMS (BIP129) text record.
    NunchukBsms,
    /// Electrum multisig text export (Tier-2 workaround).
    Electrum,
    /// BlueWallet multisig vault text export (Tier-2 workaround).
    BlueWallet,
}

impl WalletFormat {
    /// A stable lowercase identifier (`"bitcoin_core"`, `"electrum"`, …), suitable
    /// for a `--format` argument or a `source_wallet` label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WalletFormat::BitcoinCore => "bitcoin_core",
            WalletFormat::Sparrow => "sparrow",
            WalletFormat::Specter => "specter",
            WalletFormat::Jade => "jade",
            WalletFormat::Liana => "liana",
            WalletFormat::ColdcardJson => "coldcard_json",
            WalletFormat::DescriptorFile => "descriptor_file",
            WalletFormat::NunchukBsms => "nunchuk_bsms",
            WalletFormat::Electrum => "electrum",
            WalletFormat::BlueWallet => "bluewallet",
        }
    }
}

/// Identify a wallet export's format by sniffing its content (PRD §17.9; backs
/// `parse-export --format auto` in the CLI, US-036).
///
/// JSON exports are distinguished by their unique top-level keys; text exports by
/// their structural markers (a `BSMS` header, an Electrum `wallet_type:` line, a
/// `Policy:`/`Format:` multisig setup file, or a leading output descriptor). The
/// sniff is conservative: a buffer that matches no known signature is rejected so
/// the caller never feeds an unrecognized file to the wrong parser.
///
/// # Errors
/// `E-INPUT-001` / `E-INPUT-002` for empty / oversized content;
/// `E-INPUT-003` when the content matches no recognized format.
pub fn detect_format(content: &str) -> Result<WalletFormat, LifeboatError> {
    guard_input(content)?;
    let trimmed = content.trim_start();

    if trimmed.starts_with('{') {
        return detect_json_format(content);
    }
    detect_text_format(content)
}

/// Sniff a JSON export by its unique top-level keys. Keys are matched with their
/// surrounding quotes so `"descriptor"` never matches `"descriptors"`.
fn detect_json_format(content: &str) -> Result<WalletFormat, LifeboatError> {
    let has = |key: &str| content.contains(key);
    let format = if has("\"liana_backup_version\"") || (has("\"recipients\"") && has("\"payload\""))
    {
        WalletFormat::Liana
    } else if has("\"policyType\"") && has("\"keystores\"") {
        WalletFormat::Sparrow
    } else if has("\"multisig_name\"") || has("\"signers\"") {
        WalletFormat::Jade
    } else if has("\"devices\"") && has("\"descriptor\"") {
        WalletFormat::Specter
    } else if has("\"descriptors\"") {
        WalletFormat::BitcoinCore
    } else if has("\"xfp\"") {
        WalletFormat::ColdcardJson
    } else {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("unrecognized JSON wallet export"));
    };
    Ok(format)
}

/// Output-descriptor function prefixes that start a descriptor-file text line.
const DESCRIPTOR_PREFIXES: [&str; 8] = [
    "pkh(", "wpkh(", "sh(", "wsh(", "tr(", "combo(", "addr(", "raw(",
];

/// Sniff a non-JSON (text) export by its structural markers.
fn detect_text_format(content: &str) -> Result<WalletFormat, LifeboatError> {
    // Meaningful (non-blank, non-comment) lines, trimmed.
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if lines
        .iter()
        .any(|l| l.split_whitespace().next() == Some("BSMS"))
    {
        return Ok(WalletFormat::NunchukBsms);
    }
    if lines.iter().any(|l| {
        l.split_once(':')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("wallet_type"))
    }) {
        return Ok(WalletFormat::Electrum);
    }
    let field = |name: &str| {
        lines.iter().any(|l| {
            l.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        })
    };
    if field("policy") && field("format") {
        return Ok(WalletFormat::BlueWallet);
    }
    if lines
        .iter()
        .any(|l| DESCRIPTOR_PREFIXES.iter().any(|p| l.starts_with(p)))
    {
        return Ok(WalletFormat::DescriptorFile);
    }
    Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
        .with_context("unrecognized wallet export"))
}

/// Detect a wallet export's format and import it with default options (PRD §17.9;
/// the `parse-export --format auto` path, US-036).
///
/// A convenience wrapper over [`detect_format`] for the formats that need no
/// out-of-band input. Formats that require extra arguments are still routed by
/// detection but cannot be auto-imported here: a Liana `.bed` needs the user's
/// decryption xpubs, so it returns `E-INPUT-003` directing the caller to
/// [`import_liana_bed`] (version/`.sig`/decryption inputs are supplied by the CLI
/// when the format is given explicitly).
///
/// # Errors
/// Whatever [`detect_format`] or the selected importer returns.
pub fn import_auto(content: &str) -> Result<NormalizedWalletExport, LifeboatError> {
    match detect_format(content)? {
        WalletFormat::BitcoinCore => import_bitcoin_core(content, None),
        WalletFormat::Sparrow => import_sparrow(content, None),
        WalletFormat::Specter => import_specter(content, None),
        WalletFormat::Jade => import_jade(content, None),
        WalletFormat::ColdcardJson => import_coldcard_json(content, None),
        WalletFormat::DescriptorFile => import_coldcard_descriptor(content, None, None),
        WalletFormat::NunchukBsms => import_nunchuk_bsms(content, None),
        WalletFormat::Electrum => import_electrum(content, None),
        WalletFormat::BlueWallet => import_bluewallet(content, None),
        WalletFormat::Liana => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Liana .bed requires decryption inputs; import it explicitly")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/bitcoin_core_listdescriptors.json"
    ));
    const XPRV_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/invalid/contains_xprv.txt"
    ));
    // The receive descriptor inside CORE_FIXTURE (also fixtures/.../wpkh_valid.txt).
    const RECEIVE_DESC: &str = "wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/0/*)#r6yctejg";

    #[test]
    fn bitcoin_core_good_import() {
        let e = import_bitcoin_core(CORE_FIXTURE, Some("29.0.0")).unwrap();
        assert_eq!(e.source_wallet, "bitcoin_core");
        assert_eq!(e.source_wallet_version.as_deref(), Some("29.0.0"));
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
        assert_eq!(e.threshold, None);
        assert_eq!(e.key_count, None);
        assert!(e.descriptors.receive.as_deref().unwrap().contains("/0/*"));
        assert!(e.descriptors.change.as_deref().unwrap().contains("/1/*"));
        // Latest active timestamp 1705276800 → 2024-01-15T00:00:00Z (§17.12).
        assert_eq!(e.birth_timestamp.as_deref(), Some("2024-01-15T00:00:00Z"));
        assert_eq!(e.birth_height, None);
        // Caller-set fields stay unset by the importer.
        assert!(e.imported_at.is_none());
        assert!(e.raw_source_filename.is_none());
        assert!(e.labels.is_empty());
        // Key origin extracted from the descriptor.
        assert_eq!(e.keys.len(), 1);
        let k = &e.keys[0];
        assert_eq!(k.index, 0);
        assert_eq!(k.fingerprint.as_deref(), Some("71348c8a"));
        assert_eq!(k.derivation_path.as_deref(), Some("m/84h/1h/0h"));
        assert!(k.xpub.as_deref().unwrap().starts_with("tpub"));
        assert!(k.key_origin_present);
    }

    #[test]
    fn accepts_29x_and_unknown_version() {
        assert!(import_bitcoin_core(CORE_FIXTURE, Some("29.0.0")).is_ok());
        assert!(import_bitcoin_core(CORE_FIXTURE, Some("/Satoshi:29.0.0/")).is_ok());
        assert!(import_bitcoin_core(CORE_FIXTURE, None).is_ok());
        // A future major (31.x) is not the rejected 30.x line.
        assert!(import_bitcoin_core(CORE_FIXTURE, Some("31.0.0")).is_ok());
        // Without a version, source_wallet_version is unknown.
        assert_eq!(
            import_bitcoin_core(CORE_FIXTURE, None)
                .unwrap()
                .source_wallet_version,
            None
        );
    }

    #[test]
    fn rejects_bitcoin_core_30x() {
        let expected = "Bitcoin Core 30.x has known wallet bugs; please use 29.x or wait for 30.2+";
        for v in ["30.0.0", "30.1", "v30.0.0", "/Satoshi:30.1.0/"] {
            let err = import_bitcoin_core(CORE_FIXTURE, Some(v)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InputInvalidFormat, "version {v}");
            assert_eq!(err.context(), Some(expected), "version {v}");
        }
    }

    #[test]
    fn rejects_oversize_before_parsing() {
        let big = "x".repeat(MAX_EXPORT_SIZE_BYTES + 1);
        let err = import_bitcoin_core(&big, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InputTooLarge);
        // Exactly at the limit is not rejected for size (it fails to parse instead).
        let at_limit = "x".repeat(MAX_EXPORT_SIZE_BYTES);
        assert_eq!(
            import_bitcoin_core(&at_limit, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn rejects_empty_and_malformed() {
        assert_eq!(
            import_bitcoin_core("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_bitcoin_core("   \n ", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_bitcoin_core("{not json", None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // deny_unknown_fields rejects an unexpected top-level key.
        assert_eq!(
            import_bitcoin_core(r#"{"descriptors":[],"surprise":1}"#, None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn inactive_descriptors_are_ignored() {
        let json = format!(
            r#"{{"descriptors":[{{"desc":"{RECEIVE_DESC}","timestamp":1705276800,"active":false,"internal":false}}]}}"#
        );
        let e = import_bitcoin_core(&json, None).unwrap();
        assert!(e.descriptors.receive.is_none());
        assert!(e.descriptors.change.is_none());
        assert!(e.keys.is_empty());
        // Birth hint is derived from active entries only.
        assert!(e.birth_timestamp.is_none());
        assert_eq!(e.wallet_type, None);
    }

    #[test]
    fn timestamp_now_is_not_a_birth_hint() {
        // A freshly created descriptor has timestamp "now" (a string, not a Unix
        // time); it must not crash parsing and yields no birth hint.
        let json = format!(
            r#"{{"descriptors":[{{"desc":"{RECEIVE_DESC}","timestamp":"now","active":true,"internal":false}}]}}"#
        );
        let e = import_bitcoin_core(&json, None).unwrap();
        assert!(e.descriptors.receive.is_some());
        assert!(e.birth_timestamp.is_none());
    }

    #[test]
    fn refuses_descriptor_with_private_key() {
        // A `listdescriptors true` export contains xprv; it must be refused with
        // E-PARSE-005 before any NormalizedWalletExport is built.
        let json = format!(
            r#"{{"descriptors":[{{"desc":"{}","timestamp":1,"active":true,"internal":false}}]}}"#,
            XPRV_FIXTURE.trim()
        );
        let err = import_bitcoin_core(&json, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContainsPrivateKey);
    }

    #[test]
    fn json_shape_is_snake_case() {
        let v = serde_json::to_value(import_bitcoin_core(CORE_FIXTURE, Some("29.0.0")).unwrap())
            .unwrap();
        assert_eq!(v["source_wallet"], "bitcoin_core");
        assert_eq!(v["source_wallet_version"], "29.0.0");
        assert!(v["imported_at"].is_null());
        assert!(v["descriptors"]["receive"]
            .as_str()
            .unwrap()
            .contains("/0/*"));
        assert!(v["descriptors"]["change"]
            .as_str()
            .unwrap()
            .contains("/1/*"));
        assert_eq!(v["keys"][0]["fingerprint"], "71348c8a");
        assert_eq!(v["keys"][0]["derivation_path"], "m/84h/1h/0h");
        assert_eq!(v["keys"][0]["key_origin_present"], true);
        assert_eq!(v["birth_timestamp"], "2024-01-15T00:00:00Z");
        assert!(v["birth_height"].is_null());
        assert!(v["threshold"].is_null());
        assert_eq!(v["wallet_type"], "singlesig");
        assert!(v["labels"].as_array().unwrap().is_empty());
        assert!(v["raw_source_filename"].is_null());
    }

    #[test]
    fn unix_to_iso8601_known_vectors() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(1_705_276_800), "2024-01-15T00:00:00Z");
        // Bitcoin genesis block timestamp.
        assert_eq!(unix_to_iso8601(1_231_006_505), "2009-01-03T18:15:05Z");
        assert_eq!(unix_to_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn core_major_version_parsing() {
        assert_eq!(core_major_version("30.0.0"), Some(30));
        assert_eq!(core_major_version("29.0.0"), Some(29));
        assert_eq!(core_major_version("v30.1"), Some(30));
        assert_eq!(core_major_version("/Satoshi:30.0.0/"), Some(30));
        assert_eq!(core_major_version("/Satoshi:29.0.0/"), Some(29));
        assert_eq!(core_major_version("31.2"), Some(31));
        assert_eq!(core_major_version(""), None);
        assert_eq!(core_major_version("unknown"), None);
    }

    #[test]
    fn guard_input_rejects_empty_then_oversize() {
        assert_eq!(guard_input("").unwrap_err().code(), ErrorCode::InputEmpty);
        let big = "x".repeat(MAX_EXPORT_SIZE_BYTES + 1);
        assert_eq!(
            guard_input(&big).unwrap_err().code(),
            ErrorCode::InputTooLarge
        );
        assert!(guard_input("{}").is_ok());
    }

    // ---- US-024: Sparrow and Specter importers ----

    const SPARROW_SINGLESIG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/sparrow_singlesig.json"
    ));
    const SPARROW_MULTISIG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/sparrow_multisig.json"
    ));
    const SPECTER_MULTISIG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/specter_multisig.json"
    ));
    // The known-good receive descriptors the importers must (re)produce.
    const WPKH_RECEIVE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
    ));
    const WSH_2OF3_RECEIVE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt"
    ));

    #[test]
    fn sparrow_singlesig_import() {
        let e = import_sparrow(SPARROW_SINGLESIG, Some("2.5.1")).unwrap();
        assert_eq!(e.source_wallet, "sparrow");
        assert_eq!(e.source_wallet_version.as_deref(), Some("2.5.1"));
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
        assert_eq!(e.threshold, None);
        assert_eq!(e.key_count, None);
        // The receive branch the importer reconstructs from the keystore is
        // byte-identical to the canonical wpkh fixture (same key + BIP380 checksum).
        assert_eq!(e.descriptors.receive.as_deref(), Some(WPKH_RECEIVE.trim()));
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(descriptor_audit::parse_descriptor(change).is_ok());
        // birthDate (epoch ms) → ISO 8601; gapLimit carries through; no height.
        assert_eq!(e.birth_timestamp.as_deref(), Some("2024-01-15T00:00:00Z"));
        assert_eq!(e.birth_height, None);
        assert_eq!(e.gap_limit, Some(20));
        // Key origin reconstructed from the keystore.
        assert_eq!(e.keys.len(), 1);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("71348c8a"));
        assert_eq!(e.keys[0].derivation_path.as_deref(), Some("m/84h/1h/0h"));
        assert!(e.keys[0].xpub.as_deref().unwrap().starts_with("tpub"));
        assert!(e.keys[0].key_origin_present);
        // Caller-set fields stay unset by the importer.
        assert!(e.imported_at.is_none());
        assert!(e.raw_source_filename.is_none());
    }

    #[test]
    fn sparrow_multisig_import_assembles_known_descriptor() {
        let e = import_sparrow(SPARROW_MULTISIG, None).unwrap();
        assert_eq!(e.source_wallet, "sparrow");
        assert_eq!(e.source_wallet_version, None);
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // The reconstructed receive descriptor matches the committed 2-of-3 fixture
        // byte-for-byte — proof the keystore→descriptor assembly is correct.
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(descriptor_audit::parse_descriptor(change).is_ok());
        assert_eq!(e.birth_height, Some(815_000));
        assert_eq!(e.birth_timestamp.as_deref(), Some("2024-01-15T00:00:00Z"));
        assert_eq!(e.gap_limit, Some(20));
        // Three key origins, in keystore order.
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[1].fingerprint.as_deref(), Some("6e37edb9"));
        assert_eq!(e.keys[2].fingerprint.as_deref(), Some("8dfc9b34"));
        assert_eq!(e.keys[0].derivation_path.as_deref(), Some("m/48h/1h/0h/2h"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
    }

    #[test]
    fn sparrow_rejects_empty_malformed_and_unsupported() {
        assert_eq!(
            import_sparrow("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_sparrow("{not json", None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // deny_unknown_fields rejects an unexpected top-level key.
        let surprise = r#"{"policyType":"SINGLE","scriptType":"P2WPKH","defaultPolicy":{"numSignaturesRequired":1},"keystores":[],"surprise":1}"#;
        assert_eq!(
            import_sparrow(surprise, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // No keystores is a typed error, not a panic.
        let empty_ks = r#"{"policyType":"SINGLE","scriptType":"P2WPKH","defaultPolicy":{"numSignaturesRequired":1},"keystores":[]}"#;
        assert_eq!(
            import_sparrow(empty_ks, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // An unsupported policy/script combination (e.g. a CUSTOM miniscript
        // policy) is refused with a typed error rather than mis-assembled.
        let custom = r#"{"policyType":"CUSTOM","scriptType":"P2WSH","defaultPolicy":{"numSignaturesRequired":2},"keystores":[{"keyDerivation":{"masterFingerprint":"4ba43603","derivationPath":"m/48'/1'/0'/2'"},"extendedPublicKey":"tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz"}]}"#;
        assert_eq!(
            import_sparrow(custom, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn sparrow_refuses_keystore_with_private_material() {
        // A non-watch-only Sparrow export carries a `seed` (or
        // `masterPrivateExtendedKey`); strict parsing refuses it rather than ever
        // deserializing secret material (the field is intentionally undeclared).
        let with_seed = r#"{"policyType":"SINGLE","scriptType":"P2WPKH","defaultPolicy":{"numSignaturesRequired":1},"keystores":[{"keyDerivation":{"masterFingerprint":"71348c8a","derivationPath":"m/84'/1'/0'"},"extendedPublicKey":"tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L","seed":{"type":"BIP39"}}]}"#;
        assert_eq!(
            import_sparrow(with_seed, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn sparrow_json_shape_is_snake_case() {
        let v = serde_json::to_value(import_sparrow(SPARROW_MULTISIG, None).unwrap()).unwrap();
        assert_eq!(v["source_wallet"], "sparrow");
        assert_eq!(v["wallet_type"], "multisig");
        assert_eq!(v["threshold"], 2);
        assert_eq!(v["key_count"], 3);
        assert_eq!(v["birth_height"], 815_000);
        assert_eq!(v["birth_timestamp"], "2024-01-15T00:00:00Z");
        assert_eq!(v["gap_limit"], 20);
        assert!(v["descriptors"]["receive"]
            .as_str()
            .unwrap()
            .contains("/0/*"));
        assert!(v["descriptors"]["change"]
            .as_str()
            .unwrap()
            .contains("/1/*"));
        assert_eq!(v["keys"][0]["fingerprint"], "4ba43603");
        assert_eq!(v["keys"][0]["derivation_path"], "m/48h/1h/0h/2h");
    }

    #[test]
    fn specter_multisig_import() {
        let e = import_specter(SPECTER_MULTISIG, Some("2.1.0")).unwrap();
        assert_eq!(e.source_wallet, "specter");
        assert_eq!(e.source_wallet_version.as_deref(), Some("2.1.0"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // Specter exports only the receive descriptor (no change branch, #2494).
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        assert!(e.descriptors.change.is_none());
        // blockheight → birth_height; Specter carries no birth timestamp.
        assert_eq!(e.birth_height, Some(2_500_000));
        assert!(e.birth_timestamp.is_none());
        assert_eq!(e.gap_limit, None);
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[2].fingerprint.as_deref(), Some("8dfc9b34"));
        assert!(e.imported_at.is_none());
    }

    #[test]
    fn specter_rejects_empty_and_malformed() {
        assert_eq!(
            import_specter("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_specter("{not json", None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // deny_unknown_fields rejects an unexpected key.
        let surprise = r#"{"descriptor":"wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/0/*)#r6yctejg","surprise":1}"#;
        assert_eq!(
            import_specter(surprise, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn specter_refuses_descriptor_with_private_key() {
        // A descriptor carrying xprv is refused with E-PARSE-005 before any
        // normalized value is built.
        let json = format!(
            r#"{{"descriptor":"{}","blockheight":0}}"#,
            XPRV_FIXTURE.trim()
        );
        assert_eq!(
            import_specter(&json, None).unwrap_err().code(),
            ErrorCode::ContainsPrivateKey
        );
    }

    #[test]
    fn epoch_value_to_iso8601_forms() {
        use serde_json::json;
        // Java Date milliseconds and Unix seconds both normalize to the same ISO.
        assert_eq!(
            epoch_value_to_iso8601(&json!(1_705_276_800_000i64)).as_deref(),
            Some("2024-01-15T00:00:00Z")
        );
        assert_eq!(
            epoch_value_to_iso8601(&json!(1_705_276_800i64)).as_deref(),
            Some("2024-01-15T00:00:00Z")
        );
        // An integer encoded as a string, and an already-ISO string, both work.
        assert_eq!(
            epoch_value_to_iso8601(&json!("1705276800000")).as_deref(),
            Some("2024-01-15T00:00:00Z")
        );
        assert_eq!(
            epoch_value_to_iso8601(&json!("2024-01-15T00:00:00Z")).as_deref(),
            Some("2024-01-15T00:00:00Z")
        );
        // Non-date strings, empty strings, and other types yield no timestamp.
        assert!(epoch_value_to_iso8601(&json!("someday")).is_none());
        assert!(epoch_value_to_iso8601(&json!("")).is_none());
        assert!(epoch_value_to_iso8601(&json!(true)).is_none());
    }

    // ---- US-025: Coldcard (generic JSON + descriptor file) and Nunchuk (BSMS) ----

    const COLDCARD_GENERIC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/coldcard_generic.json"
    ));
    const COLDCARD_DESCRIPTOR: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/coldcard_descriptor.txt"
    ));
    const NUNCHUK_BSMS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/nunchuk_bsms.txt"
    ));
    // Known-good receive descriptors the assemblers/expansions must (re)produce.
    const PKH_RECEIVE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/singlesig/pkh_valid.txt"
    ));
    const SH_WPKH_RECEIVE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/descriptors/singlesig/sh_wpkh_valid.txt"
    ));
    // Coldcard generic-export parts (same fixed testnet seed, master fp 71348c8a).
    const CC_XFP: &str = "71348C8A";
    const CC_BIP44_XPUB: &str = "tpubDDQ4QMVqUvUTtdttiA5scX1xZeYncsVSGkGQvBfbboywvsLkTE5pLnstHuWqAbvgwjEzVo7fa4WVgNFWF6bc7keZ4p5qGT6ad7J1qNWLxtr";
    const CC_BIP49_XPUB: &str = "tpubDC4cRypn5w4uVn9E8GTjCnw9g1K9rraPSwfrFTTFriXBGBHe6oDCeGgcbWELw1Mpe5A1r2Hutpm8AriXD8jGqJhht7RMctGtJjmoBcjUaeh";
    const CC_BIP84_XPUB: &str = "tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L";

    #[test]
    fn coldcard_json_singlesig_import() {
        let e = import_coldcard_json(COLDCARD_GENERIC, Some("5.4.0")).unwrap();
        assert_eq!(e.source_wallet, "coldcard");
        assert_eq!(e.source_wallet_version.as_deref(), Some("5.4.0"));
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
        assert_eq!(e.threshold, None);
        assert_eq!(e.key_count, None);
        // bip84 is preferred; the assembled receive is byte-identical to the
        // canonical wpkh fixture (uppercase XFP lowercased + BIP380 checksum).
        assert_eq!(e.descriptors.receive.as_deref(), Some(WPKH_RECEIVE.trim()));
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(descriptor_audit::parse_descriptor(change).is_ok());
        // Coldcard exports carry no birth or gap-limit hint.
        assert_eq!(e.birth_height, None);
        assert!(e.birth_timestamp.is_none());
        assert_eq!(e.gap_limit, None);
        // Key origin reconstructed from the assembled descriptor.
        assert_eq!(e.keys.len(), 1);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("71348c8a"));
        assert_eq!(e.keys[0].derivation_path.as_deref(), Some("m/84h/1h/0h"));
        assert!(e.keys[0].xpub.as_deref().unwrap().starts_with("tpub"));
        assert!(e.keys[0].key_origin_present);
        // Caller-set fields stay unset by the importer.
        assert!(e.imported_at.is_none());
        assert!(e.raw_source_filename.is_none());
    }

    #[test]
    fn coldcard_json_branch_priority_and_assembly() {
        // bip84 wins when present, even alongside bip44.
        let with_both = format!(
            r#"{{"xfp":"{CC_XFP}","bip44":{{"deriv":"m/44'/1'/0'","xpub":"{CC_BIP44_XPUB}"}},"bip84":{{"deriv":"m/84'/1'/0'","xpub":"{CC_BIP84_XPUB}"}}}}"#
        );
        assert_eq!(
            import_coldcard_json(&with_both, None)
                .unwrap()
                .descriptors
                .receive
                .as_deref(),
            Some(WPKH_RECEIVE.trim())
        );
        // Only bip44 present → legacy pkh, byte-identical to the pkh fixture.
        let only_44 = format!(
            r#"{{"xfp":"{CC_XFP}","bip44":{{"deriv":"m/44'/1'/0'","xpub":"{CC_BIP44_XPUB}"}}}}"#
        );
        assert_eq!(
            import_coldcard_json(&only_44, None)
                .unwrap()
                .descriptors
                .receive
                .as_deref(),
            Some(PKH_RECEIVE.trim())
        );
        // bip44 + bip49 (no bip84) → nested segwit, byte-identical to sh_wpkh fixture.
        let upto_49 = format!(
            r#"{{"xfp":"{CC_XFP}","bip44":{{"deriv":"m/44'/1'/0'","xpub":"{CC_BIP44_XPUB}"}},"bip49":{{"deriv":"m/49'/1'/0'","xpub":"{CC_BIP49_XPUB}"}}}}"#
        );
        assert_eq!(
            import_coldcard_json(&upto_49, None)
                .unwrap()
                .descriptors
                .receive
                .as_deref(),
            Some(SH_WPKH_RECEIVE.trim())
        );
    }

    #[test]
    fn coldcard_json_accepts_full_real_export_fields() {
        // A fuller export with the master xpub, per-branch xfp/desc/first/_pub,
        // bip86, and multisig bip48_* branches must be accepted (declared as unused),
        // and still resolve to the bip84 descriptor.
        let full = format!(
            r#"{{"chain":"XTN","xfp":"{CC_XFP}","account":0,"xpub":"{CC_BIP44_XPUB}",
                "bip44":{{"name":"p2pkh","xfp":"00000000","deriv":"m/44'/1'/0'","xpub":"{CC_BIP44_XPUB}","desc":"ignored","first":"addr"}},
                "bip84":{{"name":"p2wpkh","xfp":"11111111","deriv":"m/84'/1'/0'","xpub":"{CC_BIP84_XPUB}","desc":"ignored","first":"addr","_pub":"vpub..."}},
                "bip86":{{"name":"p2tr","deriv":"m/86'/1'/0'","xpub":"{CC_BIP49_XPUB}"}},
                "bip48_1":{{"deriv":"m/48'/1'/0'/1'"}},"bip48_2":{{"deriv":"m/48'/1'/0'/2'"}}}}"#
        );
        let e = import_coldcard_json(&full, None).unwrap();
        assert_eq!(e.descriptors.receive.as_deref(), Some(WPKH_RECEIVE.trim()));
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
    }

    #[test]
    fn coldcard_json_rejects_empty_malformed_and_no_branch() {
        assert_eq!(
            import_coldcard_json("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_coldcard_json("{not json", None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // deny_unknown_fields rejects an unexpected top-level key.
        let surprise = format!(
            r#"{{"xfp":"{CC_XFP}","bip84":{{"deriv":"m/84'/1'/0'","xpub":"{CC_BIP84_XPUB}"}},"surprise":1}}"#
        );
        assert_eq!(
            import_coldcard_json(&surprise, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // No singlesig branch (only multisig bip48_* present) is a typed error.
        let no_branch = r#"{"xfp":"71348C8A","bip48_2":{"deriv":"m/48'/1'/0'/2'"}}"#;
        assert_eq!(
            import_coldcard_json(no_branch, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn coldcard_descriptor_multisig_import() {
        let e = import_coldcard_descriptor(COLDCARD_DESCRIPTOR, None, Some("5.4.0")).unwrap();
        assert_eq!(e.source_wallet, "coldcard");
        assert_eq!(e.source_wallet_version.as_deref(), Some("5.4.0"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // The <0;1> multipath descriptor expands to the canonical receive/change.
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(change.ends_with("#al0du9sk"));
        assert!(descriptor_audit::parse_descriptor(change).is_ok());
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[2].fingerprint.as_deref(), Some("8dfc9b34"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
    }

    #[test]
    fn coldcard_descriptor_handles_starstar_shorthand_and_comments() {
        // The `/**` shorthand (with a now-stale checksum) plus comment/blank lines
        // resolve to the same canonical receive/change as the `<0;1>` form.
        let body = WSH_2OF3_RECEIVE.trim().replace("/0/*", "/**");
        let body = body.split_once('#').map_or(body.as_str(), |(b, _)| b);
        let content = format!("# exported by coldcard\n\n{body}#deadbeef\n");
        let e = import_coldcard_descriptor(&content, None, None).unwrap();
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        assert!(e
            .descriptors
            .change
            .as_deref()
            .unwrap()
            .ends_with("#al0du9sk"));
        assert_eq!(e.threshold, Some(2));
    }

    #[test]
    fn coldcard_descriptor_two_line_receive_change() {
        // Two single-path descriptor lines are taken as receive then change.
        let recv = WPKH_RECEIVE.trim();
        let chg = "wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/1/*)";
        let content = format!("{recv}\n{chg}\n");
        let e = import_coldcard_descriptor(&content, None, None).unwrap();
        assert_eq!(e.descriptors.receive.as_deref(), Some(recv));
        assert_eq!(e.descriptors.change.as_deref(), Some(chg));
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
        assert_eq!(e.keys.len(), 1);
    }

    #[test]
    fn coldcard_descriptor_singlesig_single_line() {
        let e = import_coldcard_descriptor(WPKH_RECEIVE, None, None).unwrap();
        assert_eq!(e.descriptors.receive.as_deref(), Some(WPKH_RECEIVE.trim()));
        assert!(e.descriptors.change.is_none());
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
    }

    #[test]
    fn coldcard_descriptor_rejects_empty_no_descriptor_and_too_many() {
        assert_eq!(
            import_coldcard_descriptor("", None, None)
                .unwrap_err()
                .code(),
            ErrorCode::InputEmpty
        );
        // Only comments → no descriptor line.
        assert_eq!(
            import_coldcard_descriptor("# just a comment\n#\n", None, None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        // More than two descriptor lines is refused, not silently truncated.
        let three = format!("{0}\n{0}\n{0}\n", WPKH_RECEIVE.trim());
        assert_eq!(
            import_coldcard_descriptor(&three, None, None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn coldcard_descriptor_refuses_private_key_and_accepts_sig() {
        // A descriptor carrying xprv is refused with E-PARSE-005.
        assert_eq!(
            import_coldcard_descriptor(XPRV_FIXTURE, None, None)
                .unwrap_err()
                .code(),
            ErrorCode::ContainsPrivateKey
        );
        // A supplied .sig is accepted (not verified in the MVP) and does not change
        // the result.
        let with_sig =
            import_coldcard_descriptor(COLDCARD_DESCRIPTOR, Some("H4sIc2ln..."), None).unwrap();
        let without = import_coldcard_descriptor(COLDCARD_DESCRIPTOR, None, None).unwrap();
        assert_eq!(with_sig, without);
    }

    #[test]
    fn nunchuk_bsms_import() {
        let e = import_nunchuk_bsms(NUNCHUK_BSMS, Some("1.9.32")).unwrap();
        assert_eq!(e.source_wallet, "nunchuk");
        assert_eq!(e.source_wallet_version.as_deref(), Some("1.9.32"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // The BSMS `/**` template (checksum stripped) expands to the canonical
        // receive/change, byte-identical to the committed 2-of-3 fixture.
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(change.ends_with("#al0du9sk"));
        // BSMS carries no birth hint.
        assert_eq!(e.birth_height, None);
        assert!(e.birth_timestamp.is_none());
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[0].derivation_path.as_deref(), Some("m/48h/1h/0h/2h"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
        assert!(e.imported_at.is_none());
    }

    #[test]
    fn nunchuk_bsms_rejects_malformed() {
        // Empty input.
        assert_eq!(
            import_nunchuk_bsms("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        // Missing the BSMS version header (descriptor pasted directly).
        assert_eq!(
            import_nunchuk_bsms(WSH_2OF3_RECEIVE, None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        // Header present but no descriptor line.
        assert_eq!(
            import_nunchuk_bsms("BSMS 1.0\n", None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // A line that merely starts with BSMS-like text but is not the marker.
        assert_eq!(
            import_nunchuk_bsms("BSMSX\nwsh(...)\n", None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn nunchuk_bsms_refuses_private_key() {
        // A BSMS template carrying xprv is refused with E-PARSE-005.
        let bsms = format!("BSMS 1.0\n{}\n/0/*,/1/*\n", XPRV_FIXTURE.trim());
        assert_eq!(
            import_nunchuk_bsms(&bsms, None).unwrap_err().code(),
            ErrorCode::ContainsPrivateKey
        );
    }

    #[test]
    fn nunchuk_bsms_tolerates_unparseable_descriptor() {
        // A well-formed BSMS file whose descriptor template is broken (non-secret)
        // is tolerated: the raw descriptor is kept and the analysis layer reports it.
        // This mirrors the §16.5 split — an unrecognized FILE is CannotDetermine,
        // a broken DESCRIPTOR is NotReady — so the importer must not hard-fail here.
        let bsms = "BSMS 1.0\nwsh(this-is-not-a-descriptor)\n/0/*,/1/*\n";
        let e = import_nunchuk_bsms(bsms, None).unwrap();
        assert_eq!(e.source_wallet, "nunchuk");
        assert!(e.descriptors.receive.is_some());
        assert_eq!(e.wallet_type, None);
        assert!(e.keys.is_empty());
    }

    #[test]
    fn coldcard_and_nunchuk_json_shape_is_snake_case() {
        let cc =
            serde_json::to_value(import_coldcard_json(COLDCARD_GENERIC, None).unwrap()).unwrap();
        assert_eq!(cc["source_wallet"], "coldcard");
        assert_eq!(cc["wallet_type"], "singlesig");
        assert!(cc["descriptors"]["receive"]
            .as_str()
            .unwrap()
            .contains("/0/*"));
        assert!(cc["birth_height"].is_null());
        assert_eq!(cc["keys"][0]["key_origin_present"], true);

        let nk = serde_json::to_value(import_nunchuk_bsms(NUNCHUK_BSMS, None).unwrap()).unwrap();
        assert_eq!(nk["source_wallet"], "nunchuk");
        assert_eq!(nk["wallet_type"], "multisig");
        assert_eq!(nk["threshold"], 2);
        assert_eq!(nk["key_count"], 3);
        assert_eq!(nk["keys"][0]["derivation_path"], "m/48h/1h/0h/2h");
    }

    // ---- US-026: Liana (.bed), Jade, and Passport importers ----

    const LIANA_BED: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/liana_v13_backup.bed"
    ));
    const JADE_MULTISIG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/jade_multisig.json"
    ));
    const PASSPORT_DESC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/passport_descriptor.txt"
    ));
    // The 2-of-3 fixture's bare account xpubs (fingerprints 4ba43603 / 6e37edb9 /
    // 8dfc9b34). A and B are the Liana backup's recipients; C is not.
    const XPUB_A: &str = "tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz";
    const XPUB_B: &str = "tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ";
    const XPUB_C: &str = "tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq";

    /// Hex-encode a string's bytes (test-only; mirrors the Liana importer's payload).
    fn hex_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 2);
        for b in s.bytes() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    #[test]
    fn liana_bed_decryption_input_flow() {
        // Supplying a recipient xpub decrypts the backup and yields the timelock
        // descriptor's receive/change branches.
        let e = import_liana_bed(LIANA_BED, &[XPUB_A], Some("13.0")).unwrap();
        assert_eq!(e.source_wallet, "liana");
        assert_eq!(e.source_wallet_version.as_deref(), Some("13.0"));
        // A Liana or_d() timelock policy is classified as a supported timelock
        // wallet, but it still has no single plain M-of-N quorum.
        assert_eq!(e.wallet_type.as_deref(), Some("timelock"));
        assert_eq!(e.threshold, None);
        assert_eq!(e.key_count, None);
        let receive = e.descriptors.receive.as_deref().unwrap();
        assert!(receive.starts_with("wsh(or_d("));
        assert!(receive.contains("/0/*"));
        assert!(receive.ends_with("#uny393kd"));
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(change.ends_with("#s0952kd2"));
        // Two key origins (primary + recovery), in descriptor order.
        assert_eq!(e.keys.len(), 2);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[1].fingerprint.as_deref(), Some("6e37edb9"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
        // timestamp 1705276800 → ISO 8601.
        assert_eq!(e.birth_timestamp.as_deref(), Some("2024-01-15T00:00:00Z"));
        assert_eq!(e.birth_height, None);
        assert!(e.imported_at.is_none());
        // The second recipient also decrypts; the result is identical.
        assert_eq!(
            import_liana_bed(LIANA_BED, &[XPUB_B], Some("13.0")).unwrap(),
            e
        );
    }

    #[test]
    fn liana_bed_requires_a_matching_decryption_input() {
        // No decryption input → refused (the user must provide one of their xpubs).
        assert_eq!(
            import_liana_bed(LIANA_BED, &[], None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // A key that is not one of the recipients cannot decrypt the backup.
        assert_eq!(
            import_liana_bed(LIANA_BED, &[XPUB_C], None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn liana_bed_rejects_empty_and_malformed() {
        assert_eq!(
            import_liana_bed("", &[XPUB_A], None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_liana_bed("{not json", &[XPUB_A], None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        // deny_unknown_fields rejects an unexpected top-level key.
        let surprise = r#"{"recipients":["x"],"payload":"7763","surprise":1}"#;
        assert_eq!(
            import_liana_bed(surprise, &["x"], None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // A non-hex payload (gate passed) is a typed error, not a panic.
        let bad_payload = r#"{"recipients":["x"],"payload":"zz"}"#;
        assert_eq!(
            import_liana_bed(bad_payload, &["x"], None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn liana_bed_refuses_descriptor_with_private_key() {
        // A backup whose payload is an xprv descriptor is refused with E-PARSE-005
        // once the recipient gate passes — secret material is never stored.
        let bed = format!(
            r#"{{"recipients":["k"],"payload":"{}"}}"#,
            hex_encode(XPRV_FIXTURE.trim())
        );
        assert_eq!(
            import_liana_bed(&bed, &["k"], None).unwrap_err().code(),
            ErrorCode::ContainsPrivateKey
        );
    }

    #[test]
    fn jade_multisig_import() {
        let e = import_jade(JADE_MULTISIG, Some("1.0.38")).unwrap();
        assert_eq!(e.source_wallet, "jade");
        assert_eq!(e.source_wallet_version.as_deref(), Some("1.0.38"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // The int-array derivation + sorted=true assemble byte-identically to the
        // canonical 2-of-3 fixture (proves the assembly with no new fixture minting).
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(change.ends_with("#al0du9sk"));
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[1].fingerprint.as_deref(), Some("6e37edb9"));
        assert_eq!(e.keys[2].fingerprint.as_deref(), Some("8dfc9b34"));
        assert_eq!(e.keys[0].derivation_path.as_deref(), Some("m/48h/1h/0h/2h"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
        assert!(e.imported_at.is_none());
    }

    #[test]
    fn jade_accepts_byte_array_fingerprint_and_string_derivation() {
        // Jade's native wire form (4-byte fingerprint, index-array derivation) and a
        // file export's hex/string forms both assemble to the same descriptor.
        let json = format!(
            r#"{{"descriptor":{{"variant":"wsh(multi(k))","sorted":true,"threshold":2,"signers":[
                {{"fingerprint":[75,164,54,3],"derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_A}"}},
                {{"fingerprint":"6E37EDB9","derivation":"48'/1'/0'/2'","xpub":"{XPUB_B}"}},
                {{"fingerprint":[141,252,155,52],"derivation":[2147483696,2147483649,2147483648,2147483650],"xpub":"{XPUB_C}"}}
            ]}}}}"#
        );
        let e = import_jade(&json, None).unwrap();
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[1].fingerprint.as_deref(), Some("6e37edb9"));
        assert_eq!(e.keys[2].fingerprint.as_deref(), Some("8dfc9b34"));
    }

    #[test]
    fn jade_unsorted_uses_multi_not_sortedmulti() {
        let json = format!(
            r#"{{"descriptor":{{"variant":"wsh(multi(k))","sorted":false,"threshold":2,"signers":[
                {{"fingerprint":"4ba43603","derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_A}"}},
                {{"fingerprint":"6e37edb9","derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_B}"}},
                {{"fingerprint":"8dfc9b34","derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_C}"}}
            ]}}}}"#
        );
        let e = import_jade(&json, None).unwrap();
        let receive = e.descriptors.receive.as_deref().unwrap();
        assert!(receive.starts_with("wsh(multi(2,"));
        assert!(!receive.contains("sortedmulti"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
    }

    #[test]
    fn jade_sh_wsh_variant() {
        let json = format!(
            r#"{{"descriptor":{{"variant":"sh(wsh(multi(k)))","sorted":true,"threshold":2,"signers":[
                {{"fingerprint":"4ba43603","derivation":"m/48'/1'/0'/1'","xpub":"{XPUB_A}"}},
                {{"fingerprint":"6e37edb9","derivation":"m/48'/1'/0'/1'","xpub":"{XPUB_B}"}},
                {{"fingerprint":"8dfc9b34","derivation":"m/48'/1'/0'/1'","xpub":"{XPUB_C}"}}
            ]}}}}"#
        );
        let e = import_jade(&json, None).unwrap();
        let receive = e.descriptors.receive.as_deref().unwrap();
        assert!(receive.starts_with("sh(wsh(sortedmulti(2,"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
    }

    #[test]
    fn jade_rejects_empty_malformed_and_invalid() {
        assert_eq!(
            import_jade("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        assert_eq!(
            import_jade("{not json", None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // No signers.
        let no_signers = r#"{"descriptor":{"variant":"wsh(multi(k))","sorted":true,"threshold":2,"signers":[]}}"#;
        assert_eq!(
            import_jade(no_signers, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // Unsupported variant.
        let bad_variant = format!(
            r#"{{"descriptor":{{"variant":"tr(multi_a(k))","sorted":true,"threshold":2,"signers":[{{"fingerprint":"4ba43603","derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_A}"}}]}}}}"#
        );
        assert_eq!(
            import_jade(&bad_variant, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // Malformed fingerprint (not 8 hex characters).
        let bad_fp = format!(
            r#"{{"descriptor":{{"variant":"wsh(multi(k))","sorted":true,"threshold":2,"signers":[{{"fingerprint":"xyz","derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_A}"}}]}}}}"#
        );
        assert_eq!(
            import_jade(&bad_fp, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // deny_unknown_fields rejects an unexpected top-level key.
        let surprise = format!(
            r#"{{"descriptor":{{"variant":"wsh(multi(k))","sorted":true,"threshold":2,"signers":[{{"fingerprint":"4ba43603","derivation":"m/48'/1'/0'/2'","xpub":"{XPUB_A}"}}]}},"surprise":1}}"#
        );
        assert_eq!(
            import_jade(&surprise, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }

    #[test]
    fn jade_json_shape_is_snake_case() {
        let v = serde_json::to_value(import_jade(JADE_MULTISIG, None).unwrap()).unwrap();
        assert_eq!(v["source_wallet"], "jade");
        assert_eq!(v["wallet_type"], "multisig");
        assert_eq!(v["threshold"], 2);
        assert_eq!(v["key_count"], 3);
        assert!(v["descriptors"]["receive"]
            .as_str()
            .unwrap()
            .contains("/0/*"));
        assert_eq!(v["keys"][0]["fingerprint"], "4ba43603");
        assert_eq!(v["keys"][0]["derivation_path"], "m/48h/1h/0h/2h");
        assert!(v["birth_height"].is_null());
    }

    #[test]
    fn passport_descriptor_import() {
        let e = import_passport(PASSPORT_DESC, Some("2.3.0")).unwrap();
        assert_eq!(e.source_wallet, "passport");
        assert_eq!(e.source_wallet_version.as_deref(), Some("2.3.0"));
        assert_eq!(e.wallet_type.as_deref(), Some("singlesig"));
        assert_eq!(e.threshold, None);
        // The multipath singlesig descriptor (with comment lines) expands to the
        // canonical wpkh receive/change.
        assert_eq!(e.descriptors.receive.as_deref(), Some(WPKH_RECEIVE.trim()));
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(descriptor_audit::parse_descriptor(change).is_ok());
        assert_eq!(e.keys.len(), 1);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("71348c8a"));
        assert_eq!(e.keys[0].derivation_path.as_deref(), Some("m/84h/1h/0h"));
        assert!(e.keys[0].key_origin_present);
        assert!(e.birth_timestamp.is_none());
        assert!(e.imported_at.is_none());
    }

    #[test]
    fn passport_rejects_empty_and_refuses_private_key() {
        assert_eq!(
            import_passport("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        // Only comments → no descriptor line.
        assert_eq!(
            import_passport("# Passport Core\n#\n", None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        // A descriptor carrying xprv is refused with E-PARSE-005.
        assert_eq!(
            import_passport(XPRV_FIXTURE, None).unwrap_err().code(),
            ErrorCode::ContainsPrivateKey
        );
    }

    #[test]
    fn passport_json_shape_is_snake_case() {
        let v = serde_json::to_value(import_passport(PASSPORT_DESC, None).unwrap()).unwrap();
        assert_eq!(v["source_wallet"], "passport");
        assert_eq!(v["wallet_type"], "singlesig");
        assert!(v["descriptors"]["receive"]
            .as_str()
            .unwrap()
            .contains("/0/*"));
        assert!(v["descriptors"]["change"]
            .as_str()
            .unwrap()
            .contains("/1/*"));
        assert_eq!(v["keys"][0]["fingerprint"], "71348c8a");
    }

    // ---- US-027: Electrum + BlueWallet (Tier-2) importers and auto-detection ----

    const ELECTRUM_MULTISIG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/electrum_multisig.txt"
    ));
    const BLUEWALLET_VAULT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/wallet_exports/bluewallet_vault.txt"
    ));
    // A bare key expression carrying private-key material (from contains_xprv.txt).
    const XPRV_KEY: &str = "[e2867bb6/84h/1h/0h]tprv8ghPpfvGovnEcJquDtmPuj8ufbqaXSsyUi4g4SV8GhcyGk59jdWXzpaP1tAEy2XjQXWiMjZcYf2GjW8xMZZKW2FP42DvpwtipQfgUftkBzP";

    #[test]
    fn electrum_multisig_import_assembles_known_descriptor() {
        let e = import_electrum(ELECTRUM_MULTISIG, Some("4.5.5")).unwrap();
        assert_eq!(e.source_wallet, "electrum");
        assert_eq!(e.source_wallet_version.as_deref(), Some("4.5.5"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // The three cosigner keys are the canonical 2-of-3 set, so the assembled
        // P2WSH descriptor is byte-identical to the committed fixture.
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.contains("/1/*"));
        assert!(change.ends_with("#al0du9sk"));
        assert!(descriptor_audit::parse_descriptor(change).is_ok());
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[2].fingerprint.as_deref(), Some("8dfc9b34"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
        // Caller-stamped fields stay unset (deterministic import).
        assert!(e.imported_at.is_none());
        assert!(e.raw_source_filename.is_none());
    }

    #[test]
    fn electrum_rejects_empty_malformed_and_refuses_private_key() {
        assert_eq!(
            import_electrum("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        // No wallet_type line → unrecognized file.
        assert_eq!(
            import_electrum("[4ba43603/48h]tpubfoo\n", None)
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        // Cosigner count disagrees with the declared N.
        let one_key = format!("wallet_type: 2of3\n[4ba43603/48'/1'/0'/2']{}\n", "tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz");
        assert_eq!(
            import_electrum(&one_key, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // A cosigner key carrying xprv material is refused with E-PARSE-005.
        let with_xprv = format!("wallet_type: 1of1\n{XPRV_KEY}\n");
        assert_eq!(
            import_electrum(&with_xprv, None).unwrap_err().code(),
            ErrorCode::ContainsPrivateKey
        );
    }

    #[test]
    fn bluewallet_vault_import_assembles_known_descriptor() {
        let e = import_bluewallet(BLUEWALLET_VAULT, Some("6.4.0")).unwrap();
        assert_eq!(e.source_wallet, "bluewallet");
        assert_eq!(e.source_wallet_version.as_deref(), Some("6.4.0"));
        assert_eq!(e.wallet_type.as_deref(), Some("multisig"));
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
        // Same canonical keys + shared Derivation → byte-identical 2-of-3 P2WSH.
        assert_eq!(
            e.descriptors.receive.as_deref(),
            Some(WSH_2OF3_RECEIVE.trim())
        );
        let change = e.descriptors.change.as_deref().unwrap();
        assert!(change.ends_with("#al0du9sk"));
        assert_eq!(e.keys.len(), 3);
        assert_eq!(e.keys[0].fingerprint.as_deref(), Some("4ba43603"));
        assert_eq!(e.keys[1].fingerprint.as_deref(), Some("6e37edb9"));
        assert!(e.keys.iter().all(|k| k.key_origin_present));
        assert!(e.imported_at.is_none());
    }

    #[test]
    fn bluewallet_p2sh_p2wsh_format_selects_nested_segwit_wrapper() {
        // Swapping only the Format line changes the assembled script wrapper.
        let nested = BLUEWALLET_VAULT.replace("P2WSH", "P2SH-P2WSH");
        let e = import_bluewallet(&nested, None).unwrap();
        let receive = e.descriptors.receive.as_deref().unwrap();
        assert!(receive.starts_with("sh(wsh(sortedmulti(2,"));
        assert!(descriptor_audit::parse_descriptor(receive).is_ok());
        assert_eq!(e.threshold, Some(2));
        assert_eq!(e.key_count, Some(3));
    }

    #[test]
    fn bluewallet_rejects_empty_malformed_and_refuses_private_key() {
        assert_eq!(
            import_bluewallet("", None).unwrap_err().code(),
            ErrorCode::InputEmpty
        );
        // Missing the Policy line → unrecognized setup file.
        let no_policy = "Derivation: m/48'/1'/0'/2'\nFormat: P2WSH\n4ba43603: tpubfoo\n";
        assert_eq!(
            import_bluewallet(no_policy, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // Cosigner count disagrees with the policy N (2 of 3, but two keys).
        let short = "Policy: 2 of 3\nDerivation: m/48'/1'/0'/2'\nFormat: P2WSH\n4ba43603: tpubA\n6e37edb9: tpubB\n";
        assert_eq!(
            import_bluewallet(short, None).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
        // A cosigner xpub carrying private-key material is refused (E-PARSE-005).
        let with_xprv = format!(
            "Policy: 1 of 1\nDerivation: m/48'/1'/0'/2'\nFormat: P2WSH\ne2867bb6: {}\n",
            XPRV_KEY.split_once(']').unwrap().1
        );
        assert_eq!(
            import_bluewallet(&with_xprv, None).unwrap_err().code(),
            ErrorCode::ContainsPrivateKey
        );
    }

    #[test]
    fn electrum_and_bluewallet_json_shape_is_snake_case() {
        for export in [
            import_electrum(ELECTRUM_MULTISIG, None).unwrap(),
            import_bluewallet(BLUEWALLET_VAULT, None).unwrap(),
        ] {
            let v = serde_json::to_value(&export).unwrap();
            assert_eq!(v["wallet_type"], "multisig");
            assert_eq!(v["threshold"], 2);
            assert_eq!(v["key_count"], 3);
            assert!(v["descriptors"]["receive"]
                .as_str()
                .unwrap()
                .contains("/0/*"));
            assert_eq!(v["keys"][0]["fingerprint"], "4ba43603");
            assert_eq!(v["keys"][0]["derivation_path"], "m/48h/1h/0h/2h");
            assert!(v["keys"][0]["key_origin_present"].as_bool().unwrap());
        }
    }

    #[test]
    fn detect_format_routes_new_fixtures_and_rejects_unknown() {
        // The two new Tier-2 fixtures route to their parsers (the core AC).
        assert_eq!(
            detect_format(ELECTRUM_MULTISIG).unwrap(),
            WalletFormat::Electrum
        );
        assert_eq!(
            detect_format(BLUEWALLET_VAULT).unwrap(),
            WalletFormat::BlueWallet
        );
        // Unknown text and unknown JSON both return E-INPUT-003.
        assert_eq!(
            detect_format("this is not a wallet export at all\n")
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        assert_eq!(
            detect_format("{\"unrecognized\": true}")
                .unwrap_err()
                .code(),
            ErrorCode::InputInvalidFormat
        );
        // Empty content is guarded before sniffing.
        assert_eq!(
            detect_format("   ").unwrap_err().code(),
            ErrorCode::InputEmpty
        );
    }

    #[test]
    fn detect_format_routes_every_existing_fixture() {
        // Content-sniffing must route all committed fixtures unambiguously. The
        // Coldcard descriptor file and Passport share the descriptor-file shape.
        let cases = [
            (CORE_FIXTURE, WalletFormat::BitcoinCore),
            (SPARROW_SINGLESIG, WalletFormat::Sparrow),
            (SPARROW_MULTISIG, WalletFormat::Sparrow),
            (SPECTER_MULTISIG, WalletFormat::Specter),
            (JADE_MULTISIG, WalletFormat::Jade),
            (LIANA_BED, WalletFormat::Liana),
            (COLDCARD_GENERIC, WalletFormat::ColdcardJson),
            (COLDCARD_DESCRIPTOR, WalletFormat::DescriptorFile),
            (PASSPORT_DESC, WalletFormat::DescriptorFile),
            (NUNCHUK_BSMS, WalletFormat::NunchukBsms),
            (ELECTRUM_MULTISIG, WalletFormat::Electrum),
            (BLUEWALLET_VAULT, WalletFormat::BlueWallet),
        ];
        for (content, expected) in cases {
            assert_eq!(
                detect_format(content).unwrap(),
                expected,
                "misrouted {} fixture",
                expected.as_str()
            );
        }
    }

    #[test]
    fn import_auto_dispatches_to_the_detected_importer() {
        assert_eq!(
            import_auto(ELECTRUM_MULTISIG).unwrap().source_wallet,
            "electrum"
        );
        assert_eq!(
            import_auto(BLUEWALLET_VAULT).unwrap().source_wallet,
            "bluewallet"
        );
        assert_eq!(
            import_auto(CORE_FIXTURE).unwrap().source_wallet,
            "bitcoin_core"
        );
        assert_eq!(
            import_auto(SPARROW_MULTISIG).unwrap().source_wallet,
            "sparrow"
        );
        // A detected Liana .bed cannot be auto-imported without decryption inputs.
        assert_eq!(
            import_auto(LIANA_BED).unwrap_err().code(),
            ErrorCode::InputInvalidFormat
        );
    }
}
