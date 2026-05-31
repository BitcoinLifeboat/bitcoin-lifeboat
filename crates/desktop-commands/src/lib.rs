//! `desktop-commands` — the GUI-agnostic command layer for the Bitcoin Lifeboat
//! desktop app (PRD §21.3).
//!
//! The Tauri `#[tauri::command]` wrappers in
//! `apps/desktop/src-tauri/src/commands.rs` are intentionally thin: each one
//! reads the wall clock / app version at the boundary and delegates to a pure
//! function here. Keeping the logic in this `tauri`-free crate means it builds and
//! is exercised by the fast core gate (`cargo test --workspace`, Rust 1.78)
//! **without** the webkit2gtk/GTK system libraries the desktop crate links — and
//! it keeps all Bitcoin logic in GUI-agnostic Rust crates (§13.7 / §20), reusing
//! exactly the `lifeboat-core` surface the CLI does.
//!
//! # Boundary contract
//! - **Typed errors.** Every command returns `Result<T, LifeboatError>`. A
//!   [`LifeboatError`] serializes to a stable, **leak-free** JSON object (its
//!   stable code + catalog text + i18n key; never the chained source — see
//!   `error-taxonomy`). Tauri requires the error half to be `Serialize`.
//! - **Serializable outputs.** Every `T` is `serde::Serialize` (§21.3).
//! - **Screen before processing (§13.5).** Pasted text is wrapped in a
//!   [`SecretString`] and run through the detector **before** any parsing; a
//!   confirmed secret becomes a typed `E-SECRET-*` error carrying only its code,
//!   never the content. Only a [`DetectorReport`] — discriminants and byte ranges,
//!   never raw secret content — crosses back out of [`detect_sensitive_input`].
//! - **Validated inputs, no panics.** Inputs are checked at the boundary; nothing
//!   here `unwrap`s or panics (outside `#[cfg(test)]`).
//! - **Determinism (§19 / §27).** [`audit_descriptor`] takes `created_at` and
//!   `app_version` as parameters so the report engine stays a pure function of its
//!   inputs; the wrapper supplies the clock ([`now_iso8601`]) and crate version.
//!   [`generate_report`], [`generate_runbook`], and [`parse_wallet_export`] follow
//!   the same rule for their timestamp/version inputs.
//!
//! # US-043 — output, import, and IO commands (§21.3)
//! The second command tranche adds [`generate_report`] / [`generate_runbook`]
//! (deterministic exports with `public-safe`/`private` redaction),
//! [`parse_wallet_export`] (read a file by path, screen it, normalize it), and the
//! IO commands' GUI-agnostic halves: [`save_export`] (write bytes to a
//! dialog-chosen path) and [`check_external_link`] (the `open_external_link`
//! allowlist decision; the Tauri wrapper performs the OS-browser open only after
//! this passes). The allowlist itself is generated at build time from
//! `project.config.toml` (`github.url_base` + `site.domain`; see `build.rs`), so no
//! org/domain is hardcoded — changing the config updates the allowlist and
//! [`app_info`]'s URLs with no code change.

// Re-exported so the Tauri wrappers (and tests) can name the whole boundary
// surface through this one crate — including the field types nested inside the
// outputs ([`Chain`] on a [`DerivedAddress`], [`DetectedSecret`] inside a
// [`DetectorReport`] finding).
pub use lifeboat_core::address_derive::{Chain, DerivedAddress, MatchLocation};
pub use lifeboat_core::error_taxonomy::{ErrorCode, LifeboatError, Severity};
pub use lifeboat_core::miniscript_viz::{
    AbsoluteTimelock, AbsoluteTimelockUnit, LianaRecoveryCountdown, LianaRecoveryPath,
    LianaRecoveryPathKind, LianaRecoveryTree, RelativeTimelock, RelativeTimelockUnit,
};
pub use lifeboat_core::report_engine::{ReadinessReport, RedactionMode};
pub use lifeboat_core::sensitive_input_detector::{DetectedSecret, DetectorReport};
// US-043: `parse_wallet_export` returns a `NormalizedWalletExport`; re-export it
// and the field types nested inside it so the Tauri wrapper (and tests) can name
// the whole boundary surface through this one crate.
pub use lifeboat_core::wallet_imports::{
    NormalizedWalletExport, WalletDescriptors, WalletKey, WalletLabel,
};

use lifeboat_core::address_derive::{
    compare_known_address, derive_addresses as core_derive_addresses, DerivedAddresses, Network,
};
use lifeboat_core::descriptor_audit::{
    compute_checksum as core_compute_checksum, parse_descriptor,
    validate_checksum as core_validate_checksum, ChecksumStatus, ParsedDescriptor,
};
use lifeboat_core::miniscript_viz::{
    descriptor_to_dot as core_descriptor_to_dot, liana_recovery_tree as core_liana_recovery_tree,
    liana_recovery_tree_at_block as core_liana_recovery_tree_at_block,
};
use lifeboat_core::report_engine::{build_report, ReportInput};
use lifeboat_core::runbook_engine::{
    render_heir_markdown, render_heir_pdf, render_owner_markdown, render_owner_pdf, HeirTemplate,
    OwnerTemplate, PageSize, PdfBackend, RunbookData, RunbookWalletSummary, Signer,
};
use lifeboat_core::sensitive_input_detector::detect_secret;
use lifeboat_core::wallet_imports::import_auto;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

// --- Boundary DTOs ----------------------------------------------------------

/// The Bitcoin network a command should operate on, as it crosses the JS boundary
/// (snake_case: `"mainnet"` / `"testnet"` / `"signet"` / `"regtest"`).
///
/// A boundary-local enum so an unknown value is rejected at deserialization;
/// [`to_network`] maps it onto the `rust-bitcoin` [`Network`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkArg {
    /// Bitcoin mainnet.
    Mainnet,
    /// The public test network.
    Testnet,
    /// The Signet test network.
    Signet,
    /// A local regtest network.
    Regtest,
}

/// Which derivation chain(s) [`derive_addresses`] should return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainArg {
    /// External / receive addresses only.
    Receive,
    /// Internal / change addresses only.
    Change,
    /// Both receive and change addresses (the default).
    #[default]
    Both,
}

/// The default address count for [`derive_addresses`] / search range for
/// [`compare_address`] when the caller omits it (PRD §17.10.2 default `N = 10`).
const fn default_count() -> u32 {
    10
}

/// Input for [`audit_descriptor`] (§21.3 `DescriptorAuditInput`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DescriptorAuditInput {
    /// The watch-only output descriptor to audit.
    pub descriptor: String,
    /// Explicit network override; when absent the network is inferred, and an
    /// ambiguous descriptor (a shared `tpub`) is a typed error (§16.5).
    #[serde(default)]
    pub network: Option<NetworkArg>,
    /// A known address to confirm membership of, if any (§17.5).
    #[serde(default)]
    pub known_address: Option<String>,
    /// How many receive/change addresses the report derives; the engine default
    /// applies when omitted.
    #[serde(default)]
    pub derive_count: Option<u32>,
}

/// Input for [`derive_addresses`] (§21.3 `AddressDeriveInput`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AddressDeriveInput {
    /// The watch-only output descriptor to derive from.
    pub descriptor: String,
    /// Explicit network override; inferred from the descriptor when absent.
    #[serde(default)]
    pub network: Option<NetworkArg>,
    /// How many addresses to derive per requested chain (default 10, `1..=1000`).
    #[serde(default = "default_count")]
    pub count: u32,
    /// Which chain(s) to return (default both).
    #[serde(default)]
    pub chain: ChainArg,
}

/// Input for [`compare_address`] (§21.3 `AddressCompareInput`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AddressCompareInput {
    /// The watch-only output descriptor to search.
    pub descriptor: String,
    /// The address to look for among the descriptor's derived addresses.
    pub address: String,
    /// Explicit network override; inferred from the descriptor when absent.
    #[serde(default)]
    pub network: Option<NetworkArg>,
    /// How many receive/change indices to search before reporting a miss; the
    /// core search transparently expands further on a miss (§17.5).
    #[serde(default = "default_count")]
    pub search_range: u32,
}

/// The address list returned by [`derive_addresses`] (§21.3 `DerivedAddressList`):
/// the resolved network and the requested addresses, receive chain before change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DerivedAddressList {
    /// The resolved network the addresses were derived on (e.g. `"bitcoin"`).
    pub network: String,
    /// The derived addresses, in the requested chain order.
    pub addresses: Vec<DerivedAddress>,
}

/// The result of [`compare_address`] (§21.3 `AddressCompareResult`): whether the
/// supplied address was found within the searched range, and where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AddressCompareResult {
    /// The resolved network the search ran on.
    pub network: String,
    /// The address the user supplied (trimmed, verbatim).
    pub provided: String,
    /// Whether `provided` matched a derived address within the searched range.
    pub matched: bool,
    /// The hit location, or `null` on a miss.
    pub matched_at: Option<MatchLocation>,
}

/// The tri-state verdict of [`validate_checksum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumValidationStatus {
    /// A `#checksum` is present and matches the descriptor body.
    Valid,
    /// No `#checksum` is present — non-fatal (`W-NO-DESC-CHECKSUM`).
    Missing,
    /// A `#checksum` is present but does not match the body (`E-PARSE-003`).
    Invalid,
}

/// The result of [`validate_checksum`] (§21.3 `ChecksumValidation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChecksumValidation {
    /// The verdict.
    pub status: ChecksumValidationStatus,
    /// Convenience flag: `true` only for [`ChecksumValidationStatus::Valid`].
    pub valid: bool,
}

// --- Boundary helpers -------------------------------------------------------

/// Map the boundary [`NetworkArg`] to the `rust-bitcoin` [`Network`].
fn to_network(arg: NetworkArg) -> Network {
    match arg {
        NetworkArg::Mainnet => Network::Bitcoin,
        NetworkArg::Testnet => Network::Testnet,
        NetworkArg::Signet => Network::Signet,
        NetworkArg::Regtest => Network::Regtest,
    }
}

/// Reject blank descriptor/text input at the boundary (AC: "validate all inputs").
/// `validate_checksum` would otherwise report an empty string as `Missing`; making
/// every descriptor command reject it uniformly is clearer for the UI.
fn ensure_nonempty(text: &str) -> Result<(), LifeboatError> {
    if text.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    Ok(())
}

/// Screen pasted text for secret material **before** any processing (§13.5). The
/// text is wrapped in a [`SecretString`] for the detector call (which zeroizes it
/// on drop); a confirmed secret (`Block`) becomes a typed `E-SECRET-*`
/// [`LifeboatError`] carrying only the stable reason code — never the content.
/// `Warn` / `Allow` proceed (a normal watch-only descriptor is `Allow`; text that
/// merely resembles a secret parses and fails later if malformed).
fn screen_for_secrets(text: &str) -> Result<(), LifeboatError> {
    let report = detect_secret(SecretString::from(text.to_owned()));
    if !report.is_blocked() {
        return Ok(());
    }
    // A blocked report always carries at least one reason code; default to the
    // generic "raw private key suspected" code only to stay panic-free.
    let code = report
        .reason_codes()
        .first()
        .copied()
        .unwrap_or(ErrorCode::RawPrivateKeySuspected);
    Err(LifeboatError::new(code))
}

/// Resolve the network to operate on: the explicit override, else the descriptor's
/// inferred network. An ambiguous descriptor (a `tpub`, shared by
/// testnet/signet/regtest) with no override is a user-correctable error — Lifeboat
/// never guesses (§16.5). There is no network-specific Appendix-C code, so this
/// uses the closest user-correctable one (`E-INPUT-003`) with the precise reason in
/// the context — the convention `address-derive` uses for its own ambiguous cases.
fn resolve_network(
    parsed: &ParsedDescriptor,
    override_arg: Option<NetworkArg>,
) -> Result<Network, LifeboatError> {
    if let Some(arg) = override_arg {
        return Ok(to_network(arg));
    }
    parsed.network().ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(
            "the network could not be inferred from the descriptor (a tpub is shared by \
             testnet, signet, and regtest); pass an explicit network",
        )
    })
}

// --- Commands (§21.3) -------------------------------------------------------

/// `audit_descriptor` (§21.3): screen the descriptor for secrets, parse it, and
/// build the deterministic §19.1 readiness report. A blocked secret, an
/// unparseable descriptor, or an ambiguous network (when a `known_address` forces
/// derivation) surfaces as a typed `Err`.
///
/// `created_at` (ISO-8601) and `app_version` are supplied by the boundary so the
/// report engine stays a pure function of its inputs (§19 / §27 determinism).
///
/// # Errors
/// Propagates the typed [`LifeboatError`] from secret screening (`E-SECRET-*`),
/// descriptor parsing (`E-PARSE-*`), or an empty input (`E-INPUT-001`).
pub fn audit_descriptor(
    input: DescriptorAuditInput,
    created_at: &str,
    app_version: &str,
) -> Result<ReadinessReport, LifeboatError> {
    ensure_nonempty(&input.descriptor)?;
    screen_for_secrets(&input.descriptor)?;
    if let Some(address) = &input.known_address {
        // A pasted known address is screened too (§13.5); a normal address is
        // `Allow` and proceeds.
        screen_for_secrets(address)?;
    }
    let parsed = parse_descriptor(&input.descriptor)?;

    let mut report_input = ReportInput::new(&parsed, created_at).with_app_version(app_version);
    if let Some(arg) = input.network {
        report_input = report_input.with_network(to_network(arg));
    }
    if let Some(address) = input.known_address.as_deref() {
        report_input = report_input.with_known_address(address);
    }
    if let Some(count) = input.derive_count {
        report_input = report_input.with_derive_count(count);
    }
    Ok(build_report(&report_input))
}

/// `derive_addresses` (§21.3): derive the first `count` receive and/or change
/// addresses from a watch-only descriptor, filtered to the requested chain(s).
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), parse (`E-PARSE-*`), ambiguous
/// network (`E-INPUT-003`), or derivation (`E-INPUT-002` for a bad `count` /
/// wildcard-less descriptor) errors.
pub fn derive_addresses(input: AddressDeriveInput) -> Result<DerivedAddressList, LifeboatError> {
    ensure_nonempty(&input.descriptor)?;
    screen_for_secrets(&input.descriptor)?;
    let parsed = parse_descriptor(&input.descriptor)?;
    let network = resolve_network(&parsed, input.network)?;
    let derived: DerivedAddresses = core_derive_addresses(&parsed, network, input.count)?;

    let mut addresses: Vec<DerivedAddress> = Vec::new();
    if matches!(input.chain, ChainArg::Receive | ChainArg::Both) {
        addresses.extend(derived.receive_derived.iter().cloned());
    }
    if matches!(input.chain, ChainArg::Change | ChainArg::Both) {
        addresses.extend(derived.change_derived.iter().cloned());
    }
    Ok(DerivedAddressList {
        network: network.to_string(),
        addresses,
    })
}

/// `compare_address` (§21.3): search a descriptor's derived receive/change range
/// for a known address. A miss is a successful result (`matched: false`), not an
/// error; an address invalid for the resolved network is a typed `Err`
/// (`E-INPUT-003`).
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), parse (`E-PARSE-*`), ambiguous
/// network, or invalid-address (`E-INPUT-003`) errors.
pub fn compare_address(input: AddressCompareInput) -> Result<AddressCompareResult, LifeboatError> {
    ensure_nonempty(&input.descriptor)?;
    // Screen BOTH the descriptor and the pasted address for secrets (§13.5).
    screen_for_secrets(&input.descriptor)?;
    screen_for_secrets(&input.address)?;
    let parsed = parse_descriptor(&input.descriptor)?;
    let network = resolve_network(&parsed, input.network)?;
    let found = compare_known_address(&parsed, network, &input.address, input.search_range)?;
    Ok(AddressCompareResult {
        network: network.to_string(),
        provided: found.provided,
        matched: found.matched,
        matched_at: found.matched_at,
    })
}

/// `detect_sensitive_input` (§21.3): screen pasted text for Bitcoin secret material
/// and return the leak-free [`DetectorReport`] (discriminants + byte ranges only,
/// never the content). The input is consumed into a [`SecretString`], exposed only
/// for the detector call, and zeroized on drop.
///
/// Always `Ok` in practice — the `Result` is for §21.3 signature uniformity — and
/// the report's `action` tells the UI whether to block.
///
/// # Errors
/// None today; the `Result` wrapper keeps the boundary signature uniform.
pub fn detect_sensitive_input(input: String) -> Result<DetectorReport, LifeboatError> {
    Ok(detect_secret(SecretString::from(input)))
}

/// `validate_checksum` (§21.3): report whether a descriptor's BIP380 checksum is
/// present-and-valid, missing (non-fatal), or present-but-invalid. The descriptor
/// is screened for secrets first.
///
/// A present-but-invalid checksum (the core's `E-PARSE-003`) is mapped to the
/// [`ChecksumValidationStatus::Invalid`] verdict rather than an `Err`, so the UI
/// gets one clean tri-state; only genuine input errors (e.g. empty) are `Err`.
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`) or empty-input (`E-INPUT-001`)
/// errors.
pub fn validate_checksum(descriptor: String) -> Result<ChecksumValidation, LifeboatError> {
    ensure_nonempty(&descriptor)?;
    screen_for_secrets(&descriptor)?;
    match core_validate_checksum(&descriptor) {
        Ok(ChecksumStatus::Present) => Ok(ChecksumValidation {
            status: ChecksumValidationStatus::Valid,
            valid: true,
        }),
        Ok(ChecksumStatus::Missing) => Ok(ChecksumValidation {
            status: ChecksumValidationStatus::Missing,
            valid: false,
        }),
        Err(e) if e.code() == ErrorCode::ChecksumInvalid => Ok(ChecksumValidation {
            status: ChecksumValidationStatus::Invalid,
            valid: false,
        }),
        Err(e) => Err(e),
    }
}

/// `compute_checksum` (§21.3): return the descriptor with a freshly computed BIP380
/// `#checksum`. The descriptor is screened for secrets first — `compute` echoes the
/// descriptor back, so an `xprv` must be blocked before it is processed or returned.
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), empty-input (`E-INPUT-001`), or
/// charset (`E-PARSE-001`) errors.
pub fn compute_checksum(descriptor: String) -> Result<String, LifeboatError> {
    ensure_nonempty(&descriptor)?;
    screen_for_secrets(&descriptor)?;
    core_compute_checksum(&descriptor)
}

/// `render_miniscript_policy_dot` (US-088): render a descriptor's lifted
/// spending policy as redacted GraphViz DOT for the desktop UI. The UI may draw
/// the tree, but descriptor parsing and Miniscript lifting stay in Rust.
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), empty-input (`E-INPUT-001`), or
/// descriptor/policy parse (`E-PARSE-*`) errors.
pub fn render_miniscript_policy_dot(descriptor: String) -> Result<String, LifeboatError> {
    ensure_nonempty(&descriptor)?;
    screen_for_secrets(&descriptor)?;
    core_descriptor_to_dot(&descriptor)
}

/// `render_liana_recovery_tree` (US-091): extract and render the public-safe
/// Liana recovery-path tree, including per-path timelock estimates.
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), empty-input (`E-INPUT-001`), or
/// descriptor/policy parse (`E-PARSE-*`) errors.
pub fn render_liana_recovery_tree(descriptor: String) -> Result<LianaRecoveryTree, LifeboatError> {
    ensure_nonempty(&descriptor)?;
    screen_for_secrets(&descriptor)?;
    core_liana_recovery_tree(&descriptor)
}

/// `render_liana_recovery_tree` with an optional current block height (US-092):
/// extract and render the public-safe Liana recovery-path tree, adding countdowns
/// for block-height `older` / `after` constraints when the caller supplies a
/// current height. No network lookup happens here.
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), empty-input (`E-INPUT-001`), or
/// descriptor/policy parse (`E-PARSE-*`) errors.
pub fn render_liana_recovery_tree_at_block(
    descriptor: String,
    current_block_height: Option<u32>,
) -> Result<LianaRecoveryTree, LifeboatError> {
    ensure_nonempty(&descriptor)?;
    screen_for_secrets(&descriptor)?;
    match current_block_height {
        Some(height) => core_liana_recovery_tree_at_block(&descriptor, height),
        None => core_liana_recovery_tree(&descriptor),
    }
}

// --- Boundary clock ---------------------------------------------------------

/// Current UTC time as an ISO-8601 `YYYY-MM-DDThh:mm:ssZ` string, for stamping a
/// report's `created_at` at the command boundary. The wall clock is read **here**,
/// never inside the report engine (§19 / §27 determinism); tests pass a fixed
/// timestamp to [`audit_descriptor`] instead.
#[must_use]
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    unix_to_iso8601(secs)
}

/// Render a Unix timestamp (seconds since the epoch, UTC) as ISO-8601 using Howard
/// Hinnant's `civil_from_days` algorithm — no date-library dependency (the same
/// approach the CLI and `wallet-imports` use for timestamps).
fn unix_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 -> civil (y, m, d), shifting the era to March-based.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// ===========================================================================
// US-043 — report / runbook / import / save / link / app-info (§21.3)
// ===========================================================================

/// The `#checksum`/text label for a redaction mode (`RedactionMode`'s kebab-case
/// serde spelling), used in deterministic suggested filenames.
fn redaction_slug(mode: RedactionMode) -> &'static str {
    match mode {
        RedactionMode::PublicSafe => "public-safe",
        RedactionMode::Private => "private",
    }
}

// --- generate_report (§21.3) ------------------------------------------------

/// The serialization format for [`generate_report`] (§21.3 `ReportFormat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    /// The canonical compact §19.1 JSON (the default).
    #[default]
    Json,
    /// Pretty-printed JSON, for human inspection.
    JsonPretty,
    /// The §19.1 Markdown rendering.
    Markdown,
}

/// Input for [`generate_report`] (§21.3 `ReportGenerationInput`): the descriptor to
/// audit plus the same optional knobs as [`audit_descriptor`], and the export
/// redaction mode (§17.7 default `public-safe`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportGenerationInput {
    /// The watch-only output descriptor to audit.
    pub descriptor: String,
    /// Explicit network override; inferred when absent (ambiguous → typed error).
    #[serde(default)]
    pub network: Option<NetworkArg>,
    /// A known address to confirm membership of, if any (§17.5).
    #[serde(default)]
    pub known_address: Option<String>,
    /// How many receive/change addresses the report derives.
    #[serde(default)]
    pub derive_count: Option<u32>,
    /// The export redaction mode; defaults to the §17.7 share-safe `public-safe`.
    #[serde(default)]
    pub redaction: RedactionMode,
}

/// The result of [`generate_report`] (§21.3 `ReportArtifact`): the rendered,
/// redaction-applied document plus the metadata the UI needs to save it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportArtifact {
    /// The format the document was rendered to (echoed back).
    pub format: ReportFormat,
    /// The redaction mode applied (echoed back).
    pub redaction: RedactionMode,
    /// The MIME type for the document (e.g. `"application/json"`).
    pub mime_type: String,
    /// A deterministic, date-free suggested filename for the save dialog.
    pub suggested_filename: String,
    /// The rendered document text. The UI encodes it to UTF-8 bytes for
    /// [`save_export`].
    pub content: String,
}

/// `generate_report` (§21.3): audit `input.descriptor` and render the §19.1 report
/// as JSON / pretty JSON / Markdown, with the requested redaction applied
/// (`public-safe` by default, §17.7). Unlike the raw `report-json` machine output,
/// this is the **export** path, so it honors redaction.
///
/// `created_at` and `app_version` are supplied by the boundary so the report engine
/// stays a pure function of its inputs (§19 / §27 determinism).
///
/// # Errors
/// Propagates secret screening (`E-SECRET-*`), empty-input (`E-INPUT-001`),
/// descriptor parsing (`E-PARSE-*`), or ambiguous-network (`E-INPUT-003`) errors.
pub fn generate_report(
    input: ReportGenerationInput,
    format: ReportFormat,
    created_at: &str,
    app_version: &str,
) -> Result<ReportArtifact, LifeboatError> {
    ensure_nonempty(&input.descriptor)?;
    screen_for_secrets(&input.descriptor)?;
    if let Some(address) = &input.known_address {
        screen_for_secrets(address)?;
    }
    let parsed = parse_descriptor(&input.descriptor)?;

    let mut report_input = ReportInput::new(&parsed, created_at).with_app_version(app_version);
    if let Some(arg) = input.network {
        report_input = report_input.with_network(to_network(arg));
    }
    if let Some(address) = input.known_address.as_deref() {
        report_input = report_input.with_known_address(address);
    }
    if let Some(count) = input.derive_count {
        report_input = report_input.with_derive_count(count);
    }
    let report = build_report(&report_input);
    let redaction = input.redaction;

    // JSON applies redaction by emitting the redacted report; Markdown's
    // `to_markdown_mode` redacts internally (and adds the §private xpub warning).
    let (content, mime_type, ext) = match format {
        ReportFormat::Json => (
            report.redact(redaction).to_json(),
            "application/json",
            "json",
        ),
        ReportFormat::JsonPretty => (
            report.redact(redaction).to_json_pretty(),
            "application/json",
            "json",
        ),
        ReportFormat::Markdown => (report.to_markdown_mode(redaction), "text/markdown", "md"),
    };

    Ok(ReportArtifact {
        format,
        redaction,
        mime_type: mime_type.to_owned(),
        suggested_filename: format!(
            "bitcoin-lifeboat-readiness-{}.{ext}",
            redaction_slug(redaction)
        ),
        content,
    })
}

// --- generate_runbook (§21.3) -----------------------------------------------

/// The output format for [`generate_runbook`] (§21.3 `RunbookArtifact` content).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookFormat {
    /// A printable PDF (the default). Rendered by the runbook engine's pure-Rust
    /// backend when no Typst binary is bundled, so it needs no external dependency.
    #[default]
    Pdf,
    /// The runbook Markdown source.
    Markdown,
}

/// Input for [`generate_runbook`] (§21.3 `RunbookGenerationInput`): the template id,
/// an optional descriptor to pre-fill from, the redaction mode, and the format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RunbookGenerationInput {
    /// The runbook template id (an owner or heir/workshop/business template name).
    pub template: String,
    /// An optional watch-only descriptor to pre-fill the runbook; when absent the
    /// template's blanks are left for manual entry.
    #[serde(default)]
    pub descriptor: Option<String>,
    /// The redaction mode; defaults to the §17.7 share-safe `public-safe`.
    #[serde(default)]
    pub redaction: RedactionMode,
    /// The output format; defaults to `pdf`.
    #[serde(default)]
    pub format: RunbookFormat,
}

/// The result of [`generate_runbook`] (§21.3 `RunbookArtifact`): the rendered
/// runbook bytes plus the metadata the UI needs to save it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RunbookArtifact {
    /// The resolved template id (echoed back).
    pub template: String,
    /// The output format (echoed back).
    pub format: RunbookFormat,
    /// The redaction mode applied (echoed back).
    pub redaction: RedactionMode,
    /// The MIME type for the document (e.g. `"application/pdf"`).
    pub mime_type: String,
    /// A deterministic, date-free suggested filename for the save dialog.
    pub suggested_filename: String,
    /// The rendered runbook bytes (a PDF, or UTF-8 Markdown) for [`save_export`].
    pub content: Vec<u8>,
}

/// A bundled runbook template, of either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunbookTemplateKind {
    /// An owner recovery runbook (US-032).
    Owner(OwnerTemplate),
    /// A heir / workshop / business runbook (US-033).
    Heir(HeirTemplate),
}

/// A standalone `generate-runbook` template is not the companion of a specific
/// saved report, so it cites a constant, obviously-null hash — keeping the footer
/// populated and the output byte-deterministic (§19 / §27) without implying a
/// report that does not exist. (Mirrors the CLI's `RUNBOOK_PLACEHOLDER_REPORT_HASH`.)
const RUNBOOK_PLACEHOLDER_REPORT_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Resolve a template id to its template by scanning both families' stable names
/// (so this never drifts as templates are added); `None` for an unknown id.
fn resolve_template(id: &str) -> Option<RunbookTemplateKind> {
    if let Some(template) = OwnerTemplate::ALL.into_iter().find(|t| t.name() == id) {
        return Some(RunbookTemplateKind::Owner(template));
    }
    if let Some(template) = HeirTemplate::ALL.into_iter().find(|t| t.name() == id) {
        return Some(RunbookTemplateKind::Heir(template));
    }
    None
}

/// The comma-separated list of every valid template id (for an error message).
fn known_template_ids() -> String {
    OwnerTemplate::ALL
        .iter()
        .map(|t| t.name())
        .chain(HeirTemplate::ALL.iter().map(|t| t.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `template`'s stable id (used as the artifact's `template` and in the filename).
fn template_name(template: RunbookTemplateKind) -> &'static str {
    match template {
        RunbookTemplateKind::Owner(t) => t.name(),
        RunbookTemplateKind::Heir(t) => t.name(),
    }
}

/// The default `(script_type, threshold, key_count, has_passphrase)` for a
/// template — used for a blank runbook and as the fallback when a supplied
/// descriptor is singlesig. (Mirrors the CLI's `template_defaults`.)
fn template_defaults(template: RunbookTemplateKind) -> (&'static str, Option<u32>, u32, bool) {
    match template {
        RunbookTemplateKind::Owner(t) => match t.quorum() {
            Some((m, n)) => ("wsh(sortedmulti)", Some(m), n, false),
            None => ("wpkh", None, 1, t == OwnerTemplate::SinglesigPassphrase),
        },
        RunbookTemplateKind::Heir(t) => match t {
            HeirTemplate::HeirMultisig2of3 | HeirTemplate::BusinessTreasury => {
                ("wsh(sortedmulti)", Some(2), 3, false)
            }
            HeirTemplate::HeirMultisig3of5 => ("wsh(sortedmulti)", Some(3), 5, false),
            HeirTemplate::LianaTimelock => ("wsh(or_d timelock)", None, 2, false),
            HeirTemplate::HeirSinglesigPassphrase => ("wpkh", None, 1, true),
            HeirTemplate::HeirSinglesigBasic | HeirTemplate::MeetupWorkshop => {
                ("wpkh", None, 1, false)
            }
        },
    }
}

/// `A`, `B`, … for signer labels (a multisig has at most 15 keys, §17.2).
fn signer_letter(index: usize) -> char {
    char::from(b'A'.wrapping_add((index % 26) as u8))
}

/// Build the §17.8 signer list from a descriptor's key origins: one labelled signer
/// per key, with its fingerprint and origin path (blank when the descriptor omits
/// them). No xpubs or device models — those are not present in a watch-only
/// descriptor. (Mirrors the CLI's `signers_from_descriptor`.)
fn signers_from_descriptor(parsed: &ParsedDescriptor) -> Vec<Signer> {
    parsed
        .key_origins()
        .iter()
        .enumerate()
        .map(|(index, origin)| {
            Signer::new(
                format!("Signer {}", signer_letter(index)),
                origin.fingerprint_hex().unwrap_or_default(),
                origin.derivation_path_display().unwrap_or_default(),
            )
        })
        .collect()
}

/// Build the runbook data, pre-filling from a parsed descriptor when one was
/// supplied and otherwise leaving template-appropriate blanks. (Mirrors the CLI's
/// `build_runbook_data`.)
fn build_runbook_data(
    template: RunbookTemplateKind,
    parsed: Option<&ParsedDescriptor>,
    app_version: &str,
) -> RunbookData {
    let (def_script, def_threshold, def_n, def_passphrase) = template_defaults(template);

    // A supplied multisig descriptor pins the actual M/N; otherwise the template
    // defaults stand in. `threshold`/`key_count` are `usize` upstream.
    let (threshold, key_count) = match parsed.and_then(ParsedDescriptor::multisig_info) {
        Some(info) => (Some(info.threshold() as u32), info.key_count() as u32),
        None => (def_threshold, def_n),
    };
    let signers = parsed.map(signers_from_descriptor).unwrap_or_default();
    let descriptor = parsed.map(|p| p.canonical().to_owned()).unwrap_or_default();

    RunbookData::new(
        RunbookWalletSummary::new(def_script, threshold, key_count),
        descriptor,
        String::new(), // next_drill: a blank field the owner fills in after a drill
        RUNBOOK_PLACEHOLDER_REPORT_HASH,
        app_version,
    )
    .with_signers(signers)
    .with_passphrase(def_passphrase)
}

/// Render `template`'s runbook Markdown in `mode`.
fn render_runbook_markdown(
    template: RunbookTemplateKind,
    data: &RunbookData,
    mode: RedactionMode,
) -> String {
    match template {
        RunbookTemplateKind::Owner(t) => render_owner_markdown(t, data, mode),
        RunbookTemplateKind::Heir(t) => render_heir_markdown(t, data, mode),
    }
}

/// Render `template`'s runbook PDF in `mode` (A4, the auto backend — which falls
/// back to the always-available pure-Rust renderer when no Typst binary is bundled,
/// so this needs no external dependency).
fn render_runbook_pdf(
    template: RunbookTemplateKind,
    data: &RunbookData,
    mode: RedactionMode,
) -> Result<Vec<u8>, LifeboatError> {
    match template {
        RunbookTemplateKind::Owner(t) => {
            render_owner_pdf(t, data, PdfBackend::Auto, PageSize::A4, mode)
        }
        RunbookTemplateKind::Heir(t) => {
            render_heir_pdf(t, data, PdfBackend::Auto, PageSize::A4, mode)
        }
    }
}

/// `generate_runbook` (§21.3): render a recovery / inheritance runbook from a
/// bundled template — optionally pre-filled from a watch-only descriptor — in the
/// requested redaction mode and format (`pdf` by default).
///
/// `app_version` is supplied by the boundary so the runbook footer stays a pure
/// function of its inputs (§19 / §27 determinism).
///
/// # Errors
/// Returns `E-INPUT-003` for an unknown template id; propagates secret screening
/// (`E-SECRET-*`), empty / parse (`E-INPUT-001` / `E-PARSE-*`) errors for a supplied
/// descriptor, or a PDF backend error (`E-DEP-001`).
pub fn generate_runbook(
    input: RunbookGenerationInput,
    app_version: &str,
) -> Result<RunbookArtifact, LifeboatError> {
    let template = resolve_template(&input.template).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "unknown runbook template '{}'; available templates: {}",
            input.template,
            known_template_ids()
        ))
    })?;

    // An optional descriptor pre-fills the runbook; screen it for secrets BEFORE
    // parsing (§13.5), exactly like the other descriptor commands.
    let parsed = match input.descriptor.as_deref() {
        Some(descriptor) => {
            ensure_nonempty(descriptor)?;
            screen_for_secrets(descriptor)?;
            Some(parse_descriptor(descriptor)?)
        }
        None => None,
    };

    let data = build_runbook_data(template, parsed.as_ref(), app_version);
    let content = match input.format {
        RunbookFormat::Markdown => {
            render_runbook_markdown(template, &data, input.redaction).into_bytes()
        }
        RunbookFormat::Pdf => render_runbook_pdf(template, &data, input.redaction)?,
    };

    let (mime_type, ext) = match input.format {
        RunbookFormat::Pdf => ("application/pdf", "pdf"),
        RunbookFormat::Markdown => ("text/markdown", "md"),
    };
    Ok(RunbookArtifact {
        template: template_name(template).to_owned(),
        format: input.format,
        redaction: input.redaction,
        mime_type: mime_type.to_owned(),
        suggested_filename: format!(
            "{}-{}.{ext}",
            template_name(template),
            redaction_slug(input.redaction)
        ),
        content,
    })
}

// --- parse_wallet_export (§21.3) --------------------------------------------

/// `parse_wallet_export` (§21.3): read a wallet export file, screen it for secrets,
/// auto-detect its format, and normalize it into a [`NormalizedWalletExport`].
///
/// The file is read by path (no Tauri scope needed); a missing/unreadable file is
/// `E-FS-001` and an oversized file `E-INPUT-002`. `imported_at` is supplied by the
/// boundary (read there, like a report's `created_at`) so the result is a pure
/// function of its inputs (§19); the source filename is stamped from the path.
///
/// # Errors
/// `E-FS-001` (unreadable), `E-INPUT-002` (oversized), `E-SECRET-*` (a file carrying
/// private keys is refused before parsing, §13.5), or the importer's
/// `E-INPUT-*`/`E-PARSE-*` for an unrecognized or malformed export.
pub fn parse_wallet_export(
    file_path: &str,
    imported_at: &str,
) -> Result<NormalizedWalletExport, LifeboatError> {
    let path = std::path::Path::new(file_path);

    // Reject an oversized file before reading it into memory. `import_auto` also
    // guards the content length, but checking the on-disk size first avoids loading
    // a huge file (§17.9 / `wallet_imports::MAX_EXPORT_SIZE_BYTES`).
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > lifeboat_core::wallet_imports::MAX_EXPORT_SIZE_BYTES as u64 {
            return Err(
                LifeboatError::new(ErrorCode::InputTooLarge).with_context(format!(
                    "wallet export `{}` exceeds the {}-byte limit",
                    path.display(),
                    lifeboat_core::wallet_imports::MAX_EXPORT_SIZE_BYTES
                )),
            );
        }
    }

    let content = std::fs::read_to_string(path).map_err(|e| {
        LifeboatError::new(ErrorCode::FileNotFound)
            .with_context(format!("could not read wallet export `{}`", path.display()))
            .with_source(e)
    })?;

    // Screen for secret material BEFORE parsing (the §13.5 invariant): an export
    // carrying private keys is refused and never normalized or echoed.
    screen_for_secrets(&content)?;

    let mut export = import_auto(&content)?;
    // Stamp the fields the importer leaves to the caller: the import time (read at
    // the boundary) and the source filename's basename.
    export.imported_at = Some(imported_at.to_owned());
    export.raw_source_filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    Ok(export)
}

// --- save_export (§21.3) ----------------------------------------------------

/// `save_export` (§21.3): write `content` to a dialog-chosen `path`.
///
/// The path is selected by the OS save dialog on the frontend (which also confirms
/// any overwrite); this writes the bytes to it. A write failure (a non-writable
/// destination) is `E-FS-002`.
///
/// # Errors
/// `E-FS-002` when the destination cannot be written.
pub fn save_export(path: &str, content: &[u8]) -> Result<(), LifeboatError> {
    std::fs::write(path, content).map_err(|e| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context(format!("could not write to `{path}`"))
            .with_source(e)
    })
}

// --- open_external_link allowlist (§21.3) -----------------------------------

/// The GitHub repository URL base, generated at build time from
/// `project.config.toml` `github.url_base` (see `build.rs`). Never hardcoded.
const GH_URL_BASE: &str = env!("LIFEBOAT_GH_URL_BASE");

/// The website domain, generated at build time from `project.config.toml`
/// `site.domain` (see `build.rs`). Never hardcoded.
const SITE_DOMAIN: &str = env!("LIFEBOAT_SITE_DOMAIN");

/// The Signet faucet URL surfaced as browser-only instructions in Practice Mode.
const SIGNET_FAUCET_URL: &str = "https://faucet.mutinynet.com/";

/// The website origin, `https://<domain>`.
fn site_origin() -> String {
    format!("https://{SITE_DOMAIN}")
}

/// The `https://<domain>/docs/` prefix the `/docs/*` allowlist glob matches.
fn docs_prefix() -> String {
    format!("https://{SITE_DOMAIN}/docs/")
}

/// The §21.3 external-link allowlist, in display form (the `/docs/*` entry shows the
/// glob). Generated from `project.config.toml`, so changing the org/domain there
/// updates the list with no code change. For the UI's "links we can open" affordance.
#[must_use]
pub fn external_link_allowlist() -> Vec<String> {
    vec![
        GH_URL_BASE.to_owned(),
        format!("{GH_URL_BASE}/releases"),
        format!("{GH_URL_BASE}/issues"),
        site_origin(),
        format!("{}/docs/*", site_origin()),
        SIGNET_FAUCET_URL.to_owned(),
    ]
}

/// `open_external_link` allowlist check (§21.3): the **decision** half of the
/// command, kept here (GUI-agnostic, tested) so the Tauri wrapper only performs the
/// OS-browser IO once a URL is vetted.
///
/// A URL is allowed iff it exactly equals the repo URL, its `/releases` or `/issues`
/// child, the site origin, or the Signet faucet — or begins with the
/// `https://<domain>/docs/` prefix (the `/docs/*` glob). Exact matching (and an
/// `https://`-anchored docs prefix) rejects look-alike hosts such as
/// `https://<domain>.evil.example`.
///
/// # Errors
/// `E-LINK-001` (`LinkNotAllowed`, severity `security`) when the URL is not on the
/// allowlist.
pub fn check_external_link(url: &str) -> Result<(), LifeboatError> {
    let url = url.trim();
    let exact = [
        GH_URL_BASE.to_owned(),
        format!("{GH_URL_BASE}/releases"),
        format!("{GH_URL_BASE}/issues"),
        site_origin(),
        SIGNET_FAUCET_URL.to_owned(),
    ];
    let docs = docs_prefix();
    if exact.iter().any(|u| u == url) || url.starts_with(docs.as_str()) {
        Ok(())
    } else {
        Err(LifeboatError::new(ErrorCode::LinkNotAllowed)
            .with_context("the requested link is not in the project's external-link allowlist"))
    }
}

// --- get_app_info (§21.3) ---------------------------------------------------

/// Application metadata for [`app_info`] (§21.3 `AppInfo`). `repository` and
/// `homepage` come from `project.config.toml` (never hardcoded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AppInfo {
    /// The application name.
    pub name: String,
    /// The application version (supplied by the boundary).
    pub version: String,
    /// The SPDX license id of the application code.
    pub license: String,
    /// The source repository URL (from `project.config.toml`).
    pub repository: String,
    /// The project homepage URL (from `project.config.toml`).
    pub homepage: String,
}

/// `get_app_info` (§21.3): return the app's name, version, license, and the
/// repository / homepage URLs (the latter two from `project.config.toml`).
///
/// `app_version` is supplied by the boundary (the desktop crate's
/// `CARGO_PKG_VERSION`), so this crate carries no version of its own.
#[must_use]
pub fn app_info(app_version: &str) -> AppInfo {
    AppInfo {
        name: "Bitcoin Lifeboat".to_owned(),
        version: app_version.to_owned(),
        license: "MIT".to_owned(),
        repository: GH_URL_BASE.to_owned(),
        homepage: site_origin(),
    }
}
// --- settings (§22.11 Public preferences) -----------------------------------

/// The current settings-file schema version. Bumped when the on-disk shape
/// changes; [`load_settings`] uses it (with serde field defaults) to stay
/// forward/backward tolerant.
pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

/// The settings file name, stored inside the app config directory.
const SETTINGS_FILE_NAME: &str = "settings.json";

/// Serde default for [`Settings::version`].
fn default_schema_version() -> u32 {
    SETTINGS_SCHEMA_VERSION
}

/// Serde default for [`Settings::language`].
fn default_language() -> String {
    "en".to_owned()
}

/// The UI theme preference (§22.10). Serializes snake_case to match the
/// frontend: `"system"` / `"light"` / `"dark"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeSetting {
    /// Follow the operating-system light/dark preference.
    #[default]
    System,
    /// Always use the light theme.
    Light,
    /// Always use the dark theme.
    Dark,
}

/// The §15.5 large-text accessibility preference. Serializes snake_case to match
/// the frontend: `"normal"` (1x) / `"large"` (1.5x) / `"larger"` (2x). The UI
/// applies the scale by setting the root font size, so all rem-based sizing
/// grows together (§15.5 item 7 — "Large-text mode (1.5x and 2x scaling)").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextScaleSetting {
    /// Default 1x text size.
    #[default]
    Normal,
    /// 1.5x large-text mode.
    Large,
    /// 2x large-text mode.
    Larger,
}

/// The §22.11 Public, non-confidential user preferences persisted to the
/// settings file.
///
/// SAFETY (§13 / §22.11): EVERY field here is Public — a UI theme, a language
/// tag, and two display/diagnostic toggles. There is deliberately NO field that
/// unlocks seed entry, reveals a secret, or bypasses a safety warning, and no
/// Confidential wallet data (descriptors, xpubs, addresses) is ever stored here.
/// Diagnostic logging is OFF by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// The settings-file schema version (see [`SETTINGS_SCHEMA_VERSION`]).
    #[serde(default = "default_schema_version")]
    pub version: u32,
    /// The UI theme preference.
    #[serde(default)]
    pub theme: ThemeSetting,
    /// The BCP-47 UI language tag (e.g. `"en"`).
    #[serde(default = "default_language")]
    pub language: String,
    /// Whether diagnostic logging is enabled. OFF by default (§22.11).
    #[serde(default)]
    pub diagnostics_enabled: bool,
    /// Whether the UI shows advanced technical details (§22.7).
    #[serde(default)]
    pub show_advanced_details: bool,
    /// The §15.5 large-text accessibility scale. `normal` (1x) by default.
    #[serde(default)]
    pub text_scale: TextScaleSetting,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: SETTINGS_SCHEMA_VERSION,
            theme: ThemeSetting::System,
            language: default_language(),
            diagnostics_enabled: false,
            show_advanced_details: false,
            text_scale: TextScaleSetting::Normal,
        }
    }
}

/// Load the §22.11 Public settings from `<config_dir>/settings.json`.
///
/// A missing file yields [`Settings::default`] (first launch); missing individual
/// fields fall back to their defaults (forward/backward tolerant). A
/// present-but-unparseable file is `E-INTERNAL-002`
/// ([`ErrorCode::SchemaMigrationRequired`]) so the UI can offer "Clear all local
/// data"; any other read error is `E-FS-001`.
pub fn load_settings(config_dir: &std::path::Path) -> Result<Settings, LifeboatError> {
    let path = config_dir.join(SETTINGS_FILE_NAME);
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Settings>(&bytes).map_err(|e| {
            LifeboatError::new(ErrorCode::SchemaMigrationRequired)
                .with_context("the settings file could not be read in the current schema")
                .with_source(e)
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(LifeboatError::new(ErrorCode::FileNotFound)
            .with_context("could not read the settings file")
            .with_source(e)),
    }
}

/// Save the §22.11 Public settings to `<config_dir>/settings.json`, creating the
/// directory if needed. A write failure is `E-FS-002`.
pub fn save_settings(
    config_dir: &std::path::Path,
    settings: &Settings,
) -> Result<(), LifeboatError> {
    std::fs::create_dir_all(config_dir).map_err(|e| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not create the settings directory")
            .with_source(e)
    })?;
    let json = serde_json::to_vec_pretty(settings).map_err(|e| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the settings")
            .with_source(e)
    })?;
    let path = config_dir.join(SETTINGS_FILE_NAME);
    std::fs::write(path, json).map_err(|e| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not write the settings file")
            .with_source(e)
    })
}

/// Clear all local data: remove `<config_dir>/settings.json` (§22.11 "Clear all
/// local data"). Absence is success — nothing else is persisted by default (no
/// wallet metadata, §13). A removal failure is `E-FS-002`.
pub fn clear_all_data(config_dir: &std::path::Path) -> Result<(), LifeboatError> {
    let path = config_dir.join(SETTINGS_FILE_NAME);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not remove the settings file")
            .with_source(e)),
    }
}
