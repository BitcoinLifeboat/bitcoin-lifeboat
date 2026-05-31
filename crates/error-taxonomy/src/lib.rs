//! `error-taxonomy` — the single, typed error vocabulary for Bitcoin Lifeboat.
//!
//! Every layer of the application (core crates, CLI, desktop commands) maps its
//! failures to a [`LifeboatError`], which carries a stable [`ErrorCode`]. Each
//! code has a fixed [`Severity`], human-readable `title` / `description` /
//! `action` text, and an [i18n key](ErrorCode::i18n_key) (e.g.
//! `errors.E-PARSE-001`) that resolves against the string catalog in
//! `strings/en.json`.
//!
//! # Invariants
//! - **Stable codes.** The string form of every [`ErrorCode`] (`E-PARSE-001`,
//!   …) is part of the public contract and is never renamed; it appears in JSON
//!   reports, CLI output, and the i18n catalog. New failure modes get new codes.
//! - **No panics.** Nothing in this crate panics or calls `unwrap` / `expect`
//!   outside of `#[cfg(test)]`.
//! - **Catalog parity.** `strings/en.json` mirrors the `title` / `description` /
//!   `action` text of every code; a unit test fails the build if they drift.
//! - **Fluent parity.** The Rust-side Project Fluent catalogs use the same
//!   logical keys as the JSON/i18next catalog (`errors.<CODE>.title`, etc.),
//!   represented as Fluent message IDs `errors-<CODE>` with `.title`,
//!   `.description`, and `.action` attributes.
//!
//! The catalog corresponds to PRD Appendix C (error codes) and Appendix D
//! (i18n). See `docs/PRD-v2.md`.

use fluent_bundle::{FluentBundle, FluentResource};
use std::fmt;
use unic_langid::LanguageIdentifier;

const EN_FTL: &str = include_str!("../strings/en.ftl");
const ES_FTL: &str = include_str!("../strings/es.ftl");
const DE_FTL: &str = include_str!("../strings/de.ftl");
const FR_FTL: &str = include_str!("../strings/fr.ftl");

/// Rust-side Fluent locales bundled with the error catalog (US-097).
pub const SUPPORTED_FLUENT_LOCALES: &[&str] = &["en", "es", "de", "fr"];

type ErrorFluentBundle = FluentBundle<FluentResource>;

/// Severity classification for a [`LifeboatError`] (PRD Appendix C).
///
/// Serializes to its stable snake_case string (`"user_correctable"`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The user can correct the input and retry (e.g. empty input, bad path).
    UserCorrectable,
    /// Non-fatal: readiness is reduced but analysis can continue.
    Warning,
    /// A serious defect that forces a "Not Ready" verdict.
    Critical,
    /// A safety event: secret material or an unexpected network call.
    Security,
    /// A bug or environment fault the user cannot correct.
    Internal,
}

impl Severity {
    /// The stable snake_case string form (`"user_correctable"`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCorrectable => "user_correctable",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Security => "security",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Static metadata describing a single [`ErrorCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorMeta {
    /// Stable code string, e.g. `"E-PARSE-001"`.
    pub code: &'static str,
    /// Fixed severity classification.
    pub severity: Severity,
    /// Short human-readable label.
    pub title: &'static str,
    /// Plain-English description of the failure.
    pub description: &'static str,
    /// What the user should do next.
    pub action: &'static str,
    /// i18n lookup key, e.g. `"errors.E-PARSE-001"`.
    pub i18n_key: &'static str,
}

/// Localized user-facing text for an [`ErrorCode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedError {
    /// The normalized locale actually used (`"en"`, `"es"`, `"de"`, or `"fr"`).
    pub locale: &'static str,
    /// Short localized label.
    pub title: String,
    /// Localized description of the failure.
    pub description: String,
    /// Localized next action.
    pub action: String,
}

/// Every stable error code in the Bitcoin Lifeboat taxonomy (PRD Appendix C).
///
/// The [string form](Self::as_str) of each variant is a stable public
/// identifier and must never be renamed. The enum is `#[non_exhaustive]`:
/// later milestones add codes, and that must not be a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    // E-INPUT-*
    /// `E-INPUT-001` — no descriptor or file was provided.
    InputEmpty,
    /// `E-INPUT-002` — input exceeds the 10 MB limit.
    InputTooLarge,
    /// `E-INPUT-003` — content matches no known wallet export format.
    InputInvalidFormat,
    // E-PARSE-*
    /// `E-PARSE-001` — text is not a valid BIP380 descriptor.
    ParseFailed,
    /// `E-PARSE-002` — descriptor checksum is missing.
    ChecksumMissing,
    /// `E-PARSE-003` — descriptor checksum does not match its content.
    ChecksumInvalid,
    /// `E-PARSE-004` — descriptor mixes keys from multiple networks.
    NetworkMixed,
    /// `E-PARSE-005` — descriptor contains private-key material.
    ContainsPrivateKey,
    /// `E-PARSE-006` — descriptor uses an unsupported function.
    UnsupportedFunction,
    /// `E-PARSE-007` — multisig threshold M exceeds key count N.
    ThresholdExceedsKeys,
    // E-SECRET-*
    /// `E-SECRET-001` — BIP39 mnemonic with a valid checksum detected.
    Bip39Detected,
    /// `E-SECRET-002` — suspected BIP39 mnemonic (checksum did not validate).
    Bip39Suspected,
    /// `E-SECRET-003` — WIF private key detected.
    WifDetected,
    /// `E-SECRET-004` — extended private key (xprv/…) detected.
    ExtendedPrivateKeyDetected,
    /// `E-SECRET-005` — SLIP-39 Shamir backup share detected.
    Slip39Detected,
    /// `E-SECRET-006` — codex32 (BIP-93) secret detected.
    Codex32Detected,
    /// `E-SECRET-007` — suspected raw private key (hex in a risky context).
    RawPrivateKeySuspected,
    // E-FS-*
    /// `E-FS-001` — file path does not exist or is not readable.
    FileNotFound,
    /// `E-FS-002` — destination path is not writable.
    CannotWrite,
    /// `E-FS-003` — a file already exists at the destination.
    DestinationExists,
    // E-NETWORK-*
    /// `E-NETWORK-001` — a user-initiated network call failed.
    NetworkUnreachable,
    /// `E-NETWORK-002` — a network call was attempted without user action.
    UnexpectedNetworkCall,
    // E-DEP-*
    /// `E-DEP-001` — the bundled Typst binary was not found.
    TypstNotBundled,
    /// `E-DEP-002` — the HWI sidecar binary was not found.
    HwiNotAvailable,
    // E-LINK-*
    /// `E-LINK-001` — external link is not in the allowlist.
    LinkNotAllowed,
    // E-INTERNAL-*
    /// `E-INTERNAL-001` — an unexpected internal error occurred.
    Internal,
    /// `E-INTERNAL-002` — the settings file needs a schema migration.
    SchemaMigrationRequired,
}

impl ErrorCode {
    /// Every code, in catalog order. Use for exhaustive iteration/validation.
    pub const ALL: &'static [ErrorCode] = &[
        Self::InputEmpty,
        Self::InputTooLarge,
        Self::InputInvalidFormat,
        Self::ParseFailed,
        Self::ChecksumMissing,
        Self::ChecksumInvalid,
        Self::NetworkMixed,
        Self::ContainsPrivateKey,
        Self::UnsupportedFunction,
        Self::ThresholdExceedsKeys,
        Self::Bip39Detected,
        Self::Bip39Suspected,
        Self::WifDetected,
        Self::ExtendedPrivateKeyDetected,
        Self::Slip39Detected,
        Self::Codex32Detected,
        Self::RawPrivateKeySuspected,
        Self::FileNotFound,
        Self::CannotWrite,
        Self::DestinationExists,
        Self::NetworkUnreachable,
        Self::UnexpectedNetworkCall,
        Self::TypstNotBundled,
        Self::HwiNotAvailable,
        Self::LinkNotAllowed,
        Self::Internal,
        Self::SchemaMigrationRequired,
    ];

    /// Static metadata (code string, severity, text, i18n key) for this code.
    ///
    /// This is the single source of truth; `strings/en.json` mirrors the text.
    #[must_use]
    pub const fn meta(self) -> ErrorMeta {
        match self {
            Self::InputEmpty => ErrorMeta {
                code: "E-INPUT-001",
                severity: Severity::UserCorrectable,
                title: "Empty input",
                description: "No descriptor or file was provided.",
                action: "Paste a descriptor or choose a file.",
                i18n_key: "errors.E-INPUT-001",
            },
            Self::InputTooLarge => ErrorMeta {
                code: "E-INPUT-002",
                severity: Severity::UserCorrectable,
                title: "Input too large",
                description: "The file exceeds the 10 MB limit.",
                action: "Trim the file or contact support if it should be smaller.",
                i18n_key: "errors.E-INPUT-002",
            },
            Self::InputInvalidFormat => ErrorMeta {
                code: "E-INPUT-003",
                severity: Severity::UserCorrectable,
                title: "Invalid file format",
                description: "The file's content does not match any known wallet export format.",
                action: "Confirm the file is a descriptor (.txt, .json) or supported wallet \
                         export.",
                i18n_key: "errors.E-INPUT-003",
            },
            Self::ParseFailed => ErrorMeta {
                code: "E-PARSE-001",
                severity: Severity::UserCorrectable,
                title: "Descriptor cannot be parsed",
                description: "The text you provided is not a valid BIP380 descriptor.",
                action: "Confirm you copied the full descriptor including any leading \
                         `wsh(`/`wpkh(`. If you're unsure, see the per-wallet export \
                         instructions.",
                i18n_key: "errors.E-PARSE-001",
            },
            Self::ChecksumMissing => ErrorMeta {
                code: "E-PARSE-002",
                severity: Severity::Warning,
                title: "Descriptor checksum missing",
                description: "BIP380 descriptors should include a `#xxxxxxxx` checksum.",
                action: "Add the checksum (Lifeboat can compute one) or re-export from your \
                         wallet.",
                i18n_key: "errors.E-PARSE-002",
            },
            Self::ChecksumInvalid => ErrorMeta {
                code: "E-PARSE-003",
                severity: Severity::Critical,
                title: "Descriptor checksum invalid",
                description: "The descriptor's checksum does not match its content. The \
                              descriptor may have been transcribed incorrectly.",
                action: "Re-export the descriptor from your wallet software.",
                i18n_key: "errors.E-PARSE-003",
            },
            Self::NetworkMixed => ErrorMeta {
                code: "E-PARSE-004",
                severity: Severity::Critical,
                title: "Descriptor mixes networks",
                description: "The descriptor contains keys from multiple Bitcoin networks \
                              (e.g., mainnet and testnet).",
                action: "This is almost always a mistake. Re-export the descriptor and verify \
                         it contains only mainnet keys (or only testnet, if intentional).",
                i18n_key: "errors.E-PARSE-004",
            },
            Self::ContainsPrivateKey => ErrorMeta {
                code: "E-PARSE-005",
                severity: Severity::Critical,
                title: "Descriptor contains private keys",
                description: "The descriptor includes an extended private key \
                              (xprv/yprv/zprv/tprv/uprv/vprv) or a raw private key. Lifeboat \
                              refuses to process descriptors that contain secret material.",
                action: "Re-export the descriptor in watch-only form (xpub instead of xprv).",
                i18n_key: "errors.E-PARSE-005",
            },
            Self::UnsupportedFunction => ErrorMeta {
                code: "E-PARSE-006",
                severity: Severity::UserCorrectable,
                title: "Unsupported descriptor function",
                description: "The descriptor uses a function Lifeboat does not yet support in \
                              this version (e.g., raw(), addr()).",
                action: "Use a wallet that exports a supported descriptor (wpkh, wsh, \
                         sh(wpkh), multi, sortedmulti).",
                i18n_key: "errors.E-PARSE-006",
            },
            Self::ThresholdExceedsKeys => ErrorMeta {
                code: "E-PARSE-007",
                severity: Severity::Warning,
                title: "Multisig threshold exceeds key count",
                description: "The descriptor specifies M-of-N where M > N, which can never be \
                              satisfied.",
                action: "Confirm the descriptor; this likely indicates a transcription error.",
                i18n_key: "errors.E-PARSE-007",
            },
            Self::Bip39Detected => ErrorMeta {
                code: "E-SECRET-001",
                severity: Severity::Security,
                title: "BIP39 mnemonic detected",
                description: "The input contains a sequence of words matching a BIP39 wordlist \
                              with a valid checksum. Lifeboat does not accept seed phrases.",
                action: "Export the OUTPUT DESCRIPTOR (not the seed) from your wallet software \
                         and paste it instead.",
                i18n_key: "errors.E-SECRET-001",
            },
            Self::Bip39Suspected => ErrorMeta {
                code: "E-SECRET-002",
                severity: Severity::Security,
                title: "Possible BIP39 mnemonic detected",
                description: "The input contains a sequence of BIP39 words; the checksum did \
                              not validate but the pattern is suspicious.",
                action: "If you intended to paste a descriptor and this is a false positive, \
                         type \"I confirm this is not a real seed\" to proceed.",
                i18n_key: "errors.E-SECRET-002",
            },
            Self::WifDetected => ErrorMeta {
                code: "E-SECRET-003",
                severity: Severity::Security,
                title: "Private key (WIF) detected",
                description: "The input matches the WIF private key format. Lifeboat does not \
                              accept private keys.",
                action: "Use the corresponding public key or xpub instead.",
                i18n_key: "errors.E-SECRET-003",
            },
            Self::ExtendedPrivateKeyDetected => ErrorMeta {
                code: "E-SECRET-004",
                severity: Severity::Security,
                title: "Extended private key detected",
                description: "The input contains an xprv / yprv / zprv / tprv / uprv / vprv. \
                              Lifeboat does not accept extended private keys.",
                action: "Use the corresponding xpub / ypub / zpub / tpub / upub / vpub \
                         instead.",
                i18n_key: "errors.E-SECRET-004",
            },
            Self::Slip39Detected => ErrorMeta {
                code: "E-SECRET-005",
                severity: Severity::Security,
                title: "SLIP-39 share detected",
                description: "The input appears to be a SLIP-39 Shamir backup share.",
                action: "Lifeboat does not need SLIP-39 shares. Use your wallet's output \
                         descriptor.",
                i18n_key: "errors.E-SECRET-005",
            },
            Self::Codex32Detected => ErrorMeta {
                code: "E-SECRET-006",
                severity: Severity::Security,
                title: "codex32 secret detected",
                description: "The input appears to be a codex32 (BIP-93) secret.",
                action: "Lifeboat does not need codex32 secrets. Use your wallet's output \
                         descriptor.",
                i18n_key: "errors.E-SECRET-006",
            },
            Self::RawPrivateKeySuspected => ErrorMeta {
                code: "E-SECRET-007",
                severity: Severity::Security,
                title: "Possible raw private key detected",
                description: "The input contains a 64-character hex string in a suspicious \
                              context (e.g., adjacent to the word \"private\" or \"key\").",
                action: "Confirm this is not a private key. If you intended a transaction ID \
                         or block hash, it should not appear in this field.",
                i18n_key: "errors.E-SECRET-007",
            },
            Self::FileNotFound => ErrorMeta {
                code: "E-FS-001",
                severity: Severity::UserCorrectable,
                title: "File not found",
                description: "The file path you provided does not exist or is not readable.",
                action: "Verify the path and permissions, then try again.",
                i18n_key: "errors.E-FS-001",
            },
            Self::CannotWrite => ErrorMeta {
                code: "E-FS-002",
                severity: Severity::UserCorrectable,
                title: "Cannot write to destination",
                description: "The destination path is not writable.",
                action: "Choose a different destination or check permissions.",
                i18n_key: "errors.E-FS-002",
            },
            Self::DestinationExists => ErrorMeta {
                code: "E-FS-003",
                severity: Severity::Warning,
                title: "Destination file exists",
                description: "A file already exists at the destination.",
                action: "Confirm overwrite or choose a different name.",
                i18n_key: "errors.E-FS-003",
            },
            Self::NetworkUnreachable => ErrorMeta {
                code: "E-NETWORK-001",
                severity: Severity::UserCorrectable,
                title: "Network unreachable",
                description: "The user-initiated network call failed.",
                action: "Verify your internet connection or try again later.",
                i18n_key: "errors.E-NETWORK-001",
            },
            Self::UnexpectedNetworkCall => ErrorMeta {
                code: "E-NETWORK-002",
                severity: Severity::Security,
                title: "Unexpected network call attempted",
                description: "Internal: A component attempted a network call without explicit \
                              user action.",
                action: "This is a bug. Please file an issue at the GitHub repository.",
                i18n_key: "errors.E-NETWORK-002",
            },
            Self::TypstNotBundled => ErrorMeta {
                code: "E-DEP-001",
                severity: Severity::Internal,
                title: "Typst not bundled",
                description: "PDF generation requires the bundled Typst binary, which was not \
                              found.",
                action: "Reinstall Lifeboat. If the issue persists, file an issue.",
                i18n_key: "errors.E-DEP-001",
            },
            Self::HwiNotAvailable => ErrorMeta {
                code: "E-DEP-002",
                severity: Severity::Internal,
                title: "HWI not available",
                description: "Hardware wallet operations require the HWI sidecar binary \
                              (v0.4+), which was not found.",
                action: "Reinstall the version of Lifeboat that includes HWI, or use \
                         file-based PSBT.",
                i18n_key: "errors.E-DEP-002",
            },
            Self::LinkNotAllowed => ErrorMeta {
                code: "E-LINK-001",
                severity: Severity::Security,
                title: "External link not allowed",
                description: "The link is not in the project's allowlist of external URLs.",
                action: "Verify the link manually in your browser if you trust it.",
                i18n_key: "errors.E-LINK-001",
            },
            Self::Internal => ErrorMeta {
                code: "E-INTERNAL-001",
                severity: Severity::Internal,
                title: "Unexpected error",
                description: "An unexpected internal error occurred.",
                action: "Please file an issue at the GitHub repository with the reproduction \
                         steps.",
                i18n_key: "errors.E-INTERNAL-001",
            },
            Self::SchemaMigrationRequired => ErrorMeta {
                code: "E-INTERNAL-002",
                severity: Severity::Internal,
                title: "Schema migration required",
                description: "The settings file uses a format from an older version of \
                              Lifeboat.",
                action: "Lifeboat will attempt to migrate. If that fails, delete the settings \
                         file.",
                i18n_key: "errors.E-INTERNAL-002",
            },
        }
    }

    /// The stable code string, e.g. `"E-PARSE-001"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.meta().code
    }

    /// The fixed [`Severity`] for this code.
    #[must_use]
    pub const fn severity(self) -> Severity {
        self.meta().severity
    }

    /// The short human-readable label.
    #[must_use]
    pub const fn title(self) -> &'static str {
        self.meta().title
    }

    /// The plain-English description of the failure.
    #[must_use]
    pub const fn description(self) -> &'static str {
        self.meta().description
    }

    /// What the user should do next.
    #[must_use]
    pub const fn action(self) -> &'static str {
        self.meta().action
    }

    /// The i18n lookup key, e.g. `"errors.E-PARSE-001"`.
    #[must_use]
    pub const fn i18n_key(self) -> &'static str {
        self.meta().i18n_key
    }

    /// Resolve a stable code string (`"E-PARSE-001"`) back into an [`ErrorCode`].
    ///
    /// Returns `None` for any unknown code.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == code)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_code(&code)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown error code: {code}")))
    }
}

/// The single error type returned across Bitcoin Lifeboat.
///
/// Wraps a stable [`ErrorCode`] plus an optional human-readable `context`
/// string and an optional underlying `source` error for diagnostics.
///
/// # Safety note
/// `context` is rendered in logs and surfaced to callers; it must **never**
/// contain secret material (seed words, private keys, raw descriptors with
/// xprv, …). Pass only safe, structural context (a code, a redacted hint).
#[derive(Debug, thiserror::Error)]
#[error("[{}] {}: {}", .code.as_str(), .code.title(), .code.description())]
pub struct LifeboatError {
    code: ErrorCode,
    context: Option<String>,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl LifeboatError {
    /// Construct an error from a [`ErrorCode`] with no extra context.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            context: None,
            source: None,
        }
    }

    /// Attach a safe, secret-free context string (builder style).
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Attach an underlying source error for diagnostics (builder style).
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The stable [`ErrorCode`].
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The fixed [`Severity`] of the underlying code.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.code.severity()
    }

    /// The i18n lookup key of the underlying code.
    #[must_use]
    pub const fn i18n_key(&self) -> &'static str {
        self.code.i18n_key()
    }

    /// The attached context string, if any.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }
}

impl From<ErrorCode> for LifeboatError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

/// Normalize a BCP-47-ish locale tag to one of the bundled Fluent locales.
///
/// Region-specific tags use their primary language subtag (`"es-MX"` → `"es"`).
/// Unsupported locales fall back to English instead of guessing.
#[must_use]
pub fn normalize_fluent_locale(locale: &str) -> &'static str {
    match locale
        .split('-')
        .next()
        .unwrap_or("en")
        .to_ascii_lowercase()
        .as_str()
    {
        "es" => "es",
        "de" => "de",
        "fr" => "fr",
        _ => "en",
    }
}

/// The Fluent message ID that represents an [`ErrorCode`].
///
/// `ErrorCode::i18n_key()` remains the canonical logical key
/// (`errors.E-PARSE-001`). Fluent message IDs cannot use dots in that shape, so
/// the FTL resource stores `errors-E-PARSE-001` with attributes named
/// `.title`, `.description`, and `.action`.
#[must_use]
pub fn fluent_message_id(code: ErrorCode) -> String {
    code.i18n_key().replace('.', "-")
}

/// Resolve localized error text from the Rust-side Fluent catalog.
///
/// This is intentionally side-effect-free and bundled-only: it never fetches a
/// translation backend, and unsupported locale tags fall back to English.
pub fn localize_error(code: ErrorCode, locale: &str) -> Result<LocalizedError, LifeboatError> {
    let locale = normalize_fluent_locale(locale);
    let bundle = build_fluent_bundle(locale)?;
    let message_id = fluent_message_id(code);

    Ok(LocalizedError {
        locale,
        title: format_fluent_attribute(&bundle, &message_id, "title")?,
        description: format_fluent_attribute(&bundle, &message_id, "description")?,
        action: format_fluent_attribute(&bundle, &message_id, "action")?,
    })
}

fn fluent_source(locale: &str) -> (&'static str, &'static str) {
    match locale {
        "es" => ("es", ES_FTL),
        "de" => ("de", DE_FTL),
        "fr" => ("fr", FR_FTL),
        _ => ("en", EN_FTL),
    }
}

fn build_fluent_bundle(locale: &'static str) -> Result<ErrorFluentBundle, LifeboatError> {
    let (locale, source) = fluent_source(locale);
    let resource = FluentResource::try_new(source.to_owned()).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("the bundled Fluent error catalog could not be parsed")
    })?;
    let langid = locale.parse::<LanguageIdentifier>().map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("the bundled Fluent locale tag could not be parsed")
    })?;
    let mut bundle = FluentBundle::new(vec![langid]);
    bundle.add_resource(resource).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("the bundled Fluent error catalog has duplicate message IDs")
    })?;
    Ok(bundle)
}

fn format_fluent_attribute(
    bundle: &ErrorFluentBundle,
    message_id: &str,
    attribute_name: &str,
) -> Result<String, LifeboatError> {
    let message = bundle.get_message(message_id).ok_or_else(|| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("the bundled Fluent error catalog is missing an error code")
    })?;
    let attribute = message.get_attribute(attribute_name).ok_or_else(|| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("the bundled Fluent error catalog is missing an error field")
    })?;
    let mut errors = Vec::new();
    let value = bundle
        .format_pattern(attribute.value(), None, &mut errors)
        .into_owned();
    if errors.is_empty() && !value.trim().is_empty() {
        Ok(value)
    } else {
        Err(LifeboatError::new(ErrorCode::Internal)
            .with_context("the bundled Fluent error catalog could not format an error field"))
    }
}

impl serde::Serialize for LifeboatError {
    /// Serialize the **leak-free** surface of the error for the §21.3 desktop
    /// command boundary: the stable [`ErrorCode`] string, its [`Severity`], the
    /// catalog `title` / `description` / `action`, the [i18n key](Self::i18n_key),
    /// and the secret-free [`context`](Self::context) (`null` when absent).
    ///
    /// The chained `source` is deliberately **never** serialized: it can quote the
    /// offending descriptor or secret material (a miniscript/IO error string),
    /// which must never cross to the UI (§13.5 and the safety note on this type).
    /// This mirrors the [`Display`](std::fmt::Display) impl, which is likewise
    /// source-free. A `LifeboatError` is the error half of every Tauri command
    /// (§21.3), and Tauri requires the error type to be `Serialize`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let code = self.code;
        let mut state = serializer.serialize_struct("LifeboatError", 7)?;
        state.serialize_field("code", code.as_str())?;
        state.serialize_field("severity", &code.severity())?;
        state.serialize_field("title", code.title())?;
        state.serialize_field("description", code.description())?;
        state.serialize_field("action", code.action())?;
        state.serialize_field("i18n_key", code.i18n_key())?;
        state.serialize_field("context", &self.context)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn metadata_is_well_formed_for_every_code() {
        for &code in ErrorCode::ALL {
            let m = code.meta();
            assert!(!m.code.is_empty(), "{code:?} has an empty code string");
            assert!(!m.title.is_empty(), "{} has an empty title", m.code);
            assert!(
                !m.description.is_empty(),
                "{} has an empty description",
                m.code
            );
            assert!(!m.action.is_empty(), "{} has an empty action", m.code);
            // i18n key is non-empty and follows the `errors.<CODE>` convention.
            assert!(!m.i18n_key.is_empty(), "{} has an empty i18n key", m.code);
            assert_eq!(
                m.i18n_key,
                format!("errors.{}", m.code),
                "{} has a non-conventional i18n key",
                m.code
            );
            // The string form round-trips through `from_code`.
            assert_eq!(ErrorCode::from_code(m.code), Some(code));
        }
    }

    #[test]
    fn all_codes_are_present_and_unique() {
        let mut seen = HashSet::new();
        for &code in ErrorCode::ALL {
            assert!(
                seen.insert(code.as_str()),
                "duplicate code {}",
                code.as_str()
            );
        }
        // 3 input + 7 parse + 7 secret + 3 fs + 2 network + 2 dep + 1 link + 2 internal.
        assert_eq!(seen.len(), 27);
        assert_eq!(ErrorCode::ALL.len(), 27);
    }

    #[test]
    fn every_code_maps_to_the_severity_from_appendix_c() {
        use ErrorCode as C;
        use Severity as S;
        let expected = [
            (C::InputEmpty, S::UserCorrectable),
            (C::InputTooLarge, S::UserCorrectable),
            (C::InputInvalidFormat, S::UserCorrectable),
            (C::ParseFailed, S::UserCorrectable),
            (C::ChecksumMissing, S::Warning),
            (C::ChecksumInvalid, S::Critical),
            (C::NetworkMixed, S::Critical),
            (C::ContainsPrivateKey, S::Critical),
            (C::UnsupportedFunction, S::UserCorrectable),
            (C::ThresholdExceedsKeys, S::Warning),
            (C::Bip39Detected, S::Security),
            (C::Bip39Suspected, S::Security),
            (C::WifDetected, S::Security),
            (C::ExtendedPrivateKeyDetected, S::Security),
            (C::Slip39Detected, S::Security),
            (C::Codex32Detected, S::Security),
            (C::RawPrivateKeySuspected, S::Security),
            (C::FileNotFound, S::UserCorrectable),
            (C::CannotWrite, S::UserCorrectable),
            (C::DestinationExists, S::Warning),
            (C::NetworkUnreachable, S::UserCorrectable),
            (C::UnexpectedNetworkCall, S::Security),
            (C::TypstNotBundled, S::Internal),
            (C::HwiNotAvailable, S::Internal),
            (C::LinkNotAllowed, S::Security),
            (C::Internal, S::Internal),
            (C::SchemaMigrationRequired, S::Internal),
        ];
        assert_eq!(expected.len(), ErrorCode::ALL.len());
        for (code, severity) in expected {
            assert_eq!(code.severity(), severity, "{} severity", code.as_str());
        }
    }

    #[test]
    fn en_json_catalog_mirrors_every_code() {
        let raw = include_str!("../strings/en.json");
        let root: serde_json::Value = serde_json::from_str(raw).expect("en.json must parse");
        let errors = root
            .get("errors")
            .and_then(serde_json::Value::as_object)
            .expect("en.json must have an `errors` object");

        for &code in ErrorCode::ALL {
            let m = code.meta();
            let entry = errors
                .get(m.code)
                .unwrap_or_else(|| panic!("{} is missing from en.json", m.code));
            let field = |name: &str| entry.get(name).and_then(serde_json::Value::as_str);
            assert_eq!(field("title"), Some(m.title), "{} title drift", m.code);
            assert_eq!(
                field("description"),
                Some(m.description),
                "{} description drift",
                m.code
            );
            assert_eq!(field("action"), Some(m.action), "{} action drift", m.code);
        }
        // No stale or undocumented entries.
        assert_eq!(
            errors.len(),
            ErrorCode::ALL.len(),
            "en.json `errors` count must match the code catalog"
        );
    }

    #[test]
    fn fluent_catalogs_cover_every_error_code_without_dead_keys() {
        let expected: HashSet<String> = ErrorCode::ALL
            .iter()
            .copied()
            .map(fluent_message_id)
            .collect();

        for &locale in SUPPORTED_FLUENT_LOCALES {
            let (_, source) = fluent_source(locale);
            let actual = fluent_message_ids(source);
            assert_eq!(
                actual, expected,
                "{locale} Fluent keys must match ErrorCode::ALL"
            );
        }
    }

    #[test]
    fn fluent_catalogs_localize_every_error_code() {
        for &locale in SUPPORTED_FLUENT_LOCALES {
            for &code in ErrorCode::ALL {
                let localized = localize_error(code, locale)
                    .unwrap_or_else(|err| panic!("{locale} {} failed: {err}", code.as_str()));
                assert_eq!(localized.locale, locale);
                assert!(
                    !localized.title.trim().is_empty(),
                    "{locale} {} title",
                    code.as_str()
                );
                assert!(
                    !localized.description.trim().is_empty(),
                    "{locale} {} description",
                    code.as_str()
                );
                assert!(
                    !localized.action.trim().is_empty(),
                    "{locale} {} action",
                    code.as_str()
                );
            }
        }
    }

    #[test]
    fn english_fluent_catalog_matches_error_meta() {
        for &code in ErrorCode::ALL {
            let localized = localize_error(code, "en").expect("English Fluent catalog loads");
            assert_eq!(localized.title, code.title(), "{} title", code.as_str());
            assert_eq!(
                localized.description,
                code.description(),
                "{} description",
                code.as_str()
            );
            assert_eq!(localized.action, code.action(), "{} action", code.as_str());
        }
    }

    #[test]
    fn unsupported_fluent_locale_falls_back_to_english() {
        assert_eq!(normalize_fluent_locale("es-MX"), "es");
        assert_eq!(normalize_fluent_locale("de-DE"), "de");
        assert_eq!(normalize_fluent_locale("fr-CA"), "fr");
        let localized =
            localize_error(ErrorCode::InputEmpty, "pt-BR").expect("fallback catalog loads");
        assert_eq!(localized.locale, "en");
        assert_eq!(localized.title, ErrorCode::InputEmpty.title());
    }

    fn fluent_message_ids(source: &str) -> HashSet<String> {
        source
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with('#')
                    || trimmed.starts_with('.')
                    || !trimmed.starts_with("errors-")
                {
                    return None;
                }
                let (id, _) = trimmed.split_once('=')?;
                Some(id.trim().to_owned())
            })
            .collect()
    }

    #[test]
    fn severity_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&Severity::UserCorrectable).unwrap(),
            "\"user_correctable\""
        );
        for severity in [
            Severity::UserCorrectable,
            Severity::Warning,
            Severity::Critical,
            Severity::Security,
            Severity::Internal,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            let back: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(severity, back);
            assert_eq!(json, format!("\"{}\"", severity.as_str()));
        }
    }

    #[test]
    fn error_code_serializes_to_its_stable_string() {
        for &code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, back);
        }
        assert!(serde_json::from_str::<ErrorCode>("\"E-DOES-NOT-EXIST\"").is_err());
        assert_eq!(ErrorCode::from_code("nope"), None);
    }

    #[test]
    fn lifeboat_error_exposes_code_severity_and_message() {
        let err = LifeboatError::new(ErrorCode::ChecksumInvalid)
            .with_context("descriptor with checksum #abcd1234");
        assert_eq!(err.code(), ErrorCode::ChecksumInvalid);
        assert_eq!(err.severity(), Severity::Critical);
        assert_eq!(err.i18n_key(), "errors.E-PARSE-003");
        assert_eq!(err.context(), Some("descriptor with checksum #abcd1234"));

        let shown = err.to_string();
        assert!(
            shown.contains("E-PARSE-003"),
            "display missing code: {shown}"
        );
        assert!(
            shown.contains("Descriptor checksum invalid"),
            "display missing title: {shown}"
        );
    }

    #[test]
    fn lifeboat_error_chains_an_underlying_source() {
        use std::error::Error;
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = LifeboatError::new(ErrorCode::FileNotFound).with_source(io);
        assert!(err.source().is_some(), "source should be chained");
        assert_eq!(err.code(), ErrorCode::FileNotFound);

        // Without a source, none is reported.
        let bare = LifeboatError::from(ErrorCode::InputEmpty);
        assert!(bare.source().is_none());
    }

    #[test]
    fn lifeboat_error_serializes_leak_free() {
        // A chained source whose message quotes "secret material" — it must never
        // appear in the serialized form; only the stable, leak-free fields do.
        let leaky = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "xprv9s21ZrQH-SECRET-MUST-NOT-LEAK",
        );
        let err = LifeboatError::new(ErrorCode::ParseFailed)
            .with_context("descriptor failed to parse")
            .with_source(leaky);

        let json = serde_json::to_string(&err).expect("serializes");

        // The leak-free catalog surface is present...
        assert!(json.contains("\"code\":\"E-PARSE-001\""), "{json}");
        assert!(json.contains("\"severity\":\"user_correctable\""), "{json}");
        assert!(
            json.contains("\"i18n_key\":\"errors.E-PARSE-001\""),
            "{json}"
        );
        assert!(
            json.contains("\"context\":\"descriptor failed to parse\""),
            "{json}"
        );
        // ...and the chained source is NEVER serialized.
        assert!(
            !json.contains("SECRET-MUST-NOT-LEAK"),
            "serialized error leaked its chained source: {json}"
        );

        // The shape is a fixed 7-key object; `context` is `null` when absent.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value
            .as_object()
            .expect("error serializes to a JSON object");
        for key in [
            "code",
            "severity",
            "title",
            "description",
            "action",
            "i18n_key",
            "context",
        ] {
            assert!(obj.contains_key(key), "missing `{key}` in {json}");
        }
        let bare = serde_json::to_string(&LifeboatError::new(ErrorCode::InputEmpty)).unwrap();
        assert!(bare.contains("\"context\":null"), "{bare}");
    }
}
