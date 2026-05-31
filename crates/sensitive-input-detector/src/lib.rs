//! `sensitive-input-detector` — recognizes pasted Bitcoin secrets without ever
//! leaking what it found.
//!
//! Bitcoin Lifeboat is a *watch-only* tool: it never needs a real seed phrase,
//! private key, or other spending secret. To keep users safe, every value a user
//! pastes or imports is screened by this crate **before** it reaches any parser
//! (descriptor audit, wallet import, …). The screen recognizes the common ways a
//! secret can arrive — BIP39 mnemonics, WIF and extended (xprv-family) private
//! keys, raw-hex private keys, SLIP-39 shares, and codex32 / BIP-93 secrets — and
//! reports them so the caller can refuse the input.
//!
//! # The no-leak invariant (NORMATIVE, PRD §13.5.8)
//!
//! The detector accepts a borrowed [`str`] and returns a [`DetectorReport`] that
//! contains **only**:
//!
//! * the *kind* of secret found ([`DetectedSecret`] — a discriminant plus
//!   non-secret metadata such as word count or network), and
//! * the *byte range* it occupied in the input ([`ByteRange`]).
//!
//! A [`DetectorReport`] never contains the secret's characters, and the detector
//! holds no secret beyond the borrow: it keeps no global or cached state, copies
//! no input text into a returned value, and logs nothing. This is enforced
//! structurally (no field on any returned type can hold input text) and locked by
//! the `report_contains_no_secret_substring` unit test.
//!
//! # Memory-handling contract (PRD §13.5.8)
//!
//! Callers must:
//!
//! 1. wrap the user input in [`secrecy::SecretString`] as early as possible,
//! 2. pass it to [`detect_secret`] (or expose it only for the [`detect`] call),
//! 3. drop the `SecretString` immediately afterwards — its `Drop` zeroizes the
//!    buffer, satisfying "zeroize after".
//!
//! The Tauri command boundary (US-042) returns only the [`DetectorReport`] to the
//! webview; the original string stays in Rust inside a `SecretString` and is
//! never handed back to JavaScript.
//!
//! ```
//! use secrecy::SecretString;
//! use sensitive_input_detector::{detect_secret, DetectorAction};
//!
//! // The caller wraps the paste as early as possible, screens it, and lets the
//! // `SecretString` drop (zeroize) when `detect_secret` returns.
//! let report = detect_secret(SecretString::from("just some descriptor text".to_string()));
//! assert_eq!(report.action, DetectorAction::Allow);
//! ```
//!
//! # Status
//!
//! This crate's *skeleton and safe API* is established by US-012; detectors are
//! added incrementally, each as a `scan(input, &mut Collector)` submodule wired
//! into [`detect`]:
//!
//! * US-013 — BIP39 mnemonics, 10 languages (`mnemonic`) — **done**
//! * US-014 — WIF and extended private keys (`wif`, `xprv`) — **done**
//! * US-015 — raw-hex private keys (`raw_hex`), SLIP-39 shares (`slip39`),
//!   codex32 secrets (`codex`) — **done**
//! * US-016 — action semantics, user-facing messages, and fuzz targets — **done**
//!
//! # Action semantics & user-facing messages (PRD §13.5.7)
//!
//! Every finding maps to a stable [`ErrorCode`] (`E-SECRET-*`, PRD Appendix C)
//! via [`DetectedSecret::error_code`]; that code is the single, i18n-keyed source
//! of the finding's `title` / `description` / `action` text — callers render it
//! from `error-taxonomy` rather than restating copy here. The overall
//! [`DetectorAction`] carries the §13.5.7 [headline](DetectorAction::headline)
//! and the [`cli_exit_code`](DetectorAction::cli_exit_code) (Block→5, Warn→1,
//! Allow→0; PRD §17.10.6). All of this text is static catalog copy and **never**
//! contains detected content (locked by a unit test over real detections of the
//! committed secret fixtures).
//!
//! Mapping a finding to a code does not make [`detect`] fallible: it still
//! returns a [`DetectorReport`], never a `Result`.
//!
//! The four `cargo-fuzz` targets (PRD §13.5.10) live in the detached `fuzz/`
//! workspace; their invariants are also enforced under the standard `cargo test`
//! gate by `tests/fuzz_properties.rs`.
//!
//! See `docs/PRD-v2.md` §13.5 for the full specification.

use error_taxonomy::ErrorCode;
use secrecy::{ExposeSecret, SecretString};

mod codex;
mod mnemonic;
mod raw_hex;
mod slip39;
mod wif;
mod xprv;

/// A single detection: *what* was found and *where* it sat in the input.
///
/// This is exactly `(DetectedSecret, ByteRange)` as specified in PRD §13.5; the
/// alias keeps later detector code readable.
pub type Finding = (DetectedSecret, ByteRange);

/// The result of screening one input string.
///
/// Crosses the Tauri boundary to the webview (PRD §13.5.8) as the *only* value
/// derived from the input — it carries no secret content. See the crate-level
/// no-leak invariant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DetectorReport {
    /// Every secret recognized in the input, in the order found.
    pub findings: Vec<Finding>,
    /// The overall verdict the caller should enforce: the most severe action
    /// implied by any finding, or [`DetectorAction::Allow`] when nothing was
    /// found.
    pub action: DetectorAction,
}

impl DetectorReport {
    /// A report with no findings and an [`DetectorAction::Allow`] verdict.
    #[must_use]
    pub fn allow() -> Self {
        Self {
            findings: Vec::new(),
            action: DetectorAction::Allow,
        }
    }

    /// `true` when the caller must hard-stop the input (a confirmed secret).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.action == DetectorAction::Block
    }

    /// `true` when the caller should warn but may allow an explicit override.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        self.action == DetectorAction::Warn
    }

    /// `true` when nothing actionable was detected.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.action == DetectorAction::Allow
    }

    /// The user-facing headline for the overall verdict (PRD §13.5.7), if any.
    /// Static copy; never contains detected content.
    #[must_use]
    pub const fn headline(&self) -> Option<&'static str> {
        self.action.headline()
    }

    /// The CLI process exit code implied by the verdict (PRD §17.10.6).
    #[must_use]
    pub const fn cli_exit_code(&self) -> i32 {
        self.action.cli_exit_code()
    }

    /// The distinct [`ErrorCode`]s across all findings, in first-seen order.
    ///
    /// These are the "detector reason[s] logged (without the secret content)" of
    /// PRD §13.5.7: each resolves to leak-free `error-taxonomy` catalog text and
    /// an i18n key. [`DetectedSecret::None`] findings (which carry no code) are
    /// skipped.
    #[must_use]
    pub fn reason_codes(&self) -> Vec<ErrorCode> {
        let mut codes = Vec::new();
        for (secret, _) in &self.findings {
            if let Some(code) = secret.error_code() {
                if !codes.contains(&code) {
                    codes.push(code);
                }
            }
        }
        codes
    }
}

/// What the caller should do with the input.
///
/// Ordered by severity (`Allow < Warn < Block`) so a set of per-finding verdicts
/// can be folded to the strongest one with [`Ord::max`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DetectorAction {
    /// No secret detected; proceed normally.
    Allow,
    /// Looks like a secret but unconfirmed (e.g. BIP39 words with a bad
    /// checksum); warn with an explicit user override.
    Warn,
    /// A confirmed secret; refuse the input and clear the field.
    Block,
}

/// The exact phrase a user must type to override a [`DetectorAction::Warn`]
/// before suspicious-but-unconfirmed input is accepted (PRD §13.5.7).
///
/// The desktop UI (US-042) and the CLI (US-036) require this phrase verbatim;
/// centralizing it here keeps the two in sync. (PRD §13.5.1's BIP39-specific
/// dialog quotes the narrower "…not a real seed"; §13.5.7's general override —
/// used for every `Warn`, including raw-hex — is the canonical one below.)
pub const WARN_OVERRIDE_PHRASE: &str = "I confirm this is not a real secret";

impl DetectorAction {
    /// The verbatim user-facing headline for this verdict (PRD §13.5.7), or
    /// `None` when the action needs no headline of its own.
    ///
    /// Only [`Block`](DetectorAction::Block) has a fixed headline (quoted
    /// verbatim from §13.5.7). For [`Warn`](DetectorAction::Warn) the inline
    /// override ([`WARN_OVERRIDE_PHRASE`]) plus the per-finding
    /// [`error_code`](DetectedSecret::error_code) text carry the message; for
    /// [`Allow`](DetectorAction::Allow) nothing is shown. This is static copy and
    /// never contains detected content.
    #[must_use]
    pub const fn headline(self) -> Option<&'static str> {
        match self {
            Self::Block => Some(
                "This looks like a real Bitcoin secret. Lifeboat does not need this. Input \
                 cleared.",
            ),
            Self::Warn | Self::Allow => None,
        }
    }

    /// The CLI process exit code for this verdict (PRD §17.10.6 `detect-secrets`):
    /// [`Block`](DetectorAction::Block) → 5, [`Warn`](DetectorAction::Warn) → 1,
    /// [`Allow`](DetectorAction::Allow) → 0.
    #[must_use]
    pub const fn cli_exit_code(self) -> i32 {
        match self {
            Self::Block => 5,
            Self::Warn => 1,
            Self::Allow => 0,
        }
    }
}

/// A half-open `[start, end)` byte range into the screened input.
///
/// Holds indices only — never input bytes — so it is safe to log or serialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ByteRange {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl ByteRange {
    /// Construct a `[start, end)` range.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Number of bytes covered (0 if `end <= start`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// `true` when the range covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// As a standard [`core::ops::Range`], for slicing the original input.
    #[must_use]
    pub fn as_range(&self) -> core::ops::Range<usize> {
        self.start..self.end
    }
}

/// The kind of secret recognized, with non-secret metadata about it.
///
/// Every variant carries only *facts about* the secret (its format, length,
/// network, …) — never the secret's own characters. Mirrors PRD §13.5.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedSecret {
    /// A BIP39 mnemonic (detection in US-013).
    Bip39 {
        /// Detected wordlist language.
        language: Bip39Language,
        /// Number of words in the matched window (12/15/18/21/24).
        word_count: u8,
        /// Whether the BIP39 checksum validated (valid ⇒ Block, invalid ⇒ Warn).
        checksum_valid: bool,
    },
    /// A WIF-encoded private key (detection in US-014).
    Wif {
        /// Network encoded in the WIF version byte.
        network: Network,
        /// Whether the WIF encodes a compressed public key.
        compressed: bool,
    },
    /// An extended private key — xprv/yprv/zprv/tprv/uprv/vprv (detection in
    /// US-014).
    Xprv {
        /// Which extended-key prefix was seen.
        kind: XprvKind,
        /// Network encoded in the version bytes.
        network: Network,
    },
    /// A 64-hex-character value that context marks as a raw private key
    /// (detection in US-015).
    RawHexPrivKey,
    /// One or more SLIP-39 shares (detection in US-015).
    Slip39 {
        /// How many shares appeared in this input.
        share_count_in_input: u8,
    },
    /// A codex32 / BIP-93 secret (detection in US-015).
    Codex32 {
        /// The `k` threshold encoded in the secret.
        threshold: u8,
    },
    /// No secret. Present for exhaustive matching; an empty
    /// [`DetectorReport::findings`] already means "nothing found", so this is not
    /// normally stored as a finding.
    None,
}

impl DetectedSecret {
    /// The stable [`ErrorCode`] (PRD Appendix C, `E-SECRET-*`) that names this
    /// kind of secret, or `None` for [`DetectedSecret::None`].
    ///
    /// This is the single source of a finding's user-facing message: callers
    /// render `code.title()` / `code.description()` / `code.action()` and resolve
    /// `code.i18n_key()` from `error-taxonomy` rather than restating the copy
    /// here (a second copy would have no parity test and could drift). The codes
    /// distinguish a checksum-valid BIP39 mnemonic ([`Bip39Detected`]) from a
    /// suspected one ([`Bip39Suspected`]).
    ///
    /// [`Bip39Detected`]: error_taxonomy::ErrorCode::Bip39Detected
    /// [`Bip39Suspected`]: error_taxonomy::ErrorCode::Bip39Suspected
    #[must_use]
    pub fn error_code(&self) -> Option<ErrorCode> {
        Some(match self {
            Self::Bip39 {
                checksum_valid: true,
                ..
            } => ErrorCode::Bip39Detected,
            Self::Bip39 {
                checksum_valid: false,
                ..
            } => ErrorCode::Bip39Suspected,
            Self::Wif { .. } => ErrorCode::WifDetected,
            Self::Xprv { .. } => ErrorCode::ExtendedPrivateKeyDetected,
            Self::RawHexPrivKey => ErrorCode::RawPrivateKeySuspected,
            Self::Slip39 { .. } => ErrorCode::Slip39Detected,
            Self::Codex32 { .. } => ErrorCode::Codex32Detected,
            Self::None => return None,
        })
    }
}

/// BIP39 wordlist languages — the ten official lists in `bitcoin/bips`
/// (`bip-0039/`). Selected by detection in US-013.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip39Language {
    /// English (`english.txt`).
    English,
    /// Japanese (`japanese.txt`).
    Japanese,
    /// Korean (`korean.txt`).
    Korean,
    /// Spanish (`spanish.txt`).
    Spanish,
    /// Chinese, Simplified (`chinese_simplified.txt`).
    ChineseSimplified,
    /// Chinese, Traditional (`chinese_traditional.txt`).
    ChineseTraditional,
    /// French (`french.txt`).
    French,
    /// Italian (`italian.txt`).
    Italian,
    /// Czech (`czech.txt`).
    Czech,
    /// Portuguese (`portuguese.txt`).
    Portuguese,
}

/// The network a key encodes, to the resolution its version bytes allow.
///
/// Key and WIF version bytes only separate mainnet from the test networks;
/// testnet, signet, and regtest share version bytes and are all reported as
/// [`Network::Testnet`] (the same limitation as descriptor network inference —
/// PRD §17.4 / §16.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    /// Bitcoin mainnet.
    Mainnet,
    /// A test network (testnet, signet, or regtest — indistinguishable here).
    Testnet,
}

/// Extended-private-key prefix family (PRD §13.5.3): standard `xprv`/`tprv` plus
/// the SLIP-132 script-type variants. Selected by detection in US-014.
// The shared `prv` suffix is the actual BIP32 / SLIP-132 prefix these variants
// name; renaming them to drop it (as `enum_variant_names` would suggest) would
// hide that one-to-one mapping.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XprvKind {
    /// BIP32 `xprv` (mainnet).
    Xprv,
    /// SLIP-132 `yprv` (mainnet, BIP49 P2SH-P2WPKH).
    Yprv,
    /// SLIP-132 `zprv` (mainnet, BIP84 P2WPKH).
    Zprv,
    /// `tprv` (testnet BIP32).
    Tprv,
    /// SLIP-132 `uprv` (testnet BIP49).
    Uprv,
    /// SLIP-132 `vprv` (testnet BIP84).
    Vprv,
}

/// Screen `input` for pasted Bitcoin secrets (PRD §13.5).
///
/// Returns a [`DetectorReport`] describing what — if anything — was recognized,
/// with **no** secret content (see the crate-level no-leak invariant). Infallible
/// and panic-free for any input.
///
/// Prefer [`detect_secret`] when you hold a [`SecretString`]; it manages exposure
/// and zeroization for you.
#[must_use]
pub fn detect(input: &str) -> DetectorReport {
    // Each detector pushes its findings into the collector and folds in the
    // action that finding implies; the strongest action across all findings
    // becomes the report's verdict (§13.5.7).
    let mut collector = Collector::new();
    mnemonic::scan(input, &mut collector);
    wif::scan(input, &mut collector);
    xprv::scan(input, &mut collector);
    raw_hex::scan(input, &mut collector);
    slip39::scan(input, &mut collector);
    codex::scan(input, &mut collector);
    collector.into_report()
}

/// Accumulates findings from the individual detectors and folds the overall
/// action (`Allow < Warn < Block`, the strongest wins — §13.5.7).
///
/// Internal: detector submodules push into it; only the resulting
/// [`DetectorReport`] is public. The action is decided per finding at detection
/// time (it is contextual — e.g. a checksum-valid BIP39 mnemonic is `Block` but
/// an invalid one is `Warn`), never derived from the [`DetectedSecret`] variant
/// alone.
pub(crate) struct Collector {
    findings: Vec<Finding>,
    action: DetectorAction,
}

impl Collector {
    pub(crate) fn new() -> Self {
        Self {
            findings: Vec::new(),
            action: DetectorAction::Allow,
        }
    }

    /// Record a finding and fold its action into the running verdict.
    pub(crate) fn push(
        &mut self,
        secret: DetectedSecret,
        range: ByteRange,
        action: DetectorAction,
    ) {
        self.findings.push((secret, range));
        self.action = self.action.max(action);
    }

    fn into_report(self) -> DetectorReport {
        DetectorReport {
            findings: self.findings,
            action: self.action,
        }
    }
}

/// Screen a [`SecretString`] for pasted secrets, then zeroize it.
///
/// This is the recommended entry point: it exposes the secret only for the
/// duration of the [`detect`] call and consumes the `SecretString`, whose `Drop`
/// zeroizes the buffer — satisfying the PRD §13.5.8 "wrap, screen, zeroize"
/// contract in one place so callers cannot get it wrong.
#[must_use]
pub fn detect_secret(secret: SecretString) -> DetectorReport {
    detect(secret.expose_secret())
    // `secret` is dropped here; its underlying buffer is zeroized.
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic, obviously-fake stand-in for secret content. NOT a real secret:
    // the PRD §27 anonymization rule and the project safety invariants forbid real
    // seeds or keys in tests and fixtures. Used only to prove the report type
    // cannot echo input bytes.
    const PRETEND_SECRET: &str = "NOT-A-REAL-SECRET-marker-0xC0FFEE-do-not-leak";

    /// A report exercising every [`DetectedSecret`] variant, with byte ranges
    /// that point into a (pretend) secret. Used by the no-leak and round-trip
    /// tests.
    fn report_with_every_variant() -> DetectorReport {
        DetectorReport {
            findings: vec![
                (
                    DetectedSecret::Bip39 {
                        language: Bip39Language::English,
                        word_count: 24,
                        checksum_valid: true,
                    },
                    ByteRange::new(0, 8),
                ),
                (
                    DetectedSecret::Bip39 {
                        language: Bip39Language::ChineseSimplified,
                        word_count: 12,
                        checksum_valid: false,
                    },
                    ByteRange::new(8, 16),
                ),
                (
                    DetectedSecret::Wif {
                        network: Network::Mainnet,
                        compressed: true,
                    },
                    ByteRange::new(16, 24),
                ),
                (
                    DetectedSecret::Xprv {
                        kind: XprvKind::Zprv,
                        network: Network::Testnet,
                    },
                    ByteRange::new(24, 32),
                ),
                (DetectedSecret::RawHexPrivKey, ByteRange::new(32, 40)),
                (
                    DetectedSecret::Slip39 {
                        share_count_in_input: 2,
                    },
                    ByteRange::new(40, 48),
                ),
                (
                    DetectedSecret::Codex32 { threshold: 2 },
                    ByteRange::new(48, 56),
                ),
                (DetectedSecret::None, ByteRange::new(0, 0)),
            ],
            action: DetectorAction::Block,
        }
    }

    #[test]
    fn report_contains_no_secret_substring() {
        // Even a report whose findings span a secret must never carry that
        // secret's bytes — neither in its Debug form nor its JSON serialization.
        // This is the structural no-leak guarantee: the report stores only
        // discriminants and byte ranges, so there is nowhere for input text to
        // hide. US-013+ extend this with reports built from *real* detections.
        let report = report_with_every_variant();
        let debug = format!("{report:?}");
        let json = serde_json::to_string(&report).expect("report serializes");

        for needle in [PRETEND_SECRET, "C0FFEE", "do-not-leak", "marker"] {
            assert!(
                !debug.contains(needle),
                "Debug output leaked secret content: {needle}"
            );
            assert!(
                !json.contains(needle),
                "JSON output leaked secret content: {needle}"
            );
        }
    }

    #[test]
    fn detect_never_echoes_input() {
        // The skeleton allows everything, but the *type* guarantee holds no matter
        // what `input` contains: the returned report cannot carry input bytes.
        let report = detect(PRETEND_SECRET);
        let json = serde_json::to_string(&report).expect("serializes");
        assert!(!json.contains("marker"));
        assert!(report.is_allowed());
    }

    #[test]
    fn clean_input_is_allowed() {
        for s in [
            "",
            "hello world",
            "wpkh([deadbeef/84h/0h/0h]xpub6Abc/0/*)#checksum",
        ] {
            let r = detect(s);
            assert!(r.findings.is_empty());
            assert!(r.is_allowed());
            assert!(!r.is_blocked());
            assert!(!r.is_warning());
            assert_eq!(r.action, DetectorAction::Allow);
        }
    }

    #[test]
    fn detect_secret_screens_then_zeroizes() {
        // Embodies the §13.5.8 contract: wrap → screen → drop (zeroize).
        let secret = SecretString::from(PRETEND_SECRET.to_string());
        let report = detect_secret(secret);
        // `secret` was consumed (and zeroized on drop). The report carries nothing.
        assert!(report.is_allowed());
        let json = serde_json::to_string(&report).expect("serializes");
        assert!(!json.contains("marker"));
    }

    #[test]
    fn action_severity_orders_allow_warn_block() {
        assert!(DetectorAction::Allow < DetectorAction::Warn);
        assert!(DetectorAction::Warn < DetectorAction::Block);
        // Folding a set of verdicts to the strongest one (the way detectors will
        // combine multiple findings in US-016).
        assert_eq!(
            [
                DetectorAction::Allow,
                DetectorAction::Block,
                DetectorAction::Warn,
            ]
            .into_iter()
            .max(),
            Some(DetectorAction::Block)
        );
    }

    #[test]
    fn byte_range_geometry() {
        let r = ByteRange::new(3, 9);
        assert_eq!(r.len(), 6);
        assert!(!r.is_empty());
        assert_eq!(r.as_range(), 3..9);

        let empty = ByteRange::new(5, 5);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        // Defensive: a reversed range reports empty and never underflows.
        assert_eq!(ByteRange::new(9, 3).len(), 0);
        assert!(ByteRange::new(9, 3).is_empty());
    }

    #[test]
    fn report_json_round_trips() {
        let report = report_with_every_variant();
        let json = serde_json::to_string(&report).expect("serializes");
        let back: DetectorReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(report, back);
    }

    #[test]
    fn json_shape_is_stable_snake_case() {
        // Lock the JSON shape the Tauri/JS boundary (US-042) will consume.
        assert_eq!(
            serde_json::to_string(&DetectedSecret::RawHexPrivKey).unwrap(),
            "\"raw_hex_priv_key\""
        );
        assert_eq!(
            serde_json::to_string(&DetectedSecret::Codex32 { threshold: 2 }).unwrap(),
            "{\"codex32\":{\"threshold\":2}}"
        );
        assert_eq!(
            serde_json::to_string(&DetectorAction::Block).unwrap(),
            "\"block\""
        );
        assert_eq!(serde_json::to_string(&XprvKind::Zprv).unwrap(), "\"zprv\"");
        assert_eq!(
            serde_json::to_string(&Network::Testnet).unwrap(),
            "\"testnet\""
        );
        assert_eq!(
            serde_json::to_string(&Bip39Language::ChineseSimplified).unwrap(),
            "\"chinese_simplified\""
        );
        assert_eq!(
            serde_json::to_string(&DetectorReport::allow()).unwrap(),
            "{\"findings\":[],\"action\":\"allow\"}"
        );
    }

    // ------------------------------------------------------------------
    // US-016 — action semantics + user-facing messages (PRD §13.5.7).
    // ------------------------------------------------------------------

    /// Every committed secret fixture (a documented test vector, never a real
    /// secret — PRD §27). Reused below and a stand-in for the real-detection
    /// no-leak corpus the US-012 skeleton test asked for.
    fn secret_fixtures() -> [(&'static str, &'static str); 7] {
        [
            (
                "bip39_english_12",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/bip39_english_12.txt"
                )),
            ),
            (
                "bip39_english_24",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/bip39_english_24.txt"
                )),
            ),
            (
                "bip39_japanese_12",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/bip39_japanese_12.txt"
                )),
            ),
            (
                "wif_mainnet",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/wif_mainnet.txt"
                )),
            ),
            (
                "xprv_mainnet",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/xprv_mainnet.txt"
                )),
            ),
            (
                "slip39_share_20w",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/slip39_share_20w.txt"
                )),
            ),
            (
                "codex32_128bit",
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/secrets/codex32_128bit.txt"
                )),
            ),
        ]
    }

    #[test]
    fn error_code_maps_every_secret_kind() {
        // BIP39 splits on checksum validity (§13.5.1 / E-SECRET-001 vs -002).
        assert_eq!(
            DetectedSecret::Bip39 {
                language: Bip39Language::English,
                word_count: 12,
                checksum_valid: true,
            }
            .error_code(),
            Some(ErrorCode::Bip39Detected)
        );
        assert_eq!(
            DetectedSecret::Bip39 {
                language: Bip39Language::English,
                word_count: 12,
                checksum_valid: false,
            }
            .error_code(),
            Some(ErrorCode::Bip39Suspected)
        );
        assert_eq!(
            DetectedSecret::Wif {
                network: Network::Mainnet,
                compressed: true,
            }
            .error_code(),
            Some(ErrorCode::WifDetected)
        );
        assert_eq!(
            DetectedSecret::Xprv {
                kind: XprvKind::Xprv,
                network: Network::Mainnet,
            }
            .error_code(),
            Some(ErrorCode::ExtendedPrivateKeyDetected)
        );
        assert_eq!(
            DetectedSecret::RawHexPrivKey.error_code(),
            Some(ErrorCode::RawPrivateKeySuspected)
        );
        assert_eq!(
            DetectedSecret::Slip39 {
                share_count_in_input: 1
            }
            .error_code(),
            Some(ErrorCode::Slip39Detected)
        );
        assert_eq!(
            DetectedSecret::Codex32 { threshold: 0 }.error_code(),
            Some(ErrorCode::Codex32Detected)
        );
        assert_eq!(DetectedSecret::None.error_code(), None);
        // Every E-SECRET code is a Security-severity event (PRD Appendix C).
        for kind in [
            ErrorCode::Bip39Detected,
            ErrorCode::Bip39Suspected,
            ErrorCode::WifDetected,
            ErrorCode::ExtendedPrivateKeyDetected,
            ErrorCode::RawPrivateKeySuspected,
            ErrorCode::Slip39Detected,
            ErrorCode::Codex32Detected,
        ] {
            assert_eq!(kind.severity(), error_taxonomy::Severity::Security);
        }
    }

    #[test]
    fn block_headline_is_verbatim_and_warn_allow_have_none() {
        // Quoted verbatim from PRD §13.5.7 (self-checks the line-continuation
        // spacing in `DetectorAction::headline`).
        assert_eq!(
            DetectorAction::Block.headline(),
            Some(
                "This looks like a real Bitcoin secret. Lifeboat does not need this. Input cleared."
            )
        );
        assert_eq!(DetectorAction::Warn.headline(), None);
        assert_eq!(DetectorAction::Allow.headline(), None);
        // The report delegates to its action.
        assert_eq!(
            DetectorReport::allow().headline(),
            DetectorAction::Allow.headline()
        );
    }

    #[test]
    fn cli_exit_codes_match_prd_17_10_6() {
        assert_eq!(DetectorAction::Block.cli_exit_code(), 5);
        assert_eq!(DetectorAction::Warn.cli_exit_code(), 1);
        assert_eq!(DetectorAction::Allow.cli_exit_code(), 0);
        assert_eq!(DetectorReport::allow().cli_exit_code(), 0);
    }

    #[test]
    fn warn_override_phrase_is_canonical() {
        assert_eq!(WARN_OVERRIDE_PHRASE, "I confirm this is not a real secret");
    }

    #[test]
    fn reason_codes_dedup_in_first_seen_order() {
        let report = DetectorReport {
            findings: vec![
                (
                    DetectedSecret::Wif {
                        network: Network::Mainnet,
                        compressed: true,
                    },
                    ByteRange::new(0, 1),
                ),
                (
                    DetectedSecret::Bip39 {
                        language: Bip39Language::English,
                        word_count: 12,
                        checksum_valid: true,
                    },
                    ByteRange::new(1, 2),
                ),
                // Duplicate kind → collapsed.
                (
                    DetectedSecret::Wif {
                        network: Network::Testnet,
                        compressed: false,
                    },
                    ByteRange::new(2, 3),
                ),
                // `None` carries no code → skipped.
                (DetectedSecret::None, ByteRange::new(3, 3)),
            ],
            action: DetectorAction::Block,
        };
        assert_eq!(
            report.reason_codes(),
            vec![ErrorCode::WifDetected, ErrorCode::Bip39Detected]
        );
        assert!(DetectorReport::allow().reason_codes().is_empty());
    }

    #[test]
    fn messages_never_contain_detected_content() {
        // The strongest no-leak proof: run `detect` on REAL secret vectors, then
        // assemble the full user-facing message (action headline + every
        // finding's title/description/action/i18n key) and confirm none of it —
        // nor the serialized report — echoes the secret. The message is static
        // catalog copy, so this holds by construction; the test guards against a
        // future change that interpolates input into a message.
        for (name, raw) in secret_fixtures() {
            let secret = raw.trim();
            let report = detect(secret);
            assert!(
                report.is_blocked(),
                "{name}: committed secret fixture must Block"
            );

            let mut message = String::new();
            if let Some(headline) = report.headline() {
                message.push_str(headline);
            }
            for code in report.reason_codes() {
                message.push_str(code.title());
                message.push_str(code.description());
                message.push_str(code.action());
                message.push_str(code.i18n_key());
            }
            assert!(
                !message.contains(secret),
                "{name}: user-facing message leaked the secret"
            );

            let json = serde_json::to_string(&report).expect("report serializes");
            assert!(
                !json.contains(secret),
                "{name}: serialized report leaked the secret"
            );
        }
    }
}
