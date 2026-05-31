//! `report-engine` — the deterministic readiness-report orchestration layer.
//!
//! This crate assembles the PRD §19.1 `ReadinessReport`. It is the layer that
//! ties the lower analysis crates together: it runs the [`readiness_score`]
//! checks / criticals / score / status / survivability over a parsed descriptor,
//! derives addresses via [`address_derive`], enriches the §16.4 warnings with
//! user-facing text, derives the "what passed" / "what to do next" lists, and
//! stamps the verbatim §15.6 disclaimers.
//!
//! ## Determinism (PRD §19, §27)
//! The same input plus the same `scoring_engine_version` and `app_version`
//! produces **byte-identical** JSON. To make that hold, every ambient value that
//! would otherwise vary (`created_at`, `app_version`) is supplied by the caller —
//! never read from the clock here — exactly as `wallet-imports` leaves
//! `imported_at` to its caller. [`ReadinessReport::to_json`] is the canonical
//! serialization; serde emits struct fields in declaration order, so the field
//! order matches §19.1.
//!
//! ## Hashes
//! `input_hash` is the `sha256:` digest of a canonical fingerprint of the
//! meaningful inputs (canonical descriptors, network, known address, checklist,
//! …) — it excludes `created_at`/`app_version`, so the same wallet correlates
//! across time. `report_hash` is the `sha256:` digest of the full report JSON
//! with the `report_hash` field blanked to `""` (a verifier blanks it and
//! recomputes). Hashes are one-way digests, so hashing confidential descriptor
//! material does not leak it.
//!
//! ## Redaction modes (PRD §17.7 / §9.5 / §19)
//! [`build_report`] always produces the complete `private`-mode report (both the
//! full `raw`/`xpub` and the `raw_redacted`/`xpub_redacted` forms).
//! [`ReadinessReport::redact`] derives a mode-appropriate copy:
//! [`RedactionMode::PublicSafe`] (the §17.7 default share-safe form) omits every
//! full `xpub` (keeping the `xpub6...XXXX` `xpub_redacted` form), redacts each
//! descriptor's `raw` to that same xpub-redacted text, and trims the derived
//! addresses to the first per chain; [`RedactionMode::Private`] returns the full
//! report unchanged. Redaction recomputes `report_hash` over the emitted bytes so
//! either mode self-verifies by blank-and-recompute, while `input_hash` is
//! mode-independent (it correlates a wallet's public-safe and private exports).
//!
//! ## §14.3 xpub privacy + §16.8 anti-overclaim
//! [`ReadinessReport::to_markdown_mode`] prepends the verbatim §14.3
//! [`XPUB_PRIVACY_WARNING`] to a **private**-mode Markdown export whenever the
//! report carries an xpub. [`passes_anti_overclaim_lint`] / [`find_overclaim`]
//! are the reusable §16.8 guard (no claim that a wallet is "safe"/"secure", that
//! recovery is "guaranteed", or that "you can recover"); every string this crate
//! authors and every rendered report passes it.

use address_derive::{
    compare_known_address, derive_addresses, DerivedAddress, KnownAddressMatch, Network,
    DEFAULT_ADDRESS_COUNT,
};
use descriptor_audit::{ChecksumStatus, MultisigKind, ParsedDescriptor};
use miniscript::descriptor::DescriptorType;
use readiness_score::{
    compute_score, compute_survivability, evaluate_critical_failures, map_status, run_checks,
    Check, CheckInput, CheckResult, CriticalCode, CriticalContext, CriticalIssue,
    DeclaredWalletType, Passphrase, ReadinessStatus, RecoveryChecklist, ScoringAuditEntry,
    ScoringContext, StatusContext, Survivability, WarningCode, SCORING_ENGINE_VERSION,
};
use sha2::{Digest, Sha256};

/// The §19.1 `schema_version` of the report shape this crate emits.
pub const SCHEMA_VERSION: &str = "0.1.0";

/// The Lifeboat application version stamped as `app_version` when the caller
/// does not override it. Tracks the workspace package version.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The §19.1 `mode` for a readiness check (drill modes arrive in v0.3+).
const MODE: &str = "readiness_check";

/// How many addresses per chain the report derives for display. The PRD §31
/// redaction table shows the first 5 in `private` mode (US-030 trims this to one
/// for `public-safe`). The known-address comparison searches far deeper
/// ([`address_derive::MAX_ADDRESS_COUNT`]) regardless.
const REPORT_ADDRESS_COUNT: u32 = 5;

/// The PRD §15.6 short disclaimer, verbatim (report header).
pub const DISCLAIMER_SHORT: &str =
    "This report is a diagnostic aid. It is not legal, tax, financial,\n\
or security advice. Bitcoin Lifeboat cannot guarantee that any\n\
wallet is recoverable.";

/// The PRD §15.6 long disclaimer, verbatim (report footer).
pub const DISCLAIMER_LONG: &str = "About this document\n\
\n\
Bitcoin Lifeboat is an open-source diagnostic and rehearsal tool.\n\
This document reflects only the information you provided. It cannot\n\
detect missing materials Lifeboat was not asked to check, it cannot\n\
verify the physical location or condition of your backups, and it\n\
cannot predict the future condition of your hardware wallets.\n\
\n\
A \"Ready\" status means the metadata you provided appears complete\n\
for the scenarios Lifeboat tested. It does not mean your bitcoin\n\
is safe. It does not mean recovery will succeed in a real emergency.\n\
\n\
You are responsible for verifying recovery end-to-end on a test\n\
network before trusting your real wallet. Consult an attorney for\n\
estate planning. Consult a tax professional for tax implications.\n\
\n\
Bitcoin Lifeboat does not custody funds, does not contact you,\n\
does not call you, and does not ask for your seed phrase.\n\
\n\
If anyone claiming to be from Bitcoin Lifeboat contacts you, it\n\
is a scam. Hang up.";

/// The PRD §15.7 "Not a Wallet" canonical paragraph, verbatim. NORMATIVE on the
/// top of every report. Rendered as a Markdown blockquote in the report header.
pub const NOT_A_WALLET: &str = "\
Bitcoin Lifeboat is not a wallet, not a custody service, not a
seed phrase manager, not an inheritance legal service, and not a
recovery company. It is a free, open-source diagnostic tool that
helps you test whether your recovery plan works.";

/// The PRD §15.8 "What this report CANNOT tell you" section, verbatim. Every
/// report reproduces this. The two-space bullet indents and the parenthetical
/// continuation indents (four/five spaces) are part of the text and are
/// preserved byte-for-byte, so this literal is written flush-left (a leading
/// `\` swallows the opening newline) and rendered inside a fenced block.
pub const REPORT_CANNOT_TELL: &str = "\
What this report CANNOT tell you

  - Whether your hardware wallets still work.
    (Lifeboat did not power them on. Run a Disaster Drill in v0.3.)
  - Whether your seed words are still legible on the paper/metal.
    (Go check. In person. Today.)
  - Whether the location you store backups in is still safe.
    (Lifeboat cannot see your closet.)
  - Whether your heirs can find the materials.
    (Run a Heir Drill in v0.6, or talk to them now.)
  - Whether your passphrase is correct.
    (Lifeboat does not know your passphrase. Test it on a
     low-value wallet first.)
  - Whether the wallet software you depend on will still exist
    when you need it.
    (Print this report. Print the descriptor. Make recovery
     possible without specific software.)";

/// The PRD §14.3 xpub-privacy warning, verbatim. Prepended to any **private**-mode
/// export whose report carries an xpub (a `public-safe` export shows only the
/// `xpub6...XXXX` form and never needs it). Stored without the leading `> `
/// markers and rendered as a Markdown blockquote, so the bytes stay reusable by
/// the runbook engine (US-031/032). Written flush-left (a leading `\` swallows
/// the opening newline) so the literal's bytes match the rendered text exactly.
pub const XPUB_PRIVACY_WARNING: &str = "\
⚠️ This document contains an extended public key (xpub).
An xpub reveals every receive AND change address for this wallet,
past and future. Anyone with this xpub can see your wallet's
entire transaction history on the blockchain.
Store this where you store your seed backup. Do not email it,
do not upload it, do not share it on chat.";

/// The PRD §16.8 banned overclaim phrasings (lowercased substrings). Lifeboat
/// never tells a user their wallet is "safe", their bitcoin is "secure", that
/// recovery is "guaranteed", or that "you can recover" — see
/// [`find_overclaim`]. The substrings catch the §16.8 verbatim claims and their
/// "Your …" / capitalized variants.
pub const BANNED_OVERCLAIM_PHRASES: [&str; 4] = [
    "wallet is safe",
    "bitcoin is secure",
    "recovery is guaranteed",
    "you can recover",
];

/// The §19.1 `anti_actions` — fixed "what NOT to do" guidance present in every
/// report (PRD §15.10 item 7).
const ANTI_ACTIONS: [&str; 3] = [
    "Do not email the descriptor.",
    "Do not store the descriptor in cloud notes apps.",
    "Do not photograph this report and send it on chat.",
];

/// The PRD §17.7 / §9.5 report-and-runbook export mode. `public-safe` (the
/// default) is the share-safe form; `private` is the full form and requires an
/// explicit user toggle in the UI/CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactionMode {
    /// Redacted, share-safe export (xpubs shown only as `xpub6...XXXX`, the
    /// descriptor redacted, one address per chain). The §17.7 default.
    #[default]
    PublicSafe,
    /// Full export (complete xpubs, full descriptor, first five addresses).
    Private,
}

/// Scan `text` for PRD §16.8 banned overclaim phrasing (case-insensitive).
/// Returns the first [`BANNED_OVERCLAIM_PHRASES`] entry present, or `None` when
/// the text is clean. The reusable §16.8 guard for any user-facing copy — the
/// runbook engine (US-031/032) and the CLI/UI export paths (US-036/042) lint
/// their rendered output through it before it reaches the user.
#[must_use]
pub fn find_overclaim(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    BANNED_OVERCLAIM_PHRASES
        .into_iter()
        .find(|&phrase| lower.contains(phrase))
}

/// True when `text` is free of PRD §16.8 banned overclaim phrasing.
#[must_use]
pub fn passes_anti_overclaim_lint(text: &str) -> bool {
    find_overclaim(text).is_none()
}

// --- The §19.1 report types ------------------------------------------------

/// The PRD §19.1 `ReadinessReport`. Crate-owned `serde` type (the JS-boundary
/// convention); field order matches §19.1 so the JSON does too.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReadinessReport {
    /// Report schema version ([`SCHEMA_VERSION`]).
    pub schema_version: String,
    /// Lifeboat application version that produced the report.
    pub app_version: String,
    /// Scoring-engine version ([`readiness_score::SCORING_ENGINE_VERSION`]).
    pub scoring_engine_version: String,
    /// ISO-8601 UTC timestamp, supplied by the caller (kept out of `input_hash`).
    pub created_at: String,
    /// The report mode (`"readiness_check"`).
    pub mode: String,
    /// `sha256:` digest of the canonical input fingerprint.
    pub input_hash: String,
    /// `sha256:` digest of this report with `report_hash` blanked to `""`.
    pub report_hash: String,
    /// The resolved Bitcoin network, or `null` when undeterminable.
    pub network: Option<String>,
    /// Wallet-shape summary.
    pub wallet_summary: WalletSummary,
    /// Receive and (optional) change descriptors.
    pub descriptors: ReportDescriptors,
    /// Per-key provenance.
    pub keys: Vec<ReportKey>,
    /// Derived addresses and the known-address comparison.
    pub addresses: ReportAddresses,
    /// Numeric score, qualitative status, and headline.
    pub score: Score,
    /// The §9.1 A–G analysis checks.
    pub checks: Vec<Check>,
    /// The §16.3 critical failures (force "Not Ready").
    pub critical_issues: Vec<CriticalIssue>,
    /// The §16.4 warnings that fired, with user-facing text.
    pub warnings: Vec<WarningDetail>,
    /// The headline positives (PRD §15.10 item 2).
    pub passes: Vec<PassItem>,
    /// The transparent §16.7 scoring audit trail.
    pub scoring_audit: Vec<ScoringAuditEntry>,
    /// Multisig survivability (§16.6), or `null` for singlesig wallets.
    pub survivability: Option<Survivability>,
    /// Prioritized "what to do next" list (PRD §15.10 item 6).
    pub next_steps: Vec<NextStep>,
    /// "What NOT to do" guidance (PRD §15.10 item 7).
    pub anti_actions: Vec<String>,
    /// Recommended next drill date, `created_at` + 12 months (+ 6 months if the
    /// score is below 70), or `null` if `created_at` is not a parseable date.
    pub next_drill_recommendation: Option<String>,
    /// The §15.6 short disclaimer ([`DISCLAIMER_SHORT`]).
    pub disclaimer_short: String,
    /// The §15.6 long disclaimer ([`DISCLAIMER_LONG`]).
    pub disclaimer_long: String,
}

impl ReadinessReport {
    /// Serialize to the canonical, byte-identical compact JSON (the §19.1 form).
    ///
    /// # Panics
    /// Never in practice: every field is a `String`/number/`bool`/`Option`/`Vec`
    /// or an enum with a string representation, so `serde_json` cannot fail. A
    /// failure here would be a programmer bug (a malformed `Serialize` impl), and
    /// is surfaced as a panic rather than silently corrupting the hash. The
    /// determinism tests exercise this path.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("BUG: ReadinessReport is always serializable")
    }

    /// Serialize to pretty-printed JSON (for human inspection / `--pretty`).
    ///
    /// # Panics
    /// See [`ReadinessReport::to_json`].
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("BUG: ReadinessReport is always serializable")
    }

    /// Derive a mode-appropriate copy of the report (PRD §17.7 / §9.5 / §19).
    ///
    /// [`RedactionMode::Private`] returns the full report unchanged (it is
    /// already complete). [`RedactionMode::PublicSafe`] returns the share-safe
    /// form: every full `xpub` is dropped (the `xpub6...XXXX` `xpub_redacted`
    /// form is kept and, per §19.1, the `xpub` field is omitted from the JSON),
    /// each descriptor's `raw` is replaced by its xpub-redacted text, and the
    /// derived-address lists are trimmed to the first address per chain.
    ///
    /// `report_hash` is recomputed over the emitted bytes so the result
    /// self-verifies by blank-and-recompute in either mode; `input_hash` is left
    /// untouched (it is mode-independent and correlates a wallet's public-safe
    /// and private exports). `redact(Private)` is therefore the identity on a
    /// freshly built report.
    #[must_use]
    pub fn redact(&self, mode: RedactionMode) -> ReadinessReport {
        let mut out = self.clone();
        if mode == RedactionMode::PublicSafe {
            // The wallet's xpubs (the report's keys[] are the receive keys; a
            // change branch is the same wallet, so it shares them). Used to
            // redact the `canonical` text, which has no precomputed redacted
            // form. `raw` already has one (`raw_redacted`), per-descriptor
            // correct, so it is reused directly.
            let xpubs: Vec<String> = out.keys.iter().filter_map(|k| k.xpub.clone()).collect();
            out.descriptors
                .receive
                .raw
                .clone_from(&out.descriptors.receive.raw_redacted);
            redact_xpubs_in_place(&mut out.descriptors.receive.canonical, &xpubs);
            if let Some(change) = out.descriptors.change.as_mut() {
                change.raw.clone_from(&change.raw_redacted);
                redact_xpubs_in_place(&mut change.canonical, &xpubs);
            }
            for key in &mut out.keys {
                key.xpub = None;
            }
            out.addresses.receive_derived.truncate(1);
            out.addresses.change_derived.truncate(1);
        }
        // Recompute over the (possibly redacted) content: blank → serialize →
        // hash → fill, exactly as `build_report` does.
        out.report_hash = String::new();
        out.report_hash = sha256_prefixed(out.to_json().as_bytes());
        out
    }

    /// True when the report carries at least one full extended public key — i.e.
    /// a `private`-mode export would reveal an xpub, so the §14.3 warning applies.
    #[must_use]
    fn contains_xpub(&self) -> bool {
        self.keys.iter().any(|k| k.xpub.is_some())
    }
}

/// The §19.1 `wallet_summary` object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WalletSummary {
    /// `"singlesig"` / `"multisig"` / `"taproot"` / `"timelock"`, or `null`
    /// for an unclassified policy shape.
    pub wallet_type: Option<String>,
    /// Script-type string, e.g. `"wpkh"`, `"wsh(sortedmulti)"`, `"tr"`.
    pub script_type: String,
    /// Multisig threshold *M*, or `null` for non-multisig.
    pub threshold: Option<u32>,
    /// Number of keys *N* (1 for singlesig).
    pub key_count: u32,
    /// Always `true` here (the report is built from a receive descriptor).
    pub has_receive_descriptor: bool,
    /// True when a change branch exists (explicit change descriptor or multipath).
    pub has_change_descriptor: bool,
    /// True for a BIP389 `<0;1>` multipath descriptor.
    pub uses_multipath: bool,
    /// True for a Taproot descriptor.
    pub uses_taproot: bool,
    /// Miniscript-policy use.
    pub uses_miniscript: bool,
    /// Timelock use (`older`/`after`).
    pub uses_timelock: bool,
    /// True when a passphrase exists and is documented for heirs.
    pub passphrase_documented: bool,
}

/// The §19.1 `descriptors` object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportDescriptors {
    /// The receive (or sole / multipath) descriptor.
    pub receive: DescriptorEntry,
    /// An explicitly-provided change descriptor, or `null`.
    pub change: Option<DescriptorEntry>,
}

/// A single descriptor's report entry (§19.1 `descriptors.receive`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DescriptorEntry {
    /// The user's input, verbatim.
    pub raw: String,
    /// `raw` with every xpub redacted to `xpub6...XXXX` (first 6 + last 4).
    pub raw_redacted: String,
    /// The canonical (normalized, `h`-marker, re-checksummed) form.
    pub canonical: String,
    /// Whether a `#checksum` was present.
    pub checksum_present: bool,
    /// Whether the checksum is valid (a present checksum is always valid — an
    /// invalid one is fatal at parse, so it never reaches the report).
    pub checksum_valid: bool,
    /// Parse outcome (`"ok"` for a successfully parsed descriptor).
    pub parse_status: String,
}

/// A §19.1 `keys[]` entry. Carries both the full `xpub` (private mode) and the
/// `xpub_redacted` form regardless of mode.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportKey {
    /// Position in the descriptor's key list (descriptor order).
    pub index: u32,
    /// Master fingerprint (8 lowercase hex), or `null` if absent.
    pub fingerprint: Option<String>,
    /// Origin derivation path (`m/48h/0h/0h/2h` form), or `null` if absent.
    pub derivation_path: Option<String>,
    /// The full extended public key (private mode), or `null` for a raw single
    /// pubkey. Omitted from the JSON in `public-safe` mode (and for a raw
    /// pubkey), per the §19.1 convention "the public-safe export … omits the
    /// `xpub` field"; the `xpub_redacted` form remains in both modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
    /// The redacted `xpub6...XXXX` form, or `null`. Present regardless of mode.
    pub xpub_redacted: Option<String>,
    /// True when both a fingerprint and a non-empty path are present.
    pub key_origin_present: bool,
}

/// The §19.1 `addresses` object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportAddresses {
    /// First-N receive addresses.
    pub receive_derived: Vec<DerivedAddress>,
    /// First-N change addresses (empty unless multipath / explicit change).
    pub change_derived: Vec<DerivedAddress>,
    /// The known-address comparison, or `null` if no known address was provided.
    pub known_address_match: Option<KnownAddressMatch>,
}

/// The §19.1 `score` object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Score {
    /// Numeric score in `[0, 100]`.
    pub numeric: u32,
    /// Qualitative status (snake_case `"mostly_ready"` etc.).
    pub status: ReadinessStatus,
    /// Title-case headline (`"Mostly Ready"` etc.).
    pub headline: String,
}

/// A §19.1 `warnings[]` entry — a fired §16.4 warning with user-facing text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WarningDetail {
    /// The stable §16.4 code.
    pub code: WarningCode,
    /// Short label.
    pub title: String,
    /// What it means and why it matters.
    pub description: String,
    /// How to address it.
    pub recommended_fix: String,
}

/// A §19.1 `passes[]` entry — a headline positive (PRD §15.10 item 2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PassItem {
    /// A `P-…` code (report-local; not part of the §16 catalogs).
    pub code: String,
    /// Human-readable description of what passed.
    pub title: String,
}

/// A §19.1 `next_steps[]` entry (PRD §15.10 item 6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NextStep {
    /// 1-based priority (criticals first, then warnings, in fixed order).
    pub priority: u32,
    /// The recommended action.
    pub action: String,
    /// A rough effort estimate (`"5 min"`, `"future"`, …).
    pub effort: String,
}

// --- The report input ------------------------------------------------------

/// Everything the report is built from. `Copy` (holds only references and small
/// values), mirroring the `readiness_score` context builders — build it with
/// [`ReportInput::new`] plus `with_*`.
///
/// `created_at` is required (the caller stamps an ISO-8601 UTC timestamp so the
/// report stays deterministic); `app_version` defaults to [`APP_VERSION`].
#[derive(Debug, Clone, Copy)]
pub struct ReportInput<'a> {
    receive: &'a ParsedDescriptor,
    change: Option<&'a ParsedDescriptor>,
    network: Option<Network>,
    known_address: Option<&'a str>,
    /// How many receive/change addresses to derive into the report sample.
    /// Defaults to [`REPORT_ADDRESS_COUNT`]; the CLI exposes it as `--derive-count`.
    derive_count: u32,
    declared_wallet_type: Option<DeclaredWalletType>,
    network_confirmed: bool,
    passphrase: Passphrase,
    checklist: RecoveryChecklist,
    emergency_contact_named: bool,
    hardware_signed_recently: bool,
    backup_same_location: bool,
    change_descriptor_required: bool,
    created_at: &'a str,
    app_version: &'a str,
}

impl<'a> ReportInput<'a> {
    /// Start from a parsed receive descriptor and the caller's `created_at`
    /// timestamp. All other signals default to the conservative baseline (no
    /// passphrase, nothing answered, no network chosen).
    #[must_use]
    pub fn new(receive: &'a ParsedDescriptor, created_at: &'a str) -> Self {
        Self {
            receive,
            change: None,
            network: None,
            known_address: None,
            derive_count: REPORT_ADDRESS_COUNT,
            declared_wallet_type: None,
            network_confirmed: false,
            passphrase: Passphrase::Absent,
            checklist: RecoveryChecklist::default(),
            emergency_contact_named: false,
            hardware_signed_recently: false,
            backup_same_location: false,
            change_descriptor_required: false,
            created_at,
            app_version: APP_VERSION,
        }
    }

    /// Provide a separately-supplied change descriptor.
    #[must_use]
    pub fn with_change_descriptor(mut self, change: &'a ParsedDescriptor) -> Self {
        self.change = Some(change);
        self
    }

    /// Set the network to derive on (required for an ambiguous `tpub`; a mainnet
    /// `xpub` resolves its own network).
    #[must_use]
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Provide a known address to compare against the derived range.
    #[must_use]
    pub fn with_known_address(mut self, address: &'a str) -> Self {
        self.known_address = Some(address);
        self
    }

    /// Record the wallet type the user declared (drives the B2 cross-check).
    #[must_use]
    pub fn with_declared_wallet_type(mut self, declared: DeclaredWalletType) -> Self {
        self.declared_wallet_type = Some(declared);
        self
    }

    /// Record that the user confirmed the network (the F2 signal).
    #[must_use]
    pub fn with_network_confirmed(mut self, confirmed: bool) -> Self {
        self.network_confirmed = confirmed;
        self
    }

    /// Set the passphrase documentation signal.
    #[must_use]
    pub fn with_passphrase(mut self, passphrase: Passphrase) -> Self {
        self.passphrase = passphrase;
        self
    }

    /// Set the §9.1 section-H recovery checklist answers.
    #[must_use]
    pub fn with_checklist(mut self, checklist: RecoveryChecklist) -> Self {
        self.checklist = checklist;
        self
    }

    /// Record that an emergency contact was named (suppresses
    /// `W-NO-EMERGENCY-CONTACT`).
    #[must_use]
    pub fn with_emergency_contact_named(mut self, named: bool) -> Self {
        self.emergency_contact_named = named;
        self
    }

    /// Record that hardware signers were exercised recently (suppresses
    /// `W-NO-HW-TEST`).
    #[must_use]
    pub fn with_hardware_signed_recently(mut self, signed: bool) -> Self {
        self.hardware_signed_recently = signed;
        self
    }

    /// Record that the backup and signing device share a location (fires
    /// `W-SAME-LOCATION-BACKUP`).
    #[must_use]
    pub fn with_backup_same_location(mut self, same: bool) -> Self {
        self.backup_same_location = same;
        self
    }

    /// Record that this wallet requires a change descriptor (drives
    /// `C-CHANGE-DESC-REQUIRED-MISSING`).
    #[must_use]
    pub fn with_change_descriptor_required(mut self, required: bool) -> Self {
        self.change_descriptor_required = required;
        self
    }

    /// Override the `app_version` stamped in the report.
    #[must_use]
    pub fn with_app_version(mut self, version: &'a str) -> Self {
        self.app_version = version;
        self
    }

    /// Set how many receive/change addresses the report samples (the CLI
    /// `--derive-count`). Defaults to [`REPORT_ADDRESS_COUNT`]. The count is part
    /// of the report content (it changes `report_hash`) but not of the wallet
    /// identity (`input_hash` is unaffected), so the same wallet still correlates
    /// across samples of different sizes.
    #[must_use]
    pub fn with_derive_count(mut self, count: u32) -> Self {
        self.derive_count = count;
        self
    }
}

// --- The orchestrator ------------------------------------------------------

/// Build the PRD §19.1 [`ReadinessReport`] from a parsed descriptor and context.
///
/// Infallible: address-derivation problems degrade to empty address lists (the
/// G-checks already encode the derivation outcome), and a malformed known
/// address is treated as "not provided". The same input always yields the same
/// report (and thus byte-identical [`ReadinessReport::to_json`]).
#[must_use]
pub fn build_report(input: &ReportInput) -> ReadinessReport {
    let receive = input.receive;

    // The network the caller explicitly chose (drives the F2/G checks) vs. the
    // network actually used for derivation (the choice, else the descriptor's
    // own — only a mainnet xpub resolves itself; a tpub stays ambiguous).
    let chosen_network = input.network;
    let resolved_network = input.network.or_else(|| receive.network());

    // 1. The §9.1 A–G checks (read by every downstream layer).
    let mut check_input = CheckInput::new(receive).with_network_confirmed(input.network_confirmed);
    if let Some(n) = chosen_network {
        check_input = check_input.with_network(n);
    }
    if let Some(change) = input.change {
        check_input = check_input.with_change_descriptor(change);
    }
    if let Some(declared) = input.declared_wallet_type {
        check_input = check_input.with_declared_wallet_type(declared);
    }
    if let Some(addr) = input.known_address {
        check_input = check_input.with_known_address(addr);
    }
    let checks = run_checks(&check_input);

    // 2. The §16.3 critical failures.
    let mut critical_ctx = CriticalContext::new()
        .with_change_descriptor_required(input.change_descriptor_required)
        .with_passphrase(input.passphrase)
        .with_checklist(input.checklist);
    if let Some(declared) = input.declared_wallet_type {
        critical_ctx = critical_ctx.with_declared_wallet_type(declared);
    }
    let criticals = evaluate_critical_failures(&checks, &critical_ctx);

    // 3. The §16.4 numeric score + audit trail.
    let scoring_ctx = ScoringContext::new()
        .with_descriptor(receive, input.change.is_some())
        .with_checklist(input.checklist)
        .with_emergency_contact_named(input.emergency_contact_named)
        .with_hardware_signed_recently(input.hardware_signed_recently)
        .with_backup_same_location(input.backup_same_location);
    let scoring = compute_score(&checks, &scoring_ctx);

    // 4. The §16.2 / §16.5 qualitative status.
    let status_ctx = StatusContext::new().with_descriptor(receive);
    let status = map_status(&checks, scoring.numeric, &criticals, &status_ctx);

    // 5. The §16.6 multisig survivability dimension (None for singlesig).
    let survivability = compute_survivability(receive);

    // 6. Addresses (degrade to empty if the network is unresolved or derivation
    // fails — the G-checks above already report that).
    let (receive_derived, change_derived) = match resolved_network {
        Some(network) => derive_addresses(receive, network, input.derive_count)
            .map(|d| (d.receive_derived, d.change_derived))
            .unwrap_or_default(),
        None => (Vec::new(), Vec::new()),
    };
    let known_address_match = match (input.known_address, resolved_network) {
        (Some(addr), Some(network)) => {
            compare_known_address(receive, network, addr, DEFAULT_ADDRESS_COUNT).ok()
        }
        _ => None,
    };

    // 7. Assemble the §19.1 objects.
    let wallet_summary = WalletSummary {
        wallet_type: wallet_type_str(receive),
        script_type: script_type_str(receive),
        threshold: receive.multisig_info().map(|i| i.threshold() as u32),
        key_count: receive.multisig_info().map_or_else(
            || receive.key_origins().len() as u32,
            |i| i.key_count() as u32,
        ),
        has_receive_descriptor: true,
        has_change_descriptor: input.change.is_some() || receive.uses_multipath(),
        uses_multipath: receive.uses_multipath(),
        uses_taproot: receive.is_taproot(),
        uses_miniscript: receive.uses_miniscript(),
        uses_timelock: receive.uses_timelock(),
        passphrase_documented: matches!(input.passphrase, Passphrase::Documented),
    };

    let descriptors = ReportDescriptors {
        receive: descriptor_entry(receive),
        change: input.change.map(descriptor_entry),
    };

    let keys = receive.key_origins().iter().map(report_key).collect();

    let warnings = scoring
        .scoring_audit
        .iter()
        .map(|entry| {
            let text = warning_text(entry.code);
            WarningDetail {
                code: entry.code,
                title: text.title.to_owned(),
                description: text.description.to_owned(),
                recommended_fix: text.recommended_fix.to_owned(),
            }
        })
        .collect();

    let passes = derive_passes(&checks, receive, known_address_match.as_ref());
    let next_steps = derive_next_steps(&criticals, &scoring.scoring_audit);
    let next_drill_recommendation = next_drill(input.created_at, scoring.numeric);

    let addresses = ReportAddresses {
        receive_derived,
        change_derived,
        known_address_match,
    };

    let score = Score {
        numeric: scoring.numeric,
        status,
        headline: status.headline().to_owned(),
    };

    let input_hash = compute_input_hash(input, resolved_network);

    // Build with the hash field blank, serialize, hash, then fill it in.
    let mut report = ReadinessReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        app_version: input.app_version.to_owned(),
        scoring_engine_version: SCORING_ENGINE_VERSION.to_owned(),
        created_at: input.created_at.to_owned(),
        mode: MODE.to_owned(),
        input_hash,
        report_hash: String::new(),
        network: resolved_network.map(|n| n.to_string()),
        wallet_summary,
        descriptors,
        keys,
        addresses,
        score,
        checks,
        critical_issues: criticals,
        warnings,
        passes,
        scoring_audit: scoring.scoring_audit,
        survivability,
        next_steps,
        anti_actions: ANTI_ACTIONS.iter().map(|s| (*s).to_owned()).collect(),
        next_drill_recommendation,
        disclaimer_short: DISCLAIMER_SHORT.to_owned(),
        disclaimer_long: DISCLAIMER_LONG.to_owned(),
    };
    let pre_hash = report.to_json();
    report.report_hash = sha256_prefixed(pre_hash.as_bytes());
    report
}

// --- Hashing ---------------------------------------------------------------

/// A canonical fingerprint of the meaningful inputs. Excludes `created_at` and
/// `app_version` so the same wallet hashes identically across runs/versions.
#[derive(serde::Serialize)]
struct HashInput<'a> {
    receive_canonical: &'a str,
    change_canonical: Option<&'a str>,
    network: Option<String>,
    known_address: Option<&'a str>,
    declared_wallet_type: Option<DeclaredWalletType>,
    network_confirmed: bool,
    passphrase: Passphrase,
    checklist: RecoveryChecklist,
    emergency_contact_named: bool,
    hardware_signed_recently: bool,
    backup_same_location: bool,
    change_descriptor_required: bool,
}

fn compute_input_hash(input: &ReportInput, resolved_network: Option<Network>) -> String {
    let hash_input = HashInput {
        receive_canonical: input.receive.canonical(),
        change_canonical: input.change.map(ParsedDescriptor::canonical),
        network: resolved_network.map(|n| n.to_string()),
        known_address: input.known_address,
        declared_wallet_type: input.declared_wallet_type,
        network_confirmed: input.network_confirmed,
        passphrase: input.passphrase,
        checklist: input.checklist,
        emergency_contact_named: input.emergency_contact_named,
        hardware_signed_recently: input.hardware_signed_recently,
        backup_same_location: input.backup_same_location,
        change_descriptor_required: input.change_descriptor_required,
    };
    let canonical =
        serde_json::to_string(&hash_input).expect("BUG: HashInput is always serializable");
    sha256_prefixed(canonical.as_bytes())
}

/// `sha256:<64 lowercase hex>` of `bytes`.
fn sha256_prefixed(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity("sha256:".len() + 64);
    out.push_str("sha256:");
    for &b in digest.iter() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// --- Per-descriptor helpers ------------------------------------------------

fn descriptor_entry(parsed: &ParsedDescriptor) -> DescriptorEntry {
    let present = matches!(parsed.checksum_status(), ChecksumStatus::Present);
    DescriptorEntry {
        raw: parsed.raw().to_owned(),
        raw_redacted: redact_raw(parsed),
        canonical: parsed.canonical().to_owned(),
        checksum_present: present,
        checksum_valid: present,
        parse_status: "ok".to_owned(),
    }
}

fn report_key(origin: &descriptor_audit::KeyOrigin) -> ReportKey {
    ReportKey {
        index: origin.index() as u32,
        fingerprint: origin.fingerprint_hex(),
        derivation_path: origin.derivation_path_display(),
        xpub: origin.xpub().map(str::to_owned),
        xpub_redacted: origin.xpub().map(redact_xpub),
        key_origin_present: origin.key_origin_present(),
    }
}

/// Redact an xpub to the §14.3 `xpub6...XXXX` form (first 6 + last 4). Extended
/// keys are ASCII Base58, so byte slicing is safe.
fn redact_xpub(xpub: &str) -> String {
    let n = xpub.len();
    if n <= 10 {
        return xpub.to_owned();
    }
    format!("{}...{}", &xpub[..6], &xpub[n - 4..])
}

/// `raw` with every key's xpub replaced by its redacted form (origin and path
/// preserved), per the §19.1 `raw_redacted` example.
fn redact_raw(parsed: &ParsedDescriptor) -> String {
    let mut redacted = parsed.raw().to_owned();
    for origin in parsed.key_origins() {
        if let Some(xpub) = origin.xpub() {
            redacted = redacted.replace(xpub, &redact_xpub(xpub));
        }
    }
    redacted
}

/// Replace every full `xpub` in `descriptor` with its `xpub6...XXXX` redaction.
/// Used by [`ReadinessReport::redact`] for the `canonical` text, which has no
/// precomputed redacted form. The xpub base58 is identical between a
/// descriptor's `raw` and `canonical` (canonicalization only rewrites path
/// markers and the checksum), so the keys' xpub strings match here.
fn redact_xpubs_in_place(descriptor: &mut String, xpubs: &[String]) {
    for xpub in xpubs {
        if descriptor.contains(xpub.as_str()) {
            *descriptor = descriptor.replace(xpub.as_str(), &redact_xpub(xpub));
        }
    }
}

fn wallet_type_str(parsed: &ParsedDescriptor) -> Option<String> {
    if parsed.is_multisig() {
        Some("multisig".to_owned())
    } else if parsed.is_singlesig() {
        Some("singlesig".to_owned())
    } else if parsed.is_taproot() {
        Some("taproot".to_owned())
    } else if parsed.uses_timelock() {
        Some("timelock".to_owned())
    } else {
        None
    }
}

/// The §19.1 `script_type` string. Combines miniscript's [`DescriptorType`] with
/// the multisig kind so `multi` and `sortedmulti` are distinguished.
fn script_type_str(parsed: &ParsedDescriptor) -> String {
    let is_multi = matches!(
        parsed.multisig_info().map(|i| i.kind()),
        Some(MultisigKind::Multi)
    );
    let s = match parsed.descriptor_type() {
        DescriptorType::Pkh => "pkh",
        DescriptorType::Wpkh => "wpkh",
        DescriptorType::ShWpkh => "sh(wpkh)",
        DescriptorType::Tr => "tr",
        DescriptorType::ShSortedMulti => "sh(sortedmulti)",
        DescriptorType::WshSortedMulti => "wsh(sortedmulti)",
        DescriptorType::ShWshSortedMulti => "sh(wsh(sortedmulti))",
        DescriptorType::Wsh if is_multi => "wsh(multi)",
        DescriptorType::Wsh if parsed.uses_miniscript() => "wsh(miniscript)",
        DescriptorType::Wsh => "wsh",
        DescriptorType::Sh if is_multi => "sh(multi)",
        DescriptorType::Sh if parsed.uses_miniscript() => "sh(miniscript)",
        DescriptorType::Sh => "sh",
        DescriptorType::ShWsh if is_multi => "sh(wsh(multi))",
        DescriptorType::ShWsh if parsed.uses_miniscript() => "sh(wsh(miniscript))",
        DescriptorType::ShWsh => "sh(wsh)",
        DescriptorType::Bare if is_multi => "multi",
        DescriptorType::Bare if parsed.uses_miniscript() => "miniscript",
        DescriptorType::Bare => "bare",
    };
    s.to_owned()
}

// --- Passes / next steps ---------------------------------------------------

fn check_result(checks: &[Check], code: &str) -> Option<CheckResult> {
    checks.iter().find(|c| c.code == code).map(|c| c.result)
}

fn is_pass(checks: &[Check], code: &str) -> bool {
    check_result(checks, code) == Some(CheckResult::Pass)
}

/// Derive the headline positives (§15.10 item 2) from the passing checks. The
/// `P-…` codes are report-local and reproduce the §19.1 example for a matched
/// 2-of-3.
fn derive_passes(
    checks: &[Check],
    receive: &ParsedDescriptor,
    known: Option<&KnownAddressMatch>,
) -> Vec<PassItem> {
    let mut passes = Vec::new();
    if is_pass(checks, "A1") {
        passes.push(PassItem {
            code: "P-DESC-PARSEABLE".to_owned(),
            title: "Descriptor parsed successfully".to_owned(),
        });
    }
    if is_pass(checks, "A2") {
        passes.push(PassItem {
            code: "P-CHECKSUM-VALID".to_owned(),
            title: "Descriptor checksum is valid".to_owned(),
        });
    }
    if let Some(info) = receive.multisig_info() {
        if is_pass(checks, "D2") {
            passes.push(PassItem {
                code: "P-THRESHOLD-CLEAR".to_owned(),
                title: format!(
                    "Multisig threshold identified as {}-of-{}",
                    info.threshold(),
                    info.key_count()
                ),
            });
        }
    }
    if is_pass(checks, "G3") {
        let title = match known.and_then(|m| m.matched_at) {
            Some(loc) => format!(
                "Known address matched at {} index {}",
                loc.chain.as_str(),
                loc.index
            ),
            None => "Known address matched".to_owned(),
        };
        passes.push(PassItem {
            code: "P-ADDRESS-MATCH".to_owned(),
            title,
        });
    }
    passes
}

/// Derive the prioritized "what to do next" list (§15.10 item 6): one step per
/// critical (most urgent, in §16.3 order) then one per fired warning (in §16.4
/// order), matching the order of `critical_issues` / `scoring_audit`.
fn derive_next_steps(criticals: &[CriticalIssue], audit: &[ScoringAuditEntry]) -> Vec<NextStep> {
    let mut steps = Vec::with_capacity(criticals.len() + audit.len());
    let mut priority = 1;
    for issue in criticals {
        let (action, effort) = critical_step(issue.code);
        steps.push(NextStep {
            priority,
            action: action.to_owned(),
            effort: effort.to_owned(),
        });
        priority += 1;
    }
    for entry in audit {
        let text = warning_text(entry.code);
        steps.push(NextStep {
            priority,
            action: text.action.to_owned(),
            effort: text.effort.to_owned(),
        });
        priority += 1;
    }
    steps
}

// --- The §16.4 warning text table (US-028 owns this copy) ------------------

struct WarningText {
    title: &'static str,
    description: &'static str,
    recommended_fix: &'static str,
    action: &'static str,
    effort: &'static str,
}

#[allow(clippy::too_many_lines)]
fn warning_text(code: WarningCode) -> WarningText {
    match code {
        WarningCode::NoDescChecksum => WarningText {
            title: "Descriptor has no checksum",
            description: "Your descriptor was provided without a BIP380 #checksum. A checksum catches transcription errors when you copy the descriptor by hand.",
            recommended_fix: "Re-export the descriptor from your wallet software, or run `lifeboat checksum` to append one, and back up the checksummed form.",
            action: "Add a BIP380 checksum to your descriptor backup.",
            effort: "5 min",
        },
        WarningCode::NoChangeDesc => WarningText {
            title: "Change descriptor missing",
            description: "A complete recovery backup should include both receive and change descriptors. Without the change descriptor, an empty wallet restore will not see funds returned to change addresses.",
            recommended_fix: "Export both descriptors from your wallet software. In Sparrow: File > Export Wallet > Output Descriptor. In Bitcoin Core: listdescriptors true.",
            action: "Export your change descriptor.",
            effort: "5 min",
        },
        WarningCode::NoBirthHeight => WarningText {
            title: "No wallet birth height documented",
            description: "Without a creation date or block height, a recovery wallet must scan the whole chain, which is slow and can miss funds if the gap limit is exceeded.",
            recommended_fix: "Record the wallet's creation date or the block height at first use alongside your descriptor backup.",
            action: "Write down your wallet's creation date or block height.",
            effort: "5 min",
        },
        WarningCode::NoGapLimit => WarningText {
            title: "Gap limit not documented",
            description: "If you have used many addresses, a default gap limit (20) may stop a recovery wallet before it finds all your funds.",
            recommended_fix: "Note the highest address index you have used, or your wallet's configured gap limit, with your backup.",
            action: "Document your wallet's gap limit.",
            effort: "5 min",
        },
        WarningCode::NoKnownAddress => WarningText {
            title: "No known address provided",
            description: "You did not provide a known address to compare against the derived range, so Lifeboat could not confirm the descriptor produces addresses you recognize.",
            recommended_fix: "Re-run the check and paste one address you know belongs to this wallet.",
            action: "Provide one known address from this wallet to compare.",
            effort: "2 min",
        },
        WarningCode::NoPrintedBackup => WarningText {
            title: "No printed descriptor backup",
            description: "A descriptor stored only on a computer can be lost with the device. A printed or stamped copy survives disk failure and software changes.",
            recommended_fix: "Print at least two copies of the descriptor backup and store them in separate, secure locations.",
            action: "Print two copies of the descriptor backup.",
            effort: "10 min",
        },
        WarningCode::NoRecentDrill => WarningText {
            title: "No recovery drill in the last 12 months",
            description: "A recovery plan that has never been rehearsed end-to-end is untested. Hardware, software, and memory all change over time.",
            recommended_fix: "Run a Disaster Drill in Lifeboat v0.3 when available, or rehearse a recovery on a test network now.",
            action: "Run a Disaster Drill in Lifeboat v0.3 when available.",
            effort: "future",
        },
        WarningCode::NoHeirInstructions => WarningText {
            title: "No heir instructions written",
            description: "Without written instructions, the people you intend to inherit your bitcoin may not know the materials exist or how to use them.",
            recommended_fix: "Write a plain-language recovery runbook for your heirs and store it with your estate documents.",
            action: "Write recovery instructions for your heirs.",
            effort: "30 min",
        },
        WarningCode::NoEmergencyContact => WarningText {
            title: "No emergency contact named",
            description: "No trusted person is recorded to help an heir who gets stuck during recovery.",
            recommended_fix: "Name a trusted, Bitcoin-literate contact in your recovery instructions.",
            action: "Name a trusted emergency contact.",
            effort: "5 min",
        },
        WarningCode::NoHwTest => WarningText {
            title: "Hardware wallet not exercised recently",
            description: "A hardware signer that has not signed anything in over a year may have a dead battery, corrupted firmware, or a forgotten PIN.",
            recommended_fix: "Sign a test transaction on a test network with each hardware device.",
            action: "Sign a test transaction with each hardware device.",
            effort: "20 min",
        },
        WarningCode::SameLocationBackup => WarningText {
            title: "Backup and device in the same location",
            description: "Storing the backup and the signing device together means a single fire, flood, or theft can destroy both.",
            recommended_fix: "Move one copy of the backup to a separate, secure location.",
            action: "Move a backup copy to a separate location.",
            effort: "1 day",
        },
        WarningCode::WalletSwUndocumented => WarningText {
            title: "Wallet software not documented",
            description: "If you do not record which wallet software your setup depends on, an heir may not know how to load the descriptor.",
            recommended_fix: "Note the wallet software (and version) needed to use this descriptor, and prefer descriptor-based recovery that works in multiple wallets.",
            action: "Document which wallet software your setup needs.",
            effort: "5 min",
        },
        WarningCode::NoMultipath => WarningText {
            title: "Two separate descriptors instead of multipath",
            description: "Your singlesig wallet uses separate receive and change descriptors. A single BIP389 multipath descriptor (<0;1>) is shorter to back up and harder to get wrong.",
            recommended_fix: "Consider exporting a BIP389 multipath descriptor if your wallet supports it.",
            action: "Consider a single BIP389 multipath descriptor.",
            effort: "10 min",
        },
    }
}

/// The next-step action and effort for each §16.3 critical.
fn critical_step(code: CriticalCode) -> (&'static str, &'static str) {
    match code {
        CriticalCode::DescParseFail => (
            "Fix or re-export the descriptor so it parses as a valid BIP380 expression.",
            "10 min",
        ),
        CriticalCode::DescChecksumInvalid => (
            "Re-copy the descriptor carefully — its checksum does not match the body.",
            "10 min",
        ),
        CriticalCode::MultisigNoDescriptor => (
            "Provide the full multisig descriptor, not just the xpubs.",
            "10 min",
        ),
        CriticalCode::MultisigThresholdMissing => (
            "Provide a descriptor that states the M-of-N threshold.",
            "10 min",
        ),
        CriticalCode::KeyCountBelowThreshold => (
            "Correct the descriptor: the threshold exceeds the number of keys.",
            "10 min",
        ),
        CriticalCode::DuplicateXpub => (
            "Replace the duplicated xpub — each cosigner must use a distinct key.",
            "30 min",
        ),
        CriticalCode::AddressMismatch => (
            "Confirm the descriptor belongs to this wallet; the known address did not match the derived range.",
            "15 min",
        ),
        CriticalCode::WalletTypeMismatch => (
            "Reconcile the wallet type: the descriptor's script type differs from what you declared.",
            "10 min",
        ),
        CriticalCode::ChangeDescRequiredMissing => (
            "Add the change descriptor; this wallet cannot rely on multipath expansion.",
            "10 min",
        ),
        CriticalCode::PassphraseUndocumented => (
            "Document that a passphrase exists in your heir instructions (never write the passphrase itself here).",
            "10 min",
        ),
        CriticalCode::SecretDetected => (
            "Remove the secret from the input and paste only watch-only data (a descriptor or xpub).",
            "5 min",
        ),
        CriticalCode::DescContainsXprv => (
            "Remove the extended private key and use the corresponding xpub instead.",
            "10 min",
        ),
    }
}

// --- Next-drill date arithmetic (dependency-free) --------------------------

/// The §15.10 item-8 recommendation: `created_at` + 12 months, or + 6 months if
/// the score is below 70 ("sooner if score < 70"). `None` if `created_at` is not
/// a parseable `YYYY-MM-DD…` date.
fn next_drill(created_at: &str, numeric: u32) -> Option<String> {
    let (year, month, day) = parse_ymd(created_at)?;
    let months = if numeric >= 70 { 12 } else { 6 };
    let (new_year, new_month) = add_months(year, month, months);
    let new_day = day.min(days_in_month(new_year, new_month));
    Some(format!("{new_year:04}-{new_month:02}-{new_day:02}"))
}

fn parse_ymd(s: &str) -> Option<(i32, u32, u32)> {
    let bytes = s.as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

fn add_months(year: i32, month: u32, add: u32) -> (i32, u32) {
    let zero_based = (month - 1) + add;
    let new_year = year + (zero_based / 12) as i32;
    let new_month = (zero_based % 12) + 1;
    (new_year, new_month)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 30,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// --- Markdown rendering (US-029) -------------------------------------------

/// Which §15.10 section a fired §16.4 warning is reported under.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WarningSection {
    /// §15.10 item 3 — a risky condition, an activity not performed recently, or
    /// a tool limitation. The materials exist; something about them needs a look.
    NeedsAttention,
    /// §15.10 item 5 — an absent artifact, datum, or document a complete recovery
    /// backup should contain.
    Missing,
}

/// Partition the thirteen active §16.4 warnings between §15.10 "what needs attention"
/// (item 3) and "what is missing" (item 5). The split is by intent: a *missing*
/// warning names an absent static artifact/datum/document (add the thing); a
/// *needs-attention* warning names a risky condition, an activity to perform, or
/// a practice to revisit. Exhaustive (no wildcard arm) so any future warning code
/// must be categorized here explicitly.
fn warning_section(code: WarningCode) -> WarningSection {
    match code {
        WarningCode::NoDescChecksum
        | WarningCode::NoChangeDesc
        | WarningCode::NoBirthHeight
        | WarningCode::NoGapLimit
        | WarningCode::NoKnownAddress
        | WarningCode::NoPrintedBackup
        | WarningCode::NoHeirInstructions
        | WarningCode::NoEmergencyContact
        | WarningCode::WalletSwUndocumented => WarningSection::Missing,
        WarningCode::NoRecentDrill
        | WarningCode::NoHwTest
        | WarningCode::SameLocationBackup
        | WarningCode::NoMultipath => WarningSection::NeedsAttention,
    }
}

/// Human label for a §16.6 signer-loss survivability verdict (`"ok"` /
/// `"fail_expected_for_<M>of<N>"`).
fn survives_label(verdict: &str) -> &'static str {
    if verdict == "ok" {
        "yes"
    } else {
        "no — the remaining signers would fall below the threshold"
    }
}

/// Human label for the §16.6 descriptor-loss verdict (`"ok_if_xpubs_retained"`).
fn descriptor_survives_label(verdict: &str) -> &'static str {
    if verdict == "ok_if_xpubs_retained" {
        "yes, if the xpubs are retained"
    } else {
        "no"
    }
}

/// `"no warnings"` / `"1 warning"` / `"3 warnings"` — count-aware phrasing.
fn count_phrase(n: usize, singular: &str, plural: &str) -> String {
    match n {
        0 => format!("no {plural}"),
        1 => format!("1 {singular}"),
        _ => format!("{n} {plural}"),
    }
}

/// Uppercase the first character of `s` (ASCII-only here; inputs are generated).
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Prefix every line of `text` with `"> "` (a Markdown blockquote).
fn push_blockquote(md: &mut String, text: &str) {
    for line in text.lines() {
        md.push_str("> ");
        md.push_str(line);
        md.push('\n');
    }
}

/// Reproduce `body` verbatim inside a fenced code block, so its exact bytes
/// (line breaks and indentation) survive Markdown rendering. The §15.6 / §15.8
/// blocks have no backticks, so a plain triple-backtick fence is unambiguous.
fn push_verbatim_block(md: &mut String, body: &str) {
    md.push_str("```\n");
    md.push_str(body);
    md.push_str("\n```\n");
}

impl ReadinessReport {
    /// Render the human-readable PRD §15.10 Markdown report.
    ///
    /// Answers the ten §15.10 items in order — status, what passed, what needs
    /// attention, what failed, what is missing, what to do next, what NOT to do,
    /// when to run again, the §15.6 short disclaimer, and the Lifeboat version +
    /// report hash — then reproduces the verbatim §15.8 "What this report cannot
    /// tell you" section and the §15.6 long disclaimer (report footer).
    ///
    /// A pure function of `self` (itself deterministic), so the Markdown is
    /// deterministic too: the same input yields byte-identical output, well under
    /// the 64 KB ceiling. US-030 layers the public-safe redaction mode on top.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn to_markdown(&self) -> String {
        let mut md = String::with_capacity(8192);

        // Header: title + the §15.7 "not a wallet" framing (normative on top of
        // every report).
        md.push_str("# Bitcoin Lifeboat — Recovery Readiness Report\n\n");
        push_blockquote(&mut md, NOT_A_WALLET);
        md.push('\n');

        // 1. Status.
        md.push_str("## 1. Status\n\n");
        md.push_str(&format!(
            "**Status: {}** (score {}/100)\n\n",
            self.score.headline, self.score.numeric
        ));
        md.push_str(&capitalize_first(&format!(
            "{}, {}.\n\n",
            count_phrase(
                self.critical_issues.len(),
                "critical failure",
                "critical failures"
            ),
            count_phrase(self.warnings.len(), "warning", "warnings"),
        )));
        md.push_str(&self.wallet_summary_line());
        md.push_str(&format!(
            "- Network: {}\n",
            self.network.as_deref().unwrap_or("not determined")
        ));
        // §16.6: multisig survivability is reported alongside the main status.
        if let Some(s) = &self.survivability {
            md.push_str(&format!(
                "- Survives loss of 1 signer: {}\n",
                survives_label(&s.lose_1_signer)
            ));
            md.push_str(&format!(
                "- Survives loss of 2 signers: {}\n",
                survives_label(&s.lose_2_signers)
            ));
            md.push_str(&format!(
                "- Survives loss of the descriptor backup: {}\n",
                descriptor_survives_label(&s.lose_descriptor_only)
            ));
        }
        md.push('\n');

        // 2. What passed.
        md.push_str("## 2. What passed\n\n");
        if self.passes.is_empty() {
            md.push_str("_None._\n\n");
        } else {
            for pass in &self.passes {
                md.push_str(&format!("- {}\n", pass.title));
            }
            md.push('\n');
        }

        // 3. What needs attention.
        md.push_str("## 3. What needs attention\n\n");
        self.push_warnings(&mut md, WarningSection::NeedsAttention);

        // 4. What failed.
        md.push_str("## 4. What failed\n\n");
        if self.critical_issues.is_empty() {
            md.push_str("_None._\n\n");
        } else {
            for issue in &self.critical_issues {
                md.push_str(&format!(
                    "- **{}** — {} _({})_\n",
                    issue.title,
                    issue.description,
                    issue.code.as_str()
                ));
            }
            md.push('\n');
        }

        // 5. What is missing.
        md.push_str("## 5. What is missing\n\n");
        self.push_warnings(&mut md, WarningSection::Missing);

        // 6. What to do next.
        md.push_str("## 6. What to do next\n\n");
        if self.next_steps.is_empty() {
            md.push_str("_No actions required right now._\n\n");
        } else {
            for step in &self.next_steps {
                md.push_str(&format!(
                    "{}. {} _(est. {})_\n",
                    step.priority, step.action, step.effort
                ));
            }
            md.push('\n');
        }

        // 7. What NOT to do.
        md.push_str("## 7. What NOT to do\n\n");
        for action in &self.anti_actions {
            md.push_str(&format!("- {action}\n"));
        }
        md.push('\n');

        // 8. When to run this again.
        md.push_str("## 8. When to run this again\n\n");
        match &self.next_drill_recommendation {
            Some(date) => md.push_str(&format!(
                "Run this readiness check again by **{date}** — within 12 months, or sooner if your score is below 70.\n\n"
            )),
            None => md.push_str(
                "Run this readiness check again within 12 months, or sooner if your score is below 70.\n\n",
            ),
        }

        // 9. Disclaimer (§15.6 short form).
        md.push_str("## 9. Disclaimer\n\n");
        push_verbatim_block(&mut md, DISCLAIMER_SHORT);
        md.push('\n');

        // 10. Lifeboat version + report hash (reproducibility / forensic
        // correlation).
        md.push_str("## 10. Lifeboat version and report hash\n\n");
        md.push_str(&format!("- Lifeboat version: {}\n", self.app_version));
        md.push_str(&format!(
            "- Scoring engine version: {}\n",
            self.scoring_engine_version
        ));
        md.push_str(&format!(
            "- Report schema version: {}\n",
            self.schema_version
        ));
        md.push_str(&format!("- Generated (UTC): {}\n", self.created_at));
        md.push_str(&format!("- Input hash: {}\n", self.input_hash));
        md.push_str(&format!("- Report hash: {}\n\n", self.report_hash));

        // The verbatim §15.8 section (every report reproduces it).
        md.push_str("## What this report cannot tell you\n\n");
        push_verbatim_block(&mut md, REPORT_CANNOT_TELL);
        md.push('\n');

        // Footer: the verbatim §15.6 long disclaimer.
        md.push_str("## About this document\n\n");
        push_verbatim_block(&mut md, DISCLAIMER_LONG);

        md
    }

    /// Render the §15.10 Markdown report for `mode` (PRD §17.7).
    ///
    /// The report is first [`redact`](ReadinessReport::redact)ed for the mode (so
    /// the rendered `report_hash` matches the corresponding mode's JSON export).
    /// In [`RedactionMode::Private`], when the report carries any xpub, the
    /// verbatim §14.3 [`XPUB_PRIVACY_WARNING`] is prepended as a Markdown
    /// blockquote; the share-safe `public-safe` form shows only the
    /// `xpub6...XXXX` redaction and needs no warning. Both modes pass the §16.8
    /// [`passes_anti_overclaim_lint`]. A pure function of `self`, hence
    /// deterministic.
    #[must_use]
    pub fn to_markdown_mode(&self, mode: RedactionMode) -> String {
        let body = self.redact(mode).to_markdown();
        if mode == RedactionMode::Private && self.contains_xpub() {
            let mut out = String::with_capacity(body.len() + XPUB_PRIVACY_WARNING.len() + 16);
            push_blockquote(&mut out, XPUB_PRIVACY_WARNING);
            out.push('\n');
            out.push_str(&body);
            out
        } else {
            body
        }
    }

    /// The §15.10-item-1 wallet-shape bullet (`- Wallet type: …`).
    fn wallet_summary_line(&self) -> String {
        let ws = &self.wallet_summary;
        let kind = ws.wallet_type.as_deref().unwrap_or("unknown");
        match ws.threshold {
            Some(m) => format!(
                "- Wallet type: {} — {}, {}-of-{}\n",
                kind, ws.script_type, m, ws.key_count
            ),
            None => format!("- Wallet type: {} — {}\n", kind, ws.script_type),
        }
    }

    /// Push the fired warnings belonging to `section` as Markdown bullets, or the
    /// `_None._` placeholder when none fired. Warnings keep their `scoring_audit`
    /// (§16.4 table) order within the section.
    fn push_warnings(&self, md: &mut String, section: WarningSection) {
        let mut any = false;
        for warning in &self.warnings {
            if warning_section(warning.code) != section {
                continue;
            }
            any = true;
            md.push_str(&format!(
                "- **{}** — {} _({})_\n",
                warning.title,
                warning.description,
                warning.code.as_str()
            ));
        }
        if any {
            md.push('\n');
        } else {
            md.push_str("_None._\n\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use descriptor_audit::{compute_checksum, parse_descriptor};
    use readiness_score::Answer;

    macro_rules! fixture {
        ($path:literal) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/",
                $path
            ))
            .trim()
        };
    }

    const CREATED_AT: &str = "2026-05-28T00:00:00Z";

    fn parse(contents: &str) -> ParsedDescriptor {
        parse_descriptor(contents).expect("fixture parses")
    }

    /// A multipath singlesig built from `wpkh_valid.txt` (`/0/*` → `/<0;1>/*`,
    /// re-checksummed) — used for the end-to-end "Ready" case (no separate change
    /// descriptor warning, change branch derivable).
    fn multipath_singlesig() -> ParsedDescriptor {
        let body = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let no_checksum = body.split('#').next().expect("body");
        let multipath = no_checksum.replace("/0/*", "/<0;1>/*");
        let with_checksum = compute_checksum(&multipath).expect("checksum");
        parse(&with_checksum)
    }

    fn full_yes_checklist() -> RecoveryChecklist {
        RecoveryChecklist {
            physical_copies: Some(Answer::Yes),
            signer_locations_known: Some(Answer::Yes),
            signers_tested_recently: Some(Answer::Yes),
            passphrase_documented: Some(Answer::Yes),
            wallet_software_documented: Some(Answer::Yes),
            gap_limit_documented: Some(Answer::Yes),
            birth_height_documented: Some(Answer::Yes),
            heir_instructions_written: Some(Answer::Yes),
            recent_drill: Some(Answer::Yes),
        }
    }

    #[test]
    fn report_is_byte_identical_across_two_runs() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let input = ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet);
        let a = build_report(&input).to_json();
        let b = build_report(&input).to_json();
        assert_eq!(a, b, "identical inputs must yield byte-identical JSON");
    }

    #[test]
    fn derive_count_controls_the_address_sample_without_changing_wallet_identity() {
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));

        // Default samples REPORT_ADDRESS_COUNT receive addresses.
        let default =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        assert_eq!(
            default.addresses.receive_derived.len(),
            REPORT_ADDRESS_COUNT as usize
        );

        // An explicit count is honored verbatim.
        let three = build_report(
            &ReportInput::new(&parsed, CREATED_AT)
                .with_network(Network::Testnet)
                .with_derive_count(3),
        );
        assert_eq!(three.addresses.receive_derived.len(), 3);

        // The count changes the report content (report_hash) but not the wallet
        // identity (input_hash correlates the same wallet across sample sizes).
        assert_ne!(three.report_hash, default.report_hash);
        assert_eq!(three.input_hash, default.input_hash);
    }

    #[test]
    fn report_round_trips_through_serde() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let json = report.to_json();
        let parsed_back: ReadinessReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(parsed_back, report, "serde round-trip must be lossless");
        assert_eq!(parsed_back.to_json(), json, "re-serialization is stable");
    }

    #[test]
    fn report_has_every_section_19_1_top_level_key() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).expect("json");
        let object = value.as_object().expect("top-level object");
        for key in [
            "schema_version",
            "app_version",
            "scoring_engine_version",
            "created_at",
            "mode",
            "input_hash",
            "report_hash",
            "network",
            "wallet_summary",
            "descriptors",
            "keys",
            "addresses",
            "score",
            "checks",
            "critical_issues",
            "warnings",
            "passes",
            "scoring_audit",
            "survivability",
            "next_steps",
            "anti_actions",
            "next_drill_recommendation",
            "disclaimer_short",
            "disclaimer_long",
        ] {
            assert!(object.contains_key(key), "missing top-level key: {key}");
        }
        // Stamped metadata.
        assert_eq!(object["schema_version"], "0.1.0");
        assert_eq!(object["scoring_engine_version"], SCORING_ENGINE_VERSION);
        assert_eq!(object["mode"], "readiness_check");
        assert_eq!(object["created_at"], CREATED_AT);
        assert!(object["input_hash"]
            .as_str()
            .expect("input_hash string")
            .starts_with("sha256:"));
        assert!(object["report_hash"]
            .as_str()
            .expect("report_hash string")
            .starts_with("sha256:"));
    }

    #[test]
    fn report_hash_is_verifiable_by_blanking_the_field() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let mut blanked = report.clone();
        blanked.report_hash = String::new();
        let recomputed = sha256_prefixed(blanked.to_json().as_bytes());
        assert_eq!(report.report_hash, recomputed);
        assert_eq!(report.report_hash.len(), "sha256:".len() + 64);
    }

    #[test]
    fn input_hash_is_stable_and_input_sensitive() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let base = ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet);
        let h1 = build_report(&base).input_hash;
        // A different created_at must NOT change the input hash.
        let other_time = build_report(
            &ReportInput::new(&parsed, "2030-01-01T00:00:00Z").with_network(Network::Testnet),
        )
        .input_hash;
        assert_eq!(h1, other_time, "created_at is excluded from input_hash");
        // A different network choice MUST change it.
        let other_net = build_report(&ReportInput::new(&parsed, CREATED_AT)).input_hash;
        assert_ne!(h1, other_net, "the resolved network is part of input_hash");
    }

    #[test]
    fn singlesig_with_matched_address_is_ready() {
        let parsed = multipath_singlesig();
        // Self-derive a known receive address so D8 matches.
        let derived =
            address_derive::derive_addresses(&parsed, Network::Testnet, 5).expect("derive");
        let known = derived.receive_derived[0].address.clone();
        let input = ReportInput::new(&parsed, CREATED_AT)
            .with_network(Network::Testnet)
            .with_known_address(&known)
            .with_checklist(full_yes_checklist())
            .with_passphrase(Passphrase::Absent)
            .with_emergency_contact_named(true)
            .with_hardware_signed_recently(true);
        let report = build_report(&input);

        assert_eq!(report.score.numeric, 100);
        assert_eq!(report.score.status, ReadinessStatus::Ready);
        assert_eq!(report.score.headline, "Ready");
        assert_eq!(
            report.wallet_summary.wallet_type.as_deref(),
            Some("singlesig")
        );
        assert_eq!(report.wallet_summary.script_type, "wpkh");
        assert!(report.wallet_summary.uses_multipath);
        assert_eq!(report.network.as_deref(), Some("testnet"));
        assert!(
            report.survivability.is_none(),
            "singlesig has no survivability"
        );
        assert!(report.warnings.is_empty());
        assert!(report.critical_issues.is_empty());
        // Headline positives include the parse, checksum, and address-match items.
        let codes: Vec<&str> = report.passes.iter().map(|p| p.code.as_str()).collect();
        assert!(codes.contains(&"P-DESC-PARSEABLE"));
        assert!(codes.contains(&"P-CHECKSUM-VALID"));
        assert!(codes.contains(&"P-ADDRESS-MATCH"));
        assert_eq!(
            report.next_drill_recommendation.as_deref(),
            Some("2027-05-28")
        );
        // The known_address_match object is present and matched.
        let m = report.addresses.known_address_match.expect("match present");
        assert!(m.matched);
    }

    #[test]
    fn multisig_2of3_reports_survivability_and_quorum() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));

        assert_eq!(
            report.wallet_summary.wallet_type.as_deref(),
            Some("multisig")
        );
        assert_eq!(report.wallet_summary.script_type, "wsh(sortedmulti)");
        assert_eq!(report.wallet_summary.threshold, Some(2));
        assert_eq!(report.wallet_summary.key_count, 3);
        assert_eq!(report.keys.len(), 3);

        let s = report.survivability.expect("multisig has survivability");
        assert_eq!(s.lose_1_signer, "ok");
        assert_eq!(s.lose_2_signers, "fail_expected_for_2of3");
        assert_eq!(s.lose_descriptor_only, "ok_if_xpubs_retained");

        // A bare 2-of-3 with nothing else answered accrues warnings and is not Ready.
        assert!(!report.warnings.is_empty());
        assert_eq!(report.warnings.len(), report.scoring_audit.len());
        assert_eq!(report.next_steps.len(), report.scoring_audit.len());
    }

    #[test]
    fn liana_timelock_report_is_first_class_not_preview() {
        let parsed = parse(fixture!("descriptors/timelock/liana_basic.txt"));
        let derived =
            address_derive::derive_addresses(&parsed, Network::Testnet, 1).expect("derive");
        let known = derived.receive_derived[0].address.clone();
        let input = ReportInput::new(&parsed, CREATED_AT)
            .with_network(Network::Testnet)
            .with_network_confirmed(true)
            .with_known_address(&known)
            .with_checklist(full_yes_checklist())
            .with_passphrase(Passphrase::Absent)
            .with_emergency_contact_named(true)
            .with_hardware_signed_recently(true);
        let report = build_report(&input);

        assert_eq!(
            report.wallet_summary.wallet_type.as_deref(),
            Some("timelock")
        );
        assert_eq!(report.wallet_summary.script_type, "wsh(miniscript)");
        assert_eq!(report.wallet_summary.threshold, None);
        assert_eq!(report.wallet_summary.key_count, 2);
        assert!(report.wallet_summary.uses_miniscript);
        assert!(report.wallet_summary.uses_timelock);
        assert!(report.wallet_summary.uses_multipath);
        assert!(!report.wallet_summary.uses_taproot);
        assert_eq!(report.addresses.receive_derived.len(), 5);
        assert_eq!(report.addresses.change_derived.len(), 5);
        assert!(report.warnings.is_empty());
        assert!(report.scoring_audit.is_empty());
        assert!(report.next_steps.is_empty());
    }

    #[test]
    fn duplicate_xpub_forces_not_ready_and_drives_a_next_step() {
        let parsed = parse(fixture!("descriptors/multisig/duplicate_xpub.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));

        assert_eq!(report.score.status, ReadinessStatus::NotReady);
        assert!(report
            .critical_issues
            .iter()
            .any(|c| c.code.as_str() == "C-DUPLICATE-XPUB"));
        // Criticals lead the next-steps list at priority 1.
        assert_eq!(report.next_steps[0].priority, 1);
        assert!(report.next_steps[0].action.contains("xpub"));
    }

    #[test]
    fn descriptor_entry_redacts_xpubs_in_raw() {
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let receive = &report.descriptors.receive;
        // The full xpub is in `raw` but redacted in `raw_redacted`.
        let xpub = parsed.key_origins()[0].xpub().expect("xpub").to_owned();
        assert!(receive.raw.contains(&xpub));
        assert!(!receive.raw_redacted.contains(&xpub));
        assert!(receive.raw_redacted.contains("..."));
        assert!(receive.checksum_present && receive.checksum_valid);
        // Per-key redaction matches.
        let key = &report.keys[0];
        assert_eq!(key.xpub.as_deref(), Some(xpub.as_str()));
        let red = key.xpub_redacted.clone().expect("redacted");
        assert_eq!(red, format!("{}...{}", &xpub[..6], &xpub[xpub.len() - 4..]));
    }

    #[test]
    fn redact_xpub_keeps_first_six_and_last_four() {
        let x = "xpub6CUGRUonZSQ4TWtTMmzXTm1234567890abcdEFGH";
        let r = redact_xpub(x);
        assert_eq!(r, format!("{}...{}", &x[..6], &x[x.len() - 4..]));
        // Too-short strings are returned unchanged.
        assert_eq!(redact_xpub("short"), "short");
    }

    #[test]
    fn next_drill_adds_twelve_or_six_months() {
        // Score >= 70 → +12 months (matches the §19.1 example).
        assert_eq!(
            next_drill("2026-05-28T00:00:00Z", 75).as_deref(),
            Some("2027-05-28")
        );
        // Score < 70 → +6 months (sooner).
        assert_eq!(
            next_drill("2026-05-28T00:00:00Z", 30).as_deref(),
            Some("2026-11-28")
        );
        // Day clamping across a short month (Aug 31 + 6 months = Feb 28, 2027).
        assert_eq!(
            next_drill("2026-08-31T00:00:00Z", 30).as_deref(),
            Some("2027-02-28")
        );
        // Unparseable input → None.
        assert!(next_drill("not-a-date", 100).is_none());
    }

    #[test]
    fn every_warning_code_has_complete_text() {
        for code in WarningCode::ALL {
            let t = warning_text(code);
            assert!(!t.title.is_empty(), "{code:?} title");
            assert!(!t.description.is_empty(), "{code:?} description");
            assert!(!t.recommended_fix.is_empty(), "{code:?} fix");
            assert!(!t.action.is_empty(), "{code:?} action");
            assert!(!t.effort.is_empty(), "{code:?} effort");
        }
    }

    #[test]
    fn every_critical_code_has_a_next_step() {
        for code in CriticalCode::ALL {
            let (action, effort) = critical_step(code);
            assert!(!action.is_empty(), "{code:?} action");
            assert!(!effort.is_empty(), "{code:?} effort");
        }
    }

    #[test]
    fn generated_text_avoids_overclaim_phrases() {
        // The text THIS crate authors (warnings / passes / next steps /
        // anti-actions) never makes a §16.8 banned claim, enforced via the
        // reusable lint. The verbatim §15.6 disclaimer is deliberately excluded
        // (it uses "is safe" to NEGATE the claim).
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let report =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let mut generated = String::new();
        for w in &report.warnings {
            generated.push_str(&w.title);
            generated.push_str(&w.description);
            generated.push_str(&w.recommended_fix);
        }
        for p in &report.passes {
            generated.push_str(&p.title);
        }
        for s in &report.next_steps {
            generated.push_str(&s.action);
        }
        for a in &report.anti_actions {
            generated.push_str(a);
        }
        assert!(
            passes_anti_overclaim_lint(&generated),
            "banned overclaim present: {:?}",
            find_overclaim(&generated)
        );
    }

    #[test]
    fn disclaimers_are_the_verbatim_section_15_6_text() {
        // Anchor phrases from §15.6 (full verbatim text is in the consts).
        assert!(DISCLAIMER_SHORT.starts_with("This report is a diagnostic aid."));
        assert!(DISCLAIMER_SHORT.contains("cannot guarantee that any"));
        assert!(DISCLAIMER_LONG.starts_with("About this document"));
        assert!(DISCLAIMER_LONG.contains("It does not mean your bitcoin\nis safe."));
        assert!(DISCLAIMER_LONG.trim_end().ends_with("Hang up."));
        // anti_actions match §19.1 exactly.
        assert_eq!(ANTI_ACTIONS[0], "Do not email the descriptor.");
    }

    // --- US-029: Markdown report ------------------------------------------

    /// The end-to-end "Ready" singlesig case (multipath, matched known address,
    /// everything confirmed). `app_version` is pinned so the snapshot is stable
    /// across workspace version bumps.
    fn ready_singlesig_report() -> ReadinessReport {
        let parsed = multipath_singlesig();
        let derived =
            address_derive::derive_addresses(&parsed, Network::Testnet, 5).expect("derive");
        let known = derived.receive_derived[0].address.clone();
        let input = ReportInput::new(&parsed, CREATED_AT)
            .with_network(Network::Testnet)
            .with_known_address(&known)
            .with_checklist(full_yes_checklist())
            .with_passphrase(Passphrase::Absent)
            .with_emergency_contact_named(true)
            .with_hardware_signed_recently(true)
            .with_app_version("0.1.0");
        build_report(&input)
    }

    /// A bare 2-of-3 multisig with nothing else answered — accrues the §16.4
    /// warnings and is not Ready.
    fn warn_multisig_report() -> ReadinessReport {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let input = ReportInput::new(&parsed, CREATED_AT)
            .with_network(Network::Testnet)
            .with_app_version("0.1.0");
        build_report(&input)
    }

    #[test]
    fn markdown_singlesig_ready_snapshot() {
        insta::assert_snapshot!("singlesig_ready", ready_singlesig_report().to_markdown());
    }

    #[test]
    fn markdown_multisig_warn_snapshot() {
        insta::assert_snapshot!("multisig_warn", warn_multisig_report().to_markdown());
    }

    #[test]
    fn markdown_is_deterministic_and_under_64kb() {
        let report = warn_multisig_report();
        let a = report.to_markdown();
        let b = report.to_markdown();
        assert_eq!(a, b, "identical input must yield byte-identical Markdown");
        assert!(
            a.len() < 64 * 1024,
            "report is {} bytes (>= 64 KB)",
            a.len()
        );
    }

    #[test]
    fn markdown_answers_the_ten_section_15_10_items_in_order() {
        let md = warn_multisig_report().to_markdown();
        // The ten §15.10 section headings, in order, must each appear and be
        // monotonically positioned.
        let headings = [
            "## 1. Status",
            "## 2. What passed",
            "## 3. What needs attention",
            "## 4. What failed",
            "## 5. What is missing",
            "## 6. What to do next",
            "## 7. What NOT to do",
            "## 8. When to run this again",
            "## 9. Disclaimer",
            "## 10. Lifeboat version and report hash",
        ];
        let mut last = 0usize;
        for heading in headings {
            let at = md
                .find(heading)
                .unwrap_or_else(|| panic!("missing heading: {heading}"));
            assert!(at >= last, "heading out of order: {heading}");
            last = at;
        }
    }

    #[test]
    fn markdown_reproduces_the_verbatim_15_8_and_15_6_blocks() {
        let md = warn_multisig_report().to_markdown();
        // The verbatim §15.8 section, byte-for-byte (including the indented
        // bullets and the parenthetical continuation lines).
        assert!(
            md.contains(REPORT_CANNOT_TELL),
            "missing verbatim §15.8 block"
        );
        assert!(REPORT_CANNOT_TELL.contains("\n  - Whether your hardware wallets still work."));
        assert!(REPORT_CANNOT_TELL.contains("\n     low-value wallet first.)"));
        // Both §15.6 disclaimers, verbatim.
        assert!(
            md.contains(DISCLAIMER_SHORT),
            "missing verbatim §15.6 short"
        );
        assert!(md.contains(DISCLAIMER_LONG), "missing verbatim §15.6 long");
        // The §15.7 "not a wallet" framing, rendered as a blockquote.
        assert!(md.contains("> Bitcoin Lifeboat is not a wallet, not a custody service, not a"));
    }

    #[test]
    fn markdown_never_overclaims() {
        // The §16.8 banned phrases must not appear anywhere in the rendered
        // Markdown — including the verbatim disclaimers, which negate the claim
        // ("does not mean your bitcoin is safe") without using a banned phrase.
        let md = ready_singlesig_report().to_markdown();
        assert!(
            passes_anti_overclaim_lint(&md),
            "banned overclaim present: {:?}",
            find_overclaim(&md)
        );
    }

    #[test]
    fn ready_markdown_shows_status_and_passes_no_failures() {
        let md = ready_singlesig_report().to_markdown();
        assert!(md.contains("**Status: Ready** (score 100/100)"));
        assert!(md.contains("No critical failures, no warnings."));
        assert!(md.contains("- Descriptor parsed successfully"));
        // No criticals/warnings → the failed/missing/attention sections are empty.
        assert!(md.contains("## 4. What failed\n\n_None._"));
        assert!(md.contains("## 5. What is missing\n\n_None._"));
        // Version + hash section carries the report hash.
        assert!(md.contains("- Report hash: sha256:"));
        assert!(md.contains("- Lifeboat version: 0.1.0"));
    }

    #[test]
    fn warn_markdown_reports_multisig_survivability_in_status() {
        let md = warn_multisig_report().to_markdown();
        // §16.6 survivability is reported in the Status section for multisig.
        assert!(md.contains("- Survives loss of 1 signer: yes"));
        assert!(md.contains(
            "- Survives loss of 2 signers: no — the remaining signers would fall below the threshold"
        ));
        assert!(
            md.contains("- Survives loss of the descriptor backup: yes, if the xpubs are retained")
        );
        // Singlesig has no survivability dimension.
        assert!(!ready_singlesig_report()
            .to_markdown()
            .contains("Survives loss of"));
    }

    #[test]
    fn warn_markdown_partitions_warnings_between_attention_and_missing() {
        let md = warn_multisig_report().to_markdown();
        // "Missing" carries absent artifacts/documents.
        assert!(md.contains("_(W-NO-CHANGE-DESC)_"));
        assert!(md.contains("_(W-NO-KNOWN-ADDRESS)_"));
        // "Needs attention" carries activities/conditions.
        assert!(md.contains("_(W-NO-RECENT-DRILL)_"));
        assert!(md.contains("_(W-NO-HW-TEST)_"));
        // A missing-bucket code must sit under §5, not §3.
        let attention = md.find("## 3. What needs attention").expect("§3");
        let missing = md.find("## 5. What is missing").expect("§5");
        let next = md.find("## 6. What to do next").expect("§6");
        let change_desc = md
            .find("_(W-NO-CHANGE-DESC)_")
            .expect("change-desc warning");
        assert!(
            change_desc > missing && change_desc < next,
            "W-NO-CHANGE-DESC must render under §5 (missing)"
        );
        let drill = md.find("_(W-NO-RECENT-DRILL)_").expect("drill warning");
        assert!(
            drill > attention && drill < missing,
            "W-NO-RECENT-DRILL must render under §3 (needs attention)"
        );
    }

    #[test]
    fn every_warning_code_is_partitioned_and_buckets_are_stable() {
        // The match in `warning_section` is exhaustive (compiler-checked), so this
        // pins the actual split: 9 "missing" + 4 "needs attention" = all active codes.
        let missing = WarningCode::ALL
            .iter()
            .filter(|c| warning_section(**c) == WarningSection::Missing)
            .count();
        let attention = WarningCode::ALL
            .iter()
            .filter(|c| warning_section(**c) == WarningSection::NeedsAttention)
            .count();
        assert_eq!(missing, 9, "missing-bucket size changed");
        assert_eq!(attention, 4, "needs-attention-bucket size changed");
        assert_eq!(missing + attention, WarningCode::ALL.len());
    }

    #[test]
    fn count_phrase_pluralizes() {
        assert_eq!(count_phrase(0, "warning", "warnings"), "no warnings");
        assert_eq!(count_phrase(1, "warning", "warnings"), "1 warning");
        assert_eq!(count_phrase(3, "warning", "warnings"), "3 warnings");
    }

    // --- US-030: redaction modes + §14.3 prepend + §16.8 lint -------------

    #[test]
    fn public_safe_mode_redacts_xpubs_descriptor_and_addresses() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let full =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let ps = full.redact(RedactionMode::PublicSafe);
        let json = ps.to_json();

        // No full xpub leaks anywhere in the public-safe JSON.
        for origin in parsed.key_origins() {
            if let Some(xpub) = origin.xpub() {
                assert!(
                    !json.contains(xpub),
                    "a full xpub leaked into public-safe JSON"
                );
            }
        }
        // Per key: the full xpub is dropped, the redacted form is kept.
        for key in &ps.keys {
            assert!(key.xpub.is_none(), "public-safe must drop the full xpub");
            assert!(key.xpub_redacted.is_some());
        }
        // §19.1: the public-safe JSON OMITS the `xpub` field (not `null`).
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        let key0 = &value["keys"][0];
        assert!(
            key0.get("xpub").is_none(),
            "public-safe JSON must omit the xpub field entirely"
        );
        assert!(key0.get("xpub_redacted").is_some());

        // The descriptor `raw` is the xpub-redacted form.
        assert_eq!(
            ps.descriptors.receive.raw,
            ps.descriptors.receive.raw_redacted
        );
        assert!(ps.descriptors.receive.raw.contains("..."));

        // Addresses trimmed to the first per chain (private keeps up to five).
        assert!(full.addresses.receive_derived.len() > 1);
        assert_eq!(ps.addresses.receive_derived.len(), 1);
    }

    #[test]
    fn public_safe_mode_trims_change_addresses_too() {
        let parsed = multipath_singlesig();
        let full =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        // The full report derives multiple receive AND change addresses.
        assert!(full.addresses.receive_derived.len() > 1);
        assert!(full.addresses.change_derived.len() > 1);
        let ps = full.redact(RedactionMode::PublicSafe);
        assert_eq!(ps.addresses.receive_derived.len(), 1);
        assert_eq!(ps.addresses.change_derived.len(), 1);
    }

    #[test]
    fn private_mode_returns_the_full_report_unchanged() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let full =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        assert_eq!(
            full.redact(RedactionMode::Private),
            full,
            "private redaction must be the identity on a freshly built report"
        );
    }

    #[test]
    fn public_safe_report_hash_self_verifies() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let ps =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet))
                .redact(RedactionMode::PublicSafe);
        let mut blanked = ps.clone();
        blanked.report_hash = String::new();
        assert_eq!(
            ps.report_hash,
            sha256_prefixed(blanked.to_json().as_bytes()),
            "a public-safe export must verify by blank-and-recompute"
        );
    }

    #[test]
    fn modes_share_input_hash_but_differ_in_report_hash() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let full =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet));
        let ps = full.redact(RedactionMode::PublicSafe);
        // input_hash is the mode-independent wallet fingerprint (correlates exports).
        assert_eq!(ps.input_hash, full.input_hash);
        // report_hash is over the emitted bytes, which differ by mode.
        assert_ne!(ps.report_hash, full.report_hash);
    }

    #[test]
    fn public_safe_json_round_trips_with_xpub_field_omitted() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let ps =
            build_report(&ReportInput::new(&parsed, CREATED_AT).with_network(Network::Testnet))
                .redact(RedactionMode::PublicSafe);
        let json = ps.to_json();
        // The omitted `xpub` field deserializes back to None (lossless round-trip).
        let back: ReadinessReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, ps, "public-safe report round-trips losslessly");
        assert!(back.keys.iter().all(|k| k.xpub.is_none()));
        assert_eq!(back.to_json(), json, "re-serialization is stable");
    }

    #[test]
    fn private_markdown_prepends_the_section_14_3_xpub_warning() {
        let report = warn_multisig_report();
        let private = report.to_markdown_mode(RedactionMode::Private);
        let public = report.to_markdown_mode(RedactionMode::PublicSafe);

        // The §14.3 block, verbatim, as a leading Markdown blockquote.
        assert!(
            private.starts_with("> ⚠️ This document contains an extended public key (xpub).\n"),
            "private Markdown must open with the §14.3 warning"
        );
        assert!(
            private.contains("> An xpub reveals every receive AND change address for this wallet,")
        );
        assert!(private.contains("> do not upload it, do not share it on chat."));

        // The share-safe form shows only the redaction and never the warning.
        assert!(!public.contains("⚠️ This document contains an extended public key"));

        // Both render modes pass the §16.8 lint.
        assert!(passes_anti_overclaim_lint(&private));
        assert!(passes_anti_overclaim_lint(&public));
    }

    #[test]
    fn xpub_privacy_warning_is_the_verbatim_section_14_3_text() {
        assert!(XPUB_PRIVACY_WARNING
            .starts_with("⚠️ This document contains an extended public key (xpub)."));
        assert!(XPUB_PRIVACY_WARNING.contains(
            "An xpub reveals every receive AND change address for this wallet,\npast and future."
        ));
        assert!(XPUB_PRIVACY_WARNING.contains(
            "Anyone with this xpub can see your wallet's\nentire transaction history on the blockchain."
        ));
        assert!(XPUB_PRIVACY_WARNING
            .contains("Store this where you store your seed backup. Do not email it,"));
        assert!(XPUB_PRIVACY_WARNING
            .trim_end()
            .ends_with("do not upload it, do not share it on chat."));
        // Flush-left literal: no leading newline (the `\` swallowed it).
        assert!(!XPUB_PRIVACY_WARNING.starts_with('\n'));
    }

    #[test]
    fn anti_overclaim_lint_rejects_banned_and_accepts_approved() {
        // The four §16.8 banned claims (verbatim) — each must be caught.
        for banned in [
            "Your wallet is safe.",
            "Your bitcoin is secure.",
            "Recovery is guaranteed.",
            "You can recover.",
        ] {
            assert!(
                !passes_anti_overclaim_lint(banned),
                "lint must reject banned claim: {banned}"
            );
            assert!(find_overclaim(banned).is_some());
        }
        // The four §16.8 approved alternatives — each must pass.
        for approved in [
            "Your backup appears complete for the scenarios we tested.",
            "The metadata you provided passed all checks.",
            "Ready for the tested scenario.",
            "Your descriptor parses and your known address matches.",
        ] {
            assert!(
                passes_anti_overclaim_lint(approved),
                "lint must accept approved alternative: {approved}"
            );
        }
        // Case-insensitive; clean text returns None.
        assert!(!passes_anti_overclaim_lint("YOUR WALLET IS SAFE!"));
        assert_eq!(find_overclaim("nothing to see here"), None);
    }

    #[test]
    fn authored_copy_and_both_render_modes_pass_the_lint() {
        // Every authored §16.4 warning string.
        for code in WarningCode::ALL {
            let t = warning_text(code);
            for s in [t.title, t.description, t.recommended_fix, t.action] {
                assert!(
                    passes_anti_overclaim_lint(s),
                    "{code:?} authors an overclaim: {s}"
                );
            }
        }
        // Every authored §16.3 critical next-step.
        for code in CriticalCode::ALL {
            let (action, _) = critical_step(code);
            assert!(
                passes_anti_overclaim_lint(action),
                "{code:?} authors an overclaim: {action}"
            );
        }
        // Full rendered reports in BOTH modes.
        for report in [ready_singlesig_report(), warn_multisig_report()] {
            for mode in [RedactionMode::PublicSafe, RedactionMode::Private] {
                let md = report.to_markdown_mode(mode);
                assert!(
                    passes_anti_overclaim_lint(&md),
                    "{mode:?} render overclaims: {:?}",
                    find_overclaim(&md)
                );
            }
        }
    }
}
