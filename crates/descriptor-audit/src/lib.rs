//! `descriptor-audit` — output-descriptor parsing, validation, and analysis.
//!
//! Parses singlesig, multisig, and Taproot descriptors, validates BIP380
//! checksums, normalizes to canonical form, and extracts key origins.
//!
//! This module is the single entry point for turning an untrusted descriptor
//! string into a typed [`ParsedDescriptor`]. It is built up story by story
//! (see `docs/PRD-v2.md`):
//! - US-003: singlesig parsing (`pkh`, `wpkh`, `sh(wpkh)`), rejection of
//!   unsupported functions, and a `sanity_check` pass.
//! - US-004: BIP380 checksum validation ([`validate_checksum`]) and computation
//!   ([`compute_checksum`]); parsing now records a [`ChecksumStatus`].
//! - US-005: canonical normalization ([`normalize`] /
//!   [`ParsedDescriptor::canonical`]) — hardened markers rendered as `h` with a
//!   fresh checksum, the user's raw input preserved alongside.
//! - US-006: multisig quorum extraction ([`ParsedDescriptor::multisig_info`]) —
//!   threshold *M*, key count *N*, and `multi` vs `sortedmulti` classification.
//! - US-007: multisig integrity — quorum bounds `1 <= M <= N <= 15`
//!   (`E-PARSE-007`), mixed-network rejection (`E-PARSE-004`), and a non-fatal
//!   duplicate-key fact ([`ParsedDescriptor::has_duplicate_keys`]).
//! - US-008: key-origin extraction ([`ParsedDescriptor::key_origins`]) — per-key
//!   master fingerprint, derivation path, and xpub, with standard-path
//!   classification ([`StandardPath`]) and a hardened-marker consistency check
//!   ([`ParsedDescriptor::hardened_marker_style`]).
//! - US-009: BIP389 multipath detection ([`ParsedDescriptor::uses_multipath`])
//!   and expansion into one descriptor per parallel path
//!   ([`ParsedDescriptor::expand_multipath`]).
//! - US-010: refusal of descriptors that carry extended private-key material
//!   ([`ErrorCode::ContainsPrivateKey`] / `E-PARSE-005`) and Taproot detection
//!   ([`ParsedDescriptor::is_taproot`]).
//! - US-011: network inference from extended-key version bytes
//!   ([`ParsedDescriptor::network_inference`]) and SLIP-132 → `xpub`/`tpub`
//!   normalization on import ([`normalize_slip132`]).
//! - US-073: full Taproot support for key-path `tr(KEY)` and simple script-path
//!   `tr(KEY,multi_a(M,...))` descriptors, including `multi_a` quorum extraction.
//! - US-074: full `wsh` Miniscript support for tested policy fragments
//!   (`or_d`, `and_v`, `older`, `after`) and Liana-style timelock descriptors,
//!   surfaced through [`ParsedDescriptor::uses_miniscript`] and
//!   [`ParsedDescriptor::uses_timelock`].
//!
//! # Invariants
//! - **No panics.** Parsing never panics on arbitrary input; every failure is a
//!   typed [`error_taxonomy::LifeboatError`] with a stable code (PRD Appendix C).
//! - **All Bitcoin logic stays in Rust.** Callers (CLI, desktop) hand raw text
//!   in and receive typed results; they never parse descriptors themselves.

use std::str::FromStr;

use error_taxonomy::{ErrorCode, LifeboatError};
use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use miniscript::bitcoin::{base58, Network, NetworkKind};
use miniscript::descriptor::{
    checksum, DescriptorPublicKey, DescriptorType, ShInner, SortedMultiVec, WshInner,
};
use miniscript::{Descriptor, ForEachKey, Miniscript, ScriptContext, Tap, Terminal};

/// Top-level descriptor functions Bitcoin Lifeboat refuses to parse (PRD §17.2).
///
/// rust-miniscript rejects these with a generic parse error; we intercept them
/// first so the user gets the specific `E-PARSE-006` (unsupported function)
/// code and a clear message instead.
const UNSUPPORTED_FUNCTIONS: &[&str] = &["combo", "addr", "raw"];

/// The largest key count `N` Bitcoin Lifeboat accepts in an `M-of-N` multisig
/// (PRD §9.1 check D5 / §16.3). A quorum must satisfy `1 <= M <= N <= 15`.
const MAX_MULTISIG_KEYS: usize = 15;

/// The textual prefixes of every extended *private* key Bitcoin Lifeboat refuses
/// (BIP32 `xprv`/`tprv` and the SLIP-132 variants), per PRD §13.5.3. A descriptor
/// carrying any of these contains secret material and is rejected with the
/// critical [`ErrorCode::ContainsPrivateKey`] (`E-PARSE-005` / §16.3
/// `C-DESC-CONTAINS-XPRV`) rather than processed.
const EXTENDED_PRIVATE_KEY_PREFIXES: &[&str] = &[
    // BIP32 mainnet/testnet + SLIP-132 single-sig (lowercase first letter).
    "xprv", "tprv", "yprv", "zprv", "uprv", "vprv",
    // SLIP-132 multisig (uppercase first letter).
    "Yprv", "Zprv", "Uprv", "Vprv",
];

/// The minimum run of key characters that must follow an extended private-key
/// prefix for it to be treated as a real key. A Base58 BIP32 extended key is 111
/// characters — a 4-character prefix and ~107 more — so requiring a long trailing
/// run avoids flagging an incidental occurrence of, say, `tprv` in garbage input
/// while still matching every real key comfortably.
const MIN_EXTENDED_KEY_TRAILING_LEN: usize = 100;

/// BIP32 extended-key payload length in bytes, as decoded from Base58Check:
/// version (4) + depth (1) + parent fingerprint (4) + child number (4) +
/// chain code (32) + key data (33).
const EXTENDED_KEY_LEN: usize = 78;

/// Standard BIP32 mainnet public version bytes (`xpub`).
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

/// Standard BIP32 testnet public version bytes (`tpub`).
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

/// SLIP-132 *public* extended-key prefixes and the standard version bytes each
/// normalizes to (PRD §17.4). The script type these encode is redundant with the
/// descriptor's own wrapper, so every mainnet variant becomes `xpub` and every
/// testnet variant becomes `tpub`. (The matching SLIP-132 *private* prefixes are
/// refused outright; see [`EXTENDED_PRIVATE_KEY_PREFIXES`].)
const SLIP132_PUBLIC_PREFIXES: &[(&str, [u8; 4])] = &[
    ("ypub", XPUB_VERSION),
    ("zpub", XPUB_VERSION),
    ("Ypub", XPUB_VERSION),
    ("Zpub", XPUB_VERSION),
    ("upub", TPUB_VERSION),
    ("vpub", TPUB_VERSION),
    ("Upub", TPUB_VERSION),
    ("Vpub", TPUB_VERSION),
];

/// Whether a descriptor carried a BIP380 `#checksum`.
///
/// An *invalid* checksum is never represented here: a checksum that does not
/// match its descriptor body is a critical, fatal error
/// ([`ErrorCode::ChecksumInvalid`] / `E-PARSE-003`), so it never yields a
/// [`ParsedDescriptor`]. Only the two non-fatal outcomes survive parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumStatus {
    /// A `#checksum` was present and matched the descriptor body.
    Present,
    /// No `#checksum` was present. Non-fatal on its own, but later scoring
    /// records the warning `W-NO-DESC-CHECKSUM` (`E-PARSE-002`, -5 points).
    Missing,
}

/// How a multisig descriptor combines its keys (PRD §17.2/§17.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigKind {
    /// `multi(M, …)` — key order is fixed and is part of the locking script.
    Multi,
    /// `sortedmulti(M, …)` — keys are sorted lexicographically (BIP67) when the
    /// script is built at each derivation index, so the order the keys appear in
    /// the descriptor text does not affect the resulting addresses.
    SortedMulti,
    /// `multi_a(M, …)` — Taproot/Tapscript CHECKSIGADD multisig. Key order is
    /// fixed in the script, like [`Multi`](MultisigKind::Multi).
    MultiA,
}

impl MultisigKind {
    /// True for `sortedmulti(…)`.
    #[must_use]
    pub fn is_sorted(self) -> bool {
        matches!(self, MultisigKind::SortedMulti)
    }

    /// The descriptor function name (`"multi"`, `"sortedmulti"`, or `"multi_a"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MultisigKind::Multi => "multi",
            MultisigKind::SortedMulti => "sortedmulti",
            MultisigKind::MultiA => "multi_a",
        }
    }
}

/// A standard account-level derivation scheme recognized in a key's origin path
/// (PRD §9.1 check C4 / §17.6 item 6).
///
/// Classification is purely structural: it reads the *purpose* (first path
/// component) and the path's shape. It does **not** check that the scheme agrees
/// with the descriptor's script type (e.g. that a `wpkh` key uses BIP84) — that
/// cross-check is the scoring layer's job (US-019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardPath {
    /// `m/44h/coinh/accounth` — legacy P2PKH (BIP44).
    Bip44,
    /// `m/49h/coinh/accounth` — P2SH-nested P2WPKH (BIP49).
    Bip49,
    /// `m/84h/coinh/accounth` — native segwit P2WPKH (BIP84).
    Bip84,
    /// `m/86h/coinh/accounth` — single-key Taproot P2TR (BIP86).
    Bip86,
    /// `m/48h/coinh/accounth/script_typeh` — multisig (BIP48).
    Bip48,
}

impl StandardPath {
    /// The scheme's conventional public name (`"BIP44"`, `"BIP48"`, …).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StandardPath::Bip44 => "BIP44",
            StandardPath::Bip49 => "BIP49",
            StandardPath::Bip84 => "BIP84",
            StandardPath::Bip86 => "BIP86",
            StandardPath::Bip48 => "BIP48",
        }
    }

    /// Whether this scheme is the multisig scheme (BIP48). All others are
    /// single-key account schemes.
    #[must_use]
    pub fn is_multisig_scheme(self) -> bool {
        matches!(self, StandardPath::Bip48)
    }
}

impl std::fmt::Display for StandardPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a descriptor spells its hardened-derivation markers (PRD §9.1 check C3).
///
/// BIP380 lets a hardened child be written either `h` or `'`; the two are
/// semantically identical (the canonical form always uses `h`, see [`normalize`]).
/// A descriptor that mixes both styles ([`Mixed`](HardenedMarkerStyle::Mixed)) is
/// a transcription smell worth surfacing, even though it parses fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardenedMarkerStyle {
    /// The descriptor has no hardened components at all (no markers to compare).
    None,
    /// Every hardened marker is written `'` (e.g. `48'/1'/0'/2'`).
    Apostrophe,
    /// Every hardened marker is written `h` (e.g. `48h/1h/0h/2h`).
    H,
    /// The descriptor mixes `'` and `h` markers — inconsistent (check C3 warns).
    Mixed,
}

impl HardenedMarkerStyle {
    /// Whether the markers are used consistently — i.e. anything but
    /// [`Mixed`](HardenedMarkerStyle::Mixed). A descriptor with no hardened
    /// components is trivially consistent.
    #[must_use]
    pub fn is_consistent(self) -> bool {
        !matches!(self, HardenedMarkerStyle::Mixed)
    }
}

/// The Bitcoin network inferred from a descriptor's extended-key version bytes
/// (PRD §17.4 / §9.1 check F).
///
/// Only the mainnet `xpub` version bytes uniquely identify a network. Testnet,
/// signet, and regtest all share the `tpub` version bytes, so a test-network
/// descriptor is *ambiguous*: Lifeboat reports the family but never guesses which
/// of the three it is — the user must confirm (PRD §16.5 condition 1). A
/// descriptor built only from raw public keys has no version bytes to infer from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkInference {
    /// The version bytes uniquely identify the network. In practice this is only
    /// ever [`Network::Bitcoin`] (mainnet `xpub`).
    Determined(Network),
    /// Test-family version bytes (`tpub`): the network is testnet, signet, *or*
    /// regtest and cannot be told apart from the descriptor; the caller must ask
    /// the user which one (PRD §9.1 F2).
    AmbiguousTestNetwork,
    /// The descriptor has no extended keys (raw public keys only), so there are no
    /// version bytes to infer a network from.
    NoExtendedKeys,
}

impl NetworkInference {
    /// The uniquely inferred network, or `None` when it is ambiguous or there are
    /// no extended keys. A `None` is exactly the signal that the caller must
    /// resolve the network with the user before trusting a derived address
    /// (PRD §16.5).
    #[must_use]
    pub fn network(&self) -> Option<Network> {
        match self {
            NetworkInference::Determined(network) => Some(*network),
            NetworkInference::AmbiguousTestNetwork | NetworkInference::NoExtendedKeys => None,
        }
    }

    /// Whether the network was uniquely determined from the version bytes. When
    /// `false`, the descriptor's network is ambiguous (or absent) and the user
    /// must declare it (PRD §9.1 F2 / §17.4).
    #[must_use]
    pub fn is_determinable(&self) -> bool {
        matches!(self, NetworkInference::Determined(_))
    }

    /// The candidate networks consistent with the version bytes: one network when
    /// determinable, the three test networks when ambiguous, and none when the
    /// descriptor has no extended keys.
    #[must_use]
    pub fn candidates(&self) -> Vec<Network> {
        match self {
            NetworkInference::Determined(network) => vec![*network],
            NetworkInference::AmbiguousTestNetwork => {
                vec![Network::Testnet, Network::Signet, Network::Regtest]
            }
            NetworkInference::NoExtendedKeys => Vec::new(),
        }
    }
}

/// The outcome of normalizing SLIP-132 extended public keys in a descriptor to
/// the standard `xpub`/`tpub` form (PRD §17.4), returned by [`normalize_slip132`].
#[derive(Debug, Clone)]
pub struct Slip132Normalization {
    descriptor: String,
    normalized_keys: usize,
}

impl Slip132Normalization {
    /// The normalized descriptor. When [`changed`](Self::changed) is `true` it
    /// carries a freshly computed BIP380 `#checksum` (rewriting a key body
    /// invalidates any original one); when `false` it is the trimmed input
    /// verbatim.
    #[must_use]
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    /// Whether any SLIP-132 key was rewritten.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.normalized_keys > 0
    }

    /// How many SLIP-132 keys were normalized to standard form.
    #[must_use]
    pub fn normalized_keys(&self) -> usize {
        self.normalized_keys
    }
}

/// The provenance of one descriptor key: its master fingerprint, the origin
/// derivation path (master → account xpub), the extended key itself, and whether
/// the origin path matches a [`StandardPath`] scheme (PRD §17.6 item 3, §19.1
/// `keys[]`).
///
/// Produced in descriptor key order by [`ParsedDescriptor::key_origins`]. A key
/// written without a `[fingerprint/path]` origin annotation yields `None` for the
/// fingerprint and path; [`key_origin_present`](KeyOrigin::key_origin_present)
/// reports whether a *complete* origin (fingerprint **and** non-empty path) was
/// found.
#[derive(Debug, Clone)]
pub struct KeyOrigin {
    index: usize,
    fingerprint: Option<Fingerprint>,
    derivation_path: Option<DerivationPath>,
    xpub: Option<String>,
    standard_path: Option<StandardPath>,
}

impl KeyOrigin {
    /// The key's position in the descriptor, counting from 0 in the order the
    /// keys appear in the text.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// The master key fingerprint from the `[fingerprint/…]` origin, or `None`
    /// when the key carries no origin annotation (PRD §9.1 check C1).
    #[must_use]
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint
    }

    /// The master key fingerprint as 8 lowercase hex characters (e.g.
    /// `"4ba43603"`), or `None` when absent. This is the `keys[].fingerprint`
    /// form in the §19.1 report.
    #[must_use]
    pub fn fingerprint_hex(&self) -> Option<String> {
        self.fingerprint.map(|fp| fp.to_string())
    }

    /// The origin derivation path (master → account xpub), e.g. `48'/1'/0'/2'`.
    /// `None` when the key has no origin; may be present-but-empty for a
    /// fingerprint-only origin like `[abc12345]`.
    #[must_use]
    pub fn derivation_path(&self) -> Option<&DerivationPath> {
        self.derivation_path.as_ref()
    }

    /// The origin derivation path in the §19.1 display form `m/48h/0h/0h/2h`
    /// (leading `m/`, hardened markers as `h`), or `None` when the key has no
    /// origin. A fingerprint-only origin renders as `"m"`.
    #[must_use]
    pub fn derivation_path_display(&self) -> Option<String> {
        self.derivation_path.as_ref().map(format_origin_path)
    }

    /// The extended public key as a string (`xpub…`/`tpub…`), or `None` for a raw
    /// single public key, which has no extended-key form. This is the
    /// `keys[].xpub` field in the §19.1 report (redaction is the report layer's
    /// job, US-030).
    #[must_use]
    pub fn xpub(&self) -> Option<&str> {
        self.xpub.as_deref()
    }

    /// Whether a master fingerprint is present (PRD §9.1 check C1).
    #[must_use]
    pub fn has_fingerprint(&self) -> bool {
        self.fingerprint.is_some()
    }

    /// Whether a non-empty origin derivation path is present (PRD §9.1 check C2).
    /// A fingerprint-only origin (`[abc12345]`) counts as *no* path.
    #[must_use]
    pub fn has_derivation_path(&self) -> bool {
        self.derivation_path
            .as_ref()
            .is_some_and(|path| !path.is_empty())
    }

    /// Whether a *complete* key origin (fingerprint **and** a non-empty
    /// derivation path) was found — the `keys[].key_origin_present` summary in
    /// the §19.1 report.
    #[must_use]
    pub fn key_origin_present(&self) -> bool {
        self.has_fingerprint() && self.has_derivation_path()
    }

    /// The standard derivation scheme the origin path matches, or `None` for a
    /// non-standard or absent path (PRD §9.1 check C4).
    #[must_use]
    pub fn standard_path(&self) -> Option<StandardPath> {
        self.standard_path
    }

    /// Whether the origin path matches a recognized [`StandardPath`] scheme.
    #[must_use]
    pub fn is_standard_path(&self) -> bool {
        self.standard_path.is_some()
    }
}

/// The threshold/quorum of a multisig descriptor (PRD §17.6, item 1–2).
///
/// Produced by [`ParsedDescriptor::multisig_info`] for every descriptor whose
/// script is a single *M-of-N* `multi`/`sortedmulti`, in any of its supported
/// wrappers (`wsh`, `sh`, `sh(wsh(…))`, or bare `multi`). Returns the threshold
/// *M*, the key count *N*, the [`MultisigKind`], and the keys in descriptor
/// order — the foundation later stories build on (duplicate-xpub and threshold
/// checks in US-007, key-origin extraction in US-008).
///
/// A more complex Miniscript policy inside `wsh`/`sh` (timelocks, `or`/`and`,
/// Liana-style recovery paths) is *not* a plain multisig and yields `None` here;
/// those are analyzed by the Miniscript-policy stories (US-087+).
#[derive(Debug, Clone)]
pub struct MultisigInfo {
    threshold: usize,
    kind: MultisigKind,
    keys: Vec<DescriptorPublicKey>,
}

impl MultisigInfo {
    /// The threshold *M*: how many signatures are required.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The key count *N*: how many keys are in the quorum.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Whether the quorum is `multi` (ordered) or `sortedmulti` (BIP67-sorted).
    #[must_use]
    pub fn kind(&self) -> MultisigKind {
        self.kind
    }

    /// True for `sortedmulti(…)`; shorthand for `self.kind().is_sorted()`.
    #[must_use]
    pub fn is_sorted_multi(&self) -> bool {
        self.kind.is_sorted()
    }

    /// The quorum's keys, in the order they appear in the descriptor text.
    #[must_use]
    pub fn keys(&self) -> &[DescriptorPublicKey] {
        &self.keys
    }

    /// Whether the keys, as written in the descriptor, are already in ascending
    /// lexicographic order by their key body (the xpub/derivation expression,
    /// with any `[origin]` prefix ignored).
    ///
    /// This is a *descriptor-text* check, not a per-address one: for
    /// [`MultisigKind::SortedMulti`] the funds-affecting BIP67 sort is applied to
    /// the *derived* public keys at each index, so the order keys appear in the
    /// text has no effect on the addresses — this merely reports whether the
    /// written keys are already tidy (as most wallet exports emit them). For
    /// [`MultisigKind::Multi`] key order *is* significant, so a `false` here is
    /// meaningful structure rather than cosmetics.
    #[must_use]
    pub fn keys_lexicographically_sorted(&self) -> bool {
        self.keys
            .windows(2)
            .all(|pair| key_body(&pair[0]) <= key_body(&pair[1]))
    }

    /// Whether two or more positions in the quorum use the same extended public
    /// key — an *illusory quorum* (PRD §16.3 `C-DUPLICATE-XPUB`): a "2-of-3" that
    /// reuses one cosigner's xpub is really a weaker policy than it looks.
    ///
    /// Keys are compared by xpub identity, ignoring the `[origin]` prefix and the
    /// derivation path, so the same xpub under two different paths still counts.
    /// This crate only reports the fact; the scoring layer (US-020) turns it into
    /// the critical condition that forces a "Not Ready" verdict.
    #[must_use]
    pub fn has_duplicate_keys(&self) -> bool {
        keys_have_duplicate(&self.keys)
    }
}

/// A successfully parsed output descriptor.
///
/// Holds the user's original input verbatim alongside the typed rust-miniscript
/// representation and a [canonical] string form, so later analysis can show the
/// user their own text while operating on the canonical parse (PRD §17.2/§17.3).
///
/// [canonical]: ParsedDescriptor::canonical
#[derive(Debug, Clone)]
pub struct ParsedDescriptor {
    raw: String,
    descriptor: Descriptor<DescriptorPublicKey>,
    checksum_status: ChecksumStatus,
    canonical: String,
    has_duplicate_keys: bool,
}

impl ParsedDescriptor {
    /// The user's original input, preserved verbatim for display (PRD §17.3).
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The parsed rust-miniscript descriptor.
    ///
    /// Exposed so sibling core crates (e.g. `address-derive`) can operate on the
    /// canonical parse. Frontends never see this type.
    #[must_use]
    pub fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }

    /// The structural classification (`pkh`, `wpkh`, `sh(wpkh)`, `wsh`, …) as
    /// reported by rust-miniscript.
    #[must_use]
    pub fn descriptor_type(&self) -> DescriptorType {
        self.descriptor.desc_type()
    }

    /// True for single-key descriptors: `pkh(KEY)`, `wpkh(KEY)`, `sh(wpkh(KEY))`.
    #[must_use]
    pub fn is_singlesig(&self) -> bool {
        matches!(
            self.descriptor_type(),
            DescriptorType::Pkh | DescriptorType::Wpkh | DescriptorType::ShWpkh
        )
    }

    /// The *M-of-N* quorum if this descriptor's script is a plain `multi` or
    /// `sortedmulti` (PRD §17.6), in any supported wrapper; `None` otherwise
    /// (singlesig, Taproot, or a richer Miniscript policy). See [`MultisigInfo`].
    #[must_use]
    pub fn multisig_info(&self) -> Option<MultisigInfo> {
        extract_multisig(&self.descriptor)
    }

    /// True when this descriptor is a plain multisig (see [`multisig_info`]).
    ///
    /// [`multisig_info`]: ParsedDescriptor::multisig_info
    #[must_use]
    pub fn is_multisig(&self) -> bool {
        self.multisig_info().is_some()
    }

    /// Whether this is a Taproot descriptor: key-path `tr(KEY)` or script-path
    /// `tr(KEY, {…})`, including `tr(KEY,multi_a(…))` (PRD §17.2).
    ///
    /// Taproot is first-class as of US-073. Key-path descriptors return no
    /// [`multisig_info`](Self::multisig_info), while a simple script-path
    /// `multi_a(M, …)` leaf exposes its quorum as [`MultisigKind::MultiA`].
    #[must_use]
    pub fn is_taproot(&self) -> bool {
        matches!(self.descriptor_type(), DescriptorType::Tr)
    }

    /// Whether this descriptor carries a richer Miniscript policy rather than a
    /// simple singlesig or plain `multi`/`sortedmulti` quorum.
    ///
    /// US-074 promotes tested `wsh` Miniscript fragments (`or_d`, `and_v`,
    /// `older`, `after`) from preview to first-class support. This fact is used
    /// by the report layer for `wallet_summary.uses_miniscript`; it does not
    /// imply a warning or score deduction.
    #[must_use]
    pub fn uses_miniscript(&self) -> bool {
        descriptor_uses_miniscript(&self.descriptor)
    }

    /// Whether this descriptor contains an absolute or relative timelock
    /// (`after(n)` or `older(n)`).
    ///
    /// Liana-style descriptors such as
    /// `wsh(or_d(pk(K),and_v(v:pkh(R),older(N))))` return `true` here while still
    /// returning `None` from [`multisig_info`](Self::multisig_info), because they
    /// are a recovery policy rather than one plain M-of-N quorum.
    #[must_use]
    pub fn uses_timelock(&self) -> bool {
        descriptor_uses_timelock(&self.descriptor)
    }

    /// Whether the descriptor uses a BIP389 multipath key expression (e.g.
    /// `<0;1>`), as emitted by Sparrow, Liana, and others to fold the receive and
    /// change descriptors into one string (PRD §17.2, §17.3 step 4). When true,
    /// [`expand_multipath`](Self::expand_multipath) splits it into one descriptor
    /// per parallel derivation path. Surfaced as `wallet_summary.uses_multipath`
    /// in the §19.1 report.
    #[must_use]
    pub fn uses_multipath(&self) -> bool {
        self.descriptor.is_multipath()
    }

    /// Expand a BIP389 multipath descriptor into its parallel single-path
    /// descriptors for analysis (PRD §17.3 step 4), leaving the multipath form on
    /// `self` untouched for display.
    ///
    /// The result is ordered by multipath index, matching the order the indices
    /// were written: for the conventional receive/change form `<0;1>` it is
    /// `[receive (…/0/*), change (…/1/*)]`. It is **never empty** — a descriptor
    /// with no multipath expression ([`uses_multipath`](Self::uses_multipath) is
    /// `false`) yields a single element equal to the original descriptor — so a
    /// caller reads the receive branch as the first element and the change branch,
    /// if any, as the second.
    ///
    /// Expansion does not alter [`canonical`](Self::canonical) or
    /// [`raw`](Self::raw): both preserve the multipath form intact, and only the
    /// returned analysis copies are split.
    ///
    /// # Errors
    /// [`ErrorCode::ParseFailed`] (`E-PARSE-001`) if rust-miniscript cannot split
    /// the paths. This cannot arise for a [`ParsedDescriptor`] in practice —
    /// `from_str` already rejects a descriptor whose keys disagree on the number
    /// of multipath indices — but the fallible signature keeps expansion from
    /// ever panicking.
    pub fn expand_multipath(&self) -> Result<Vec<Descriptor<DescriptorPublicKey>>, LifeboatError> {
        self.descriptor
            .clone()
            .into_single_descriptors()
            .map_err(|e| {
                LifeboatError::new(ErrorCode::ParseFailed)
                    .with_context("could not expand multipath descriptor into single paths")
                    .with_source(e)
            })
    }

    /// Whether the descriptor reuses the same extended public key across more
    /// than one position (PRD §16.3 `C-DUPLICATE-XPUB`).
    ///
    /// This is recorded as a non-fatal fact, not a parse error: a duplicate-key
    /// descriptor still parses and derives addresses, so analysis continues and
    /// the scoring layer (US-020) raises the critical condition. (rust-miniscript
    /// *does* reject exact repeats in `sanity_check`; [`parse_descriptor`]
    /// tolerates that specific failure precisely so this fact can be surfaced.)
    /// See [`MultisigInfo::has_duplicate_keys`] for the multisig-scoped view.
    #[must_use]
    pub fn has_duplicate_keys(&self) -> bool {
        self.has_duplicate_keys
    }

    /// Whether the descriptor carried a valid BIP380 `#checksum`
    /// ([`ChecksumStatus::Present`]) or none at all ([`ChecksumStatus::Missing`]).
    ///
    /// An invalid checksum never reaches this point — it is rejected during
    /// parsing as the critical `E-PARSE-003`.
    #[must_use]
    pub fn checksum_status(&self) -> ChecksumStatus {
        self.checksum_status
    }

    /// The canonical, normalized form of the descriptor (PRD §17.3; surfaced as
    /// `descriptors.*.canonical` in the §19.1 report).
    ///
    /// This is rust-miniscript's `Descriptor::to_string()` with every hardened
    /// marker rendered as `h` (rather than the equivalent `'`) and a freshly
    /// computed BIP380 `#checksum`. Unlike [`raw`], which echoes the user's exact
    /// input, the canonical form is deterministic: inputs that differ only in
    /// hardened-marker style (`'` vs `h`) or checksum normalize to the same
    /// string. See the free [`normalize`] function for the standalone operation.
    ///
    /// [`raw`]: ParsedDescriptor::raw
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The provenance of every key in the descriptor, in descriptor key order
    /// (PRD §17.6 item 3, §19.1 `keys[]`).
    ///
    /// Each [`KeyOrigin`] carries the master fingerprint, origin derivation path,
    /// extended key, and standard-scheme classification, plus flags for missing
    /// fingerprint or path. A singlesig descriptor yields one entry; a multisig
    /// yields one per cosigner key (a reused xpub appears at each position it
    /// occupies).
    #[must_use]
    pub fn key_origins(&self) -> Vec<KeyOrigin> {
        collect_keys(&self.descriptor)
            .iter()
            .enumerate()
            .map(|(index, key)| key_origin(index, key))
            .collect()
    }

    /// How the descriptor spells its hardened-derivation markers (PRD §9.1 check
    /// C3): all `'`, all `h`, mixed, or none present. Computed from the user's
    /// [`raw`](ParsedDescriptor::raw) input — the canonical form always uses `h`.
    #[must_use]
    pub fn hardened_marker_style(&self) -> HardenedMarkerStyle {
        let total = total_hardened(&self.descriptor);
        if total == 0 {
            return HardenedMarkerStyle::None;
        }
        // Every `'` in a valid descriptor is a hardened marker (the character
        // appears nowhere else — keys are hex/base58/bech32 and the checksum
        // charset excludes it), so the apostrophe count is exactly the number of
        // `'`-style markers. The rest of the `total` hardened components must
        // therefore be written `h`.
        let apostrophes = self.raw.matches('\'').count();
        if apostrophes == total {
            HardenedMarkerStyle::Apostrophe
        } else if apostrophes == 0 {
            HardenedMarkerStyle::H
        } else {
            HardenedMarkerStyle::Mixed
        }
    }

    /// Whether hardened markers are spelled consistently (PRD §9.1 check C3);
    /// shorthand for [`hardened_marker_style().is_consistent()`](HardenedMarkerStyle::is_consistent).
    #[must_use]
    pub fn hardened_markers_consistent(&self) -> bool {
        self.hardened_marker_style().is_consistent()
    }

    /// The Bitcoin network inferred from this descriptor's extended-key version
    /// bytes (PRD §17.4 / §9.1 check F). See [`NetworkInference`]: only mainnet is
    /// uniquely determinable; a `tpub` descriptor is an ambiguous test network the
    /// user must resolve, and a raw-pubkey descriptor has no version bytes at all.
    ///
    /// The descriptor is guaranteed to commit to a single network —
    /// [`parse_descriptor`] rejects mixed-network descriptors with `E-PARSE-004` —
    /// so this reads the network off the first extended key.
    #[must_use]
    pub fn network_inference(&self) -> NetworkInference {
        infer_network(&self.descriptor)
    }

    /// The uniquely inferred network, or `None` when it is ambiguous or absent;
    /// shorthand for [`network_inference().network()`](NetworkInference::network).
    #[must_use]
    pub fn network(&self) -> Option<Network> {
        self.network_inference().network()
    }
}

/// Parse an output-descriptor string into a typed [`ParsedDescriptor`].
///
/// Accepts the BIP380 expressions listed in PRD §17.2 (singlesig, multisig,
/// Taproot, and tested `wsh` Miniscript), as understood by
/// `Descriptor::<DescriptorPublicKey>::from_str`. A present `#checksum` is
/// validated up front (see [`validate_checksum`]); a missing one is recorded as
/// [`ChecksumStatus::Missing`] rather than rejected.
///
/// # Errors
/// - [`ErrorCode::InputEmpty`] (`E-INPUT-001`) — the input is blank.
/// - [`ErrorCode::ContainsPrivateKey`] (`E-PARSE-005`) — the descriptor carries
///   extended private-key material (`xprv`/`tprv`/…); Lifeboat refuses to process
///   secret material (PRD §16.3 `C-DESC-CONTAINS-XPRV`).
/// - [`ErrorCode::UnsupportedFunction`] (`E-PARSE-006`) — the descriptor uses a
///   top-level function Lifeboat does not support (`combo`, `addr`, `raw`).
/// - [`ErrorCode::ChecksumInvalid`] (`E-PARSE-003`) — a `#checksum` is present
///   but does not match the descriptor body (likely a transcription error).
/// - [`ErrorCode::ThresholdExceedsKeys`] (`E-PARSE-007`) — a multisig quorum
///   violates `1 <= M <= N <= 15` (PRD §16.3 `C-KEY-COUNT-BELOW-THRESHOLD`).
/// - [`ErrorCode::NetworkMixed`] (`E-PARSE-004`) — the keys span more than one
///   Bitcoin network, so no chain can be chosen for derivation (PRD §17.4).
/// - [`ErrorCode::ParseFailed`] (`E-PARSE-001`) — the text is not a valid BIP380
///   descriptor, or it fails rust-miniscript's `sanity_check` for a reason other
///   than duplicate keys (which are tolerated; see [`Self::has_duplicate_keys`]).
pub fn parse_descriptor(input: &str) -> Result<ParsedDescriptor, LifeboatError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }

    // Refuse any descriptor that carries private-key material *first*: it is the
    // most security-critical problem, and rust-miniscript would otherwise reject
    // an xprv with a generic, misleading parse error (so the specific, actionable
    // `E-PARSE-005` would never reach the user).
    reject_private_keys(trimmed)?;

    reject_unsupported_function(trimmed)?;

    // Validate any present checksum *before* the generic parse, so a transcription
    // error surfaces as the specific, critical `E-PARSE-003` instead of a vague
    // `E-PARSE-001`. A missing checksum is recorded, not rejected.
    let checksum_status = validate_checksum(trimmed)?;

    // Validate the multisig quorum bounds before the generic parse: rust-miniscript
    // rejects `M > N` / `M = 0` with a generic error (which would surface as the
    // vague `E-PARSE-001`) and silently *accepts* `N > 15`, so checking the raw
    // text is the only way every bound violation maps to the specific `E-PARSE-007`.
    check_quorum_bounds(trimmed)?;

    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(trimmed)
        .map_err(|e| LifeboatError::new(ErrorCode::ParseFailed).with_source(e))?;

    // A descriptor whose keys span multiple networks cannot derive addresses
    // (which chain?) and is almost always a transcription mistake (PRD §17.4).
    check_single_network(&descriptor)?;

    // A duplicate key makes the quorum illusory (PRD §16.3 `C-DUPLICATE-XPUB`).
    // It is recorded as a non-fatal fact for the scoring layer rather than
    // rejected here — but rust-miniscript's `sanity_check` *does* reject exact
    // repeats, so we tolerate that one failure when (and only when) we have
    // detected duplicates ourselves; any other sanity failure stays fatal.
    let has_duplicate_keys = descriptor_has_duplicate_keys(&descriptor);
    if let Err(e) = descriptor.sanity_check() {
        if !has_duplicate_keys {
            return Err(LifeboatError::new(ErrorCode::ParseFailed)
                .with_context("descriptor failed rust-miniscript sanity check")
                .with_source(e));
        }
    }

    let canonical = canonicalize(&descriptor)?;

    Ok(ParsedDescriptor {
        raw: input.to_string(),
        descriptor,
        checksum_status,
        canonical,
        has_duplicate_keys,
    })
}

/// Normalize a descriptor string to its canonical form (PRD §17.3).
///
/// Equivalent to `parse_descriptor(input)?.canonical().to_owned()`: the input is
/// fully parsed and validated, then re-rendered as rust-miniscript's
/// `Descriptor::to_string()` with hardened markers as `h` and a fresh BIP380
/// checksum. The result is deterministic and idempotent — two descriptors that
/// differ only in hardened-marker style (`'` vs `h`) normalize to the same
/// string, and `normalize(normalize(x)) == normalize(x)`.
///
/// # Errors
/// Any error from [`parse_descriptor`]: the input must be a non-empty, supported
/// descriptor whose `#checksum`, if present, is valid.
pub fn normalize(input: &str) -> Result<String, LifeboatError> {
    Ok(parse_descriptor(input)?.canonical().to_owned())
}

/// Render a parsed descriptor in canonical form (PRD §17.3, steps 1–3).
///
/// rust-miniscript's `Descriptor::to_string()` yields a valid descriptor with a
/// `#checksum`, using `'` for hardened-derivation markers. In a descriptor, `'`
/// only ever appears as a hardened marker (keys are hex/base58/bech32 and the
/// BIP380 checksum charset excludes `'`), so replacing every `'` with `h`
/// rewrites exactly those markers and nothing else. That edit invalidates the
/// trailing checksum, so [`compute_checksum`] strips and recomputes it over the
/// normalized body. The canonical form *preserves* any BIP389 multipath
/// expression (`<0;1>`) intact for display; splitting it into per-path
/// descriptors for analysis is the separate
/// [`ParsedDescriptor::expand_multipath`] step (§17.3 step 4). (`sortedmulti`
/// key ordering — §17.3 step 5 — is left as written; see
/// [`MultisigInfo::keys_lexicographically_sorted`].)
fn canonicalize(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<String, LifeboatError> {
    let with_h_markers = descriptor.to_string().replace('\'', "h");
    compute_checksum(&with_h_markers)
}

/// Extract the *M-of-N* quorum from a descriptor whose script is a plain
/// `multi`/`sortedmulti`/Taproot `multi_a` (PRD §17.6 / US-073). Returns `None`
/// for singlesig, Taproot key-path, and richer Miniscript policies. Backs
/// [`ParsedDescriptor::multisig_info`].
///
/// The two spellings are represented differently by rust-miniscript:
/// `sortedmulti` is a dedicated [`SortedMultiVec`] inner type, while `multi` is a
/// [`Miniscript`] whose root [`Terminal`] is [`Terminal::Multi`]. We walk the
/// wrappers (`wsh`, `sh`, `sh(wsh(…))`, bare) and handle each at the leaf.
fn extract_multisig(descriptor: &Descriptor<DescriptorPublicKey>) -> Option<MultisigInfo> {
    match descriptor {
        Descriptor::Wsh(wsh) => wsh_multisig(wsh.as_inner()),
        Descriptor::Sh(sh) => sh_multisig(sh.as_inner()),
        // Top-level `multi(M, …)` parses as a bare descriptor (a Miniscript).
        // (Bare `sortedmulti(…)` is not a valid descriptor — it only exists
        // inside `sh`/`wsh`.)
        Descriptor::Bare(bare) => ms_root_multisig(bare.as_inner()),
        Descriptor::Tr(tr) => tr_multisig(tr),
        // Pkh / Wpkh are singlesig.
        _ => None,
    }
}

/// Quorum inside a `wsh(…)`: either a `sortedmulti` leaf or a Miniscript body.
fn wsh_multisig(inner: &WshInner<DescriptorPublicKey>) -> Option<MultisigInfo> {
    match inner {
        WshInner::SortedMulti(smv) => Some(from_sorted_multi(smv)),
        WshInner::Ms(ms) => ms_root_multisig(ms),
    }
}

/// Quorum inside an `sh(…)`: a `sortedmulti` leaf, a nested `wsh`, or a
/// Miniscript body. (`sh(wpkh(…))` is singlesig and yields `None`.)
fn sh_multisig(inner: &ShInner<DescriptorPublicKey>) -> Option<MultisigInfo> {
    match inner {
        ShInner::SortedMulti(smv) => Some(from_sorted_multi(smv)),
        ShInner::Wsh(wsh) => wsh_multisig(wsh.as_inner()),
        ShInner::Ms(ms) => ms_root_multisig(ms),
        ShInner::Wpkh(_) => None,
    }
}

/// Build [`MultisigInfo`] from a `sortedmulti` leaf (works for both the segwit
/// and legacy script contexts).
fn from_sorted_multi<Ctx: ScriptContext>(
    smv: &SortedMultiVec<DescriptorPublicKey, Ctx>,
) -> MultisigInfo {
    MultisigInfo {
        threshold: smv.k(),
        kind: MultisigKind::SortedMulti,
        keys: smv.pks().to_vec(),
    }
}

/// Build [`MultisigInfo`] when a Miniscript body is itself a single `multi(M, …)`
/// fragment; `None` for any richer policy (the case later stories handle).
fn ms_root_multisig<Ctx: ScriptContext>(
    ms: &Miniscript<DescriptorPublicKey, Ctx>,
) -> Option<MultisigInfo> {
    match ms.as_inner() {
        Terminal::Multi(threshold) => Some(MultisigInfo {
            threshold: threshold.k(),
            kind: MultisigKind::Multi,
            keys: threshold.data().to_vec(),
        }),
        _ => None,
    }
}

/// Extract a Taproot `multi_a(M, …)` quorum when the script tree is a single
/// `multi_a` leaf. Richer Taproot trees are valid and derivable, but they do not
/// describe one plain M-of-N quorum, so they return `None`.
fn tr_multisig(tr: &miniscript::descriptor::Tr<DescriptorPublicKey>) -> Option<MultisigInfo> {
    let mut leaves = tr.leaves();
    let leaf = leaves.next()?;
    if leaves.next().is_some() {
        return None;
    }
    ms_root_multi_a(leaf.miniscript())
}

/// Build [`MultisigInfo`] when a Taproot Miniscript leaf is exactly
/// `multi_a(M, …)`.
fn ms_root_multi_a(ms: &Miniscript<DescriptorPublicKey, Tap>) -> Option<MultisigInfo> {
    match ms.as_inner() {
        Terminal::MultiA(threshold) => Some(MultisigInfo {
            threshold: threshold.k(),
            kind: MultisigKind::MultiA,
            keys: threshold.data().to_vec(),
        }),
        _ => None,
    }
}

/// Whether the descriptor contains a richer Miniscript policy. Plain
/// `multi(...)`/`sortedmulti(...)` descriptors are already modeled as multisig and
/// are not counted as `uses_miniscript` for report-summary purposes.
fn descriptor_uses_miniscript(descriptor: &Descriptor<DescriptorPublicKey>) -> bool {
    match descriptor {
        Descriptor::Wsh(wsh) => wsh_uses_miniscript(wsh.as_inner()),
        Descriptor::Sh(sh) => sh_uses_miniscript(sh.as_inner()),
        // Bare `multi(...)` is plain multisig; any other bare Miniscript is a
        // policy, though it is outside the supported recovery-wallet shapes.
        Descriptor::Bare(bare) => !matches!(bare.as_inner().as_inner(), Terminal::Multi(_)),
        // Taproot support has its own report fact. A simple `multi_a` leaf is not
        // counted as legacy `wsh` Miniscript here.
        _ => false,
    }
}

fn wsh_uses_miniscript(inner: &WshInner<DescriptorPublicKey>) -> bool {
    match inner {
        WshInner::SortedMulti(_) => false,
        WshInner::Ms(ms) => !matches!(ms.as_inner(), Terminal::Multi(_)),
    }
}

fn sh_uses_miniscript(inner: &ShInner<DescriptorPublicKey>) -> bool {
    match inner {
        ShInner::Wsh(wsh) => wsh_uses_miniscript(wsh.as_inner()),
        ShInner::Ms(ms) => !matches!(ms.as_inner(), Terminal::Multi(_)),
        ShInner::SortedMulti(_) | ShInner::Wpkh(_) => false,
    }
}

/// Whether the descriptor contains `after(n)` or `older(n)`.
fn descriptor_uses_timelock(descriptor: &Descriptor<DescriptorPublicKey>) -> bool {
    match descriptor {
        Descriptor::Wsh(wsh) => wsh_uses_timelock(wsh.as_inner()),
        Descriptor::Sh(sh) => sh_uses_timelock(sh.as_inner()),
        Descriptor::Bare(bare) => ms_uses_timelock(bare.as_inner()),
        Descriptor::Tr(tr) => tr.leaves().any(|leaf| ms_uses_timelock(leaf.miniscript())),
        _ => false,
    }
}

fn wsh_uses_timelock(inner: &WshInner<DescriptorPublicKey>) -> bool {
    match inner {
        WshInner::SortedMulti(_) => false,
        WshInner::Ms(ms) => ms_uses_timelock(ms),
    }
}

fn sh_uses_timelock(inner: &ShInner<DescriptorPublicKey>) -> bool {
    match inner {
        ShInner::Wsh(wsh) => wsh_uses_timelock(wsh.as_inner()),
        ShInner::Ms(ms) => ms_uses_timelock(ms),
        ShInner::SortedMulti(_) | ShInner::Wpkh(_) => false,
    }
}

fn ms_uses_timelock<Ctx: ScriptContext>(ms: &Miniscript<DescriptorPublicKey, Ctx>) -> bool {
    terminal_uses_timelock(ms.as_inner())
}

fn terminal_uses_timelock<Ctx: ScriptContext>(
    terminal: &Terminal<DescriptorPublicKey, Ctx>,
) -> bool {
    match terminal {
        Terminal::After(_) | Terminal::Older(_) => true,
        Terminal::Alt(sub)
        | Terminal::Swap(sub)
        | Terminal::Check(sub)
        | Terminal::DupIf(sub)
        | Terminal::Verify(sub)
        | Terminal::NonZero(sub)
        | Terminal::ZeroNotEqual(sub) => ms_uses_timelock(sub),
        Terminal::AndV(left, right)
        | Terminal::AndB(left, right)
        | Terminal::OrB(left, right)
        | Terminal::OrD(left, right)
        | Terminal::OrC(left, right)
        | Terminal::OrI(left, right) => ms_uses_timelock(left) || ms_uses_timelock(right),
        Terminal::AndOr(first, second, third) => {
            ms_uses_timelock(first) || ms_uses_timelock(second) || ms_uses_timelock(third)
        }
        Terminal::Thresh(thresh) => thresh.iter().any(|sub| ms_uses_timelock(sub)),
        Terminal::True
        | Terminal::False
        | Terminal::PkK(_)
        | Terminal::PkH(_)
        | Terminal::RawPkH(_)
        | Terminal::Sha256(_)
        | Terminal::Hash256(_)
        | Terminal::Ripemd160(_)
        | Terminal::Hash160(_)
        | Terminal::Multi(_)
        | Terminal::MultiA(_) => false,
    }
}

/// A descriptor key's body — the xpub/derivation expression with any leading
/// `[origin]` (master fingerprint + path) stripped. Used to compare keys for
/// [`MultisigInfo::keys_lexicographically_sorted`] by their key material rather
/// than by their origin metadata.
fn key_body(key: &DescriptorPublicKey) -> String {
    let s = key.to_string();
    if let Some((_origin, body)) = s.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        body.to_string()
    } else {
        s
    }
}

/// Enforce a multisig quorum's bounds `1 <= M <= N <= 15` (PRD §9.1 check D5 /
/// §16.3 `C-KEY-COUNT-BELOW-THRESHOLD`).
///
/// Runs on the raw descriptor text *before* rust-miniscript parses it, because
/// miniscript rejects `M > N` and `M = 0` with a generic error (which would
/// surface as `E-PARSE-001`) and silently accepts `N > 15`. Extracting `M` and
/// `N` textually lets every bound violation map to the specific `E-PARSE-007`.
/// A descriptor with no `multi`/`sortedmulti`, or whose threshold is not a plain
/// integer, returns `Ok(())` — those are left for `from_str` to handle.
///
/// # Errors
/// [`ErrorCode::ThresholdExceedsKeys`] (`E-PARSE-007`) when `M < 1`, `M > N`, or
/// `N > 15`.
fn check_quorum_bounds(trimmed: &str) -> Result<(), LifeboatError> {
    let Some((m, n)) = extract_quorum(trimmed) else {
        return Ok(());
    };
    if m >= 1 && m <= n && n <= MAX_MULTISIG_KEYS {
        return Ok(());
    }
    Err(
        LifeboatError::new(ErrorCode::ThresholdExceedsKeys).with_context(format!(
            "multisig quorum must satisfy 1 <= M <= N <= {MAX_MULTISIG_KEYS}, got M={m}, N={n}"
        )),
    )
}

/// Extract `(M, N)` from the first `multi(...)`/`sortedmulti(...)`/`multi_a(...)`
/// fragment in a descriptor string: `M` is the threshold, `N` the number of
/// comma-separated keys. Returns `None` when there is no multisig fragment, or
/// when `M` is not a plain integer.
///
/// Descriptor keys never contain `(`, `)`, or `,` — they are xpubs, hex,
/// `[origin]` prefixes, `/`-derivation paths, and `<a;b>` multipath — so the
/// commas at the `multi(` paren depth are exactly its argument separators: the
/// first argument is `M`, and the remaining `N` arguments are the keys.
fn extract_quorum(s: &str) -> Option<(usize, usize)> {
    // `find("multi(")` also matches the tail of `sortedmulti(` (they share the
    // opening paren), while `multi_a(` is Taproot's CHECKSIGADD form and must be
    // searched separately.
    let multi = s.find("multi(").map(|pos| (pos, "multi("));
    let multi_a = s.find("multi_a(").map(|pos| (pos, "multi_a("));
    let (pos, name) = match (multi, multi_a) {
        (Some(left), Some(right)) => {
            if left.0 <= right.0 {
                left
            } else {
                right
            }
        }
        (Some(found), None) | (None, Some(found)) => found,
        (None, None) => return None,
    };
    let start = pos + name.len();
    let mut depth = 1usize;
    let mut threshold = String::new();
    let mut commas = 0usize;
    let mut past_first_arg = false;
    for ch in s[start..].chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            ',' if depth == 1 => {
                commas += 1;
                past_first_arg = true;
            }
            c if depth == 1 && !past_first_arg => threshold.push(c),
            _ => {}
        }
    }
    let m: usize = threshold.trim().parse().ok()?;
    Some((m, commas))
}

/// Reject a descriptor whose keys span more than one Bitcoin network
/// (`E-PARSE-004`; PRD §17.4 — derivation cannot pick a chain). Raw single
/// public keys carry no network and are ignored.
///
/// # Errors
/// [`ErrorCode::NetworkMixed`] (`E-PARSE-004`) when at least two keys commit to
/// different networks (e.g. one mainnet `xpub` and one testnet `tpub`).
fn check_single_network(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<(), LifeboatError> {
    let mut networks = Vec::new();
    descriptor.for_each_key(|key| {
        if let Some(network) = key_network(key) {
            networks.push(network);
        }
        true
    });
    if let Some(first) = networks.first() {
        if networks.iter().any(|network| network != first) {
            return Err(LifeboatError::new(ErrorCode::NetworkMixed)
                .with_context("descriptor mixes keys from multiple Bitcoin networks"));
        }
    }
    Ok(())
}

/// The Bitcoin network a descriptor key commits to via its xpub version bytes,
/// or `None` for a raw single public key (which carries no network). Note that
/// [`NetworkKind`] distinguishes only mainnet from "test" (testnet/signet/regtest
/// share version bytes); the finer split is US-011's job.
fn key_network(key: &DescriptorPublicKey) -> Option<NetworkKind> {
    match key {
        DescriptorPublicKey::XPub(x) => Some(x.xkey.network),
        DescriptorPublicKey::MultiXPub(x) => Some(x.xkey.network),
        DescriptorPublicKey::Single(_) => None,
    }
}

/// Infer the network from a descriptor's extended-key version bytes (PRD §17.4);
/// backs [`ParsedDescriptor::network_inference`].
///
/// [`NetworkKind`] carries exactly the granularity the version bytes encode:
/// mainnet (`Main`) is unique, while the whole test family (`Test`) —
/// testnet/signet/regtest — is indistinguishable. The first extended key decides;
/// [`parse_descriptor`] has already guaranteed every key agrees on the network.
fn infer_network(descriptor: &Descriptor<DescriptorPublicKey>) -> NetworkInference {
    match collect_keys(descriptor).iter().find_map(key_network) {
        Some(NetworkKind::Main) => NetworkInference::Determined(Network::Bitcoin),
        Some(_) => NetworkInference::AmbiguousTestNetwork,
        None => NetworkInference::NoExtendedKeys,
    }
}

/// Normalize SLIP-132 extended *public* keys (`ypub`/`zpub`/`upub`/`vpub` and the
/// uppercase multisig spellings) in a descriptor to the standard `xpub`/`tpub`
/// form (PRD §17.4, "normalize on import").
///
/// SLIP-132 version bytes encode the script type, which a descriptor already
/// expresses through its `wpkh`/`sh(wpkh(…))`/… wrapper, and rust-bitcoin's parser
/// only accepts the standard `xpub`/`tpub` bytes — so a SLIP-132 key must be
/// rewritten before [`parse_descriptor`] can read it. Mainnet variants become
/// `xpub`, testnet variants `tpub`; each key is matched by its prefix at a key
/// boundary and rewritten purely by swapping its four Base58Check version bytes,
/// leaving the key material untouched.
///
/// When at least one key is rewritten the body changes, so the returned descriptor
/// carries a freshly computed BIP380 `#checksum`; when nothing matches the trimmed
/// input is returned verbatim. This is a standalone import step — the wallet-import
/// layer (US-023+) and the CLI call it before `parse_descriptor` — kept out of the
/// parse spine so it never invalidates a checksum a user computed over the original
/// SLIP-132 text.
///
/// # Errors
/// - [`ErrorCode::InputEmpty`] (`E-INPUT-001`) — the input is blank.
/// - [`ErrorCode::ParseFailed`] (`E-PARSE-001`) — recomputing the checksum over the
///   rewritten body failed (a non-charset character in the descriptor).
pub fn normalize_slip132(input: &str) -> Result<Slip132Normalization, LifeboatError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    // SLIP-132 keys and descriptor syntax are ASCII; a non-ASCII descriptor has no
    // SLIP-132 key to rewrite and is left for `from_str` to reject. Bailing here
    // keeps the byte-indexed scan below free of UTF-8 boundary hazards.
    if !trimmed.is_ascii() {
        return Ok(Slip132Normalization {
            descriptor: trimmed.to_string(),
            normalized_keys: 0,
        });
    }

    let bytes = trimmed.as_bytes();
    let mut out = String::with_capacity(trimmed.len());
    let mut normalized_keys = 0usize;
    let mut i = 0usize;
    while i < trimmed.len() {
        if is_key_boundary(bytes, i) {
            if let Some((run_len, normalized)) = normalize_slip132_key_at(trimmed, i) {
                out.push_str(&normalized);
                i += run_len;
                normalized_keys += 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }

    if normalized_keys == 0 {
        return Ok(Slip132Normalization {
            descriptor: trimmed.to_string(),
            normalized_keys: 0,
        });
    }
    // The rewritten body invalidates any original checksum; recompute a fresh one.
    let descriptor = compute_checksum(&out)?;
    Ok(Slip132Normalization {
        descriptor,
        normalized_keys,
    })
}

/// If a SLIP-132 public extended key begins at byte offset `at` (already known to
/// be a [key boundary](is_key_boundary)), return the length of its Base58 run and
/// its standard `xpub`/`tpub` rewrite. Returns `None` when no SLIP-132 prefix
/// matches, or when the run is not a valid 78-byte Base58Check extended key — in
/// which case it is left untouched for `from_str` to reject.
fn normalize_slip132_key_at(s: &str, at: usize) -> Option<(usize, String)> {
    let rest = &s[at..];
    for (prefix, version) in SLIP132_PUBLIC_PREFIXES {
        if rest.starts_with(*prefix) {
            // The whole key is the maximal run of Base58 characters (a subset of
            // ASCII alphanumerics) from here; the prefix itself is alphanumeric.
            let run_len = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
            let run = &rest[..run_len];
            let mut decoded = base58::decode_check(run).ok()?;
            if decoded.len() != EXTENDED_KEY_LEN {
                return None;
            }
            decoded[..4].copy_from_slice(version);
            return Some((run_len, base58::encode_check(&decoded)));
        }
    }
    None
}

/// Every key in the descriptor, cloned, in the deterministic order
/// `Descriptor::for_each_key` visits them (the order they appear in the text).
/// The single source of "all keys, in descriptor order" used by the duplicate
/// check and key-origin extraction.
fn collect_keys(descriptor: &Descriptor<DescriptorPublicKey>) -> Vec<DescriptorPublicKey> {
    let mut keys = Vec::new();
    descriptor.for_each_key(|key| {
        keys.push(key.clone());
        true
    });
    keys
}

/// Whether any extended public key is reused across positions anywhere in the
/// descriptor (PRD §16.3 `C-DUPLICATE-XPUB`). Backs the parse-time fact recorded
/// on [`ParsedDescriptor`].
fn descriptor_has_duplicate_keys(descriptor: &Descriptor<DescriptorPublicKey>) -> bool {
    keys_have_duplicate(&collect_keys(descriptor))
}

/// Build the [`KeyOrigin`] for one descriptor key at `index` (PRD §17.6 item 3).
///
/// The master fingerprint and origin derivation path come from the key's
/// `[fingerprint/path]` origin annotation (absent → `None`). The xpub is the
/// extended key's string form for `XPub`/`MultiXPub`, or `None` for a raw single
/// public key. Standard-scheme classification runs on the origin path.
fn key_origin(index: usize, key: &DescriptorPublicKey) -> KeyOrigin {
    let (origin, xpub) = match key {
        DescriptorPublicKey::Single(single) => (single.origin.clone(), None),
        DescriptorPublicKey::XPub(x) => (x.origin.clone(), Some(x.xkey.to_string())),
        DescriptorPublicKey::MultiXPub(m) => (m.origin.clone(), Some(m.xkey.to_string())),
    };
    let (fingerprint, derivation_path) = match origin {
        Some((fingerprint, path)) => (Some(fingerprint), Some(path)),
        None => (None, None),
    };
    let standard_path = derivation_path.as_ref().and_then(classify_standard_path);
    KeyOrigin {
        index,
        fingerprint,
        derivation_path,
        xpub,
        standard_path,
    }
}

/// Classify an origin derivation path as a standard account-level scheme (PRD
/// §9.1 check C4). A standard path is fully hardened and has the canonical shape:
/// `m/{44,49,84,86}h/coinh/accounth` (3 components) for the single-key schemes,
/// or `m/48h/coinh/accounth/script_typeh` (4 components) for multisig. Anything
/// else — wrong purpose, wrong length, or a non-hardened component — is `None`.
fn classify_standard_path(path: &DerivationPath) -> Option<StandardPath> {
    let components: Vec<ChildNumber> = path.into_iter().copied().collect();
    if components.is_empty() || !components.iter().all(|child| child.is_hardened()) {
        return None;
    }
    let purpose = match components[0] {
        ChildNumber::Hardened { index } => index,
        ChildNumber::Normal { .. } => return None,
    };
    match (purpose, components.len()) {
        (44, 3) => Some(StandardPath::Bip44),
        (49, 3) => Some(StandardPath::Bip49),
        (84, 3) => Some(StandardPath::Bip84),
        (86, 3) => Some(StandardPath::Bip86),
        (48, 4) => Some(StandardPath::Bip48),
        _ => None,
    }
}

/// Render an origin derivation path in the §19.1 display form `m/48h/0h/0h/2h`:
/// a leading `m/`, hardened markers as `h` rather than `'`. An empty path (a
/// fingerprint-only origin) renders as `"m"`.
fn format_origin_path(path: &DerivationPath) -> String {
    if path.is_empty() {
        "m".to_string()
    } else {
        format!("m/{path}").replace('\'', "h")
    }
}

/// The total number of hardened-derivation components across every key's origin
/// and derivation path(s). Equals the number of hardened markers the user must
/// have written, which [`ParsedDescriptor::hardened_marker_style`] compares
/// against the `'` count in the raw text.
fn total_hardened(descriptor: &Descriptor<DescriptorPublicKey>) -> usize {
    collect_keys(descriptor)
        .iter()
        .map(key_hardened_count)
        .sum()
}

/// The number of hardened components in one key's origin path plus its own
/// derivation path(s).
fn key_hardened_count(key: &DescriptorPublicKey) -> usize {
    let origin = match key {
        DescriptorPublicKey::Single(single) => &single.origin,
        DescriptorPublicKey::XPub(x) => &x.origin,
        DescriptorPublicKey::MultiXPub(m) => &m.origin,
    };
    let mut count = origin.as_ref().map_or(0, |(_, path)| hardened_in(path));
    match key {
        DescriptorPublicKey::Single(_) => {}
        DescriptorPublicKey::XPub(x) => count += hardened_in(&x.derivation_path),
        DescriptorPublicKey::MultiXPub(m) => {
            count += m
                .derivation_paths
                .paths()
                .iter()
                .map(hardened_in)
                .sum::<usize>();
        }
    }
    count
}

/// The number of hardened components in a single derivation path.
fn hardened_in(path: &DerivationPath) -> usize {
    path.into_iter().filter(|child| child.is_hardened()).count()
}

/// True if two or more keys share the same [identity](key_identity).
fn keys_have_duplicate(keys: &[DescriptorPublicKey]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(keys.len());
    !keys.iter().all(|key| seen.insert(key_identity(key)))
}

/// A key's deduplication identity: the extended public key itself — without the
/// `[origin]` prefix or `/`-derivation suffix — for xpub keys, or the full key
/// string for raw single public keys. Comparing by the xpub alone means the same
/// xpub under two different derivation paths still counts as a duplicate, which
/// is the "illusory quorum" the check exists to catch.
fn key_identity(key: &DescriptorPublicKey) -> String {
    match key {
        DescriptorPublicKey::XPub(x) => x.xkey.to_string(),
        DescriptorPublicKey::MultiXPub(x) => x.xkey.to_string(),
        DescriptorPublicKey::Single(_) => key.to_string(),
    }
}

/// Validate a descriptor's BIP380 checksum and report whether one was present.
///
/// This is the checksum half of [`parse_descriptor`], exposed for the CLI
/// `checksum --validate` command (US-037) and any caller that wants the checksum
/// verdict without a full parse. Leading and trailing whitespace is ignored.
///
/// - Present and correct → `Ok(`[`ChecksumStatus::Present`]`)`.
/// - Absent → `Ok(`[`ChecksumStatus::Missing`]`)` — non-fatal; corresponds to
///   the warning `W-NO-DESC-CHECKSUM` (`E-PARSE-002`).
///
/// # Errors
/// [`ErrorCode::ChecksumInvalid`] (`E-PARSE-003`) when a `#checksum` is present
/// but does not match the descriptor body — a wrong checksum, a wrong length, or
/// a character outside the BIP380 descriptor charset. The underlying
/// rust-miniscript error is chained as a secret-free source.
pub fn validate_checksum(descriptor: &str) -> Result<ChecksumStatus, LifeboatError> {
    let trimmed = descriptor.trim();
    // No `#` at all means no checksum to verify. A non-ASCII body without a
    // checksum is left for `from_str` to reject as `E-PARSE-001`, not treated as
    // a checksum problem here.
    if !trimmed.contains('#') {
        return Ok(ChecksumStatus::Missing);
    }
    match checksum::verify_checksum(trimmed) {
        Ok(_) => Ok(ChecksumStatus::Present),
        Err(e) => Err(LifeboatError::new(ErrorCode::ChecksumInvalid).with_source(e)),
    }
}

/// Compute the BIP380 checksum for a descriptor, returning `descriptor#xxxxxxxx`.
///
/// Any existing `#checksum` on the input is stripped and recomputed, so the
/// function is idempotent (`compute_checksum(compute_checksum(d)?) ==
/// compute_checksum(d)`). Uses rust-miniscript's BIP380 checksum engine. Leading
/// and trailing whitespace is ignored.
///
/// # Errors
/// - [`ErrorCode::InputEmpty`] (`E-INPUT-001`) — the input is blank.
/// - [`ErrorCode::ParseFailed`] (`E-PARSE-001`) — the descriptor body contains a
///   character outside the BIP380 descriptor charset.
pub fn compute_checksum(descriptor: &str) -> Result<String, LifeboatError> {
    let trimmed = descriptor.trim();
    if trimmed.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    // Strip any existing checksum: everything from the last `#` onward.
    let body = trimmed.rfind('#').map_or(trimmed, |pos| &trimmed[..pos]);

    let mut engine = checksum::Engine::new();
    engine
        .input(body)
        .map_err(|e| LifeboatError::new(ErrorCode::ParseFailed).with_source(e))?;

    Ok(format!("{body}#{}", engine.checksum()))
}

/// Reject the unsupported top-level functions in [`UNSUPPORTED_FUNCTIONS`] with
/// a clear [`ErrorCode::UnsupportedFunction`]. `trimmed` must already be
/// whitespace-trimmed.
fn reject_unsupported_function(trimmed: &str) -> Result<(), LifeboatError> {
    for func in UNSUPPORTED_FUNCTIONS {
        if has_function_prefix(trimmed, func) {
            return Err(LifeboatError::new(ErrorCode::UnsupportedFunction)
                .with_context(format!("descriptor uses unsupported `{func}(...)`")));
        }
    }
    Ok(())
}

/// True if `s` begins with `name(` — i.e. an invocation of the named function.
fn has_function_prefix(s: &str, name: &str) -> bool {
    s.strip_prefix(name)
        .is_some_and(|rest| rest.starts_with('('))
}

/// Refuse a descriptor that carries extended private-key material (PRD §13.5.3 /
/// §16.3 `C-DESC-CONTAINS-XPRV`). `trimmed` must already be whitespace-trimmed.
///
/// Runs on the raw text *before* rust-miniscript parses it, for two reasons.
/// First, `Descriptor::<DescriptorPublicKey>::from_str` rejects an `xprv` with a
/// generic, misleading error ("public keys must be 64, 66 or 130 characters"),
/// so a textual pre-check is the only way the user gets the specific, actionable
/// `E-PARSE-005`. Second — and more to the point — the error's own contract is
/// that Lifeboat *refuses to process* secret material: recognizing the shape of
/// a private key and refusing, **without ever Base58-decoding it or deriving a
/// public key from it**, is exactly that promise. (The secret-aware parse path
/// `Descriptor::parse_descriptor(&secp, …)` would walk the tree, but it performs
/// an elliptic-curve operation on the private key — processing it — which this
/// check deliberately avoids.)
///
/// Detection is scoped to *extended* private keys (the `xprv` family and its
/// SLIP-132 spellings), which is precisely what `C-DESC-CONTAINS-XPRV` names. Raw
/// private keys (WIF, raw hex) are the `sensitive-input-detector` crate's domain
/// (US-014/US-015); that detector runs on every paste *before* a descriptor
/// reaches this parser, and a WIF that somehow arrives here still fails to parse
/// (as a non-specific `E-PARSE-001`).
///
/// # Errors
/// [`ErrorCode::ContainsPrivateKey`] (`E-PARSE-005`) when an extended private key
/// is present. The context is a fixed format description — never any key
/// material.
fn reject_private_keys(trimmed: &str) -> Result<(), LifeboatError> {
    if contains_extended_private_key(trimmed) {
        return Err(LifeboatError::new(ErrorCode::ContainsPrivateKey)
            .with_context("descriptor contains an extended private key (xprv/tprv/…)"));
    }
    Ok(())
}

/// Whether the descriptor text contains an extended private key at a key
/// position. A prefix from [`EXTENDED_PRIVATE_KEY_PREFIXES`] counts only when it
/// sits at a [key boundary](is_key_boundary) and is followed by a long run of key
/// characters ([`has_key_length_after`]) — see [`reject_private_keys`] for why
/// this is a textual scan rather than a parse.
fn contains_extended_private_key(s: &str) -> bool {
    let bytes = s.as_bytes();
    EXTENDED_PRIVATE_KEY_PREFIXES.iter().any(|prefix| {
        s.match_indices(prefix)
            .any(|(at, _)| is_key_boundary(bytes, at) && has_key_length_after(s, at + prefix.len()))
    })
}

/// Whether byte offset `at` is the start of a descriptor key: the very beginning
/// of the string, or immediately after `(`, `,`, or `]` (the only characters a
/// key follows). These delimiters never appear inside a Base58 key body, so this
/// precisely targets key positions and never matches inside a public key — which
/// is why a valid watch-only descriptor can never trip the private-key check.
fn is_key_boundary(bytes: &[u8], at: usize) -> bool {
    at == 0 || matches!(bytes[at - 1], b'(' | b',' | b']')
}

/// Whether at least [`MIN_EXTENDED_KEY_TRAILING_LEN`] key characters
/// (alphanumeric, the Base58 superset) follow byte offset `from`.
fn has_key_length_after(s: &str, from: usize) -> bool {
    s[from..]
        .bytes()
        .take_while(u8::is_ascii_alphanumeric)
        .count()
        >= MIN_EXTENDED_KEY_TRAILING_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load a fixture from the repo-root `fixtures/` tree at compile time.
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

    #[test]
    fn parses_singlesig_fixtures_with_correct_type() {
        let cases = [
            (
                fixture!("descriptors/singlesig/pkh_valid.txt"),
                DescriptorType::Pkh,
            ),
            (
                fixture!("descriptors/singlesig/wpkh_valid.txt"),
                DescriptorType::Wpkh,
            ),
            (
                fixture!("descriptors/singlesig/sh_wpkh_valid.txt"),
                DescriptorType::ShWpkh,
            ),
        ];
        for (text, expected_type) in cases {
            let parsed = parse_descriptor(text).expect("fixture must parse");
            assert_eq!(parsed.descriptor_type(), expected_type, "type for {text}");
            assert!(parsed.is_singlesig(), "{text} should be singlesig");
            // The original input is preserved verbatim (PRD §17.3).
            assert_eq!(parsed.raw(), text);
        }
    }

    #[test]
    fn rejects_unsupported_functions_with_e_parse_006() {
        // Minimal valid arguments so only the *function* is the reason to reject.
        for desc in [
            "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
            "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)",
            "raw(0014751e76e8199196d454941c45d1b3a323f1433bd6)",
        ] {
            let err = parse_descriptor(desc).expect_err("must reject");
            assert_eq!(
                err.code(),
                ErrorCode::UnsupportedFunction,
                "wrong code for {desc}"
            );
        }
    }

    #[test]
    fn empty_input_is_e_input_001() {
        for blank in ["", "   ", "\n\t  "] {
            let err = parse_descriptor(blank).expect_err("blank must error");
            assert_eq!(err.code(), ErrorCode::InputEmpty);
        }
    }

    #[test]
    fn unparseable_input_is_e_parse_001() {
        for garbage in ["not a descriptor", "wpkh(", "wpkh(zzz)", "🦀🦀🦀"] {
            let err = parse_descriptor(garbage).expect_err("garbage must error");
            assert_eq!(
                err.code(),
                ErrorCode::ParseFailed,
                "wrong code for {garbage}"
            );
        }
    }

    #[test]
    fn leading_and_trailing_whitespace_is_tolerated() {
        let text = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let padded = format!("  \n{text}\t ");
        let parsed = parse_descriptor(&padded).expect("padded fixture must parse");
        assert_eq!(parsed.descriptor_type(), DescriptorType::Wpkh);
        // raw() preserves exactly what the caller passed, including padding.
        assert_eq!(parsed.raw(), padded);
    }

    #[test]
    fn insane_descriptor_surfaces_typed_error_not_panic() {
        // This descriptor parses, but its only satisfaction path requires no
        // signature (pure timelocks), so rust-miniscript's `sanity_check`
        // rejects it (`SiglessBranch`). The result must be a typed E-PARSE-001,
        // never a panic.
        let err = parse_descriptor("wsh(and_v(v:after(100),after(500000000)))")
            .expect_err("sigless descriptor must be rejected");
        assert_eq!(err.code(), ErrorCode::ParseFailed);
    }

    #[test]
    fn present_valid_checksum_is_present() {
        for text in [
            fixture!("descriptors/singlesig/pkh_valid.txt"),
            fixture!("descriptors/singlesig/wpkh_valid.txt"),
            fixture!("descriptors/singlesig/sh_wpkh_valid.txt"),
        ] {
            assert_eq!(
                validate_checksum(text).expect("valid checksum must verify"),
                ChecksumStatus::Present,
                "validate_checksum for {text}"
            );
            let parsed = parse_descriptor(text).expect("valid fixture must parse");
            assert_eq!(parsed.checksum_status(), ChecksumStatus::Present);
        }
    }

    #[test]
    fn present_invalid_checksum_is_e_parse_003() {
        // wpkh_valid.txt with one checksum character flipped (`g` -> `q`): a
        // single-character transcription error.
        let text = fixture!("descriptors/singlesig/invalid_checksum.txt");
        // Both the standalone validator and the full parse must reject it with the
        // specific critical code, never a generic E-PARSE-001.
        assert_eq!(
            validate_checksum(text)
                .expect_err("bad checksum must error")
                .code(),
            ErrorCode::ChecksumInvalid
        );
        assert_eq!(
            parse_descriptor(text)
                .expect_err("bad checksum must error")
                .code(),
            ErrorCode::ChecksumInvalid
        );
    }

    #[test]
    fn missing_checksum_is_non_fatal_and_recorded() {
        // Strip the `#checksum` off a known-good fixture to get a bare descriptor.
        let with = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let body = with.rsplit_once('#').expect("fixture has a checksum").0;
        assert!(!body.contains('#'), "body must have no checksum");

        assert_eq!(
            validate_checksum(body).expect("missing checksum is not an error"),
            ChecksumStatus::Missing
        );
        let parsed = parse_descriptor(body).expect("bare descriptor must still parse");
        assert_eq!(parsed.checksum_status(), ChecksumStatus::Missing);
    }

    #[test]
    fn compute_checksum_round_trips() {
        let with = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let body = with.rsplit_once('#').expect("fixture has a checksum").0;

        // Computing over the bare body reproduces the canonical fixture exactly.
        assert_eq!(compute_checksum(body).expect("compute over body"), with);
        // Idempotent: recomputing over an already-checksummed descriptor is a no-op.
        assert_eq!(
            compute_checksum(with).expect("compute over checksummed"),
            with
        );

        // The computed descriptor parses back with a Present checksum.
        let recomputed = compute_checksum(body).expect("compute over body");
        let parsed = parse_descriptor(&recomputed).expect("computed descriptor parses");
        assert_eq!(parsed.checksum_status(), ChecksumStatus::Present);
    }

    #[test]
    fn compute_checksum_rejects_blank_input() {
        for blank in ["", "   ", "\n\t "] {
            assert_eq!(
                compute_checksum(blank)
                    .expect_err("blank must error")
                    .code(),
                ErrorCode::InputEmpty
            );
        }
    }

    /// The three singlesig fixtures, each carrying `'` hardened markers. A
    /// function (not a `const`) because `fixture!` calls `str::trim`, which is
    /// not `const` on the pinned 1.78 toolchain.
    fn singlesig_fixtures() -> [&'static str; 3] {
        [
            fixture!("descriptors/singlesig/pkh_valid.txt"),
            fixture!("descriptors/singlesig/wpkh_valid.txt"),
            fixture!("descriptors/singlesig/sh_wpkh_valid.txt"),
        ]
    }

    /// Rewrite a `'`-marker descriptor into its equivalent `h`-marker form with a
    /// fresh, valid checksum. Used to prove `'`/`h` equivalence without baking a
    /// second copy of every fixture.
    fn to_h_variant(apostrophe_form: &str) -> String {
        let body = apostrophe_form
            .rsplit_once('#')
            .map_or(apostrophe_form, |(body, _checksum)| body);
        compute_checksum(&body.replace('\'', "h")).expect("h-variant must checksum")
    }

    #[test]
    fn canonical_form_uses_h_markers_and_a_valid_checksum() {
        for text in singlesig_fixtures() {
            // The fixtures are written with `'`; the canonical form must not be.
            assert!(text.contains('\''), "fixture {text} should use `'` markers");
            let parsed = parse_descriptor(text).expect("fixture must parse");
            let canonical = parsed.canonical();

            assert!(
                !canonical.contains('\''),
                "canonical form must not contain `'`: {canonical}"
            );
            assert!(
                canonical.contains('h'),
                "canonical form should render hardened markers as `h`: {canonical}"
            );
            // The canonical form is itself a valid, checksummed descriptor.
            let reparsed = parse_descriptor(canonical).expect("canonical form must parse");
            assert_eq!(reparsed.checksum_status(), ChecksumStatus::Present);
            // raw() still echoes the user's exact input, distinct from canonical.
            assert_eq!(parsed.raw(), text);
            assert_ne!(parsed.canonical(), parsed.raw());
        }
    }

    #[test]
    fn hardened_markers_h_and_apostrophe_are_equivalent() {
        for text in singlesig_fixtures() {
            let h_form = to_h_variant(text);
            assert!(h_form.contains('h') && !h_form.contains('\''));

            // Both spellings parse, and both normalize to the identical string.
            assert_eq!(
                normalize(text).expect("`'` form normalizes"),
                normalize(&h_form).expect("`h` form normalizes"),
                "`'` and `h` forms of {text} must normalize identically"
            );
            // The stored canonical form agrees with the free `normalize` function.
            assert_eq!(
                parse_descriptor(text).expect("parse `'`").canonical(),
                parse_descriptor(&h_form).expect("parse `h`").canonical()
            );
        }
    }

    #[test]
    fn normalization_round_trip_is_stable() {
        for text in singlesig_fixtures() {
            let once = normalize(text).expect("first normalize");
            let twice = normalize(&once).expect("second normalize");
            assert_eq!(once, twice, "normalize must be idempotent for {text}");
            // Equivalently, re-parsing the canonical form yields the same canonical.
            assert_eq!(
                parse_descriptor(&once)
                    .expect("canonical re-parses")
                    .canonical(),
                once
            );
        }
    }

    /// The two multisig fixtures with their expected `(M, N)` quorum. A function,
    /// not a `const`, because `fixture!` calls non-const `str::trim` (see
    /// `singlesig_fixtures`).
    fn multisig_fixtures() -> [(&'static str, usize, usize); 2] {
        [
            (
                fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"),
                2,
                3,
            ),
            (
                fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"),
                3,
                5,
            ),
        ]
    }

    /// Join descriptor keys back into a comma-separated argument list.
    fn join_keys(keys: &[DescriptorPublicKey]) -> String {
        keys.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The 2-of-3 fixture's keys, for building variant descriptors in tests.
    fn fixture_2of3_keys() -> Vec<DescriptorPublicKey> {
        parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"))
            .expect("2of3 fixture parses")
            .multisig_info()
            .expect("2of3 is multisig")
            .keys()
            .to_vec()
    }

    #[test]
    fn parses_multisig_fixtures_with_correct_quorum() {
        for (text, m, n) in multisig_fixtures() {
            let parsed = parse_descriptor(text).expect("multisig fixture must parse");
            assert!(parsed.is_multisig(), "{text} should be multisig");
            assert!(!parsed.is_singlesig(), "{text} is not singlesig");

            let info = parsed.multisig_info().expect("multisig info present");
            assert_eq!(info.threshold(), m, "M for {text}");
            assert_eq!(info.key_count(), n, "N for {text}");
            assert_eq!(info.keys().len(), n, "key list length for {text}");
            assert_eq!(info.kind(), MultisigKind::SortedMulti, "kind for {text}");
            assert!(info.is_sorted_multi());
            assert_eq!(info.kind().as_str(), "sortedmulti");
            // The fixtures are emitted with keys pre-sorted by xpub body.
            assert!(
                info.keys_lexicographically_sorted(),
                "fixture keys should be sorted: {text}"
            );
        }
    }

    #[test]
    fn classifies_multi_vs_sortedmulti() {
        // Build both spellings from one key set so only the function differs.
        let joined = join_keys(&fixture_2of3_keys());
        let sorted =
            parse_descriptor(&format!("wsh(sortedmulti(2,{joined}))")).expect("sortedmulti parses");
        let ordered = parse_descriptor(&format!("wsh(multi(2,{joined}))")).expect("multi parses");

        let si = sorted.multisig_info().expect("sortedmulti info");
        let mi = ordered.multisig_info().expect("multi info");
        assert_eq!(si.kind(), MultisigKind::SortedMulti);
        assert!(si.is_sorted_multi());
        assert_eq!(mi.kind(), MultisigKind::Multi);
        assert!(!mi.is_sorted_multi());
        assert_eq!(mi.kind().as_str(), "multi");
        // Same quorum either way.
        assert_eq!((si.threshold(), si.key_count()), (2, 3));
        assert_eq!((mi.threshold(), mi.key_count()), (2, 3));
    }

    #[test]
    fn extracts_quorum_across_wrapper_forms() {
        let joined = join_keys(&fixture_2of3_keys());
        // Every supported wrapper from PRD §17.2 resolves to the same 2-of-3.
        // (Bare `sortedmulti(…)` is intentionally absent: it is not a valid
        // descriptor in rust-miniscript — `sortedmulti` only exists inside
        // `sh`/`wsh`.)
        let cases = [
            (format!("multi(2,{joined})"), MultisigKind::Multi),
            (format!("sh(multi(2,{joined}))"), MultisigKind::Multi),
            (format!("wsh(multi(2,{joined}))"), MultisigKind::Multi),
            (
                format!("sh(sortedmulti(2,{joined}))"),
                MultisigKind::SortedMulti,
            ),
            (
                format!("wsh(sortedmulti(2,{joined}))"),
                MultisigKind::SortedMulti,
            ),
            (
                format!("sh(wsh(sortedmulti(2,{joined})))"),
                MultisigKind::SortedMulti,
            ),
        ];
        for (desc, kind) in cases {
            let parsed = parse_descriptor(&desc).unwrap_or_else(|e| panic!("parse {desc}: {e}"));
            let info = parsed
                .multisig_info()
                .unwrap_or_else(|| panic!("no multisig info for {desc}"));
            assert_eq!(info.kind(), kind, "kind for {desc}");
            assert_eq!(info.threshold(), 2, "M for {desc}");
            assert_eq!(info.key_count(), 3, "N for {desc}");
        }
    }

    #[test]
    fn sortedmulti_key_ordering_is_detected() {
        let fixture = parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"))
            .expect("fixture parses");
        assert!(fixture
            .multisig_info()
            .expect("info")
            .keys_lexicographically_sorted());

        // Reverse the keys: identical M/N/kind, but the written order is no
        // longer ascending. (Reversing 3 distinct sorted keys guarantees this.)
        let mut keys = fixture_2of3_keys();
        keys.reverse();
        let scrambled = parse_descriptor(&format!("wsh(sortedmulti(2,{}))", join_keys(&keys)))
            .expect("scrambled parses");
        let info = scrambled.multisig_info().expect("info");
        assert_eq!((info.threshold(), info.key_count()), (2, 3));
        assert!(info.is_sorted_multi());
        assert!(
            !info.keys_lexicographically_sorted(),
            "reversed keys must not report as sorted"
        );
    }

    #[test]
    fn singlesig_and_complex_policy_have_no_multisig_info() {
        for text in singlesig_fixtures() {
            let parsed = parse_descriptor(text).expect("singlesig fixture parses");
            assert!(parsed.multisig_info().is_none(), "{text} is not multisig");
            assert!(!parsed.is_multisig());
        }
        // A richer Miniscript policy (a Liana-style timelocked recovery branch) is
        // not a plain M-of-N quorum, so it is deliberately not classified as
        // multisig here — the Miniscript-policy stories (US-087+) handle it.
        let keys = fixture_2of3_keys();
        let policy = format!(
            "wsh(or_d(pk({}),and_v(v:pkh({}),older(65535))))",
            keys[0], keys[1]
        );
        let parsed = parse_descriptor(&policy).expect("liana-style policy parses");
        assert!(
            parsed.multisig_info().is_none(),
            "a timelock policy is not a plain multisig: {policy}"
        );
        assert!(parsed.uses_miniscript());
        assert!(parsed.uses_timelock());
    }

    #[test]
    fn liana_timelock_fixture_is_first_class_miniscript() {
        let text = fixture!("descriptors/timelock/liana_basic.txt");
        let parsed = parse_descriptor(text).expect("Liana-style fixture parses");
        assert_eq!(parsed.checksum_status(), ChecksumStatus::Present);
        assert_eq!(parsed.descriptor_type(), DescriptorType::Wsh);
        assert!(parsed.uses_miniscript());
        assert!(parsed.uses_timelock());
        assert!(parsed.uses_multipath());
        assert!(!parsed.is_singlesig());
        assert!(!parsed.is_multisig());
        assert!(parsed.multisig_info().is_none());

        let origins = parsed.key_origins();
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[0].fingerprint_hex().as_deref(), Some("4ba43603"));
        assert_eq!(origins[1].fingerprint_hex().as_deref(), Some("6e37edb9"));
        assert!(origins
            .iter()
            .all(|origin| origin.standard_path() == Some(StandardPath::Bip48)));

        let expanded = parsed.expand_multipath().expect("multipath expands");
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].desc_type(), DescriptorType::Wsh);
        assert_eq!(expanded[1].desc_type(), DescriptorType::Wsh);
        assert!(
            expanded[0].to_string().ends_with("#uny393kd"),
            "receive branch checksum stays pinned"
        );
        assert!(
            expanded[1].to_string().ends_with("#s0952kd2"),
            "change branch checksum stays pinned"
        );
    }

    #[test]
    fn absolute_and_relative_timelock_fragments_are_detected() {
        let key = fixture_2of3_keys()
            .into_iter()
            .next()
            .expect("fixture has a key");
        for desc in [
            format!("wsh(and_v(v:pk({key}),after(500000)))"),
            format!("wsh(and_v(v:pk({key}),older(144)))"),
        ] {
            let parsed = parse_descriptor(&desc).unwrap_or_else(|e| panic!("{desc}: {e}"));
            assert!(parsed.uses_miniscript(), "{desc} is a Miniscript policy");
            assert!(parsed.uses_timelock(), "{desc} carries a timelock");
        }
    }

    #[test]
    fn multisig_quorum_bounds_violations_are_e_parse_007() {
        // Fixture: sortedmulti(3, k0, k1) — M=3 > N=2.
        assert_eq!(
            parse_descriptor(fixture!("descriptors/multisig/threshold_exceeds_keys.txt"))
                .expect_err("M>N must error")
                .code(),
            ErrorCode::ThresholdExceedsKeys
        );

        let keys = fixture_2of3_keys();
        let joined3 = join_keys(&keys); // 3 distinct keys
        let sixteen = vec![keys[0].to_string(); 16].join(",");

        // M>N, M=0, and N>15 all map to the same specific code — and the textual
        // bounds check fires before `from_str`, so the duplicate keys in the
        // N>15 case are irrelevant (the count alone trips the limit).
        for desc in [
            format!("wsh(multi(4,{joined3}))"),       // 4-of-3
            format!("wsh(sortedmulti(0,{joined3}))"), // 0-of-3
            format!("wsh(sortedmulti(1,{sixteen}))"), // 1-of-16
        ] {
            assert_eq!(
                parse_descriptor(&desc)
                    .expect_err("bounds violation")
                    .code(),
                ErrorCode::ThresholdExceedsKeys,
                "wrong code for {desc}"
            );
        }

        // Valid bounds at the edges still parse cleanly.
        for desc in [
            format!("wsh(sortedmulti(2,{}))", join_keys(&keys[..2])), // 2-of-2
            format!("sh(multi(1,{}))", keys[0]),                      // 1-of-1
        ] {
            parse_descriptor(&desc).unwrap_or_else(|e| panic!("valid bounds {desc}: {e}"));
        }
    }

    #[test]
    fn mixed_network_descriptor_is_e_parse_004() {
        // Fixture: sortedmulti(2, testnet tpub, mainnet xpub).
        assert_eq!(
            parse_descriptor(fixture!("descriptors/invalid/network_mixed.txt"))
                .expect_err("mixed network must error")
                .code(),
            ErrorCode::NetworkMixed
        );
    }

    #[test]
    fn duplicate_xpub_is_a_non_fatal_fact() {
        // Fixture: sortedmulti(2, k0, k0, k1) — k0 repeated exactly. The descriptor
        // still parses (so the scoring layer can flag C-DUPLICATE-XPUB); the
        // duplicate is recorded as a fact, not a parse error.
        let parsed = parse_descriptor(fixture!("descriptors/multisig/duplicate_xpub.txt"))
            .expect("duplicate descriptor still parses");
        assert!(
            parsed.has_duplicate_keys(),
            "exact duplicate must be detected"
        );
        let info = parsed.multisig_info().expect("is multisig");
        assert!(info.has_duplicate_keys());
        // On paper it is still a 2-of-3 quorum.
        assert_eq!((info.threshold(), info.key_count()), (2, 3));
    }

    #[test]
    fn same_xpub_under_different_paths_is_a_duplicate() {
        let keys = fixture_2of3_keys();
        // Reuse key 0's xpub under a different derivation path (/0/* -> /1/*).
        let k0 = keys[0].to_string();
        let k0_alt = k0.replace("/0/*", "/1/*");
        assert_ne!(k0, k0_alt, "the path variant must differ textually");

        let desc = format!("wsh(sortedmulti(2,{k0},{k0_alt},{}))", keys[1]);
        let parsed = parse_descriptor(&desc).expect("same-xpub-different-path still parses");
        assert!(
            parsed.has_duplicate_keys(),
            "the same xpub under two paths is an illusory quorum"
        );
    }

    #[test]
    fn clean_descriptors_have_no_duplicates_and_one_network() {
        for text in [
            fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"),
            fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"),
        ] {
            let parsed = parse_descriptor(text).expect("clean multisig parses");
            assert!(!parsed.has_duplicate_keys(), "no duplicates in {text}");
            assert!(!parsed
                .multisig_info()
                .expect("is multisig")
                .has_duplicate_keys());
        }
        for text in singlesig_fixtures() {
            let parsed = parse_descriptor(text).expect("singlesig parses");
            assert!(!parsed.has_duplicate_keys(), "singlesig has no duplicates");
        }
    }

    /// The xpub+path body of a key with its `[origin]` prefix removed
    /// (`[fp/path]tpub.../0/*` -> `tpub.../0/*`), for building origin variants in
    /// tests without baking new fixtures.
    fn strip_origin(key_str: &str) -> String {
        key_str
            .find(']')
            .map_or_else(|| key_str.to_string(), |i| key_str[i + 1..].to_string())
    }

    #[test]
    fn key_origins_extract_multisig_provenance_in_descriptor_order() {
        let parsed = parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"))
            .expect("fixture parses");
        let origins = parsed.key_origins();
        assert_eq!(origins.len(), 3, "2-of-3 has three keys");

        // The fingerprints come out in the order the keys appear in the text.
        let fingerprints: Vec<String> = origins
            .iter()
            .map(|o| o.fingerprint_hex().expect("fingerprint present"))
            .collect();
        let fingerprints: Vec<&str> = fingerprints.iter().map(String::as_str).collect();
        assert_eq!(fingerprints, ["4ba43603", "6e37edb9", "8dfc9b34"]);

        for (i, origin) in origins.iter().enumerate() {
            assert_eq!(origin.index(), i, "index matches position");
            assert!(origin.has_fingerprint(), "key {i} has a fingerprint");
            assert!(origin.has_derivation_path(), "key {i} has a path");
            assert!(origin.key_origin_present(), "key {i} origin complete");
            // Every cosigner uses the BIP48 multisig path m/48h/1h/0h/2h.
            assert_eq!(origin.standard_path(), Some(StandardPath::Bip48));
            assert!(origin.is_standard_path());
            assert!(origin.standard_path().expect("scheme").is_multisig_scheme());
            assert_eq!(
                origin.derivation_path_display().as_deref(),
                Some("m/48h/1h/0h/2h")
            );
            // The fingerprint is 8 lowercase hex characters.
            let fp = origin.fingerprint_hex().expect("fp");
            assert_eq!(fp.len(), 8);
            assert!(fp
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            // Each key is an extended key, so xpub() is present.
            assert!(origin.xpub().expect("xpub").starts_with("tpub"));
        }
        // The first cosigner's xpub is the first tpub written in the fixture.
        assert!(origins[0]
            .xpub()
            .expect("xpub")
            .starts_with("tpubDDwf2gdFxFahr"));

        // 3-of-5: five origins, all BIP48, in textual order.
        let five = parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"))
            .expect("fixture parses")
            .key_origins();
        assert_eq!(five.len(), 5);
        let five_fps: Vec<String> = five
            .iter()
            .map(|o| o.fingerprint_hex().expect("fp"))
            .collect();
        let five_fps: Vec<&str> = five_fps.iter().map(String::as_str).collect();
        assert_eq!(
            five_fps,
            ["4ba43603", "6e37edb9", "8dfc9b34", "83bfab59", "56c4fac3"]
        );
        assert!(five
            .iter()
            .all(|o| o.standard_path() == Some(StandardPath::Bip48)));
    }

    #[test]
    fn key_origins_detect_singlesig_standard_schemes() {
        let pkh = parse_descriptor(fixture!("descriptors/singlesig/pkh_valid.txt")).expect("pkh");
        let wpkh =
            parse_descriptor(fixture!("descriptors/singlesig/wpkh_valid.txt")).expect("wpkh");
        let sh_wpkh =
            parse_descriptor(fixture!("descriptors/singlesig/sh_wpkh_valid.txt")).expect("shwpkh");

        // pkh -> BIP44, wpkh -> BIP84, sh(wpkh) -> BIP49 (all m/<purpose>h/1h/0h).
        for (parsed, scheme, display) in [
            (&pkh, StandardPath::Bip44, "m/44h/1h/0h"),
            (&wpkh, StandardPath::Bip84, "m/84h/1h/0h"),
            (&sh_wpkh, StandardPath::Bip49, "m/49h/1h/0h"),
        ] {
            let origins = parsed.key_origins();
            assert_eq!(origins.len(), 1, "singlesig has one key");
            let origin = &origins[0];
            assert_eq!(origin.fingerprint_hex().as_deref(), Some("71348c8a"));
            assert!(origin.key_origin_present());
            assert_eq!(origin.standard_path(), Some(scheme));
            assert!(!origin.standard_path().expect("scheme").is_multisig_scheme());
            assert_eq!(origin.derivation_path_display().as_deref(), Some(display));
            assert!(origin.xpub().expect("xpub").starts_with("tpub"));
        }
    }

    #[test]
    fn key_origins_flag_missing_fingerprint_and_path() {
        // `tpub.../0/*` with the [origin] stripped off the first 2-of-3 key.
        let body = strip_origin(&fixture_2of3_keys()[0].to_string());

        // No origin annotation at all: a bare xpub.
        let bare = parse_descriptor(&format!("wpkh({body})")).expect("bare xpub parses");
        let origin = &bare.key_origins()[0];
        assert!(!origin.has_fingerprint());
        assert!(!origin.has_derivation_path());
        assert!(!origin.key_origin_present());
        assert_eq!(origin.fingerprint(), None);
        assert_eq!(origin.fingerprint_hex(), None);
        assert_eq!(origin.derivation_path(), None);
        assert_eq!(origin.derivation_path_display(), None);
        assert_eq!(origin.standard_path(), None);
        assert!(!origin.is_standard_path());
        // It is still an extended key.
        assert!(origin.xpub().expect("xpub").starts_with("tpub"));

        // A fingerprint-only origin `[fp]`: fingerprint present, path missing.
        let fp_only = parse_descriptor(&format!("wpkh([71348c8a]{body})"))
            .expect("fingerprint-only origin parses");
        let origin = &fp_only.key_origins()[0];
        assert!(origin.has_fingerprint());
        assert_eq!(origin.fingerprint_hex().as_deref(), Some("71348c8a"));
        assert!(
            !origin.has_derivation_path(),
            "empty path counts as missing"
        );
        assert!(!origin.key_origin_present());
        assert_eq!(origin.standard_path(), None);
        assert_eq!(origin.derivation_path_display().as_deref(), Some("m"));

        // A raw single public key has no extended-key form.
        let raw = parse_descriptor(
            "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        )
        .expect("raw pubkey parses");
        let origin = &raw.key_origins()[0];
        assert_eq!(origin.xpub(), None);
        assert!(!origin.has_fingerprint());
        assert!(!origin.key_origin_present());
    }

    #[test]
    fn key_origins_classify_nonstandard_and_taproot_paths() {
        let body = strip_origin(&fixture_2of3_keys()[0].to_string());

        // A non-standard purpose (0h) and a too-short path (2 components): the
        // origin is present, but no standard scheme matches.
        for origin_path in ["0'/0'/0'", "84'/1'"] {
            let desc = format!("wpkh([71348c8a/{origin_path}]{body})");
            let parsed = parse_descriptor(&desc).unwrap_or_else(|e| panic!("{desc}: {e}"));
            let origin = &parsed.key_origins()[0];
            assert!(origin.has_fingerprint(), "{desc} has a fingerprint");
            assert!(
                origin.has_derivation_path(),
                "{desc} has a (non-standard) path"
            );
            assert!(
                !origin.is_standard_path(),
                "{desc} is not a standard scheme"
            );
            assert_eq!(origin.standard_path(), None, "{desc}");
        }

        // Single-key Taproot uses BIP86 (m/86h/...). tr() already parses; US-010
        // adds the preview flag, but path classification works today.
        let tr = parse_descriptor(&format!("tr([71348c8a/86'/1'/0']{body})"))
            .expect("taproot descriptor parses");
        let origin = &tr.key_origins()[0];
        assert_eq!(origin.standard_path(), Some(StandardPath::Bip86));
        assert!(!origin.standard_path().expect("scheme").is_multisig_scheme());
        assert_eq!(
            origin.derivation_path_display().as_deref(),
            Some("m/86h/1h/0h")
        );
    }

    #[test]
    fn hardened_marker_style_classifies_apostrophe_h_mixed_and_none() {
        // The fixtures are written with `'` markers, consistently.
        for text in singlesig_fixtures() {
            let parsed = parse_descriptor(text).expect("fixture parses");
            assert_eq!(
                parsed.hardened_marker_style(),
                HardenedMarkerStyle::Apostrophe
            );
            assert!(parsed.hardened_markers_consistent());
        }
        // The multisig fixture too (4 hardened markers per cosigner, all `'`).
        let multi = parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"))
            .expect("fixture parses");
        assert_eq!(
            multi.hardened_marker_style(),
            HardenedMarkerStyle::Apostrophe
        );

        // The `h`-form of a fixture uses `h` markers, consistently.
        let h_form = to_h_variant(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let parsed = parse_descriptor(&h_form).expect("h-form parses");
        assert_eq!(parsed.hardened_marker_style(), HardenedMarkerStyle::H);
        assert!(parsed.hardened_markers_consistent());

        // Flipping exactly one `'` to `h` mixes the two styles (inconsistent).
        let wpkh = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let body = wpkh.rsplit_once('#').expect("fixture has a checksum").0;
        let mixed = body.replacen('\'', "h", 1);
        assert!(
            mixed.contains('h') && mixed.contains('\''),
            "the variant must mix both marker styles"
        );
        let parsed = parse_descriptor(&mixed).expect("mixed-marker descriptor parses");
        assert_eq!(parsed.hardened_marker_style(), HardenedMarkerStyle::Mixed);
        assert!(!parsed.hardened_markers_consistent());

        // A descriptor with no hardened components has no markers to compare.
        let none = parse_descriptor(
            "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        )
        .expect("raw pubkey parses");
        assert_eq!(none.hardened_marker_style(), HardenedMarkerStyle::None);
        assert!(none.hardened_markers_consistent());
    }

    #[test]
    fn multipath_descriptor_is_detected_and_expands_to_receive_and_change() {
        use miniscript::bitcoin::Network;

        let parsed = parse_descriptor(fixture!("descriptors/multisig/multipath_2of3.txt"))
            .expect("multipath fixture parses");
        assert!(parsed.uses_multipath(), "fixture uses BIP389 <0;1>");
        // The original multipath form is preserved verbatim for display, in both
        // the raw input and the canonical form (expansion is for analysis only).
        assert!(
            parsed.raw().contains("<0;1>"),
            "raw keeps the multipath form"
        );
        assert!(
            parsed.canonical().contains("<0;1>"),
            "canonical preserves the multipath form: {}",
            parsed.canonical()
        );
        // It is still recognized as a 2-of-3 multisig through the multipath keys.
        let info = parsed.multisig_info().expect("multipath is still multisig");
        assert_eq!((info.threshold(), info.key_count()), (2, 3));

        // <0;1> expands into exactly two single-path descriptors: receive, change.
        let expanded = parsed.expand_multipath().expect("expansion succeeds");
        assert_eq!(expanded.len(), 2, "<0;1> expands to receive + change");

        // The multipath descriptor itself cannot be derived directly...
        assert!(
            parsed.descriptor().at_derivation_index(0).is_err(),
            "a multipath descriptor is not directly derivable"
        );
        // ...but each expanded branch is concrete, single-path, and derivable.
        let mut addresses = Vec::new();
        for branch in &expanded {
            assert!(!branch.is_multipath(), "an expanded branch is single-path");
            let definite = branch
                .at_derivation_index(0)
                .expect("expanded branch derives at index 0");
            addresses.push(
                definite
                    .address(Network::Testnet)
                    .expect("wsh descriptor has an address"),
            );
        }
        // Receive (…/0/*) and change (…/1/*) derive different addresses.
        assert_ne!(
            addresses[0], addresses[1],
            "receive and change branches must derive different addresses"
        );

        // The receive branch (index 0) is byte-identical to the standalone
        // single-path 2-of-3 fixture — the multipath form is just its /0 and /1
        // branches folded together.
        let single = fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt");
        assert_eq!(
            expanded[0].to_string(),
            single,
            "the /0 branch equals the single-path 2-of-3 fixture"
        );
    }

    #[test]
    fn non_multipath_descriptors_expand_to_themselves() {
        // Singlesig fixtures plus the single-path multisig fixture: none multipath.
        let mut cases: Vec<&str> = singlesig_fixtures().to_vec();
        cases.push(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        for text in cases {
            let parsed = parse_descriptor(text).expect("fixture parses");
            assert!(!parsed.uses_multipath(), "{text} is single-path");
            let expanded = parsed.expand_multipath().expect("expansion succeeds");
            assert_eq!(
                expanded.len(),
                1,
                "a single-path descriptor expands to itself: {text}"
            );
            assert_eq!(
                &expanded[0],
                parsed.descriptor(),
                "the sole expansion equals the original descriptor: {text}"
            );
        }
    }

    #[test]
    fn multipath_singlesig_expands_to_two_branches() {
        // Sparrow-style singlesig wallets are multipath too. Build one from a
        // fixture key body (no checksum needed — `Missing` is non-fatal).
        let body = strip_origin(&fixture_2of3_keys()[0].to_string()); // tpub…/0/*
        let multipath = body.replace("/0/*", "/<0;1>/*");
        let parsed = parse_descriptor(&format!("wpkh([71348c8a/84h/1h/0h]{multipath})"))
            .expect("multipath singlesig parses");

        assert!(parsed.uses_multipath());
        let expanded = parsed.expand_multipath().expect("expansion succeeds");
        assert_eq!(expanded.len(), 2, "<0;1> singlesig expands to two branches");
        assert!(
            expanded.iter().all(|d| !d.is_multipath()),
            "every expanded branch is single-path"
        );
        // The two branches are distinct (…/0/* vs …/1/*).
        assert_ne!(expanded[0], expanded[1]);
    }

    /// The `[origin]tprv.../0/*` key of the `contains_xprv` fixture, for building
    /// private-key variants in tests without minting new fixtures.
    fn fixture_xprv_key() -> String {
        let text = fixture!("descriptors/invalid/contains_xprv.txt");
        let no_checksum = text.rsplit_once('#').map_or(text, |(body, _)| body);
        no_checksum
            .strip_prefix("wpkh(")
            .and_then(|s| s.strip_suffix(')'))
            .expect("fixture is wpkh(KEY)#checksum")
            .to_string()
    }

    #[test]
    fn descriptor_with_xprv_is_blocked_with_e_parse_005() {
        // The fixture is a wpkh descriptor that looks watch-only but carries a
        // tprv, with an otherwise-valid checksum and structure: it is refused
        // purely because it contains private-key material — the critical
        // C-DESC-CONTAINS-XPRV / E-PARSE-005.
        let text = fixture!("descriptors/invalid/contains_xprv.txt");
        let err = parse_descriptor(text).expect_err("xprv descriptor must be refused");
        assert_eq!(err.code(), ErrorCode::ContainsPrivateKey);
        assert_eq!(err.severity(), error_taxonomy::Severity::Critical);
        // The error never echoes the secret key material (no-leak invariant).
        let surfaced = format!("{err}{}", err.context().unwrap_or_default());
        assert!(
            !surfaced.contains("tprv8ghPpf"),
            "error must not echo key material: {surfaced}"
        );
    }

    #[test]
    fn private_keys_are_blocked_at_any_key_position_and_for_every_prefix() {
        let xprv_key = fixture_xprv_key(); // [origin]tprv.../0/*
        let bare = strip_origin(&xprv_key); // tprv.../0/*

        // A private key is refused wherever a key can sit: after `(`, after `]`
        // (origin present), and after `,` inside a multisig mixed with watch-only
        // keys. None of these reach rust-miniscript — the pre-check fires first.
        let pubs = fixture_2of3_keys();
        let cases = [
            format!("wpkh({bare})"),                                       // after `(`
            format!("wpkh({xprv_key})"),                                   // after `]`
            format!("sh(wpkh({xprv_key}))"),                               // nested, after `]`
            format!("wsh(sortedmulti(2,{bare},{},{}))", pubs[0], pubs[1]), // after `,`
        ];
        for desc in &cases {
            assert_eq!(
                parse_descriptor(desc)
                    .expect_err("private key present")
                    .code(),
                ErrorCode::ContainsPrivateKey,
                "must block: {desc}"
            );
        }

        // Every extended-private-key spelling is detected. Swap only the leading
        // marker on the real key body so the trailing run stays key-length.
        let body = bare.strip_prefix("tprv").expect("fixture key is a tprv");
        for prefix in [
            "xprv", "yprv", "zprv", "uprv", "vprv", "Yprv", "Zprv", "Uprv", "Vprv",
        ] {
            let desc = format!("wpkh({prefix}{body})");
            assert_eq!(
                parse_descriptor(&desc).expect_err("prefix variant").code(),
                ErrorCode::ContainsPrivateKey,
                "prefix {prefix} must be blocked"
            );
        }
    }

    #[test]
    fn watch_only_descriptors_are_never_flagged_as_private() {
        // Every public fixture must still parse: the textual private-key scan must
        // not trip on a tpub/xpub body. The `prv` prefixes never start a key in a
        // watch-only descriptor, and the key-boundary characters (`(`, `,`, `]`)
        // never appear inside a Base58 key, so a valid descriptor cannot trip it.
        let mut cases: Vec<&str> = singlesig_fixtures().to_vec();
        cases.extend([
            fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"),
            fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"),
            fixture!("descriptors/multisig/multipath_2of3.txt"),
            fixture!("descriptors/taproot/tr_keypath.txt"),
            fixture!("descriptors/taproot/tr_scriptpath_multi_a.txt"),
            fixture!("descriptors/timelock/liana_basic.txt"),
        ]);
        for text in cases {
            parse_descriptor(text).unwrap_or_else(|e| panic!("watch-only must parse {text}: {e}"));
        }
    }

    #[test]
    fn taproot_descriptors_parse_as_first_class_descriptors() {
        let keypath = parse_descriptor(fixture!("descriptors/taproot/tr_keypath.txt"))
            .expect("taproot key-path fixture must parse");
        assert!(keypath.is_taproot());
        assert_eq!(keypath.descriptor_type(), DescriptorType::Tr);
        assert!(!keypath.is_singlesig());
        assert!(keypath.multisig_info().is_none());
        assert!(!keypath.is_multisig());
        assert_eq!(keypath.checksum_status(), ChecksumStatus::Present);
        assert!(
            parse_descriptor(keypath.canonical())
                .expect("canonical re-parses")
                .is_taproot(),
            "canonical form is still taproot: {}",
            keypath.canonical()
        );

        let scriptpath =
            parse_descriptor(fixture!("descriptors/taproot/tr_scriptpath_multi_a.txt"))
                .expect("taproot script-path fixture must parse");
        assert!(scriptpath.is_taproot());
        assert_eq!(scriptpath.descriptor_type(), DescriptorType::Tr);
        let info = scriptpath
            .multisig_info()
            .expect("single multi_a leaf exposes M-of-N");
        assert_eq!((info.threshold(), info.key_count()), (2, 2));
        assert_eq!(info.kind(), MultisigKind::MultiA);
        assert_eq!(info.kind().as_str(), "multi_a");
        assert!(!info.is_sorted_multi());
        assert!(scriptpath.is_multisig());
        assert_eq!(scriptpath.key_origins().len(), 3);

        // Non-Taproot descriptors are not marked as Taproot.
        for text in singlesig_fixtures() {
            assert!(!parse_descriptor(text).expect("parses").is_taproot());
        }
        assert!(
            !parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"))
                .expect("parses")
                .is_taproot()
        );
    }

    #[test]
    fn taproot_multi_a_quorum_bounds_are_checked_before_parse() {
        let keys = fixture_2of3_keys();
        let desc = format!("tr({},multi_a(3,{},{}))", keys[0], keys[1], keys[2]);
        let err = parse_descriptor(&desc).expect_err("M>N multi_a must be rejected");
        assert_eq!(err.code(), ErrorCode::ThresholdExceedsKeys);
    }

    // ---- US-011: network inference + SLIP-132 normalization ----

    /// SLIP-132 mainnet native-segwit public version bytes (`zpub`), used to mint
    /// a SLIP-132 test key from fixture material.
    const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
    /// SLIP-132 testnet native-segwit public version bytes (`vpub`).
    const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

    /// A valid testnet `tpub` lifted from a fixture key (no `[origin]`, no path),
    /// used as raw key material to mint version-byte variants. Avoids hardcoding a
    /// Base58 literal, whose checksum is easy to get wrong.
    fn fixture_tpub() -> String {
        let parsed = parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"))
            .expect("2of3 fixture parses");
        parsed.key_origins()[0]
            .xpub()
            .expect("fixture key is an xpub")
            .to_string()
    }

    /// Re-version an extended key: decode Base58Check, overwrite the 4 version
    /// bytes, re-encode (which recomputes the checksum). The key material is left
    /// untouched, so only the network/script-type the prefix advertises changes.
    fn reversion(extended_key: &str, version: [u8; 4]) -> String {
        let mut decoded = base58::decode_check(extended_key).expect("valid base58 ext key");
        decoded[..4].copy_from_slice(&version);
        base58::encode_check(&decoded)
    }

    #[test]
    fn infers_mainnet_from_xpub_version_bytes() {
        let xpub = reversion(&fixture_tpub(), XPUB_VERSION);
        assert!(xpub.starts_with("xpub"));
        let parsed =
            parse_descriptor(&format!("wpkh({xpub}/0/*)")).expect("xpub descriptor parses");
        assert_eq!(
            parsed.network_inference(),
            NetworkInference::Determined(Network::Bitcoin)
        );
        assert_eq!(parsed.network(), Some(Network::Bitcoin));
        assert!(parsed.network_inference().is_determinable());
        assert_eq!(
            parsed.network_inference().candidates(),
            vec![Network::Bitcoin]
        );
    }

    #[test]
    fn infers_ambiguous_test_network_from_tpub() {
        // testnet/signet/regtest share `tpub` version bytes, so the network is
        // ambiguous and must not be guessed (PRD §9.1 F2 / §16.5 condition 1).
        let parsed =
            parse_descriptor(&format!("wpkh({}/0/*)", fixture_tpub())).expect("tpub parses");
        assert_eq!(
            parsed.network_inference(),
            NetworkInference::AmbiguousTestNetwork
        );
        assert_eq!(parsed.network(), None);
        assert!(!parsed.network_inference().is_determinable());
        assert_eq!(
            parsed.network_inference().candidates(),
            vec![Network::Testnet, Network::Signet, Network::Regtest]
        );
    }

    #[test]
    fn multisig_fixture_infers_ambiguous_test_network() {
        // The committed fixtures are all testnet (`tpub`) per the fixtures rule.
        for (text, _, _) in multisig_fixtures() {
            let parsed = parse_descriptor(text).expect("multisig fixture parses");
            assert_eq!(
                parsed.network_inference(),
                NetworkInference::AmbiguousTestNetwork,
                "network for {text}"
            );
        }
    }

    #[test]
    fn raw_pubkey_descriptor_has_no_inferable_network() {
        // A raw compressed public key carries no version bytes at all. The 33-byte
        // key data is the tail of the decoded extended key (bytes 45..78).
        use std::fmt::Write as _;
        let decoded = base58::decode_check(&fixture_tpub()).expect("decode tpub");
        let mut pubkey_hex = String::with_capacity(66);
        for byte in &decoded[45..78] {
            write!(pubkey_hex, "{byte:02x}").expect("writing hex into a String never fails");
        }
        let parsed = parse_descriptor(&format!("wpkh({pubkey_hex})")).expect("raw-key parses");
        assert_eq!(parsed.network_inference(), NetworkInference::NoExtendedKeys);
        assert_eq!(parsed.network(), None);
        assert!(!parsed.network_inference().is_determinable());
        assert!(parsed.network_inference().candidates().is_empty());
    }

    #[test]
    fn normalizes_slip132_zpub_to_mainnet_xpub() {
        let zpub = reversion(&fixture_tpub(), ZPUB_VERSION);
        let xpub = reversion(&fixture_tpub(), XPUB_VERSION);
        assert!(zpub.starts_with("zpub") && xpub.starts_with("xpub"));

        let result = normalize_slip132(&format!("wpkh({zpub}/0/*)")).expect("normalizes");
        assert!(result.changed());
        assert_eq!(result.normalized_keys(), 1);
        assert!(
            result.descriptor().contains(xpub.as_str()),
            "expected xpub in {}",
            result.descriptor()
        );
        assert!(!result.descriptor().contains("zpub"));

        // The normalized descriptor parses and now infers mainnet.
        let parsed = parse_descriptor(result.descriptor()).expect("normalized parses");
        assert_eq!(parsed.network(), Some(Network::Bitcoin));
    }

    #[test]
    fn normalizes_slip132_vpub_to_testnet_tpub() {
        let tpub = fixture_tpub();
        let vpub = reversion(&tpub, VPUB_VERSION);
        assert!(vpub.starts_with("vpub"));

        let result = normalize_slip132(&format!("wpkh({vpub}/0/*)")).expect("normalizes");
        assert!(result.changed());
        // vpub and tpub share key material, so it round-trips back to the tpub.
        assert!(
            result.descriptor().contains(tpub.as_str()),
            "expected tpub in {}",
            result.descriptor()
        );

        let parsed = parse_descriptor(result.descriptor()).expect("normalized parses");
        assert_eq!(
            parsed.network_inference(),
            NetworkInference::AmbiguousTestNetwork
        );
    }

    #[test]
    fn normalize_slip132_leaves_standard_descriptors_unchanged() {
        // A standard `tpub` descriptor has no SLIP-132 key to rewrite.
        let input = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let result = normalize_slip132(input).expect("normalizes");
        assert!(!result.changed());
        assert_eq!(result.normalized_keys(), 0);
        assert_eq!(result.descriptor(), input);
    }

    #[test]
    fn normalize_slip132_rejects_blank_input() {
        for blank in ["", "   ", "\n\t "] {
            assert_eq!(
                normalize_slip132(blank)
                    .expect_err("blank must error")
                    .code(),
                ErrorCode::InputEmpty
            );
        }
    }
}
