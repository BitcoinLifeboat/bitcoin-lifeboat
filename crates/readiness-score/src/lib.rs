//! `readiness-score` — recovery-readiness checks, scoring, and status mapping.
//!
//! This crate is the **scoring/orchestration layer**: it consumes the typed
//! *facts* produced by [`descriptor_audit`] and [`address_derive`] and turns them
//! into the user-facing readiness verdict described in PRD §9.1 and §16. The
//! analysis crates never score; this crate never re-parses or re-derives the
//! Bitcoin primitives (it only calls their public entry points).
//!
//! It is built up story by story (see `docs/PRD-v2.md`):
//! - **US-019 (this module): the §9.1 analysis checks A–G** —
//!   [`run_checks`] evaluates checks A1–A4, B1–B2, C1–C4, D1–D5, E1–E4, F1–F2,
//!   G1–G3 and returns the §19.1 `checks[]` list. Each [`Check`] carries a stable
//!   `code`, a snake_case `category`, a human-readable `title`, and a
//!   [`CheckResult`] (`pass` / `warn` / `fail` / `na` / `unknown`).
//! - **US-020 (this module): the recovery checklist H1–H9 and the §16.3 critical
//!   failures** — [`evaluate_critical_failures`] turns the [`Check`] results plus
//!   the user-supplied [`CriticalContext`] (parse outcome, [`RecoveryChecklist`],
//!   passphrase status, detector verdict) into the twelve [`CriticalCode`]s, and
//!   [`forced_status`] reports the **Not Ready** that any critical forces
//!   (regardless of the numeric score). E.g. `A1 == Fail` ⇒ `C-DESC-PARSE-FAIL`,
//!   `D4 == Fail` ⇒ `C-DUPLICATE-XPUB`.
//! - **US-021 (this module): the §16.4 warning weights and the numeric score** —
//!   [`compute_score`] starts at 100, subtracts each fired [`WarningCode`]'s fixed
//!   [`WarningCode::impact`] (e.g. `A2 == Warn` ⇒ `W-NO-DESC-CHECKSUM` (-5),
//!   `E2 == Warn` ⇒ `W-NO-CHANGE-DESC` (-15)), clamps to `[0, 100]`, and returns the
//!   [`ScoringResult`] (the numeric score plus the §16.7 `scoring_audit` trail).
//! - **US-022 (this module): the §16.2 headline status, §16.5 *Cannot
//!   Determine*, and §16.6 survivability** — [`map_status`] turns the numeric
//!   score, the [`CriticalIssue`] list, and the §16.5 signals into the headline
//!   [`ReadinessStatus`] (criticals force `Not Ready`; the four §16.5 conditions
//!   yield `Cannot Determine`; otherwise the numeric band, with `Ready` gated on
//!   the D8 known-address match). [`compute_survivability`] computes the §16.6
//!   multisig survivability dimension (`lose_1_signer` / `lose_2_signers` /
//!   `lose_descriptor_only`).
//!
//! # Check semantics (the `pass`/`warn`/`fail`/`na`/`unknown` choice)
//! A check result is independent of the numeric weight applied later. The
//! mapping mirrors §16:
//! - `fail` — a §16.3 critical condition (parse failure, duplicate xpub, address
//!   mismatch, declared-type mismatch, threshold below key count).
//! - `warn` — a §16.4 deduction condition (missing checksum, missing change
//!   descriptor, inconsistent markers, non-standard derivation).
//! - `na` — the check does not apply to this descriptor (e.g. a multisig-only
//!   check on a singlesig wallet, or a checksum-validity check when none is
//!   present).
//! - `unknown` — the inputs were insufficient to decide (e.g. a `tpub` descriptor
//!   whose network is genuinely ambiguous across testnet/signet/regtest, or
//!   derivation requested without a resolved network).
//!
//! # Invariants
//! - **No panics; the whole crate is infallible.** [`run_checks`] and
//!   [`compute_score`] never return `Result`: an upstream error (e.g. a derivation
//!   that refuses to proceed) becomes a `fail`/`unknown` check result, never a
//!   propagated error. The numeric weights live only in [`WarningCode::impact`].

use address_derive::{compare_known_address, derive_addresses, derive_chain, Chain, Network};
use descriptor_audit::{
    normalize, ChecksumStatus, KeyOrigin, MultisigInfo, ParsedDescriptor, StandardPath,
};
use error_taxonomy::ErrorCode;
use miniscript::descriptor::DescriptorType;

/// Default number of receive/change addresses derived for checks G1/G2 (PRD §17.4).
pub const DEFAULT_ADDRESS_COUNT: u32 = 10;

/// Largest key count `N` accepted in an `M-of-N` multisig (PRD §9.1 D5 / §16.3):
/// a quorum must satisfy `1 <= M <= N <= 15`.
const MAX_MULTISIG_KEYS: usize = 15;

/// The outcome of a single §9.1 readiness check.
///
/// Serializes to the lowercase strings used in the §19.1 `checks[].result` field:
/// `"pass"`, `"warn"`, `"fail"`, `"na"`, `"unknown"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    /// The check passed.
    Pass,
    /// The check surfaced a non-fatal concern (maps to a §16.4 warning in US-021).
    Warn,
    /// The check surfaced a critical problem (maps to a §16.3 critical in US-020).
    Fail,
    /// The check does not apply to this descriptor.
    Na,
    /// The available inputs were insufficient to decide.
    Unknown,
}

/// One §9.1 analysis check and its result, as it appears in the §19.1 `checks[]`
/// array: `{"code":"A1","category":"descriptor_parse","result":"pass","title":"…"}`.
///
/// This is a crate-owned `serde` type (the established convention for any value
/// that crosses the Tauri → JS boundary, see the detector / `address-derive`
/// crates), with field order matching the §19.1 example.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Check {
    /// Stable check code, e.g. `"A1"`, `"E2"`. Never reordered or renamed.
    pub code: String,
    /// Snake_case category grouping, e.g. `"descriptor_parse"`, `"change_descriptor"`.
    pub category: String,
    /// The check's outcome.
    pub result: CheckResult,
    /// Human-readable check title (PRD §9.1 wording).
    pub title: String,
}

/// The wallet type a user declared in the wizard, used for the B2 cross-check
/// (PRD §9.1 B2 / §16.3 `C-WALLET-TYPE-MISMATCH`).
///
/// Modeled as the wizard's primary fork (singlesig vs multisig); finer
/// script-type matching can extend this later. Deserializes from `"singlesig"` /
/// `"multisig"` for the Tauri command / CLI flag that carries the user's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredWalletType {
    /// The user said their wallet is single-signature.
    Singlesig,
    /// The user said their wallet is multisig.
    Multisig,
}

/// Inputs to [`run_checks`].
///
/// Construct from a parsed descriptor with [`CheckInput::new`] (or
/// [`CheckInput::parse_failed`] when parsing failed), then attach the optional
/// user context with the `with_*` builders. Defaults: address count
/// [`DEFAULT_ADDRESS_COUNT`], no declared type, no change descriptor, no known
/// address, network unconfirmed, network unset (derivation checks resolve it from
/// the descriptor when uniquely inferable).
#[derive(Debug, Clone, Copy)]
pub struct CheckInput<'a> {
    descriptor: Option<&'a ParsedDescriptor>,
    change_descriptor: Option<&'a ParsedDescriptor>,
    network: Option<Network>,
    address_count: u32,
    declared_wallet_type: Option<DeclaredWalletType>,
    network_confirmed: bool,
    known_address: Option<&'a str>,
}

impl<'a> CheckInput<'a> {
    /// Build the inputs for a descriptor that parsed successfully.
    #[must_use]
    pub fn new(descriptor: &'a ParsedDescriptor) -> Self {
        Self {
            descriptor: Some(descriptor),
            change_descriptor: None,
            network: None,
            address_count: DEFAULT_ADDRESS_COUNT,
            declared_wallet_type: None,
            network_confirmed: false,
            known_address: None,
        }
    }

    /// Build the inputs for input that failed to parse: A1 reports `fail` and
    /// every downstream check is `na` (nothing can be evaluated without a parse).
    #[must_use]
    pub fn parse_failed() -> Self {
        Self {
            descriptor: None,
            change_descriptor: None,
            network: None,
            address_count: DEFAULT_ADDRESS_COUNT,
            declared_wallet_type: None,
            network_confirmed: false,
            known_address: None,
        }
    }

    /// Set the network used for address derivation (checks G1–G3). The caller
    /// resolves the §16.5 ambiguity (a `tpub` is testnet/signet/regtest) and
    /// passes the chosen network here.
    #[must_use]
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Attach an explicitly-supplied change descriptor (the "Add change
    /// descriptor" flow), for checks E2–E4 and G2.
    #[must_use]
    pub fn with_change_descriptor(mut self, change: &'a ParsedDescriptor) -> Self {
        self.change_descriptor = Some(change);
        self
    }

    /// Record the wallet type the user declared, for the B2 cross-check.
    #[must_use]
    pub fn with_declared_wallet_type(mut self, declared: DeclaredWalletType) -> Self {
        self.declared_wallet_type = Some(declared);
        self
    }

    /// Record that the user confirmed the network (check F2), relevant only when
    /// the network is not determinable from the descriptor.
    #[must_use]
    pub fn with_network_confirmed(mut self, confirmed: bool) -> Self {
        self.network_confirmed = confirmed;
        self
    }

    /// Attach a known address to compare against the derived range (check G3).
    #[must_use]
    pub fn with_known_address(mut self, address: &'a str) -> Self {
        self.known_address = Some(address);
        self
    }

    /// Override the number of addresses derived for G1/G2 (default
    /// [`DEFAULT_ADDRESS_COUNT`]).
    #[must_use]
    pub fn with_address_count(mut self, count: u32) -> Self {
        self.address_count = count;
        self
    }
}

/// The §9.1 checks in fixed order, as `(code, category, title)`. This is the
/// single source of truth for check metadata; [`compute_results`] produces a
/// result for each entry, in the same order.
const CATALOG: [(&str, &str, &str); 24] = [
    ("A1", "descriptor_parse", "Descriptor parses as BIP380"),
    ("A2", "descriptor_checksum", "Descriptor checksum present"),
    ("A3", "descriptor_checksum", "Descriptor checksum valid"),
    (
        "A4",
        "normalization",
        "Descriptor canonical form matches user input",
    ),
    ("B1", "script_type", "Script type identified"),
    (
        "B2",
        "script_type",
        "Script type matches declared wallet type",
    ),
    (
        "C1",
        "key_origin",
        "Master fingerprint present for every key",
    ),
    ("C2", "key_origin", "Derivation path present for every key"),
    ("C3", "key_origin", "Hardened markers consistent (h vs ')"),
    (
        "C4",
        "key_origin",
        "Account-level derivation looks standard",
    ),
    ("D1", "wallet_type", "Wallet type detected"),
    (
        "D2",
        "multisig_quorum",
        "Multisig threshold and key count extracted",
    ),
    (
        "D3",
        "multisig_quorum",
        "Multisig sortedmulti vs multi flagged",
    ),
    ("D4", "multisig_quorum", "No duplicate xpubs"),
    (
        "D5",
        "multisig_quorum",
        "Multisig threshold sanity (1 <= M <= N <= 15)",
    ),
    ("E1", "receive_descriptor", "Receive descriptor present"),
    ("E2", "change_descriptor", "Change descriptor present"),
    (
        "E3",
        "change_descriptor",
        "Receive and change derive same script type",
    ),
    (
        "E4",
        "change_descriptor",
        "Receive and change differ only in chain index",
    ),
    ("F1", "network", "Network determinable from descriptor"),
    ("F2", "network", "User confirmed network"),
    (
        "G1",
        "address_derivation",
        "First N receive addresses derive without error",
    ),
    (
        "G2",
        "address_derivation",
        "First N change addresses derive without error",
    ),
    (
        "G3",
        "address_derivation",
        "Known address matches a derived address",
    ),
];

/// Run the PRD §9.1 analysis checks A–G and return the §19.1 `checks[]` list.
///
/// The result always has exactly 24 entries in the fixed order A1..G3. This is
/// infallible: insufficient inputs or upstream derivation refusals are reported
/// as [`CheckResult::Unknown`] / [`CheckResult::Fail`], never as an error.
#[must_use]
pub fn run_checks(input: &CheckInput) -> Vec<Check> {
    let results = compute_results(input);
    CATALOG
        .iter()
        .zip(results)
        .map(|(&(code, category, title), result)| Check {
            code: code.to_owned(),
            category: category.to_owned(),
            result,
            title: title.to_owned(),
        })
        .collect()
}

/// Compute the result of each check in [`CATALOG`] order.
fn compute_results(input: &CheckInput) -> [CheckResult; 24] {
    use CheckResult::{Fail, Na, Pass, Unknown, Warn};

    let Some(parsed) = input.descriptor else {
        // Parsing failed (C-DESC-PARSE-FAIL): A1 fails; nothing downstream can be
        // evaluated without a parsed descriptor.
        let mut results = [Na; 24];
        results[0] = Fail;
        return results;
    };

    // --- A. Descriptor parse ---
    let a1 = Pass; // a `ParsedDescriptor` exists ⇒ it parsed as a BIP380 expression.
    let checksum_present = matches!(parsed.checksum_status(), ChecksumStatus::Present);
    let a2 = if checksum_present { Pass } else { Warn };
    // An *invalid* checksum is fatal at parse time (E-PARSE-003), so a present
    // checksum on a `ParsedDescriptor` is always valid; absent ⇒ not applicable.
    let a3 = if checksum_present { Pass } else { Na };
    let a4 = a4_round_trip(parsed);

    // --- B. Script type ---
    let b1 = Pass; // miniscript always classifies a parsed descriptor's script type.
    let b2 = b2_matches_declared(parsed, input.declared_wallet_type);

    // --- C. Key origin ---
    let origins = parsed.key_origins();
    let c1 = all_keys(&origins, KeyOrigin::has_fingerprint);
    let c2 = all_keys(&origins, KeyOrigin::has_derivation_path);
    let c3 = if parsed.hardened_markers_consistent() {
        Pass
    } else {
        Warn
    };
    let c4 = c4_standard_paths(parsed, &origins);

    // --- D. Singlesig vs multisig ---
    let d1 = if wallet_type_detected(parsed) {
        Pass
    } else {
        Unknown
    };
    let ms = parsed.multisig_info();
    let (d2, d3, d4, d5) = match ms.as_ref() {
        None => (Na, Na, Na, Na),
        Some(m) => (
            Pass, // threshold M and key count N are extracted.
            Pass, // multi vs sortedmulti is classified.
            if m.has_duplicate_keys() { Fail } else { Pass },
            if threshold_in_bounds(m) { Pass } else { Fail },
        ),
    };

    // --- E. Receive + change ---
    let e1 = Pass; // the parsed descriptor is the receive descriptor.
    let has_change = parsed.uses_multipath() || input.change_descriptor.is_some();
    let e2 = if has_change { Pass } else { Warn };
    let e3 = e3_same_script_type(parsed, input.change_descriptor);
    let e4 = e4_chain_index_only(parsed, input.change_descriptor);

    // --- F. Network ---
    let determinable = parsed.network_inference().is_determinable();
    let f1 = if determinable { Pass } else { Unknown };
    let f2 = if determinable {
        Na // no confirmation needed when the network is uniquely inferable.
    } else if input.network_confirmed {
        Pass
    } else {
        Unknown
    };

    // --- G. Address derivation ---
    let (g1, g2, g3) = address_checks(parsed, input);

    [
        a1, a2, a3, a4, b1, b2, c1, c2, c3, c4, d1, d2, d3, d4, d5, e1, e2, e3, e4, f1, f2, g1, g2,
        g3,
    ]
}

/// A4 — the canonical form is a stable normalization fixed point and the user's
/// raw input matches it after normalization (the §9.1 "normalization round-trip";
/// a literal `raw == canonical` would fail for every descriptor written with `'`
/// markers or without a checksum, which is not the intent).
fn a4_round_trip(parsed: &ParsedDescriptor) -> CheckResult {
    let canonical = parsed.canonical();
    match (normalize(parsed.raw()), normalize(canonical)) {
        (Ok(from_raw), Ok(from_canonical))
            if from_raw == canonical && from_canonical == canonical =>
        {
            CheckResult::Pass
        }
        // Unreachable for an already-parsed descriptor, but kept honest.
        _ => CheckResult::Fail,
    }
}

/// B2 — the descriptor's script type agrees with the user-declared wallet type.
/// `na` when nothing was declared; a clear singlesig/multisig contradiction is a
/// `fail` (`C-WALLET-TYPE-MISMATCH`); ambiguous shapes (Taproot, richer policies)
/// are not failed against a declaration to avoid a false mismatch.
fn b2_matches_declared(
    parsed: &ParsedDescriptor,
    declared: Option<DeclaredWalletType>,
) -> CheckResult {
    use CheckResult::{Fail, Na, Pass};
    match declared {
        None => Na,
        Some(DeclaredWalletType::Singlesig) => {
            if parsed.is_multisig() {
                Fail
            } else {
                Pass
            }
        }
        Some(DeclaredWalletType::Multisig) => {
            if parsed.is_multisig() {
                Pass
            } else if parsed.is_singlesig() {
                Fail
            } else {
                Pass
            }
        }
    }
}

/// C1/C2 — every key satisfies `pred`. `unknown` when there are no keys to assess
/// (degenerate), `pass` when all satisfy it, `warn` otherwise.
fn all_keys(origins: &[KeyOrigin], pred: impl Fn(&KeyOrigin) -> bool) -> CheckResult {
    if origins.is_empty() {
        return CheckResult::Unknown;
    }
    if origins.iter().all(pred) {
        CheckResult::Pass
    } else {
        CheckResult::Warn
    }
}

/// C4 — every key with an origin path uses a recognized standard scheme
/// (BIP44/49/84/86/48) **and** that scheme matches the descriptor's script type
/// (the §17.6 item-6 cross-check, deferred to the scoring layer by
/// `descriptor-audit`). `na` when no key carries a path; `warn` on the first
/// non-standard or mismatched path.
fn c4_standard_paths(parsed: &ParsedDescriptor, origins: &[KeyOrigin]) -> CheckResult {
    let expected = expected_scheme(parsed);
    let mut assessed = 0usize;
    for origin in origins.iter().filter(|o| o.has_derivation_path()) {
        assessed += 1;
        match origin.standard_path() {
            None => return CheckResult::Warn,
            Some(scheme) => {
                if let Some(exp) = expected {
                    if scheme != exp {
                        return CheckResult::Warn;
                    }
                }
            }
        }
    }
    if assessed == 0 {
        CheckResult::Na
    } else {
        CheckResult::Pass
    }
}

/// The derivation scheme expected for a descriptor's script type, or `None` when
/// the script type has no conventional scheme (so C4 only checks "is standard").
fn expected_scheme(parsed: &ParsedDescriptor) -> Option<StandardPath> {
    // Taproot multi_a is both Taproot and multisig-shaped; Taproot's BIP86
    // convention wins over the legacy P2WSH multisig BIP48 convention.
    if parsed.is_taproot() {
        return Some(StandardPath::Bip86);
    }
    if parsed.is_multisig() {
        return Some(StandardPath::Bip48);
    }
    match parsed.descriptor_type() {
        DescriptorType::Pkh => Some(StandardPath::Bip44),
        DescriptorType::ShWpkh => Some(StandardPath::Bip49),
        DescriptorType::Wpkh => Some(StandardPath::Bip84),
        _ => None,
    }
}

/// D1 — whether the wallet type was classified (singlesig, multisig, Taproot, or
/// timelock Miniscript).
fn wallet_type_detected(parsed: &ParsedDescriptor) -> bool {
    parsed.is_singlesig() || parsed.is_multisig() || parsed.is_taproot() || parsed.uses_timelock()
}

/// D5 — `1 <= M <= N <= 15`.
fn threshold_in_bounds(info: &MultisigInfo) -> bool {
    let m = info.threshold();
    let n = info.key_count();
    m >= 1 && m <= n && n <= MAX_MULTISIG_KEYS
}

/// E3 — receive and change derive the same script type. Driven by multipath
/// expansion (branches differ only in the derivation index) or an explicit pair.
fn e3_same_script_type(
    parsed: &ParsedDescriptor,
    change: Option<&ParsedDescriptor>,
) -> CheckResult {
    use CheckResult::{Fail, Na, Pass, Unknown};
    if parsed.uses_multipath() {
        match parsed.expand_multipath() {
            Ok(branches) if branches.len() >= 2 => {
                if branches[0].desc_type() == branches[1].desc_type() {
                    Pass
                } else {
                    Fail
                }
            }
            Ok(_) => Na, // single-branch multipath ⇒ no change branch.
            Err(_) => Unknown,
        }
    } else if let Some(change) = change {
        if parsed.descriptor_type() == change.descriptor_type() {
            Pass
        } else {
            Fail
        }
    } else {
        Na
    }
}

/// E4 — receive and change differ only in the BIP44 chain index. A BIP389
/// `<0;1>` multipath guarantees this by construction (the two branches are the
/// same descriptor with only the multipath index differing). Rigorous diffing of
/// an explicitly-supplied pair is deferred ⇒ `unknown` for that case.
fn e4_chain_index_only(
    parsed: &ParsedDescriptor,
    change: Option<&ParsedDescriptor>,
) -> CheckResult {
    use CheckResult::{Na, Pass, Unknown, Warn};
    if parsed.uses_multipath() {
        match parsed.expand_multipath() {
            Ok(branches) if branches.len() == 2 => Pass,
            Ok(branches) if branches.len() < 2 => Na,
            Ok(_) => Warn, // more than two parallel paths ⇒ not a simple receive/change pair.
            Err(_) => Unknown,
        }
    } else if change.is_some() {
        Unknown
    } else {
        Na
    }
}

/// G1/G2/G3 — derive receive and change addresses and compare a known address.
/// Returns `(g1, g2, g3)`.
fn address_checks(
    parsed: &ParsedDescriptor,
    input: &CheckInput,
) -> (CheckResult, CheckResult, CheckResult) {
    use CheckResult::{Fail, Na, Pass, Unknown};

    let has_change = parsed.uses_multipath() || input.change_descriptor.is_some();
    let has_known = input.known_address.is_some();

    // Resolve the network to derive on: caller override, else a uniquely-inferred
    // network. A `tpub` descriptor is ambiguous (testnet/signet/regtest), so
    // without a caller-supplied network the G checks cannot run.
    let Some(network) = input.network.or_else(|| parsed.network()) else {
        let g2 = if has_change { Unknown } else { Na };
        let g3 = if has_known { Unknown } else { Na };
        return (Unknown, g2, g3);
    };

    // A fixed (no-`*`) descriptor describes exactly one address; derive just that.
    let has_wildcard = parsed.descriptor().has_wildcard();
    let count = if has_wildcard {
        input.address_count.max(1)
    } else {
        1
    };

    // G1 (and the multipath change branch) via the multipath-aware entry.
    let derived = derive_addresses(parsed, network, count);
    let g1 = match &derived {
        Ok(addrs) if addrs.receive_derived.len() == count as usize => Pass,
        _ => Fail,
    };

    let g2 = if parsed.uses_multipath() {
        match &derived {
            Ok(addrs) if !addrs.change_derived.is_empty() => Pass,
            _ => Fail,
        }
    } else if let Some(change) = input.change_descriptor {
        let change_count = if change.descriptor().has_wildcard() {
            input.address_count.max(1)
        } else {
            1
        };
        match derive_chain(change.descriptor(), network, Chain::Change, change_count) {
            Ok(addrs) if !addrs.is_empty() => Pass,
            _ => Fail,
        }
    } else {
        Na
    };

    let g3 = match input.known_address {
        None => Na,
        Some(address) => match compare_known_address(parsed, network, address, count) {
            Ok(found) if found.matched => Pass,
            // Searched receive + change out to 1000 and found no match ⇒ the
            // §16.3 C-ADDRESS-MISMATCH condition.
            Ok(_) => Fail,
            // The address did not parse or is for the wrong network ⇒ cannot decide.
            Err(_) => Unknown,
        },
    };

    (g1, g2, g3)
}

// ===========================================================================
// US-020 — §9.1 recovery checklist (H1–H9) and the §16.3 critical failures
// ===========================================================================
//
// `run_checks` (US-019) grades each A–G check; this layer turns those facts plus
// the user-supplied recovery context into the PRD §16.3 *critical failures*. Per
// §16.3, **any** critical present forces the headline status to `Not Ready`
// regardless of the numeric score (US-021). The fact→scoring split holds: the
// analysis crates expose facts, `run_checks` grades them, and only here are the
// `C-*` codes assigned and the forced status derived.

/// An answer to a §9.1 H-series recovery-completeness question.
///
/// H1–H3 are `yes`/`no`/`unsure`; H4–H9 are `yes`/`no` (the wizard never offers
/// `Unsure` for those, but the shared type harmlessly allows it). Serializes
/// snake_case → `"yes"` / `"no"` / `"unsure"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// The user answered yes.
    Yes,
    /// The user answered no.
    No,
    /// The user was unsure (H1–H3 only).
    Unsure,
}

/// The §9.1 section-H recovery-completeness checklist (user-answered).
///
/// US-020 accepts these as scoring inputs. The only §16.3 critical that depends
/// on this section is the passphrase one — and that is modeled precisely by the
/// separate [`Passphrase`] signal (see [`CriticalContext::with_passphrase`]),
/// because H4 (yes/no "documented *whether* a passphrase exists") cannot by
/// itself express "a passphrase exists **and** the heir packet omits it". US-021
/// reads the rest of this checklist to apply the §16.4 warning weights (e.g. H9
/// `No` ⇒ `W-NO-RECENT-DRILL`).
///
/// Every field is `Option<Answer>`; `None` means "not answered" — the wizard was
/// aborted, or the question does not apply (H2/H3 on a singlesig wallet). Crate-
/// owned `serde` type (the JS-boundary convention); the wizard / CLI deserialize
/// the user's answers into it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryChecklist {
    /// H1 — at least two physical copies of recovery materials exist.
    pub physical_copies: Option<Answer>,
    /// H2 — the user can name where each signer is located *(multisig only)*.
    pub signer_locations_known: Option<Answer>,
    /// H3 — at least M of N signers were tested in the last 12 months *(multisig only)*.
    pub signers_tested_recently: Option<Answer>,
    /// H4 — the user has documented whether a passphrase exists.
    pub passphrase_documented: Option<Answer>,
    /// H5 — the wallet software needed for recovery is documented locally.
    pub wallet_software_documented: Option<Answer>,
    /// H6 — the gap-limit setting is documented.
    pub gap_limit_documented: Option<Answer>,
    /// H7 — the wallet birth height or creation date is documented.
    pub birth_height_documented: Option<Answer>,
    /// H8 — heir/executor instructions are written down.
    pub heir_instructions_written: Option<Answer>,
    /// H9 — a recovery drill was run in the last 12 months.
    pub recent_drill: Option<Answer>,
}

/// Whether a BIP39 passphrase protects the wallet and, if so, whether the heir
/// instructions explain it — the precise signal behind §16.3
/// `C-PASSPHRASE-UNDOCUMENTED`.
///
/// The wizard's passphrase sub-flow ("Does a passphrase protect this wallet?" →
/// if yes, "Do your heir instructions explain it and where to find it?")
/// populates this directly. Only [`Passphrase::Undocumented`] is a critical; the
/// other two are safe states. Serializes snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Passphrase {
    /// No passphrase protects the wallet.
    Absent,
    /// A passphrase exists and the heir instructions explain it.
    Documented,
    /// A passphrase exists but the heir instructions do not mention it.
    Undocumented,
}

/// A PRD §16.3 critical-failure code. Any critical present forces the headline
/// status to [`ReadinessStatus::NotReady`] (see [`forced_status`]).
///
/// Serializes to its stable string code (`"C-DESC-PARSE-FAIL"`, …) via the
/// per-variant `serde(rename = …)`, kept in lockstep with [`CriticalCode::as_str`]
/// by a parity test. These are **scoring-layer** codes, distinct from the
/// Appendix C `E-*` errors: some §16.3 conditions double as a parse error (e.g.
/// `C-DESC-CHECKSUM-INVALID` ↔ `E-PARSE-003`, `C-DESC-CONTAINS-XPRV` ↔
/// `E-PARSE-005`), in which case the parser refuses with the `E-*` code and this
/// layer still emits the `C-*` critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CriticalCode {
    /// `C-DESC-PARSE-FAIL` — the descriptor is not a valid BIP380 expression.
    #[serde(rename = "C-DESC-PARSE-FAIL")]
    DescParseFail,
    /// `C-DESC-CHECKSUM-INVALID` — a present `#checksum` does not match.
    #[serde(rename = "C-DESC-CHECKSUM-INVALID")]
    DescChecksumInvalid,
    /// `C-MULTISIG-NO-DESCRIPTOR` — declared multisig but no quorum descriptor.
    #[serde(rename = "C-MULTISIG-NO-DESCRIPTOR")]
    MultisigNoDescriptor,
    /// `C-MULTISIG-THRESHOLD-MISSING` — multisig threshold cannot be determined.
    #[serde(rename = "C-MULTISIG-THRESHOLD-MISSING")]
    MultisigThresholdMissing,
    /// `C-KEY-COUNT-BELOW-THRESHOLD` — threshold M exceeds key count N.
    #[serde(rename = "C-KEY-COUNT-BELOW-THRESHOLD")]
    KeyCountBelowThreshold,
    /// `C-DUPLICATE-XPUB` — the same xpub appears more than once.
    #[serde(rename = "C-DUPLICATE-XPUB")]
    DuplicateXpub,
    /// `C-ADDRESS-MISMATCH` — a known address matches no derived address.
    #[serde(rename = "C-ADDRESS-MISMATCH")]
    AddressMismatch,
    /// `C-WALLET-TYPE-MISMATCH` — declared type contradicts the script type.
    #[serde(rename = "C-WALLET-TYPE-MISMATCH")]
    WalletTypeMismatch,
    /// `C-CHANGE-DESC-REQUIRED-MISSING` — a required change descriptor is absent.
    #[serde(rename = "C-CHANGE-DESC-REQUIRED-MISSING")]
    ChangeDescRequiredMissing,
    /// `C-PASSPHRASE-UNDOCUMENTED` — a passphrase exists but the heir packet omits it.
    #[serde(rename = "C-PASSPHRASE-UNDOCUMENTED")]
    PassphraseUndocumented,
    /// `C-SECRET-DETECTED` — the sensitive-input detector blocked a real secret.
    #[serde(rename = "C-SECRET-DETECTED")]
    SecretDetected,
    /// `C-DESC-CONTAINS-XPRV` — the descriptor embeds an extended private key.
    #[serde(rename = "C-DESC-CONTAINS-XPRV")]
    DescContainsXprv,
}

/// Static metadata for a [`CriticalCode`], transcribed verbatim from the PRD
/// §16.3 table (`Code | Check | Description`).
struct CriticalMeta {
    code: &'static str,
    title: &'static str,
    description: &'static str,
}

impl CriticalCode {
    /// All twelve §16.3 critical codes, in PRD table order (the order
    /// [`evaluate_critical_failures`] also emits them in).
    pub const ALL: [CriticalCode; 12] = [
        CriticalCode::DescParseFail,
        CriticalCode::DescChecksumInvalid,
        CriticalCode::MultisigNoDescriptor,
        CriticalCode::MultisigThresholdMissing,
        CriticalCode::KeyCountBelowThreshold,
        CriticalCode::DuplicateXpub,
        CriticalCode::AddressMismatch,
        CriticalCode::WalletTypeMismatch,
        CriticalCode::ChangeDescRequiredMissing,
        CriticalCode::PassphraseUndocumented,
        CriticalCode::SecretDetected,
        CriticalCode::DescContainsXprv,
    ];

    /// The §16.3 row for this code (the single source of truth for its text).
    const fn meta(self) -> CriticalMeta {
        match self {
            CriticalCode::DescParseFail => CriticalMeta {
                code: "C-DESC-PARSE-FAIL",
                title: "Descriptor failed to parse",
                description: "The descriptor as provided is not a valid BIP380 expression",
            },
            CriticalCode::DescChecksumInvalid => CriticalMeta {
                code: "C-DESC-CHECKSUM-INVALID",
                title: "Descriptor checksum present but invalid",
                description: "One or more characters differ from canonical form",
            },
            CriticalCode::MultisigNoDescriptor => CriticalMeta {
                code: "C-MULTISIG-NO-DESCRIPTOR",
                title: "Multisig wallet identified but full descriptor missing",
                description: "User answered \"multisig\" but provided only xpubs without quorum",
            },
            CriticalCode::MultisigThresholdMissing => CriticalMeta {
                code: "C-MULTISIG-THRESHOLD-MISSING",
                title: "Multisig threshold cannot be determined",
                description: "Descriptor or user input lacks M-of-N",
            },
            CriticalCode::KeyCountBelowThreshold => CriticalMeta {
                code: "C-KEY-COUNT-BELOW-THRESHOLD",
                title: "Threshold > number of keys in descriptor",
                description: "Descriptor is self-inconsistent",
            },
            CriticalCode::DuplicateXpub => CriticalMeta {
                code: "C-DUPLICATE-XPUB",
                title: "Same xpub appears multiple times",
                description: "Quorum is illusory",
            },
            CriticalCode::AddressMismatch => CriticalMeta {
                code: "C-ADDRESS-MISMATCH",
                title: "User's known address does not match any address in the derived range",
                description: "Descriptor is wrong, or address belongs to another wallet",
            },
            CriticalCode::WalletTypeMismatch => CriticalMeta {
                code: "C-WALLET-TYPE-MISMATCH",
                title: "User declared wallet type does not match descriptor's script type",
                description: "Descriptor is wrong, or user confused about their setup",
            },
            CriticalCode::ChangeDescRequiredMissing => CriticalMeta {
                code: "C-CHANGE-DESC-REQUIRED-MISSING",
                title: "A wallet that requires change descriptor lacks one AND the descriptor is non-multipath AND BIP389 expansion is impossible",
                description: "Single-line descriptor with no change branch",
            },
            CriticalCode::PassphraseUndocumented => CriticalMeta {
                code: "C-PASSPHRASE-UNDOCUMENTED",
                title: "User indicated a passphrase exists but heir instructions do not mention it",
                description: "Heir cannot recover without knowing a passphrase exists",
            },
            CriticalCode::SecretDetected => CriticalMeta {
                code: "C-SECRET-DETECTED",
                title: "Sensitive-input detector found a real secret in the input",
                description: "Input rejected; user must remove and retry",
            },
            CriticalCode::DescContainsXprv => CriticalMeta {
                code: "C-DESC-CONTAINS-XPRV",
                title: "Descriptor includes an extended private key",
                description: "App refuses to process; user must remove xprv and use xpub instead",
            },
        }
    }

    /// The stable code string, e.g. `"C-DESC-PARSE-FAIL"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.meta().code
    }

    /// The §16.3 "Check" label.
    #[must_use]
    pub const fn title(self) -> &'static str {
        self.meta().title
    }

    /// The §16.3 "Description" text.
    #[must_use]
    pub const fn description(self) -> &'static str {
        self.meta().description
    }

    /// Build the report-ready [`CriticalIssue`] for this code.
    #[must_use]
    pub fn issue(self) -> CriticalIssue {
        CriticalIssue {
            code: self,
            title: self.title().to_owned(),
            description: self.description().to_owned(),
        }
    }
}

impl std::fmt::Display for CriticalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A fired §16.3 critical failure, shaped as a `critical_issues[]` entry in the
/// §19.1 report. Crate-owned `serde` (the JS-boundary convention):
/// `{"code":"C-DESC-PARSE-FAIL","title":"…","description":"…"}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CriticalIssue {
    /// The stable §16.3 code.
    pub code: CriticalCode,
    /// Short human-readable label (PRD §16.3 "Check" column).
    pub title: String,
    /// What it means (PRD §16.3 "Description" column).
    pub description: String,
}

/// The PRD §16.2 qualitative readiness status — the report headline (the numeric
/// score is a sub-detail). Serializes snake_case to match §19.1 `score.status`
/// (`"ready"`, `"mostly_ready"`, `"needs_attention"`, `"not_ready"`,
/// `"cannot_determine"`).
///
/// US-020 establishes only the **critical-forcing rule** ([`forced_status`]): any
/// §16.3 critical forces [`ReadinessStatus::NotReady`]. The score→status mapping,
/// the `Cannot Determine` triggers (§16.5), and the `Ready` known-address (D8)
/// requirement are US-022.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    /// Numeric ≥ 90, zero criticals, and a known-address match (§16.2 / D8).
    Ready,
    /// Numeric 70–89.
    MostlyReady,
    /// Numeric 40–69.
    NeedsAttention,
    /// Numeric 0–39, **or** any §16.3 critical present.
    NotReady,
    /// Insufficient information to score (§16.5).
    CannotDetermine,
}

/// The user/wizard-supplied context the §16.3 critical evaluator needs beyond the
/// A–G [`Check`] results: the parse outcome, the recovery checklist, and the
/// signals that originate in flows outside the descriptor itself (the detector
/// verdict, the passphrase sub-flow, the "loose xpubs" and "change required"
/// wizard states).
///
/// Built with [`CriticalContext::default`] / [`CriticalContext::new`] plus `with_*`
/// builders, mirroring [`CheckInput`]. `Copy` (holds only small values).
#[derive(Debug, Clone, Copy, Default)]
pub struct CriticalContext {
    parse_failure: Option<ErrorCode>,
    declared_wallet_type: Option<DeclaredWalletType>,
    secret_detected: bool,
    multisig_descriptor_missing: bool,
    change_descriptor_required: bool,
    passphrase: Option<Passphrase>,
    checklist: RecoveryChecklist,
}

impl CriticalContext {
    /// An empty context: descriptor parsed, nothing declared, no recovery answers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that descriptor parsing failed, carrying the [`ErrorCode`] the parser
    /// returned. The evaluator maps it to the precise parse-time critical:
    /// `E-PARSE-003` ⇒ `C-DESC-CHECKSUM-INVALID`, `E-PARSE-005` ⇒
    /// `C-DESC-CONTAINS-XPRV`, `E-PARSE-007` ⇒ `C-KEY-COUNT-BELOW-THRESHOLD`,
    /// anything else ⇒ the generic `C-DESC-PARSE-FAIL`.
    #[must_use]
    pub fn with_parse_failure(mut self, code: ErrorCode) -> Self {
        self.parse_failure = Some(code);
        self
    }

    /// Record the wallet type the user declared. Needed to assign the multisig
    /// criticals; pass the same value to [`CheckInput::with_declared_wallet_type`]
    /// so the B2 check agrees.
    #[must_use]
    pub fn with_declared_wallet_type(mut self, declared: DeclaredWalletType) -> Self {
        self.declared_wallet_type = Some(declared);
        self
    }

    /// Record that the sensitive-input detector blocked a real secret (detector
    /// verdict `Block`) ⇒ `C-SECRET-DETECTED`.
    #[must_use]
    pub fn with_secret_detected(mut self, detected: bool) -> Self {
        self.secret_detected = detected;
        self
    }

    /// Record that the user declared multisig but supplied only loose xpubs with no
    /// quorum descriptor (so there is nothing to analyze) ⇒ `C-MULTISIG-NO-DESCRIPTOR`.
    #[must_use]
    pub fn with_multisig_descriptor_missing(mut self, missing: bool) -> Self {
        self.multisig_descriptor_missing = missing;
        self
    }

    /// Record that this wallet *requires* a change descriptor (set by the wizard
    /// flow that demands one). Combined with a missing change branch (E2 `Warn`)
    /// ⇒ `C-CHANGE-DESC-REQUIRED-MISSING`. When the wallet merely *lacks* a change
    /// descriptor without it being required, that is the §16.4 `W-NO-CHANGE-DESC`
    /// warning (US-021), not a critical.
    #[must_use]
    pub fn with_change_descriptor_required(mut self, required: bool) -> Self {
        self.change_descriptor_required = required;
        self
    }

    /// Record the resolved passphrase status; [`Passphrase::Undocumented`] ⇒
    /// `C-PASSPHRASE-UNDOCUMENTED`.
    #[must_use]
    pub fn with_passphrase(mut self, passphrase: Passphrase) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    /// Attach the H1–H9 recovery checklist answers.
    #[must_use]
    pub fn with_checklist(mut self, checklist: RecoveryChecklist) -> Self {
        self.checklist = checklist;
        self
    }

    /// The attached H1–H9 answers (US-021 reads these to apply the §16.4 weights).
    #[must_use]
    pub fn checklist(&self) -> RecoveryChecklist {
        self.checklist
    }

    /// The recorded parse-failure code, if parsing failed.
    #[must_use]
    pub fn parse_failure(&self) -> Option<ErrorCode> {
        self.parse_failure
    }
}

/// Look up a check's result by code in a [`run_checks`] output slice.
fn check_result(checks: &[Check], code: &str) -> Option<CheckResult> {
    checks.iter().find(|c| c.code == code).map(|c| c.result)
}

/// Evaluate the PRD §16.3 critical failures from the A–G [`Check`] results and the
/// user/wizard [`CriticalContext`].
///
/// Each of the twelve [`CriticalCode`]s is assigned by exactly one rule, evaluated
/// in §16.3 table order, so the result is deterministic and duplicate-free. Any
/// non-empty result forces the headline status to [`ReadinessStatus::NotReady`]
/// (see [`forced_status`]), regardless of the numeric score (US-021).
///
/// `checks` must be the [`run_checks`] output for the same subject: the parsed
/// descriptor's checks, or [`run_checks`]`(&`[`CheckInput::parse_failed`]`())` (or
/// an empty slice) when there is no parsed descriptor — in which case
/// [`CriticalContext::with_parse_failure`] carries *why* parsing failed.
#[must_use]
pub fn evaluate_critical_failures(
    checks: &[Check],
    context: &CriticalContext,
) -> Vec<CriticalIssue> {
    use CheckResult::{Fail, Na, Warn};
    use CriticalCode as C;

    let result = |code: &str| check_result(checks, code);
    // A parse failure with no *more specific* code ⇒ the generic parse failure.
    let parse_failed_generic = matches!(
        context.parse_failure,
        Some(code)
            if !matches!(
                code,
                ErrorCode::ChecksumInvalid
                    | ErrorCode::ContainsPrivateKey
                    | ErrorCode::ThresholdExceedsKeys
            )
    );
    let declared_multisig = context.declared_wallet_type == Some(DeclaredWalletType::Multisig);

    let mut issues = Vec::new();

    // §16.3, in table order. Each rule is mutually exclusive of the others that
    // could otherwise fire on the same input (the guards are documented inline).

    // C-DESC-PARSE-FAIL — a parse failure with no more-specific code.
    if parse_failed_generic {
        issues.push(C::DescParseFail.issue());
    }
    // C-DESC-CHECKSUM-INVALID — E-PARSE-003 (a present `#checksum` that is wrong).
    if context.parse_failure == Some(ErrorCode::ChecksumInvalid) {
        issues.push(C::DescChecksumInvalid.issue());
    }
    // C-MULTISIG-NO-DESCRIPTOR — declared multisig, only loose xpubs (no descriptor
    // to parse). Driven by an explicit wizard signal: there is no descriptor here,
    // so no A–G check can express it.
    if context.multisig_descriptor_missing {
        issues.push(C::MultisigNoDescriptor.issue());
    }
    // C-MULTISIG-THRESHOLD-MISSING — declared multisig and the descriptor parsed,
    // but no M-of-N could be extracted (e.g. a Taproot key-path or a richer policy)
    // AND it is not a clear singlesig (which is C-WALLET-TYPE-MISMATCH via B2). D2
    // is `Na` exactly when `multisig_info()` is absent.
    if declared_multisig
        && context.parse_failure.is_none()
        && result("D2") == Some(Na)
        && result("B2") != Some(Fail)
    {
        issues.push(C::MultisigThresholdMissing.issue());
    }
    // C-KEY-COUNT-BELOW-THRESHOLD — M > N. Normally caught at parse (E-PARSE-007);
    // the D5 path is defensive (a parsed descriptor always satisfies the bounds, so
    // it never double-fires with the parse path).
    if context.parse_failure == Some(ErrorCode::ThresholdExceedsKeys) || result("D5") == Some(Fail)
    {
        issues.push(C::KeyCountBelowThreshold.issue());
    }
    // C-DUPLICATE-XPUB — D4 fail (the same xpub reused across positions).
    if result("D4") == Some(Fail) {
        issues.push(C::DuplicateXpub.issue());
    }
    // C-ADDRESS-MISMATCH — G3 fail (a known address matched nothing in range).
    if result("G3") == Some(Fail) {
        issues.push(C::AddressMismatch.issue());
    }
    // C-WALLET-TYPE-MISMATCH — B2 fail (declared type vs the descriptor's script type).
    if result("B2") == Some(Fail) {
        issues.push(C::WalletTypeMismatch.issue());
    }
    // C-CHANGE-DESC-REQUIRED-MISSING — a change descriptor is required but absent.
    // E2 `Warn` is precisely "change not provided AND not multipath" (§16.4), i.e.
    // the §16.3 "non-multipath AND BIP389 expansion impossible" condition.
    if context.change_descriptor_required && result("E2") == Some(Warn) {
        issues.push(C::ChangeDescRequiredMissing.issue());
    }
    // C-PASSPHRASE-UNDOCUMENTED — a passphrase exists but the heir packet omits it.
    if context.passphrase == Some(Passphrase::Undocumented) {
        issues.push(C::PassphraseUndocumented.issue());
    }
    // C-SECRET-DETECTED — the detector blocked a real secret in the input.
    if context.secret_detected {
        issues.push(C::SecretDetected.issue());
    }
    // C-DESC-CONTAINS-XPRV — E-PARSE-005 (an extended private key in the descriptor).
    if context.parse_failure == Some(ErrorCode::ContainsPrivateKey) {
        issues.push(C::DescContainsXprv.issue());
    }

    issues
}

/// The headline status forced by the §16.3 critical failures, if any.
///
/// Returns `Some(`[`ReadinessStatus::NotReady`]`)` when one or more criticals are
/// present (PRD §16.3: "Any of these forces status `Not Ready` regardless of
/// numeric score"), or `None` when nothing forces the status — in which case it is
/// computed from the numeric score and the §16.5 triggers (US-022).
#[must_use]
pub fn forced_status(criticals: &[CriticalIssue]) -> Option<ReadinessStatus> {
    if criticals.is_empty() {
        None
    } else {
        Some(ReadinessStatus::NotReady)
    }
}

// ===========================================================================
// US-021 — §16.4 warning weights and the numeric score
// ===========================================================================
//
// `run_checks` (US-019) grades each A–G check and US-020 maps the `Fail` results
// to the §16.3 criticals. This layer maps the §16.4 *warning* conditions to their
// fixed score deductions: the numeric score starts at 100, each fired warning
// subtracts its weight, and the running total is clamped to `[0, 100]`. The
// fact→scoring split still holds — the weights live ONLY here (in
// `WarningCode::impact`), never in the analysis crates.
//
// Three sources feed the warnings, all read here (never re-derived downstream):
//   * the A–G `Check` results — `A2 == Warn` ⇒ `W-NO-DESC-CHECKSUM`,
//     `E2 == Warn` ⇒ `W-NO-CHANGE-DESC`, and (descriptor parsed, no known address
//     supplied) `G3 == Na` ⇒ `W-NO-KNOWN-ADDRESS`;
//   * the descriptor fact the orchestrator records on the `ScoringContext`
//     (`singlesig_separate_descriptors` ⇒ `W-NO-MULTIPATH`); and
//   * the user/wizard answers — the H1 / H5–H9 `RecoveryChecklist` entries plus the
//     three signals that are not H questions (emergency contact, hardware test,
//     same-location backup).

/// The scoring-engine version stamped into the §19.1 report
/// (`scoring_engine_version`). The §16.4 weights are versioned with it and are
/// **not** user-configurable — a configurable weight would invite score-shopping
/// (PRD §16.7).
pub const SCORING_ENGINE_VERSION: &str = "0.1.0";

/// A PRD §16.4 warning code. Each warning reduces the numeric score by a fixed
/// weight (see [`WarningCode::impact`]); warnings never fail the wallet (that is
/// the §16.3 [`CriticalCode`] layer).
///
/// Serializes to its stable string code (`"W-NO-CHANGE-DESC"`, …) via the
/// per-variant `serde(rename = …)`, kept in lockstep with [`WarningCode::as_str`]
/// by a parity test. Crate-owned `serde` (the JS-boundary convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WarningCode {
    /// `W-NO-DESC-CHECKSUM` (-5) — the descriptor lacks a `#checksum`.
    #[serde(rename = "W-NO-DESC-CHECKSUM")]
    NoDescChecksum,
    /// `W-NO-CHANGE-DESC` (-15) — no change descriptor and not multipath.
    #[serde(rename = "W-NO-CHANGE-DESC")]
    NoChangeDesc,
    /// `W-NO-BIRTH-HEIGHT` (-5) — no wallet creation date / block height documented.
    #[serde(rename = "W-NO-BIRTH-HEIGHT")]
    NoBirthHeight,
    /// `W-NO-GAP-LIMIT` (-3) — gap limit not documented.
    #[serde(rename = "W-NO-GAP-LIMIT")]
    NoGapLimit,
    /// `W-NO-KNOWN-ADDRESS` (-10) — the user did not provide a known address.
    #[serde(rename = "W-NO-KNOWN-ADDRESS")]
    NoKnownAddress,
    /// `W-NO-PRINTED-BACKUP` (-8) — no printed descriptor backup.
    #[serde(rename = "W-NO-PRINTED-BACKUP")]
    NoPrintedBackup,
    /// `W-NO-RECENT-DRILL` (-10) — no recovery drill in the last 12 months.
    #[serde(rename = "W-NO-RECENT-DRILL")]
    NoRecentDrill,
    /// `W-NO-HEIR-INSTRUCTIONS` (-8) — no heir/executor instructions written.
    #[serde(rename = "W-NO-HEIR-INSTRUCTIONS")]
    NoHeirInstructions,
    /// `W-NO-EMERGENCY-CONTACT` (-3) — no emergency contact named.
    #[serde(rename = "W-NO-EMERGENCY-CONTACT")]
    NoEmergencyContact,
    /// `W-NO-HW-TEST` (-8) — the hardware wallet signed nothing in the past 12 months.
    #[serde(rename = "W-NO-HW-TEST")]
    NoHwTest,
    /// `W-SAME-LOCATION-BACKUP` (-10) — backup and signing device share a location.
    #[serde(rename = "W-SAME-LOCATION-BACKUP")]
    SameLocationBackup,
    /// `W-WALLET-SW-UNDOCUMENTED` (-5) — the required wallet software is undocumented.
    #[serde(rename = "W-WALLET-SW-UNDOCUMENTED")]
    WalletSwUndocumented,
    /// `W-NO-MULTIPATH` (-2) — a singlesig wallet uses two separate descriptors
    /// instead of one BIP389 multipath descriptor.
    #[serde(rename = "W-NO-MULTIPATH")]
    NoMultipath,
}

/// Static metadata for a [`WarningCode`], transcribed verbatim from the PRD §16.4
/// table (`Code | Check | Score Impact`).
struct WarningMeta {
    code: &'static str,
    condition: &'static str,
    impact: i32,
}

impl WarningCode {
    /// All active §16.4 warning codes, in PRD table order — the order
    /// [`compute_score`] evaluates and emits them in, so the audit trail is
    /// deterministic. The Taproot preview warning was lifted in US-073 when
    /// Taproot became fully supported.
    pub const ALL: [WarningCode; 13] = [
        WarningCode::NoDescChecksum,
        WarningCode::NoChangeDesc,
        WarningCode::NoBirthHeight,
        WarningCode::NoGapLimit,
        WarningCode::NoKnownAddress,
        WarningCode::NoPrintedBackup,
        WarningCode::NoRecentDrill,
        WarningCode::NoHeirInstructions,
        WarningCode::NoEmergencyContact,
        WarningCode::NoHwTest,
        WarningCode::SameLocationBackup,
        WarningCode::WalletSwUndocumented,
        WarningCode::NoMultipath,
    ];

    /// The §16.4 row for this code (the single source of truth for its weight).
    const fn meta(self) -> WarningMeta {
        match self {
            WarningCode::NoDescChecksum => WarningMeta {
                code: "W-NO-DESC-CHECKSUM",
                condition: "Descriptor lacks #checksum",
                impact: -5,
            },
            WarningCode::NoChangeDesc => WarningMeta {
                code: "W-NO-CHANGE-DESC",
                condition: "Change descriptor not provided AND not multipath",
                impact: -15,
            },
            WarningCode::NoBirthHeight => WarningMeta {
                code: "W-NO-BIRTH-HEIGHT",
                condition: "No wallet creation date / block height documented",
                impact: -5,
            },
            WarningCode::NoGapLimit => WarningMeta {
                code: "W-NO-GAP-LIMIT",
                condition: "Gap limit not documented",
                impact: -3,
            },
            WarningCode::NoKnownAddress => WarningMeta {
                code: "W-NO-KNOWN-ADDRESS",
                condition: "User did not provide a known address",
                impact: -10,
            },
            WarningCode::NoPrintedBackup => WarningMeta {
                code: "W-NO-PRINTED-BACKUP",
                condition: "User answers \"no\" to \"Do you have a printed descriptor backup?\"",
                impact: -8,
            },
            WarningCode::NoRecentDrill => WarningMeta {
                code: "W-NO-RECENT-DRILL",
                condition: "No drill in last 12 months (or never)",
                impact: -10,
            },
            WarningCode::NoHeirInstructions => WarningMeta {
                code: "W-NO-HEIR-INSTRUCTIONS",
                condition: "No heir instructions written",
                impact: -8,
            },
            WarningCode::NoEmergencyContact => WarningMeta {
                code: "W-NO-EMERGENCY-CONTACT",
                condition: "No emergency contact named",
                impact: -3,
            },
            WarningCode::NoHwTest => WarningMeta {
                code: "W-NO-HW-TEST",
                condition: "Hardware wallet not signed anything in past 12 months",
                impact: -8,
            },
            WarningCode::SameLocationBackup => WarningMeta {
                code: "W-SAME-LOCATION-BACKUP",
                condition:
                    "User answers \"yes\" to \"Are your backup and your device in the same location?\"",
                impact: -10,
            },
            WarningCode::WalletSwUndocumented => WarningMeta {
                code: "W-WALLET-SW-UNDOCUMENTED",
                condition: "User did not document which wallet software is needed",
                impact: -5,
            },
            WarningCode::NoMultipath => WarningMeta {
                code: "W-NO-MULTIPATH",
                condition:
                    "Singlesig descriptor uses two separate descriptors instead of BIP389 multipath",
                impact: -2,
            },
        }
    }

    /// The stable code string, e.g. `"W-NO-CHANGE-DESC"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.meta().code
    }

    /// The §16.4 "Check" condition text (i.e. when this warning fires).
    #[must_use]
    pub const fn condition(self) -> &'static str {
        self.meta().condition
    }

    /// The score impact: a negative weight, e.g. `-15`.
    #[must_use]
    pub const fn impact(self) -> i32 {
        self.meta().impact
    }
}

impl std::fmt::Display for WarningCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One entry in the §19.1 `scoring_audit` array: the warning that fired, its score
/// `impact` (negative), and the `running_score` immediately after applying it.
///
/// Crate-owned `serde` (the JS-boundary convention):
/// `{"code":"W-NO-CHANGE-DESC","impact":-15,"running_score":85}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScoringAuditEntry {
    /// The §16.4 warning that fired.
    pub code: WarningCode,
    /// The score change it applied (a negative weight).
    pub impact: i32,
    /// The numeric score immediately after this warning (clamped to `[0, 100]`).
    pub running_score: u32,
}

/// The numeric readiness score and the transparent audit trail that produced it
/// (PRD §16.4 / §16.7). The qualitative status / headline (§16.2) is layered on
/// top in US-022; this struct carries only what US-021 computes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScoringResult {
    /// The §19.1 `score.numeric` value, in `[0, 100]` (starts at 100, reduced by the
    /// active §16.4 warning weights). With the current weights summing to -92,
    /// the realistic range is `[8, 100]`; the clamp's lower bound is defensive.
    pub numeric: u32,
    /// The §19.1 `scoring_audit` array: one entry per fired warning, in §16.4 table
    /// order. Folding the impacts from 100 reproduces `numeric`.
    pub scoring_audit: Vec<ScoringAuditEntry>,
}

/// The user/wizard-supplied context for the §16.4 warnings that the A–G [`Check`]
/// results do not already express: the [`RecoveryChecklist`] answers, the
/// `singlesig_separate_descriptors` descriptor fact, and the three wizard signals
/// that are not H questions (emergency contact, hardware test, same-location backup).
///
/// Built with [`ScoringContext::default`] / [`ScoringContext::new`] plus `with_*`
/// builders, mirroring [`CriticalContext`]. `Copy` (holds only small values). The
/// default is the conservative "nothing answered" baseline: every checklist field
/// is `None` and the two "good thing confirmed" booleans are `false`, so the
/// corresponding warnings fire (PRD §9.1: "each skip = warning").
#[derive(Debug, Clone, Copy, Default)]
pub struct ScoringContext {
    checklist: RecoveryChecklist,
    singlesig_separate_descriptors: bool,
    emergency_contact_named: bool,
    hardware_signed_recently: bool,
    backup_same_location: bool,
}

impl ScoringContext {
    /// An empty context (every warning gated on a user answer fires).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the H1–H9 recovery checklist answers. H1 and H5–H9 drive warnings
    /// (H2–H4 carry no §16.4 weight — H4/passphrase is the US-020 critical); see
    /// [`compute_score`].
    #[must_use]
    pub fn with_checklist(mut self, checklist: RecoveryChecklist) -> Self {
        self.checklist = checklist;
        self
    }

    /// Record the descriptor-derived warning fact from a parsed descriptor: when
    /// the wallet is singlesig and a separate change descriptor was supplied
    /// instead of a BIP389 multipath one, `singlesig_separate_descriptors`
    /// (⇒ `W-NO-MULTIPATH`) fires. `has_explicit_change` is whether the caller
    /// passed a separate change descriptor (i.e.
    /// [`CheckInput::with_change_descriptor`] was used).
    #[must_use]
    pub fn with_descriptor(mut self, parsed: &ParsedDescriptor, has_explicit_change: bool) -> Self {
        self.singlesig_separate_descriptors =
            parsed.is_singlesig() && has_explicit_change && !parsed.uses_multipath();
        self
    }

    /// Record that a singlesig wallet was supplied as two separate descriptors
    /// rather than one BIP389 multipath descriptor (⇒ `W-NO-MULTIPATH`).
    #[must_use]
    pub fn with_singlesig_separate_descriptors(mut self, separate: bool) -> Self {
        self.singlesig_separate_descriptors = separate;
        self
    }

    /// Record that the user named an emergency contact (suppresses
    /// `W-NO-EMERGENCY-CONTACT`).
    #[must_use]
    pub fn with_emergency_contact_named(mut self, named: bool) -> Self {
        self.emergency_contact_named = named;
        self
    }

    /// Record that the hardware wallet signed something in the past 12 months
    /// (suppresses `W-NO-HW-TEST`).
    #[must_use]
    pub fn with_hardware_signed_recently(mut self, signed: bool) -> Self {
        self.hardware_signed_recently = signed;
        self
    }

    /// Record that the backup and the signing device share a location
    /// (⇒ `W-SAME-LOCATION-BACKUP`).
    #[must_use]
    pub fn with_backup_same_location(mut self, same: bool) -> Self {
        self.backup_same_location = same;
        self
    }

    /// The attached H1–H9 answers.
    #[must_use]
    pub fn checklist(&self) -> RecoveryChecklist {
        self.checklist
    }
}

/// Whether a recovery-checklist answer leaves its warning firing: only an explicit
/// `Yes` suppresses the warning. A `No`, an `Unsure`, or an unanswered (`None`,
/// skipped) question all fire it (PRD §9.1: "each skip = warning").
fn not_confirmed(answer: Option<Answer>) -> bool {
    !matches!(answer, Some(Answer::Yes))
}

/// Compute the PRD §16.4 numeric score and its §16.7 audit trail.
///
/// The score starts at 100; each fired warning subtracts its [`WarningCode::impact`]
/// and the running total is clamped to `[0, 100]`. Warnings are evaluated in §16.4
/// table order, so [`ScoringResult::scoring_audit`] is deterministic. The weights
/// are fixed (not user-configurable) and versioned by [`SCORING_ENGINE_VERSION`].
///
/// `checks` is the [`run_checks`] output for this subject; `context` carries the
/// checklist answers and the wizard/descriptor signals the checks do not already
/// express. Infallible.
#[must_use]
pub fn compute_score(checks: &[Check], context: &ScoringContext) -> ScoringResult {
    use CheckResult::{Na, Pass, Warn};
    use WarningCode as W;

    let cl = context.checklist;
    let result = |code: &str| check_result(checks, code);

    // The §16.4 conditions paired with their codes, in PRD table order.
    let candidates = [
        // From the A–G check results.
        (result("A2") == Some(Warn), W::NoDescChecksum),
        (result("E2") == Some(Warn), W::NoChangeDesc),
        // From the H checklist answers.
        (not_confirmed(cl.birth_height_documented), W::NoBirthHeight),
        (not_confirmed(cl.gap_limit_documented), W::NoGapLimit),
        // The descriptor parsed but no known address was supplied (G3 == Na).
        (
            result("A1") == Some(Pass) && result("G3") == Some(Na),
            W::NoKnownAddress,
        ),
        (not_confirmed(cl.physical_copies), W::NoPrintedBackup),
        (not_confirmed(cl.recent_drill), W::NoRecentDrill),
        (
            not_confirmed(cl.heir_instructions_written),
            W::NoHeirInstructions,
        ),
        // From the wizard signals that are not H questions.
        (!context.emergency_contact_named, W::NoEmergencyContact),
        (!context.hardware_signed_recently, W::NoHwTest),
        (context.backup_same_location, W::SameLocationBackup),
        (
            not_confirmed(cl.wallet_software_documented),
            W::WalletSwUndocumented,
        ),
        // From the descriptor facts.
        (context.singlesig_separate_descriptors, W::NoMultipath),
    ];

    let mut numeric: i32 = 100;
    let scoring_audit: Vec<ScoringAuditEntry> = candidates
        .into_iter()
        .filter(|&(fires, _)| fires)
        .map(|(_, code)| {
            numeric = (numeric + code.impact()).clamp(0, 100);
            ScoringAuditEntry {
                code,
                impact: code.impact(),
                running_score: numeric as u32,
            }
        })
        .collect();

    ScoringResult {
        numeric: numeric as u32,
        scoring_audit,
    }
}

// ===========================================================================
// US-022 — §16.2 status mapping, §16.5 Cannot Determine, §16.6 survivability
// ===========================================================================
//
// US-019 grades the A–G checks, US-020 maps the `Fail`s to the §16.3 criticals
// (and `forced_status` reports the Not Ready they force), and US-021 produces the
// numeric score. This final layer turns those into the §16.2 *headline status*,
// detects the four §16.5 *Cannot Determine* conditions, and computes the §16.6
// multisig *survivability* dimension. It re-parses/re-derives nothing and stays
// infallible (no function here returns `Result`).

impl ReadinessStatus {
    /// The Title-Case headline shown in the report (§15.10 / §19.1
    /// `score.headline`): `"Ready"`, `"Mostly Ready"`, `"Needs Attention"`,
    /// `"Not Ready"`, `"Cannot Determine"`. The snake_case form is the `serde`
    /// representation (§19.1 `score.status`); this is the human-facing string.
    #[must_use]
    pub const fn headline(self) -> &'static str {
        match self {
            ReadinessStatus::Ready => "Ready",
            ReadinessStatus::MostlyReady => "Mostly Ready",
            ReadinessStatus::NeedsAttention => "Needs Attention",
            ReadinessStatus::NotReady => "Not Ready",
            ReadinessStatus::CannotDetermine => "Cannot Determine",
        }
    }
}

/// The signals the §16.2 status mapping needs that the A–G [`Check`] results and
/// the [`CriticalIssue`] list do not already express: the two §16.5 *Cannot
/// Determine* conditions no check can represent (an unrecognized import file; a
/// wizard aborted before the address-comparison step) and the "key origin
/// entirely absent" descriptor fact (§16.5 condition 2).
///
/// Built with [`StatusContext::default`] / [`StatusContext::new`] plus `with_*`
/// builders, mirroring [`ScoringContext`] / [`CriticalContext`]. `Copy`. The
/// network-undeterminable condition (§16.5 condition 1) and the D8 known-address
/// match are derived from the checks, so they are NOT fields here.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusContext {
    key_origin_absent: bool,
    unrecognized_export: bool,
    wizard_aborted: bool,
}

impl StatusContext {
    /// An empty context: a descriptor was analyzed, the import was recognized, and
    /// the wizard ran to completion (no §16.5 signal set).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the §16.5 condition-2 descriptor fact: whether key-origin information
    /// is *entirely* absent (no key carries a fingerprint or a derivation path).
    /// Partial origins do not trigger it — only a complete absence, which (with no
    /// manual provision) leaves provenance undeterminable.
    #[must_use]
    pub fn with_descriptor(mut self, parsed: &ParsedDescriptor) -> Self {
        self.key_origin_absent = key_origins_entirely_absent(parsed);
        self
    }

    /// Record §16.5 condition 2 directly (key origin entirely absent). Lower-level
    /// alternative to [`StatusContext::with_descriptor`].
    #[must_use]
    pub fn with_key_origin_absent(mut self, absent: bool) -> Self {
        self.key_origin_absent = absent;
        self
    }

    /// Record §16.5 condition 3: the user imported a wallet-export file the app
    /// does not recognize (so there is no descriptor to analyze). The caller passes
    /// NO parse-failure critical in this case — an unrecognized *file* is Cannot
    /// Determine, distinct from a broken *descriptor* (`C-DESC-PARSE-FAIL` → Not
    /// Ready).
    #[must_use]
    pub fn with_unrecognized_export(mut self, unrecognized: bool) -> Self {
        self.unrecognized_export = unrecognized;
        self
    }

    /// Record §16.5 condition 4: the user aborted the wizard before reaching the
    /// address-comparison step, so the audit is incomplete.
    #[must_use]
    pub fn with_wizard_aborted(mut self, aborted: bool) -> Self {
        self.wizard_aborted = aborted;
        self
    }
}

/// §16.5 condition 2 — every key lacks both a fingerprint and a derivation path
/// (and there is at least one key). A descriptor with *some* origins present is
/// not "entirely absent".
fn key_origins_entirely_absent(parsed: &ParsedDescriptor) -> bool {
    let origins = parsed.key_origins();
    !origins.is_empty()
        && origins
            .iter()
            .all(|o| !o.has_fingerprint() && !o.has_derivation_path())
}

/// Whether the inputs trigger one of the four §16.5 *Cannot Determine* conditions.
fn cannot_determine(checks: &[Check], context: &StatusContext) -> bool {
    use CheckResult::{Pass, Unknown};
    let result = |code: &str| check_result(checks, code);

    // §16.5.1 — the network is not inferable from the descriptor (F1 Unknown), the
    // user did not confirm one (F2 != Pass), and none was supplied to derive on
    // (G1 Unknown ⟺ no resolvable network). If the user DID supply a derivation
    // network, G1 is Pass/Fail and we can render a verdict, so this does not fire.
    let network_undeterminable = result("F1") == Some(Unknown)
        && result("F2") != Some(Pass)
        && result("G1") == Some(Unknown);

    network_undeterminable
        || context.key_origin_absent // §16.5.2
        || context.unrecognized_export // §16.5.3
        || context.wizard_aborted // §16.5.4
}

/// Map the numeric score, the §16.3 criticals, and the §16.5 signals to the §16.2
/// headline [`ReadinessStatus`].
///
/// Precedence (PRD §16.2 / §16.3 / §16.5):
/// 1. **Any §16.3 critical forces [`ReadinessStatus::NotReady`]** regardless of the
///    numeric score (via [`forced_status`]).
/// 2. Otherwise, a §16.5 condition yields [`ReadinessStatus::CannotDetermine`]. A
///    definitive critical is more actionable than "insufficient information", so
///    criticals take precedence over Cannot Determine.
/// 3. Otherwise the numeric score maps to a band: `Ready` 90–100, `Mostly Ready`
///    70–89, `Needs Attention` 40–69, `Not Ready` 0–39. **`Ready` additionally
///    requires the D8 known-address match** (`G3 == Pass`): a 90+ score without a
///    confirmed known address falls to `Mostly Ready` (you cannot be "Ready"
///    without verifying an address you control). The "zero criticals" half of the
///    §16.2 `Ready` rule is guaranteed here by step 1.
///
/// `checks` is the [`run_checks`] output for the subject; `numeric` is
/// [`ScoringResult::numeric`]; `criticals` is the [`evaluate_critical_failures`]
/// output; `context` carries the §16.5 signals no check expresses. Infallible.
#[must_use]
pub fn map_status(
    checks: &[Check],
    numeric: u32,
    criticals: &[CriticalIssue],
    context: &StatusContext,
) -> ReadinessStatus {
    use ReadinessStatus::{CannotDetermine, MostlyReady, NeedsAttention, NotReady, Ready};

    // 1. A §16.3 critical forces Not Ready regardless of the numeric score.
    if let Some(forced) = forced_status(criticals) {
        return forced;
    }

    // 2. §16.5 — insufficient information to render a verdict.
    if cannot_determine(checks, context) {
        return CannotDetermine;
    }

    // 3. The numeric band (criticals are empty here, guaranteed by step 1). `Ready`
    // additionally requires the D8 known-address match.
    let d8_matched = check_result(checks, "G3") == Some(CheckResult::Pass);
    if numeric >= 90 && d8_matched {
        Ready
    } else if numeric >= 70 {
        MostlyReady
    } else if numeric >= 40 {
        NeedsAttention
    } else {
        NotReady
    }
}

// --- §16.6 multisig survivability ------------------------------------------

/// The PRD §16.6 multisig *survivability* dimension, reported alongside the main
/// status (it is a separate dimension, NOT a warning that moves the score).
///
/// Crate-owned `serde` (the JS-boundary convention), shaped as the §19.1
/// `survivability` object:
/// `{"tested":true,"lose_1_signer":"ok","lose_2_signers":"fail_expected_for_2of3",
/// "lose_descriptor_only":"ok_if_xpubs_retained"}`. Singlesig wallets have no
/// survivability dimension (single point of failure by definition), so
/// [`compute_survivability`] returns `None` for them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Survivability {
    /// Whether the survivability dimension was evaluated. Always `true` when this
    /// object is present: a multisig quorum's survivability is computed
    /// analytically from `M-of-N` (no signing needed), which is exactly the §16.6
    /// question. The v0.2 signing drill (DS-6) exercises the same scenarios with
    /// real signatures and reuses this shape.
    pub tested: bool,
    /// Can recovery still meet the threshold after losing one signer? `"ok"` when
    /// `N - 1 >= M`, else `"fail_expected_for_<M>of<N>"`.
    pub lose_1_signer: String,
    /// As [`Survivability::lose_1_signer`] but for losing two signers
    /// (`N - 2 >= M`).
    pub lose_2_signers: String,
    /// Can the descriptor be rebuilt from the retained xpubs if the descriptor
    /// backup is lost? For a standard `M-of-N` this is `"ok_if_xpubs_retained"`
    /// (the quorum, script type, and xpubs suffice to reconstruct it).
    pub lose_descriptor_only: String,
}

/// The §16.6 verdict for losing `lost` signers from an `M-of-N` quorum: `"ok"`
/// when the remaining signers still meet the threshold, else
/// `"fail_expected_for_<M>of<N>"` (the failure is inherent to the quorum, not a
/// defect — e.g. a 2-of-3 cannot survive losing two signers).
fn signer_loss_verdict(m: usize, n: usize, lost: usize) -> String {
    if n.saturating_sub(lost) >= m {
        "ok".to_owned()
    } else {
        format!("fail_expected_for_{m}of{n}")
    }
}

/// Compute the PRD §16.6 multisig survivability for a parsed descriptor, or `None`
/// for a singlesig wallet / a descriptor with no extractable `M-of-N` (Taproot
/// key-path, richer policies — those get other dimensions in later milestones).
#[must_use]
pub fn compute_survivability(parsed: &ParsedDescriptor) -> Option<Survivability> {
    let info = parsed.multisig_info()?;
    let m = info.threshold();
    let n = info.key_count();
    Some(Survivability {
        tested: true,
        lose_1_signer: signer_loss_verdict(m, n, 1),
        lose_2_signers: signer_loss_verdict(m, n, 2),
        lose_descriptor_only: "ok_if_xpubs_retained".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use descriptor_audit::{compute_checksum, parse_descriptor};

    /// Read a repo-root fixture (same convention as `descriptor-audit`).
    macro_rules! fixture {
        ($path:expr) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/",
                $path
            ))
            .trim()
        };
    }

    use CheckResult::{Fail, Na, Pass, Unknown, Warn};

    fn codes() -> Vec<&'static str> {
        CATALOG.iter().map(|(code, _, _)| *code).collect()
    }

    fn parse(desc: &str) -> ParsedDescriptor {
        parse_descriptor(desc).expect("fixture descriptor parses")
    }

    fn results(checks: &[Check]) -> Vec<CheckResult> {
        checks.iter().map(|c| c.result).collect()
    }

    fn result_of(checks: &[Check], code: &str) -> CheckResult {
        checks
            .iter()
            .find(|c| c.code == code)
            .unwrap_or_else(|| panic!("no check with code {code}"))
            .result
    }

    /// Re-version a `tpub`-bearing key string to a mainnet `xpub` by swapping the
    /// 4 Base58Check version bytes (key material untouched) — the US-011 trick, so
    /// no mainnet key is committed and no Base58 literal is hand-transcribed.
    fn to_mainnet_xpub(tpub: &str) -> String {
        use miniscript::bitcoin::base58;
        let mut bytes = base58::decode_check(tpub).expect("tpub decodes");
        bytes[0..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]); // xpub version bytes
        base58::encode_check(&bytes)
    }

    #[test]
    fn catalog_is_24_checks_in_a1_to_g3_order() {
        let checks = run_checks(&CheckInput::new(&parse(fixture!(
            "descriptors/singlesig/wpkh_valid.txt"
        ))));
        assert_eq!(checks.len(), 24);
        assert_eq!(
            checks.iter().map(|c| c.code.as_str()).collect::<Vec<_>>(),
            codes()
        );
        // Every check carries a non-empty category and title.
        assert!(checks
            .iter()
            .all(|c| !c.category.is_empty() && !c.title.is_empty()));
    }

    #[test]
    fn parse_failure_fails_a1_and_marks_the_rest_na() {
        let checks = run_checks(&CheckInput::parse_failed());
        assert_eq!(checks.len(), 24);
        assert_eq!(result_of(&checks, "A1"), Fail);
        assert!(checks.iter().skip(1).all(|c| c.result == Na));
    }

    #[test]
    fn singlesig_fixtures_share_the_expected_results() {
        // pkh (BIP44), wpkh (BIP84), sh(wpkh) (BIP49) all classify identically;
        // C4 passes because each script type's scheme matches its derivation path.
        let expected = vec![
            Pass, Pass, Pass, Pass, // A1–A4
            Pass, Na, // B1–B2 (nothing declared)
            Pass, Pass, Pass, Pass, // C1–C4
            Pass, Na, Na, Na, Na, // D1–D5 (not multisig)
            Pass, Warn, Na, Na, // E1–E4 (no change descriptor ⇒ W-NO-CHANGE-DESC)
            Unknown, Unknown, // F1–F2 (tpub is ambiguous; user did not confirm)
            Pass, Na, Na, // G1–G3 (derives on testnet; no change, no known address)
        ];
        // `fixture!` wraps `include_str!`, so each path must be a literal.
        let fixtures = [
            ("pkh", fixture!("descriptors/singlesig/pkh_valid.txt")),
            ("wpkh", fixture!("descriptors/singlesig/wpkh_valid.txt")),
            (
                "sh_wpkh",
                fixture!("descriptors/singlesig/sh_wpkh_valid.txt"),
            ),
        ];
        for (label, desc) in fixtures {
            let parsed = parse(desc);
            let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
            assert_eq!(results(&checks), expected, "results for {label}");
        }
    }

    #[test]
    fn multisig_fixtures_pass_the_quorum_checks() {
        let expected = vec![
            Pass, Pass, Pass, Pass, // A1–A4
            Pass, Na, // B1–B2
            Pass, Pass, Pass, Pass, // C1–C4 (BIP48 matches a multisig script type)
            Pass, Pass, Pass, Pass,
            Pass, // D1–D5 (M-of-N extracted; sortedmulti; no dups; bounds ok)
            Pass, Warn, Na, Na, // E1–E4 (single-path ⇒ no change descriptor)
            Unknown, Unknown, // F1–F2
            Pass, Na, Na, // G1–G3
        ];
        let fixtures = [
            (
                "2of3",
                fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"),
            ),
            (
                "3of5",
                fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"),
            ),
        ];
        for (label, desc) in fixtures {
            let parsed = parse(desc);
            let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
            assert_eq!(results(&checks), expected, "results for {label}");
        }
    }

    #[test]
    fn multipath_descriptor_has_a_change_branch() {
        let parsed = parse(fixture!("descriptors/multisig/multipath_2of3.txt"));
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        // The receive/change pair comes from the BIP389 <0;1> expansion.
        assert_eq!(result_of(&checks, "E2"), Pass, "change descriptor present");
        assert_eq!(result_of(&checks, "E3"), Pass, "same script type");
        assert_eq!(result_of(&checks, "E4"), Pass, "differ only in chain index");
        assert_eq!(result_of(&checks, "G2"), Pass, "change addresses derive");
        // It is still a valid 2-of-3, so the quorum checks pass.
        assert_eq!(result_of(&checks, "D2"), Pass);
        assert_eq!(result_of(&checks, "D4"), Pass);
    }

    #[test]
    fn duplicate_xpub_fails_d4() {
        let parsed = parse(fixture!("descriptors/multisig/duplicate_xpub.txt"));
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        assert_eq!(result_of(&checks, "D4"), Fail, "C-DUPLICATE-XPUB");
        // The descriptor is otherwise a parseable 2-of-3, so other quorum facts hold.
        assert_eq!(result_of(&checks, "D2"), Pass);
        assert_eq!(result_of(&checks, "D5"), Pass);
    }

    #[test]
    fn missing_checksum_warns_a2_and_na_a3() {
        let with_checksum = fixture!("descriptors/singlesig/wpkh_valid.txt");
        let without = with_checksum.rsplit_once('#').unwrap().0;
        let parsed = parse(without);
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        assert_eq!(result_of(&checks, "A2"), Warn, "W-NO-DESC-CHECKSUM");
        assert_eq!(result_of(&checks, "A3"), Na, "validity n/a when absent");
    }

    #[test]
    fn declared_wallet_type_mismatch_fails_b2() {
        let singlesig = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let multisig = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));

        // Declared singlesig, descriptor is multisig ⇒ mismatch.
        let checks = run_checks(
            &CheckInput::new(&multisig).with_declared_wallet_type(DeclaredWalletType::Singlesig),
        );
        assert_eq!(result_of(&checks, "B2"), Fail);

        // Declared multisig, descriptor is singlesig ⇒ mismatch.
        let checks = run_checks(
            &CheckInput::new(&singlesig).with_declared_wallet_type(DeclaredWalletType::Multisig),
        );
        assert_eq!(result_of(&checks, "B2"), Fail);

        // Declared correctly ⇒ pass.
        let checks = run_checks(
            &CheckInput::new(&multisig).with_declared_wallet_type(DeclaredWalletType::Multisig),
        );
        assert_eq!(result_of(&checks, "B2"), Pass);
    }

    #[test]
    fn c4_warns_when_scheme_does_not_match_script_type() {
        // wpkh expects BIP84; give it a BIP44 origin path ⇒ recognized but mismatched.
        let tpub = {
            let p = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
            p.key_origins()[0].xpub().expect("xpub present").to_owned()
        };
        let body = format!("wpkh([71348c8a/44'/1'/0']{tpub}/0/*)");
        let descriptor = compute_checksum(&body).expect("checksum computes");
        let parsed = parse(&descriptor);
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        assert_eq!(result_of(&checks, "C4"), Warn);
    }

    #[test]
    fn c4_taproot_multi_a_uses_bip86_not_legacy_multisig_bip48() {
        let parsed = parse(fixture!("descriptors/taproot/tr_scriptpath_multi_a.txt"));
        assert!(parsed.is_taproot());
        assert!(parsed.is_multisig());
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        assert_eq!(result_of(&checks, "C4"), Pass);
        assert_eq!(result_of(&checks, "D2"), Pass);
    }

    #[test]
    fn f1_passes_for_a_determinable_mainnet_descriptor() {
        let tpub = {
            let p = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
            p.key_origins()[0].xpub().expect("xpub present").to_owned()
        };
        let xpub = to_mainnet_xpub(&tpub);
        let body = format!("wpkh([71348c8a/84'/0'/0']{xpub}/0/*)");
        let descriptor = compute_checksum(&body).expect("checksum computes");
        let parsed = parse(&descriptor);
        let checks = run_checks(&CheckInput::new(&parsed));
        assert_eq!(
            result_of(&checks, "F1"),
            Pass,
            "mainnet xpub is determinable"
        );
        assert_eq!(result_of(&checks, "F2"), Na, "no confirmation needed");
    }

    #[test]
    fn f2_passes_when_the_user_confirms_an_ambiguous_network() {
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = run_checks(
            &CheckInput::new(&parsed)
                .with_network(Network::Testnet)
                .with_network_confirmed(true),
        );
        assert_eq!(result_of(&checks, "F1"), Unknown, "tpub stays ambiguous");
        assert_eq!(result_of(&checks, "F2"), Pass, "user confirmed");
    }

    #[test]
    fn g_checks_are_unknown_without_a_resolvable_network() {
        // No caller network + a tpub (ambiguous) ⇒ derivation cannot pick a chain.
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = run_checks(&CheckInput::new(&parsed));
        assert_eq!(result_of(&checks, "G1"), Unknown);
        assert_eq!(result_of(&checks, "G2"), Na, "no change descriptor");
        assert_eq!(result_of(&checks, "G3"), Na, "no known address");
    }

    #[test]
    fn g3_matches_a_known_address_and_flags_a_mismatch() {
        let known = fixture!("addresses/known_match_tb1.txt"); // 2-of-3 receive index 2 (testnet)

        // Correct wallet ⇒ the known address is in the derived range.
        let multisig = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let checks = run_checks(
            &CheckInput::new(&multisig)
                .with_network(Network::Testnet)
                .with_known_address(known),
        );
        assert_eq!(result_of(&checks, "G3"), Pass);

        // Same address against a different (singlesig) wallet ⇒ C-ADDRESS-MISMATCH.
        let singlesig = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = run_checks(
            &CheckInput::new(&singlesig)
                .with_network(Network::Testnet)
                .with_known_address(known),
        );
        assert_eq!(result_of(&checks, "G3"), Fail);
    }

    #[test]
    fn check_serializes_to_the_section_19_1_shape() {
        let check = Check {
            code: "A1".to_owned(),
            category: "descriptor_parse".to_owned(),
            result: CheckResult::Pass,
            title: "Descriptor parses as BIP380".to_owned(),
        };
        let value = serde_json::to_value(check).expect("serializes");
        assert_eq!(
            value,
            serde_json::json!({
                "code": "A1",
                "category": "descriptor_parse",
                "result": "pass",
                "title": "Descriptor parses as BIP380"
            })
        );
    }

    #[test]
    fn check_result_serializes_snake_case() {
        let pairs = [
            (CheckResult::Pass, "pass"),
            (CheckResult::Warn, "warn"),
            (CheckResult::Fail, "fail"),
            (CheckResult::Na, "na"),
            (CheckResult::Unknown, "unknown"),
        ];
        for (result, expected) in pairs {
            assert_eq!(
                serde_json::to_value(result).unwrap(),
                serde_json::Value::String(expected.to_owned())
            );
        }
    }

    // === US-020: H1–H9 checklist + §16.3 critical failures ===

    /// The codes present in a critical-issues list (drops the title/description).
    fn issue_codes(issues: &[CriticalIssue]) -> Vec<CriticalCode> {
        issues.iter().map(|i| i.code).collect()
    }

    /// Run the A–G checks for a parsed descriptor on testnet (every committed
    /// descriptor fixture is a `tpub`, so a network must be supplied for G).
    fn checks_testnet(parsed: &ParsedDescriptor) -> Vec<Check> {
        run_checks(&CheckInput::new(parsed).with_network(Network::Testnet))
    }

    // --- The four parse-failure criticals (each maps a parse `ErrorCode`) ---

    #[test]
    fn generic_parse_failure_forces_not_ready() {
        let err = parse_descriptor("clearly not a descriptor").unwrap_err();
        // Not one of the more-specific parse codes ⇒ the generic critical.
        assert!(!matches!(
            err.code(),
            ErrorCode::ChecksumInvalid
                | ErrorCode::ContainsPrivateKey
                | ErrorCode::ThresholdExceedsKeys
        ));
        let checks = run_checks(&CheckInput::parse_failed());
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_parse_failure(err.code()),
        );
        assert_eq!(issue_codes(&issues), vec![CriticalCode::DescParseFail]);
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn invalid_checksum_forces_not_ready() {
        let err =
            parse_descriptor(fixture!("descriptors/singlesig/invalid_checksum.txt")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ChecksumInvalid); // self-check the fixture
        let checks = run_checks(&CheckInput::parse_failed());
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_parse_failure(err.code()),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![CriticalCode::DescChecksumInvalid]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn threshold_exceeds_keys_forces_not_ready() {
        let err = parse_descriptor(fixture!("descriptors/multisig/threshold_exceeds_keys.txt"))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ThresholdExceedsKeys);
        let checks = run_checks(&CheckInput::parse_failed());
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_parse_failure(err.code()),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![CriticalCode::KeyCountBelowThreshold]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn descriptor_with_xprv_forces_not_ready() {
        let err = parse_descriptor(fixture!("descriptors/invalid/contains_xprv.txt")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContainsPrivateKey);
        let checks = run_checks(&CheckInput::parse_failed());
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_parse_failure(err.code()),
        );
        assert_eq!(issue_codes(&issues), vec![CriticalCode::DescContainsXprv]);
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    // --- The descriptor-fact criticals (read from the A–G results) ---

    #[test]
    fn duplicate_xpub_forces_not_ready() {
        let parsed = parse(fixture!("descriptors/multisig/duplicate_xpub.txt"));
        let checks = checks_testnet(&parsed);
        let issues = evaluate_critical_failures(&checks, &CriticalContext::new());
        assert_eq!(issue_codes(&issues), vec![CriticalCode::DuplicateXpub]);
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn address_mismatch_forces_not_ready() {
        // The tb1 known address belongs to the 2-of-3 multisig; comparing it against
        // a singlesig wallet ⇒ G3 fail (the US-019 mismatch scenario).
        let known = fixture!("addresses/known_match_tb1.txt");
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = run_checks(
            &CheckInput::new(&parsed)
                .with_network(Network::Testnet)
                .with_known_address(known),
        );
        let issues = evaluate_critical_failures(&checks, &CriticalContext::new());
        assert_eq!(issue_codes(&issues), vec![CriticalCode::AddressMismatch]);
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn wallet_type_mismatch_forces_not_ready() {
        // Declared singlesig, descriptor is a 2-of-3 multisig ⇒ B2 fail.
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let checks = run_checks(
            &CheckInput::new(&parsed)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Singlesig),
        );
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_declared_wallet_type(DeclaredWalletType::Singlesig),
        );
        assert_eq!(issue_codes(&issues), vec![CriticalCode::WalletTypeMismatch]);
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn declared_multisig_without_quorum_forces_not_ready() {
        // Declared multisig, descriptor is a Taproot key-path: no extractable M-of-N
        // (D2 == Na) and not a clear singlesig (B2 != Fail) ⇒ threshold-missing, NOT
        // a wallet-type mismatch.
        let parsed = parse(fixture!("descriptors/taproot/tr_keypath.txt"));
        let checks = run_checks(
            &CheckInput::new(&parsed)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig),
        );
        assert_eq!(result_of(&checks, "D2"), Na); // precondition
        assert_ne!(result_of(&checks, "B2"), Fail);
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_declared_wallet_type(DeclaredWalletType::Multisig),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![CriticalCode::MultisigThresholdMissing]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    // --- The wizard-signal criticals (no descriptor / out-of-band facts) ---

    #[test]
    fn multisig_with_no_descriptor_forces_not_ready() {
        // Declared multisig, only loose xpubs ⇒ no descriptor to analyze; the
        // explicit wizard signal drives the critical.
        let issues = evaluate_critical_failures(
            &[],
            &CriticalContext::new()
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_multisig_descriptor_missing(true),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![CriticalCode::MultisigNoDescriptor]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn required_but_missing_change_descriptor_forces_not_ready() {
        // Singlesig, non-multipath, no change descriptor ⇒ E2 warn. Marking change as
        // required promotes the warning to a critical.
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = checks_testnet(&parsed);
        assert_eq!(result_of(&checks, "E2"), Warn); // precondition
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_change_descriptor_required(true),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![CriticalCode::ChangeDescRequiredMissing]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));

        // Without the "required" flag the same wallet has no critical (US-021 emits
        // the W-NO-CHANGE-DESC warning instead).
        let issues = evaluate_critical_failures(&checks, &CriticalContext::new());
        assert!(issues.is_empty());
        assert_eq!(forced_status(&issues), None);
    }

    #[test]
    fn undocumented_passphrase_forces_not_ready() {
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = checks_testnet(&parsed);
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new().with_passphrase(Passphrase::Undocumented),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![CriticalCode::PassphraseUndocumented]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));

        // A documented or absent passphrase is not a critical.
        for safe in [Passphrase::Documented, Passphrase::Absent] {
            let issues =
                evaluate_critical_failures(&checks, &CriticalContext::new().with_passphrase(safe));
            assert!(issues.is_empty(), "{safe:?} must not be a critical");
        }
    }

    #[test]
    fn detected_secret_forces_not_ready() {
        // The detector blocks before any parse, so there is no descriptor.
        let issues =
            evaluate_critical_failures(&[], &CriticalContext::new().with_secret_detected(true));
        assert_eq!(issue_codes(&issues), vec![CriticalCode::SecretDetected]);
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    // --- Aggregate behavior, status forcing, and serde shapes ---

    #[test]
    fn a_clean_wallet_has_no_criticals_and_forces_no_status() {
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = checks_testnet(&parsed);
        let issues = evaluate_critical_failures(&checks, &CriticalContext::new());
        assert!(issues.is_empty());
        assert_eq!(forced_status(&issues), None);
    }

    #[test]
    fn multiple_criticals_accumulate_in_table_order() {
        // A duplicate-xpub 2-of-3 that also has an undocumented passphrase and a
        // detected secret ⇒ three criticals, emitted in §16.3 table order.
        let parsed = parse(fixture!("descriptors/multisig/duplicate_xpub.txt"));
        let checks = checks_testnet(&parsed);
        let issues = evaluate_critical_failures(
            &checks,
            &CriticalContext::new()
                .with_passphrase(Passphrase::Undocumented)
                .with_secret_detected(true),
        );
        assert_eq!(
            issue_codes(&issues),
            vec![
                CriticalCode::DuplicateXpub,
                CriticalCode::PassphraseUndocumented,
                CriticalCode::SecretDetected,
            ]
        );
        assert_eq!(forced_status(&issues), Some(ReadinessStatus::NotReady));
    }

    #[test]
    fn all_twelve_critical_codes_are_defined() {
        assert_eq!(CriticalCode::ALL.len(), 12);
    }

    #[test]
    fn critical_code_serializes_to_its_stable_string() {
        for code in CriticalCode::ALL {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(code.as_str().to_owned()),
                "{code:?} serde rename must match as_str()"
            );
            let back: CriticalCode = serde_json::from_value(json).unwrap();
            assert_eq!(back, code, "round-trips");
            assert!(code.as_str().starts_with("C-"), "{code:?} code string");
            assert!(
                !code.title().is_empty() && !code.description().is_empty(),
                "{code:?} has text"
            );
        }
    }

    #[test]
    fn critical_issue_serializes_to_the_section_19_1_shape() {
        let issue = CriticalCode::DescParseFail.issue();
        let value = serde_json::to_value(issue).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "code": "C-DESC-PARSE-FAIL",
                "title": "Descriptor failed to parse",
                "description": "The descriptor as provided is not a valid BIP380 expression"
            })
        );
    }

    #[test]
    fn readiness_status_serializes_snake_case() {
        let pairs = [
            (ReadinessStatus::Ready, "ready"),
            (ReadinessStatus::MostlyReady, "mostly_ready"),
            (ReadinessStatus::NeedsAttention, "needs_attention"),
            (ReadinessStatus::NotReady, "not_ready"),
            (ReadinessStatus::CannotDetermine, "cannot_determine"),
        ];
        for (status, expected) in pairs {
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                serde_json::Value::String(expected.to_owned())
            );
        }
    }

    #[test]
    fn recovery_checklist_round_trips_h_answers() {
        let checklist = RecoveryChecklist {
            physical_copies: Some(Answer::Yes),
            signer_locations_known: Some(Answer::Unsure),
            recent_drill: Some(Answer::No),
            ..RecoveryChecklist::default()
        };
        let value = serde_json::to_value(checklist).unwrap();
        assert_eq!(value["physical_copies"], serde_json::json!("yes"));
        assert_eq!(value["signer_locations_known"], serde_json::json!("unsure"));
        assert_eq!(value["recent_drill"], serde_json::json!("no"));
        assert_eq!(value["passphrase_documented"], serde_json::Value::Null);
        let back: RecoveryChecklist = serde_json::from_value(value).unwrap();
        assert_eq!(back, checklist);
        // The context threads the checklist through for US-021.
        let ctx = CriticalContext::new().with_checklist(checklist);
        assert_eq!(ctx.checklist(), checklist);
    }

    // === US-021: §16.4 warning weights and the numeric score ===

    use WarningCode as W;

    /// A bare [`Check`] carrying only the `code`/`result` that scoring reads.
    fn scoring_check(code: &str, result: CheckResult) -> Check {
        Check {
            code: code.to_owned(),
            category: String::new(),
            result,
            title: String::new(),
        }
    }

    /// The four checks [`compute_score`] consults, all set so no check-derived
    /// warning fires (checksum present, change present, known address provided).
    fn base_checks() -> Vec<Check> {
        vec![
            scoring_check("A1", Pass),
            scoring_check("A2", Pass),
            scoring_check("E2", Pass),
            scoring_check("G3", Pass),
        ]
    }

    fn set_result(checks: &mut [Check], code: &str, result: CheckResult) {
        for c in checks.iter_mut().filter(|c| c.code == code) {
            c.result = result;
        }
    }

    /// Every H answer = `Yes` (no checklist warning fires).
    fn all_yes_checklist() -> RecoveryChecklist {
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

    /// A fully-prepared wallet: every warning suppressed.
    fn full_context() -> ScoringContext {
        ScoringContext::new()
            .with_checklist(all_yes_checklist())
            .with_emergency_contact_named(true)
            .with_hardware_signed_recently(true)
            .with_backup_same_location(false)
            .with_singlesig_separate_descriptors(false)
    }

    #[test]
    fn scoring_engine_version_is_pinned() {
        assert_eq!(SCORING_ENGINE_VERSION, "0.1.0");
    }

    #[test]
    fn active_warning_weights_match_the_section_16_4_table() {
        // (code, exact §16.4 weight), in PRD table order.
        let table = [
            (W::NoDescChecksum, -5),
            (W::NoChangeDesc, -15),
            (W::NoBirthHeight, -5),
            (W::NoGapLimit, -3),
            (W::NoKnownAddress, -10),
            (W::NoPrintedBackup, -8),
            (W::NoRecentDrill, -10),
            (W::NoHeirInstructions, -8),
            (W::NoEmergencyContact, -3),
            (W::NoHwTest, -8),
            (W::SameLocationBackup, -10),
            (W::WalletSwUndocumented, -5),
            (W::NoMultipath, -2),
        ];
        assert_eq!(WarningCode::ALL.len(), 13);
        assert_eq!(
            WarningCode::ALL.to_vec(),
            table.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
            "ALL must be in §16.4 table order"
        );
        for (code, weight) in table {
            assert_eq!(code.impact(), weight, "{code} weight");
        }
        // The active weights sum to -92, so the realistic score range is [8, 100].
        let total: i32 = WarningCode::ALL.iter().map(|c| c.impact()).sum();
        assert_eq!(total, -92);
    }

    #[test]
    fn warning_code_serializes_to_its_stable_string() {
        for code in WarningCode::ALL {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(code.as_str().to_owned()),
                "{code:?} serde rename must match as_str()"
            );
            let back: WarningCode = serde_json::from_value(json).unwrap();
            assert_eq!(back, code, "round-trips");
            assert!(code.as_str().starts_with("W-"), "{code:?} code string");
            assert!(code.impact() < 0, "{code:?} reduces the score");
            assert!(!code.condition().is_empty(), "{code:?} has condition text");
        }
    }

    #[test]
    fn a_fully_prepared_wallet_scores_100_with_an_empty_audit() {
        let result = compute_score(&base_checks(), &full_context());
        assert_eq!(result.numeric, 100);
        assert!(result.scoring_audit.is_empty());
    }

    #[test]
    fn each_warning_applies_its_exact_impact_in_isolation() {
        for code in WarningCode::ALL {
            let mut checks = base_checks();
            let mut cl = all_yes_checklist();
            let mut separate = false;
            let mut emergency = true;
            let mut hardware = true;
            let mut same_location = false;
            match code {
                W::NoDescChecksum => set_result(&mut checks, "A2", Warn),
                W::NoChangeDesc => set_result(&mut checks, "E2", Warn),
                W::NoBirthHeight => cl.birth_height_documented = Some(Answer::No),
                W::NoGapLimit => cl.gap_limit_documented = Some(Answer::No),
                W::NoKnownAddress => set_result(&mut checks, "G3", Na),
                W::NoPrintedBackup => cl.physical_copies = Some(Answer::No),
                W::NoRecentDrill => cl.recent_drill = Some(Answer::No),
                W::NoHeirInstructions => cl.heir_instructions_written = Some(Answer::No),
                W::NoEmergencyContact => emergency = false,
                W::NoHwTest => hardware = false,
                W::SameLocationBackup => same_location = true,
                W::WalletSwUndocumented => cl.wallet_software_documented = Some(Answer::No),
                W::NoMultipath => separate = true,
            }
            let ctx = ScoringContext::new()
                .with_checklist(cl)
                .with_singlesig_separate_descriptors(separate)
                .with_emergency_contact_named(emergency)
                .with_hardware_signed_recently(hardware)
                .with_backup_same_location(same_location);

            let result = compute_score(&checks, &ctx);
            assert_eq!(
                result.scoring_audit.len(),
                1,
                "{code} must fire exactly one warning"
            );
            let entry = result.scoring_audit[0];
            assert_eq!(entry.code, code);
            assert_eq!(entry.impact, code.impact());
            let expected = (100 + code.impact()) as u32;
            assert_eq!(entry.running_score, expected, "{code} running_score");
            assert_eq!(result.numeric, expected, "{code} numeric");
        }
    }

    #[test]
    fn only_yes_suppresses_a_checklist_warning() {
        // H7 birth-height: Yes ⇒ no warning; No / Unsure / skipped ⇒ W-NO-BIRTH-HEIGHT.
        let fires = |answer: Option<Answer>| {
            let cl = RecoveryChecklist {
                birth_height_documented: answer,
                ..all_yes_checklist()
            };
            let ctx = full_context().with_checklist(cl);
            compute_score(&base_checks(), &ctx)
                .scoring_audit
                .iter()
                .any(|e| e.code == W::NoBirthHeight)
        };
        assert!(!fires(Some(Answer::Yes)), "Yes suppresses");
        assert!(fires(Some(Answer::No)), "No fires");
        assert!(fires(Some(Answer::Unsure)), "Unsure fires");
        assert!(fires(None), "skip fires");
    }

    #[test]
    fn scoring_audit_entry_serializes_to_the_section_19_1_shape() {
        let entry = ScoringAuditEntry {
            code: WarningCode::NoChangeDesc,
            impact: -15,
            running_score: 85,
        };
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "code": "W-NO-CHANGE-DESC",
                "impact": -15,
                "running_score": 85
            })
        );
    }

    #[test]
    fn audit_trail_matches_the_section_19_1_example() {
        // §19.1: W-NO-CHANGE-DESC (-15 → 85) then W-NO-RECENT-DRILL (-10 → 75).
        let mut checks = base_checks();
        set_result(&mut checks, "E2", Warn);
        let cl = RecoveryChecklist {
            recent_drill: Some(Answer::No),
            ..all_yes_checklist()
        };
        let ctx = full_context().with_checklist(cl);

        let result = compute_score(&checks, &ctx);
        assert_eq!(result.numeric, 75);
        let value = serde_json::to_value(result.scoring_audit).unwrap();
        assert_eq!(
            value,
            serde_json::json!([
                {"code": "W-NO-CHANGE-DESC", "impact": -15, "running_score": 85},
                {"code": "W-NO-RECENT-DRILL", "impact": -10, "running_score": 75}
            ])
        );
    }

    #[test]
    fn all_warnings_fire_in_table_order_and_reconstruct_the_score() {
        let mut checks = base_checks();
        set_result(&mut checks, "A2", Warn);
        set_result(&mut checks, "E2", Warn);
        set_result(&mut checks, "G3", Na);
        // Every H answer skipped ⇒ all checklist warnings fire.
        let ctx = ScoringContext::new()
            .with_checklist(RecoveryChecklist::default())
            .with_singlesig_separate_descriptors(true)
            .with_emergency_contact_named(false)
            .with_hardware_signed_recently(false)
            .with_backup_same_location(true);

        let result = compute_score(&checks, &ctx);

        // All active warnings, in §16.4 table order.
        assert_eq!(
            result
                .scoring_audit
                .iter()
                .map(|e| e.code)
                .collect::<Vec<_>>(),
            WarningCode::ALL.to_vec()
        );
        // 100 − 92 = 8 (no clamping needed; the floor is defensive).
        assert_eq!(result.numeric, 8);

        // The audit reconstructs the running score from 100, clamped to [0, 100].
        let mut running = 100i32;
        for entry in &result.scoring_audit {
            assert_eq!(entry.impact, entry.code.impact());
            running = (running + entry.impact).clamp(0, 100);
            assert_eq!(entry.running_score, running as u32);
        }
        assert_eq!(result.numeric, running as u32);
    }

    #[test]
    fn integrates_with_run_checks_on_a_singlesig_fixture() {
        // wpkh tpub on testnet, no change descriptor, no known address:
        // A2 Pass (checksum present), E2 Warn (no change), G3 Na (no known address).
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        // Fully documented elsewhere ⇒ only the two check-derived warnings fire.
        let ctx = full_context().with_descriptor(&parsed, false);
        let result = compute_score(&checks, &ctx);
        assert_eq!(
            result
                .scoring_audit
                .iter()
                .map(|e| e.code)
                .collect::<Vec<_>>(),
            vec![W::NoChangeDesc, W::NoKnownAddress]
        );
        assert_eq!(result.numeric, 75);
    }

    #[test]
    fn taproot_no_longer_fires_a_preview_warning() {
        let parsed = parse(fixture!("descriptors/taproot/tr_keypath.txt"));
        // Clean check results + fully-documented context should stay clean:
        // Taproot preview was lifted in US-073.
        let ctx = full_context().with_descriptor(&parsed, false);
        let result = compute_score(&base_checks(), &ctx);
        assert!(result.scoring_audit.is_empty());
        assert_eq!(result.numeric, 100);
    }

    #[test]
    fn liana_miniscript_no_longer_fires_a_preview_warning() {
        let parsed = parse(fixture!("descriptors/timelock/liana_basic.txt"));
        assert!(parsed.uses_miniscript());
        assert!(parsed.uses_timelock());

        let checks = run_checks(
            &CheckInput::new(&parsed)
                .with_network(Network::Testnet)
                .with_network_confirmed(true),
        );
        assert_eq!(check_result(&checks, "D1"), Some(CheckResult::Pass));

        // Clean check results + fully-documented context should stay clean:
        // Miniscript-in-wsh preview is lifted in US-074.
        let ctx = full_context().with_descriptor(&parsed, false);
        let result = compute_score(&base_checks(), &ctx);
        assert!(result.scoring_audit.is_empty());
        assert_eq!(result.numeric, 100);
    }

    // === US-022: §16.2 status, §16.5 Cannot Determine, §16.6 survivability ===

    /// A single critical issue (any code) for the "criticals force Not Ready" tests.
    fn one_critical() -> Vec<CriticalIssue> {
        vec![CriticalCode::DescParseFail.issue()]
    }

    #[test]
    fn headline_strings_match_the_section_16_2_wording() {
        assert_eq!(ReadinessStatus::Ready.headline(), "Ready");
        assert_eq!(ReadinessStatus::MostlyReady.headline(), "Mostly Ready");
        assert_eq!(
            ReadinessStatus::NeedsAttention.headline(),
            "Needs Attention"
        );
        assert_eq!(ReadinessStatus::NotReady.headline(), "Not Ready");
        assert_eq!(
            ReadinessStatus::CannotDetermine.headline(),
            "Cannot Determine"
        );
    }

    #[test]
    fn numeric_bands_map_to_the_section_16_2_statuses() {
        use ReadinessStatus as S;
        // No criticals, no §16.5 signal. A `G3 == Pass` check supplies the D8 match
        // the `Ready` band requires; `no_d8` omits it.
        let d8 = vec![scoring_check("G3", Pass)];
        let no_d8: Vec<Check> = vec![];
        let ctx = StatusContext::new();

        // Ready 90–100 (with D8).
        assert_eq!(map_status(&d8, 100, &[], &ctx), S::Ready);
        assert_eq!(map_status(&d8, 90, &[], &ctx), S::Ready);
        // 89 drops to Mostly Ready even with a D8 match.
        assert_eq!(map_status(&d8, 89, &[], &ctx), S::MostlyReady);
        // Mostly Ready 70–89.
        assert_eq!(map_status(&no_d8, 89, &[], &ctx), S::MostlyReady);
        assert_eq!(map_status(&no_d8, 70, &[], &ctx), S::MostlyReady);
        // Needs Attention 40–69.
        assert_eq!(map_status(&no_d8, 69, &[], &ctx), S::NeedsAttention);
        assert_eq!(map_status(&no_d8, 40, &[], &ctx), S::NeedsAttention);
        // Not Ready 0–39.
        assert_eq!(map_status(&no_d8, 39, &[], &ctx), S::NotReady);
        assert_eq!(map_status(&no_d8, 0, &[], &ctx), S::NotReady);
    }

    #[test]
    fn ready_requires_the_d8_known_address_match() {
        // A 90+ score is necessary but not sufficient: without `G3 == Pass`, the
        // best attainable status is Mostly Ready.
        let matched = vec![scoring_check("G3", Pass)];
        let not_provided = vec![scoring_check("G3", Na)];
        let ctx = StatusContext::new();
        assert_eq!(map_status(&matched, 95, &[], &ctx), ReadinessStatus::Ready);
        assert_eq!(
            map_status(&not_provided, 95, &[], &ctx),
            ReadinessStatus::MostlyReady
        );
        // No G3 check at all behaves like "no match".
        assert_eq!(map_status(&[], 95, &[], &ctx), ReadinessStatus::MostlyReady);
    }

    #[test]
    fn any_critical_forces_not_ready_regardless_of_score() {
        // A perfect score with a D8 match still becomes Not Ready when a critical is
        // present (§16.3 "regardless of numeric score").
        let d8 = vec![scoring_check("G3", Pass)];
        assert_eq!(
            map_status(&d8, 100, &one_critical(), &StatusContext::new()),
            ReadinessStatus::NotReady
        );
    }

    #[test]
    fn criticals_take_precedence_over_cannot_determine() {
        // Both a critical AND a §16.5 signal present ⇒ Not Ready wins (a definitive
        // finding beats "insufficient information").
        let ctx = StatusContext::new().with_unrecognized_export(true);
        assert_eq!(
            map_status(&[], 80, &one_critical(), &ctx),
            ReadinessStatus::NotReady
        );
    }

    // --- The four §16.5 Cannot Determine triggers ---

    #[test]
    fn cannot_determine_when_network_is_undeterminable_and_undeclared() {
        // §16.5.1 — a tpub (ambiguous network) with NO network supplied: F1/F2/G1
        // are all Unknown, so no verdict can be rendered.
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        let checks = run_checks(&CheckInput::new(&parsed));
        assert_eq!(result_of(&checks, "F1"), Unknown); // preconditions
        assert_eq!(result_of(&checks, "G1"), Unknown);
        let numeric = compute_score(&checks, &ScoringContext::new()).numeric;
        assert_eq!(
            map_status(&checks, numeric, &[], &StatusContext::new()),
            ReadinessStatus::CannotDetermine
        );

        // Supplying a network to derive on lifts the condition (we can now assess).
        let checks = run_checks(&CheckInput::new(&parsed).with_network(Network::Testnet));
        assert_ne!(
            map_status(&checks, numeric, &[], &StatusContext::new()),
            ReadinessStatus::CannotDetermine
        );
    }

    #[test]
    fn cannot_determine_when_key_origin_is_entirely_absent() {
        // §16.5.2 — a bare-xpub descriptor with no [fingerprint/path] on any key.
        // A mainnet xpub keeps the network determinable, isolating §16.5.2 from .1.
        let tpub = {
            let p = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
            p.key_origins()[0].xpub().expect("xpub present").to_owned()
        };
        let xpub = to_mainnet_xpub(&tpub);
        let body = format!("wpkh({xpub}/0/*)");
        let descriptor = compute_checksum(&body).expect("checksum computes");
        let parsed = parse(&descriptor);
        assert!(key_origins_entirely_absent(&parsed)); // precondition

        let checks = run_checks(&CheckInput::new(&parsed));
        assert_eq!(result_of(&checks, "F1"), Pass, "mainnet ⇒ determinable");
        let ctx = StatusContext::new().with_descriptor(&parsed);
        assert_eq!(
            map_status(&checks, 80, &[], &ctx),
            ReadinessStatus::CannotDetermine
        );

        // A descriptor WITH origins does not trigger it.
        let with_origins = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        assert!(!key_origins_entirely_absent(&with_origins));
    }

    #[test]
    fn cannot_determine_for_an_unrecognized_export() {
        // §16.5.3 — no descriptor, an explicit wizard signal, and NO parse-failure
        // critical (an unrecognized file is Cannot Determine, not Not Ready).
        let ctx = StatusContext::new().with_unrecognized_export(true);
        assert_eq!(
            map_status(&[], 0, &[], &ctx),
            ReadinessStatus::CannotDetermine
        );
    }

    #[test]
    fn cannot_determine_when_wizard_aborted_before_address_comparison() {
        // §16.5.4.
        let ctx = StatusContext::new().with_wizard_aborted(true);
        assert_eq!(
            map_status(&[], 50, &[], &ctx),
            ReadinessStatus::CannotDetermine
        );
    }

    #[test]
    fn a_complete_wallet_with_a_matched_address_is_ready() {
        // End-to-end: a multipath 2-of-3 (has a change branch) on testnet, network
        // confirmed, known address matched, everything documented ⇒ 100 + D8 ⇒ Ready.
        let parsed = parse(fixture!("descriptors/multisig/multipath_2of3.txt"));
        let known = fixture!("addresses/known_match_tb1.txt");
        let checks = run_checks(
            &CheckInput::new(&parsed)
                .with_network(Network::Testnet)
                .with_network_confirmed(true)
                .with_known_address(known),
        );
        assert_eq!(result_of(&checks, "G3"), Pass); // D8 matched
        let criticals = evaluate_critical_failures(&checks, &CriticalContext::new());
        assert!(criticals.is_empty());
        let numeric =
            compute_score(&checks, &full_context().with_descriptor(&parsed, false)).numeric;
        assert_eq!(numeric, 100);
        assert_eq!(
            map_status(&checks, numeric, &criticals, &StatusContext::new()),
            ReadinessStatus::Ready
        );
    }

    // --- §16.6 survivability ---

    #[test]
    fn survivability_2of3_matches_the_section_19_1_example() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
        let s = compute_survivability(&parsed).expect("multisig has survivability");
        assert!(s.tested);
        assert_eq!(s.lose_1_signer, "ok"); // 3 - 1 = 2 ≥ 2
        assert_eq!(s.lose_2_signers, "fail_expected_for_2of3"); // 3 - 2 = 1 < 2
        assert_eq!(s.lose_descriptor_only, "ok_if_xpubs_retained");

        let value = serde_json::to_value(&s).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "tested": true,
                "lose_1_signer": "ok",
                "lose_2_signers": "fail_expected_for_2of3",
                "lose_descriptor_only": "ok_if_xpubs_retained"
            })
        );
    }

    #[test]
    fn survivability_3of5_survives_both_signer_losses() {
        let parsed = parse(fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"));
        let s = compute_survivability(&parsed).expect("multisig has survivability");
        assert!(s.tested);
        assert_eq!(s.lose_1_signer, "ok"); // 5 - 1 = 4 ≥ 3
        assert_eq!(s.lose_2_signers, "ok"); // 5 - 2 = 3 ≥ 3
        assert_eq!(s.lose_descriptor_only, "ok_if_xpubs_retained");
    }

    #[test]
    fn singlesig_has_no_survivability() {
        let parsed = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
        assert_eq!(compute_survivability(&parsed), None);
    }

    #[test]
    fn taproot_keypath_has_no_survivability() {
        // No extractable M-of-N ⇒ no survivability dimension (richer policies get
        // other dimensions in later milestones).
        let parsed = parse(fixture!("descriptors/taproot/tr_keypath.txt"));
        assert_eq!(compute_survivability(&parsed), None);
    }
}
