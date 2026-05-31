//! `address-derive` — receive/change address derivation from a parsed descriptor.
//!
//! Given a [`descriptor_audit::ParsedDescriptor`], derive the first-N receive and
//! change addresses (PRD §17.4) into the [`DerivedAddresses`] shape the §19.1
//! report consumes (`addresses.receive_derived` / `addresses.change_derived`).
//! Known-address comparison (§17.5) — [`compare_known_address`] — searches that
//! derived range for a user-supplied address and reports the hit index/chain (or a
//! miss) as the §19.1 `addresses.known_address_match` fact.
//!
//! # Safety inheritance — the §17.4 derivation refusals
//! Derivation "refuses to proceed" on three conditions. Two are guaranteed
//! upstream by [`descriptor_audit::parse_descriptor`], so a value of type
//! [`ParsedDescriptor`] can never carry them and this crate never has to re-check:
//! - **xprv present** → refused at parse with `E-PARSE-005`, and structurally
//!   impossible anyway: a [`Descriptor<DescriptorPublicKey>`] holds only public
//!   keys (a private key would be a `DescriptorSecretKey`).
//! - **mixed networks** → refused at parse with `E-PARSE-004`.
//!
//! The third refusal is enforced here, because it depends on the requested count:
//! - **no `*` wildcard AND count > 1** → a fixed descriptor describes a single
//!   address, so a request for more is refused ([`ErrorCode::InputTooLarge`]).
//!
//! # Network
//! [`derive_addresses`] takes an explicit `network`: address *encoding* (the
//! `bc`/`tb`/`bcrt` HRP and version byte) is chosen by the network, not by the
//! key. The caller resolves the descriptor's inferred family
//! ([`ParsedDescriptor::network_inference`](descriptor_audit::ParsedDescriptor::network_inference))
//! — mainnet `xpub` is determined; a `tpub` is ambiguous across
//! testnet/signet/regtest and the user must confirm (§16.5) — and passes the
//! concrete [`Network`]. This crate does not guess.

use descriptor_audit::ParsedDescriptor;
use error_taxonomy::{ErrorCode, LifeboatError};
use miniscript::bitcoin::address::NetworkUnchecked;
use miniscript::bitcoin::Address;
use miniscript::{Descriptor, DescriptorPublicKey};

pub use miniscript::bitcoin::Network;

/// Default number of addresses to derive per chain (PRD §17.4).
pub const DEFAULT_ADDRESS_COUNT: u32 = 10;

/// Maximum number of addresses derivable per chain. PRD §17.4 makes the count
/// configurable over `1..=1000`; known-address comparison (§17.5) expands its
/// search to this bound.
pub const MAX_ADDRESS_COUNT: u32 = 1000;

/// Which derivation chain a derived address belongs to (the §19.1 `chain` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    /// External / receive chain (BIP44 chain index `0`).
    Receive,
    /// Internal / change chain (BIP44 chain index `1`).
    Change,
}

impl Chain {
    /// The stable lower-case string used in the §19.1 report and the CLI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Receive => "receive",
            Chain::Change => "change",
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single derived address — one entry of the §19.1 `addresses.*_derived` arrays
/// (`{"index": 0, "address": "bc1q…", "chain": "receive"}`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DerivedAddress {
    /// The wildcard (`*`) index this address was derived at.
    pub index: u32,
    /// The address in its canonical string form for the target network.
    pub address: String,
    /// Whether this is a receive or change address.
    pub chain: Chain,
}

/// Receive and change addresses derived from one descriptor — the §19.1
/// `addresses` object (minus `known_address_match`, which US-018 adds).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DerivedAddresses {
    /// First-N receive addresses (chain index `0`).
    pub receive_derived: Vec<DerivedAddress>,
    /// First-N change addresses (chain index `1`). Empty for a single-path
    /// descriptor with no change branch (the change descriptor, if any, is a
    /// separate input — see [`derive_chain`]).
    pub change_derived: Vec<DerivedAddress>,
}

/// Derive `count` addresses (indices `0..count`) from one **single-path**
/// descriptor, labeling each with `chain`.
///
/// Multipath descriptors must be expanded first via
/// [`ParsedDescriptor::expand_multipath`](descriptor_audit::ParsedDescriptor::expand_multipath);
/// passing one here is rejected. This is the primitive [`derive_addresses`] is
/// built on, and the entry the report/CLI use for an explicitly-provided change
/// descriptor (label it [`Chain::Change`]).
///
/// # Errors
/// - [`ErrorCode::InputTooLarge`] when `count` is outside `1..=`[`MAX_ADDRESS_COUNT`],
///   or when the descriptor has no `*` wildcard and `count > 1` (PRD §17.4: a
///   fixed descriptor describes a single address).
/// - [`ErrorCode::Internal`] if a multipath descriptor is passed, or if
///   derivation/encoding unexpectedly fails for an otherwise-valid descriptor
///   (e.g. a script type with no address, such as bare `pk`).
pub fn derive_chain(
    descriptor: &Descriptor<DescriptorPublicKey>,
    network: Network,
    chain: Chain,
    count: u32,
) -> Result<Vec<DerivedAddress>, LifeboatError> {
    if !(1..=MAX_ADDRESS_COUNT).contains(&count) {
        return Err(
            LifeboatError::new(ErrorCode::InputTooLarge).with_context(format!(
                "address count must be between 1 and {MAX_ADDRESS_COUNT} (requested {count})"
            )),
        );
    }
    if descriptor.is_multipath() {
        return Err(LifeboatError::new(ErrorCode::Internal).with_context(
            "derive_chain requires a single-path descriptor; expand multipath first",
        ));
    }
    if !descriptor.has_wildcard() && count > 1 {
        return Err(LifeboatError::new(ErrorCode::InputTooLarge).with_context(
            "descriptor has no '*' wildcard, so it describes a single fixed address; \
             request 1 address or provide a ranged descriptor",
        ));
    }

    let mut derived = Vec::with_capacity(count as usize);
    for index in 0..count {
        let address = derive_at(descriptor, network, index)?;
        derived.push(DerivedAddress {
            index,
            address: address.to_string(),
            chain,
        });
    }
    Ok(derived)
}

/// Derive the address at one wildcard `index` of a **single-path** descriptor.
///
/// The shared derivation primitive behind [`derive_chain`] and the known-address
/// search ([`compare_known_address`]). Both miniscript failure modes map to
/// [`ErrorCode::Internal`]: an otherwise-valid [`ParsedDescriptor`] should always
/// derive, so the only realistic trigger is a script type with no address (e.g.
/// bare `pk`), which is outside the §17.4 supported types.
fn derive_at(
    descriptor: &Descriptor<DescriptorPublicKey>,
    network: Network,
    index: u32,
) -> Result<Address, LifeboatError> {
    let definite = descriptor.at_derivation_index(index).map_err(|e| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context(format!("could not derive descriptor at index {index}"))
            .with_source(e)
    })?;
    definite.address(network).map_err(|e| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context(format!("descriptor has no address at index {index}"))
            .with_source(e)
    })
}

/// Derive the first-`count` receive and change addresses from a parsed descriptor
/// (PRD §17.4, §19.1).
///
/// A BIP389 multipath descriptor (`<0;1>`) is expanded so `receive_derived` comes
/// from the receive branch and `change_derived` from the change branch. A
/// single-path descriptor yields only `receive_derived`; `change_derived` is
/// empty (its change descriptor, if any, is supplied separately).
///
/// Pass [`DEFAULT_ADDRESS_COUNT`] for the §17.4 default of 10.
///
/// # Errors
/// Propagates [`derive_chain`]'s errors (count range, no-wildcard refusal), plus
/// `E-PARSE-001` if multipath expansion fails (unreachable for an already-parsed
/// descriptor — see [`ParsedDescriptor::expand_multipath`](descriptor_audit::ParsedDescriptor::expand_multipath)).
pub fn derive_addresses(
    parsed: &ParsedDescriptor,
    network: Network,
    count: u32,
) -> Result<DerivedAddresses, LifeboatError> {
    let branches = parsed.expand_multipath()?;
    let receive = branches.first().ok_or_else(|| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("multipath expansion produced no descriptors")
    })?;
    let receive_derived = derive_chain(receive, network, Chain::Receive, count)?;
    let change_derived = match branches.get(1) {
        Some(change) => derive_chain(change, network, Chain::Change, count)?,
        None => Vec::new(),
    };
    Ok(DerivedAddresses {
        receive_derived,
        change_derived,
    })
}

/// Where in a descriptor's derived range a known address was found — the
/// `matched_at` object of the §19.1 `known_address_match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MatchLocation {
    /// The wildcard (`*`) index the address derived at.
    pub index: u32,
    /// Which chain (receive/change) the match was on.
    pub chain: Chain,
}

/// Result of comparing a user-supplied "known" address against a descriptor's
/// derived addresses (PRD §17.5) — the §19.1 `addresses.known_address_match`
/// object.
///
/// This is a **fact**, never an error: a miss is a legitimate, expected outcome
/// (it is exactly what the [`AddressExpectation::ToNotMatch`] flow asks for). The
/// readiness-score layer (US-020) is the single place that turns *a miss against a
/// [`ToMatch`](AddressExpectation::ToMatch) expectation* into the critical
/// `C-ADDRESS-MISMATCH` condition that forces "Not Ready" — this crate only reports
/// whether the address was found and where (the universal fact→scoring split).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KnownAddressMatch {
    /// The address the user supplied (trimmed, verbatim — what they typed).
    pub provided: String,
    /// Whether `provided` matched any derived address within the search range.
    pub matched: bool,
    /// The hit location, or `null` when `matched` is `false`.
    pub matched_at: Option<MatchLocation>,
}

impl KnownAddressMatch {
    fn hit(provided: String, index: u32, chain: Chain) -> Self {
        Self {
            provided,
            matched: true,
            matched_at: Some(MatchLocation { index, chain }),
        }
    }

    fn miss(provided: String) -> Self {
        Self {
            provided,
            matched: false,
            matched_at: None,
        }
    }

    /// Whether the actual outcome met the caller's [`AddressExpectation`] (§17.5).
    ///
    /// - [`ToMatch`](AddressExpectation::ToMatch): met iff the address was found
    ///   (the default "this address belongs to my wallet" flow; an unmet
    ///   expectation is the `C-ADDRESS-MISMATCH` case).
    /// - [`ToNotMatch`](AddressExpectation::ToNotMatch): met iff the address was
    ///   *not* found (the "rule out a wrong-wallet import" flow; an unmet
    ///   expectation means the address unexpectedly *does* belong).
    #[must_use]
    pub fn meets_expectation(&self, expectation: AddressExpectation) -> bool {
        match expectation {
            AddressExpectation::ToMatch => self.matched,
            AddressExpectation::ToNotMatch => !self.matched,
        }
    }
}

/// What the user expects when supplying a known address for comparison (PRD §17.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressExpectation {
    /// The address is believed to belong to this wallet — the default §17.5 flow.
    /// A miss is the critical `C-ADDRESS-MISMATCH` condition (emitted by
    /// readiness-score, not here).
    ToMatch,
    /// The address is expected **not** to belong, e.g. to rule out a wrong-wallet
    /// import. A hit is the surprising result.
    ToNotMatch,
}

/// Compare a user-supplied known address against a descriptor's derived addresses
/// (PRD §17.5).
///
/// The address is first validated to parse for `network` (a malformed address, or
/// one valid only on another network, is a user-correctable input error). Then the
/// first `count` receive and change addresses are searched; on a miss the search
/// transparently expands to the first [`MAX_ADDRESS_COUNT`] of each chain (§17.5
/// step 4). Receive is searched before change within each phase, so a hit reports
/// the lowest receive index first, then the lowest change index.
///
/// For a BIP389 multipath descriptor, receive = branch 0 and change = branch 1 (as
/// in [`derive_addresses`]); a single-path descriptor has no change branch. A fixed
/// (no-`*`) descriptor describes exactly one address, searched at index 0.
///
/// The returned [`KnownAddressMatch`] is a fact (a miss is **not** an error); see
/// its docs and [`AddressExpectation`] for how readiness-score maps it to
/// `C-ADDRESS-MISMATCH`.
///
/// # Errors
/// - [`ErrorCode::InputEmpty`] if `address` is empty/whitespace.
/// - [`ErrorCode::InputInvalidFormat`] if `address` does not parse as a Bitcoin
///   address, or parses but is not valid for `network` (§17.5 step 1). There is no
///   address-specific Appendix-C code, so this is the closest user-correctable one,
///   with the precise reason in the context (the same convention [`derive_chain`]
///   uses for the count range).
/// - [`ErrorCode::InputTooLarge`] if `count` is outside `1..=`[`MAX_ADDRESS_COUNT`].
/// - [`ErrorCode::Internal`] if multipath expansion or derivation unexpectedly
///   fails for an otherwise-valid descriptor.
pub fn compare_known_address(
    parsed: &ParsedDescriptor,
    network: Network,
    address: &str,
    count: u32,
) -> Result<KnownAddressMatch, LifeboatError> {
    if !(1..=MAX_ADDRESS_COUNT).contains(&count) {
        return Err(
            LifeboatError::new(ErrorCode::InputTooLarge).with_context(format!(
                "address count must be between 1 and {MAX_ADDRESS_COUNT} (requested {count})"
            )),
        );
    }
    let provided = address.trim();
    if provided.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty)
            .with_context("no known address was provided to compare"));
    }
    let target = parse_known_address(provided, network)?;

    let branches = parsed.expand_multipath()?;
    let receive = branches.first().ok_or_else(|| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("multipath expansion produced no descriptors")
    })?;
    let change = branches.get(1);

    // §17.5: search the first `count` of each chain, then transparently expand to
    // MAX_ADDRESS_COUNT. Receive is searched before change within each phase.
    for (start, end) in [(0, count), (count, MAX_ADDRESS_COUNT)] {
        if start >= end {
            continue;
        }
        if let Some(index) = find_in_chain(receive, network, &target, start, end)? {
            return Ok(KnownAddressMatch::hit(
                provided.to_string(),
                index,
                Chain::Receive,
            ));
        }
        if let Some(change) = change {
            if let Some(index) = find_in_chain(change, network, &target, start, end)? {
                return Ok(KnownAddressMatch::hit(
                    provided.to_string(),
                    index,
                    Chain::Change,
                ));
            }
        }
    }
    Ok(KnownAddressMatch::miss(provided.to_string()))
}

/// Parse `address` and require it to be valid for `network` (PRD §17.5 step 1).
fn parse_known_address(address: &str, network: Network) -> Result<Address, LifeboatError> {
    let unchecked = address.parse::<Address<NetworkUnchecked>>().map_err(|e| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("the provided known address is not a valid Bitcoin address")
            .with_source(e)
    })?;
    unchecked.require_network(network).map_err(|e| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!(
                "the provided known address is not valid for the {network} network"
            ))
            .with_source(e)
    })
}

/// Search `[start, end)` of one single-path `descriptor` for `target`, returning
/// the matching index. A fixed (no-`*`) descriptor has a single address and is
/// checked only in the phase that includes index 0.
fn find_in_chain(
    descriptor: &Descriptor<DescriptorPublicKey>,
    network: Network,
    target: &Address,
    start: u32,
    end: u32,
) -> Result<Option<u32>, LifeboatError> {
    if !descriptor.has_wildcard() {
        if start == 0 {
            let addr = derive_at(descriptor, network, 0)?;
            return Ok((addr == *target).then_some(0));
        }
        return Ok(None);
    }
    for index in start..end {
        if derive_at(descriptor, network, index)? == *target {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use descriptor_audit::parse_descriptor;

    /// Read a repo-root fixture (same convention as `descriptor-audit`).
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

    // Account-level extended public keys (m/44h|49h|84h|86h/0h/0h) for the
    // documented BIP39 test mnemonic "abandon abandon … about". Derived and
    // verified by examples/probe_vectors.rs against the published BIP44/49/84/86
    // address vectors (a transcription error would make `decode`/derivation fail
    // or the address mismatch the known value below). Never a real wallet (§27).
    const BIP44_XPUB: &str = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
    const BIP49_XPUB: &str = "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7";
    const BIP84_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    const BIP86_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

    fn derive(descriptor: &str, network: Network, count: u32) -> DerivedAddresses {
        let parsed = parse_descriptor(descriptor).expect("fixture/descriptor parses");
        derive_addresses(&parsed, network, count).expect("derivation succeeds")
    }

    // --- Known-answer vectors: derived addresses match the published BIP vectors.

    #[test]
    fn bip84_wpkh_matches_published_vectors() {
        // BIP84 §Test vectors, account 0 of "abandon … about".
        let out = derive(&format!("wpkh({BIP84_XPUB}/<0;1>/*)"), Network::Bitcoin, 2);
        assert_eq!(
            out.receive_derived[0].address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            out.receive_derived[1].address,
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            out.change_derived[0].address,
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
    }

    #[test]
    fn bip49_sh_wpkh_matches_published_vector() {
        let out = derive(&format!("sh(wpkh({BIP49_XPUB}/0/*))"), Network::Bitcoin, 1);
        assert_eq!(
            out.receive_derived[0].address,
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );
        // Single-path descriptor: no change branch.
        assert!(out.change_derived.is_empty());
    }

    #[test]
    fn bip86_tr_matches_published_vector() {
        let out = derive(&format!("tr({BIP86_XPUB}/0/*)"), Network::Bitcoin, 1);
        assert_eq!(
            out.receive_derived[0].address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    fn taproot_scriptpath_multi_a_fixture_derives_expected_addresses() {
        let out = derive(
            fixture!("descriptors/taproot/tr_scriptpath_multi_a.txt"),
            Network::Testnet,
            2,
        );
        assert_eq!(out.receive_derived.len(), 2);
        assert!(out.change_derived.is_empty());
        assert_eq!(
            out.receive_derived[0].address,
            "tb1pvgqgfnxss6zf5fhkkkx243uccxk9zp47myqpvfdpm8u3pcmvspdst2he0a"
        );
        assert_eq!(
            out.receive_derived[1].address,
            "tb1pd4tad03lq8jwmf046rfcva6hxdek952v2wmt73yv84z2232ws2cqmlzasl"
        );
    }

    #[test]
    fn liana_timelock_fixture_derives_receive_and_change() {
        let out = derive(
            fixture!("descriptors/timelock/liana_basic.txt"),
            Network::Testnet,
            2,
        );
        assert_eq!(out.receive_derived.len(), 2);
        assert_eq!(out.change_derived.len(), 2);
        assert_eq!(
            out.receive_derived[0].address,
            "tb1qvjxt7vawfdgspm3nng20kjhlm48qwrvvt6l36kq3ttgsrugtnhtqgt9zyc"
        );
        assert_eq!(
            out.receive_derived[1].address,
            "tb1qmx7k2esh2n8upjuheq3uuqzwxg0glj44azjv7yhyetf4lss78nhqd2mdv8"
        );
        assert_eq!(
            out.change_derived[0].address,
            "tb1qysy5g6nqhd5x9ml080vu88lvqrcp0h9wrnnp5f6y53hs5qjm397quddjku"
        );
        assert_eq!(
            out.change_derived[1].address,
            "tb1qd2f06xxvaamjstpg3gqurqjklufgwvw4j4h32fcdqfrnc8n33ggsma77pw"
        );
    }

    #[test]
    fn bip44_pkh_matches_vector() {
        let out = derive(&format!("pkh({BIP44_XPUB}/0/*)"), Network::Bitcoin, 1);
        assert_eq!(
            out.receive_derived[0].address,
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        );
    }

    // --- Multisig (wsh sortedmulti) on its inferred test network.

    #[test]
    fn wsh_sortedmulti_testnet_fixture_derives() {
        let out = derive(
            fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"),
            Network::Testnet,
            3,
        );
        assert_eq!(out.receive_derived.len(), 3);
        assert!(
            out.change_derived.is_empty(),
            "single-path fixture: no change"
        );
        for (i, a) in out.receive_derived.iter().enumerate() {
            assert_eq!(a.index, i as u32);
            assert_eq!(a.chain, Chain::Receive);
            // P2WSH on testnet → 62-char `tb1q` bech32 address.
            assert!(a.address.starts_with("tb1q"), "got {}", a.address);
        }
        // Distinct per index.
        assert_ne!(
            out.receive_derived[0].address,
            out.receive_derived[1].address
        );
    }

    #[test]
    fn multipath_fixture_splits_receive_and_change() {
        let out = derive(
            fixture!("descriptors/multisig/multipath_2of3.txt"),
            Network::Testnet,
            2,
        );
        assert_eq!(out.receive_derived.len(), 2);
        assert_eq!(out.change_derived.len(), 2);
        assert_eq!(out.receive_derived[0].chain, Chain::Receive);
        assert_eq!(out.change_derived[0].chain, Chain::Change);
        assert_ne!(
            out.receive_derived[0].address,
            out.change_derived[0].address
        );

        // Cross-check (US-009 byte-identity): the multipath `/0` branch is the
        // standalone single-path 2-of-3 fixture, so its receive addresses match.
        let single = derive(
            fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"),
            Network::Testnet,
            2,
        );
        assert_eq!(out.receive_derived, single.receive_derived);
    }

    // --- §17.4 derivation refusals.

    #[test]
    fn no_wildcard_refuses_many_but_allows_one() {
        // A fixed (no `*`) descriptor describes exactly one address.
        let parsed = parse_descriptor(&format!("wpkh({BIP84_XPUB}/0/0)")).unwrap();
        let err = derive_addresses(&parsed, Network::Bitcoin, 10).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InputTooLarge);

        let one = derive_addresses(&parsed, Network::Bitcoin, 1).unwrap();
        assert_eq!(one.receive_derived.len(), 1);
        // The fixed /0/0 address is exactly BIP84 receive index 0.
        assert_eq!(
            one.receive_derived[0].address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    #[test]
    fn count_out_of_range_is_refused() {
        let parsed = parse_descriptor(&format!("wpkh({BIP84_XPUB}/0/*)")).unwrap();
        assert_eq!(
            derive_addresses(&parsed, Network::Bitcoin, 0)
                .unwrap_err()
                .code(),
            ErrorCode::InputTooLarge
        );
        assert_eq!(
            derive_addresses(&parsed, Network::Bitcoin, MAX_ADDRESS_COUNT + 1)
                .unwrap_err()
                .code(),
            ErrorCode::InputTooLarge
        );
        // The boundary value is accepted.
        let max = derive_addresses(&parsed, Network::Bitcoin, MAX_ADDRESS_COUNT).unwrap();
        assert_eq!(max.receive_derived.len(), MAX_ADDRESS_COUNT as usize);
    }

    #[test]
    fn xprv_descriptor_is_refused_before_derivation() {
        // Derivation takes a `ParsedDescriptor`, which `parse_descriptor` refuses
        // to build from a descriptor containing an extended private key — so a
        // private key can never reach the derivation engine (§17.4 / E-PARSE-005).
        let err = parse_descriptor(fixture!("descriptors/invalid/contains_xprv.txt")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContainsPrivateKey);
    }

    #[test]
    fn mixed_network_descriptor_is_refused_before_derivation() {
        // Likewise, mixed-network descriptors are refused at parse (§17.4 /
        // E-PARSE-004), so derivation never has to pick a chain for them.
        let err = parse_descriptor(fixture!("descriptors/invalid/network_mixed.txt")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NetworkMixed);
    }

    // --- Result shape and metadata.

    #[test]
    fn chain_labels_and_indices_are_correct() {
        let out = derive(&format!("wpkh({BIP84_XPUB}/<0;1>/*)"), Network::Bitcoin, 5);
        for (i, a) in out.receive_derived.iter().enumerate() {
            assert_eq!(a.index, i as u32);
            assert_eq!(a.chain, Chain::Receive);
        }
        for (i, a) in out.change_derived.iter().enumerate() {
            assert_eq!(a.index, i as u32);
            assert_eq!(a.chain, Chain::Change);
        }
    }

    #[test]
    fn derived_address_json_shape_matches_schema() {
        // Locks the §19.1 `addresses.*_derived` entry shape.
        let entry = DerivedAddress {
            index: 3,
            address: "bc1qexample".to_string(),
            chain: Chain::Receive,
        };
        let json = serde_json::to_value(entry).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"index": 3, "address": "bc1qexample", "chain": "receive"})
        );
        assert_eq!(
            serde_json::to_value(Chain::Change).unwrap(),
            serde_json::json!("change")
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let d = format!("wpkh({BIP84_XPUB}/0/*)");
        assert_eq!(
            derive(&d, Network::Bitcoin, 4),
            derive(&d, Network::Bitcoin, 4)
        );
    }

    #[test]
    fn derive_chain_rejects_multipath_input() {
        // The low-level primitive requires a single-path descriptor.
        let parsed = parse_descriptor(&format!("wpkh({BIP84_XPUB}/<0;1>/*)")).unwrap();
        let err =
            derive_chain(parsed.descriptor(), Network::Bitcoin, Chain::Receive, 5).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn derives_100_singlesig_under_200ms() {
        // The §17.4 / §28 performance target, enforced in the gate (the criterion
        // benchmark in benches/derive.rs measures it precisely). 100 singlesig
        // derivations run in single-digit milliseconds; 200 ms is a wide guard.
        let parsed = parse_descriptor(fixture!("descriptors/singlesig/wpkh_valid.txt")).unwrap();
        let descriptor = parsed.descriptor();
        // Warm up any one-time setup so the measurement is steady-state.
        let _ = derive_chain(descriptor, Network::Testnet, Chain::Receive, 1).unwrap();

        let start = std::time::Instant::now();
        let out = derive_chain(descriptor, Network::Testnet, Chain::Receive, 100).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(out.len(), 100);
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "deriving 100 singlesig addresses took {elapsed:?} (budget 200ms)"
        );
    }

    // --- US-018: known-address comparison (§17.5). ---

    /// One mainnet multipath descriptor with both a receive and a change branch,
    /// reused across the hit/miss/expansion cases.
    fn bip84_multipath() -> ParsedDescriptor {
        parse_descriptor(&format!("wpkh({BIP84_XPUB}/<0;1>/*)")).unwrap()
    }

    #[test]
    fn known_address_hits_on_receive() {
        // The bc1 fixture is BIP84 receive index 1 of the multipath descriptor.
        let parsed = bip84_multipath();
        let addr = fixture!("addresses/known_match_bc1.txt");
        let m = compare_known_address(&parsed, Network::Bitcoin, addr, 10).unwrap();
        assert!(m.matched);
        assert_eq!(
            m.matched_at,
            Some(MatchLocation {
                index: 1,
                chain: Chain::Receive
            })
        );
        assert_eq!(m.provided, addr);
    }

    #[test]
    fn known_address_hits_on_change() {
        // BIP84 change index 0 (a published vector) matches on the change branch.
        let parsed = bip84_multipath();
        let change0 = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";
        let m = compare_known_address(&parsed, Network::Bitcoin, change0, 10).unwrap();
        assert!(m.matched);
        assert_eq!(
            m.matched_at,
            Some(MatchLocation {
                index: 0,
                chain: Chain::Change
            })
        );
    }

    #[test]
    fn known_address_miss_is_a_fact_and_satisfies_expect_not_to_match() {
        // A valid mainnet P2SH address that cannot appear in this wpkh range → a
        // miss, which is a FACT (matched:false), not an error. readiness-score maps
        // it to C-ADDRESS-MISMATCH; this crate just records it.
        let parsed = bip84_multipath();
        let not_mine = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf";
        let m = compare_known_address(&parsed, Network::Bitcoin, not_mine, 10).unwrap();
        assert!(!m.matched);
        assert_eq!(m.matched_at, None);
        // AC3: ruling out a wrong-wallet import — a miss is the expected outcome.
        assert!(m.meets_expectation(AddressExpectation::ToNotMatch));
        // The same miss against the default "should belong" expectation is unmet
        // (the C-ADDRESS-MISMATCH condition).
        assert!(!m.meets_expectation(AddressExpectation::ToMatch));
    }

    #[test]
    fn meets_expectation_logic() {
        // Pure interpretation of the §17.5 outcomes against both expectations.
        let hit = KnownAddressMatch::hit("bc1qexample".to_string(), 1, Chain::Receive);
        let miss = KnownAddressMatch::miss("bc1qexample".to_string());
        assert!(hit.meets_expectation(AddressExpectation::ToMatch));
        assert!(!hit.meets_expectation(AddressExpectation::ToNotMatch));
        assert!(miss.meets_expectation(AddressExpectation::ToNotMatch));
        assert!(!miss.meets_expectation(AddressExpectation::ToMatch));
    }

    #[test]
    fn search_expands_past_first_n_up_to_1000() {
        // Receive index 50 is beyond the default N=10; the search must still find
        // it via the transparent expansion (§17.5 step 4).
        let parsed = bip84_multipath();
        let derived = derive_addresses(&parsed, Network::Bitcoin, 51).unwrap();
        let at50 = derived.receive_derived[50].address.clone();
        let m = compare_known_address(&parsed, Network::Bitcoin, &at50, 10).unwrap();
        assert!(m.matched);
        assert_eq!(
            m.matched_at,
            Some(MatchLocation {
                index: 50,
                chain: Chain::Receive
            })
        );
    }

    #[test]
    fn known_address_tb1_fixture_matches_testnet_multisig() {
        let parsed =
            parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt")).unwrap();
        let addr = fixture!("addresses/known_match_tb1.txt");
        // Self-check: the committed fixture equals receive index 2 of this descriptor
        // (so a wrong baked value fails here, not silently).
        let derived = derive_addresses(&parsed, Network::Testnet, 3).unwrap();
        assert_eq!(derived.receive_derived[2].address, addr);
        // And the comparison finds it on the testnet multisig.
        let m = compare_known_address(&parsed, Network::Testnet, addr, 10).unwrap();
        assert!(m.matched);
        assert_eq!(
            m.matched_at,
            Some(MatchLocation {
                index: 2,
                chain: Chain::Receive
            })
        );
    }

    #[test]
    fn invalid_address_is_rejected() {
        let parsed = bip84_multipath();
        let err = compare_known_address(&parsed, Network::Bitcoin, "not-a-valid-address", 10)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn wrong_network_address_is_rejected() {
        // A mainnet address compared on testnet must be refused (§17.5 step 1):
        // parses fine, but not valid for the requested network.
        let parsed =
            parse_descriptor(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt")).unwrap();
        let mainnet_addr = fixture!("addresses/known_match_bc1.txt");
        let err = compare_known_address(&parsed, Network::Testnet, mainnet_addr, 10).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn empty_address_is_rejected() {
        let parsed = bip84_multipath();
        let err = compare_known_address(&parsed, Network::Bitcoin, "   ", 10).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InputEmpty);
    }

    #[test]
    fn comparison_count_out_of_range_is_refused() {
        let parsed = bip84_multipath();
        let addr = fixture!("addresses/known_match_bc1.txt");
        assert_eq!(
            compare_known_address(&parsed, Network::Bitcoin, addr, 0)
                .unwrap_err()
                .code(),
            ErrorCode::InputTooLarge
        );
        assert_eq!(
            compare_known_address(&parsed, Network::Bitcoin, addr, MAX_ADDRESS_COUNT + 1)
                .unwrap_err()
                .code(),
            ErrorCode::InputTooLarge
        );
    }

    #[test]
    fn known_address_match_json_shape_matches_schema() {
        // Locks the §19.1 `addresses.known_address_match` shape (both branches).
        let hit = KnownAddressMatch::hit("bc1qexample".to_string(), 3, Chain::Receive);
        assert_eq!(
            serde_json::to_value(hit).unwrap(),
            serde_json::json!({
                "provided": "bc1qexample",
                "matched": true,
                "matched_at": {"index": 3, "chain": "receive"}
            })
        );
        let miss = KnownAddressMatch::miss("bc1qexample".to_string());
        assert_eq!(
            serde_json::to_value(miss).unwrap(),
            serde_json::json!({
                "provided": "bc1qexample",
                "matched": false,
                "matched_at": null
            })
        );
    }

    #[test]
    fn fixed_descriptor_matches_its_single_address() {
        // A no-`*` descriptor describes exactly one address; comparison finds it at
        // index 0 and a different address misses (without a 1000-wide loop).
        let parsed = parse_descriptor(&format!("wpkh({BIP84_XPUB}/0/0)")).unwrap();
        let only = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"; // BIP84 /0/0
        let hit = compare_known_address(&parsed, Network::Bitcoin, only, 10).unwrap();
        assert!(hit.matched);
        assert_eq!(
            hit.matched_at,
            Some(MatchLocation {
                index: 0,
                chain: Chain::Receive
            })
        );
        let miss = compare_known_address(
            &parsed,
            Network::Bitcoin,
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
            10,
        )
        .unwrap();
        assert!(!miss.matched);
    }
}
