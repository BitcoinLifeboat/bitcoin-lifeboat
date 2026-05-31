//! WIF (Wallet Import Format) private-key detection (US-014, PRD §13.5.2).
//!
//! Recognizes pasted WIF private keys so the caller can refuse them — Lifeboat
//! is watch-only and never needs a spending key.
//!
//! # Algorithm (§13.5.2)
//!
//! 1. Match candidates with the anchored WIF patterns: a base58 run of the exact
//!    WIF length whose first character fixes the network/compression class
//!    (`5`/`9` ⇒ uncompressed 51 chars, `K`/`L`/`c` ⇒ compressed 52 chars).
//! 2. Base58Check-verify each candidate via [`PrivateKey::from_wif`]. A valid WIF
//!    ⇒ `Block`; an invalid look-alike (bad checksum, wrong payload) ⇒ no action.
//!
//! The network and compression flag reported come from the decoded key, not from
//! which pattern matched, so they are always authoritative.
//!
//! # Secret hygiene
//!
//! The detector borrows the input and stores only a [`ByteRange`] and the
//! non-secret [`DetectedSecret::Wif`] metadata (network, compression). It copies
//! no key material into any returned value. The transient [`PrivateKey`] produced
//! by verification is read for its public metadata and dropped immediately.

use std::sync::OnceLock;

use miniscript::bitcoin::{NetworkKind, PrivateKey};
use regex_lite::Regex;

use crate::{ByteRange, Collector, DetectedSecret, DetectorAction, Network};

/// Anchored WIF candidate patterns (§13.5.2), combined into one regex. Each
/// alternative pins a first character and exact base58 length; the body charset
/// is the Bitcoin base58 alphabet (no `0`/`O`/`I`/`l`). `PrivateKey::from_wif`
/// then verifies the checksum and reads the real network/compression, so the
/// branch that matched is irrelevant past candidate-finding.
const WIF_PATTERN: &str = concat!(
    r"\b(?:",
    r"5[1-9A-HJ-NP-Za-km-z]{50}", // mainnet, uncompressed (total 51 chars)
    r"|[KL][1-9A-HJ-NP-Za-km-z]{51}", // mainnet, compressed   (total 52 chars)
    r"|9[1-9A-HJ-NP-Za-km-z]{50}", // testnet, uncompressed (total 51 chars)
    r"|c[1-9A-HJ-NP-Za-km-z]{51}", // testnet, compressed   (total 52 chars)
    r")\b",
);

/// The compiled WIF regex, built once. The pattern is a fixed literal, so a
/// compile failure would be a programmer bug caught by `pattern_compiles` (and
/// any test that screens input), never a runtime condition on user data.
fn wif_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(WIF_PATTERN).expect("BUG: static WIF pattern must compile"))
}

/// Map rust-bitcoin's two-way [`NetworkKind`] to the crate-owned [`Network`].
/// Testnet/signet/regtest share version bytes and all surface as
/// [`Network::Testnet`] (the §17.4 / §16.5 limitation).
fn map_network(kind: NetworkKind) -> Network {
    match kind {
        NetworkKind::Main => Network::Mainnet,
        NetworkKind::Test => Network::Testnet,
    }
}

/// Scan `input` for WIF private keys and push any findings into `out`.
pub(crate) fn scan(input: &str, out: &mut Collector) {
    for m in wif_regex().find_iter(input) {
        // Base58Check verification is the real gate: a shape match that fails
        // `from_wif` (wrong checksum / payload) is a look-alike and yields no
        // action (§13.5.2). `from_wif` decodes but performs no derivation.
        if let Ok(key) = PrivateKey::from_wif(m.as_str()) {
            out.push(
                DetectedSecret::Wif {
                    network: map_network(key.network),
                    compressed: key.compressed,
                },
                ByteRange::new(m.start(), m.end()),
                DetectorAction::Block,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::secp256k1::SecretKey;

    /// Mint a WIF for the given class from a fixed, obviously-synthetic scalar
    /// (`0x11` repeated) — never a real key (§27). `to_wif()` is the inverse of
    /// the `from_wif` the detector uses, so the round-trip is exact.
    fn wif(network: NetworkKind, compressed: bool) -> String {
        let inner = SecretKey::from_slice(&[0x11u8; 32]).expect("0x11.. is a valid scalar");
        PrivateKey {
            compressed,
            network,
            inner,
        }
        .to_wif()
    }

    fn single_wif(report: &crate::DetectorReport) -> (Network, bool, ByteRange) {
        assert_eq!(report.findings.len(), 1, "expected exactly one finding");
        match report.findings[0] {
            (
                DetectedSecret::Wif {
                    network,
                    compressed,
                },
                range,
            ) => (network, compressed, range),
            ref other => panic!("expected a Wif finding, got {other:?}"),
        }
    }

    #[test]
    fn pattern_compiles() {
        // The static pattern must compile; this makes the `.expect` in
        // `wif_regex` a guaranteed-unreachable branch under CI.
        let _ = wif_regex();
    }

    #[test]
    fn blocks_valid_wif_all_four_variants() {
        for (network, compressed, expected) in [
            (NetworkKind::Main, false, Network::Mainnet),
            (NetworkKind::Main, true, Network::Mainnet),
            (NetworkKind::Test, false, Network::Testnet),
            (NetworkKind::Test, true, Network::Testnet),
        ] {
            let s = wif(network, compressed);
            let report = crate::detect(&s);
            assert!(
                report.is_blocked(),
                "{network:?} compressed={compressed} must Block"
            );
            let (net, comp, range) = single_wif(&report);
            assert_eq!(net, expected, "wrong network for {network:?}");
            assert_eq!(comp, compressed, "wrong compression for {network:?}");
            assert_eq!(range.start, 0);
            assert_eq!(range.end, s.len());
        }
    }

    #[test]
    fn no_action_on_invalid_lookalikes() {
        // A valid WIF with one character corrupted breaks the Base58Check ⇒ no
        // action. We flip a body character to another base58 char so the SHAPE
        // still matches the regex but the checksum fails.
        let valid = wif(NetworkKind::Main, true);
        let mut chars: Vec<char> = valid.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(
            crate::detect(&corrupted).is_allowed(),
            "a bad-checksum WIF look-alike must not be flagged"
        );

        // A base58 address (starts with `1`) is not WIF-shaped at all.
        assert!(crate::detect("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_allowed());

        // A 51-char base58 run shaped like a mainnet-uncompressed WIF but with a
        // junk payload fails Base58Check ⇒ no action.
        let shaped_but_invalid = format!("5{}", "z".repeat(50));
        assert!(crate::detect(&shaped_but_invalid).is_allowed());
    }

    #[test]
    fn detects_wif_embedded_in_text() {
        let s = wif(NetworkKind::Main, true);
        let input = format!("my key is {s} please delete this message");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let (net, _, range) = single_wif(&report);
        assert_eq!(net, Network::Mainnet);
        assert_eq!(&input[range.as_range()], s);
    }

    #[test]
    fn report_omits_wif_json_and_debug() {
        // No-leak over a real detection: the report must not echo the WIF.
        let s = wif(NetworkKind::Main, true);
        let report = crate::detect(&s);
        assert!(report.is_blocked());
        let json = serde_json::to_string(&report).expect("serializes");
        let debug = format!("{report:?}");
        assert!(!json.contains(&s), "JSON leaked the WIF");
        assert!(!debug.contains(&s), "Debug leaked the WIF");
    }

    #[test]
    fn detects_committed_wif_mainnet_fixture() {
        // The synthetic mainnet WIF committed under `fixtures/secrets/`. Reading
        // it here proves the committed file is a genuine Base58Check-valid WIF
        // the detector blocks. Repo-root fixtures are reached via the manifest
        // dir (this crate is two levels down).
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/wif_mainnet.txt"
        ))
        .trim();
        let report = crate::detect(fixture);
        assert!(report.is_blocked(), "the wif_mainnet fixture must Block");
        let (net, _, _) = single_wif(&report);
        assert_eq!(net, Network::Mainnet);
    }
}
