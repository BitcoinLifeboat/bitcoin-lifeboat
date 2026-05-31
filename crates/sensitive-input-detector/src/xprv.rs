//! Extended-private-key detection (US-014, PRD §13.5.3).
//!
//! Recognizes pasted extended *private* keys — BIP32 `xprv`/`tprv` and the
//! SLIP-132 script-type variants `yprv`/`zprv`/`uprv`/`vprv` (plus the uppercase
//! multisig forms `Yprv`/`Zprv`/`Uprv`/`Vprv`) — so the caller can refuse them.
//! An extended private key embedded inside a descriptor is caught by the same
//! scan, because the key sits at a word boundary within the descriptor text.
//!
//! # Algorithm (§13.5.3)
//!
//! 1. Match candidates with the anchored prefix + base58-body pattern.
//! 2. Base58Check-verify each candidate and classify it from its 4-byte version.
//!    A valid 78-byte extended key with a known *private* version ⇒ `Block`;
//!    anything else (bad checksum, wrong length, or a *public* version such as an
//!    xpub) ⇒ no action.
//!
//! # Why not `Xpriv::from_str` (the verifier the PRD names)?
//!
//! The §13.5.3 prose says "verify via `bitcoin::bip32::Xpriv::from_str`", but
//! rust-bitcoin only understands the two *standard* version bytes — it rejects
//! every SLIP-132 prefix the same section enumerates with
//! `Error::UnknownVersion` (verified empirically). Relying on it would silently
//! miss a real `zprv`/`yprv`/`uprv`/`vprv` — a security-grade false negative for
//! a secret detector. So all ten prefixes are verified uniformly via
//! [`base58::decode_check`] + a length and version-byte check against the known
//! extended-private versions. This is also strictly *safer*: `decode_check`
//! validates the Base58Check checksum without ever constructing a `SecretKey` or
//! performing an elliptic-curve operation, so the secret is recognized by shape
//! and never "processed" (the US-010 / §13.5 invariant).
//!
//! # Secret hygiene
//!
//! The 78 decoded bytes include the key material, so they are held in
//! [`zeroize::Zeroizing`] and wiped on drop. Findings carry only a [`ByteRange`]
//! and the non-secret [`DetectedSecret::Xprv`] metadata (kind, network).

use std::sync::OnceLock;

use miniscript::bitcoin::base58;
use regex_lite::Regex;
use zeroize::Zeroizing;

use crate::{ByteRange, Collector, DetectedSecret, DetectorAction, Network, XprvKind};

/// §13.5.3 candidate pattern: one of the ten extended-private prefixes followed
/// by the base58 body of a Base58Check-encoded 78-byte key (107–108 trailing
/// base58 characters). Kept verbatim from the PRD for auditability.
const XPRV_PATTERN: &str = r"\b(?:x|y|z|Y|Z|t|u|v|U|V)prv[1-9A-HJ-NP-Za-km-z]{107,108}\b";

/// Serialized length of a BIP32 extended key (4 version + 1 depth + 4 parent
/// fingerprint + 4 child number + 32 chain code + 33 key data), before the
/// Base58Check checksum.
const EXTENDED_KEY_LEN: usize = 78;

/// The compiled extended-private-key regex, built once. The pattern is a fixed
/// literal, so a compile failure would be a programmer bug caught immediately by
/// `pattern_compiles`, never a runtime condition on user data.
fn xprv_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(XPRV_PATTERN).expect("BUG: static xprv pattern must compile"))
}

/// Classify a 4-byte version as a known extended-*private*-key kind + network,
/// or `None` for any other version. Public versions (xpub/ypub/… `0x0488B21E`,
/// etc.) are deliberately absent, so a watch-only extended *public* key is never
/// misread as a secret. Mainnet/testnet is all the version bytes resolve
/// (testnet/signet/regtest share versions — the §17.4 / §16.5 limitation).
fn extended_private_kind(version: u32) -> Option<(XprvKind, Network)> {
    use Network::{Mainnet, Testnet};
    use XprvKind::{Tprv, Uprv, Vprv, Xprv, Yprv, Zprv};
    Some(match version {
        0x0488_ADE4 => (Xprv, Mainnet), // xprv — BIP32
        0x0435_8394 => (Tprv, Testnet), // tprv — BIP32 testnet
        0x049D_7878 => (Yprv, Mainnet), // yprv — SLIP-132 P2SH-P2WPKH
        0x0295_B005 => (Yprv, Mainnet), // Yprv — SLIP-132 P2SH-P2WSH multisig
        0x04B2_430C => (Zprv, Mainnet), // zprv — SLIP-132 P2WPKH
        0x02AA_7A99 => (Zprv, Mainnet), // Zprv — SLIP-132 P2WSH multisig
        0x044A_4E28 => (Uprv, Testnet), // uprv — SLIP-132 testnet P2SH-P2WPKH
        0x0242_85B5 => (Uprv, Testnet), // Uprv — SLIP-132 testnet P2SH-P2WSH multisig
        0x045F_18BC => (Vprv, Testnet), // vprv — SLIP-132 testnet P2WPKH
        0x0257_5048 => (Vprv, Testnet), // Vprv — SLIP-132 testnet P2WSH multisig
        _ => return None,
    })
}

/// Base58Check-verify a candidate and classify it, or `None` if it is not a
/// valid 78-byte extended key with a known private version.
fn verify(candidate: &str) -> Option<(XprvKind, Network)> {
    // `decode_check` validates the checksum without building a `SecretKey` or
    // doing EC math; the decoded bytes (which contain the key material) are
    // zeroized on drop.
    let bytes = Zeroizing::new(base58::decode_check(candidate).ok()?);
    if bytes.len() != EXTENDED_KEY_LEN {
        return None;
    }
    let version = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    extended_private_kind(version)
}

/// Scan `input` for extended private keys and push any findings into `out`.
pub(crate) fn scan(input: &str, out: &mut Collector) {
    for m in xprv_regex().find_iter(input) {
        if let Some((kind, network)) = verify(m.as_str()) {
            out.push(
                DetectedSecret::Xprv { kind, network },
                ByteRange::new(m.start(), m.end()),
                DetectorAction::Block,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use miniscript::bitcoin::bip32::Xpriv;
    use miniscript::bitcoin::NetworkKind;

    /// Mint a standard extended private key from a fixed, obviously-synthetic
    /// seed (`0x11` repeated) — never a real seed (§27).
    fn xprv(network: NetworkKind) -> String {
        Xpriv::new_master(network, &[0x11u8; 32])
            .expect("valid master")
            .to_string()
    }

    /// Re-encode an extended key with different version bytes (used to mint
    /// SLIP-132 fixtures at runtime without a second seed). `decode_check` +
    /// `encode_check` round-trips the 78-byte body and recomputes the checksum.
    fn reversion(extended_key: &str, version: [u8; 4]) -> String {
        let mut bytes = base58::decode_check(extended_key).expect("valid base58check");
        bytes[0..4].copy_from_slice(&version);
        base58::encode_check(&bytes)
    }

    fn single_xprv(report: &crate::DetectorReport) -> (XprvKind, Network, ByteRange) {
        assert_eq!(report.findings.len(), 1, "expected exactly one finding");
        match report.findings[0] {
            (DetectedSecret::Xprv { kind, network }, range) => (kind, network, range),
            ref other => panic!("expected an Xprv finding, got {other:?}"),
        }
    }

    #[test]
    fn pattern_compiles() {
        let _ = xprv_regex();
    }

    #[test]
    fn blocks_standard_xprv_and_tprv() {
        for (network, expected_kind, expected_net) in [
            (NetworkKind::Main, XprvKind::Xprv, Network::Mainnet),
            (NetworkKind::Test, XprvKind::Tprv, Network::Testnet),
        ] {
            let s = xprv(network);
            let report = crate::detect(&s);
            assert!(report.is_blocked(), "{network:?} xprv must Block");
            let (kind, net, range) = single_xprv(&report);
            assert_eq!(kind, expected_kind);
            assert_eq!(net, expected_net);
            assert_eq!(range.start, 0);
            assert_eq!(range.end, s.len());
        }
    }

    #[test]
    fn blocks_slip132_variants_xpriv_from_str_would_reject() {
        // SLIP-132 keys that `Xpriv::from_str` rejects with UnknownVersion must
        // still Block via the version-table path. Mint each by re-versioning the
        // synthetic mainnet/testnet xprv body.
        let main_body = xprv(NetworkKind::Main);
        let test_body = xprv(NetworkKind::Test);
        for (body, version, expected_kind, expected_net) in [
            (
                &main_body,
                [0x04, 0x9d, 0x78, 0x78],
                XprvKind::Yprv,
                Network::Mainnet,
            ), // yprv
            (
                &main_body,
                [0x04, 0xb2, 0x43, 0x0c],
                XprvKind::Zprv,
                Network::Mainnet,
            ), // zprv
            (
                &main_body,
                [0x02, 0x95, 0xb0, 0x05],
                XprvKind::Yprv,
                Network::Mainnet,
            ), // Yprv
            (
                &main_body,
                [0x02, 0xaa, 0x7a, 0x99],
                XprvKind::Zprv,
                Network::Mainnet,
            ), // Zprv
            (
                &test_body,
                [0x04, 0x4a, 0x4e, 0x28],
                XprvKind::Uprv,
                Network::Testnet,
            ), // uprv
            (
                &test_body,
                [0x04, 0x5f, 0x18, 0xbc],
                XprvKind::Vprv,
                Network::Testnet,
            ), // vprv
            (
                &test_body,
                [0x02, 0x42, 0x85, 0xb5],
                XprvKind::Uprv,
                Network::Testnet,
            ), // Uprv
            (
                &test_body,
                [0x02, 0x57, 0x50, 0x48],
                XprvKind::Vprv,
                Network::Testnet,
            ), // Vprv
        ] {
            let s = reversion(body, version);
            // Self-check: rust-bitcoin really does reject these (so the
            // version-table path, not `Xpriv::from_str`, is what catches them).
            assert!(
                Xpriv::from_str(&s).is_err(),
                "expected {expected_kind:?} to be rejected by Xpriv::from_str"
            );
            let report = crate::detect(&s);
            assert!(report.is_blocked(), "{expected_kind:?} must Block");
            let (kind, net, _) = single_xprv(&report);
            assert_eq!(kind, expected_kind);
            assert_eq!(net, expected_net);
        }
    }

    #[test]
    fn detects_xprv_embedded_in_descriptor() {
        // Criterion 3: an xprv inside a descriptor is caught by the same scan —
        // the key sits at a word boundary (`]` before, `/` after), so no
        // descriptor parsing (which would *process* the secret) is needed.
        let key = xprv(NetworkKind::Main);
        let descriptor = format!("wpkh([11223344/84h/0h/0h]{key}/0/*)");
        let report = crate::detect(&descriptor);
        assert!(
            report.is_blocked(),
            "an xprv inside a descriptor must Block"
        );
        let (kind, _, range) = single_xprv(&report);
        assert_eq!(kind, XprvKind::Xprv);
        assert_eq!(&descriptor[range.as_range()], key);
    }

    #[test]
    fn no_action_on_invalid_lookalikes() {
        // A corrupted xprv (broken checksum) ⇒ no action.
        let valid = xprv(NetworkKind::Main);
        let mut chars: Vec<char> = valid.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(
            crate::detect(&corrupted).is_allowed(),
            "a bad-checksum xprv look-alike must not be flagged"
        );

        // An extended *public* key (xpub) must never be read as a secret. It
        // does not even match the `...prv` pattern, but assert the outcome.
        let xpub = reversion(&valid, [0x04, 0x88, 0xb2, 0x1e]); // xpub version
        assert!(
            crate::detect(&xpub).is_allowed(),
            "an xpub must not be flagged as a private key"
        );
    }

    #[test]
    fn report_omits_xprv_json_and_debug() {
        let s = xprv(NetworkKind::Main);
        let report = crate::detect(&s);
        assert!(report.is_blocked());
        let json = serde_json::to_string(&report).expect("serializes");
        let debug = format!("{report:?}");
        assert!(!json.contains(&s), "JSON leaked the xprv");
        assert!(!debug.contains(&s), "Debug leaked the xprv");
    }

    #[test]
    fn detects_committed_xprv_mainnet_fixture() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/xprv_mainnet.txt"
        ))
        .trim();
        let report = crate::detect(fixture);
        assert!(report.is_blocked(), "the xprv_mainnet fixture must Block");
        let (kind, net, _) = single_xprv(&report);
        assert_eq!(kind, XprvKind::Xprv);
        assert_eq!(net, Network::Mainnet);
    }
}
