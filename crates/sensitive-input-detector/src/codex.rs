//! codex32 / BIP-93 secret detection (US-015, PRD §13.5.6).
//!
//! Recognizes pasted codex32 (BIP-93) strings — checksummed, optionally
//! secret-shared BIP32 master seeds — so the caller can refuse them.
//!
//! The module is named `codex` (not `codex32`) so the `codex32` *crate* keeps
//! resolving inside it — the same reason the BIP39 module is `mnemonic`, not
//! `bip39`.
//!
//! # Algorithm (§13.5.6)
//!
//! 1. Find candidates with an anchored `ms1`/`MS1` + threshold-digit + bech32
//!    body pattern.
//! 2. Validate each candidate with [`codex32::Codex32String::from_string`],
//!    which checks the length, the bech32 checksum, **and** case consistency
//!    (codex32 forbids mixed case). A valid string ⇒ `Block`.
//!
//! The reported `threshold` is the `k` value, read directly from the candidate's
//! shape (the digit right after the 3-byte `ms1`/`MS1` prefix). We never call the
//! crate's `interpolate_at` / `from_seed` / `Parts::data()` — those reconstruct
//! or extract the secret, which a detector must never do.
//!
//! # Two deviations from the PRD §13.5.6 regex (both fix false negatives)
//!
//! The PRD names the pattern
//! `\b(?:ms|MS)1[0-9][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{45,125}\b`. Verified
//! empirically, it matches **none** of the three official codex32 vectors — it
//! would `Block` zero real codex32 strings:
//!
//! * **Lower bound 45 → 44.** The shortest valid codex32 (a 48-char, 128-bit
//!   secret such as the canonical `ms10tests…czlw`) has only 44 body characters
//!   after `ms1` + the threshold digit, so `{45,…}` excludes it.
//! * **Uppercase mirror.** codex32 is commonly engraved/printed uppercase, and
//!   `from_string` accepts it, but the PRD body charset is lowercase-only, so an
//!   all-uppercase share would be missed. We add an uppercase alternative.
//!
//! Each alternative is single-case, so a *mixed*-case string matches neither —
//! "no mixed case" is enforced structurally, and `from_string` re-checks it
//! anyway. A too-narrow detector that misses a real secret is a security bug
//! (the US-014 lesson); the lower alternative is otherwise the PRD pattern
//! verbatim.
//!
//! # Secret hygiene
//!
//! `Codex32String::from_string` requires an owned `String`, so each candidate is
//! copied once for validation; that transient copy (and any error holding it) is
//! dropped at the end of its loop iteration, exactly like the transient
//! `PrivateKey` the WIF detector builds (US-014). The crate performs no
//! elliptic-curve work — it only checks a bech32 checksum. The finding carries
//! only the non-secret threshold and a [`ByteRange`] into the original input,
//! whose authoritative copy is zeroized by the caller's `SecretString`.

use std::sync::OnceLock;

use codex32::Codex32String;
use regex_lite::Regex;

use crate::{ByteRange, Collector, DetectedSecret, DetectorAction};

/// codex32 candidate pattern. The lowercase alternative is the PRD §13.5.6
/// pattern with the body lower bound widened 45 → 44 (see the module docs); the
/// uppercase alternative mirrors it for uppercase codex32. Single-case
/// alternatives never match a mixed-case string.
const CODEX32_PATTERN: &str = concat!(
    r"\b(?:",
    r"ms1[0-9][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{44,125}",
    r"|MS1[0-9][QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{44,125}",
    r")\b",
);

/// The compiled codex32 regex, built once. The pattern is a fixed literal, so a
/// compile failure would be a programmer bug caught immediately by
/// `pattern_compiles`, never a runtime condition on user data.
fn codex32_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(CODEX32_PATTERN).expect("BUG: static codex32 pattern must compile")
    })
}

/// The `k` threshold of a candidate: the digit at byte 3, immediately after the
/// 3-byte `ms1`/`MS1` prefix (the regex guarantees a `[0-9]` there). Non-secret
/// structural metadata (0, or 2–9 for valid codex32).
fn threshold_of(candidate: &str) -> u8 {
    candidate.as_bytes()[3] - b'0'
}

/// Scan `input` for codex32 / BIP-93 secrets and push any findings into `out`.
pub(crate) fn scan(input: &str, out: &mut Collector) {
    for m in codex32_regex().find_iter(input) {
        let candidate = m.as_str();
        // Authoritative validation: length + bech32 checksum + case consistency,
        // all enforced by the codex32 crate. The owned copy is dropped (with any
        // error that holds it) at the end of this iteration.
        if Codex32String::from_string(candidate.to_string()).is_ok() {
            out.push(
                DetectedSecret::Codex32 {
                    threshold: threshold_of(candidate),
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

    // Official codex32 / BIP-93 test vectors (from the codex32 crate's own test
    // suite and the BIP-93 examples). Documented vectors, never real seeds (§27).
    const VECTOR_128BIT: &str = "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw"; // k=0, lowercase
    const VECTOR_UPPER_K2: &str = "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM"; // k=2, uppercase
    const VECTOR_K3: &str = "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln"; // k=3, lowercase

    fn single_codex32(report: &crate::DetectorReport) -> (u8, ByteRange) {
        let found: Vec<(u8, ByteRange)> = report
            .findings
            .iter()
            .filter_map(|f| match f {
                (DetectedSecret::Codex32 { threshold }, range) => Some((*threshold, *range)),
                _ => None,
            })
            .collect();
        assert_eq!(found.len(), 1, "expected exactly one codex32 finding");
        found[0]
    }

    #[test]
    fn pattern_compiles() {
        let _ = codex32_regex();
    }

    #[test]
    fn blocks_official_vectors_with_correct_threshold() {
        for (vector, expected_threshold) in
            [(VECTOR_128BIT, 0u8), (VECTOR_UPPER_K2, 2), (VECTOR_K3, 3)]
        {
            let report = crate::detect(vector);
            assert!(report.is_blocked(), "codex32 {vector:?} must Block");
            let (threshold, range) = single_codex32(&report);
            assert_eq!(
                threshold, expected_threshold,
                "wrong threshold for {vector:?}"
            );
            assert_eq!(&vector[range.as_range()], vector);
        }
    }

    #[test]
    fn detects_codex32_embedded_in_text() {
        let input = format!("my backup is {VECTOR_128BIT} please ignore");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let (threshold, range) = single_codex32(&report);
        assert_eq!(threshold, 0);
        assert_eq!(&input[range.as_range()], VECTOR_128BIT);
    }

    #[test]
    fn no_action_on_bad_checksum() {
        // Flip the last checksum character to another bech32 char: the shape
        // still matches the pattern, but `from_string` rejects the checksum.
        let mut chars: Vec<char> = VECTOR_128BIT.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'w' { 'q' } else { 'w' };
        let corrupted: String = chars.into_iter().collect();
        assert!(
            crate::detect(&corrupted).is_allowed(),
            "a bad-checksum codex32 look-alike must not be flagged"
        );
    }

    #[test]
    fn no_action_on_mixed_case() {
        // Uppercase the final character of the otherwise-lowercase vector. The
        // single-case pattern alternatives do not match a mixed-case string, and
        // `from_string` would reject it too (codex32 forbids mixed case).
        let mut s = VECTOR_128BIT.to_string();
        s.replace_range(
            s.len() - 1..,
            &VECTOR_128BIT[VECTOR_128BIT.len() - 1..].to_uppercase(),
        );
        assert_ne!(s, VECTOR_128BIT, "the case change must be a real change");
        assert!(
            crate::detect(&s).is_allowed(),
            "a mixed-case codex32 string must not be flagged"
        );
    }

    #[test]
    fn no_action_on_too_short() {
        // `ms1` + threshold + a short body: below codex32's minimum length, and
        // below the pattern's {44,..} body floor, so it is not even a candidate.
        assert!(crate::detect("ms10tests").is_allowed());
        assert!(crate::detect("ms10testsxxxxxxxxxx").is_allowed());
    }

    #[test]
    fn no_action_on_non_codex32_bech32() {
        // A bech32 address (HRP `bc`, not `ms`) is not a codex32 candidate.
        assert!(crate::detect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_allowed());
        // An `ms1` string of the right shape but a random (invalid) body fails
        // `from_string` ⇒ no action.
        let junk = format!("ms10{}", "q".repeat(44));
        assert!(crate::detect(&junk).is_allowed());
    }

    #[test]
    fn report_omits_codex32_json_and_debug() {
        // No-leak over a real detection: the report must not echo the secret.
        let report = crate::detect(VECTOR_128BIT);
        assert!(report.is_blocked());
        let json = serde_json::to_string(&report).expect("serializes");
        let debug = format!("{report:?}");
        assert!(
            !json.contains(VECTOR_128BIT),
            "JSON leaked the codex32 secret"
        );
        assert!(
            !debug.contains(VECTOR_128BIT),
            "Debug leaked the codex32 secret"
        );
    }

    #[test]
    fn detects_committed_codex32_fixture() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/codex32_128bit.txt"
        ))
        .trim();
        let report = crate::detect(fixture);
        assert!(report.is_blocked(), "the codex32_128bit fixture must Block");
        let (threshold, _) = single_codex32(&report);
        assert_eq!(threshold, 0);
    }
}
