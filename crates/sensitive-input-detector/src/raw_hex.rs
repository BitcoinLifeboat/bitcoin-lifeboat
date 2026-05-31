//! Raw-hex private-key detection (US-015, PRD §13.5.4).
//!
//! A 32-byte private key is often written as 64 hex characters. That shape is
//! shared by many *non*-secret values (SHA256 hashes, txids, block hashes,
//! merkle roots), so a bare 64-hex run is far too common to block on sight.
//! §13.5.4 therefore gates the match on its surrounding context:
//!
//! * preceded within 32 characters by `priv`, `key`, `secret`, or `wif`
//!   (case-insensitive) ⇒ `Block` — the context strongly implies a private key;
//! * otherwise, alone on its own line whose length is ≤ 80 ⇒ `Warn` — a
//!   plausible key paste, but unconfirmed;
//! * otherwise ⇒ no action (a 64-hex run inside other text is treated as a
//!   hash/txid, not a secret).
//!
//! `Block` takes precedence over `Warn` when both could apply (e.g. a labelled
//! key on its own line): the keyword context is the stronger signal.
//!
//! # Secret hygiene
//!
//! Unlike the WIF/xprv detectors, this one never decodes or copies the matched
//! value: it only computes a [`ByteRange`] and inspects the *surrounding*
//! (non-secret) bytes for context keywords and line geometry. No secret-derived
//! buffer is created, so there is nothing to zeroize. The finding carries only
//! the [`DetectedSecret::RawHexPrivKey`] discriminant and the range.

use std::sync::OnceLock;

use regex_lite::Regex;

use crate::{ByteRange, Collector, DetectedSecret, DetectorAction};

/// §13.5.4 candidate pattern: exactly 64 hex characters at word boundaries. The
/// `\b` anchors mean a longer hex run (e.g. a 128-hex value) does not match,
/// since there is no word boundary mid-run. Kept verbatim from the PRD.
const RAW_HEX_PATTERN: &str = r"\b[0-9a-fA-F]{64}\b";

/// How far back to look for a context keyword before the match (§13.5.4).
const CONTEXT_WINDOW: usize = 32;

/// Maximum length of a line for the "alone on its own line" `Warn` heuristic.
const MAX_OWN_LINE_LEN: usize = 80;

/// Case-insensitive context keywords that escalate a bare 64-hex run to `Block`.
const CONTEXT_KEYWORDS: [&str; 4] = ["priv", "key", "secret", "wif"];

/// The compiled raw-hex regex, built once. The pattern is a fixed literal, so a
/// compile failure would be a programmer bug caught immediately by
/// `pattern_compiles`, never a runtime condition on user data.
fn raw_hex_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(RAW_HEX_PATTERN).expect("BUG: static raw-hex pattern must compile")
    })
}

/// `true` if any context keyword appears in the up-to-[`CONTEXT_WINDOW`] bytes
/// immediately before `start` (case-insensitive). The preceding slice is plain
/// surrounding text (labels like "private key:"), never the secret itself.
fn has_context_keyword(input: &str, start: usize) -> bool {
    // Walk back to a char boundary so slicing a multibyte input never panics.
    let mut from = start.saturating_sub(CONTEXT_WINDOW);
    while from < start && !input.is_char_boundary(from) {
        from += 1;
    }
    let preceding = input[from..start].to_lowercase();
    CONTEXT_KEYWORDS.iter().any(|kw| preceding.contains(kw))
}

/// `true` if the 64-hex match at `[start, end)` is alone on its own line (only
/// surrounding whitespace) and that line is at most [`MAX_OWN_LINE_LEN`] bytes.
fn is_alone_on_short_line(input: &str, start: usize, end: usize, matched: &str) -> bool {
    let line_start = input[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = input[end..].find('\n').map_or(input.len(), |i| end + i);
    let line = &input[line_start..line_end];
    line.trim() == matched && line.len() <= MAX_OWN_LINE_LEN
}

/// Scan `input` for context-gated raw-hex private keys and push any findings.
pub(crate) fn scan(input: &str, out: &mut Collector) {
    for m in raw_hex_regex().find_iter(input) {
        // `Block` (keyword context) is the stronger signal and wins over the
        // own-line `Warn`; a run with neither signal is ignored (§13.5.4).
        let action = if has_context_keyword(input, m.start()) {
            DetectorAction::Block
        } else if is_alone_on_short_line(input, m.start(), m.end(), m.as_str()) {
            DetectorAction::Warn
        } else {
            continue;
        };
        out.push(
            DetectedSecret::RawHexPrivKey,
            ByteRange::new(m.start(), m.end()),
            action,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid 64-hex string (not a real key — a fixed repeating
    /// nibble pattern). The detector never decodes it, so its value is moot; what
    /// matters in these tests is its surrounding context.
    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn single(report: &crate::DetectorReport) -> (DetectorAction, ByteRange) {
        assert_eq!(report.findings.len(), 1, "expected exactly one finding");
        match report.findings[0] {
            (DetectedSecret::RawHexPrivKey, range) => (report.action, range),
            ref other => panic!("expected a RawHexPrivKey finding, got {other:?}"),
        }
    }

    #[test]
    fn pattern_compiles() {
        let _ = raw_hex_regex();
    }

    #[test]
    fn blocks_when_preceded_by_context_keyword() {
        // Each keyword, case-insensitively, within 32 chars before the hex.
        for prefix in [
            "private key: ",
            "KEY=",
            "my secret is ",
            "WIF ",
            "the PRIVate material ",
        ] {
            let input = format!("{prefix}{HEX64}");
            let report = crate::detect(&input);
            assert!(
                report.is_blocked(),
                "context {prefix:?} should escalate to Block"
            );
            let (action, range) = single(&report);
            assert_eq!(action, DetectorAction::Block);
            assert_eq!(&input[range.as_range()], HEX64);
        }
    }

    #[test]
    fn keyword_outside_window_does_not_block() {
        // A keyword further than 32 chars before the hex must not Block. Here
        // "key" is followed by 40 spaces (>32), and the hex is embedded mid-line
        // (not alone) so the Warn path also does not apply ⇒ no action.
        let input = format!("key{}{HEX64} trailing", " ".repeat(40));
        assert!(
            crate::detect(&input).is_allowed(),
            "a keyword beyond the 32-char window must not Block"
        );
    }

    #[test]
    fn warns_when_alone_on_short_line() {
        // The hex on its own line, no context keyword ⇒ Warn (§13.5.4).
        for input in [
            HEX64.to_string(),
            format!("first line\n{HEX64}\nthird line"),
            format!("  {HEX64}  \nnext"), // surrounded only by whitespace
        ] {
            let report = crate::detect(&input);
            assert!(report.is_warning(), "own-line hex should Warn: {input:?}");
            let (action, _) = single(&report);
            assert_eq!(action, DetectorAction::Warn);
        }
    }

    #[test]
    fn no_action_for_hash_embedded_in_text() {
        // A 64-hex value mid-sentence with no key context is treated as a hash /
        // txid, not a secret (§13.5.4's false-positive mitigation).
        let input = format!("the transaction {HEX64} was confirmed in block 800000");
        assert!(
            crate::detect(&input).is_allowed(),
            "an embedded hash with no key context must not be flagged"
        );
    }

    #[test]
    fn block_beats_warn_for_labelled_own_line() {
        // Both signals apply (keyword context AND alone-ish): Block must win.
        let input = format!("private key\n{HEX64}");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let (action, _) = single(&report);
        assert_eq!(action, DetectorAction::Block);
    }

    #[test]
    fn not_sixty_four_hex_is_ignored() {
        // 63 and 65 hex chars, and a 64-run containing a non-hex char, never match.
        let sixty_three = &HEX64[..63];
        let sixty_five = format!("{HEX64}a");
        let with_g = format!("g{}", &HEX64[1..]);
        for s in [sixty_three, &sixty_five, &with_g] {
            assert!(
                crate::detect(s).is_allowed(),
                "non-64-hex {s:?} must not be flagged"
            );
        }
    }

    #[test]
    fn long_hex_run_does_not_match_a_64_window() {
        // A 128-hex run has no word boundary at offset 64, so `\b...{64}\b`
        // does not match a sub-window of it.
        let input = format!("{HEX64}{HEX64}");
        assert!(
            crate::detect(&input).is_allowed(),
            "a 128-hex run must not match the 64-hex pattern"
        );
    }

    #[test]
    fn report_omits_hex_json_and_debug() {
        // No-leak over a real (Block) detection: the report must not echo the hex.
        let input = format!("private key {HEX64}");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let json = serde_json::to_string(&report).expect("serializes");
        let debug = format!("{report:?}");
        assert!(!json.contains(HEX64), "JSON leaked the hex");
        assert!(!debug.contains(HEX64), "Debug leaked the hex");
    }
}
