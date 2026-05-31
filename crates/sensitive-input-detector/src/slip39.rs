//! SLIP-39 (Shamir backup share) detection (US-015, PRD §13.5.5).
//!
//! Recognizes pasted SLIP-0039 mnemonic shares so the caller can refuse them —
//! Lifeboat is watch-only and never needs Shamir shares.
//!
//! # Algorithm (§13.5.5)
//!
//! 1. Tokenize the input on whitespace and commas (the same separators the BIP39
//!    detector uses), recording each token's byte range.
//! 2. Slide a window of 33 or 20 tokens (the two SLIP-39 share lengths, for
//!    256- and 128-bit secrets), largest first.
//! 3. A window is a share when **every** token is in the 1024-word SLIP-0039
//!    wordlist **and** the share's RS1024 checksum validates. Such a window ⇒
//!    `Block`.
//!
//! `share_count_in_input` reports how many distinct shares were found across the
//! whole input (a SLIP-39 backup is several shares), and is the same on every
//! finding.
//!
//! # Why a direct RS1024 check, not the `slip-0039` crate the PRD names
//!
//! Two reasons, both decisive:
//!
//! * **License.** The `slip-0039` crate on crates.io (`slip39`) is
//!   `GPL-3.0-or-later`, which the workspace `deny.toml` bans (GPL/AGPL are
//!   denied). Its underlying library `sssmc39` is Apache-2.0 but pulls a heavy,
//!   dated tree (`rand 0.6`, `tiny-bip39`, `failure`).
//! * **Security.** Those crates *reconstruct* the secret from shares — exactly
//!   what a detector must never do. Validating a single share's RS1024 checksum
//!   is a pure checksum over its 10-bit words (it reveals nothing and combines
//!   nothing), the same "recognize by shape, never process" stance as the
//!   xprv detector's `base58::decode_check` (US-014). So we implement RS1024
//!   directly (~20 lines, fully specified by SLIP-0039) and validate shares
//!   without ever attempting recovery.
//!
//! The vendored wordlist's byte-correct *order* is what makes the 10-bit indices
//! meaningful; it is pinned by SHA256 in `build.rs` and independently confirmed
//! by the official-vector tests below (a single misplaced word would change the
//! indices and break RS1024).
//!
//! # Secret hygiene
//!
//! Each token's lowercased text and every vector of 10-bit indices derived from
//! the input are held in [`zeroize::Zeroizing`] and wiped on drop. Findings carry
//! only the share count and a [`ByteRange`] into the original input.

use std::collections::HashMap;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::{ByteRange, Collector, DetectedSecret, DetectorAction};

/// SLIP-39 share lengths in words, scanned largest-first: 33 words encode a
/// 256-bit secret, 20 words a 128-bit secret (§13.5.5).
const WINDOW_SIZES: [usize; 2] = [33, 20];

/// Shortest share; inputs with fewer tokens can never contain one.
const MIN_WORDS: usize = 20;

/// The SLIP-0039 checksum customization string, prepended to a share's symbols
/// before the RS1024 polymod (SLIP-0039 §"Checksum").
const CUSTOMIZATION_STRING: [u16; 6] = [
    b's' as u16,
    b'h' as u16,
    b'a' as u16,
    b'm' as u16,
    b'i' as u16,
    b'r' as u16,
];

/// The vendored, integrity-pinned SLIP-0039 wordlist (`build.rs`). 1024 words,
/// one per line; the line index is the word's 10-bit value.
const RAW_WORDLIST: &str = include_str!("../wordlists/slip0039/wordlist.txt");

/// Word → 10-bit index map, built once from the vendored wordlist.
fn wordlist_index() -> &'static HashMap<&'static str, u16> {
    static MAP: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    MAP.get_or_init(|| {
        RAW_WORDLIST
            .lines()
            .filter(|line| !line.is_empty())
            .enumerate()
            // index 0..=1023 always fits u16 (the list is exactly 1024 words).
            .map(|(i, word)| (word, i as u16))
            .collect()
    })
}

/// The RS1024 (Reed–Solomon over GF(1024)) polymod from SLIP-0039. Operates on
/// 10-bit symbols; the share is valid when this returns 1 over the customization
/// string followed by the share's word indices.
fn rs1024_polymod(values: &[u16]) -> u32 {
    const GEN: [u32; 10] = [
        0x00E0_E040,
        0x01C1_C080,
        0x0383_8100,
        0x0707_0200,
        0x0E0E_0009,
        0x1C0C_2412,
        0x3808_6C24,
        0x3090_FC48,
        0x21B1_F890,
        0x03F3_F120,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 20;
        chk = ((chk & 0xF_FFFF) << 10) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// `true` if `indices` (a share's word values, including its 3 checksum words)
/// has a valid RS1024 checksum. The combined buffer holds secret-derived symbols
/// and is zeroized on drop.
fn rs1024_verify_checksum(indices: &[u16]) -> bool {
    let mut values: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(
        CUSTOMIZATION_STRING.len() + indices.len(),
    ));
    values.extend_from_slice(&CUSTOMIZATION_STRING);
    values.extend_from_slice(indices);
    rs1024_polymod(&values) == 1
}

/// A token: its lowercased text (secret-derived, zeroized on drop) and the byte
/// range it occupied in the original input.
struct Token {
    word: Zeroizing<String>,
    range: ByteRange,
}

/// `true` for the token separators of §13.5.5/§13.5.1: any Unicode whitespace
/// (space, newline, ideographic space U+3000) plus the comma.
fn is_separator(ch: char) -> bool {
    ch.is_whitespace() || ch == ','
}

/// Split `input` into lowercased tokens, recording each token's byte range in
/// the original input.
fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (idx, ch) in input.char_indices() {
        if is_separator(ch) {
            if let Some(s) = start.take() {
                tokens.push(make_token(input, s, idx));
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }
    if let Some(s) = start.take() {
        tokens.push(make_token(input, s, input.len()));
    }
    tokens
}

fn make_token(input: &str, start: usize, end: usize) -> Token {
    Token {
        word: Zeroizing::new(input[start..end].to_lowercase()),
        range: ByteRange::new(start, end),
    }
}

/// The 10-bit indices for a window of tokens, or `None` if any token is not a
/// SLIP-39 word. The returned buffer is secret-derived and zeroized on drop.
fn window_indices(window: &[Token]) -> Option<Zeroizing<Vec<u16>>> {
    let map = wordlist_index();
    let mut indices: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(window.len()));
    for token in window {
        indices.push(*map.get(token.word.as_str())?);
    }
    Some(indices)
}

/// Scan `input` for SLIP-39 shares and push any findings into `out`.
pub(crate) fn scan(input: &str, out: &mut Collector) {
    let tokens = tokenize(input);
    if tokens.len() < MIN_WORDS {
        return;
    }
    let n = tokens.len();

    // First, collect the byte ranges of every distinct share (advancing past a
    // matched window so shares are not double-counted), then push them all once
    // the total share count is known.
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < n {
        let mut matched = None;
        for &size in &WINDOW_SIZES {
            if i + size > n {
                continue; // window runs past the end
            }
            if let Some(indices) = window_indices(&tokens[i..i + size]) {
                if rs1024_verify_checksum(&indices) {
                    matched = Some(size);
                    break; // largest valid window wins
                }
            }
        }
        if let Some(size) = matched {
            ranges.push(ByteRange::new(
                tokens[i].range.start,
                tokens[i + size - 1].range.end,
            ));
            i += size;
        } else {
            i += 1;
        }
    }

    let count = u8::try_from(ranges.len()).unwrap_or(u8::MAX);
    for range in ranges {
        out.push(
            DetectedSecret::Slip39 {
                share_count_in_input: count,
            },
            range,
            DetectorAction::Block,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official SLIP-0039 test vectors (trezor/python-shamir-mnemonic vectors.json).
    // These are *documented* vectors with non-real master secrets, never real
    // backups (§27). Each is a standalone 1-of-1 share with a valid RS1024
    // checksum.
    const VECTOR_20W: &str = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
    const VECTOR_33W: &str = "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck";

    /// Every SLIP-39 finding in a report (there may also be incidental findings
    /// from other detectors over the same words; we assert only on ours).
    fn slip39_findings(report: &crate::DetectorReport) -> Vec<(u8, ByteRange)> {
        report
            .findings
            .iter()
            .filter_map(|f| match f {
                (
                    DetectedSecret::Slip39 {
                        share_count_in_input,
                    },
                    range,
                ) => Some((*share_count_in_input, *range)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn blocks_official_20_word_vector() {
        let report = crate::detect(VECTOR_20W);
        assert!(report.is_blocked(), "a valid 20-word share must Block");
        let found = slip39_findings(&report);
        assert_eq!(found.len(), 1, "expected exactly one SLIP-39 share");
        assert_eq!(found[0].0, 1, "share_count_in_input should be 1");
        assert_eq!(&VECTOR_20W[found[0].1.as_range()], VECTOR_20W);
    }

    #[test]
    fn blocks_official_33_word_vector() {
        let report = crate::detect(VECTOR_33W);
        assert!(report.is_blocked(), "a valid 33-word share must Block");
        let found = slip39_findings(&report);
        assert_eq!(found.len(), 1, "expected exactly one SLIP-39 share");
        assert_eq!(found[0].0, 1);
    }

    #[test]
    fn no_finding_on_invalid_checksum() {
        // Replace the last word with a *different* SLIP-39 word: still all
        // in-wordlist (so the all-in-list gate passes) but the RS1024 checksum
        // now fails, so it must NOT be reported as a share.
        let mut words: Vec<&str> = VECTOR_20W.split_whitespace().collect();
        let last = *words.last().unwrap();
        let replacement = if last == "academic" {
            "zero"
        } else {
            "academic"
        };
        *words.last_mut().unwrap() = replacement;
        let phrase = words.join(" ");

        // Self-check: every word is still a SLIP-39 word.
        let map = wordlist_index();
        assert!(
            phrase.split_whitespace().all(|w| map.contains_key(w)),
            "the modified phrase should still be all-in-wordlist"
        );

        let report = crate::detect(&phrase);
        assert!(
            slip39_findings(&report).is_empty(),
            "a checksum-invalid share must not be reported"
        );
    }

    #[test]
    fn no_finding_when_a_word_is_not_in_wordlist() {
        // 20 tokens, but one ("article" — a BIP39 word, not SLIP-39) is not in
        // the SLIP-39 wordlist, so the all-in-list gate fails.
        let mut words: Vec<&str> = VECTOR_20W.split_whitespace().collect();
        words[10] = "article";
        let phrase = words.join(" ");
        let report = crate::detect(&phrase);
        assert!(
            slip39_findings(&report).is_empty(),
            "a window with a non-SLIP-39 word is not a share"
        );
    }

    #[test]
    fn fewer_than_twenty_words_is_allowed() {
        // The first 19 words of the valid 20-word share: too few to be a share.
        let nineteen = VECTOR_20W
            .split_whitespace()
            .take(19)
            .collect::<Vec<_>>()
            .join(" ");
        let report = crate::detect(&nineteen);
        assert!(slip39_findings(&report).is_empty());
    }

    #[test]
    fn counts_two_shares_in_one_input() {
        // The 20-word and 33-word vectors together: two distinct shares.
        let input = format!("{VECTOR_20W}\n{VECTOR_33W}");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let found = slip39_findings(&report);
        assert_eq!(found.len(), 2, "expected two SLIP-39 shares");
        assert!(
            found.iter().all(|(count, _)| *count == 2),
            "share_count_in_input should be 2 on every finding"
        );
    }

    #[test]
    fn detects_share_embedded_in_text() {
        let input = format!("here are my shares: {VECTOR_20W} -- keep them apart");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let found = slip39_findings(&report);
        assert_eq!(found.len(), 1);
        assert_eq!(&input[found[0].1.as_range()], VECTOR_20W);
    }

    #[test]
    fn report_omits_share_words_json_and_debug() {
        // No-leak over a real detection: the report must not echo any share word.
        let report = crate::detect(VECTOR_20W);
        assert!(report.is_blocked());
        let json = serde_json::to_string(&report).expect("serializes");
        let debug = format!("{report:?}");
        for word in VECTOR_20W.split_whitespace() {
            assert!(!json.contains(word), "JSON leaked the share word {word:?}");
            assert!(
                !debug.contains(word),
                "Debug leaked the share word {word:?}"
            );
        }
    }

    #[test]
    fn detects_committed_slip39_fixture() {
        // The documented 20-word share committed under `fixtures/secrets/`. Repo
        // -root fixtures are reached via the manifest dir (this crate is two
        // levels down).
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/slip39_share_20w.txt"
        ))
        .trim();
        let report = crate::detect(fixture);
        assert!(
            report.is_blocked(),
            "the slip39_share_20w fixture must Block"
        );
        assert_eq!(slip39_findings(&report).len(), 1);
    }
}
