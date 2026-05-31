//! BIP39 mnemonic detection (US-013, PRD §13.5.1).
//!
//! Recognizes pasted BIP39 seed phrases across all ten official wordlists so the
//! caller can refuse them — Lifeboat is watch-only and never needs a mnemonic.
//!
//! # Algorithm (§13.5.1)
//!
//! 1. Tokenize the input on whitespace (including newline and the ideographic
//!    space U+3000) and commas.
//! 2. NFKD-normalize and lowercase each token, matching the canonical form of
//!    the vendored wordlists.
//! 3. Slide a window of {12, 15, 18, 21, 24} tokens (the valid mnemonic lengths),
//!    largest first so a 24-word seed is reported once, not as nested 12s.
//! 4. Identify the language by matching every token against a wordlist — exactly
//!    for the checksum path, or by 4-character prefix (the BIP39 uniqueness
//!    property) for the looser "looks like a seed" path.
//! 5. Decide the action:
//!    * all tokens are exact words **and** the BIP39 checksum validates → `Block`;
//!    * ≥12 tokens all match a single wordlist but the checksum fails → `Warn`;
//!    * fewer than 12 matching tokens → no finding (too noisy, §13.5.1).
//!
//! Checksum validation is delegated to the `bip39` crate; the wordlists used for
//! prefix detection are vendored from that same crate (`wordlists/bip39/*.txt`,
//! integrity-pinned in `build.rs`), so the two can never drift apart.
//!
//! # Secret hygiene
//!
//! Every buffer derived from the input — the per-token normalized strings and
//! the joined candidate phrase — is held in [`zeroize::Zeroizing`] and wiped when
//! it drops. The findings this module pushes carry only the language, word count,
//! checksum verdict, and a [`ByteRange`]: never the words themselves.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Bip39Language, ByteRange, Collector, DetectedSecret, DetectorAction};

/// Valid BIP39 mnemonic lengths, scanned largest-first (§13.5.1).
const WINDOW_SIZES: [usize; 5] = [24, 21, 18, 15, 12];

/// Shortest mnemonic; inputs with fewer tokens can never match.
const MIN_WORDS: usize = 12;

/// Number of leading characters that uniquely identify a BIP39 word within a
/// list (the wordlist design guarantee Lifeboat relies on for prefix matching).
const PREFIX_LEN: usize = 4;

/// One vendored wordlist plus the mapping it needs: our public language tag for
/// reporting, and the `bip39` crate's language for checksum validation.
struct WordlistData {
    /// Public tag reported in [`DetectedSecret::Bip39`].
    language: Bip39Language,
    /// Counterpart used only for `bip39` checksum validation.
    bip39_language: bip39::Language,
    /// All 2048 words (exact membership).
    words: std::collections::HashSet<&'static str>,
    /// The [`PREFIX_LEN`]-scalar prefix of each word (fuzzy membership).
    prefixes: std::collections::HashSet<&'static str>,
}

/// The vendored, integrity-pinned wordlists (`build.rs`). `include_str!` is
/// relative to this file, so `../wordlists/...` resolves to the crate root.
const RAW_WORDLISTS: [(Bip39Language, bip39::Language, &str); 10] = [
    (
        Bip39Language::English,
        bip39::Language::English,
        include_str!("../wordlists/bip39/english.txt"),
    ),
    (
        Bip39Language::Japanese,
        bip39::Language::Japanese,
        include_str!("../wordlists/bip39/japanese.txt"),
    ),
    (
        Bip39Language::Korean,
        bip39::Language::Korean,
        include_str!("../wordlists/bip39/korean.txt"),
    ),
    (
        Bip39Language::Spanish,
        bip39::Language::Spanish,
        include_str!("../wordlists/bip39/spanish.txt"),
    ),
    (
        Bip39Language::ChineseSimplified,
        bip39::Language::SimplifiedChinese,
        include_str!("../wordlists/bip39/chinese_simplified.txt"),
    ),
    (
        Bip39Language::ChineseTraditional,
        bip39::Language::TraditionalChinese,
        include_str!("../wordlists/bip39/chinese_traditional.txt"),
    ),
    (
        Bip39Language::French,
        bip39::Language::French,
        include_str!("../wordlists/bip39/french.txt"),
    ),
    (
        Bip39Language::Italian,
        bip39::Language::Italian,
        include_str!("../wordlists/bip39/italian.txt"),
    ),
    (
        Bip39Language::Czech,
        bip39::Language::Czech,
        include_str!("../wordlists/bip39/czech.txt"),
    ),
    (
        Bip39Language::Portuguese,
        bip39::Language::Portuguese,
        include_str!("../wordlists/bip39/portuguese.txt"),
    ),
];

/// Lazily build the ten wordlist indexes once. The order fixes the bit index
/// each language occupies in the per-token match masks.
fn wordlists() -> &'static [WordlistData; 10] {
    use std::sync::OnceLock;
    static LISTS: OnceLock<[WordlistData; 10]> = OnceLock::new();
    LISTS.get_or_init(|| {
        RAW_WORDLISTS.map(|(language, bip39_language, raw)| {
            let words: std::collections::HashSet<&'static str> =
                raw.lines().filter(|line| !line.is_empty()).collect();
            let prefixes = words.iter().map(|word| prefix(word)).collect();
            WordlistData {
                language,
                bip39_language,
                words,
                prefixes,
            }
        })
    })
}

/// The first [`PREFIX_LEN`] Unicode scalar values of `word` (the whole word if it
/// is shorter). Always returns a slice on a character boundary.
fn prefix(word: &str) -> &str {
    match word.char_indices().nth(PREFIX_LEN) {
        Some((byte_idx, _)) => &word[..byte_idx],
        None => word,
    }
}

/// NFKD-normalize then lowercase, matching the canonical wordlist form (§13.5.1).
/// The intermediate normalized buffer is zeroized; the returned `String` is
/// wrapped by the caller.
fn normalize(raw: &str) -> String {
    let nfkd: Zeroizing<String> = Zeroizing::new(raw.nfkd().collect());
    nfkd.to_lowercase()
}

/// `true` for the token separators of §13.5.1: any Unicode whitespace (covers
/// space, newline, and the ideographic space U+3000) plus the comma.
fn is_separator(ch: char) -> bool {
    ch.is_whitespace() || ch == ','
}

/// A token: its normalized text (secret-derived, zeroized on drop) and the byte
/// range it occupied in the *original* input (what the caller highlights/clears).
struct Token {
    norm: Zeroizing<String>,
    range: ByteRange,
}

/// Split `input` into tokens, recording each token's byte range in the original
/// input and its normalized form.
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
        norm: Zeroizing::new(normalize(&input[start..end])),
        range: ByteRange::new(start, end),
    }
}

/// For a normalized token, the bitmask of languages it matches exactly and the
/// bitmask it matches by prefix (exact ⊆ prefix). Bit `i` is the language at
/// index `i` in [`wordlists`].
fn token_masks(norm: &str) -> (u16, u16) {
    let lists = wordlists();
    let token_prefix = prefix(norm);
    let mut exact = 0u16;
    let mut prefix_mask = 0u16;
    for (i, list) in lists.iter().enumerate() {
        if list.words.contains(norm) {
            exact |= 1 << i;
            prefix_mask |= 1 << i;
        } else if list.prefixes.contains(token_prefix) {
            prefix_mask |= 1 << i;
        }
    }
    (exact, prefix_mask)
}

/// Among the languages whose bit is set in `exact_mask`, return the first whose
/// BIP39 checksum validates for `window` (⇒ `Block`), or `None` if none do.
fn checksum_validates(window: &[Token], exact_mask: u16) -> Option<Bip39Language> {
    let lists = wordlists();
    let phrase: Zeroizing<String> = Zeroizing::new(join_words(window));
    let mut bits = exact_mask;
    while bits != 0 {
        let i = bits.trailing_zeros() as usize;
        bits &= bits - 1; // clear the lowest set bit
        let list = &lists[i];
        if bip39::Mnemonic::parse_in_normalized(list.bip39_language, phrase.as_str()).is_ok() {
            return Some(list.language);
        }
    }
    None
}

/// Join a window's normalized words with a single ASCII space — the form
/// `bip39::Mnemonic::parse_in_normalized` expects (it splits on whitespace).
fn join_words(window: &[Token]) -> String {
    let mut phrase = String::new();
    for (i, token) in window.iter().enumerate() {
        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(token.norm.as_str());
    }
    phrase
}

/// Scan `input` for BIP39 mnemonics and push any findings into `out`.
pub(crate) fn scan(input: &str, out: &mut Collector) {
    let tokens = tokenize(input);
    if tokens.len() < MIN_WORDS {
        return;
    }
    let masks: Vec<(u16, u16)> = tokens
        .iter()
        .map(|t| token_masks(t.norm.as_str()))
        .collect();

    let n = tokens.len();
    let mut i = 0;
    while i < n {
        // At this position, prefer the largest window that yields a Block; only
        // if no window Blocks, take the largest window that Warns.
        let mut chosen: Option<(usize, Bip39Language, bool)> = None;
        for &size in &WINDOW_SIZES {
            if i + size > n {
                continue;
            }
            let (exact, prefix_mask) = window_masks(&masks[i..i + size]);
            if exact != 0 {
                if let Some(language) = checksum_validates(&tokens[i..i + size], exact) {
                    chosen = Some((size, language, true));
                    break; // largest Block wins; stop scanning this position
                }
            }
            if chosen.is_none() && prefix_mask != 0 {
                let language = wordlists()[prefix_mask.trailing_zeros() as usize].language;
                chosen = Some((size, language, false));
                // Keep scanning smaller sizes — a Block would still override.
            }
        }

        if let Some((size, language, checksum_valid)) = chosen {
            let range = ByteRange::new(tokens[i].range.start, tokens[i + size - 1].range.end);
            let action = if checksum_valid {
                DetectorAction::Block
            } else {
                DetectorAction::Warn
            };
            out.push(
                DetectedSecret::Bip39 {
                    language,
                    word_count: size as u8,
                    checksum_valid,
                },
                range,
                action,
            );
            i += size; // skip the matched window to avoid nested duplicates
        } else {
            i += 1;
        }
    }
}

/// AND the per-token masks across a window: `(exact, prefix)` languages shared by
/// every token.
fn window_masks(masks: &[(u16, u16)]) -> (u16, u16) {
    let mut exact = u16::MAX;
    let mut prefix_mask = u16::MAX;
    for &(e, p) in masks {
        exact &= e;
        prefix_mask &= p;
    }
    (exact, prefix_mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Map the `bip39` crate's language back to our public tag, so a vector
    /// generated for a given `bip39::Language` can be asserted against the
    /// language the detector reports.
    fn expected_tag(language: bip39::Language) -> Bip39Language {
        wordlists()
            .iter()
            .find(|list| list.bip39_language == language)
            .map(|list| list.language)
            .expect("every bip39 language is mapped")
    }

    /// The documented all-zero-entropy mnemonic for `language` — the canonical
    /// BIP39 test vector, never a real seed (entropy is all zeros). `bytes` is
    /// 16 for 12 words, 32 for 24 words.
    fn zero_vector(language: bip39::Language, entropy_bytes: usize) -> String {
        let entropy = vec![0u8; entropy_bytes];
        bip39::Mnemonic::from_entropy_in(language, &entropy)
            .expect("all-zero entropy is a valid mnemonic")
            .to_string()
    }

    fn single_bip39(report: &crate::DetectorReport) -> (Bip39Language, u8, bool, ByteRange) {
        assert_eq!(report.findings.len(), 1, "expected exactly one finding");
        match report.findings[0] {
            (
                DetectedSecret::Bip39 {
                    language,
                    word_count,
                    checksum_valid,
                },
                range,
            ) => (language, word_count, checksum_valid, range),
            ref other => panic!("expected a Bip39 finding, got {other:?}"),
        }
    }

    #[test]
    fn blocks_valid_vectors_all_languages_12_and_24() {
        for &language in bip39::Language::ALL {
            for (entropy_bytes, words) in [(16usize, 12u8), (32, 24)] {
                let phrase = zero_vector(language, entropy_bytes);
                let report = crate::detect(&phrase);
                assert!(
                    report.is_blocked(),
                    "{language:?} {words}-word valid vector must Block"
                );
                let (tag, count, checksum_valid, range) = single_bip39(&report);
                let expected = expected_tag(language);
                // The Simplified and Traditional Chinese lists share low-index
                // words at identical positions, so an all-zero vector is a valid
                // mnemonic in BOTH; the detector reports one of them. Every other
                // language is unambiguous here.
                if matches!(
                    expected,
                    Bip39Language::ChineseSimplified | Bip39Language::ChineseTraditional
                ) {
                    assert!(
                        matches!(
                            tag,
                            Bip39Language::ChineseSimplified | Bip39Language::ChineseTraditional
                        ),
                        "Chinese vector should detect a Chinese variant, got {tag:?}"
                    );
                } else {
                    assert_eq!(tag, expected, "wrong language for {language:?}");
                }
                assert_eq!(count, words, "wrong word count for {language:?}");
                assert!(checksum_valid, "{language:?} vector must be checksum-valid");
                // The finding spans the whole phrase.
                assert_eq!(range.start, 0);
                assert_eq!(range.end, phrase.len());
            }
        }
    }

    #[test]
    fn warns_on_invalid_checksum_all_languages_12_and_24() {
        for &language in bip39::Language::ALL {
            for (entropy_bytes, words_count) in [(16usize, 12u8), (32, 24)] {
                // Start from the valid all-zero vector, then replace the LAST
                // word (the checksum word) with the wordlist's first word (index
                // 0). Every token stays a real word of this language, so the
                // window still matches it, but the stored checksum becomes 0
                // while the correct one is nonzero → invalid.
                let valid = zero_vector(language, entropy_bytes);
                let mut words: Vec<&str> = valid.split_whitespace().collect();
                let first_word = language.word_list()[0];
                assert_ne!(
                    *words.last().unwrap(),
                    first_word,
                    "{language:?}/{words_count}w: swap would be a no-op"
                );
                *words.last_mut().unwrap() = first_word;
                let phrase = words.join(" ");

                // Self-check: the modified phrase really is checksum-invalid (yet
                // still all in-wordlist), so the Warn — not Block — path runs.
                assert!(
                    matches!(
                        bip39::Mnemonic::parse_in_normalized(language, &phrase),
                        Err(bip39::Error::InvalidChecksum)
                    ),
                    "{language:?}/{words_count}w: expected an invalid checksum after the swap"
                );

                let report = crate::detect(&phrase);
                assert!(
                    report.is_warning(),
                    "{language:?}/{words_count}w: invalid-checksum phrase must Warn"
                );
                // We assert the verdict and word count but NOT the exact
                // language: this degenerate all-index-0 vector prefix-matches
                // several Latin wordlists, so the reported language (lowest-index
                // match) is informational for a Warn. The valid-vector test pins
                // per-language detection unambiguously; the distinct-word test
                // below pins it for an unambiguous Warn.
                let (_, count, checksum_valid, _) = single_bip39(&report);
                assert_eq!(count, words_count);
                assert!(!checksum_valid);
            }
        }
    }

    #[test]
    fn warn_reports_correct_language_for_distinct_word_phrase() {
        // 12 DISTINCT English words make the language unambiguous (unlike the
        // repeated all-zero vector), so the Warn must name English. Pick a stride
        // of distinct indices and shift until the checksum is invalid — fully
        // deterministic, no hand-tuned vector.
        let english = bip39::Language::English.word_list();
        let phrase = (0u16..)
            .map(|offset| {
                (0usize..12)
                    .map(|i| english[(i * 100 + offset as usize) % 2048])
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .find(|candidate| {
                bip39::Mnemonic::parse_in_normalized(bip39::Language::English, candidate).is_err()
            })
            .expect("some offset yields an invalid checksum");

        let report = crate::detect(&phrase);
        assert!(report.is_warning());
        let (tag, count, checksum_valid, _) = single_bip39(&report);
        assert_eq!(tag, Bip39Language::English);
        assert_eq!(count, 12);
        assert!(!checksum_valid);
    }

    #[test]
    fn fewer_than_twelve_words_is_allowed() {
        // The first 11 words of the English all-zero vector — all real BIP39
        // words, but too few to be a mnemonic (§13.5.1: <12 ⇒ no action).
        let valid = zero_vector(bip39::Language::English, 16);
        let eleven = valid
            .split_whitespace()
            .take(11)
            .collect::<Vec<_>>()
            .join(" ");
        let report = crate::detect(&eleven);
        assert!(report.is_allowed());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn detects_seed_embedded_in_surrounding_text() {
        let valid = zero_vector(bip39::Language::English, 16);
        let input = format!("here is my backup: {valid} -- please keep it safe");
        let report = crate::detect(&input);
        assert!(report.is_blocked());
        let (_, count, checksum_valid, range) = single_bip39(&report);
        assert_eq!(count, 12);
        assert!(checksum_valid);
        // The range points at the phrase inside the larger input.
        assert_eq!(&input[range.as_range()], valid);
    }

    #[test]
    fn detects_comma_and_ideographic_space_separators() {
        let valid = zero_vector(bip39::Language::English, 16);
        let words: Vec<&str> = valid.split_whitespace().collect();
        for separator in [", ", "\u{3000}", "\n", ",", "  "] {
            let joined = words.join(separator);
            let report = crate::detect(&joined);
            assert!(
                report.is_blocked(),
                "separator {separator:?} should not defeat detection"
            );
            let (_, count, checksum_valid, _) = single_bip39(&report);
            assert_eq!(count, 12);
            assert!(checksum_valid);
        }
    }

    #[test]
    fn clean_prose_does_not_block() {
        // Ordinary English prose: even though some words are BIP39 words, a
        // random run must not produce a valid checksum (no false Block).
        let prose = "the quick brown fox jumps over the lazy dog while the cat \
                     sat quietly near a warm fire and dreamed of distant summer days";
        let report = crate::detect(prose);
        assert!(!report.is_blocked(), "clean prose must never Block");
    }

    #[test]
    fn report_omits_seed_words_json_and_debug() {
        // The no-leak invariant over a *real* detection (the all-zero vector):
        // the report must not contain any seed word, in JSON or Debug form.
        let phrase = zero_vector(bip39::Language::English, 16);
        let report = crate::detect(&phrase);
        assert!(report.is_blocked());
        let json = serde_json::to_string(&report).expect("serializes");
        let debug = format!("{report:?}");
        for word in phrase.split_whitespace() {
            assert!(!json.contains(word), "JSON leaked the seed word {word:?}");
            assert!(!debug.contains(word), "Debug leaked the seed word {word:?}");
        }
    }

    #[test]
    fn detects_committed_bip39_fixtures() {
        // The documented all-zero-entropy vectors committed under
        // `fixtures/secrets/` (the detector corpus, also used by US-016's
        // fuzzer). Reading them here proves the committed files are genuine
        // checksum-valid mnemonics that the detector blocks. Repo-root fixtures
        // are reached via the manifest dir (this crate is two levels down).
        let english_12 = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/bip39_english_12.txt"
        ))
        .trim();
        let english_24 = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/bip39_english_24.txt"
        ))
        .trim();
        let japanese_12 = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/secrets/bip39_japanese_12.txt"
        ))
        .trim();

        for (phrase, expected_lang, expected_words) in [
            (english_12, Bip39Language::English, 12u8),
            (english_24, Bip39Language::English, 24),
            (japanese_12, Bip39Language::Japanese, 12),
        ] {
            let report = crate::detect(phrase);
            // Don't print the phrase on failure — keep even test output seed-free.
            assert!(
                report.is_blocked(),
                "fixture for {expected_lang:?} must Block"
            );
            let (tag, count, checksum_valid, _) = single_bip39(&report);
            assert_eq!(tag, expected_lang);
            assert_eq!(count, expected_words);
            assert!(checksum_valid);
        }
    }

    #[test]
    fn prefix_helper_respects_char_boundaries() {
        assert_eq!(prefix("abandon"), "aban");
        assert_eq!(prefix("act"), "act"); // shorter than PREFIX_LEN
                                          // Multibyte: 4 scalar values, not 4 bytes.
        assert_eq!(prefix("あいこくしん").chars().count(), PREFIX_LEN);
    }
}
