//! Deterministic property tests mirroring the four `cargo-fuzz` targets
//! (PRD §13.5.10). The fuzz crate (`fuzz/`) is a detached, nightly-only
//! workspace that the stable quality gate never builds, so these tests give the
//! same four guarantees a place in `cargo test` — the gate that *does* run every
//! iteration:
//!
//! * `arbitrary_input_never_panics`      ↔ `fuzz_detector_arbitrary`
//! * `clean_corpus_never_blocks`         ↔ `fuzz_detector_false_positive`
//! * `valid_secrets_always_block`        ↔ `fuzz_detector_false_negative`
//! * `descriptors_with_xprv_always_block`↔ `fuzz_descriptor_with_xprv`
//!
//! Randomness is a fixed-seed xorshift (no `rand` dep) so runs are reproducible,
//! matching the project's determinism rule. All secret material is a documented
//! test vector from `fixtures/secrets/`, never a real secret (PRD §27).

use sensitive_input_detector::detect;

/// Tiny deterministic PRNG (xorshift64*). Fixed seed ⇒ reproducible corpus.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        // Arbitrary non-zero seed; constant so the generated corpus is stable.
        Self(0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    /// A random byte buffer of length in `[0, max_len]`.
    fn buf(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next_u64() as usize) % (max_len + 1);
        (0..len).map(|_| self.byte()).collect()
    }
}

/// Every committed secret fixture (documented test vectors, never real secrets).
fn secret_fixtures() -> [(&'static str, &'static str); 7] {
    [
        (
            "bip39_english_12",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/bip39_english_12.txt"
            )),
        ),
        (
            "bip39_english_24",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/bip39_english_24.txt"
            )),
        ),
        (
            "bip39_japanese_12",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/bip39_japanese_12.txt"
            )),
        ),
        (
            "wif_mainnet",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/wif_mainnet.txt"
            )),
        ),
        (
            "xprv_mainnet",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/xprv_mainnet.txt"
            )),
        ),
        (
            "slip39_share_20w",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/slip39_share_20w.txt"
            )),
        ),
        (
            "codex32_128bit",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/secrets/codex32_128bit.txt"
            )),
        ),
    ]
}

/// The xprv test vector, used to build descriptors with embedded private keys.
fn test_xprv() -> &'static str {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/secrets/xprv_mainnet.txt"
    ))
    .trim()
}

// ----------------------------------------------------------------------------
// 1. Arbitrary input must never panic (↔ fuzz_detector_arbitrary).
// ----------------------------------------------------------------------------

#[test]
fn arbitrary_input_never_panics() {
    let mut rng = Rng::new();

    // Tens of thousands of random byte buffers, decoded lossily (always valid
    // UTF-8) and, when already valid, strictly. Returning at all proves no panic
    // (a panic aborts the test).
    for _ in 0..40_000 {
        let bytes = rng.buf(160);
        let lossy = String::from_utf8_lossy(&bytes);
        let _ = detect(&lossy);
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = detect(s);
        }
    }

    // Adversarial shapes that have tripped slicing/boundary bugs before.
    let mut adversarial = vec![
        String::new(),
        " ".repeat(10_000),
        "\u{3000}".repeat(2_000),      // ideographic spaces
        "(".repeat(5_000),             // descriptor delimiters
        "],/".repeat(3_000),           // key-boundary chars
        "a".repeat(100_000),           // long word run
        "0123456789abcdef".repeat(64), // long hex run
        "ms1".repeat(4_000),           // codex32 prefix spam
        "prv".repeat(4_000),           // xprv prefix spam
        "é".repeat(5_000),             // multibyte
        "🚀".repeat(5_000),            // 4-byte chars near windows
        "abandon ".repeat(5_000),      // BIP39 word spam (huge windows)
    ];
    // Every fixture, plus all fixtures glued together, plus each wrapped in junk.
    let glued: String = secret_fixtures().iter().map(|(_, s)| *s).collect();
    adversarial.push(glued);
    for (_, raw) in secret_fixtures() {
        adversarial.push(format!("\u{0}{raw}\u{0}"));
        adversarial.push(format!("{raw}{raw}{raw}"));
    }
    for s in &adversarial {
        let _ = detect(s);
    }
}

// ----------------------------------------------------------------------------
// 2. Clean natural-language / dictionary input must never Block
//    (↔ fuzz_detector_false_positive).
// ----------------------------------------------------------------------------

/// A clean corpus: ordinary prose, descriptors, addresses, hashes, and single
/// dictionary words. None of it is a secret, so none of it may `Block`. Entries
/// deliberately avoid runs of 12+ consecutive BIP39 words with a valid checksum.
const CLEAN_CORPUS: &[&str] = &[
    "",
    "The quick brown fox jumps over the lazy dog.",
    "Bitcoin Lifeboat helps you test whether your recovery plan actually works.",
    "Export the output descriptor from your wallet software and paste it here.",
    "Please review the attached document before our meeting tomorrow afternoon.",
    "wpkh([d34db33f/84h/0h/0h]xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/0/*)#qwe7dwes",
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "The blockchain records every transaction in a public, append-only ledger.",
    "My favorite programming languages are Rust, Python, and TypeScript.",
    "Recovery, descriptor, fingerprint, derivation, multisig, timelock, inheritance.",
    "abandon ability",
    "result",
    "duckling",
    "Coffee tastes better in the morning when the weather is cold outside.",
    "She sells seashells by the seashore on sunny summer Saturday mornings.",
    "Generate a runbook and print two copies for your safe deposit box.",
    "https://bitcoinlifeboat.org/docs/getting-started",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod.",
];

#[test]
fn clean_corpus_never_blocks() {
    for &entry in CLEAN_CORPUS {
        let report = detect(entry);
        assert!(
            !report.is_blocked(),
            "false positive: clean corpus entry produced a Block: {entry:?}"
        );
    }

    // Mutate the clean corpus with the deterministic RNG (truncation, byte
    // tweaks, concatenation) — small perturbations of clean text must still not
    // Block.
    let mut rng = Rng::new();
    for _ in 0..20_000 {
        let a = CLEAN_CORPUS[(rng.next_u64() as usize) % CLEAN_CORPUS.len()];
        let b = CLEAN_CORPUS[(rng.next_u64() as usize) % CLEAN_CORPUS.len()];
        let mut bytes = format!("{a} {b}").into_bytes();
        if !bytes.is_empty() {
            // Flip a couple of bytes.
            let i = (rng.next_u64() as usize) % bytes.len();
            bytes[i] = rng.byte();
            let trunc = (rng.next_u64() as usize) % (bytes.len() + 1);
            bytes.truncate(trunc);
        }
        let s = String::from_utf8_lossy(&bytes);
        let report = detect(&s);
        assert!(
            !report.is_blocked(),
            "false positive: mutated clean text produced a Block: {s:?}"
        );
    }
}

// ----------------------------------------------------------------------------
// 3. Valid secrets (and validity-preserving mutations) must always Block
//    (↔ fuzz_detector_false_negative).
// ----------------------------------------------------------------------------

#[test]
fn valid_secrets_always_block() {
    for (name, raw) in secret_fixtures() {
        let secret = raw.trim();

        // The bare secret.
        assert!(
            detect(secret).is_blocked(),
            "false negative: {name} bare secret not blocked"
        );

        // Validity-preserving mutations: surrounding whitespace and embedding in
        // ordinary text keep the secret intact, so it must still Block.
        let surrounded = format!("  {secret}  ");
        let embedded = format!("please check this value: {secret} thank you");
        let mut variants = vec![surrounded, embedded];

        // Word-separated formats (mnemonics, SLIP-39 shares) survive any
        // whitespace separator.
        if secret.contains(' ') {
            variants.push(secret.replace(' ', "\n"));
            variants.push(secret.replace(' ', "\t"));
            variants.push(secret.replace(' ', "\u{3000}")); // ideographic space
        }

        for v in variants {
            assert!(
                detect(&v).is_blocked(),
                "false negative: {name} mutation not blocked: {v:?}"
            );
        }
    }
}

// ----------------------------------------------------------------------------
// 4. Descriptors containing an xprv must always Block
//    (↔ fuzz_descriptor_with_xprv).
// ----------------------------------------------------------------------------

#[test]
fn descriptors_with_xprv_always_block() {
    let xprv = test_xprv();
    let descriptors = [
        format!("wpkh({xprv})"),
        format!("wpkh({xprv}/0/*)"),
        format!("sh(wpkh({xprv}/0/*))"),
        format!("wsh(multi(1,{xprv}))"),
        format!("[00000000/84h/0h/0h]{xprv}/0/*"),
        format!("# my watch-only wallet\n{xprv}\n"),
        format!("combo({xprv})"),
    ];
    for d in descriptors {
        let report = detect(&d);
        assert!(
            report.is_blocked(),
            "false negative: descriptor with embedded xprv not blocked: {d:?}"
        );
    }

    // The xprv glued after arbitrary clean text, always newline-delimited so it
    // sits at a word boundary regardless of what precedes it.
    let mut rng = Rng::new();
    for _ in 0..2_000 {
        let prefix = String::from_utf8_lossy(&rng.buf(64)).into_owned();
        let candidate = format!("{prefix}\n{xprv}\n");
        assert!(
            detect(&candidate).is_blocked(),
            "false negative: newline-delimited xprv not blocked"
        );
    }
}
