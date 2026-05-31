#![no_main]
//! `fuzz_detector_false_negative` (PRD §13.5.10): a *valid* secret must always
//! `Block`.
//!
//! Every iteration mints a checksum-valid BIP39 mnemonic from the fuzzer bytes
//! (used as entropy) across all ten wordlists, so the input is a real secret by
//! construction — the detector must `Block` it 100% of the time. This explores a
//! vast space of valid mnemonics. WIF / xprv / SLIP-39 / codex32 false-negative
//! coverage lives in the deterministic corpus replay in
//! `crates/sensitive-input-detector/tests/fuzz_properties.rs` (those formats
//! cannot be minted from arbitrary bytes without heavier dependencies).

use bip39::{Language, Mnemonic};
use libfuzzer_sys::fuzz_target;
use sensitive_input_detector::detect;

fuzz_target!(|data: &[u8]| {
    // Need at least one selector byte + 16 bytes of entropy.
    if data.len() < 17 {
        return;
    }
    let lang = Language::ALL[(data[0] as usize) % Language::ALL.len()];
    // 16 bytes of entropy → 12 words; 32 bytes → 24 words.
    let entropy_len = if data.len() >= 33 { 32 } else { 16 };
    let entropy = &data[1..=entropy_len];

    let Ok(mnemonic) = Mnemonic::from_entropy_in(lang, entropy) else {
        return; // not a valid entropy length for this build
    };
    let phrase = mnemonic.to_string();
    let report = detect(&phrase);
    assert!(
        report.is_blocked(),
        "false negative: a checksum-valid BIP39 mnemonic was not blocked"
    );
});
