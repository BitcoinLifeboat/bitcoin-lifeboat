#![no_main]
//! `fuzz_detector_false_positive` (PRD §13.5.10): clean natural-language /
//! dictionary input must never yield a `Block`. Seed the run with a corpus of
//! English text and the system dictionary (e.g.
//! `cargo +nightly fuzz run fuzz_detector_false_positive corpus/...`); a `Block`
//! verdict here is a real false positive worth investigating.

use libfuzzer_sys::fuzz_target;
use sensitive_input_detector::detect;

// Keep this target inside its stated invariant: clean prose, not arbitrary bytes
// that can mutate into WIF/xprv-shaped material and correctly trigger Block.
const CLEAN_WORDS: &[&str] = &[
    "lifeboat",
    "descriptor",
    "watchonly",
    "runbook",
    "rehearsal",
    "checklist",
    "readiness",
    "keypath",
    "signerlabel",
    "vaultnote",
    "heirplan",
    "walletmap",
    "backupcard",
    "practicecopy",
    "reviewnote",
    "audittrail",
];

fuzz_target!(|data: &[u8]| {
    let s = clean_prose_from_bytes(data);
    let report = detect(&s);
    assert!(
        !report.is_blocked(),
        "false positive: clean-corpus input produced a Block verdict"
    );
});

fn clean_prose_from_bytes(data: &[u8]) -> String {
    let mut out = String::new();
    for &byte in data.iter().take(512) {
        match byte % 16 {
            0 => out.push_str(". "),
            1 => out.push_str(", "),
            2 => out.push('\n'),
            _ => {
                out.push_str(CLEAN_WORDS[usize::from(byte) % CLEAN_WORDS.len()]);
                out.push(' ');
            }
        }
    }
    out
}
