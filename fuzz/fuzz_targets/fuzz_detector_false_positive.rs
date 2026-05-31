#![no_main]
//! `fuzz_detector_false_positive` (PRD §13.5.10): clean natural-language /
//! dictionary input must never yield a `Block`. Seed the run with a corpus of
//! English text and the system dictionary (e.g.
//! `cargo +nightly fuzz run fuzz_detector_false_positive corpus/...`); a `Block`
//! verdict here is a real false positive worth investigating.

use libfuzzer_sys::fuzz_target;
use sensitive_input_detector::detect;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let report = detect(&s);
    assert!(
        !report.is_blocked(),
        "false positive: clean-corpus input produced a Block verdict"
    );
});
