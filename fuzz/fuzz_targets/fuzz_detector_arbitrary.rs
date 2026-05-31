#![no_main]
//! `fuzz_detector_arbitrary` (PRD §13.5.10): the detector must never panic on
//! arbitrary input. Returning at all is the invariant — libFuzzer treats a panic
//! / abort / overflow as a crash.

use libfuzzer_sys::fuzz_target;
use sensitive_input_detector::detect;

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes → a `&str` via lossy decode (always valid UTF-8), plus the
    // strict decode when the bytes already are UTF-8. The detector must handle
    // either without panicking, overflowing, or slicing on a non-char boundary.
    let lossy = String::from_utf8_lossy(data);
    let _ = detect(&lossy);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = detect(s);
    }
});
