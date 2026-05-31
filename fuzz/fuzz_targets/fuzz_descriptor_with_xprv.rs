#![no_main]
//! `fuzz_descriptor_with_xprv` (PRD §13.5.10): any descriptor containing an
//! extended private key must `Block`.
//!
//! A fixed synthetic test xprv (minted from a `[0x11; 32]` seed — NEVER a real
//! key; identical to `fixtures/secrets/xprv_mainnet.txt`) is embedded into
//! descriptor shapes and glued to arbitrary fuzzer bytes. The xprv is always
//! delimited (by `(`, `,`, or a newline) so it sits at a word boundary no matter
//! what surrounds it; the detector must therefore always catch it.

use libfuzzer_sys::fuzz_target;
use sensitive_input_detector::detect;

const TEST_XPRV: &str = "xprv9s21ZrQH143K2jBcWsJgb1tAam7rQuiALnTDBx7vfpXQFfYh5abvS1ui4VFgpeu9s1pC4r7qZhvimRbMcxFQ3qrkhWHQHyyMH9kqAxJqaVB";

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    // The xprv glued after arbitrary text, newline-delimited (guaranteed word
    // boundary before/after the key).
    let glued = format!("{s}\n{TEST_XPRV}\n");
    assert!(
        detect(&glued).is_blocked(),
        "false negative: newline-delimited embedded xprv was not blocked"
    );

    // Canonical descriptor wrappers (delimiters guarantee the boundary).
    for descriptor in [
        format!("wpkh({TEST_XPRV})"),
        format!("wpkh({TEST_XPRV}/0/*)"),
        format!("sh(wpkh({TEST_XPRV}/0/*))"),
        format!("wsh(multi(1,{TEST_XPRV}))"),
    ] {
        assert!(
            detect(&descriptor).is_blocked(),
            "false negative: descriptor with embedded xprv was not blocked"
        );
    }
});
