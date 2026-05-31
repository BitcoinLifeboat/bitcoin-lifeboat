# `sensitive-input-detector` fuzz targets (PRD §13.5.10)

cargo-fuzz / libFuzzer harness for the secret detector. This is a **detached,
nightly-only workspace** — it depends on `libfuzzer-sys` and is excluded from the
stable quality gate. The same four invariants are checked deterministically
under `cargo test` by
`../crates/sensitive-input-detector/tests/fuzz_properties.rs`, so a normal build
never needs nightly.

## Targets

| Target | Invariant |
| --- | --- |
| `fuzz_detector_arbitrary` | random bytes → must not panic |
| `fuzz_detector_false_positive` | clean English / dictionary corpus → zero `Block` |
| `fuzz_detector_false_negative` | minted valid BIP39 mnemonics → must `Block` |
| `fuzz_descriptor_with_xprv` | descriptors with an embedded xprv → must `Block` |

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Build & run

From this directory (`fuzz/`):

```sh
# Build all targets.
cargo +nightly fuzz build

# Run one target for 60 seconds (the acceptance-gate smoke run; CI runs 5 min
# per PR, 1 hour on release branches — PRD §13.5.10).
cargo +nightly fuzz run fuzz_detector_arbitrary       -- -max_total_time=60
cargo +nightly fuzz run fuzz_detector_false_positive  -- -max_total_time=60
cargo +nightly fuzz run fuzz_detector_false_negative  -- -max_total_time=60
cargo +nightly fuzz run fuzz_descriptor_with_xprv     -- -max_total_time=60
```

Seed `fuzz_detector_false_positive` with real clean text for best coverage, e.g.
`cargo +nightly fuzz run fuzz_detector_false_positive /usr/share/dict/`.

All embedded secret material is a documented test vector, never a real secret
(PRD §27).
