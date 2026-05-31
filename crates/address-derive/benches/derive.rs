//! Criterion benchmark for US-017's performance target: deriving 100 singlesig
//! addresses must take < 200 ms (PRD §28 budgets the heavier multisig cases).
//!
//! Run with `cargo bench -p address-derive` (the `cargo test` gate also enforces
//! the bound deterministically via `derives_100_singlesig_under_200ms`).

use address_derive::{derive_chain, Chain, Network};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use descriptor_audit::parse_descriptor;

/// A ranged singlesig (wpkh) testnet descriptor fixture (`/0/*`).
const WPKH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
));

fn bench_derive_100_singlesig(c: &mut Criterion) {
    let parsed = parse_descriptor(WPKH.trim()).expect("fixture parses");
    let descriptor = parsed.descriptor();

    c.bench_function("derive_100_singlesig_receive", |b| {
        b.iter(|| {
            let derived =
                derive_chain(black_box(descriptor), Network::Testnet, Chain::Receive, 100)
                    .expect("derivation succeeds");
            black_box(derived);
        });
    });
}

criterion_group!(benches, bench_derive_100_singlesig);
criterion_main!(benches);
