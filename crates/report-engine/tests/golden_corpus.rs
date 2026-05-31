//! US-040 — Golden fixture corpus and snapshot harness.
//!
//! This integration test is the project's permanent guarantee that a readiness
//! report is **deterministic**: the same descriptor + context + `app_version` +
//! `scoring_engine_version` always produce byte-identical JSON (PRD §19 / §27).
//!
//! ## What it does
//!
//! 1. [`corpus`] builds 50+ named [`ReadinessReport`]s from the committed
//!    testnet/signet/regtest descriptor fixtures, covering singlesig, multisig,
//!    Taproot support, every reachable §16.3 critical, the §16.4 warnings, and
//!    the §16.5 cannot-determine cases. `created_at` and `app_version` are pinned
//!    so the output never drifts with the wall clock or a workspace version bump.
//! 2. [`golden_reports_match_committed_fixtures`] writes each report to
//!    `fixtures/reports/<name>.json` when `REGEN_GOLDEN=1`, and otherwise asserts
//!    the freshly-built report is byte-identical to the committed file. This is
//!    the golden corpus.
//! 3. [`report_json_is_byte_identical_across_runs`] builds the whole corpus twice
//!    and asserts the compact `to_json()` (the product's `report-json` output)
//!    matches — the reproducibility test, at `scoring_engine_version` 0.1.0.
//! 4. [`corpus_is_anonymized_never_mainnet`] enforces the §27 anonymization rule:
//!    no report references a mainnet network, xpub, or address.
//! 5. [`corpus_covers_the_required_categories`] proves the corpus spans every
//!    category the story requires.
//! 6. [`corpus_manifest_snapshot`] is the insta snapshot suite: a one-line-per
//!    -fixture overview (status, score, counts, hashes) that surfaces any change
//!    to the whole corpus in a single reviewable diff.
//!
//! Regenerate after a deliberate scoring/format change:
//! ```text
//! REGEN_GOLDEN=1 cargo +1.78.0 test -p report-engine --test golden_corpus
//! INSTA_UPDATE=always cargo +1.78.0 test -p report-engine --test golden_corpus
//! ```
//! then review and commit the diff. See `fixtures/reports/README.md`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use address_derive::{derive_addresses, Network};
use descriptor_audit::{compute_checksum, parse_descriptor, ParsedDescriptor};
use readiness_score::{
    Answer, CriticalCode, DeclaredWalletType, Passphrase, ReadinessStatus, RecoveryChecklist,
    WarningCode,
};
use report_engine::{build_report, ReadinessReport, ReportInput};

/// Pinned report timestamp — fixed so golden output never tracks the clock.
const CREATED_AT: &str = "2024-01-15T00:00:00Z";
/// Pinned application version — fixed so a workspace version bump does not break
/// the corpus (the report stamps and hashes `app_version`).
const APP_VERSION: &str = "0.1.0";

macro_rules! fixture {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/",
            $path
        ))
        .trim()
    };
}

fn parse(contents: &str) -> ParsedDescriptor {
    parse_descriptor(contents).expect("fixture parses")
}

/// Build a report from `input`, always pinning `app_version` so the corpus is
/// stable across workspace version bumps.
fn build(input: ReportInput) -> ReadinessReport {
    build_report(&input.with_app_version(APP_VERSION))
}

/// The first receive address this descriptor derives on `network` (used to feed a
/// *matching* `--known-address`).
fn own_addr(parsed: &ParsedDescriptor, network: Network) -> String {
    derive_addresses(parsed, network, 1)
        .expect("derive")
        .receive_derived
        .first()
        .map(|d| d.address.clone())
        .expect("at least one derived address")
}

/// `wpkh_valid` rewritten to a BIP389 `<0;1>` multipath (receive+change in one
/// descriptor), re-checksummed — the clean path to a `Ready`/`MostlyReady`
/// singlesig (no missing-change-descriptor warning).
fn multipath_singlesig() -> ParsedDescriptor {
    let body = fixture!("descriptors/singlesig/wpkh_valid.txt");
    let no_checksum = body.split('#').next().expect("body");
    let multipath = no_checksum.replace("/0/*", "/<0;1>/*");
    parse(&compute_checksum(&multipath).expect("checksum"))
}

/// `wpkh_valid`'s change branch (`/1/*`) as a standalone descriptor — fed as an
/// explicit change descriptor to exercise the `descriptors.change` report field.
fn wpkh_change() -> ParsedDescriptor {
    let body = fixture!("descriptors/singlesig/wpkh_valid.txt");
    let no_checksum = body.split('#').next().expect("body");
    let change = no_checksum.replace("/0/*", "/1/*");
    parse(&compute_checksum(&change).expect("checksum"))
}

/// `sh_wpkh_valid`'s change branch (`/1/*`).
fn sh_wpkh_change() -> ParsedDescriptor {
    let body = fixture!("descriptors/singlesig/sh_wpkh_valid.txt");
    let no_checksum = body.split('#').next().expect("body");
    let change = no_checksum.replace("/0/*", "/1/*");
    parse(&compute_checksum(&change).expect("checksum"))
}

fn full_yes() -> RecoveryChecklist {
    RecoveryChecklist {
        physical_copies: Some(Answer::Yes),
        signer_locations_known: Some(Answer::Yes),
        signers_tested_recently: Some(Answer::Yes),
        passphrase_documented: Some(Answer::Yes),
        wallet_software_documented: Some(Answer::Yes),
        gap_limit_documented: Some(Answer::Yes),
        birth_height_documented: Some(Answer::Yes),
        heir_instructions_written: Some(Answer::Yes),
        recent_drill: Some(Answer::Yes),
    }
}

/// `full_yes` but the recovery drill was not run recently (one warning back).
fn drill_skipped() -> RecoveryChecklist {
    let mut c = full_yes();
    c.recent_drill = Some(Answer::No);
    c
}

/// A realistic mid-completion checklist: backups/software/gap/birth documented,
/// the rest still open.
fn partial() -> RecoveryChecklist {
    RecoveryChecklist {
        physical_copies: Some(Answer::Yes),
        signer_locations_known: None,
        signers_tested_recently: None,
        passphrase_documented: Some(Answer::Yes),
        wallet_software_documented: Some(Answer::Yes),
        gap_limit_documented: Some(Answer::Yes),
        birth_height_documented: Some(Answer::Yes),
        heir_instructions_written: Some(Answer::No),
        recent_drill: Some(Answer::No),
    }
}

/// Build the full golden corpus: `(stable name, report)` in stable order.
fn corpus() -> Vec<(&'static str, ReadinessReport)> {
    // Base descriptors (all testnet/regtest tpub fixtures — never mainnet).
    let wpkh = parse(fixture!("descriptors/singlesig/wpkh_valid.txt"));
    let pkh = parse(fixture!("descriptors/singlesig/pkh_valid.txt"));
    let sh_wpkh = parse(fixture!("descriptors/singlesig/sh_wpkh_valid.txt"));
    let wpkh_mp = multipath_singlesig();
    let m2 = parse(fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt"));
    let m2_mp = parse(fixture!("descriptors/multisig/multipath_2of3.txt"));
    let m3 = parse(fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt"));
    let dup = parse(fixture!("descriptors/multisig/duplicate_xpub.txt"));
    let tr = parse(fixture!("descriptors/taproot/tr_keypath.txt"));
    let tr_sp = parse(fixture!("descriptors/taproot/tr_scriptpath_multi_a.txt"));
    let change = wpkh_change();
    let sh_change = sh_wpkh_change();

    // Matching / foreign known addresses (derived on Testnet).
    let wpkh_mp_addr = own_addr(&wpkh_mp, Network::Testnet);
    let m2_mp_addr = own_addr(&m2_mp, Network::Testnet);
    let foreign_addr = own_addr(&pkh, Network::Testnet); // never matches wpkh/m2
    let foreign_addr2 = own_addr(&wpkh, Network::Testnet); // never matches m2

    let mut out: Vec<(&'static str, ReadinessReport)> = Vec::new();
    let mut push = |name: &'static str, report: ReadinessReport| out.push((name, report));

    // --- Singlesig basics: networks & cannot-determine -----------------------
    push(
        "singlesig_wpkh_cannot_determine_no_network",
        build(ReportInput::new(&wpkh, CREATED_AT)),
    );
    push(
        "singlesig_wpkh_testnet_bare",
        build(ReportInput::new(&wpkh, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "singlesig_wpkh_signet_bare",
        build(ReportInput::new(&wpkh, CREATED_AT).with_network(Network::Signet)),
    );
    push(
        "singlesig_wpkh_regtest_bare",
        build(ReportInput::new(&wpkh, CREATED_AT).with_network(Network::Regtest)),
    );
    push(
        "singlesig_wpkh_testnet_network_confirmed",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_network_confirmed(true),
        ),
    );
    push(
        "singlesig_pkh_testnet_bare",
        build(ReportInput::new(&pkh, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "singlesig_pkh_cannot_determine_no_network",
        build(ReportInput::new(&pkh, CREATED_AT)),
    );
    push(
        "singlesig_sh_wpkh_testnet_bare",
        build(ReportInput::new(&sh_wpkh, CREATED_AT).with_network(Network::Testnet)),
    );

    // --- Singlesig: checklists, flags, derive count --------------------------
    push(
        "singlesig_wpkh_testnet_partial_checklist",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_checklist(partial()),
        ),
    );
    push(
        "singlesig_wpkh_testnet_full_yes_checklist",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Absent),
        ),
    );
    push(
        "singlesig_wpkh_testnet_emergency_contact_only",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_emergency_contact_named(true),
        ),
    );
    push(
        "singlesig_wpkh_testnet_hardware_signed_only",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_hardware_signed_recently(true),
        ),
    );
    push(
        "singlesig_wpkh_testnet_backup_same_location",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_backup_same_location(true),
        ),
    );
    push(
        "singlesig_wpkh_testnet_derive_count_1",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_derive_count(1),
        ),
    );
    push(
        "singlesig_wpkh_testnet_derive_count_10",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_derive_count(10),
        ),
    );

    // --- Singlesig: explicit change descriptor -------------------------------
    push(
        "singlesig_wpkh_with_explicit_change_descriptor",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_change_descriptor(&change),
        ),
    );
    push(
        "singlesig_sh_wpkh_with_explicit_change_descriptor",
        build(
            ReportInput::new(&sh_wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_change_descriptor(&sh_change),
        ),
    );

    // --- Singlesig multipath: bare, cannot-determine, ready, mostly-ready ----
    push(
        "singlesig_multipath_cannot_determine_no_network",
        build(ReportInput::new(&wpkh_mp, CREATED_AT)),
    );
    push(
        "singlesig_multipath_testnet_bare",
        build(ReportInput::new(&wpkh_mp, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "singlesig_multipath_ready_full",
        build(
            ReportInput::new(&wpkh_mp, CREATED_AT)
                .with_network(Network::Testnet)
                .with_known_address(&wpkh_mp_addr)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Absent)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );
    push(
        "singlesig_multipath_ready_documented_passphrase",
        build(
            ReportInput::new(&wpkh_mp, CREATED_AT)
                .with_network(Network::Testnet)
                .with_known_address(&wpkh_mp_addr)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Documented)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );
    push(
        "singlesig_multipath_ready_drill_skipped",
        build(
            ReportInput::new(&wpkh_mp, CREATED_AT)
                .with_network(Network::Testnet)
                .with_known_address(&wpkh_mp_addr)
                .with_checklist(drill_skipped())
                .with_passphrase(Passphrase::Absent)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );
    push(
        "singlesig_multipath_mostly_ready_no_address",
        build(
            ReportInput::new(&wpkh_mp, CREATED_AT)
                .with_network(Network::Testnet)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Absent)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );

    // --- Multisig 2-of-3 -----------------------------------------------------
    push(
        "multisig_2of3_cannot_determine_no_network",
        build(ReportInput::new(&m2, CREATED_AT)),
    );
    push(
        "multisig_2of3_testnet_bare",
        build(ReportInput::new(&m2, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "multisig_2of3_signet_bare",
        build(ReportInput::new(&m2, CREATED_AT).with_network(Network::Signet)),
    );
    push(
        "multisig_2of3_declared_full_yes",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(full_yes()),
        ),
    );
    push(
        "multisig_2of3_partial_checklist",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(partial()),
        ),
    );
    push(
        "multisig_2of3_passphrase_documented",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Documented),
        ),
    );
    push(
        "multisig_2of3_network_confirmed_declared",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_network_confirmed(true)
                .with_declared_wallet_type(DeclaredWalletType::Multisig),
        ),
    );

    // --- Multisig 2-of-3 multipath ------------------------------------------
    push(
        "multisig_2of3_multipath_cannot_determine",
        build(ReportInput::new(&m2_mp, CREATED_AT)),
    );
    push(
        "multisig_2of3_multipath_testnet_bare",
        build(ReportInput::new(&m2_mp, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "multisig_2of3_multipath_ready_full",
        build(
            ReportInput::new(&m2_mp, CREATED_AT)
                .with_network(Network::Testnet)
                .with_known_address(&m2_mp_addr)
                .with_checklist(full_yes())
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_passphrase(Passphrase::Absent)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );
    push(
        "multisig_2of3_multipath_mostly_ready_no_address",
        build(
            ReportInput::new(&m2_mp, CREATED_AT)
                .with_network(Network::Testnet)
                .with_checklist(full_yes())
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_passphrase(Passphrase::Absent)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );

    // --- Multisig 3-of-5 -----------------------------------------------------
    push(
        "multisig_3of5_cannot_determine_no_network",
        build(ReportInput::new(&m3, CREATED_AT)),
    );
    push(
        "multisig_3of5_testnet_bare",
        build(ReportInput::new(&m3, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "multisig_3of5_declared_full_yes",
        build(
            ReportInput::new(&m3, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(full_yes()),
        ),
    );
    push(
        "multisig_3of5_same_location_backup",
        build(
            ReportInput::new(&m3, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(full_yes())
                .with_backup_same_location(true),
        ),
    );
    push(
        "multisig_3of5_partial_checklist",
        build(
            ReportInput::new(&m3, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(partial()),
        ),
    );

    // --- Taproot preview -----------------------------------------------------
    push(
        "taproot_keypath_cannot_determine_no_network",
        build(ReportInput::new(&tr, CREATED_AT)),
    );
    push(
        "taproot_keypath_testnet_bare",
        build(ReportInput::new(&tr, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "taproot_keypath_signet_bare",
        build(ReportInput::new(&tr, CREATED_AT).with_network(Network::Signet)),
    );
    push(
        "taproot_keypath_partial_checklist",
        build(
            ReportInput::new(&tr, CREATED_AT)
                .with_network(Network::Testnet)
                .with_checklist(partial()),
        ),
    );
    push(
        "taproot_keypath_full_context",
        build(
            ReportInput::new(&tr, CREATED_AT)
                .with_network(Network::Testnet)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Absent)
                .with_emergency_contact_named(true)
                .with_hardware_signed_recently(true),
        ),
    );
    push(
        "taproot_scriptpath_multi_a_testnet_bare",
        build(ReportInput::new(&tr_sp, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "taproot_scriptpath_multi_a_cannot_determine",
        build(ReportInput::new(&tr_sp, CREATED_AT)),
    );

    // --- Critical failures (reachable from parseable descriptors) ------------
    push(
        "critical_duplicate_xpub_testnet",
        build(ReportInput::new(&dup, CREATED_AT).with_network(Network::Testnet)),
    );
    push(
        "critical_duplicate_xpub_full_context",
        build(
            ReportInput::new(&dup, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Absent),
        ),
    );
    push(
        "critical_wallet_type_mismatch_singlesig_declared_multisig",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig),
        ),
    );
    push(
        "multisig_2of3_declared_singlesig",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Singlesig),
        ),
    );
    push(
        "critical_passphrase_undocumented_singlesig",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_passphrase(Passphrase::Undocumented),
        ),
    );
    push(
        "critical_passphrase_undocumented_multisig",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_checklist(full_yes())
                .with_passphrase(Passphrase::Undocumented),
        ),
    );
    push(
        "critical_change_desc_required_singlesig",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_change_descriptor_required(true),
        ),
    );
    push(
        "critical_change_desc_required_multisig",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_change_descriptor_required(true),
        ),
    );
    push(
        "critical_address_mismatch_singlesig",
        build(
            ReportInput::new(&wpkh, CREATED_AT)
                .with_network(Network::Testnet)
                .with_known_address(&foreign_addr),
        ),
    );
    push(
        "critical_address_mismatch_multisig",
        build(
            ReportInput::new(&m2, CREATED_AT)
                .with_network(Network::Testnet)
                .with_declared_wallet_type(DeclaredWalletType::Multisig)
                .with_known_address(&foreign_addr2),
        ),
    );

    out
}

/// Absolute path to `fixtures/reports/`.
fn reports_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/reports")
}

#[test]
fn golden_reports_match_committed_fixtures() {
    let regen = std::env::var_os("REGEN_GOLDEN").is_some();
    let dir = reports_dir();
    if regen {
        std::fs::create_dir_all(&dir).expect("create fixtures/reports");
    }
    for (name, report) in corpus() {
        // Each golden file is the pretty JSON plus a trailing newline (POSIX).
        let actual = format!("{}\n", report.to_json_pretty());
        let path = dir.join(format!("{name}.json"));
        if regen {
            std::fs::write(&path, &actual).expect("write golden");
        } else {
            let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
                panic!("missing golden fixture {path:?}; run with REGEN_GOLDEN=1 to create it")
            });
            assert_eq!(
                actual, expected,
                "golden drift for {name}: rebuild differs from {path:?} (REGEN_GOLDEN=1 to update)"
            );
        }
    }
}

#[test]
fn report_json_is_byte_identical_across_runs() {
    // Two fully-independent builds of the whole corpus must agree byte-for-byte,
    // every report at scoring-engine 0.1.0 (PRD §19/§27).
    let a = corpus();
    let b = corpus();
    assert_eq!(a.len(), b.len());
    for ((na, ra), (nb, rb)) in a.iter().zip(b.iter()) {
        assert_eq!(na, nb, "corpus order is not stable");
        assert_eq!(
            ra.to_json(),
            rb.to_json(),
            "report-json is not reproducible for {na}"
        );
        assert_eq!(
            ra.scoring_engine_version, "0.1.0",
            "{na} is not scoring-engine 0.1.0"
        );
        assert_eq!(ra.app_version, APP_VERSION, "{na} app_version drifted");
    }
}

#[test]
fn corpus_has_unique_names_and_enough_fixtures() {
    let c = corpus();
    assert!(
        c.len() >= 50,
        "corpus has {} fixtures, the story requires >= 50",
        c.len()
    );
    let names: BTreeSet<&str> = c.iter().map(|(n, _)| *n).collect();
    assert_eq!(names.len(), c.len(), "duplicate fixture name in the corpus");
}

#[test]
fn corpus_is_anonymized_never_mainnet() {
    // PRD §27 / the US-040 anonymization rule: the corpus must be built only from
    // testnet/signet/regtest material — no mainnet network, xpub, or address.
    for (name, report) in corpus() {
        if let Some(net) = &report.network {
            assert!(
                matches!(net.as_str(), "testnet" | "signet" | "regtest"),
                "{name}: mainnet network {net:?} in the corpus"
            );
        }
        for key in &report.keys {
            if let Some(xpub) = &key.xpub {
                assert!(
                    xpub.starts_with("tpub"),
                    "{name}: non-testnet extended key {xpub:.8} in the corpus"
                );
            }
        }
        let addrs = report
            .addresses
            .receive_derived
            .iter()
            .chain(report.addresses.change_derived.iter());
        for d in addrs {
            let a = &d.address;
            assert!(
                !a.starts_with("bc1") && !a.starts_with('1') && !a.starts_with('3'),
                "{name}: mainnet-looking address {a:?} in the corpus"
            );
        }
    }
}

#[test]
fn corpus_covers_the_required_categories() {
    let c = corpus();
    // These scoring enums derive `PartialEq`/`Eq` but not `Ord`, so collect into
    // `Vec`s and test membership with `contains` rather than a `BTreeSet`.
    let mut statuses: Vec<ReadinessStatus> = Vec::new();
    let mut criticals: Vec<CriticalCode> = Vec::new();
    let mut warnings: Vec<WarningCode> = Vec::new();
    let (mut singlesig, mut multisig, mut taproot) = (false, false, false);
    let (mut has_surviv, mut no_surviv, mut has_change) = (false, false, false);

    for (_, r) in &c {
        if !statuses.contains(&r.score.status) {
            statuses.push(r.score.status);
        }
        for ci in &r.critical_issues {
            if !criticals.contains(&ci.code) {
                criticals.push(ci.code);
            }
        }
        for w in &r.warnings {
            if !warnings.contains(&w.code) {
                warnings.push(w.code);
            }
        }
        match r.wallet_summary.wallet_type.as_deref() {
            Some("singlesig") => singlesig = true,
            Some("multisig") => multisig = true,
            _ => {}
        }
        if r.wallet_summary.uses_taproot {
            taproot = true;
        }
        if r.survivability.is_some() {
            has_surviv = true;
        } else {
            no_surviv = true;
        }
        if r.descriptors.change.is_some() {
            has_change = true;
        }
    }

    // All five §16.2 statuses appear.
    for s in [
        ReadinessStatus::Ready,
        ReadinessStatus::MostlyReady,
        ReadinessStatus::NeedsAttention,
        ReadinessStatus::NotReady,
        ReadinessStatus::CannotDetermine,
    ] {
        assert!(statuses.contains(&s), "no fixture has status {s:?}");
    }

    // Wallet kinds.
    assert!(singlesig, "no singlesig fixture");
    assert!(multisig, "no multisig fixture");
    assert!(taproot, "no Taproot fixture");
    assert!(
        has_surviv && no_surviv,
        "survivability not covered both ways"
    );
    assert!(has_change, "no explicit-change-descriptor fixture");

    // Every reachable §16.3 critical (parse-failure criticals are the CLI's
    // compact-error path — see fixtures/reports/README.md).
    for cc in [
        CriticalCode::DuplicateXpub,
        CriticalCode::WalletTypeMismatch,
        CriticalCode::PassphraseUndocumented,
        CriticalCode::ChangeDescRequiredMissing,
        CriticalCode::AddressMismatch,
    ] {
        assert!(criticals.contains(&cc), "no fixture raises critical {cc:?}");
    }

    // A representative spread of active §16.4 warnings.
    for wc in [
        WarningCode::NoChangeDesc,
        WarningCode::NoKnownAddress,
        WarningCode::SameLocationBackup,
        WarningCode::NoRecentDrill,
        WarningCode::NoMultipath,
    ] {
        assert!(warnings.contains(&wc), "no fixture raises warning {wc:?}");
    }
}

#[test]
fn corpus_manifest_snapshot() {
    // The insta snapshot suite: one reviewable line per fixture. Any change to a
    // report's bytes shows up here as a `report_hash` diff, and the status/score
    // columns make the corpus's category coverage visible at a glance.
    let mut manifest = String::new();
    for (name, r) in corpus() {
        writeln!(
            manifest,
            "{name}\n    status={} numeric={} criticals={} warnings={} survivability={}\n    input_hash={}\n    report_hash={}",
            r.score.status.headline(),
            r.score.numeric,
            r.critical_issues.len(),
            r.warnings.len(),
            r.survivability.is_some(),
            r.input_hash,
            r.report_hash,
        )
        .expect("write manifest");
    }
    insta::assert_snapshot!("corpus_manifest", manifest);
}
