//! Façade smoke tests (US-034): every core crate is reachable through
//! `lifeboat-core`, and the end-to-end descriptor → report pipeline runs entirely
//! through the re-exported API.
//!
//! An integration test is a separate crate that depends only on `lifeboat-core`
//! (plus std) — NOT on the underlying analysis crates. So these `use
//! lifeboat_core::<crate>::…` paths compiling is itself the proof that the façade
//! re-exports the full public surface (AC: "re-exports the stable public API of
//! descriptor-audit, …, error-taxonomy").

use lifeboat_core::descriptor_audit::parse_descriptor;
use lifeboat_core::report_engine::{build_report, ReportInput, SCHEMA_VERSION};

/// A committed, never-mainnet singlesig fixture (PRD §27 anonymization rule).
const WPKH_VALID: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
));

/// A committed 2-of-3 sorted-multisig fixture.
const WSH_2OF3: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt"
));

#[test]
fn descriptor_to_report_pipeline_runs_through_the_facade() {
    let parsed = parse_descriptor(WPKH_VALID.trim()).expect("fixture descriptor parses");
    let input = ReportInput::new(&parsed, "2026-05-29T00:00:00Z").with_app_version("0.1.0");
    let report = build_report(&input);

    // The full §9.1 A–G check set is present and the report is the §19.1 shape.
    assert_eq!(
        report.checks.len(),
        24,
        "all 24 readiness checks are present"
    );
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert!(
        report.survivability.is_none(),
        "singlesig has no survivability"
    );
    // Deterministic JSON serialization is reachable through the façade.
    assert!(report.to_json().contains("\"schema_version\""));
}

#[test]
fn multisig_report_has_survivability_through_the_facade() {
    let parsed = parse_descriptor(WSH_2OF3.trim()).expect("multisig fixture parses");
    let report = build_report(&ReportInput::new(&parsed, "2026-05-29T00:00:00Z"));
    assert_eq!(report.wallet_summary.threshold, Some(2));
    assert_eq!(report.wallet_summary.key_count, 3);
    assert!(
        report.survivability.is_some(),
        "a 2-of-3 multisig carries a §16.6 survivability dimension"
    );
}

#[test]
fn every_core_crate_is_reachable_through_the_facade() {
    // error-taxonomy
    use lifeboat_core::error_taxonomy::{ErrorCode, LifeboatError};
    let err = LifeboatError::new(ErrorCode::InputEmpty);
    assert_eq!(err.code(), ErrorCode::InputEmpty);

    // sensitive-input-detector — clean input is allowed (and never echoed).
    use lifeboat_core::sensitive_input_detector::{detect, DetectorAction};
    assert_eq!(
        detect("just some ordinary prose").action,
        DetectorAction::Allow
    );

    // address-derive — the network type and default count are re-exported.
    use lifeboat_core::address_derive::{Network, DEFAULT_ADDRESS_COUNT};
    let _network: Option<Network> = None;
    assert_eq!(DEFAULT_ADDRESS_COUNT, 10);

    // readiness-score — the pinned scoring-engine version is reachable.
    assert_eq!(
        lifeboat_core::readiness_score::SCORING_ENGINE_VERSION,
        "0.1.0"
    );

    // wallet-imports — the import-size guard constant is reachable.
    assert_eq!(
        lifeboat_core::wallet_imports::MAX_EXPORT_SIZE_BYTES,
        10 * 1024 * 1024
    );

    // qr-psbt — the current BCR PSBT UR type is reachable.
    assert_eq!(lifeboat_core::qr_psbt::PSBT_UR_TYPE, "psbt");

    // miniscript-viz - policy DOT rendering is reachable and redacts keys.
    let dot = lifeboat_core::miniscript_viz::descriptor_to_dot(WSH_2OF3.trim())
        .expect("multisig policy visualizes through the facade");
    assert!(dot.contains("thresh(2 of 3)"));
    assert!(!dot.contains("tpub"));

    // runbook-engine — owner template + page size enums are reachable.
    use lifeboat_core::runbook_engine::{OwnerTemplate, PageSize};
    let _ = (OwnerTemplate::SinglesigBasic, PageSize::A4);
}
