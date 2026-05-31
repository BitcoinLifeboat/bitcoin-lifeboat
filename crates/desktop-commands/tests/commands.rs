//! Integration tests for the §21.3 desktop command layer (US-042).
//!
//! Each command is exercised with fixture inputs, and every "bad input" path is
//! asserted to surface a typed [`LifeboatError`] with the expected stable code.
//! The known-answer descriptors and addresses are the published BIP-49/84 vectors
//! for the documented "abandon … about" test mnemonic (never a real wallet, §27);
//! the secret-detection cases use that same documented mnemonic and the repo's
//! `contains_xprv` fixture — no real secret is used anywhere.

use desktop_commands::{
    app_info, audit_descriptor, check_external_link, clear_all_data, compare_address,
    compute_checksum, derive_addresses, detect_sensitive_input, external_link_allowlist,
    generate_report, generate_runbook, load_settings, parse_wallet_export,
    render_liana_recovery_tree, render_liana_recovery_tree_at_block, render_miniscript_policy_dot,
    save_export, save_settings, validate_checksum, AddressCompareInput, AddressDeriveInput,
    ChainArg, ChecksumValidationStatus, DescriptorAuditInput, DetectedSecret, ErrorCode,
    LianaRecoveryCountdown, LianaRecoveryPathKind, NetworkArg, RedactionMode, RelativeTimelockUnit,
    ReportFormat, ReportGenerationInput, RunbookFormat, RunbookGenerationInput, Settings, Severity,
    TextScaleSetting, ThemeSetting,
};

// Account-level extended public keys (m/49h|84h/0h/0h) for the documented BIP39
// test mnemonic "abandon abandon … about" — the same vectors `address-derive`
// verifies against the published BIP49/84 address vectors. Mainnet `xpub`s, so the
// network is unambiguous (no override needed). Never a real wallet (§27).
const BIP49_XPUB: &str = "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7";
const BIP84_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";

/// BIP84 §test-vector receive address 0 for account 0 of "abandon … about".
const BIP84_RECEIVE_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
/// BIP84 §test-vector change address 0.
const BIP84_CHANGE_0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

/// The documented BIP39 test mnemonic. A published test vector — never a real seed.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A testnet (`tpub`) singlesig descriptor: its network is ambiguous (a `tpub` is
/// shared by testnet/signet/regtest), so it exercises the override / error paths.
const TPUB_WPKH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
));

/// A 2-of-3 multisig descriptor used by the US-088 policy-tree command.
const WSH_2_OF_3: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt"
));

/// A Liana-style timelock descriptor used by the US-088 policy-tree command.
const LIANA_BASIC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/timelock/liana_basic.txt"
));

/// A descriptor whose key is an extended **private** key — must be blocked by the
/// secret screen before any parsing (§13.5).
const CONTAINS_XPRV: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/descriptors/invalid/contains_xprv.txt"
));

// A fixed boundary timestamp + version, so reports are byte-deterministic in tests.
const CREATED_AT: &str = "2025-01-01T00:00:00Z";
const APP_VERSION: &str = "0.1.0-test";

fn bip84_wpkh() -> String {
    format!("wpkh({BIP84_XPUB}/<0;1>/*)")
}

fn bip49_sh_wpkh() -> String {
    format!("sh(wpkh({BIP49_XPUB}/0/*))")
}

// --- audit_descriptor -------------------------------------------------------

#[test]
fn audit_descriptor_builds_a_serializable_report() {
    let input = DescriptorAuditInput {
        descriptor: bip84_wpkh(),
        network: None,
        known_address: None,
        derive_count: None,
    };
    let report =
        audit_descriptor(input, CREATED_AT, APP_VERSION).expect("audits a watch-only desc");

    // Output is serializable to JSON (§21.3) with the §19.1 shape we depend on.
    let json = serde_json::to_string(&report).expect("report serializes");
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value.is_object());
    assert_eq!(value["app_version"], APP_VERSION);
    assert_eq!(value["wallet_summary"]["key_count"], 1);
    assert!(
        value["network"].is_string(),
        "mainnet xpub => inferred network"
    );
    assert!(value["report_hash"].is_string());
    assert!(value["score"]["numeric"].is_number());
}

#[test]
fn audit_descriptor_is_deterministic_for_fixed_inputs() {
    let mk = || DescriptorAuditInput {
        descriptor: bip84_wpkh(),
        network: None,
        known_address: None,
        derive_count: Some(5),
    };
    let a = audit_descriptor(mk(), CREATED_AT, APP_VERSION).unwrap();
    let b = audit_descriptor(mk(), CREATED_AT, APP_VERSION).unwrap();
    // Same descriptor + created_at + app_version => byte-identical report (§27).
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn audit_descriptor_rejects_empty_input() {
    let input = DescriptorAuditInput {
        descriptor: "   ".to_owned(),
        network: None,
        known_address: None,
        derive_count: None,
    };
    let err = audit_descriptor(input, CREATED_AT, APP_VERSION).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputEmpty);
}

#[test]
fn audit_descriptor_rejects_unparseable_input_with_typed_error() {
    let input = DescriptorAuditInput {
        descriptor: "wpkh(definitely-not-a-key)".to_owned(),
        network: None,
        known_address: None,
        derive_count: None,
    };
    let err = audit_descriptor(input, CREATED_AT, APP_VERSION).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ParseFailed);
}

#[test]
fn audit_descriptor_blocks_an_xprv_before_parsing() {
    // The xprv is caught by the secret screen (§13.5) before parse_descriptor runs.
    let input = DescriptorAuditInput {
        descriptor: CONTAINS_XPRV.trim().to_owned(),
        network: None,
        known_address: None,
        derive_count: None,
    };
    let err = audit_descriptor(input, CREATED_AT, APP_VERSION).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
    // The error must never echo the offending descriptor / key material — it
    // carries only the stable, leak-free catalog copy for E-SECRET-004 (no
    // context, no chained source).
    let json = serde_json::to_string(&err).unwrap();
    assert!(
        !json.contains(CONTAINS_XPRV.trim()),
        "serialized error leaked the descriptor: {json}"
    );
}

#[test]
fn audit_descriptor_blocks_a_pasted_mnemonic() {
    let input = DescriptorAuditInput {
        descriptor: TEST_MNEMONIC.to_owned(),
        network: None,
        known_address: None,
        derive_count: None,
    };
    let err = audit_descriptor(input, CREATED_AT, APP_VERSION).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Bip39Detected);
    assert_eq!(err.severity(), Severity::Security);
}

// --- derive_addresses -------------------------------------------------------

#[test]
fn derive_addresses_matches_published_vectors() {
    let list = derive_addresses(AddressDeriveInput {
        descriptor: bip84_wpkh(),
        network: None,
        count: 2,
        chain: ChainArg::Both,
    })
    .expect("derives");

    assert_eq!(list.network, "bitcoin");
    // count=2 over a multipath descriptor => 2 receive then 2 change.
    assert_eq!(list.addresses.len(), 4);
    assert_eq!(list.addresses[0].address, BIP84_RECEIVE_0);
    assert_eq!(list.addresses[0].chain, desktop_commands::Chain::Receive);
    assert_eq!(list.addresses[2].address, BIP84_CHANGE_0);
    assert_eq!(list.addresses[2].chain, desktop_commands::Chain::Change);

    // Serializes to the §17.10.2 JSON shape.
    let value: serde_json::Value = serde_json::to_value(&list).unwrap();
    assert_eq!(value["network"], "bitcoin");
    assert!(value["addresses"].is_array());
}

#[test]
fn derive_addresses_honors_the_chain_filter() {
    let list = derive_addresses(AddressDeriveInput {
        descriptor: bip84_wpkh(),
        network: None,
        count: 3,
        chain: ChainArg::Receive,
    })
    .unwrap();
    assert_eq!(list.addresses.len(), 3);
    assert!(list
        .addresses
        .iter()
        .all(|a| a.chain == desktop_commands::Chain::Receive));
}

#[test]
fn derive_addresses_supports_sh_wpkh_single_path() {
    let list = derive_addresses(AddressDeriveInput {
        descriptor: bip49_sh_wpkh(),
        network: None,
        count: 1,
        chain: ChainArg::Both,
    })
    .expect("derives a sh(wpkh) descriptor");
    assert_eq!(list.network, "bitcoin");
    // Single-path `/0/*` => receive only; published BIP49 vector.
    assert_eq!(list.addresses.len(), 1);
    assert_eq!(
        list.addresses[0].address,
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
    );
    assert_eq!(list.addresses[0].chain, desktop_commands::Chain::Receive);
}

#[test]
fn derive_addresses_refuses_an_ambiguous_network() {
    // A tpub with no override: the network cannot be inferred (§16.5).
    let err = derive_addresses(AddressDeriveInput {
        descriptor: TPUB_WPKH.trim().to_owned(),
        network: None,
        count: 1,
        chain: ChainArg::Both,
    })
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
}

#[test]
fn derive_addresses_accepts_an_explicit_network_override() {
    let list = derive_addresses(AddressDeriveInput {
        descriptor: TPUB_WPKH.trim().to_owned(),
        network: Some(NetworkArg::Testnet),
        count: 1,
        chain: ChainArg::Both,
    })
    .expect("derives with explicit network");
    assert_eq!(list.network, "testnet");
    // The fixture is a single-path (`/0/*`) descriptor: receive only, no change.
    assert_eq!(list.addresses.len(), 1);
    assert_eq!(list.addresses[0].chain, desktop_commands::Chain::Receive);
}

// --- compare_address --------------------------------------------------------

#[test]
fn compare_address_finds_a_derived_address() {
    let result = compare_address(AddressCompareInput {
        descriptor: bip84_wpkh(),
        address: BIP84_RECEIVE_0.to_owned(),
        network: None,
        search_range: 10,
    })
    .expect("compares");
    assert!(result.matched);
    let at = result.matched_at.expect("a hit reports its location");
    assert_eq!(at.index, 0);
    assert_eq!(at.chain, desktop_commands::Chain::Receive);
}

#[test]
fn compare_address_reports_a_miss_as_a_successful_result() {
    // A valid mainnet address that does not belong to this descriptor.
    let result = compare_address(AddressCompareInput {
        descriptor: bip84_wpkh(),
        address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned(),
        network: None,
        search_range: 5,
    })
    .expect("a miss is not an error");
    assert!(!result.matched);
    assert!(result.matched_at.is_none());
}

#[test]
fn compare_address_rejects_a_malformed_address_with_a_typed_error() {
    let err = compare_address(AddressCompareInput {
        descriptor: bip84_wpkh(),
        address: "not-a-bitcoin-address".to_owned(),
        network: None,
        search_range: 5,
    })
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
}

// --- detect_sensitive_input -------------------------------------------------

#[test]
fn detect_sensitive_input_blocks_a_mnemonic_without_leaking_it() {
    let report = detect_sensitive_input(TEST_MNEMONIC.to_owned()).expect("infallible");
    assert!(report.is_blocked());
    assert!(report
        .findings
        .iter()
        .any(|(secret, _)| matches!(secret, DetectedSecret::Bip39 { .. })));

    // The report crosses back to JS — it must carry no secret content (§13.5.8).
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        !json.contains("abandon"),
        "detector report leaked the mnemonic: {json}"
    );
}

#[test]
fn detect_sensitive_input_allows_clean_text() {
    let report =
        detect_sensitive_input("just some ordinary notes about my recovery plan".to_owned())
            .expect("infallible");
    assert!(report.is_allowed());
    assert!(report.findings.is_empty());
}

// --- validate_checksum ------------------------------------------------------

#[test]
fn validate_checksum_reports_present_missing_and_invalid() {
    let no_checksum = bip84_wpkh();

    // Missing.
    let missing = validate_checksum(no_checksum.clone()).unwrap();
    assert_eq!(missing.status, ChecksumValidationStatus::Missing);
    assert!(!missing.valid);

    // Valid: compute a checksum, then validate it.
    let with_checksum = compute_checksum(no_checksum).unwrap();
    let valid = validate_checksum(with_checksum.clone()).unwrap();
    assert_eq!(valid.status, ChecksumValidationStatus::Valid);
    assert!(valid.valid);

    // Invalid: corrupt the final checksum character.
    let mut chars: Vec<char> = with_checksum.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
    let corrupted: String = chars.into_iter().collect();
    let invalid = validate_checksum(corrupted).unwrap();
    assert_eq!(invalid.status, ChecksumValidationStatus::Invalid);
    assert!(!invalid.valid);
}

#[test]
fn validate_checksum_rejects_empty_input() {
    let err = validate_checksum(String::new()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputEmpty);
}

// --- compute_checksum -------------------------------------------------------

#[test]
fn compute_checksum_appends_an_eight_char_checksum_and_is_idempotent() {
    let once = compute_checksum(bip84_wpkh()).expect("computes");
    let suffix = once.rsplit_once('#').expect("has a #checksum").1;
    assert_eq!(suffix.len(), 8);

    // Idempotent: recomputing over an already-checksummed descriptor is stable.
    let twice = compute_checksum(once.clone()).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn compute_checksum_blocks_an_xprv_before_echoing_it() {
    // `compute` echoes the descriptor back, so an xprv must be refused first.
    let err = compute_checksum(CONTAINS_XPRV.trim().to_owned()).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
}

#[test]
fn compute_checksum_rejects_empty_input() {
    let err = compute_checksum("   ".to_owned()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputEmpty);
}

// --- render_miniscript_policy_dot ------------------------------------------

#[test]
fn render_miniscript_policy_dot_returns_redacted_dot_for_multisig_and_liana() {
    let multisig =
        render_miniscript_policy_dot(WSH_2_OF_3.trim().to_owned()).expect("renders multisig DOT");
    assert!(multisig.starts_with("digraph miniscript_policy {\n"));
    assert!(multisig.contains("label=\"thresh(2 of 3)\""));
    assert_eq!(multisig.matches("label=\"key ").count(), 3);
    assert!(!multisig.contains("tpub"));

    let liana =
        render_miniscript_policy_dot(LIANA_BASIC.trim().to_owned()).expect("renders Liana DOT");
    assert!(liana.contains("label=\"older(65535)\""));
    assert!(liana.contains("label=\"thresh(2 of 2)\""));
    assert_eq!(liana.matches("label=\"key ").count(), 2);
    assert!(!liana.contains("tpub"));
}

#[test]
fn render_miniscript_policy_dot_screens_secrets_before_rendering() {
    let err = render_miniscript_policy_dot(CONTAINS_XPRV.trim().to_owned()).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
}

#[test]
fn render_miniscript_policy_dot_rejects_empty_input() {
    let err = render_miniscript_policy_dot("   ".to_owned()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputEmpty);
}

// --- render_liana_recovery_tree --------------------------------------------

#[test]
fn render_liana_recovery_tree_returns_public_safe_paths_and_dot() {
    let tree =
        render_liana_recovery_tree(LIANA_BASIC.trim().to_owned()).expect("renders Liana tree");

    assert!(tree.dot.starts_with("digraph liana_recovery_tree {\n"));
    assert!(tree.dot.contains("Primary path\\n1 key\\navailable now"));
    assert!(tree
        .dot
        .contains("Recovery path 1\\n1 key\\nafter 65,535 blocks (~455 days)"));
    assert!(!tree.dot.contains("tpub"));

    assert_eq!(tree.paths.len(), 2);
    assert_eq!(tree.paths[0].kind, LianaRecoveryPathKind::Primary);
    assert_eq!(tree.paths[0].key_count, 1);
    assert!(tree.paths[0].relative_timelocks.is_empty());

    let recovery = &tree.paths[1];
    assert_eq!(recovery.kind, LianaRecoveryPathKind::Recovery);
    assert_eq!(recovery.label, "Recovery path 1");
    assert_eq!(recovery.key_count, 1);
    assert_eq!(recovery.relative_timelocks.len(), 1);
    assert_eq!(
        recovery.relative_timelocks[0].unit,
        RelativeTimelockUnit::Blocks
    );
    assert_eq!(recovery.relative_timelocks[0].value, 65_535);
    assert_eq!(recovery.relative_timelocks[0].estimated_days, 455);
    assert_eq!(recovery.countdown, None);
}

#[test]
fn render_liana_recovery_tree_at_block_returns_countdown() {
    let tree = render_liana_recovery_tree_at_block(LIANA_BASIC.trim().to_owned(), Some(840_000))
        .expect("renders Liana tree with countdown");

    assert_eq!(
        tree.paths[1].countdown,
        Some(LianaRecoveryCountdown {
            current_block_height: 840_000,
            active_in_blocks: 65_535,
            active_at_block: 905_535,
        })
    );
}

#[test]
fn render_liana_recovery_tree_screens_secrets_before_rendering() {
    let err = render_liana_recovery_tree(CONTAINS_XPRV.trim().to_owned()).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
}

#[test]
fn render_liana_recovery_tree_rejects_empty_input() {
    let err = render_liana_recovery_tree("   ".to_owned()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputEmpty);
}

// ===========================================================================
// US-043 — report / runbook / import / save / link / app-info (§21.3)
// ===========================================================================

/// A repo-root `fixtures/<rel>` path (these commands read a real file at runtime,
/// so they need a path, not an embed).
fn fixture_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel)
}

/// A unique scratch file path under the OS temp dir, cleaned up on drop. The
/// workspace deliberately avoids the `tempfile` crate (it would change the
/// 1.78-pinned dependency tree), so this is a tiny hand-rolled stand-in.
struct ScratchFile {
    path: std::path::PathBuf,
}

impl ScratchFile {
    fn new(name: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("lifeboat-us043-{}-{n}-{name}", std::process::id()));
        Self { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// --- generate_report --------------------------------------------------------

#[test]
fn generate_report_renders_each_format() {
    let input = || ReportGenerationInput {
        descriptor: bip84_wpkh(),
        network: None,
        known_address: None,
        derive_count: None,
        redaction: RedactionMode::PublicSafe,
    };

    let json = generate_report(input(), ReportFormat::Json, CREATED_AT, APP_VERSION).expect("json");
    assert_eq!(json.format, ReportFormat::Json);
    assert_eq!(json.mime_type, "application/json");
    assert!(json.suggested_filename.ends_with("public-safe.json"));
    // The content is the canonical §19.1 JSON.
    let value: serde_json::Value = serde_json::from_str(&json.content).expect("valid JSON");
    assert_eq!(value["schema_version"], "0.1.0");

    let pretty = generate_report(input(), ReportFormat::JsonPretty, CREATED_AT, APP_VERSION)
        .expect("pretty");
    assert!(pretty.content.contains('\n')); // pretty-printed spans multiple lines
                                            // Pretty and compact serialize the same report, so they parse equal.
    let pretty_value: serde_json::Value =
        serde_json::from_str(&pretty.content).expect("valid JSON");
    assert_eq!(pretty_value, value);

    let md = generate_report(input(), ReportFormat::Markdown, CREATED_AT, APP_VERSION).expect("md");
    assert_eq!(md.mime_type, "text/markdown");
    assert!(md.suggested_filename.ends_with("public-safe.md"));
    assert!(md.content.starts_with("# Bitcoin Lifeboat"));
}

#[test]
fn generate_report_applies_redaction() {
    let make = |redaction| ReportGenerationInput {
        descriptor: bip84_wpkh(),
        network: None,
        known_address: None,
        derive_count: None,
        redaction,
    };

    let public = generate_report(
        make(RedactionMode::PublicSafe),
        ReportFormat::Json,
        CREATED_AT,
        APP_VERSION,
    )
    .expect("public");
    let private = generate_report(
        make(RedactionMode::Private),
        ReportFormat::Json,
        CREATED_AT,
        APP_VERSION,
    )
    .expect("private");

    // Public-safe drops the full xpub and redacts the descriptor, so the two
    // exports differ, and the private one carries the full xpub.
    assert_ne!(public.content, private.content);
    assert!(private.content.contains(BIP84_XPUB));
    assert!(!public.content.contains(BIP84_XPUB));
    assert!(private.suggested_filename.ends_with("private.json"));
}

#[test]
fn generate_report_is_deterministic_for_fixed_inputs() {
    let make = || ReportGenerationInput {
        descriptor: bip84_wpkh(),
        network: None,
        known_address: None,
        derive_count: None,
        redaction: RedactionMode::PublicSafe,
    };
    let a = generate_report(make(), ReportFormat::Markdown, CREATED_AT, APP_VERSION).unwrap();
    let b = generate_report(make(), ReportFormat::Markdown, CREATED_AT, APP_VERSION).unwrap();
    assert_eq!(a.content, b.content);
    assert_eq!(a.suggested_filename, b.suggested_filename);
}

#[test]
fn generate_report_blocks_an_xprv_before_parsing() {
    let input = ReportGenerationInput {
        descriptor: CONTAINS_XPRV.trim().to_owned(),
        network: None,
        known_address: None,
        derive_count: None,
        redaction: RedactionMode::PublicSafe,
    };
    let err = generate_report(input, ReportFormat::Json, CREATED_AT, APP_VERSION).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
}

#[test]
fn generate_report_rejects_empty_input() {
    let input = ReportGenerationInput {
        descriptor: "   ".to_owned(),
        network: None,
        known_address: None,
        derive_count: None,
        redaction: RedactionMode::PublicSafe,
    };
    let err = generate_report(input, ReportFormat::Json, CREATED_AT, APP_VERSION).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputEmpty);
}

// --- generate_runbook -------------------------------------------------------

#[test]
fn generate_runbook_renders_a_pdf() {
    let input = RunbookGenerationInput {
        template: "singlesig-basic".to_owned(),
        descriptor: None,
        redaction: RedactionMode::PublicSafe,
        format: RunbookFormat::Pdf,
    };
    let artifact = generate_runbook(input, APP_VERSION).expect("pdf runbook");
    assert_eq!(artifact.format, RunbookFormat::Pdf);
    assert_eq!(artifact.mime_type, "application/pdf");
    assert_eq!(artifact.template, "singlesig-basic");
    assert!(artifact.suggested_filename.ends_with("public-safe.pdf"));
    // A PDF (rendered by the pure-Rust backend — no Typst binary needed) starts
    // with the `%PDF` magic.
    assert!(artifact.content.starts_with(b"%PDF"), "content is a PDF");
}

#[test]
fn generate_runbook_renders_markdown() {
    let input = RunbookGenerationInput {
        template: "heir-multisig-2of3".to_owned(),
        descriptor: None,
        redaction: RedactionMode::PublicSafe,
        format: RunbookFormat::Markdown,
    };
    let artifact = generate_runbook(input, APP_VERSION).expect("md runbook");
    assert_eq!(artifact.mime_type, "text/markdown");
    let text = String::from_utf8(artifact.content).expect("utf-8 markdown");
    assert!(text.starts_with('#'));
}

#[test]
fn generate_runbook_prefills_from_a_descriptor() {
    let blank = generate_runbook(
        RunbookGenerationInput {
            template: "singlesig-basic".to_owned(),
            descriptor: None,
            redaction: RedactionMode::Private,
            format: RunbookFormat::Markdown,
        },
        APP_VERSION,
    )
    .unwrap();
    let filled = generate_runbook(
        RunbookGenerationInput {
            template: "singlesig-basic".to_owned(),
            descriptor: Some(bip84_wpkh()),
            redaction: RedactionMode::Private,
            format: RunbookFormat::Markdown,
        },
        APP_VERSION,
    )
    .unwrap();
    // Pre-filling injects the descriptor (shown in private mode), so the rendered
    // runbook differs from the blank template.
    assert_ne!(blank.content, filled.content);
}

#[test]
fn generate_runbook_rejects_an_unknown_template() {
    let input = RunbookGenerationInput {
        template: "no-such-template".to_owned(),
        descriptor: None,
        redaction: RedactionMode::PublicSafe,
        format: RunbookFormat::Pdf,
    };
    let err = generate_runbook(input, APP_VERSION).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
}

#[test]
fn generate_runbook_blocks_an_xprv_descriptor() {
    let input = RunbookGenerationInput {
        template: "singlesig-basic".to_owned(),
        descriptor: Some(CONTAINS_XPRV.trim().to_owned()),
        redaction: RedactionMode::PublicSafe,
        format: RunbookFormat::Markdown,
    };
    let err = generate_runbook(input, APP_VERSION).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
}

// --- parse_wallet_export ----------------------------------------------------

#[test]
fn parse_wallet_export_reads_and_normalizes_a_file() {
    let path = fixture_path("wallet_exports/sparrow_singlesig.json");
    let export = parse_wallet_export(&path.to_string_lossy(), CREATED_AT).expect("parses");
    assert_eq!(export.source_wallet, "sparrow");
    assert!(export.descriptors.receive.is_some());
    // The boundary stamps the import time and the source filename's basename.
    assert_eq!(export.imported_at.as_deref(), Some(CREATED_AT));
    assert_eq!(
        export.raw_source_filename.as_deref(),
        Some("sparrow_singlesig.json")
    );
}

#[test]
fn parse_wallet_export_missing_file_is_e_fs_001() {
    let missing = std::env::temp_dir().join("lifeboat-us043-does-not-exist.json");
    let err = parse_wallet_export(&missing.to_string_lossy(), CREATED_AT).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FileNotFound);
}

#[test]
fn parse_wallet_export_blocks_a_secret_bearing_file() {
    // A descriptor file whose key is an xprv must be refused by the secret screen
    // before any normalization (§13.5).
    let path = fixture_path("descriptors/invalid/contains_xprv.txt");
    let err = parse_wallet_export(&path.to_string_lossy(), CREATED_AT).unwrap_err();
    assert_eq!(err.severity(), Severity::Security);
    assert_eq!(err.code(), ErrorCode::ExtendedPrivateKeyDetected);
}

// --- save_export ------------------------------------------------------------

#[test]
fn save_export_writes_the_content_to_the_chosen_path() {
    let scratch = ScratchFile::new("save-export.bin");
    let content = b"bitcoin-lifeboat readiness report bytes\n";
    save_export(&scratch.path_str(), content).expect("writes");
    let read_back = std::fs::read(&scratch.path).expect("file exists at the chosen path");
    assert_eq!(read_back, content);
}

#[test]
fn save_export_unwritable_destination_is_e_fs_002() {
    // A path under a directory that does not exist cannot be written.
    let bad = std::env::temp_dir()
        .join("lifeboat-us043-no-such-dir")
        .join("out.bin");
    let err = save_export(&bad.to_string_lossy(), b"x").unwrap_err();
    assert_eq!(err.code(), ErrorCode::CannotWrite);
}

// --- open_external_link allowlist -------------------------------------------

#[test]
fn external_link_allowlist_entries_are_all_allowed() {
    let allowlist = external_link_allowlist();
    assert_eq!(allowlist.len(), 6);
    for entry in &allowlist {
        if let Some(prefix) = entry.strip_suffix('*') {
            // The `/docs/*` glob: a concrete path under it is allowed.
            let concrete = format!("{prefix}getting-started");
            check_external_link(&concrete).expect("a concrete docs URL is allowed");
        } else {
            check_external_link(entry).expect("an exact allowlist entry is allowed");
        }
    }
}

#[test]
fn check_external_link_rejects_off_allowlist_urls() {
    let allowlist = external_link_allowlist();
    // The site origin is the 4th entry (index 3); the docs glob is the last.
    let site_origin = &allowlist[3];

    let rejected = [
        "https://github.com/someone-else/bitcoin-lifeboat".to_owned(),
        "https://example.com".to_owned(),
        // A look-alike host that merely *starts with* the site origin string.
        format!("{site_origin}.evil.example/docs/x"),
        // Right path, wrong scheme.
        site_origin.replacen("https://", "http://", 1) + "/docs/x",
        "https://faucet.mutinynet.com.evil.example/".to_owned(),
        "http://faucet.mutinynet.com/".to_owned(),
    ];
    for url in &rejected {
        let err = check_external_link(url).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LinkNotAllowed, "rejects {url}");
        assert_eq!(err.severity(), Severity::Security);
    }
}

// --- get_app_info -----------------------------------------------------------

#[test]
fn app_info_reports_version_and_config_urls() {
    let info = app_info("9.9.9-test");
    assert_eq!(info.name, "Bitcoin Lifeboat");
    assert_eq!(info.version, "9.9.9-test");
    assert_eq!(info.license, "MIT");
    // `repository` / `homepage` come from project.config.toml, the same source as
    // the link allowlist — so they match its GitHub-base and site-origin entries.
    let allowlist = external_link_allowlist();
    assert_eq!(info.repository, allowlist[0]);
    assert_eq!(info.homepage, allowlist[3]);
}
// --- settings (§22.11 Public preferences, US-054) ---------------------------

/// A unique scratch directory under the OS temp dir, cleaned up on drop. Mirrors
/// [`ScratchFile`] (the workspace avoids the `tempfile` crate to keep the
/// 1.78-pinned dependency tree fixed).
struct ScratchDir {
    path: std::path::PathBuf,
}

impl ScratchDir {
    fn new(name: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("lifeboat-us054-{}-{n}-{name}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn settings_default_is_safe() {
    let s = Settings::default();
    assert!(!s.diagnostics_enabled);
    assert!(!s.show_advanced_details);
    assert_eq!(s.theme, ThemeSetting::System);
    assert_eq!(s.text_scale, TextScaleSetting::Normal);
    assert_eq!(s.language, "en");
    assert_eq!(s.version, desktop_commands::SETTINGS_SCHEMA_VERSION);
}

#[test]
fn load_settings_returns_defaults_when_absent() {
    let dir = ScratchDir::new("absent");
    let s = load_settings(&dir.path).expect("missing file => defaults");
    assert_eq!(s, Settings::default());
}

#[test]
fn save_then_load_round_trips_public_prefs() {
    let dir = ScratchDir::new("round-trip");
    let saved = Settings {
        version: desktop_commands::SETTINGS_SCHEMA_VERSION,
        theme: ThemeSetting::Dark,
        language: "en".to_owned(),
        diagnostics_enabled: true,
        show_advanced_details: true,
        text_scale: TextScaleSetting::Larger,
    };
    save_settings(&dir.path, &saved).expect("writes");
    let loaded = load_settings(&dir.path).expect("reads back");
    assert_eq!(loaded, saved);
}

#[test]
fn settings_file_uses_snake_case_public_keys_only() {
    let dir = ScratchDir::new("keys");
    save_settings(&dir.path, &Settings::default()).expect("writes");
    let bytes = std::fs::read(dir.path.join("settings.json")).expect("file exists");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let obj = value.as_object().expect("settings is a JSON object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "diagnostics_enabled",
            "language",
            "show_advanced_details",
            "text_scale",
            "theme",
            "version"
        ]
    );
    assert_eq!(value["theme"], "system");
    assert_eq!(value["text_scale"], "normal");
}

#[test]
fn missing_fields_fall_back_to_defaults() {
    let dir = ScratchDir::new("partial");
    std::fs::write(dir.path.join("settings.json"), br#"{"theme":"dark"}"#).expect("writes");
    let s = load_settings(&dir.path).expect("tolerates missing fields");
    assert_eq!(s.theme, ThemeSetting::Dark);
    assert_eq!(s.language, "en");
    assert!(!s.diagnostics_enabled);
    // A pre-existing settings file with no `text_scale` key loads at the safe 1x
    // default (§15.5) — the field is additive and backward-compatible.
    assert_eq!(s.text_scale, TextScaleSetting::Normal);
    assert_eq!(s.version, desktop_commands::SETTINGS_SCHEMA_VERSION);
}

#[test]
fn corrupt_settings_file_is_schema_migration_required() {
    let dir = ScratchDir::new("corrupt");
    std::fs::write(dir.path.join("settings.json"), b"{ not valid json").expect("writes");
    let err = load_settings(&dir.path).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SchemaMigrationRequired);
}

#[test]
fn clear_all_data_removes_the_settings_file() {
    let dir = ScratchDir::new("clear");
    save_settings(&dir.path, &Settings::default()).expect("writes");
    assert!(dir.path.join("settings.json").exists());
    clear_all_data(&dir.path).expect("clears");
    assert!(!dir.path.join("settings.json").exists());
    assert_eq!(load_settings(&dir.path).unwrap(), Settings::default());
}

#[test]
fn clear_all_data_is_ok_when_nothing_is_stored() {
    let dir = ScratchDir::new("clear-empty");
    clear_all_data(&dir.path).expect("absence is success");
}
