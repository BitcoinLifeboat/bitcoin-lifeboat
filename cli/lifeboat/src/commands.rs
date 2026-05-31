//! Command handlers for `audit-descriptor` and `report-json` (US-036).
//!
//! Both commands run the same pipeline — screen the input for secrets, parse the
//! descriptor, and build the §19.1 [`ReadinessReport`] — and differ only in how
//! they present it: `audit-descriptor` renders a human summary (or the report
//! JSON under the global `--json`), while `report-json` always emits the report
//! JSON. The exit code is the §23.2 status mapping ([`ExitCode::from_status`]),
//! so a healthy plan exits `0`, warnings exit `1` (or `2` under `--strict`), and
//! a parse failure is a Not Ready *verdict* (exit `2`).
//!
//! ## Safety
//! Every input is screened by [`detect_secret`] **before** it is parsed; a
//! confirmed secret is refused with exit `5` and never echoed. Error and
//! parse-failure messages use only leak-free `error-taxonomy` catalog text — the
//! descriptor, the detected secret, and any chained library error are never
//! reproduced in output.
//!
//! ## Determinism
//! Handlers take `created_at` and `app_version` as parameters rather than reading
//! the clock or the package version, so tests can pin them and golden output
//! stays byte-identical (the report engine is itself a pure function of its
//! inputs). The CLI entry point ([`now_iso8601`]) reads the wall clock here, at
//! the boundary.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use lifeboat_core::address_derive::{
    compare_known_address, derive_addresses, DerivedAddress, DerivedAddresses, MatchLocation,
    Network,
};
use lifeboat_core::descriptor_audit::{
    compute_checksum, parse_descriptor, validate_checksum, ChecksumStatus, ParsedDescriptor,
};
use lifeboat_core::error_taxonomy::{ErrorCode, LifeboatError};
use lifeboat_core::psbt_tools::{extract_final_tx_hex, inspect_psbt_base64, PsbtInspection};
use lifeboat_core::readiness_score::SCORING_ENGINE_VERSION;
use lifeboat_core::report_engine::{build_report, ReadinessReport, ReportInput};
use lifeboat_core::runbook_engine::{
    render_heir_markdown, render_heir_pdf, render_owner_markdown, render_owner_pdf, HeirTemplate,
    OwnerTemplate, PageSize, PdfBackend, RedactionMode, RunbookData, RunbookWalletSummary, Signer,
};
use lifeboat_core::sensitive_input_detector::{
    detect_secret, ByteRange, DetectedSecret, DetectorAction, DetectorReport,
};
use lifeboat_core::wallet_imports::{
    import_auto, import_bitcoin_core, import_coldcard_descriptor, import_coldcard_json,
    import_jade, import_liana_bed, import_nunchuk_bsms, import_sparrow, import_specter,
    NormalizedWalletExport,
};
use secrecy::SecretString;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::cli::{
    AuditArgs, ChainArg, ChecksumArgs, CompareArgs, CompletionShell, CompletionsArgs, DeriveArgs,
    DetectSecretsArgs, ExportFormat, GenerateRunbookArgs, GlobalArgs, NetworkArg, ParseExportArgs,
    PsbtArgs, PsbtCommand, PsbtExtractTxArgs, PsbtInspectArgs, PsbtValidateArgs, RunbookFormatArg,
    RunbookModeArg, VerifyBuildArgs,
};
use crate::exit::ExitCode;

/// The title line shared by the human audit summary and parse-failure verdict.
const HUMAN_HEADER: &str = "Bitcoin Lifeboat - Recovery Readiness Audit";

/// A fully-resolved command result: the text to write to stdout and stderr, plus
/// the process exit code. Handlers return this (instead of writing the streams
/// themselves) so they stay pure and unit-testable; `main` does the printing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Text for standard output (the audit result / report JSON).
    pub stdout: String,
    /// Text for standard error (operational errors and refusals).
    pub stderr: String,
    /// The process exit code (§23.2).
    pub code: ExitCode,
}

/// Run `audit-descriptor` (PRD §17.10.1): audit a descriptor and report
/// readiness as a human summary, or as the report JSON under the global
/// `--json`. The exit code follows the scored verdict (`--strict` promotes a
/// warnings result to critical).
pub fn run_audit_descriptor(
    args: &AuditArgs,
    global: &GlobalArgs,
    created_at: &str,
    app_version: &str,
    stdin: impl Read,
) -> CommandOutput {
    match prepare_report(args, global.json, created_at, app_version, stdin) {
        Ok(report) => {
            let code = ExitCode::from_status(report.score.status, args.strict);
            let stdout = if global.json {
                report_json_line(&report)
            } else {
                render_human_audit(&report)
            };
            CommandOutput {
                stdout,
                stderr: String::new(),
                code,
            }
        }
        Err(early) => early,
    }
}

/// Run `report-json` (PRD §17.10.5): always emit the §19.1 [`ReadinessReport`] as
/// JSON to stdout. `--strict` promotes a warnings verdict to a failing exit code.
/// An unparseable descriptor yields a compact `not_ready` error object (exit 2),
/// since a §19.1 report requires a parsed descriptor.
pub fn run_report_json(
    args: &AuditArgs,
    created_at: &str,
    app_version: &str,
    stdin: impl Read,
) -> CommandOutput {
    match prepare_report(args, true, created_at, app_version, stdin) {
        Ok(report) => {
            let code = ExitCode::from_status(report.score.status, args.strict);
            CommandOutput {
                stdout: report_json_line(&report),
                stderr: String::new(),
                code,
            }
        }
        Err(early) => early,
    }
}

/// Run `derive-addresses` (PRD §17.10.2): derive the first `--count` receive
/// and/or change addresses from a watch-only descriptor. A successful derivation
/// always exits `0` — the address list is the output.
pub fn run_derive_addresses(args: &DeriveArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    let parsed = match screen_and_parse(&args.descriptor, emit_json) {
        Ok(parsed) => parsed,
        Err(early) => return early,
    };
    let network = match resolve_network(&parsed, args.network, emit_json) {
        Ok(network) => network,
        Err(early) => return early,
    };
    let derived = match derive_addresses(&parsed, network, args.count) {
        Ok(derived) => derived,
        Err(e) => return hard_error(&e, emit_json),
    };

    let want_receive = matches!(args.chain, ChainArg::Receive | ChainArg::Both);
    let want_change = matches!(args.chain, ChainArg::Change | ChainArg::Both);
    let mut rows: Vec<&DerivedAddress> = Vec::new();
    if want_receive {
        rows.extend(derived.receive_derived.iter());
    }
    if want_change {
        rows.extend(derived.change_derived.iter());
    }

    let stdout = if emit_json {
        json!({ "network": network.to_string(), "addresses": rows }).to_string() + "\n"
    } else {
        render_derive_human(network, want_receive, want_change, &derived)
    };
    CommandOutput {
        stdout,
        stderr: String::new(),
        code: ExitCode::Success,
    }
}

/// Run `compare-address` (PRD §17.10.3): search a descriptor's derived range for
/// a known address. The exit code is **command-local** (§17.10.3): `0` = match,
/// `1` = no match within range, `2` = the address is invalid for the resolved
/// network. Those numbers coincide with [`ExitCode::Success`] / [`ExitCode::Warnings`]
/// / [`ExitCode::Critical`], which is why those variants are reused here for their
/// numeric value (the audit-style `from_status` mapping does **not** apply).
pub fn run_compare_address(args: &CompareArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    // Screen both the descriptor and the address for pasted secrets before any
    // processing (the §13.5 invariant); a WIF/xprv pasted into either is blocked.
    if let Some(block) = screen_for_secrets(&args.address, emit_json) {
        return block;
    }
    let parsed = match screen_and_parse(&args.descriptor, emit_json) {
        Ok(parsed) => parsed,
        Err(early) => return early,
    };
    let network = match resolve_network(&parsed, args.network, emit_json) {
        Ok(network) => network,
        Err(early) => return early,
    };

    match compare_known_address(&parsed, network, &args.address, args.search_range) {
        Ok(found) => {
            // §17.10.3: 0 = match, 1 = no match (numerically Success/Warnings).
            let code = if found.matched {
                ExitCode::Success
            } else {
                ExitCode::Warnings
            };
            let stdout =
                render_compare_result(network, &found.provided, found.matched_at, None, emit_json);
            CommandOutput {
                stdout,
                stderr: String::new(),
                code,
            }
        }
        // §17.10.3: 2 = the address is invalid for the resolved network. Address
        // validation is the only `E-INPUT-003` (InputInvalidFormat) source here.
        Err(e) if e.code() == ErrorCode::InputInvalidFormat => {
            let detail = e
                .context()
                .map_or_else(|| e.code().title().to_owned(), str::to_owned);
            let stdout =
                render_compare_result(network, args.address.trim(), None, Some(&detail), emit_json);
            CommandOutput {
                stdout,
                stderr: String::new(),
                // Numerically 2 per §17.10.3 (= ExitCode::Critical's value).
                code: ExitCode::Critical,
            }
        }
        Err(e) => hard_error(&e, emit_json),
    }
}

/// Run `checksum` (PRD §17.10.8): validate or compute a descriptor's BIP380
/// checksum. The descriptor is screened for secrets **first** — `--compute`
/// echoes the (checksummed) descriptor back, so an `xprv` must be blocked before
/// it is ever processed or printed.
pub fn run_checksum(args: &ChecksumArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    if let Some(descriptor) = &args.validate {
        return run_checksum_validate(descriptor, emit_json);
    }
    if let Some(descriptor) = &args.compute {
        return run_checksum_compute(descriptor, emit_json);
    }
    // Unreachable: clap's required `checksum_op` group guarantees exactly one.
    invalid_args("checksum requires --validate or --compute", emit_json)
}

/// `checksum --validate`: exit `0` valid, `1` checksum missing (a warning), or
/// `4` checksum invalid (`E-PARSE-003` via [`ExitCode::from_error`]).
fn run_checksum_validate(descriptor: &str, emit_json: bool) -> CommandOutput {
    if let Some(block) = screen_for_secrets(descriptor, emit_json) {
        return block;
    }
    match validate_checksum(descriptor) {
        Ok(ChecksumStatus::Present) => checksum_validate_output(
            "valid",
            "checksum is present and valid",
            ExitCode::Success,
            emit_json,
        ),
        Ok(ChecksumStatus::Missing) => checksum_validate_output(
            "missing",
            "no checksum is present (W-NO-DESC-CHECKSUM)",
            ExitCode::Warnings,
            emit_json,
        ),
        Err(e) => checksum_validate_output(
            "invalid",
            "checksum is present but does not match the descriptor body (E-PARSE-003)",
            ExitCode::from_error(&e),
            emit_json,
        ),
    }
}

/// `checksum --compute`: print `descriptor#xxxxxxxx` (exit 0), or surface a hard
/// error (a blank input or a character outside the BIP380 charset → exit 4).
fn run_checksum_compute(descriptor: &str, emit_json: bool) -> CommandOutput {
    if let Some(block) = screen_for_secrets(descriptor, emit_json) {
        return block;
    }
    match compute_checksum(descriptor) {
        Ok(checksummed) => {
            let stdout = if emit_json {
                json!({ "descriptor": checksummed }).to_string() + "\n"
            } else {
                checksummed + "\n"
            };
            CommandOutput {
                stdout,
                stderr: String::new(),
                code: ExitCode::Success,
            }
        }
        Err(e) => hard_error(&e, emit_json),
    }
}

/// Render a `checksum --validate` verdict: `status` is the machine token
/// (`valid`/`missing`/`invalid`), `human` the sentence. Output goes to stdout so a
/// `--json` consumer always reads the verdict there; the exit code carries it too.
fn checksum_validate_output(
    status: &str,
    human: &str,
    code: ExitCode,
    emit_json: bool,
) -> CommandOutput {
    let stdout = if emit_json {
        json!({ "checksum": status, "valid": status == "valid" }).to_string() + "\n"
    } else {
        format!("{human}\n")
    };
    CommandOutput {
        stdout,
        stderr: String::new(),
        code,
    }
}

// --- US-077: PSBT file commands ---------------------------------------------

/// Run the nested `psbt` command group. These commands inspect PSBT files and
/// extract already-finalized transactions; wallet-backed create/sign/finalize
/// drills stay in the detached `psbt-drill` crate.
pub fn run_psbt(args: &PsbtArgs, global: &GlobalArgs) -> CommandOutput {
    match &args.command {
        PsbtCommand::Inspect(args) => run_psbt_inspect(args, global),
        PsbtCommand::Validate(args) => run_psbt_validate(args, global),
        PsbtCommand::ExtractTx(args) => run_psbt_extract_tx(args, global),
    }
}

fn run_psbt_inspect(args: &PsbtInspectArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    let content = match read_psbt_file(&args.file, emit_json) {
        Ok(content) => content,
        Err(early) => return early,
    };
    match inspect_psbt_base64(&content, args.network.map(to_network)) {
        Ok(inspection) => CommandOutput {
            stdout: render_psbt_inspection(&inspection, emit_json),
            stderr: String::new(),
            code: ExitCode::Success,
        },
        Err(error) => hard_error(&error, emit_json),
    }
}

fn run_psbt_validate(args: &PsbtValidateArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    let content = match read_psbt_file(&args.file, emit_json) {
        Ok(content) => content,
        Err(early) => return early,
    };
    match inspect_psbt_base64(&content, args.network.map(to_network)) {
        Ok(inspection) => {
            let stdout = if emit_json {
                json!({
                    "valid": true,
                    "version": inspection.version,
                    "encoding": inspection.encoding,
                    "lifecycle": inspection.lifecycle,
                    "input_count": inspection.input_count,
                    "output_count": inspection.output_count,
                })
                .to_string()
                    + "\n"
            } else {
                format!(
                    "PSBT is parseable and supported ({}). Lifecycle: {}.\n",
                    inspection.encoding.label(),
                    inspection.lifecycle.as_str()
                )
            };
            CommandOutput {
                stdout,
                stderr: String::new(),
                code: ExitCode::Success,
            }
        }
        Err(error) => hard_error(&error, emit_json),
    }
}

fn run_psbt_extract_tx(args: &PsbtExtractTxArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    let content = match read_psbt_file(&args.file, emit_json) {
        Ok(content) => content,
        Err(early) => return early,
    };
    let tx_hex = match extract_final_tx_hex(&content) {
        Ok(tx_hex) => tx_hex,
        Err(error) => return hard_error(&error, emit_json),
    };
    match &args.output {
        Some(path) => match std::fs::write(path, format!("{tx_hex}\n")) {
            Ok(()) => {
                let stdout = if emit_json {
                    json!({
                        "wrote": path.display().to_string(),
                        "bytes": tx_hex.len(),
                    })
                    .to_string()
                        + "\n"
                } else {
                    format!(
                        "Wrote extracted transaction hex ({} bytes) to {}.\n",
                        tx_hex.len(),
                        path.display()
                    )
                };
                CommandOutput {
                    stdout,
                    stderr: String::new(),
                    code: ExitCode::Success,
                }
            }
            Err(e) => hard_error(
                &LifeboatError::new(ErrorCode::CannotWrite)
                    .with_context(format!(
                        "could not write transaction file `{}`",
                        path.display()
                    ))
                    .with_source(e),
                emit_json,
            ),
        },
        None => {
            let stdout = if emit_json {
                json!({ "transaction_hex": tx_hex }).to_string() + "\n"
            } else {
                format!("{tx_hex}\n")
            };
            CommandOutput {
                stdout,
                stderr: String::new(),
                code: ExitCode::Success,
            }
        }
    }
}

fn read_psbt_file(path: &std::path::Path, emit_json: bool) -> Result<String, CommandOutput> {
    std::fs::read_to_string(path).map_err(|e| {
        let err = LifeboatError::new(ErrorCode::FileNotFound)
            .with_context(format!("could not read PSBT file `{}`", path.display()))
            .with_source(e);
        hard_error(&err, emit_json)
    })
}

fn render_psbt_inspection(inspection: &PsbtInspection, emit_json: bool) -> String {
    if emit_json {
        return serde_json::to_string(inspection).unwrap_or_else(|_| "{}".to_owned()) + "\n";
    }

    use std::fmt::Write as _;
    const HEADER: &str = "Bitcoin Lifeboat - PSBT Inspect";
    let mut out = String::new();
    let _ = writeln!(out, "{HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HEADER.len()));
    let _ = writeln!(out);
    let _ = writeln!(out, "Encoding: {}", inspection.encoding.label());
    let _ = writeln!(out, "Lifecycle: {}", inspection.lifecycle.as_str());
    let _ = writeln!(
        out,
        "Shape:    {} input(s), {} output(s)",
        inspection.input_count, inspection.output_count
    );
    let _ = writeln!(
        out,
        "Finalized inputs: {}/{}",
        inspection.finalized_input_count, inspection.input_count
    );
    let _ = writeln!(out, "Unsigned txid: {}", inspection.txid);
    let _ = writeln!(out, "Outputs total: {} sat", inspection.output_total_sat);
    match (
        inspection.input_total_sat,
        inspection.fee_sat,
        inspection.fee_rate_sat_vb,
    ) {
        (Some(input_total), Some(fee), Some(fee_rate)) => {
            let _ = writeln!(out, "Inputs total:  {input_total} sat");
            let _ = writeln!(out, "Local fee:     {fee} sat (~{fee_rate} sat/vB)");
        }
        _ => {
            let _ = writeln!(
                out,
                "Inputs total:  unknown (not every input has UTXO data)"
            );
            let _ = writeln!(out, "Local fee:     unknown");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Outputs:");
    for output in &inspection.outputs {
        let address = output.address.as_deref().unwrap_or("(no address decoded)");
        let _ = writeln!(
            out,
            "  [{}] {} sat  {}",
            output.index, output.amount_sat, address
        );
    }
    out
}

// --- US-098: verify-build ----------------------------------------------------

/// One artifact checked by `verify-build`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildVerification {
    path: PathBuf,
    name: String,
    expected_sha256: Option<String>,
    actual_sha256: String,
}

impl BuildVerification {
    fn matches(&self) -> bool {
        self.expected_sha256
            .as_deref()
            .is_some_and(|expected| expected == self.actual_sha256)
    }
}

/// Run `verify-build` (US-098): compare local build artifacts against the
/// published `SHA256SUMS` for a release. This command performs a network fetch
/// only when the user explicitly invokes it and no local checksum file is found.
pub fn run_verify_build(args: &VerifyBuildArgs, global: &GlobalArgs) -> CommandOutput {
    let emit_json = global.json;
    if !valid_release_tag(&args.version) {
        return invalid_args(
            "release version must look like v0.1.0 or v0.1.0-alpha.1",
            emit_json,
        );
    }

    let (checksum_text, checksum_source) = match read_release_checksums(args) {
        Ok(source) => source,
        Err(error) => return hard_error(&error, emit_json),
    };
    let manifest = match parse_sha256sums(&checksum_text) {
        Ok(manifest) => manifest,
        Err(error) => return hard_error(&error, emit_json),
    };
    let artifacts = if args.artifacts.is_empty() {
        match discover_release_artifacts(&manifest) {
            Ok(paths) if !paths.is_empty() => paths,
            Ok(_) => {
                return invalid_args(
                    "no local release artifacts were found; pass --artifact <PATH>",
                    emit_json,
                )
            }
            Err(error) => return hard_error(&error, emit_json),
        }
    } else {
        args.artifacts.clone()
    };

    let verifications = match verify_artifact_hashes(&artifacts, &manifest) {
        Ok(verifications) => verifications,
        Err(error) => return hard_error(&error, emit_json),
    };
    let all_match = verifications.iter().all(BuildVerification::matches);
    let stdout = render_verify_build(&args.version, &checksum_source, &verifications, emit_json);
    CommandOutput {
        stdout,
        stderr: String::new(),
        code: if all_match {
            ExitCode::Success
        } else {
            ExitCode::Critical
        },
    }
}

fn valid_release_tag(tag: &str) -> bool {
    tag.starts_with('v')
        && tag.len() > 1
        && tag
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'))
}

fn read_release_checksums(args: &VerifyBuildArgs) -> Result<(String, String), LifeboatError> {
    if let Some(path) = &args.checksums {
        return read_checksum_file(path);
    }

    let local = Path::new("SHA256SUMS");
    if local.is_file() {
        return read_checksum_file(local);
    }

    fetch_release_checksums(&args.version, args.release_base_url.as_deref())
}

fn read_checksum_file(path: &Path) -> Result<(String, String), LifeboatError> {
    std::fs::read_to_string(path)
        .map(|text| (text, path.display().to_string()))
        .map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context(format!("could not read checksum file `{}`", path.display()))
                .with_source(e)
        })
}

fn fetch_release_checksums(
    version: &str,
    release_base_url: Option<&str>,
) -> Result<(String, String), LifeboatError> {
    let base = release_base_url.map(str::to_owned).unwrap_or_else(|| {
        format!(
            "{}/releases/download/{version}",
            env!("CARGO_PKG_REPOSITORY")
        )
    });
    let url = format!("{}/SHA256SUMS", base.trim_end_matches('/'));
    let output = std::process::Command::new("curl")
        .args(["-fsSL", &url])
        .output()
        .map_err(|e| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("could not run curl to fetch SHA256SUMS")
                .with_source(e)
        })?;
    if !output.status.success() {
        return Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context(format!("could not fetch SHA256SUMS from {url}")));
    }
    String::from_utf8(output.stdout)
        .map(|text| (text, url))
        .map_err(|e| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("downloaded SHA256SUMS was not valid UTF-8")
                .with_source(e)
        })
}

fn parse_sha256sums(text: &str) -> Result<BTreeMap<String, String>, LifeboatError> {
    let mut manifest = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else {
            continue;
        };
        let Some(filename) = parts.next() else {
            return Err(
                LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
                    "SHA256SUMS line {} is missing a filename",
                    index + 1
                )),
            );
        };
        if parts.next().is_some() || !is_sha256_hex(hash) {
            return Err(
                LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
                    "SHA256SUMS line {} is not in `sha256  filename` format",
                    index + 1
                )),
            );
        }
        manifest.insert(
            filename.trim_start_matches('*').to_owned(),
            hash.to_ascii_lowercase(),
        );
    }
    if manifest.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("SHA256SUMS did not contain any artifact hashes"));
    }
    Ok(manifest)
}

fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

fn discover_release_artifacts(
    manifest: &BTreeMap<String, String>,
) -> Result<Vec<PathBuf>, LifeboatError> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(".").map_err(|e| {
        LifeboatError::new(ErrorCode::FileNotFound)
            .with_context("could not scan the current directory for release artifacts")
            .with_source(e)
    })? {
        let entry = entry.map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context("could not read a current-directory entry")
                .with_source(e)
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if manifest.contains_key(name) && !is_signature_sidecar(name) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_signature_sidecar(name: &str) -> bool {
    name.ends_with(".minisig") || name.ends_with(".sigstore.json")
}

fn verify_artifact_hashes(
    artifacts: &[PathBuf],
    manifest: &BTreeMap<String, String>,
) -> Result<Vec<BuildVerification>, LifeboatError> {
    let mut checked = Vec::with_capacity(artifacts.len());
    for path in artifacts {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(
                LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
                    "artifact path `{}` has no filename",
                    path.display()
                )),
            );
        };
        let actual_sha256 = sha256_file(path)?;
        checked.push(BuildVerification {
            path: path.clone(),
            name: name.to_owned(),
            expected_sha256: manifest.get(name).cloned(),
            actual_sha256,
        });
    }
    Ok(checked)
}

fn sha256_file(path: &Path) -> Result<String, LifeboatError> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        LifeboatError::new(ErrorCode::FileNotFound)
            .with_context(format!("could not read artifact `{}`", path.display()))
            .with_source(e)
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context(format!("could not hash artifact `{}`", path.display()))
                .with_source(e)
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn render_verify_build(
    version: &str,
    checksum_source: &str,
    verifications: &[BuildVerification],
    emit_json: bool,
) -> String {
    if emit_json {
        let artifacts: Vec<serde_json::Value> = verifications
            .iter()
            .map(|item| {
                json!({
                    "actual_sha256": item.actual_sha256,
                    "expected_sha256": item.expected_sha256,
                    "file": item.path.display().to_string(),
                    "match": item.matches(),
                    "name": item.name,
                })
            })
            .collect();
        return json!({
            "artifacts": artifacts,
            "checksum_source": checksum_source,
            "release": version,
            "verified": verifications.iter().all(BuildVerification::matches),
        })
        .to_string()
            + "\n";
    }

    use std::fmt::Write as _;
    const HEADER: &str = "Bitcoin Lifeboat - Build Verification";
    let mut out = String::new();
    let _ = writeln!(out, "{HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HEADER.len()));
    let _ = writeln!(out);
    let _ = writeln!(out, "Release:   {version}");
    let _ = writeln!(out, "Checksums: {checksum_source}");
    let _ = writeln!(out);
    for item in verifications {
        if let Some(expected) = &item.expected_sha256 {
            if item.matches() {
                let _ = writeln!(out, "[OK]   {}", item.path.display());
            } else {
                let _ = writeln!(out, "[FAIL] {}", item.path.display());
                let _ = writeln!(out, "       expected {expected}");
                let _ = writeln!(out, "       actual   {}", item.actual_sha256);
            }
        } else {
            let _ = writeln!(out, "[FAIL] {}", item.path.display());
            let _ = writeln!(out, "       no published hash for {}", item.name);
            let _ = writeln!(out, "       actual {}", item.actual_sha256);
        }
    }
    out
}

// --- US-038: detect-secrets and parse-export ----------------------------------

/// The DetectorReport JSON schema version (PRD §19.4). Stable for the 0.x line.
const DETECTOR_SCHEMA_VERSION: &str = "0.1.0";

/// Run `detect-secrets` (PRD §17.10.6): screen input for pasted Bitcoin secrets
/// and report what was found, **without ever echoing the content**. The exit code
/// is command-local (§17.10.6): `5` on any `Block`, `1` on `Warn`-only, `0`
/// otherwise — derived from the detector verdict, not the audit status mapping.
pub fn run_detect_secrets(
    args: &DetectSecretsArgs,
    global: &GlobalArgs,
    stdin: impl Read,
) -> CommandOutput {
    let emit_json = global.json;
    let text = match read_secret_source(args, stdin) {
        Ok(text) => text,
        Err(e) => return hard_error(&e, emit_json),
    };
    // Wrap as a `SecretString` and screen via the sanctioned entry; it exposes the
    // value only for the call and zeroizes it on drop. The report carries only
    // discriminants + byte ranges, never the secret content.
    let report = detect_secret(SecretString::from(text));
    let code = exit_code_for_action(report.action);
    let stdout = if emit_json {
        detector_report_json(&report)
    } else {
        render_detector_human(&report)
    };
    CommandOutput {
        stdout,
        stderr: String::new(),
        code,
    }
}

/// Map a detector verdict to the **command-local** exit code (§17.10.6): `Block` →
/// 5, `Warn` → 1, `Allow` → 0. These numbers coincide with
/// [`ExitCode::SecretDetected`] / [`ExitCode::Warnings`] / [`ExitCode::Success`],
/// reused here for their value (the audit `from_status` mapping does not apply).
fn exit_code_for_action(action: DetectorAction) -> ExitCode {
    match action {
        DetectorAction::Block => ExitCode::SecretDetected,
        DetectorAction::Warn => ExitCode::Warnings,
        DetectorAction::Allow => ExitCode::Success,
    }
}

/// Read the bytes to screen for `detect-secrets`: `--file` if given, otherwise
/// standard input (the §17.10.6 default; `--stdin` is the explicit opt-in). I/O
/// failures map to `E-FS-001` (→ exit 6); the error names the source, never the
/// content.
fn read_secret_source(
    args: &DetectSecretsArgs,
    mut stdin: impl Read,
) -> Result<String, LifeboatError> {
    if let Some(path) = &args.file {
        std::fs::read_to_string(path).map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context(format!("could not read input file `{}`", path.display()))
                .with_source(e)
        })
    } else {
        let mut buffer = String::new();
        stdin.read_to_string(&mut buffer).map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context("could not read input from standard input")
                .with_source(e)
        })?;
        Ok(buffer)
    }
}

/// Render a [`DetectorReport`] as the PRD §19.4 DetectorReport JSON.
///
/// The §19.4 shape differs from the detector crate's derived `serde` form (which
/// serializes each finding as a `[secret, range]` tuple): §19.4 *flattens* each
/// finding to `{ "kind", <metadata…>, "byte_range": [start, end] }` and adds the
/// top-level `schema_version` and `user_facing_message`. It carries only
/// discriminants, byte ranges, and static catalog copy — never secret content.
fn detector_report_json(report: &DetectorReport) -> String {
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|(secret, range)| finding_json(secret, range))
        .collect();
    json!({
        "schema_version": DETECTOR_SCHEMA_VERSION,
        "action": report.action,
        "findings": findings,
        "user_facing_message": detector_message(report),
    })
    .to_string()
        + "\n"
}

/// Build one §19.4 finding object: the secret `kind`, its non-secret metadata, and
/// the `byte_range` as a `[start, end]` array. Never contains secret content.
fn finding_json(secret: &DetectedSecret, range: &ByteRange) -> serde_json::Value {
    let mut value = json!({
        "kind": secret_kind(secret),
        "byte_range": [range.start, range.end],
    });
    match secret {
        DetectedSecret::Bip39 {
            language,
            word_count,
            checksum_valid,
        } => {
            value["language"] = json!(language);
            value["word_count"] = json!(word_count);
            value["checksum_valid"] = json!(checksum_valid);
        }
        DetectedSecret::Wif {
            network,
            compressed,
        } => {
            value["network"] = json!(network);
            value["compressed"] = json!(compressed);
        }
        DetectedSecret::Xprv { kind, network } => {
            value["xprv_kind"] = json!(kind);
            value["network"] = json!(network);
        }
        DetectedSecret::Slip39 {
            share_count_in_input,
        } => {
            value["share_count_in_input"] = json!(share_count_in_input);
        }
        DetectedSecret::Codex32 { threshold } => {
            value["threshold"] = json!(threshold);
        }
        DetectedSecret::RawHexPrivKey | DetectedSecret::None => {}
    }
    value
}

/// The §19.4 `kind` token for a detected secret (snake_case, matching the detector
/// crate's `serde` tag for the variant).
fn secret_kind(secret: &DetectedSecret) -> &'static str {
    match secret {
        DetectedSecret::Bip39 { .. } => "bip39",
        DetectedSecret::Wif { .. } => "wif",
        DetectedSecret::Xprv { .. } => "xprv",
        DetectedSecret::RawHexPrivKey => "raw_hex_priv_key",
        DetectedSecret::Slip39 { .. } => "slip39",
        DetectedSecret::Codex32 { .. } => "codex32",
        DetectedSecret::None => "none",
    }
}

/// The §19.4 `user_facing_message` for a report: the verbatim Block headline from
/// the detector crate when blocked, or a short, leak-free status line for `Warn` /
/// `Allow` (the crate defines a headline only for `Block`). Static copy; never
/// contains detected content, and passes the §16.8 anti-overclaim lint.
fn detector_message(report: &DetectorReport) -> &'static str {
    match report.action {
        DetectorAction::Block => report
            .headline()
            .unwrap_or("This looks like a real Bitcoin secret. Input rejected."),
        DetectorAction::Warn => {
            "Some of this input resembles secret material but could not be confirmed. Review it \
             and remove any real secret before continuing."
        }
        DetectorAction::Allow => "No sensitive material was detected in this input.",
    }
}

/// Render the human-readable `detect-secrets` result: the verdict, each finding's
/// kind + byte range + leak-free `E-SECRET-*` reason code, and the guidance line.
/// Plain ASCII, deterministic, and never echoes detected content.
fn render_detector_human(report: &DetectorReport) -> String {
    use std::fmt::Write as _;
    const HEADER: &str = "Bitcoin Lifeboat - Sensitive Input Scan";
    let mut out = String::new();
    let _ = writeln!(out, "{HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HEADER.len()));
    let _ = writeln!(out);

    let verdict = match report.action {
        DetectorAction::Block => "BLOCK - a real Bitcoin secret was detected",
        DetectorAction::Warn => "WARN - input may contain secret material",
        DetectorAction::Allow => "OK - no sensitive material detected",
    };
    let _ = writeln!(out, "Result: {verdict}");
    let _ = writeln!(out);

    if !report.findings.is_empty() {
        let _ = writeln!(out, "Findings:");
        for (secret, range) in &report.findings {
            let code = secret.error_code().map_or("", ErrorCode::as_str);
            let _ = writeln!(
                out,
                "  [{code}] {} at bytes {}..{}",
                secret_kind(secret),
                range.start,
                range.end
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "{}", detector_message(report));
    out
}

/// Run `parse-export` (PRD §17.10.7): parse a wallet-export file into the §19.3
/// [`NormalizedWalletExport`] and emit it as JSON (under global `--json`) or a
/// human summary. The file is screened for secret material before parsing; a
/// watch-only export (xpubs only) is `Allow` and proceeds. A successful import
/// always exits `0`.
pub fn run_parse_export(
    args: &ParseExportArgs,
    global: &GlobalArgs,
    imported_at: &str,
) -> CommandOutput {
    let emit_json = global.json;
    let content = match read_export_file(&args.file, emit_json) {
        Ok(content) => content,
        Err(early) => return early,
    };
    // Screen for secret material BEFORE parsing (the §13.5 invariant): an export
    // carrying private keys is refused (exit 5) and never normalized or echoed.
    if let Some(block) = screen_for_secrets(&content, emit_json) {
        return block;
    }
    let export = match import_export(args, &content) {
        Ok(export) => export,
        Err(e) => return hard_error(&e, emit_json),
    };
    // Stamp the fields the importer intentionally leaves to the caller (the clock
    // is read at the boundary, like the report's `created_at` — determinism §19).
    let export = stamp_export(export, args, imported_at);

    let stdout = if emit_json {
        export_json(&export)
    } else {
        render_export_human(&export)
    };
    CommandOutput {
        stdout,
        stderr: String::new(),
        code: ExitCode::Success,
    }
}

/// Read the export file's text, mapping an I/O failure to `E-FS-001` (→ exit 6).
/// The error names the path, never the file contents.
fn read_export_file(path: &std::path::Path, emit_json: bool) -> Result<String, CommandOutput> {
    std::fs::read_to_string(path).map_err(|e| {
        let err = LifeboatError::new(ErrorCode::FileNotFound)
            .with_context(format!("could not read export file `{}`", path.display()))
            .with_source(e);
        hard_error(&err, emit_json)
    })
}

/// Import the export content using the selected `--format` (or auto-detect).
///
/// `Coldcard` accepts both the JSON Generic Wallet Export and the descriptor-file
/// text export, chosen by a leading `{`. `Liana` requires `--decryption-input`
/// (one of the backup's recipient xpubs); the other named formats map 1:1 to their
/// importer. The wallet-software version is not taken on the CLI — no export embeds
/// it (`wallet-imports` accepts it out-of-band).
fn import_export(
    args: &ParseExportArgs,
    content: &str,
) -> Result<NormalizedWalletExport, LifeboatError> {
    let inputs: Vec<&str> = args.decryption_inputs.iter().map(String::as_str).collect();
    match args.format {
        ExportFormat::Auto => import_auto(content),
        ExportFormat::Sparrow => import_sparrow(content, None),
        ExportFormat::Specter => import_specter(content, None),
        ExportFormat::Coldcard => {
            if content.trim_start().starts_with('{') {
                import_coldcard_json(content, None)
            } else {
                import_coldcard_descriptor(content, None, None)
            }
        }
        ExportFormat::Nunchuk => import_nunchuk_bsms(content, None),
        ExportFormat::Jade => import_jade(content, None),
        ExportFormat::Liana => import_liana_bed(content, &inputs, None),
        ExportFormat::Core => import_bitcoin_core(content, None),
    }
}

/// Fill the caller-provided fields the importer leaves unset: `imported_at` (the
/// import time, read at the CLI boundary) and `raw_source_filename` (the basename
/// of the input file).
fn stamp_export(
    mut export: NormalizedWalletExport,
    args: &ParseExportArgs,
    imported_at: &str,
) -> NormalizedWalletExport {
    export.imported_at = Some(imported_at.to_owned());
    export.raw_source_filename = args
        .file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    export
}

/// The normalized export serialized as compact JSON (the §19.3 shape). It is a
/// crate-owned `serde` type whose declared field order is the §19.3 key order, so
/// serialize it directly (compact), like the §19.1 report. Newline-terminated.
fn export_json(export: &NormalizedWalletExport) -> String {
    serde_json::to_string(export).unwrap_or_else(|_| "{}".to_owned()) + "\n"
}

/// Render a human-readable summary of a normalized export. Plain ASCII,
/// deterministic, and free of any "safe"/"guaranteed" overclaim (§16.8). Shows the
/// source, wallet type/quorum, and per-key fingerprint + path (not xpubs or the
/// full descriptors — those are in the `--json` output); the export is watch-only.
fn render_export_human(export: &NormalizedWalletExport) -> String {
    use std::fmt::Write as _;
    const HEADER: &str = "Bitcoin Lifeboat - Wallet Export";
    let mut out = String::new();
    let _ = writeln!(out, "{HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HEADER.len()));
    let _ = writeln!(out);

    match &export.source_wallet_version {
        Some(version) => {
            let _ = writeln!(out, "Source:  {} v{version}", export.source_wallet);
        }
        None => {
            let _ = writeln!(out, "Source:  {}", export.source_wallet);
        }
    }
    let wallet_type = export.wallet_type.as_deref().unwrap_or("unknown");
    match (export.threshold, export.key_count) {
        (Some(m), Some(n)) => {
            let _ = writeln!(out, "Type:    {wallet_type} ({m}-of-{n})");
        }
        _ => {
            let _ = writeln!(out, "Type:    {wallet_type}");
        }
    }
    if let Some(birth) = &export.birth_timestamp {
        let _ = writeln!(out, "Birth:   {birth}");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "Keys ({}):", export.keys.len());
    for key in &export.keys {
        let fingerprint = key.fingerprint.as_deref().unwrap_or("--------");
        let path = key.derivation_path.as_deref().unwrap_or("(no path)");
        let _ = writeln!(out, "  [{}] {fingerprint}  {path}", key.index);
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Run with --json for the full normalized export (descriptors, keys, labels)."
    );
    out
}

/// Screen a descriptor for secrets, then parse it. Used by the utility commands
/// (`derive-addresses`, `compare-address`), where an unparseable descriptor is a
/// hard error (exit 4 via [`ExitCode::from_error`]) rather than the Not Ready
/// *verdict* the audit flow produces. The error text is leak-free — only the
/// `ErrorCode` catalog title, never the descriptor or the chained library error.
fn screen_and_parse(descriptor: &str, emit_json: bool) -> Result<ParsedDescriptor, CommandOutput> {
    if let Some(block) = screen_for_secrets(descriptor, emit_json) {
        return Err(block);
    }
    parse_descriptor(descriptor).map_err(|e| hard_error(&e, emit_json))
}

/// Resolve the network to derive on: the explicit `--network` override if given,
/// otherwise the descriptor's inferred network. Returns an exit-4 refusal when the
/// network is ambiguous (a `tpub`, shared by testnet/signet/regtest) or absent
/// (raw keys) and no override was supplied — Lifeboat never guesses (PRD §16.5).
fn resolve_network(
    parsed: &ParsedDescriptor,
    override_arg: Option<NetworkArg>,
    emit_json: bool,
) -> Result<Network, CommandOutput> {
    if let Some(arg) = override_arg {
        return Ok(to_network(arg));
    }
    parsed.network().ok_or_else(|| {
        invalid_args(
            "the network could not be inferred from the descriptor (a tpub is shared by \
             testnet, signet, and regtest); pass --network testnet|signet|regtest",
            emit_json,
        )
    })
}

/// Render the human-readable address list for `derive-addresses`. Plain ASCII and
/// deterministic; the strings carry no "safe"/"guaranteed" overclaim (§16.8).
fn render_derive_human(
    network: Network,
    want_receive: bool,
    want_change: bool,
    derived: &DerivedAddresses,
) -> String {
    use std::fmt::Write as _;
    const HEADER: &str = "Bitcoin Lifeboat - Address Derivation";
    let mut out = String::new();
    let _ = writeln!(out, "{HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HEADER.len()));
    let _ = writeln!(out);
    let _ = writeln!(out, "Network: {network}");
    let _ = writeln!(out);

    if want_receive {
        let _ = writeln!(out, "Receive addresses:");
        write_address_rows(&mut out, &derived.receive_derived);
        let _ = writeln!(out);
    }
    if want_change {
        let _ = writeln!(out, "Change addresses:");
        write_address_rows(&mut out, &derived.change_derived);
        let _ = writeln!(out);
    }
    out
}

/// Write one indented `index  address` row per derived address, or a single note
/// when the chain is empty (a single-path descriptor has no change branch).
fn write_address_rows(out: &mut String, addresses: &[DerivedAddress]) {
    use std::fmt::Write as _;
    if addresses.is_empty() {
        let _ = writeln!(
            out,
            "  (none; this descriptor has no separate change branch)"
        );
        return;
    }
    for address in addresses {
        let _ = writeln!(out, "  {:>4}  {}", address.index, address.address);
    }
}

/// Render the `compare-address` outcome (match / no-match / invalid-for-network)
/// to stdout, as JSON or human text. All three outcomes go to stdout so a `--json`
/// consumer always reads the result there; the exit code disambiguates them.
fn render_compare_result(
    network: Network,
    provided: &str,
    matched_at: Option<MatchLocation>,
    invalid_reason: Option<&str>,
    emit_json: bool,
) -> String {
    if emit_json {
        let mut value = json!({
            "network": network.to_string(),
            "provided": provided,
            "matched": invalid_reason.is_none() && matched_at.is_some(),
            "matched_at": matched_at,
        });
        if let Some(reason) = invalid_reason {
            value["error"] = json!("address_invalid_for_network");
            value["error_detail"] = json!(reason);
        }
        return value.to_string() + "\n";
    }

    use std::fmt::Write as _;
    const HEADER: &str = "Bitcoin Lifeboat - Address Comparison";
    let mut out = String::new();
    let _ = writeln!(out, "{HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HEADER.len()));
    let _ = writeln!(out);
    let _ = writeln!(out, "Network: {network}");
    let _ = writeln!(out, "Address: {provided}");
    let _ = writeln!(out);
    if let Some(reason) = invalid_reason {
        let _ = writeln!(out, "Result:  INVALID - {reason}");
    } else if let Some(location) = matched_at {
        let _ = writeln!(
            out,
            "Result:  MATCH at {} index {}",
            location.chain, location.index
        );
    } else {
        let _ = writeln!(
            out,
            "Result:  NO MATCH in the searched receive/change range"
        );
    }
    out
}

/// The shared pipeline: validate the scoring engine, resolve the descriptor text,
/// screen it for secrets, then parse and build the report. Returns the built
/// report, or an early-exit [`CommandOutput`] for the refusal / error / verdict.
/// `emit_json` selects JSON vs. human rendering for the early-exit cases.
fn prepare_report(
    args: &AuditArgs,
    emit_json: bool,
    created_at: &str,
    app_version: &str,
    stdin: impl Read,
) -> Result<ReadinessReport, CommandOutput> {
    if let Err(message) = validate_scoring_engine(args.scoring_engine.as_deref()) {
        return Err(invalid_args(&message, emit_json));
    }

    let text = resolve_input(args, stdin).map_err(|e| hard_error(&e, emit_json))?;

    if let Some(block) = screen_for_secrets(&text, emit_json) {
        return Err(block);
    }

    let parsed = parse_descriptor(&text).map_err(|e| parse_failure(&e, emit_json))?;

    let mut input = ReportInput::new(&parsed, created_at)
        .with_app_version(app_version)
        .with_derive_count(args.derive_count);
    if let Some(network) = args.network.map(to_network) {
        input = input.with_network(network);
    }
    if let Some(address) = args.known_address.as_deref() {
        input = input.with_known_address(address);
    }
    Ok(build_report(&input))
}

/// The report serialized as the canonical compact §19.1 JSON, newline-terminated.
fn report_json_line(report: &ReadinessReport) -> String {
    let mut json = report.to_json();
    json.push('\n');
    json
}

/// Validate the `--scoring-engine` pin. Absent (or `latest`) uses the current
/// engine; an explicit version must match the one this build provides.
fn validate_scoring_engine(requested: Option<&str>) -> Result<(), String> {
    match requested {
        None => Ok(()),
        Some(version)
            if version.eq_ignore_ascii_case("latest") || version == SCORING_ENGINE_VERSION =>
        {
            Ok(())
        }
        Some(version) => Err(format!(
            "scoring-engine version `{version}` is not available; this build provides \
             {SCORING_ENGINE_VERSION}"
        )),
    }
}

/// Map the CLI-local [`NetworkArg`] to the `rust-bitcoin` network.
fn to_network(arg: NetworkArg) -> Network {
    match arg {
        NetworkArg::Mainnet => Network::Bitcoin,
        NetworkArg::Testnet => Network::Testnet,
        NetworkArg::Signet => Network::Signet,
        NetworkArg::Regtest => Network::Regtest,
    }
}

/// Resolve the descriptor text from exactly one of `--descriptor` / `--stdin` /
/// `--file` (clap guarantees exactly one). I/O failures map to `E-FS-001`
/// (→ exit 6); the error context names the source but never the file contents.
fn resolve_input(args: &AuditArgs, mut stdin: impl Read) -> Result<String, LifeboatError> {
    if let Some(descriptor) = &args.descriptor {
        Ok(descriptor.clone())
    } else if args.stdin {
        let mut buffer = String::new();
        stdin.read_to_string(&mut buffer).map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context("could not read the descriptor from standard input")
                .with_source(e)
        })?;
        Ok(buffer)
    } else if let Some(path) = &args.file {
        std::fs::read_to_string(path).map_err(|e| {
            LifeboatError::new(ErrorCode::FileNotFound)
                .with_context(format!(
                    "could not read descriptor file `{}`",
                    path.display()
                ))
                .with_source(e)
        })
    } else {
        // Unreachable: the clap `descriptor_source` group is required.
        Err(LifeboatError::new(ErrorCode::InputEmpty).with_context("no descriptor source given"))
    }
}

/// Screen the input for pasted secrets **before** any parsing (the §13.5
/// invariant). A confirmed secret (`Block`) is refused with exit 5 and is never
/// echoed — only its leak-free `E-SECRET-*` reason code is reported. `Allow`
/// (a normal watch-only descriptor) and `Warn` (suspected but unconfirmed, which
/// is implausible for descriptor text) proceed to parsing.
fn screen_for_secrets(text: &str, emit_json: bool) -> Option<CommandOutput> {
    let report = detect_secret(SecretString::from(text.to_owned()));
    if !report.is_blocked() {
        return None;
    }
    let reasons: Vec<&str> = report.reason_codes().iter().map(|c| c.as_str()).collect();
    let headline = report
        .headline()
        .unwrap_or("This looks like a real Bitcoin secret. Input rejected.");
    let stderr = if emit_json {
        json!({
            "error": "sensitive_input_detected",
            "action": "block",
            "reasons": reasons,
        })
        .to_string()
            + "\n"
    } else {
        let mut message = format!("lifeboat: {headline}\n");
        if !reasons.is_empty() {
            message.push_str(&format!("Detected: {}\n", reasons.join(", ")));
        }
        message.push_str(
            "Lifeboat never needs a real secret. Audit a watch-only descriptor instead.\n",
        );
        message
    };
    Some(CommandOutput {
        stdout: String::new(),
        stderr,
        code: ExitCode::SecretDetected,
    })
}

/// Turn a descriptor parse failure into a Not Ready *verdict* (exit 2, per §23.2
/// / US-035) rather than a raw error. Uses only leak-free catalog text — never
/// the input or the chained library error (which can quote the descriptor).
fn parse_failure(error: &LifeboatError, emit_json: bool) -> CommandOutput {
    let code = error.code();
    let stdout = if emit_json {
        json!({
            "status": "not_ready",
            "error": { "code": code.as_str(), "title": code.title() },
        })
        .to_string()
            + "\n"
    } else {
        format!(
            "{HUMAN_HEADER}\n\nStatus:  Not Ready\n\nThe descriptor could not be analyzed: {} \
             ({}).\n{}\n",
            code.title(),
            code.as_str(),
            code.action(),
        )
    };
    CommandOutput {
        stdout,
        stderr: String::new(),
        code: ExitCode::Critical,
    }
}

/// Turn a hard error (file/IO, etc.) into a stderr message + the §23.2 exit code.
/// The message is the safe context we attached (e.g. a file path), or the code's
/// catalog title — never the descriptor or a chained error string.
fn hard_error(error: &LifeboatError, emit_json: bool) -> CommandOutput {
    let code = error.code();
    let exit = ExitCode::from_error(error);
    let detail = error.context().unwrap_or_else(|| code.title());
    let stderr = if emit_json {
        json!({ "error": code.as_str(), "message": detail }).to_string() + "\n"
    } else {
        format!("lifeboat: {detail} ({})\n", code.as_str())
    };
    CommandOutput {
        stdout: String::new(),
        stderr,
        code: exit,
    }
}

/// A bad-argument error (e.g. an unknown `--scoring-engine`): stderr message,
/// exit 4.
fn invalid_args(message: &str, emit_json: bool) -> CommandOutput {
    let stderr = if emit_json {
        json!({ "error": "invalid_arguments", "message": message }).to_string() + "\n"
    } else {
        format!("lifeboat: {message}\n")
    };
    CommandOutput {
        stdout: String::new(),
        stderr,
        code: ExitCode::InvalidArgs,
    }
}

/// Render the human-readable audit summary (the default `audit-descriptor`
/// output). Plain ASCII, deterministic, and free of any "safe"/"guaranteed"
/// overclaim — the strings are asserted against the §16.8 lint in tests.
fn render_human_audit(report: &ReadinessReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "{HUMAN_HEADER}");
    let _ = writeln!(out, "{}", "=".repeat(HUMAN_HEADER.len()));
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "Status:  {}  (score: {}/100)",
        report.score.headline, report.score.numeric
    );
    match &report.network {
        Some(network) => {
            let _ = writeln!(out, "Network: {network}");
        }
        None => {
            let _ = writeln!(out, "Network: (undetermined)");
        }
    }
    let wallet_type = report
        .wallet_summary
        .wallet_type
        .as_deref()
        .unwrap_or("unknown");
    let _ = writeln!(
        out,
        "Wallet:  {}, {}, {} key(s)",
        wallet_type, report.wallet_summary.script_type, report.wallet_summary.key_count
    );
    if let Some(survivability) = &report.survivability {
        let _ = writeln!(
            out,
            "Survivability: lose 1 signer -> {}; lose 2 signers -> {}",
            survivability.lose_1_signer, survivability.lose_2_signers
        );
    }
    let _ = writeln!(out);

    if !report.passes.is_empty() {
        let _ = writeln!(out, "What passed:");
        for pass in &report.passes {
            let _ = writeln!(out, "  [PASS] {}", pass.title);
        }
        let _ = writeln!(out);
    }

    if !report.warnings.is_empty() {
        let _ = writeln!(out, "Needs attention:");
        for warning in &report.warnings {
            let _ = writeln!(out, "  [WARN] {}  {}", warning.code.as_str(), warning.title);
            let _ = writeln!(out, "         {}", warning.recommended_fix);
        }
        let _ = writeln!(out);
    }

    if !report.critical_issues.is_empty() {
        let _ = writeln!(out, "Critical issues:");
        for issue in &report.critical_issues {
            let _ = writeln!(out, "  [FAIL] {}  {}", issue.code.as_str(), issue.title);
            let _ = writeln!(out, "         {}", issue.description);
        }
        let _ = writeln!(out);
    }

    if !report.next_steps.is_empty() {
        let _ = writeln!(out, "What to do next:");
        for step in &report.next_steps {
            let _ = writeln!(
                out,
                "  {}. {}  ({})",
                step.priority, step.action, step.effort
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "lifeboat v{} | scoring engine {} | {}",
        report.app_version, report.scoring_engine_version, report.report_hash
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", report.disclaimer_short.trim());

    out
}

/// Current UTC time as an ISO-8601 `YYYY-MM-DDThh:mm:ssZ` string, for stamping a
/// report's `created_at`. The clock is read here, at the CLI boundary; the report
/// engine never reads it (PRD §19 / §27 determinism).
#[must_use]
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    unix_to_iso8601(secs)
}

/// Render a Unix timestamp (seconds since the epoch, UTC) as ISO-8601 using
/// Howard Hinnant's `civil_from_days` algorithm — no date-library dependency
/// (the same approach `wallet-imports` uses for export timestamps).
fn unix_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 -> civil (y, m, d), shifting the era to March-based.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// --- US-039: generate-runbook, completions, and man -----------------------

/// The placeholder report hash stamped into a CLI-generated runbook footer.
///
/// A `generate-runbook` runbook is a standalone template, not the companion to a
/// specific saved [`ReadinessReport`], so there is no real report hash to cite. A
/// constant, obviously-null `sha256:00…00` keeps the footer field populated *and*
/// the output byte-deterministic (PRD §19 / §27) without implying a report that
/// does not exist.
const RUNBOOK_PLACEHOLDER_REPORT_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The minimal `<style>` block for the `--format html` document.
const RUNBOOK_HTML_STYLE: &str = "<style>\n\
body { font-family: system-ui, -apple-system, sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }\n\
h1, h2, h3 { line-height: 1.25; }\n\
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }\n\
pre { white-space: pre-wrap; word-break: break-all; background: #f4f4f4; padding: 0.75rem; border-radius: 0.25rem; }\n\
</style>\n";

/// A runbook template selected by `--template`: one of the two `runbook-engine`
/// families (owner singlesig/multisig, or heir/workshop/business).
#[derive(Debug, Clone, Copy)]
enum RunbookTemplateKind {
    /// An owner recovery runbook.
    Owner(OwnerTemplate),
    /// A heir / workshop / business runbook.
    Heir(HeirTemplate),
}

/// Resolve a `--template` id to its template by scanning both families' stable
/// names (so this never drifts as templates are added); `None` for an unknown id.
fn resolve_template(id: &str) -> Option<RunbookTemplateKind> {
    if let Some(template) = OwnerTemplate::ALL.into_iter().find(|t| t.name() == id) {
        return Some(RunbookTemplateKind::Owner(template));
    }
    if let Some(template) = HeirTemplate::ALL.into_iter().find(|t| t.name() == id) {
        return Some(RunbookTemplateKind::Heir(template));
    }
    None
}

/// The comma-separated list of every valid template id (for an error message).
fn known_template_ids() -> String {
    OwnerTemplate::ALL
        .iter()
        .map(|t| t.name())
        .chain(HeirTemplate::ALL.iter().map(|t| t.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `template`'s document title (used as the HTML `<title>`).
fn runbook_title(template: RunbookTemplateKind) -> &'static str {
    match template {
        RunbookTemplateKind::Owner(t) => t.title(),
        RunbookTemplateKind::Heir(t) => t.title(),
    }
}

/// The default `(script_type, threshold, key_count, has_passphrase)` for a
/// template — used for a blank runbook and as the fallback when a supplied
/// descriptor is singlesig.
fn template_defaults(template: RunbookTemplateKind) -> (&'static str, Option<u32>, u32, bool) {
    match template {
        RunbookTemplateKind::Owner(t) => match t.quorum() {
            Some((m, n)) => ("wsh(sortedmulti)", Some(m), n, false),
            None => ("wpkh", None, 1, t == OwnerTemplate::SinglesigPassphrase),
        },
        RunbookTemplateKind::Heir(t) => match t {
            HeirTemplate::HeirMultisig2of3 | HeirTemplate::BusinessTreasury => {
                ("wsh(sortedmulti)", Some(2), 3, false)
            }
            HeirTemplate::HeirMultisig3of5 => ("wsh(sortedmulti)", Some(3), 5, false),
            HeirTemplate::LianaTimelock => ("wsh(or_d timelock)", None, 2, false),
            HeirTemplate::HeirSinglesigPassphrase => ("wpkh", None, 1, true),
            HeirTemplate::HeirSinglesigBasic | HeirTemplate::MeetupWorkshop => {
                ("wpkh", None, 1, false)
            }
        },
    }
}

/// Build the runbook data, pre-filling from a parsed descriptor when one was
/// supplied and otherwise leaving template-appropriate blanks for manual entry.
fn build_runbook_data(
    template: RunbookTemplateKind,
    parsed: Option<&ParsedDescriptor>,
    app_version: &str,
) -> RunbookData {
    let (def_script, def_threshold, def_n, def_passphrase) = template_defaults(template);

    // A supplied descriptor pins the actual M/N (when multisig); otherwise the
    // template defaults stand in. `threshold`/`key_count` are `usize` upstream.
    let (threshold, key_count) = match parsed.and_then(|p| p.multisig_info()) {
        Some(info) => (Some(info.threshold() as u32), info.key_count() as u32),
        None => (def_threshold, def_n),
    };
    let signers = parsed.map(signers_from_descriptor).unwrap_or_default();
    let descriptor = parsed.map(|p| p.canonical().to_owned()).unwrap_or_default();

    RunbookData::new(
        RunbookWalletSummary::new(def_script, threshold, key_count),
        descriptor,
        String::new(), // next_drill: a blank field the owner fills in after a drill
        RUNBOOK_PLACEHOLDER_REPORT_HASH,
        app_version,
    )
    .with_signers(signers)
    .with_passphrase(def_passphrase)
}

/// Build the §17.8 signer list from a descriptor's key origins: one labelled
/// signer per key, with its fingerprint and origin path (blank when the
/// descriptor omits them). No xpubs or device models — those are not present in a
/// watch-only descriptor.
fn signers_from_descriptor(parsed: &ParsedDescriptor) -> Vec<Signer> {
    parsed
        .key_origins()
        .iter()
        .enumerate()
        .map(|(index, origin)| {
            Signer::new(
                format!("Signer {}", signer_letter(index)),
                origin.fingerprint_hex().unwrap_or_default(),
                origin.derivation_path_display().unwrap_or_default(),
            )
        })
        .collect()
}

/// `A`, `B`, … for signer labels (a multisig has at most 15 keys, PRD §17.2).
fn signer_letter(index: usize) -> char {
    char::from(b'A'.wrapping_add((index % 26) as u8))
}

/// Render `template`'s runbook Markdown in `mode`.
fn render_runbook_markdown(
    template: RunbookTemplateKind,
    data: &RunbookData,
    mode: RedactionMode,
) -> String {
    match template {
        RunbookTemplateKind::Owner(t) => render_owner_markdown(t, data, mode),
        RunbookTemplateKind::Heir(t) => render_heir_markdown(t, data, mode),
    }
}

/// Render `template`'s runbook PDF in `mode` (A4, the auto backend — which falls
/// back to the always-available pure-Rust renderer when no Typst binary is
/// bundled, so this does not require an external dependency).
fn render_runbook_pdf(
    template: RunbookTemplateKind,
    data: &RunbookData,
    mode: RedactionMode,
) -> Result<Vec<u8>, LifeboatError> {
    match template {
        RunbookTemplateKind::Owner(t) => {
            render_owner_pdf(t, data, PdfBackend::Auto, PageSize::A4, mode)
        }
        RunbookTemplateKind::Heir(t) => {
            render_heir_pdf(t, data, PdfBackend::Auto, PageSize::A4, mode)
        }
    }
}

/// Render the runbook to the bytes for `format`. The text formats are derived
/// from the Markdown; `pdf` goes through the PDF backend.
fn render_runbook_bytes(
    template: RunbookTemplateKind,
    data: &RunbookData,
    mode: RedactionMode,
    format: RunbookFormatArg,
) -> Result<Vec<u8>, LifeboatError> {
    let bytes = match format {
        RunbookFormatArg::Md => render_runbook_markdown(template, data, mode).into_bytes(),
        RunbookFormatArg::Txt => {
            markdown_to_text(&render_runbook_markdown(template, data, mode)).into_bytes()
        }
        RunbookFormatArg::Html => markdown_to_html(
            &render_runbook_markdown(template, data, mode),
            runbook_title(template),
        )
        .into_bytes(),
        RunbookFormatArg::Pdf => render_runbook_pdf(template, data, mode)?,
    };
    Ok(bytes)
}

/// The `--format` value as its CLI spelling (for the write confirmation line).
fn format_label(format: RunbookFormatArg) -> &'static str {
    match format {
        RunbookFormatArg::Pdf => "pdf",
        RunbookFormatArg::Md => "md",
        RunbookFormatArg::Txt => "txt",
        RunbookFormatArg::Html => "html",
    }
}

/// Run `generate-runbook` (PRD §17.10.4): render a recovery / inheritance runbook
/// from a bundled template — optionally pre-filled from a watch-only descriptor —
/// in `public-safe` (default) or `private` mode, as `pdf` (default) / `md` / `txt`
/// / `html`. With `--output` the runbook is written to a file; otherwise a text
/// runbook is streamed to stdout (a `pdf` requires `--output`, being binary).
pub fn run_generate_runbook(args: &GenerateRunbookArgs, app_version: &str) -> CommandOutput {
    // generate-runbook has no machine-readable mode; refusals/errors are plain.
    let emit_json = false;

    let template = match resolve_template(&args.template) {
        Some(template) => template,
        None => {
            return invalid_args(
                &format!(
                    "unknown runbook template '{}'. Available templates: {}.",
                    args.template,
                    known_template_ids()
                ),
                emit_json,
            )
        }
    };
    let mode = match args.mode {
        RunbookModeArg::PublicSafe => RedactionMode::PublicSafe,
        RunbookModeArg::Private => RedactionMode::Private,
    };

    // A supplied descriptor is screened for secrets and parsed before use; a
    // confirmed secret is refused (exit 5) and never written into the runbook.
    let parsed = match &args.descriptor {
        Some(descriptor) => match screen_and_parse(descriptor, emit_json) {
            Ok(parsed) => Some(parsed),
            Err(early) => return early,
        },
        None => None,
    };
    let data = build_runbook_data(template, parsed.as_ref(), app_version);

    // A PDF is binary and must go to a file, never to a terminal.
    if matches!(args.format, RunbookFormatArg::Pdf) && args.output.is_none() {
        return invalid_args(
            "the pdf format requires --output <PATH> (a PDF is binary and cannot be written to \
             the terminal); use --format md|txt|html to write to standard output",
            emit_json,
        );
    }

    let bytes = match render_runbook_bytes(template, &data, mode, args.format) {
        Ok(bytes) => bytes,
        Err(error) => return hard_error(&error, emit_json),
    };

    match &args.output {
        Some(path) => match std::fs::write(path, &bytes) {
            Ok(()) => CommandOutput {
                stdout: format!(
                    "Wrote the {} runbook ({} bytes) to {}.\n",
                    format_label(args.format),
                    bytes.len(),
                    path.display()
                ),
                stderr: String::new(),
                code: ExitCode::Success,
            },
            Err(_) => hard_error(&LifeboatError::new(ErrorCode::CannotWrite), emit_json),
        },
        // No --output: stream the (text) runbook to stdout. The pdf-without-output
        // case was already refused above, so `bytes` here is always valid UTF-8.
        None => CommandOutput {
            stdout: String::from_utf8_lossy(&bytes).into_owned(),
            stderr: String::new(),
            code: ExitCode::Success,
        },
    }
}

/// Convert runbook Markdown to readable plain text by stripping the markup that
/// does not render in a terminal. Conservative by design: it removes ATX heading
/// markers, bold (`**`) and inline-code (`` ` ``) markers, and code-fence
/// delimiters, but leaves `*` / `_` untouched so it can never corrupt a
/// descriptor wildcard (`/0/*`) or a derivation path.
fn markdown_to_text(markdown: &str) -> String {
    let mut out = String::with_capacity(markdown.len());
    for line in markdown.lines() {
        let line = line.trim_end();
        if line.trim_start().starts_with("```") {
            continue; // drop the code-fence delimiter, keep its contents
        }
        let line = strip_atx_heading(line);
        let line = line.replace("**", "");
        let line = line.replace('`', "");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Strip a leading ATX heading marker (`## Title` → `Title`); other lines pass
/// through unchanged.
fn strip_atx_heading(line: &str) -> &str {
    let stripped = line.trim_start_matches('#');
    if stripped.len() == line.len() {
        line
    } else {
        stripped.trim_start()
    }
}

/// Convert runbook Markdown to a minimal, self-contained HTML document. Block
/// structure (headings, bullet lists, code fences, paragraphs) maps to HTML
/// elements; inline text is HTML-escaped and otherwise left verbatim (no inline
/// emphasis parsing) so a descriptor or address can never be corrupted.
fn markdown_to_html(markdown: &str, title: &str) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str("<title>");
    html.push_str(&escape_html(title));
    html.push_str("</title>\n");
    html.push_str(RUNBOOK_HTML_STYLE);
    html.push_str("</head>\n<body>\n");
    html.push_str(&markdown_body_to_html(markdown));
    html.push_str("</body>\n</html>\n");
    html
}

/// The `<body>` content for [`markdown_to_html`].
fn markdown_body_to_html(markdown: &str) -> String {
    let mut out = String::new();
    let mut in_list = false;
    let mut in_code = false;
    let mut paragraph: Vec<String> = Vec::new();

    for line in markdown.lines() {
        let line = line.trim_end();
        let body = line.trim_start();

        if body.starts_with("```") {
            flush_paragraph(&mut out, &mut paragraph);
            flush_list(&mut out, &mut in_list);
            if in_code {
                out.push_str("</pre>\n");
                in_code = false;
            } else {
                out.push_str("<pre>");
                in_code = true;
            }
            continue;
        }
        if in_code {
            out.push_str(&escape_html(line));
            out.push('\n');
            continue;
        }
        if body.is_empty() {
            flush_paragraph(&mut out, &mut paragraph);
            flush_list(&mut out, &mut in_list);
            continue;
        }

        let hashes = body.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && body[hashes..].starts_with(' ') {
            flush_paragraph(&mut out, &mut paragraph);
            flush_list(&mut out, &mut in_list);
            let text = escape_html(body[hashes..].trim_start());
            out.push_str(&format!("<h{hashes}>{text}</h{hashes}>\n"));
            continue;
        }

        if let Some(item) = bullet_item(body) {
            flush_paragraph(&mut out, &mut paragraph);
            if !in_list {
                out.push_str("<ul>\n");
                in_list = true;
            }
            out.push_str(&format!("<li>{}</li>\n", escape_html(item)));
            continue;
        }

        flush_list(&mut out, &mut in_list);
        paragraph.push(escape_html(line));
    }
    flush_paragraph(&mut out, &mut paragraph);
    flush_list(&mut out, &mut in_list);
    if in_code {
        out.push_str("</pre>\n");
    }
    out
}

/// Close an open paragraph, emitting `<p>…</p>` with `<br>` between its lines.
fn flush_paragraph(out: &mut String, paragraph: &mut Vec<String>) {
    if !paragraph.is_empty() {
        out.push_str("<p>");
        out.push_str(&paragraph.join("<br>\n"));
        out.push_str("</p>\n");
        paragraph.clear();
    }
}

/// Close an open `<ul>` list.
fn flush_list(out: &mut String, in_list: &mut bool) {
    if *in_list {
        out.push_str("</ul>\n");
        *in_list = false;
    }
}

/// The text of a Markdown bullet item (`- x` / `* x` / `+ x`), or `None`.
fn bullet_item(line: &str) -> Option<&str> {
    ["- ", "* ", "+ "]
        .into_iter()
        .find_map(|marker| line.strip_prefix(marker))
}

/// HTML-escape `&`, `<`, `>`, and `"`.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

/// Run `completions` (PRD §17.10 / US-039): print a shell-completion script to
/// stdout, generated from the live `build_command()` clap tree so it always
/// matches the real command surface.
pub fn run_completions(args: &CompletionsArgs) -> CommandOutput {
    let mut command = crate::cli::build_command();
    let bin_name = command.get_name().to_owned();
    let mut buffer: Vec<u8> = Vec::new();
    match args.shell {
        CompletionShell::Bash => {
            clap_complete::generate(
                clap_complete::shells::Bash,
                &mut command,
                bin_name,
                &mut buffer,
            );
        }
        CompletionShell::Zsh => {
            clap_complete::generate(
                clap_complete::shells::Zsh,
                &mut command,
                bin_name,
                &mut buffer,
            );
        }
        CompletionShell::Fish => {
            clap_complete::generate(
                clap_complete::shells::Fish,
                &mut command,
                bin_name,
                &mut buffer,
            );
        }
        CompletionShell::PowerShell => {
            clap_complete::generate(
                clap_complete::shells::PowerShell,
                &mut command,
                bin_name,
                &mut buffer,
            );
        }
        CompletionShell::Nushell => {
            clap_complete::generate(
                clap_complete_nushell::Nushell,
                &mut command,
                bin_name,
                &mut buffer,
            );
        }
    }
    CommandOutput {
        stdout: String::from_utf8_lossy(&buffer).into_owned(),
        stderr: String::new(),
        code: ExitCode::Success,
    }
}

/// Run `man` (US-039): render the CLI's manual page in roff to stdout (pipe it to
/// `man/man1/lifeboat.1` or a pager). Built from the same `build_command()` tree
/// as the completions, so it cannot drift from the real command surface.
pub fn run_man() -> CommandOutput {
    let command = crate::cli::build_command();
    let mut buffer: Vec<u8> = Vec::new();
    match clap_mangen::Man::new(command).render(&mut buffer) {
        Ok(()) => CommandOutput {
            stdout: String::from_utf8_lossy(&buffer).into_owned(),
            stderr: String::new(),
            code: ExitCode::Success,
        },
        // Rendering writes to an in-memory buffer, so a failure here is not a real
        // file-I/O fault; surface it as the internal-error code (§23.2 row 20).
        Err(_) => CommandOutput {
            stdout: String::new(),
            stderr: "Failed to render the manual page.\n".to_owned(),
            code: ExitCode::Internal,
        },
    }
}

#[cfg(test)]
mod runbook_tests {
    use super::*;
    use lifeboat_core::report_engine::passes_anti_overclaim_lint;

    const VERSION: &str = "0.1.0";

    fn singlesig_descriptor() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
        ))
        .trim()
    }
    fn multisig_descriptor() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/descriptors/multisig/wsh_sortedmulti_2of3.txt"
        ))
        .trim()
    }
    fn xprv_descriptor() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/descriptors/invalid/contains_xprv.txt"
        ))
        .trim()
    }

    fn gen_args(
        template: &str,
        descriptor: Option<&str>,
        output: Option<std::path::PathBuf>,
        mode: RunbookModeArg,
        format: RunbookFormatArg,
    ) -> GenerateRunbookArgs {
        GenerateRunbookArgs {
            template: template.to_owned(),
            descriptor: descriptor.map(str::to_owned),
            output,
            mode,
            format,
        }
    }

    fn temp_output_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "lifeboat-runbook-{tag}-{}-{}.out",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn produces_a_runbook_for_a_template() {
        let out = run_generate_runbook(
            &gen_args(
                "singlesig-basic",
                None,
                None,
                RunbookModeArg::PublicSafe,
                RunbookFormatArg::Md,
            ),
            VERSION,
        );
        assert_eq!(out.code, ExitCode::Success);
        // A real runbook is a substantial document, not a stub line.
        assert!(
            out.stdout.len() > 100,
            "runbook markdown was unexpectedly short"
        );
    }

    #[test]
    fn every_template_id_renders_markdown() {
        let ids = OwnerTemplate::ALL
            .iter()
            .map(|t| t.name())
            .chain(HeirTemplate::ALL.iter().map(|t| t.name()));
        for id in ids {
            let out = run_generate_runbook(
                &gen_args(
                    id,
                    None,
                    None,
                    RunbookModeArg::PublicSafe,
                    RunbookFormatArg::Md,
                ),
                VERSION,
            );
            assert_eq!(out.code, ExitCode::Success, "template {id} should render");
            assert!(!out.stdout.is_empty(), "template {id} produced nothing");
        }
    }

    #[test]
    fn txt_and_html_formats_render() {
        let txt = run_generate_runbook(
            &gen_args(
                "multisig-2of3",
                None,
                None,
                RunbookModeArg::PublicSafe,
                RunbookFormatArg::Txt,
            ),
            VERSION,
        );
        assert_eq!(txt.code, ExitCode::Success);
        assert!(!txt.stdout.is_empty());

        let html = run_generate_runbook(
            &gen_args(
                "multisig-2of3",
                None,
                None,
                RunbookModeArg::PublicSafe,
                RunbookFormatArg::Html,
            ),
            VERSION,
        );
        assert_eq!(html.code, ExitCode::Success);
        assert!(html.stdout.starts_with("<!DOCTYPE html>"));
        assert!(html.stdout.contains("</html>"));
    }

    #[test]
    fn pdf_format_writes_a_valid_pdf_file() {
        let path = temp_output_path("pdf");
        let out = run_generate_runbook(
            &gen_args(
                "singlesig-basic",
                None,
                Some(path.clone()),
                RunbookModeArg::PublicSafe,
                RunbookFormatArg::Pdf,
            ),
            VERSION,
        );
        assert_eq!(out.code, ExitCode::Success);
        let bytes = std::fs::read(&path).expect("the PDF file should exist");
        assert!(bytes.starts_with(b"%PDF"), "output is not a PDF");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pdf_without_output_is_invalid_args() {
        let out = run_generate_runbook(
            &gen_args(
                "singlesig-basic",
                None,
                None,
                RunbookModeArg::PublicSafe,
                RunbookFormatArg::Pdf,
            ),
            VERSION,
        );
        assert_eq!(out.code, ExitCode::InvalidArgs);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn unknown_template_is_invalid_args() {
        let out = run_generate_runbook(
            &gen_args(
                "not-a-real-template",
                None,
                None,
                RunbookModeArg::PublicSafe,
                RunbookFormatArg::Md,
            ),
            VERSION,
        );
        assert_eq!(out.code, ExitCode::InvalidArgs);
    }

    #[test]
    fn a_descriptor_pre_fills_the_runbook() {
        // In private mode a supplied descriptor is rendered into the runbook, so
        // its output differs from the blank template.
        let blank = run_generate_runbook(
            &gen_args(
                "multisig-2of3",
                None,
                None,
                RunbookModeArg::Private,
                RunbookFormatArg::Md,
            ),
            VERSION,
        );
        let filled = run_generate_runbook(
            &gen_args(
                "multisig-2of3",
                Some(multisig_descriptor()),
                None,
                RunbookModeArg::Private,
                RunbookFormatArg::Md,
            ),
            VERSION,
        );
        assert_eq!(blank.code, ExitCode::Success);
        assert_eq!(filled.code, ExitCode::Success);
        assert_ne!(blank.stdout, filled.stdout);
    }

    #[test]
    fn a_secret_descriptor_is_blocked_and_never_echoed() {
        let out = run_generate_runbook(
            &gen_args(
                "singlesig-basic",
                Some(xprv_descriptor()),
                None,
                RunbookModeArg::Private,
                RunbookFormatArg::Md,
            ),
            VERSION,
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert!(
            out.stdout.is_empty(),
            "a blocked secret must not produce a runbook"
        );
        assert!(!out.stdout.contains("tprv"));
        assert!(!out.stderr.contains("tprv"));
    }

    #[test]
    fn generate_runbook_is_deterministic() {
        let args = gen_args(
            "heir-multisig-2of3",
            Some(multisig_descriptor()),
            None,
            RunbookModeArg::Private,
            RunbookFormatArg::Md,
        );
        let first = run_generate_runbook(&args, VERSION);
        let second = run_generate_runbook(&args, VERSION);
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(first.code, second.code);
    }

    #[test]
    fn rendered_runbook_passes_the_anti_overclaim_lint() {
        for format in [
            RunbookFormatArg::Md,
            RunbookFormatArg::Txt,
            RunbookFormatArg::Html,
        ] {
            let out = run_generate_runbook(
                &gen_args(
                    "heir-singlesig-basic",
                    Some(singlesig_descriptor()),
                    None,
                    RunbookModeArg::PublicSafe,
                    format,
                ),
                VERSION,
            );
            assert!(
                passes_anti_overclaim_lint(&out.stdout),
                "{format:?} runbook output tripped the anti-overclaim lint"
            );
        }
    }

    #[test]
    fn completions_generate_for_all_five_shells() {
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
            CompletionShell::PowerShell,
            CompletionShell::Nushell,
        ] {
            let out = run_completions(&CompletionsArgs { shell });
            assert_eq!(out.code, ExitCode::Success);
            assert!(!out.stdout.is_empty(), "{shell:?} completion was empty");
            assert!(
                out.stdout.contains("lifeboat"),
                "{shell:?} script is missing the bin name"
            );
        }
    }

    #[test]
    fn completion_scripts_track_the_live_command_tree() {
        // Generated off `build_command()`, so a new subcommand appears with no
        // hand-maintained list to forget.
        let out = run_completions(&CompletionsArgs {
            shell: CompletionShell::Bash,
        });
        assert!(out.stdout.contains("generate-runbook"));
    }

    #[test]
    fn man_page_builds() {
        let out = run_man();
        assert_eq!(out.code, ExitCode::Success);
        assert!(!out.stdout.is_empty());
        // A roff man page opens with a `.TH` title-header macro.
        assert!(out.stdout.contains(".TH"));
        assert!(out.stdout.to_lowercase().contains("lifeboat"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lifeboat_core::report_engine::passes_anti_overclaim_lint;

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

    // `include_str!`/`concat!` require string *literals*, so the fixture paths
    // cannot be `const`-indirected — wrap each in a helper that feeds a literal.
    fn singlesig() -> &'static str {
        fixture!("descriptors/singlesig/wpkh_valid.txt")
    }
    fn multisig() -> &'static str {
        fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt")
    }
    fn contains_xprv() -> &'static str {
        fixture!("descriptors/invalid/contains_xprv.txt")
    }

    const CREATED_AT: &str = "2024-01-15T00:00:00Z";
    const APP_VERSION: &str = "0.1.0";

    fn args_for(descriptor: &str, network: Option<NetworkArg>) -> AuditArgs {
        AuditArgs {
            file: None,
            stdin: false,
            descriptor: Some(descriptor.to_owned()),
            known_address: None,
            network,
            derive_count: 10,
            strict: false,
            scoring_engine: None,
        }
    }

    fn human() -> GlobalArgs {
        GlobalArgs {
            json: false,
            no_color: true,
            quiet: false,
            verbose: false,
        }
    }

    #[test]
    fn unix_to_iso8601_matches_known_vectors() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        // Bitcoin genesis block timestamp.
        assert_eq!(unix_to_iso8601(1_231_006_505), "2009-01-03T18:15:05Z");
        assert_eq!(unix_to_iso8601(1_705_276_800), "2024-01-15T00:00:00Z");
    }

    #[test]
    fn report_json_is_byte_identical_across_two_runs() {
        let args = args_for(multisig(), Some(NetworkArg::Testnet));
        let first = run_report_json(&args, CREATED_AT, APP_VERSION, std::io::empty());
        let second = run_report_json(&args, CREATED_AT, APP_VERSION, std::io::empty());
        assert_eq!(
            first.stdout, second.stdout,
            "report-json must be deterministic"
        );
        assert_eq!(first.code, second.code);
    }

    #[test]
    fn report_json_equals_the_engine_output() {
        let descriptor = singlesig();
        let out = run_report_json(
            &args_for(descriptor, Some(NetworkArg::Testnet)),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        let parsed = parse_descriptor(descriptor).expect("fixture parses");
        let report = build_report(
            &ReportInput::new(&parsed, CREATED_AT)
                .with_app_version(APP_VERSION)
                .with_network(Network::Testnet)
                .with_derive_count(10),
        );
        assert_eq!(out.stdout, format!("{}\n", report.to_json()));
    }

    #[test]
    fn report_json_singlesig_snapshot() {
        let out = run_report_json(
            &args_for(singlesig(), Some(NetworkArg::Testnet)),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        insta::assert_snapshot!("report_json_singlesig", out.stdout);
    }

    #[test]
    fn report_json_multisig_snapshot() {
        let out = run_report_json(
            &args_for(multisig(), Some(NetworkArg::Testnet)),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        insta::assert_snapshot!("report_json_multisig", out.stdout);
    }

    #[test]
    fn human_audit_singlesig_snapshot() {
        let out = run_audit_descriptor(
            &args_for(singlesig(), Some(NetworkArg::Testnet)),
            &human(),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        insta::assert_snapshot!("human_audit_singlesig", out.stdout);
    }

    #[test]
    fn human_audit_multisig_snapshot() {
        let out = run_audit_descriptor(
            &args_for(multisig(), Some(NetworkArg::Testnet)),
            &human(),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        insta::assert_snapshot!("human_audit_multisig", out.stdout);
    }

    #[test]
    fn human_audit_output_passes_the_anti_overclaim_lint() {
        let single = run_audit_descriptor(
            &args_for(singlesig(), Some(NetworkArg::Testnet)),
            &human(),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert!(passes_anti_overclaim_lint(&single.stdout));
        let multi = run_audit_descriptor(
            &args_for(multisig(), Some(NetworkArg::Testnet)),
            &human(),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert!(passes_anti_overclaim_lint(&multi.stdout));
    }

    #[test]
    fn descriptor_with_private_key_is_blocked_with_exit_5() {
        let xprv_descriptor = contains_xprv();
        let out = run_audit_descriptor(
            &args_for(xprv_descriptor, Some(NetworkArg::Testnet)),
            &human(),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert_eq!(out.code.code(), 5);
        assert!(
            out.stdout.is_empty(),
            "a blocked secret must not reach stdout"
        );
        // The secret content must never appear in any output.
        let combined = format!("{}{}", out.stdout, out.stderr);
        assert!(
            !combined.contains(xprv_descriptor),
            "the descriptor must not be echoed"
        );
        assert!(
            !combined.contains("tprv"),
            "the private key must not be echoed"
        );
    }

    #[test]
    fn unparseable_descriptor_is_not_ready_with_exit_2() {
        let out = run_audit_descriptor(
            &args_for("definitely-not-a-descriptor", None),
            &human(),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert_eq!(out.code, ExitCode::Critical);
        assert_eq!(out.code.code(), 2);
        assert!(out.stdout.contains("Not Ready"));
    }

    #[test]
    fn unparseable_descriptor_json_emits_a_not_ready_object() {
        let out = run_report_json(
            &args_for("garbage(", None),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert_eq!(out.code, ExitCode::Critical);
        assert!(out.stdout.contains("\"status\":\"not_ready\""));
    }

    #[test]
    fn unknown_scoring_engine_is_invalid_args_exit_4() {
        let mut args = args_for(singlesig(), Some(NetworkArg::Testnet));
        args.scoring_engine = Some("9.9.9".to_owned());
        let out = run_report_json(&args, CREATED_AT, APP_VERSION, std::io::empty());
        assert_eq!(out.code, ExitCode::InvalidArgs);
        assert_eq!(out.code.code(), 4);
    }

    #[test]
    fn pinned_scoring_engine_is_accepted() {
        let mut args = args_for(singlesig(), Some(NetworkArg::Testnet));
        args.scoring_engine = Some("0.1.0".to_owned());
        let out = run_report_json(&args, CREATED_AT, APP_VERSION, std::io::empty());
        assert_ne!(out.code, ExitCode::InvalidArgs);
        assert!(out.stdout.contains("\"scoring_engine_version\":\"0.1.0\""));
    }

    #[test]
    fn missing_descriptor_file_is_file_io_exit_6() {
        let mut args = args_for("", None);
        args.descriptor = None;
        args.file = Some(std::path::PathBuf::from(
            "/nonexistent/lifeboat/does-not-exist.txt",
        ));
        let out = run_report_json(&args, CREATED_AT, APP_VERSION, std::io::empty());
        assert_eq!(out.code, ExitCode::FileIo);
        assert_eq!(out.code.code(), 6);
    }

    #[test]
    fn reads_descriptor_from_stdin() {
        let descriptor = singlesig();
        let mut args = args_for("", None);
        args.descriptor = None;
        args.stdin = true;
        args.network = Some(NetworkArg::Testnet);
        let out = run_report_json(&args, CREATED_AT, APP_VERSION, descriptor.as_bytes());
        let inline = run_report_json(
            &args_for(descriptor, Some(NetworkArg::Testnet)),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert_eq!(out.stdout, inline.stdout, "stdin and inline must agree");
    }

    #[test]
    fn strict_promotes_a_warnings_verdict_to_critical() {
        let descriptor = singlesig();
        let parsed = parse_descriptor(descriptor).expect("fixture parses");
        let report = build_report(
            &ReportInput::new(&parsed, CREATED_AT)
                .with_app_version(APP_VERSION)
                .with_network(Network::Testnet)
                .with_derive_count(10),
        );

        let lenient = run_report_json(
            &args_for(descriptor, Some(NetworkArg::Testnet)),
            CREATED_AT,
            APP_VERSION,
            std::io::empty(),
        );
        assert_eq!(
            lenient.code,
            ExitCode::from_status(report.score.status, false)
        );

        let mut strict_args = args_for(descriptor, Some(NetworkArg::Testnet));
        strict_args.strict = true;
        let strict = run_report_json(&strict_args, CREATED_AT, APP_VERSION, std::io::empty());
        assert_eq!(
            strict.code,
            ExitCode::from_status(report.score.status, true)
        );
    }

    #[test]
    fn derive_count_flag_controls_the_address_sample() {
        let mut args = args_for(singlesig(), Some(NetworkArg::Testnet));
        args.derive_count = 3;
        let out = run_report_json(&args, CREATED_AT, APP_VERSION, std::io::empty());
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        let count = value["addresses"]["receive_derived"]
            .as_array()
            .expect("receive_derived array")
            .len();
        assert_eq!(count, 3);
    }

    // --- US-037: derive-addresses, compare-address, checksum ----------------

    fn multipath() -> &'static str {
        fixture!("descriptors/multisig/multipath_2of3.txt")
    }
    fn invalid_checksum() -> &'static str {
        fixture!("descriptors/singlesig/invalid_checksum.txt")
    }

    fn json_global() -> GlobalArgs {
        GlobalArgs {
            json: true,
            no_color: true,
            quiet: false,
            verbose: false,
        }
    }

    fn derive_args(
        descriptor: &str,
        count: u32,
        chain: ChainArg,
        network: Option<NetworkArg>,
    ) -> DeriveArgs {
        DeriveArgs {
            descriptor: descriptor.to_owned(),
            count,
            chain,
            network,
        }
    }

    fn compare_args(descriptor: &str, address: &str, network: Option<NetworkArg>) -> CompareArgs {
        CompareArgs {
            descriptor: descriptor.to_owned(),
            address: address.to_owned(),
            search_range: 10,
            network,
        }
    }

    /// The receive address at index 0 of `descriptor` on testnet (a value to feed
    /// back into `compare-address`).
    fn first_receive_address(descriptor: &str) -> String {
        let parsed = parse_descriptor(descriptor).expect("fixture parses");
        derive_addresses(&parsed, Network::Testnet, 1)
            .expect("derivation succeeds")
            .receive_derived[0]
            .address
            .clone()
    }

    #[test]
    fn derive_addresses_human_snapshot() {
        let out = run_derive_addresses(
            &derive_args(multipath(), 3, ChainArg::Both, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert_eq!(out.code, ExitCode::Success);
        insta::assert_snapshot!("derive_addresses_human", out.stdout);
    }

    #[test]
    fn derive_addresses_json_snapshot() {
        let out = run_derive_addresses(
            &derive_args(multipath(), 3, ChainArg::Both, Some(NetworkArg::Testnet)),
            &json_global(),
        );
        insta::assert_snapshot!("derive_addresses_json", out.stdout);
    }

    #[test]
    fn derive_addresses_is_deterministic() {
        let args = derive_args(multipath(), 5, ChainArg::Both, Some(NetworkArg::Testnet));
        let a = run_derive_addresses(&args, &json_global());
        let b = run_derive_addresses(&args, &json_global());
        assert_eq!(a.stdout, b.stdout, "derive-addresses must be deterministic");
    }

    #[test]
    fn derive_addresses_receive_only_omits_change() {
        let out = run_derive_addresses(
            &derive_args(multipath(), 2, ChainArg::Receive, Some(NetworkArg::Testnet)),
            &json_global(),
        );
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        let addresses = value["addresses"].as_array().expect("addresses array");
        assert_eq!(addresses.len(), 2);
        assert!(
            addresses.iter().all(|a| a["chain"] == "receive"),
            "--chain receive must emit only receive addresses"
        );
    }

    #[test]
    fn derive_addresses_requires_a_network_for_an_ambiguous_tpub() {
        // A `tpub` is shared by testnet/signet/regtest, so without `--network` the
        // network is undeterminable and Lifeboat refuses to guess (exit 4).
        let out =
            run_derive_addresses(&derive_args(multipath(), 5, ChainArg::Both, None), &human());
        assert_eq!(out.code, ExitCode::InvalidArgs);
        assert_eq!(out.code.code(), 4);
    }

    #[test]
    fn derive_addresses_blocks_a_descriptor_with_a_private_key() {
        let xprv = contains_xprv();
        let out = run_derive_addresses(
            &derive_args(xprv, 5, ChainArg::Both, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert!(
            out.stdout.is_empty(),
            "a blocked secret must not reach stdout"
        );
        let combined = format!("{}{}", out.stdout, out.stderr);
        assert!(
            !combined.contains(xprv),
            "the descriptor must not be echoed"
        );
        assert!(
            !combined.contains("tprv"),
            "the private key must not be echoed"
        );
    }

    #[test]
    fn derive_addresses_unparseable_descriptor_is_invalid_args() {
        let out = run_derive_addresses(
            &derive_args(
                "definitely-not-a-descriptor",
                5,
                ChainArg::Both,
                Some(NetworkArg::Testnet),
            ),
            &human(),
        );
        assert_eq!(out.code, ExitCode::InvalidArgs);
    }

    #[test]
    fn compare_address_match_exits_0() {
        let descriptor = multipath();
        let address = first_receive_address(descriptor);
        let out = run_compare_address(
            &compare_args(descriptor, &address, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert_eq!(out.code, ExitCode::Success);
        assert_eq!(out.code.code(), 0);
        assert!(out.stdout.contains("MATCH"));
    }

    #[test]
    fn compare_address_no_match_exits_1() {
        // A P2WPKH (singlesig) address can never appear in a P2WSH (multisig)
        // descriptor's range, so this is a guaranteed miss.
        let foreign = first_receive_address(singlesig());
        let out = run_compare_address(
            &compare_args(multipath(), &foreign, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert_eq!(out.code, ExitCode::Warnings);
        assert_eq!(out.code.code(), 1);
        assert!(out.stdout.contains("NO MATCH"));
    }

    #[test]
    fn compare_address_invalid_for_network_exits_2() {
        // A mainnet bech32 address is invalid for testnet (§17.10.3 exit 2).
        let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let out = run_compare_address(
            &compare_args(multipath(), mainnet, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert_eq!(out.code.code(), 2);
        assert!(out.stdout.contains("INVALID"));
    }

    #[test]
    fn compare_address_human_snapshot() {
        let descriptor = multipath();
        let address = first_receive_address(descriptor);
        let out = run_compare_address(
            &compare_args(descriptor, &address, Some(NetworkArg::Testnet)),
            &human(),
        );
        insta::assert_snapshot!("compare_address_human_match", out.stdout);
    }

    #[test]
    fn compare_address_json_snapshot() {
        let descriptor = multipath();
        let address = first_receive_address(descriptor);
        let out = run_compare_address(
            &compare_args(descriptor, &address, Some(NetworkArg::Testnet)),
            &json_global(),
        );
        insta::assert_snapshot!("compare_address_json_match", out.stdout);
    }

    #[test]
    fn compare_address_blocks_a_secret_descriptor() {
        let out = run_compare_address(
            &compare_args(
                contains_xprv(),
                "tb1qexampleaddress",
                Some(NetworkArg::Testnet),
            ),
            &human(),
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert!(
            out.stdout.is_empty(),
            "a blocked secret must not reach stdout"
        );
        assert!(
            !out.stderr.contains("tprv"),
            "the private key must not be echoed"
        );
    }

    #[test]
    fn checksum_validate_present_exits_0() {
        let out = run_checksum(
            &ChecksumArgs {
                validate: Some(singlesig().to_owned()),
                compute: None,
            },
            &human(),
        );
        assert_eq!(out.code, ExitCode::Success);
        assert_eq!(out.code.code(), 0);
    }

    #[test]
    fn checksum_validate_missing_exits_1() {
        // The fixture stripped of its `#checksum` has no checksum to validate.
        let body = singlesig()
            .split('#')
            .next()
            .expect("descriptor body")
            .to_owned();
        let out = run_checksum(
            &ChecksumArgs {
                validate: Some(body),
                compute: None,
            },
            &human(),
        );
        assert_eq!(out.code, ExitCode::Warnings);
        assert_eq!(out.code.code(), 1);
    }

    #[test]
    fn checksum_validate_invalid_is_nonzero() {
        let out = run_checksum(
            &ChecksumArgs {
                validate: Some(invalid_checksum().to_owned()),
                compute: None,
            },
            &human(),
        );
        assert_ne!(out.code, ExitCode::Success);
        assert_eq!(out.code.code(), 4);
    }

    #[test]
    fn checksum_compute_reproduces_the_fixture_checksum() {
        // Computing the checksum of the body must reproduce the full fixture,
        // which carries the canonical BIP380 checksum.
        let body = singlesig()
            .split('#')
            .next()
            .expect("descriptor body")
            .to_owned();
        let out = run_checksum(
            &ChecksumArgs {
                validate: None,
                compute: Some(body),
            },
            &human(),
        );
        assert_eq!(out.code, ExitCode::Success);
        assert_eq!(out.stdout.trim_end(), singlesig());
    }

    #[test]
    fn checksum_blocks_a_secret_descriptor_before_echoing_it() {
        // `--compute` echoes the descriptor back, so a private key must be blocked
        // before it is processed or printed.
        let out = run_checksum(
            &ChecksumArgs {
                validate: None,
                compute: Some(contains_xprv().to_owned()),
            },
            &human(),
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert!(
            out.stdout.is_empty(),
            "compute must never echo a blocked secret"
        );
        assert!(
            !out.stderr.contains("tprv"),
            "the private key must not be echoed"
        );
    }

    #[test]
    fn utility_human_output_passes_the_anti_overclaim_lint() {
        let derive = run_derive_addresses(
            &derive_args(multipath(), 2, ChainArg::Both, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert!(passes_anti_overclaim_lint(&derive.stdout));

        let address = first_receive_address(multipath());
        let compare = run_compare_address(
            &compare_args(multipath(), &address, Some(NetworkArg::Testnet)),
            &human(),
        );
        assert!(passes_anti_overclaim_lint(&compare.stdout));

        let checksum = run_checksum(
            &ChecksumArgs {
                validate: Some(singlesig().to_owned()),
                compute: None,
            },
            &human(),
        );
        assert!(passes_anti_overclaim_lint(&checksum.stdout));
    }

    // --- US-077: psbt inspect / validate / extract-tx -----------------------

    fn psbt_inspect_args(file: &str, network: Option<NetworkArg>) -> PsbtArgs {
        PsbtArgs {
            command: PsbtCommand::Inspect(PsbtInspectArgs {
                file: fixture_file(&format!("psbt/{file}")),
                network,
            }),
        }
    }

    fn psbt_validate_args(file: &str, network: Option<NetworkArg>) -> PsbtArgs {
        PsbtArgs {
            command: PsbtCommand::Validate(PsbtValidateArgs {
                file: fixture_file(&format!("psbt/{file}")),
                network,
            }),
        }
    }

    fn psbt_extract_args(file: &str) -> PsbtArgs {
        PsbtArgs {
            command: PsbtCommand::ExtractTx(PsbtExtractTxArgs {
                file: fixture_file(&format!("psbt/{file}")),
                output: None,
            }),
        }
    }

    #[test]
    fn psbt_inspect_json_works_on_bip174_fixture() {
        let out = run_psbt(
            &psbt_inspect_args("bip174_updated_v0.txt", Some(NetworkArg::Mainnet)),
            &json_global(),
        );
        assert_eq!(out.code, ExitCode::Success);
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["encoding"], "bip174_v0");
        assert_eq!(value["version"], 0);
        assert_eq!(value["input_count"], 1);
        assert_eq!(value["output_count"], 2);
        assert_eq!(value["lifecycle"], "unsigned");
    }

    #[test]
    fn psbt_inspect_json_works_on_bip370_fixture() {
        let out = run_psbt(
            &psbt_inspect_args("bip370_updated_v2.txt", Some(NetworkArg::Testnet)),
            &json_global(),
        );
        assert_eq!(out.code, ExitCode::Success);
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["encoding"], "bip370_v2");
        assert_eq!(value["version"], 2);
        assert_eq!(value["input_count"], 1);
        assert_eq!(value["output_count"], 2);
    }

    #[test]
    fn psbt_validate_human_works_on_fixture() {
        let out = run_psbt(
            &psbt_validate_args("bip370_updated_v2.txt", Some(NetworkArg::Testnet)),
            &human(),
        );
        assert_eq!(out.code, ExitCode::Success);
        assert!(out.stdout.contains("PSBT is parseable and supported"));
        assert!(passes_anti_overclaim_lint(&out.stdout));
    }

    #[test]
    fn psbt_extract_tx_rejects_unfinalized_fixture() {
        let out = run_psbt(&psbt_extract_args("bip174_updated_v0.txt"), &json_global());
        assert_eq!(out.code, ExitCode::InvalidArgs);
        assert!(out.stderr.contains("E-INPUT-003"));
        assert!(out.stdout.is_empty());
    }

    // --- US-098: verify-build ------------------------------------------------

    #[test]
    fn verify_build_accepts_matching_local_checksums() {
        let dir = temp_verify_dir("match");
        let artifact = dir.join("bitcoin-lifeboat-v0.1.0-test.tar.gz");
        std::fs::write(&artifact, b"deterministic artifact\n").expect("artifact writes");
        let digest = sha256_file(&artifact).expect("artifact hashes");
        let checksums = dir.join("SHA256SUMS");
        std::fs::write(
            &checksums,
            format!("{digest}  bitcoin-lifeboat-v0.1.0-test.tar.gz\n"),
        )
        .expect("checksums writes");

        let out = run_verify_build(
            &verify_build_args("v0.1.0", artifact.clone(), checksums.clone()),
            &json_global(),
        );
        assert_eq!(out.code, ExitCode::Success);
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["verified"], true);
        assert_eq!(value["artifacts"][0]["match"], true);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_build_reports_a_hash_mismatch() {
        let dir = temp_verify_dir("mismatch");
        let artifact = dir.join("bitcoin-lifeboat-v0.1.0-test.tar.gz");
        std::fs::write(&artifact, b"changed artifact\n").expect("artifact writes");
        let checksums = dir.join("SHA256SUMS");
        std::fs::write(
            &checksums,
            "0000000000000000000000000000000000000000000000000000000000000000  bitcoin-lifeboat-v0.1.0-test.tar.gz\n",
        )
        .expect("checksums writes");

        let out = run_verify_build(
            &verify_build_args("v0.1.0", artifact.clone(), checksums.clone()),
            &human(),
        );
        assert_eq!(out.code, ExitCode::Critical);
        assert!(out.stdout.contains("[FAIL]"));
        assert!(out.stdout.contains("expected"));
        assert!(out.stdout.contains("actual"));
        let _ = std::fs::remove_dir_all(dir);
    }

    // --- US-038: detect-secrets and parse-export ----------------------------

    const IMPORTED_AT: &str = "2024-01-15T00:00:00Z";

    /// The first recipient xpub of the Liana `.bed` fixture — supplying it opens
    /// the encrypted backup (it is one of the descriptor's keys). A documented test
    /// vector, never a real secret (§27).
    const LIANA_RECIPIENT: &str = "tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz";

    /// Path to a repo-root `fixtures/<rel>` file (parse-export / detect-secrets read
    /// from a real file path at runtime, so these tests need paths, not embeds).
    fn fixture_file(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(rel)
    }

    fn detect_stdin_args() -> DetectSecretsArgs {
        DetectSecretsArgs {
            file: None,
            stdin: true,
        }
    }

    fn parse_export_args(wallet_export: &str, format: ExportFormat) -> ParseExportArgs {
        ParseExportArgs {
            file: fixture_file(&format!("wallet_exports/{wallet_export}")),
            format,
            decryption_inputs: Vec::new(),
        }
    }

    fn temp_verify_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lifeboat-verify-build-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp verify dir should be created");
        dir
    }

    fn verify_build_args(
        version: &str,
        artifact: std::path::PathBuf,
        checksums: std::path::PathBuf,
    ) -> VerifyBuildArgs {
        VerifyBuildArgs {
            version: version.to_owned(),
            artifacts: vec![artifact],
            checksums: Some(checksums),
            release_base_url: None,
        }
    }

    fn wif_secret() -> &'static str {
        fixture!("secrets/wif_mainnet.txt")
    }

    #[test]
    fn detect_secrets_blocks_a_real_secret_and_exits_5() {
        let out = run_detect_secrets(
            &detect_stdin_args(),
            &json_global(),
            wif_secret().as_bytes(),
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert_eq!(out.code.code(), 5);

        // §19.4 shape: schema_version, action, flattened findings, message.
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["schema_version"], "0.1.0");
        assert_eq!(value["action"], "block");
        let findings = value["findings"].as_array().expect("findings array");
        assert!(!findings.is_empty(), "a WIF must produce a finding");
        assert_eq!(findings[0]["kind"], "wif");
        let range = findings[0]["byte_range"]
            .as_array()
            .expect("byte_range is an array");
        assert_eq!(range.len(), 2, "byte_range is [start, end]");
        assert!(value["user_facing_message"].is_string());

        // The secret must never appear anywhere in the output.
        assert!(
            !out.stdout.contains(wif_secret()),
            "the WIF must not be echoed"
        );
    }

    #[test]
    fn detect_secrets_allows_a_watch_only_descriptor() {
        let out = run_detect_secrets(&detect_stdin_args(), &json_global(), singlesig().as_bytes());
        assert_eq!(out.code, ExitCode::Success);
        assert_eq!(out.code.code(), 0);
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["action"], "allow");
        assert!(value["findings"].as_array().expect("array").is_empty());
    }

    #[test]
    fn detect_secrets_warns_on_a_bare_64_hex_run_and_exits_1() {
        // A 64-hex run alone on its own line is "suspected" → Warn → exit 1.
        let hex = "a".repeat(64);
        let out = run_detect_secrets(&detect_stdin_args(), &json_global(), hex.as_bytes());
        assert_eq!(out.code, ExitCode::Warnings);
        assert_eq!(out.code.code(), 1);
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["action"], "warn");
    }

    #[test]
    fn detect_secrets_human_output_never_echoes_the_secret() {
        let xprv = contains_xprv();
        let out = run_detect_secrets(&detect_stdin_args(), &human(), xprv.as_bytes());
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert!(out.stdout.contains("BLOCK"));
        let combined = format!("{}{}", out.stdout, out.stderr);
        assert!(
            !combined.contains(xprv),
            "the descriptor must not be echoed"
        );
        assert!(!combined.contains("tprv"), "the key must not be echoed");
        assert!(passes_anti_overclaim_lint(&out.stdout));
    }

    #[test]
    fn detect_secrets_reads_from_a_file() {
        let from_file = run_detect_secrets(
            &DetectSecretsArgs {
                file: Some(fixture_file("secrets/wif_mainnet.txt")),
                stdin: false,
            },
            &json_global(),
            std::io::empty(),
        );
        assert_eq!(from_file.code, ExitCode::SecretDetected);
        assert!(from_file.stdout.contains("\"action\":\"block\""));
    }

    #[test]
    fn detect_secrets_missing_file_is_file_io_exit_6() {
        let out = run_detect_secrets(
            &DetectSecretsArgs {
                file: Some(std::path::PathBuf::from("/nonexistent/lifeboat/nope.txt")),
                stdin: false,
            },
            &human(),
            std::io::empty(),
        );
        assert_eq!(out.code, ExitCode::FileIo);
        assert_eq!(out.code.code(), 6);
    }

    #[test]
    fn detect_secrets_json_allow_snapshot() {
        // Locks the §19.4 top-level shape on a no-findings (Allow) input. Safe to
        // snapshot: it carries no secret content.
        let out = run_detect_secrets(&detect_stdin_args(), &json_global(), singlesig().as_bytes());
        insta::assert_snapshot!("detect_secrets_json_allow", out.stdout);
    }

    #[test]
    fn detect_secrets_is_deterministic() {
        let a = run_detect_secrets(
            &detect_stdin_args(),
            &json_global(),
            wif_secret().as_bytes(),
        );
        let b = run_detect_secrets(
            &detect_stdin_args(),
            &json_global(),
            wif_secret().as_bytes(),
        );
        assert_eq!(a.stdout, b.stdout, "detect-secrets must be deterministic");
        assert_eq!(a.code, b.code);
    }

    #[test]
    fn parse_export_parses_each_format_fixture() {
        // Each selectable §17.10.7 format parses its fixture into a normalized
        // export whose `source_wallet` confirms the right importer ran. `auto`
        // exercises the content sniffer. (Liana is covered separately — it needs a
        // decryption input.)
        let cases: &[(&str, ExportFormat, &str)] = &[
            (
                "bitcoin_core_listdescriptors.json",
                ExportFormat::Core,
                "bitcoin_core",
            ),
            (
                "bitcoin_core_listdescriptors.json",
                ExportFormat::Auto,
                "bitcoin_core",
            ),
            ("sparrow_multisig.json", ExportFormat::Sparrow, "sparrow"),
            ("sparrow_singlesig.json", ExportFormat::Auto, "sparrow"),
            ("specter_multisig.json", ExportFormat::Specter, "specter"),
            ("coldcard_generic.json", ExportFormat::Coldcard, "coldcard"),
            (
                "coldcard_descriptor.txt",
                ExportFormat::Coldcard,
                "coldcard",
            ),
            ("nunchuk_bsms.txt", ExportFormat::Nunchuk, "nunchuk"),
            ("nunchuk_bsms.txt", ExportFormat::Auto, "nunchuk"),
            ("jade_multisig.json", ExportFormat::Jade, "jade"),
        ];
        for (file, format, source) in cases {
            let out = run_parse_export(
                &parse_export_args(file, *format),
                &json_global(),
                IMPORTED_AT,
            );
            assert_eq!(
                out.code,
                ExitCode::Success,
                "{file} ({format:?}) should parse"
            );
            assert!(
                out.stdout
                    .contains(&format!("\"source_wallet\":\"{source}\"")),
                "{file} ({format:?}) should normalize to source_wallet={source}; got: {}",
                out.stdout
            );
            // The export carries a receive descriptor.
            let value: serde_json::Value =
                serde_json::from_str(out.stdout.trim_end()).expect("valid json");
            assert!(
                value["descriptors"]["receive"].is_string(),
                "{file} should yield a receive descriptor"
            );
        }
    }

    #[test]
    fn parse_export_liana_requires_and_accepts_a_decryption_input() {
        // Without a decryption input an encrypted `.bed` cannot be opened
        // (E-INPUT-003 → exit 4).
        let mut args = parse_export_args("liana_v13_backup.bed", ExportFormat::Liana);
        let denied = run_parse_export(&args, &json_global(), IMPORTED_AT);
        assert_eq!(denied.code, ExitCode::InvalidArgs);

        // With a recipient xpub it decrypts and normalizes.
        args.decryption_inputs = vec![LIANA_RECIPIENT.to_owned()];
        let ok = run_parse_export(&args, &json_global(), IMPORTED_AT);
        assert_eq!(ok.code, ExitCode::Success);
        assert!(ok.stdout.contains("\"source_wallet\":\"liana\""));
    }

    #[test]
    fn parse_export_blocks_a_secret_bearing_file() {
        // A descriptor file containing an xprv is refused by the pre-parse secret
        // screen (exit 5) and never normalized or echoed.
        let out = run_parse_export(
            &ParseExportArgs {
                file: fixture_file("descriptors/invalid/contains_xprv.txt"),
                format: ExportFormat::Auto,
                decryption_inputs: Vec::new(),
            },
            &json_global(),
            IMPORTED_AT,
        );
        assert_eq!(out.code, ExitCode::SecretDetected);
        assert!(
            out.stdout.is_empty(),
            "a blocked secret must not reach stdout"
        );
        assert!(!out.stderr.contains("tprv"), "the key must not be echoed");
    }

    #[test]
    fn parse_export_missing_file_is_file_io_exit_6() {
        let out = run_parse_export(
            &ParseExportArgs {
                file: std::path::PathBuf::from("/nonexistent/lifeboat/missing.json"),
                format: ExportFormat::Auto,
                decryption_inputs: Vec::new(),
            },
            &human(),
            IMPORTED_AT,
        );
        assert_eq!(out.code, ExitCode::FileIo);
        assert_eq!(out.code.code(), 6);
    }

    #[test]
    fn parse_export_stamps_imported_at_and_source_filename() {
        let out = run_parse_export(
            &parse_export_args("bitcoin_core_listdescriptors.json", ExportFormat::Core),
            &json_global(),
            IMPORTED_AT,
        );
        let value: serde_json::Value =
            serde_json::from_str(out.stdout.trim_end()).expect("valid json");
        assert_eq!(value["imported_at"], IMPORTED_AT);
        assert_eq!(
            value["raw_source_filename"],
            "bitcoin_core_listdescriptors.json"
        );
    }

    #[test]
    fn parse_export_is_deterministic() {
        let args = parse_export_args("sparrow_multisig.json", ExportFormat::Sparrow);
        let a = run_parse_export(&args, &json_global(), IMPORTED_AT);
        let b = run_parse_export(&args, &json_global(), IMPORTED_AT);
        assert_eq!(a.stdout, b.stdout, "parse-export must be deterministic");
    }

    #[test]
    fn parse_export_json_snapshot() {
        let out = run_parse_export(
            &parse_export_args("bitcoin_core_listdescriptors.json", ExportFormat::Core),
            &json_global(),
            IMPORTED_AT,
        );
        insta::assert_snapshot!("parse_export_json_core", out.stdout);
    }

    #[test]
    fn parse_export_human_snapshot() {
        let out = run_parse_export(
            &parse_export_args("sparrow_multisig.json", ExportFormat::Sparrow),
            &human(),
            IMPORTED_AT,
        );
        insta::assert_snapshot!("parse_export_human_sparrow", out.stdout);
    }

    #[test]
    fn parse_export_human_passes_anti_overclaim_lint() {
        let out = run_parse_export(
            &parse_export_args("sparrow_multisig.json", ExportFormat::Sparrow),
            &human(),
            IMPORTED_AT,
        );
        assert!(passes_anti_overclaim_lint(&out.stdout));
    }
}
