//! Tauri command surface (PRD §21.3) — the descriptor / detector / derive /
//! checksum commands (US-042).
//!
//! These `#[tauri::command]` functions are intentionally thin: each one reads the
//! boundary inputs (and, for the audit, the wall clock + app version) and delegates
//! to the GUI-agnostic logic in the [`desktop_commands`] crate, where the behavior
//! is unit/integration-tested under the fast core gate (`cargo test --workspace`,
//! Rust 1.78) **without** the webkit2gtk/GTK system libraries this crate links.
//! Nothing here parses descriptors, derives addresses, validates checksums, or
//! touches secrets directly — that all lives in the core crates reached through
//! `desktop-commands` (§13.7 / §20).
//!
//! ## Boundary guarantees
//! - Every command returns `Result<T, LifeboatError>`. A [`LifeboatError`]
//!   serializes to a stable, **leak-free** JSON object — its chained source (which
//!   can quote a descriptor or secret) is never serialized (see `error-taxonomy`).
//! - [`detect_sensitive_input`] returns only a [`DetectorReport`] (secret
//!   discriminants + byte ranges) — never raw secret content (§13.5.8). The input
//!   is wrapped in a `SecretString` and zeroized inside the core call.
//! - US-043 adds the output / import / IO tranche: [`generate_report`],
//!   [`generate_runbook`], [`parse_wallet_export`], [`save_export`],
//!   [`open_external_link`], and [`get_app_info`]. The pure logic (including the
//!   link allowlist and the file read/write) lives in `desktop-commands`; only the
//!   OS-browser launch in [`open_external_link`] is performed here, and only after
//!   `desktop_commands::check_external_link` vets the URL.
//!
//! ## `open_external_link` and the §13.7 capability set
//! Opening a link in the OS browser is done from the **trusted Rust core** with a
//! plain per-OS process launch — deliberately **not** via a Tauri shell/opener
//! plugin, because the §13.7 capability set grants the webview none and must stay
//! exactly as specified (the security gate `verify-capabilities.mjs` enforces it).
//! The webview can only *request* a link; this command vets it against the
//! build-time allowlist and then passes it as a single non-shell argument, so even
//! a compromised webview cannot inject arguments or reach a non-allowlisted host.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use desktop_commands::{
    AddressCompareInput, AddressCompareResult, AddressDeriveInput, AppInfo, ChecksumValidation,
    DerivedAddressList, DescriptorAuditInput, DetectorReport, ErrorCode, LianaRecoveryTree,
    LifeboatError, NormalizedWalletExport, ReadinessReport, ReportArtifact, ReportFormat,
    ReportGenerationInput, RunbookArtifact, RunbookGenerationInput, Settings,
};
use hwi_bridge::{
    ExpectedHwiKey, HwiDerivedXpub, HwiDevice, HwiSidecar, HwiSignPsbtRequest, HwiSignedPsbt,
    HwiVerificationResult, HwiXpubRequest,
};
use psbt_drill::{
    DisasterQuestionnaireDrillResult, DisasterQuestionnaireInput, DisasterSigningCompleteInput,
    DisasterSigningDrillResult, DisasterSigningStartInput, DisasterSigningStartResult,
    DrillResultSaveOutcome, FamilyDrillReceiptArtifact, FamilyDrillReceiptInput,
    FilePsbtFinalizeInput, FilePsbtFinalizeResult, HeirDrillPacketExport, HeirDrillPacketInput,
    MainnetFilePsbtValidateInput, MainnetFilePsbtValidateResult, MissingSignerDrillInput,
    MissingSignerDrillResult, MultisigSurvivabilityDrillInput, MultisigSurvivabilityDrillResult,
    PracticeDrillNetwork, PracticeDrillStart, PracticeSendDrillInput, PracticeSendDrillResult,
    SignetBroadcastInput, SignetBroadcastResult,
};
use qr_psbt::{
    PsbtBbqrDecodeState, PsbtBbqrDecoder, PsbtUrDecoder, DEFAULT_MAX_FRAGMENT_LENGTH,
    DEFAULT_QR_SVG_DIMENSION,
};
use serde::{Deserialize, Serialize};
use tauri::Manager;

/// The app version stamped into a report's footer. Read here, at the boundary, so
/// the report engine stays a pure function of its inputs (§19 / §27 determinism).
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// QR transport format selected by the user for PSBT exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsbtQrFormat {
    /// BCR-2020-006 animated `ur:psbt` frames.
    Ur,
    /// Coinkite BBQr split PSBT payloads.
    Bbqr,
}

/// Request to turn a base64 PSBT into QR payloads and SVGs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PsbtQrEncodeInput {
    psbt_base64: String,
    format: PsbtQrFormat,
}

/// One renderable QR frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PsbtQrFrame {
    index: usize,
    total: usize,
    payload: String,
    svg: String,
}

/// Renderable QR frames for one PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PsbtQrFrameSet {
    format: PsbtQrFormat,
    frame_count: usize,
    frames: Vec<PsbtQrFrame>,
}

/// Request to decode scanned QR payloads back into a base64 PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PsbtQrDecodeInput {
    format: PsbtQrFormat,
    payloads: Vec<String>,
}

/// Decode progress for the scanned signed-PSBT QR flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PsbtQrDecodeResult {
    status: String,
    received_count: usize,
    parts_left: Option<usize>,
    psbt_base64: Option<String>,
}

/// §21.3 `audit_descriptor`: screen the descriptor for secrets, parse it, and build
/// the deterministic §19.1 readiness report.
#[tauri::command]
pub async fn audit_descriptor(
    input: DescriptorAuditInput,
) -> Result<ReadinessReport, LifeboatError> {
    desktop_commands::audit_descriptor(input, &desktop_commands::now_iso8601(), APP_VERSION)
}

/// §21.3 `derive_addresses`: derive receive/change addresses from a watch-only
/// descriptor.
#[tauri::command]
pub async fn derive_addresses(
    input: AddressDeriveInput,
) -> Result<DerivedAddressList, LifeboatError> {
    desktop_commands::derive_addresses(input)
}

/// §21.3 `compare_address`: search a descriptor's derived range for a known address.
#[tauri::command]
pub async fn compare_address(
    input: AddressCompareInput,
) -> Result<AddressCompareResult, LifeboatError> {
    desktop_commands::compare_address(input)
}

/// §21.3 `detect_sensitive_input`: screen pasted text for Bitcoin secret material.
/// Only the leak-free [`DetectorReport`] crosses back to JS (§13.5.8).
#[tauri::command]
pub async fn detect_sensitive_input(input: String) -> Result<DetectorReport, LifeboatError> {
    desktop_commands::detect_sensitive_input(input)
}

/// §21.3 `validate_checksum`: report a descriptor's BIP380 checksum verdict
/// (valid / missing / invalid).
#[tauri::command]
pub async fn validate_checksum(descriptor: String) -> Result<ChecksumValidation, LifeboatError> {
    desktop_commands::validate_checksum(descriptor)
}

/// §21.3 `compute_checksum`: return the descriptor with a freshly computed BIP380
/// `#checksum`.
#[tauri::command]
pub async fn compute_checksum(descriptor: String) -> Result<String, LifeboatError> {
    desktop_commands::compute_checksum(descriptor)
}

/// US-088 `render_miniscript_policy_dot`: render a descriptor's lifted spending
/// policy as redacted GraphViz DOT for the desktop UI.
#[tauri::command]
pub async fn render_miniscript_policy_dot(descriptor: String) -> Result<String, LifeboatError> {
    desktop_commands::render_miniscript_policy_dot(descriptor)
}

/// US-091 `render_liana_recovery_tree`: render a public-safe Liana recovery-path
/// tree with per-path timelock estimates and optional current-block countdowns.
#[tauri::command]
pub async fn render_liana_recovery_tree(
    descriptor: String,
    current_block_height: Option<u32>,
) -> Result<LianaRecoveryTree, LifeboatError> {
    desktop_commands::render_liana_recovery_tree_at_block(descriptor, current_block_height)
}

/// §21.3 `generate_report`: audit the descriptor and render the §19.1 report as
/// JSON / pretty JSON / Markdown with the requested redaction (an export, so it
/// honors `public-safe`/`private`). The clock + version are read here (determinism).
#[tauri::command]
pub async fn generate_report(
    input: ReportGenerationInput,
    format: ReportFormat,
) -> Result<ReportArtifact, LifeboatError> {
    desktop_commands::generate_report(input, format, &desktop_commands::now_iso8601(), APP_VERSION)
}

/// §21.3 `generate_runbook`: render a recovery / inheritance runbook (PDF or
/// Markdown) from a bundled template, optionally pre-filled from a descriptor.
#[tauri::command]
pub async fn generate_runbook(
    input: RunbookGenerationInput,
) -> Result<RunbookArtifact, LifeboatError> {
    desktop_commands::generate_runbook(input, APP_VERSION)
}

/// US-071 `start_practice_drill`: derive the disposable receive address for a
/// regtest or Signet receive/send drill. Signet returns a faucet URL for the UI
/// to open in the user's browser; the Rust helper never calls the faucet.
#[tauri::command]
pub async fn start_practice_drill(
    network: PracticeDrillNetwork,
) -> Result<PracticeDrillStart, LifeboatError> {
    psbt_drill::start_receive_send_drill(network)
}

/// US-071 `run_practice_send_drill`: create, sign, and finalize a local
/// receive/send drill transaction through the detached `psbt-drill` crate. It
/// does not broadcast; US-072 adds the separately gated Signet broadcast path.
#[tauri::command]
pub async fn run_practice_send_drill(
    input: PracticeSendDrillInput,
) -> Result<PracticeSendDrillResult, LifeboatError> {
    psbt_drill::run_receive_send_drill(input)
}

/// US-072 `broadcast_signet_transaction`: POST a finalized practice transaction
/// to a Signet Esplora endpoint. The UI must show a "Network call to X"
/// confirmation before invoking this command; the Rust helper has no mainnet
/// endpoint and rejects non-Signet practice networks before any network IO.
#[tauri::command]
pub async fn broadcast_signet_transaction(
    input: SignetBroadcastInput,
) -> Result<SignetBroadcastResult, LifeboatError> {
    psbt_drill::broadcast_signet_transaction(input)
}

/// US-075 `save_practice_drill_result`: persist a completed Practice Mode drill
/// only after the user clicks "Save this drill result." Records are written to
/// the local Lifeboat data directory and signed with a per-install random key.
#[tauri::command]
pub async fn save_practice_drill_result(
    result: PracticeSendDrillResult,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    let data_dir = psbt_drill::default_drill_data_dir()?;
    psbt_drill::save_practice_drill_result(&data_dir, result, &desktop_commands::now_iso8601())
}

/// US-076 `run_disaster_questionnaire_drill`: evaluate DS-1..DS-6 no-signing
/// disaster drills in the Rust drill layer. The helper screens descriptor input,
/// parses and derives addresses, and computes questionnaire pass/fail.
#[tauri::command]
pub async fn run_disaster_questionnaire_drill(
    input: DisasterQuestionnaireInput,
) -> Result<DisasterQuestionnaireDrillResult, LifeboatError> {
    psbt_drill::run_disaster_questionnaire_drill(input, &desktop_commands::now_iso8601())
}

/// US-076 `save_disaster_questionnaire_drill_result`: persist a completed
/// questionnaire drill only after the user explicitly opts in.
#[tauri::command]
pub async fn save_disaster_questionnaire_drill_result(
    result: DisasterQuestionnaireDrillResult,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    let data_dir = psbt_drill::default_drill_data_dir()?;
    psbt_drill::save_disaster_questionnaire_drill_result(
        &data_dir,
        result,
        &desktop_commands::now_iso8601(),
    )
}

/// US-089 `run_multisig_survivability_drill`: evaluate the 2-of-3 / 3-of-5
/// multisig survivability templates in Rust and return public readiness facts.
#[tauri::command]
pub async fn run_multisig_survivability_drill(
    input: MultisigSurvivabilityDrillInput,
) -> Result<MultisigSurvivabilityDrillResult, LifeboatError> {
    psbt_drill::run_multisig_survivability_drill(input, &desktop_commands::now_iso8601())
}

/// US-089 `save_multisig_survivability_drill_result`: persist a completed
/// multisig survivability drill only after the user explicitly opts in.
#[tauri::command]
pub async fn save_multisig_survivability_drill_result(
    result: MultisigSurvivabilityDrillResult,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    let data_dir = psbt_drill::default_drill_data_dir()?;
    psbt_drill::save_multisig_survivability_drill_result(
        &data_dir,
        result,
        &desktop_commands::now_iso8601(),
    )
}

/// US-090 `run_missing_signer_drill`: simulate losing one selected signer from a
/// multisig descriptor and report whether the remaining signer set can recover.
#[tauri::command]
pub async fn run_missing_signer_drill(
    input: MissingSignerDrillInput,
) -> Result<MissingSignerDrillResult, LifeboatError> {
    psbt_drill::run_missing_signer_drill(input, &desktop_commands::now_iso8601())
}

/// US-090 `save_missing_signer_drill_result`: persist a completed missing-signer
/// drill only after the user explicitly opts in.
#[tauri::command]
pub async fn save_missing_signer_drill_result(
    result: MissingSignerDrillResult,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    let data_dir = psbt_drill::default_drill_data_dir()?;
    psbt_drill::save_missing_signer_drill_result(
        &data_dir,
        result,
        &desktop_commands::now_iso8601(),
    )
}

/// US-082 `start_disaster_signing_drill`: create an unsigned DS-7..DS-10
/// practice PSBT for file or QR signing. The UI performs the transport step.
#[tauri::command]
pub async fn start_disaster_signing_drill(
    input: DisasterSigningStartInput,
) -> Result<DisasterSigningStartResult, LifeboatError> {
    psbt_drill::start_disaster_signing_drill(input, &desktop_commands::now_iso8601())
}

/// US-082 `complete_disaster_signing_drill`: validate a signed file/QR PSBT,
/// require destination confirmation, and return an unsaved public DrillResult.
#[tauri::command]
pub async fn complete_disaster_signing_drill(
    input: DisasterSigningCompleteInput,
) -> Result<DisasterSigningDrillResult, LifeboatError> {
    psbt_drill::complete_disaster_signing_drill(input)
}

/// US-082 `save_disaster_signing_drill_result`: persist a DS-7..DS-10 signing
/// drill only after the user explicitly opts in.
#[tauri::command]
pub async fn save_disaster_signing_drill_result(
    result: DisasterSigningDrillResult,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    let data_dir = psbt_drill::default_drill_data_dir()?;
    psbt_drill::save_disaster_signing_drill_result(
        &data_dir,
        result,
        &desktop_commands::now_iso8601(),
    )
}

/// US-078 `read_psbt_file`: read a dialog-chosen `.psbt` file. Base64-text files
/// are returned as-is; raw binary PSBT files are base64-encoded in `psbt-drill`.
#[tauri::command]
pub async fn read_psbt_file(path: String) -> Result<String, LifeboatError> {
    psbt_drill::read_psbt_file(std::path::Path::new(&path))
}

/// US-078 `finalize_file_psbt`: validate and finalize a signed PSBT imported
/// from a file-based signer flow.
#[tauri::command]
pub async fn finalize_file_psbt(
    input: FilePsbtFinalizeInput,
) -> Result<FilePsbtFinalizeResult, LifeboatError> {
    psbt_drill::finalize_file_psbt(input)
}

/// US-083 `validate_mainnet_file_psbt`: inspect a mainnet PSBT file locally.
///
/// This command does not sign, finalize, extract a transaction, or broadcast. It
/// exists only behind the UI's per-session mainnet acknowledgement.
#[tauri::command]
pub async fn validate_mainnet_file_psbt(
    input: MainnetFilePsbtValidateInput,
) -> Result<MainnetFilePsbtValidateResult, LifeboatError> {
    psbt_drill::validate_mainnet_file_psbt(input)
}

/// US-094 `write_heir_drill_packet`: create a fresh disposable regtest/Signet
/// heir drill packet and export it as files under a dialog-chosen directory.
#[tauri::command]
pub async fn write_heir_drill_packet(
    output_dir: String,
    input: HeirDrillPacketInput,
) -> Result<HeirDrillPacketExport, LifeboatError> {
    psbt_drill::write_heir_drill_packet(
        std::path::Path::new(&output_dir),
        input,
        &desktop_commands::now_iso8601(),
    )
}

/// US-096 `generate_family_drill_receipt`: create a local public-safe printable
/// PDF receipt from the heir walkthrough checklist. No network call is made.
#[tauri::command]
pub async fn generate_family_drill_receipt(
    input: FamilyDrillReceiptInput,
) -> Result<FamilyDrillReceiptArtifact, LifeboatError> {
    psbt_drill::generate_family_drill_receipt(input, &desktop_commands::now_iso8601(), APP_VERSION)
}

/// US-081 `encode_psbt_qr_frames`: convert a base64 PSBT into renderable UR or
/// BBQr QR frames. Encoding/rendering stays in `qr-psbt`; the UI only displays
/// the returned SVGs and payload labels.
#[tauri::command]
pub async fn encode_psbt_qr_frames(
    input: PsbtQrEncodeInput,
) -> Result<PsbtQrFrameSet, LifeboatError> {
    let psbt = decode_base64_psbt(&input.psbt_base64)?;
    let payloads = match input.format {
        PsbtQrFormat::Ur => {
            qr_psbt::encode_psbt_ur_frames(&psbt, DEFAULT_MAX_FRAGMENT_LENGTH)?.into_frames()
        }
        PsbtQrFormat::Bbqr => qr_psbt::encode_psbt_bbqr_parts(&psbt)?.into_parts(),
    };

    let total = payloads.len();
    let frames = payloads
        .into_iter()
        .enumerate()
        .map(|(offset, payload)| {
            let svg = qr_psbt::render_qr_svg(&payload, DEFAULT_QR_SVG_DIMENSION)?;
            Ok(PsbtQrFrame {
                index: offset + 1,
                total,
                payload,
                svg,
            })
        })
        .collect::<Result<Vec<_>, LifeboatError>>()?;

    Ok(PsbtQrFrameSet {
        format: input.format,
        frame_count: frames.len(),
        frames,
    })
}

/// US-081 `decode_psbt_qr_payloads`: decode scanned UR/BBQr payload strings
/// into a base64 PSBT once enough frames have been captured.
#[tauri::command]
pub async fn decode_psbt_qr_payloads(
    input: PsbtQrDecodeInput,
) -> Result<PsbtQrDecodeResult, LifeboatError> {
    let payloads = normalize_qr_payloads(input.payloads)?;
    match input.format {
        PsbtQrFormat::Ur => decode_ur_payloads(&payloads),
        PsbtQrFormat::Bbqr => decode_bbqr_payloads(&payloads),
    }
}

/// US-081 `capture_psbt_qr_payloads`: capture one native camera frame and return
/// any QR payload strings decoded by `qr-psbt`.
#[tauri::command]
pub async fn capture_psbt_qr_payloads(camera_index: u32) -> Result<Vec<String>, LifeboatError> {
    qr_psbt::capture_camera_qr_codes(camera_index)
}

/// US-085 `enumerate_hwi_devices`: list hardware wallets visible to the bundled
/// HWI sidecar. Device access remains subprocess-only in `hwi-bridge`.
#[tauri::command]
pub async fn enumerate_hwi_devices() -> Result<Vec<HwiDevice>, LifeboatError> {
    HwiSidecar::auto().enumerate_devices()
}

/// US-085 `read_hwi_xpub`: read one descriptor-origin xpub from a selected HWI
/// device path/fingerprint.
#[tauri::command]
pub async fn read_hwi_xpub(input: HwiXpubRequest) -> Result<HwiDerivedXpub, LifeboatError> {
    HwiSidecar::auto().get_xpub(&input)
}

/// US-086 `sign_hwi_psbt`: sign a PSBT through the subprocess-only HWI sidecar.
#[tauri::command]
pub async fn sign_hwi_psbt(input: HwiSignPsbtRequest) -> Result<HwiSignedPsbt, LifeboatError> {
    HwiSidecar::auto().sign_psbt(&input)
}

/// US-085 `verify_hwi_xpubs`: compare descriptor key origins/xpubs with the
/// connected HWI devices.
#[tauri::command]
pub async fn verify_hwi_xpubs(
    expected_keys: Vec<ExpectedHwiKey>,
) -> Result<Vec<HwiVerificationResult>, LifeboatError> {
    HwiSidecar::auto().verify_expected_xpubs(&expected_keys)
}

/// §21.3 `parse_wallet_export`: read a wallet export file by path, screen it for
/// secrets, and normalize it. The import time is read here, at the boundary.
#[tauri::command]
pub async fn parse_wallet_export(
    file_path: String,
) -> Result<NormalizedWalletExport, LifeboatError> {
    desktop_commands::parse_wallet_export(&file_path, &desktop_commands::now_iso8601())
}

/// §21.3 `save_export`: write `content` to a dialog-chosen `path`.
#[tauri::command]
pub async fn save_export(path: String, content: Vec<u8>) -> Result<(), LifeboatError> {
    desktop_commands::save_export(&path, &content)
}

/// §21.3 `open_external_link`: open a URL in the OS browser **iff** it is on the
/// build-time allowlist. The allowlist decision is the GUI-agnostic
/// `desktop_commands::check_external_link` (tested under the core gate); the launch
/// is performed here, in the trusted core, with no Tauri shell/opener capability
/// (see the module note on §13.7).
#[tauri::command]
pub async fn open_external_link(url: String) -> Result<(), LifeboatError> {
    // Vet the URL against the allowlist BEFORE any IO (§21.3): a non-allowlisted
    // URL is `E-LINK-001` and the browser is never launched.
    desktop_commands::check_external_link(&url)?;
    spawn_browser(&url).map_err(|e| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not launch the system browser to open the link")
            .with_source(e)
    })
}

/// §21.3 `get_app_info`: the app name, version, license, and repository / homepage
/// URLs (the latter two from `project.config.toml`).
#[tauri::command]
pub async fn get_app_info() -> Result<AppInfo, LifeboatError> {
    Ok(desktop_commands::app_info(APP_VERSION))
}

fn decode_base64_psbt(input: &str) -> Result<Vec<u8>, LifeboatError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputEmpty).with_context("PSBT base64 was not provided")
        );
    }
    BASE64_STANDARD.decode(trimmed).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT base64 could not be decoded")
            .with_source(err)
    })
}

fn normalize_qr_payloads(payloads: Vec<String>) -> Result<Vec<String>, LifeboatError> {
    let normalized = payloads
        .into_iter()
        .map(|payload| payload.trim().to_owned())
        .filter(|payload| !payload.is_empty())
        .collect::<Vec<_>>();

    if normalized.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty)
            .with_context("no QR PSBT payloads were provided"));
    }

    Ok(normalized)
}

fn decode_ur_payloads(payloads: &[String]) -> Result<PsbtQrDecodeResult, LifeboatError> {
    let mut decoder = PsbtUrDecoder::default();
    for payload in payloads {
        decoder.receive(payload)?;
    }

    match decoder.message()? {
        Some(psbt) => Ok(complete_qr_decode(payloads.len(), psbt)),
        None => Ok(incomplete_qr_decode(payloads.len(), None)),
    }
}

fn decode_bbqr_payloads(payloads: &[String]) -> Result<PsbtQrDecodeResult, LifeboatError> {
    let mut decoder = PsbtBbqrDecoder::default();
    let mut state = PsbtBbqrDecodeState::NotStarted;
    for payload in payloads {
        state = decoder.receive(payload)?;
    }

    match state {
        PsbtBbqrDecodeState::Complete(psbt) => Ok(complete_qr_decode(payloads.len(), psbt)),
        PsbtBbqrDecodeState::InProgress { parts_left } => {
            Ok(incomplete_qr_decode(payloads.len(), Some(parts_left)))
        }
        PsbtBbqrDecodeState::NotStarted => Ok(incomplete_qr_decode(payloads.len(), None)),
    }
}

fn complete_qr_decode(received_count: usize, psbt: Vec<u8>) -> PsbtQrDecodeResult {
    PsbtQrDecodeResult {
        status: "complete".to_owned(),
        received_count,
        parts_left: Some(0),
        psbt_base64: Some(BASE64_STANDARD.encode(psbt)),
    }
}

fn incomplete_qr_decode(received_count: usize, parts_left: Option<usize>) -> PsbtQrDecodeResult {
    PsbtQrDecodeResult {
        status: "incomplete".to_owned(),
        received_count,
        parts_left,
        psbt_base64: None,
    }
}

/// Resolve the per-OS application config directory (where the §22.11 settings file
/// lives). The directory IO is done here in the trusted Rust core, so the §13.7
/// webview capability set is never widened — the `fs` capability stays scoped to
/// dialog-chosen paths, and the webview can neither name nor read this directory.
fn settings_config_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, LifeboatError> {
    app.path().app_config_dir().map_err(|e| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not resolve the application config directory")
            .with_source(e)
    })
}

/// §22.11 `load_settings`: read the Public preferences (theme, language, and the
/// display/diagnostics toggles). A first launch returns the safe defaults.
#[tauri::command]
pub async fn load_settings(app: tauri::AppHandle) -> Result<Settings, LifeboatError> {
    desktop_commands::load_settings(&settings_config_dir(&app)?)
}

/// §22.11 `save_settings`: persist the Public preferences. Only Public
/// preferences are ever written — never Confidential wallet data (§13).
#[tauri::command]
pub async fn save_settings(app: tauri::AppHandle, settings: Settings) -> Result<(), LifeboatError> {
    desktop_commands::save_settings(&settings_config_dir(&app)?, &settings)
}

/// §22.11 `clear_all_data`: delete the local settings file. Nothing else is
/// persisted by default, so this clears all local data.
#[tauri::command]
pub async fn clear_all_data(app: tauri::AppHandle) -> Result<(), LifeboatError> {
    desktop_commands::clear_all_data(&settings_config_dir(&app)?)
}

/// Launch a pre-vetted URL in the user's default browser, detached, with **no
/// shell** so an allowlisted URL is passed verbatim and no metacharacter is
/// interpreted. Called only after [`open_external_link`] confirms the URL is on the
/// allowlist. Uses a plain per-OS process launch rather than a Tauri plugin, so the
/// §13.7 webview capability set is never widened.
#[cfg(target_os = "linux")]
fn spawn_browser(url: &str) -> std::io::Result<()> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(drop)
}

#[cfg(target_os = "macos")]
fn spawn_browser(url: &str) -> std::io::Result<()> {
    std::process::Command::new("open")
        .arg(url)
        .spawn()
        .map(drop)
}

#[cfg(target_os = "windows")]
fn spawn_browser(url: &str) -> std::io::Result<()> {
    // `rundll32 url.dll,FileProtocolHandler <url>` invokes the default URL handler
    // with no shell (unlike `cmd /c start`, which interprets `&`), so a query-string
    // URL is passed safely.
    std::process::Command::new("rundll32")
        .arg("url.dll,FileProtocolHandler")
        .arg(url)
        .spawn()
        .map(drop)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn spawn_browser(_url: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "opening external links is not supported on this platform",
    ))
}
