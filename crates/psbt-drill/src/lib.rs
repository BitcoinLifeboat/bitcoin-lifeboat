//! BIP174 PSBT v0 and BIP370 PSBT v2 helpers for local recovery signing drills.
//!
//! This crate sits beside `signet-lab` in the detached Rust 1.85 drill layer. It
//! creates PSBTs from an in-memory practice wallet, imports base64 PSBTs,
//! validates the shape needed for fee inspection, signs with the disposable
//! wallet, and finalizes to a transaction. It never estimates fees from an
//! external service and never broadcasts.

use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;

use address_derive::Network as AuditNetwork;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use bdk_chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, SignOptions, Update};
use descriptor_audit::{parse_descriptor, ParsedDescriptor};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use error_taxonomy::{ErrorCode, LifeboatError};
use rand::rngs::OsRng;
use rand::RngCore;
use readiness_score::{
    compute_survivability, run_checks, CheckInput, CheckResult, DeclaredWalletType,
    ReadinessStatus, Survivability,
};
use report_engine::{build_report, ReportInput};
use runbook_engine::{
    render_base_pdf, BaseTemplate, PageSize, PdfBackend, RedactionMode, RunbookFooter,
};
use secrecy::SecretString;
use sensitive_input_detector::detect_secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signet_lab::bitcoin::address::NetworkChecked;
use signet_lab::bitcoin::blockdata::transaction::{self, Sequence, TxIn};
use signet_lab::bitcoin::consensus::encode::{serialize, Decodable};
use signet_lab::bitcoin::hashes::Hash;
use signet_lab::bitcoin::psbt::Psbt;
use signet_lab::bitcoin::{
    absolute, Address, Amount, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Transaction,
    TxOut, Txid, VarInt, Witness,
};
use signet_lab::{DisposableWallet, PracticeNetwork};

/// Maximum accepted PSBT import size. Matches the wallet-import boundary.
pub const MAX_PSBT_SIZE_BYTES: usize = 10 * 1024 * 1024;

const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
const PSBT_GLOBAL_VERSION: u8 = 0xfb;

const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
const PSBT_IN_SEQUENCE: u8 = 0x10;
const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;

const PSBT_OUT_AMOUNT: u8 = 0x03;
const PSBT_OUT_SCRIPT: u8 = 0x04;

const PSBT_VERSION_V0: u32 = 0;
const PSBT_VERSION_V2: u32 = 2;
const DEFAULT_DRILL_FUNDING_SAT: u64 = 125_000;
const DEFAULT_DRILL_SEND_SAT: u64 = 60_000;
const DEFAULT_DRILL_FEE_RATE_SAT_VB: u64 = 2;
const DRILL_RECEIVE_INDEX: u32 = 0;
const DRILL_RECIPIENT_INDEX: u32 = 7;
const DRILL_RESULT_SCHEMA_VERSION: &str = "0.1.0";
const DRILL_SIGNATURE_ALGORITHM: &str = "ed25519-v1";
const DRILL_SIGNING_KEY_FILE_NAME: &str = "drill-signing-key-v1.bin";
const DRILL_RESULTS_DIR_NAME: &str = "drills";
const MULTISIG_2OF3_SCENARIO: &str = "DS-11";
const MULTISIG_3OF5_SCENARIO: &str = "DS-12";
const MISSING_SIGNER_SCENARIO: &str = "DS-13";
const MISSING_SIGNER_SCENARIO_TITLE: &str = "Missing signer interactive drill";
const PRACTICE_PSBT_SCENARIO: &str = "DS-9";
const PRACTICE_PSBT_SCENARIO_TITLE: &str = "I want to test a PSBT signing workflow";
const PRACTICE_WALLET_TYPE: &str = "practice_singlesig";
const DISASTER_SIGNING_REQUIRED_SIGNATURES: u8 = 1;
const HEIR_DRILL_PACKET_SCHEMA_VERSION: &str = "0.1.0";
const HEIR_DRILL_PACKET_DIR_PREFIX: &str = "bitcoin-lifeboat-heir-drill";
const HEIR_DRILL_PACKET_MANIFEST_FILE: &str = "manifest.json";
const HEIR_DRILL_PACKET_INSTRUCTIONS_FILE: &str = "README-heir-drill.md";
const HEIR_DRILL_PACKET_WALLET_FILE: &str = "wallet/practice-wallet.json";
const HEIR_DRILL_WALLET_KIND: &str = "disposable_heir_drill";
const FAMILY_DRILL_RECEIPT_SCHEMA_VERSION: &str = "0.1.0";
const FAMILY_DRILL_RECEIPT_TITLE: &str = "Bitcoin Lifeboat Family Drill Receipt";
const FAMILY_DRILL_RECEIPT_FILENAME: &str = "bitcoin-lifeboat-family-drill-receipt.pdf";

/// The public Signet faucet the UI may open in the user's browser.
///
/// This crate never calls the faucet. The URL is surfaced as instructions only,
/// matching PRD §11.1's "browser link to faucet; app never calls" rule.
pub const SIGNET_FAUCET_URL: &str = "https://faucet.mutinynet.com/";

/// Default Mutinynet Esplora broadcast endpoint for user-confirmed Signet drills.
pub const MUTINYNET_ESPLORA_TX_URL: &str = "https://mutinynet.com/api/tx";

/// Alternate public Signet Esplora broadcast endpoint.
pub const SPROVOOST_SIGNET_ESPLORA_TX_URL: &str = "https://signet.bitcoin.sprovoost.nl/api/tx";

/// Public Signet Esplora endpoints supported by the broadcast drill.
///
/// There is deliberately no mainnet variant. Mainnet broadcast is impossible by
/// construction for this command surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignetBroadcastEndpoint {
    /// Mutinynet's public Signet Esplora endpoint.
    #[default]
    Mutinynet,
    /// Sjors Provoost's public Signet Esplora endpoint.
    Sprovoost,
}

impl SignetBroadcastEndpoint {
    /// Stable snake_case display string for UI/JSON boundaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mutinynet => "mutinynet",
            Self::Sprovoost => "sprovoost",
        }
    }

    /// HTTPS Esplora `POST /tx` endpoint.
    #[must_use]
    pub const fn api_url(self) -> &'static str {
        match self {
            Self::Mutinynet => MUTINYNET_ESPLORA_TX_URL,
            Self::Sprovoost => SPROVOOST_SIGNET_ESPLORA_TX_URL,
        }
    }
}

/// Practice networks supported by the receive/send drill UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PracticeDrillNetwork {
    /// Offline local rehearsal using synthetic regtest funding.
    #[default]
    Regtest,
    /// Public Signet rehearsal. The app shows a faucet link but never calls it.
    Signet,
}

impl PracticeDrillNetwork {
    const fn to_practice_network(self) -> PracticeNetwork {
        match self {
            Self::Regtest => PracticeNetwork::Regtest,
            Self::Signet => PracticeNetwork::Signet,
        }
    }

    /// Stable snake_case display string for UI/JSON boundaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Signet => "signet",
        }
    }
}

/// Initial receive step for a practice drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PracticeDrillStart {
    pub network: String,
    pub receive_address: String,
    pub receive_index: u32,
    pub faucet_url: Option<String>,
    pub funding_hint_sat: u64,
    pub send_amount_sat: u64,
    pub fee_rate_sat_vb: u64,
}

/// Request to create, sign, and finalize a local receive/send drill transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PracticeSendDrillInput {
    #[serde(default)]
    pub network: PracticeDrillNetwork,
    #[serde(default = "default_drill_funding_sat")]
    pub funding_amount_sat: u64,
    #[serde(default = "default_drill_send_sat")]
    pub amount_sat: u64,
    #[serde(default = "default_drill_fee_rate_sat_vb")]
    pub fee_rate_sat_vb: u64,
}

/// Result of a local receive/send drill transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PracticeSendDrillResult {
    pub network: String,
    pub receive_address: String,
    pub receive_index: u32,
    pub funding_amount_sat: u64,
    pub recipient_address: String,
    pub amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    pub unsigned_psbt_base64: String,
    pub signed_psbt_base64: String,
    pub finalized_txid: String,
    pub transaction_hex: String,
    pub input_total_sat: u64,
    pub output_total_sat: u64,
    pub fee_sat: u64,
    pub finalized: bool,
    pub broadcast_available: bool,
}

/// Questionnaire-only disaster scenarios supported by US-076 (§9.3 DS-1..DS-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisasterQuestionnaireScenario {
    /// DS-1: "I lost my hardware wallet".
    #[serde(rename = "DS-1")]
    Ds1,
    /// DS-2: "My laptop died".
    #[serde(rename = "DS-2")]
    Ds2,
    /// DS-3: "My wallet app disappeared".
    #[serde(rename = "DS-3")]
    Ds3,
    /// DS-4: "I have my seed but not my wallet file".
    #[serde(rename = "DS-4")]
    Ds4,
    /// DS-5: "I have my descriptor but not all signers".
    #[serde(rename = "DS-5")]
    Ds5,
    /// DS-6: "One multisig signer is unavailable".
    #[serde(rename = "DS-6")]
    Ds6,
}

impl DisasterQuestionnaireScenario {
    /// Stable scenario code used by §19.5 DrillResult.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ds1 => "DS-1",
            Self::Ds2 => "DS-2",
            Self::Ds3 => "DS-3",
            Self::Ds4 => "DS-4",
            Self::Ds5 => "DS-5",
            Self::Ds6 => "DS-6",
        }
    }

    /// User-facing scenario title from PRD §9.3.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Ds1 => "I lost my hardware wallet",
            Self::Ds2 => "My laptop died",
            Self::Ds3 => "My wallet app disappeared",
            Self::Ds4 => "I have my seed but not my wallet file",
            Self::Ds5 => "I have my descriptor but not all signers",
            Self::Ds6 => "One multisig signer is unavailable",
        }
    }
}

/// Signing disaster scenarios supported by US-082 (§9.3 DS-7..DS-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisasterSigningScenario {
    /// DS-7: "My spouse needs to recover".
    #[serde(rename = "DS-7")]
    Ds7,
    /// DS-8: "I need to verify my hardware wallet can still sign".
    #[serde(rename = "DS-8")]
    Ds8,
    /// DS-9: "I want to test a PSBT signing workflow".
    #[serde(rename = "DS-9")]
    Ds9,
    /// DS-10: "I want to simulate restoring on a clean machine".
    #[serde(rename = "DS-10")]
    Ds10,
}

impl DisasterSigningScenario {
    /// Stable scenario code used by §19.5 DrillResult.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ds7 => "DS-7",
            Self::Ds8 => "DS-8",
            Self::Ds9 => "DS-9",
            Self::Ds10 => "DS-10",
        }
    }

    /// User-facing scenario title from PRD §9.3.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Ds7 => "My spouse needs to recover",
            Self::Ds8 => "I need to verify my hardware wallet can still sign",
            Self::Ds9 => "I want to test a PSBT signing workflow",
            Self::Ds10 => "I want to simulate restoring on a clean machine",
        }
    }
}

/// Concrete network selected for descriptor address derivation in a questionnaire drill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisasterQuestionnaireNetwork {
    /// Bitcoin mainnet address encoding.
    Mainnet,
    /// Public testnet address encoding.
    #[default]
    Testnet,
    /// Public Signet address encoding.
    Signet,
    /// Local regtest address encoding.
    Regtest,
}

impl DisasterQuestionnaireNetwork {
    const fn to_audit_network(self) -> AuditNetwork {
        match self {
            Self::Mainnet => AuditNetwork::Bitcoin,
            Self::Testnet => AuditNetwork::Testnet,
            Self::Signet => AuditNetwork::Signet,
            Self::Regtest => AuditNetwork::Regtest,
        }
    }
}

/// Yes/no/unsure answer for questionnaire-only disaster drills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisasterAnswer {
    /// User confirmed the item.
    Yes,
    /// User said the item is missing.
    No,
    /// User could not confirm the item.
    #[default]
    Unsure,
}

impl DisasterAnswer {
    const fn is_yes(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// Scenario questionnaire responses. These are public yes/no/unsure facts; never
/// seed words, passphrases, signer locations, or other secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct DisasterQuestionnaireAnswers {
    pub descriptor_backup_available: DisasterAnswer,
    pub recovery_materials_available: DisasterAnswer,
    pub wallet_software_documented: DisasterAnswer,
    pub passphrase_documented: DisasterAnswer,
    pub gap_limit_or_birthdate_documented: DisasterAnswer,
    pub signer_locations_known: DisasterAnswer,
}

/// Input for a no-signing disaster drill questionnaire (§9.3 DS-1..DS-6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DisasterQuestionnaireInput {
    pub scenario: DisasterQuestionnaireScenario,
    pub descriptor: String,
    #[serde(default)]
    pub network: DisasterQuestionnaireNetwork,
    #[serde(default)]
    pub known_address: Option<String>,
    #[serde(default)]
    pub available_signers: Option<u8>,
    #[serde(default)]
    pub user_stopped: bool,
    #[serde(default)]
    pub answers: DisasterQuestionnaireAnswers,
}

/// Built-in multisig survivability drill templates (US-089).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultisigDrillTemplate {
    /// A 2-of-3 signer set.
    #[serde(rename = "multisig-2of3")]
    Multisig2of3,
    /// A 3-of-5 signer set.
    #[serde(rename = "multisig-3of5")]
    Multisig3of5,
}

impl MultisigDrillTemplate {
    /// Stable template id for UI and DrillResult boundaries.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Multisig2of3 => "multisig-2of3",
            Self::Multisig3of5 => "multisig-3of5",
        }
    }

    /// Stable scenario code used by §19.5 DrillResult.
    #[must_use]
    pub const fn scenario(self) -> &'static str {
        match self {
            Self::Multisig2of3 => MULTISIG_2OF3_SCENARIO,
            Self::Multisig3of5 => MULTISIG_3OF5_SCENARIO,
        }
    }

    /// User-facing title for the DrillResult record.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Multisig2of3 => "2-of-3 multisig survivability simulation",
            Self::Multisig3of5 => "3-of-5 multisig survivability simulation",
        }
    }

    const fn quorum(self) -> (usize, usize) {
        match self {
            Self::Multisig2of3 => (2, 3),
            Self::Multisig3of5 => (3, 5),
        }
    }
}

/// Input for the US-089 multisig survivability simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MultisigSurvivabilityDrillInput {
    pub template: MultisigDrillTemplate,
    pub descriptor: String,
    #[serde(default)]
    pub network: DisasterQuestionnaireNetwork,
    #[serde(default)]
    pub known_address: Option<String>,
    #[serde(default)]
    pub user_stopped: bool,
}

/// Input for the US-090 missing-signer interactive drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MissingSignerDrillInput {
    pub descriptor: String,
    #[serde(default)]
    pub network: PracticeDrillNetwork,
    pub lost_signer_index: u8,
    #[serde(default)]
    pub user_stopped: bool,
}

/// PSBT transport selected for a signing disaster drill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisasterSigningTransport {
    /// Save/import a `.psbt` file through dialog-scoped file access.
    #[default]
    File,
    /// Display and scan PSBT QR frames.
    Qr,
    /// Sign the PSBT through the subprocess-only HWI sidecar.
    Hwi,
}

impl DisasterSigningTransport {
    /// Stable snake_case display string for UI/JSON boundaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Qr => "qr",
            Self::Hwi => "hwi",
        }
    }
}

/// Request to start a DS-7..DS-10 signing disaster drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DisasterSigningStartInput {
    pub scenario: DisasterSigningScenario,
    #[serde(default)]
    pub network: PracticeDrillNetwork,
    #[serde(default)]
    pub transport: DisasterSigningTransport,
}

/// Unsigned PSBT package the UI can export by file or QR for a signing drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasterSigningStartResult {
    pub schema_version: String,
    pub scenario: String,
    pub scenario_title: String,
    pub started_at: String,
    pub network: String,
    pub transport: String,
    pub wallet_type: String,
    pub required_signatures: u8,
    pub receive_address: String,
    pub destination_address: String,
    pub amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    pub unsigned_psbt_base64: String,
}

/// Request to complete a DS-7..DS-10 signing disaster drill from a signed PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DisasterSigningCompleteInput {
    pub scenario: DisasterSigningScenario,
    #[serde(default)]
    pub network: PracticeDrillNetwork,
    #[serde(default)]
    pub transport: DisasterSigningTransport,
    pub started_at: String,
    pub signed_psbt_base64: String,
    pub expected_destination_address: String,
    pub expected_amount_sat: u64,
    pub destination_confirmed: bool,
    #[serde(default)]
    pub user_stopped: bool,
}

/// Result of a no-signing disaster drill before the user explicitly saves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasterQuestionnaireDrillResult {
    pub schema_version: String,
    pub scenario: String,
    pub scenario_title: String,
    pub started_at: String,
    pub result: DrillStepResult,
    pub wallet_type: String,
    pub steps: Vec<DrillResultStep>,
    pub report_hash: String,
}

/// Result of a multisig survivability simulation before the user explicitly saves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSurvivabilityDrillResult {
    pub schema_version: String,
    pub template_id: String,
    pub scenario: String,
    pub scenario_title: String,
    pub started_at: String,
    pub result: DrillStepResult,
    pub wallet_type: String,
    pub readiness_status: Option<ReadinessStatus>,
    pub readiness_headline: Option<String>,
    pub readiness_score: Option<u32>,
    pub survivability: Option<Survivability>,
    pub steps: Vec<DrillResultStep>,
    pub report_hash: String,
}

/// Public material category required for a missing-signer recovery rehearsal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingSignerMaterialKind {
    DescriptorBackup,
    CoordinatorWallet,
    PracticeFunds,
    RemainingSigner,
}

/// One public material item the user needs for the missing-signer drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingSignerRequiredMaterial {
    pub kind: MissingSignerMaterialKind,
    pub signer_index: Option<u8>,
}

/// Result of the missing-signer interactive drill before explicit save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingSignerDrillResult {
    pub schema_version: String,
    pub scenario: String,
    pub scenario_title: String,
    pub started_at: String,
    pub result: DrillStepResult,
    pub wallet_type: String,
    pub network: String,
    pub threshold: u8,
    pub key_count: u8,
    pub lost_signer_index: u8,
    pub remaining_signer_indexes: Vec<u8>,
    pub signatures_required: u8,
    pub recovery_possible: bool,
    pub required_materials: Vec<MissingSignerRequiredMaterial>,
    pub steps: Vec<DrillResultStep>,
    pub report_hash: String,
}

/// Result of a signing disaster drill before the user explicitly saves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasterSigningDrillResult {
    pub schema_version: String,
    pub scenario: String,
    pub scenario_title: String,
    pub started_at: String,
    pub result: DrillStepResult,
    pub wallet_type: String,
    pub network: String,
    pub transport: String,
    pub required_signatures: u8,
    pub finalized_txid: String,
    pub steps: Vec<DrillResultStep>,
    pub report_hash: String,
}

/// Pass/fail result used by the local DrillResult schema (§19.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillStepResult {
    /// The step or overall drill completed.
    Pass,
    /// The step or overall drill did not complete.
    Fail,
}

/// One step inside a signed local DrillResult record (§19.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillResultStep {
    pub step: String,
    pub result: DrillStepResult,
}

/// The signable DrillResult payload from PRD §19.5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillResultPayload {
    pub schema_version: String,
    pub drill_id: String,
    pub scenario: String,
    pub scenario_title: String,
    pub started_at: String,
    pub completed_at: String,
    pub result: DrillStepResult,
    pub wallet_type: String,
    pub steps: Vec<DrillResultStep>,
    pub report_hash: String,
}

/// Ed25519 signature envelope attached to a local DrillResult record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillResultSignature {
    pub algorithm: String,
    pub public_key: String,
    pub payload_sha256: String,
    pub signature: String,
}

/// A signed local DrillResult record. The payload fields stay top-level to match
/// the §19.5 schema, while `signature` carries the local authenticity proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillResultRecord {
    #[serde(flatten)]
    pub payload: DrillResultPayload,
    pub signature: DrillResultSignature,
}

/// Result returned to the desktop UI after an explicit opt-in save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillResultSaveOutcome {
    pub path: String,
    pub record: DrillResultRecord,
}

/// Request to broadcast a finalized transaction to a public Signet Esplora
/// endpoint after explicit user confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SignetBroadcastInput {
    pub network: PracticeDrillNetwork,
    pub transaction_hex: String,
    #[serde(default)]
    pub endpoint: SignetBroadcastEndpoint,
}

/// Result of a user-confirmed Signet broadcast attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SignetBroadcastResult {
    pub network: String,
    pub endpoint: String,
    pub endpoint_url: String,
    pub txid: String,
}

/// Signed PSBT import request for the file-based hardware-wallet drill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FilePsbtFinalizeInput {
    #[serde(default)]
    pub network: PracticeDrillNetwork,
    pub psbt_base64: String,
}

/// Result of validating, finalizing, and extracting a signed file PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FilePsbtFinalizeResult {
    pub network: String,
    pub txid: String,
    pub transaction_hex: String,
    pub inspection: PsbtInspection,
}

/// Mainnet PSBT import request for the file-only validation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MainnetFilePsbtValidateInput {
    pub psbt_base64: String,
}

/// Result of locally validating a mainnet PSBT file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MainnetFilePsbtValidateResult {
    pub network: String,
    pub txid: String,
    pub finalized: bool,
    pub broadcast_available: bool,
    pub inspection: PsbtInspection,
}

/// Owner-side request for a portable heir drill packet.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacketInput {
    /// Offline regtest by default; Signet is still a test network and only adds
    /// an instruction-only faucet URL.
    #[serde(default)]
    pub network: PracticeDrillNetwork,
}

/// A generated heir drill packet held in memory before export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacket {
    pub manifest: HeirDrillPacketManifest,
    pub files: Vec<HeirDrillPacketFile>,
}

/// Public manifest for a portable heir drill packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacketManifest {
    pub schema_version: String,
    pub packet_id: String,
    pub packet_type: String,
    pub created_at: String,
    pub network: String,
    pub wallet_kind: String,
    pub instructions_file: String,
    pub wallet_file: String,
    pub first_receive_address: String,
    pub first_change_address: String,
    pub faucet_url: Option<String>,
    pub contains_real_funds: bool,
    pub contains_real_user_material: bool,
    pub includes_disposable_private_material: bool,
    pub files: Vec<HeirDrillPacketManifestFile>,
}

/// One file entry listed by the heir packet manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacketManifestFile {
    pub role: String,
    pub relative_path: String,
    pub mime_type: String,
    pub sha256: String,
}

/// One exportable file in a generated heir drill packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacketFile {
    pub relative_path: String,
    pub mime_type: String,
    pub contents: String,
    pub sha256: String,
}

/// Wallet import file included in an heir drill packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillWalletFile {
    pub schema_version: String,
    pub packet_id: String,
    pub wallet_kind: String,
    pub network: String,
    pub purpose: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub first_receive_address: String,
    pub first_change_address: String,
    pub funding_hint_sat: u64,
    pub send_amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    pub faucet_url: Option<String>,
    pub contains_real_funds: bool,
    pub contains_real_user_material: bool,
    pub material_notice: String,
}

/// Paths written when a generated heir drill packet is exported to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacketExport {
    pub packet_dir: String,
    pub manifest: HeirDrillPacketManifest,
    pub files: Vec<HeirDrillPacketWrittenFile>,
}

/// One file written to disk for an exported heir drill packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HeirDrillPacketWrittenFile {
    pub role: String,
    pub relative_path: String,
    pub path: String,
    pub mime_type: String,
    pub sha256: String,
}

/// Public checklist steps recorded on a family drill receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyDrillReceiptStep {
    Start,
    Packet,
    Wallet,
    Send,
    Result,
}

impl FamilyDrillReceiptStep {
    const ALL: [Self; 5] = [
        Self::Start,
        Self::Packet,
        Self::Wallet,
        Self::Send,
        Self::Result,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Start => "Start with care",
            Self::Packet => "Find the packet",
            Self::Wallet => "Open the practice wallet",
            Self::Send => "Send fake coins",
            Self::Result => "Write the result",
        }
    }
}

/// Public confidence checks recorded on a family drill receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyDrillConfidenceCheck {
    Packet,
    FakeBitcoin,
    RealSeeds,
    Contact,
}

impl FamilyDrillConfidenceCheck {
    const ALL: [Self; 4] = [
        Self::Packet,
        Self::FakeBitcoin,
        Self::RealSeeds,
        Self::Contact,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Packet => "Packet folder and practice wallet were found",
            Self::FakeBitcoin => "Heir understands the drill uses fake bitcoin only",
            Self::RealSeeds => "Heir knows real seed words never go into this app",
            Self::Contact => "Heir knows Bitcoin Lifeboat will never contact them",
        }
    }
}

/// Public-safe input for generating a printable family drill receipt.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FamilyDrillReceiptInput {
    /// Optional packet UUID from `manifest.json`. Arbitrary text is rejected.
    pub packet_id: Option<String>,
    /// Optional practice network shown by the packet/app. Mainnet is impossible.
    pub network: Option<PracticeDrillNetwork>,
    /// Checklist steps the heir marked complete in the walkthrough.
    #[serde(default)]
    pub completed_steps: Vec<FamilyDrillReceiptStep>,
    /// Confidence checks the heir marked complete in the walkthrough.
    #[serde(default)]
    pub confidence_checks: Vec<FamilyDrillConfidenceCheck>,
    /// True when the heir explicitly stopped instead of completing the drill.
    #[serde(default)]
    pub user_stopped: bool,
}

/// Printable public-safe family drill receipt artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FamilyDrillReceiptArtifact {
    pub schema_version: String,
    pub format: String,
    pub redaction: String,
    pub mime_type: String,
    pub suggested_filename: String,
    pub receipt_hash: String,
    pub content: Vec<u8>,
}

/// Narrow broadcast transport used by the Signet drill.
pub trait SignetBroadcaster {
    /// POST `transaction_hex` to an Esplora `POST /tx` endpoint and return the
    /// response body, expected to be the transaction id.
    fn broadcast(&self, endpoint_url: &str, transaction_hex: &str)
        -> Result<String, LifeboatError>;
}

/// Production Signet broadcaster backed by the system `curl` command.
///
/// This avoids adding a Rust TLS stack to the detached drill crate. It performs
/// no work unless the UI has called the explicitly confirmed broadcast command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemCurlBroadcaster {
    curl_path: PathBuf,
}

impl Default for SystemCurlBroadcaster {
    fn default() -> Self {
        Self {
            curl_path: PathBuf::from("curl"),
        }
    }
}

impl SystemCurlBroadcaster {
    /// Use a specific curl-compatible executable.
    #[must_use]
    pub fn new(curl_path: impl Into<PathBuf>) -> Self {
        Self {
            curl_path: curl_path.into(),
        }
    }
}

impl SignetBroadcaster for SystemCurlBroadcaster {
    fn broadcast(
        &self,
        endpoint_url: &str,
        transaction_hex: &str,
    ) -> Result<String, LifeboatError> {
        let mut child = Command::new(&self.curl_path)
            .arg("--fail")
            .arg("--location")
            .arg("--silent")
            .arg("--show-error")
            .arg("--max-time")
            .arg("30")
            .arg("--request")
            .arg("POST")
            .arg("--header")
            .arg("Content-Type: text/plain")
            .arg("--data-binary")
            .arg("@-")
            .arg(endpoint_url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                LifeboatError::new(ErrorCode::NetworkUnreachable)
                    .with_context("user-confirmed Signet broadcast could not start")
                    .with_source(err)
            })?;

        let stdin = child.stdin.as_mut().ok_or_else(|| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("could not write the Signet transaction to curl")
        })?;
        stdin.write_all(transaction_hex.as_bytes()).map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("user-confirmed Signet broadcast could not send the transaction")
                .with_source(err)
        })?;
        drop(child.stdin.take());

        let output = child.wait_with_output().map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("user-confirmed Signet broadcast could not finish")
                .with_source(err)
        })?;
        if !output.status.success() {
            return Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("user-confirmed Signet broadcast failed"));
        }

        String::from_utf8(output.stdout).map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("Signet broadcast endpoint returned non-UTF-8 output")
                .with_source(err)
        })
    }
}

const fn default_drill_funding_sat() -> u64 {
    DEFAULT_DRILL_FUNDING_SAT
}

const fn default_drill_send_sat() -> u64 {
    DEFAULT_DRILL_SEND_SAT
}

const fn default_drill_fee_rate_sat_vb() -> u64 {
    DEFAULT_DRILL_FEE_RATE_SAT_VB
}

/// Start the receive step for a disposable practice wallet.
///
/// The wallet is derived in memory from the documented practice seed. For Signet,
/// the returned faucet URL is instruction-only; no HTTP client exists in this
/// crate and no faucet request is made.
pub fn start_receive_send_drill(
    network: PracticeDrillNetwork,
) -> Result<PracticeDrillStart, LifeboatError> {
    let practice_network = network.to_practice_network();
    let wallet = DisposableWallet::from_default_practice_seed(practice_network)?;
    let receive = wallet.receive_address(DRILL_RECEIVE_INDEX);

    Ok(PracticeDrillStart {
        network: network.as_str().to_owned(),
        receive_address: receive.address().to_owned(),
        receive_index: receive.index(),
        faucet_url: (network == PracticeDrillNetwork::Signet).then(|| SIGNET_FAUCET_URL.to_owned()),
        funding_hint_sat: DEFAULT_DRILL_FUNDING_SAT,
        send_amount_sat: DEFAULT_DRILL_SEND_SAT,
        fee_rate_sat_vb: DEFAULT_DRILL_FEE_RATE_SAT_VB,
    })
}

/// Create, sign, and finalize a local receive/send drill transaction.
///
/// Funding is applied as an in-memory BDK update so tests and the desktop UI can
/// rehearse the PSBT lifecycle without spawning bitcoind, calling a faucet, or
/// broadcasting. The finalized transaction is returned for inspection only;
/// broadcasting remains a separately gated story.
pub fn run_receive_send_drill(
    input: PracticeSendDrillInput,
) -> Result<PracticeSendDrillResult, LifeboatError> {
    if input.funding_amount_sat == 0 || input.amount_sat == 0 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice drill amounts must be greater than zero"));
    }
    if input.funding_amount_sat <= input.amount_sat {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice drill funding must exceed the send amount"));
    }

    let network = input.network;
    let mut wallet = DisposableWallet::from_default_practice_seed(network.to_practice_network())?;
    let receive = wallet.receive_address(DRILL_RECEIVE_INDEX);
    apply_local_funding_update(&mut wallet, input.funding_amount_sat)?;

    let recipient = wallet.change_address(DRILL_RECIPIENT_INDEX);
    let request = CreatePsbtRequest::new(
        recipient.address().to_owned(),
        input.amount_sat,
        input.fee_rate_sat_vb,
    );
    let created = create_psbt(&mut wallet, &request)?;
    let unsigned_psbt_base64 = created.to_base64()?;
    let signed = sign_psbt(&wallet, created.into_psbt())?;
    let signed_psbt_base64 = signed.to_base64()?;
    let finalized = finalize_psbt(&wallet, signed.into_psbt())?;
    let inspection = finalized.inspection().clone();

    Ok(PracticeSendDrillResult {
        network: network.as_str().to_owned(),
        receive_address: receive.address().to_owned(),
        receive_index: receive.index(),
        funding_amount_sat: input.funding_amount_sat,
        recipient_address: recipient.address().to_owned(),
        amount_sat: input.amount_sat,
        fee_rate_sat_vb: input.fee_rate_sat_vb,
        unsigned_psbt_base64,
        signed_psbt_base64,
        finalized_txid: finalized.txid().to_string(),
        transaction_hex: hex_encode(&finalized.transaction_bytes()),
        input_total_sat: inspection.input_total_sat(),
        output_total_sat: inspection.output_total_sat(),
        fee_sat: inspection.fee_sat(),
        finalized: inspection.finalized(),
        broadcast_available: network == PracticeDrillNetwork::Signet,
    })
}

/// Read a dialog-chosen `.psbt` file and return base64 PSBT text.
///
/// Lifeboat writes base64 text PSBT files for broad wallet compatibility. Some
/// external signers write raw BIP174/BIP370 bytes instead; those bytes are encoded
/// here before the normal PSBT importer sees them.
pub fn read_psbt_file(path: &Path) -> Result<String, LifeboatError> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_PSBT_SIZE_BYTES as u64 {
            return Err(LifeboatError::new(ErrorCode::InputTooLarge)
                .with_context("PSBT file exceeds the 10 MB limit"));
        }
    }

    let bytes = std::fs::read(path).map_err(|err| {
        LifeboatError::new(ErrorCode::FileNotFound)
            .with_context("could not read the PSBT file")
            .with_source(err)
    })?;
    if bytes.len() > MAX_PSBT_SIZE_BYTES {
        return Err(LifeboatError::new(ErrorCode::InputTooLarge)
            .with_context("PSBT file exceeds the 10 MB limit"));
    }

    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(text.trim().to_owned()),
        Err(_) => Ok(BASE64_STANDARD.encode(bytes)),
    }
}

/// Validate and finalize a signed PSBT imported from a file-based signer flow.
pub fn finalize_file_psbt(
    input: FilePsbtFinalizeInput,
) -> Result<FilePsbtFinalizeResult, LifeboatError> {
    let network = input.network;
    let wallet = DisposableWallet::from_default_practice_seed(network.to_practice_network())?;
    let imported = import_psbt_base64(&input.psbt_base64, wallet.network())?;
    if imported.inspection().finalized() {
        let inspection = imported.inspection().clone();
        let transaction = imported
            .into_psbt()
            .extract_tx_fee_rate_limit()
            .map_err(|err| {
                LifeboatError::new(ErrorCode::InputInvalidFormat)
                    .with_context("finalized file PSBT could not be extracted as a transaction")
                    .with_source(err)
            })?;
        let txid = transaction.compute_txid().to_string();
        let transaction_hex = hex_encode(&serialize(&transaction));
        return Ok(FilePsbtFinalizeResult {
            network: network.as_str().to_owned(),
            txid,
            transaction_hex,
            inspection,
        });
    }

    let finalized = finalize_psbt(&wallet, imported.into_psbt())?;
    let inspection = finalized.inspection().clone();
    let txid = finalized.txid().to_string();
    let transaction_hex = hex_encode(&finalized.transaction_bytes());

    Ok(FilePsbtFinalizeResult {
        network: network.as_str().to_owned(),
        txid,
        transaction_hex,
        inspection,
    })
}

/// Validate a mainnet PSBT file without signing, finalizing, extracting, or broadcasting.
pub fn validate_mainnet_file_psbt(
    input: MainnetFilePsbtValidateInput,
) -> Result<MainnetFilePsbtValidateResult, LifeboatError> {
    let imported = import_psbt_base64(&input.psbt_base64, Network::Bitcoin)?;
    let inspection = imported.inspection().clone();

    Ok(MainnetFilePsbtValidateResult {
        network: "mainnet".to_owned(),
        txid: inspection.txid().to_owned(),
        finalized: inspection.finalized(),
        broadcast_available: false,
        inspection,
    })
}

/// Generate a portable heir drill packet with a fresh disposable test wallet.
///
/// The packet never uses user wallet material. It contains three exportable
/// files: a manifest, plain-English instructions, and a practice-wallet import
/// file holding disposable test-only private descriptors for regtest or Signet.
pub fn generate_heir_drill_packet(
    input: HeirDrillPacketInput,
    created_at: &str,
) -> Result<HeirDrillPacket, LifeboatError> {
    if !is_utc_second_timestamp(created_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("heir drill packet creation time must be a UTC second timestamp"));
    }

    let network = input.network;
    let wallet = DisposableWallet::generate(network.to_practice_network())?;
    let packet_id = random_uuid_v4();
    let receive = wallet.receive_address(DRILL_RECEIVE_INDEX);
    let change = wallet.change_address(DRILL_RECIPIENT_INDEX);
    let faucet_url =
        (network == PracticeDrillNetwork::Signet).then(|| SIGNET_FAUCET_URL.to_owned());

    let instructions = heir_drill_instructions(network, faucet_url.as_deref());
    let wallet_file = HeirDrillWalletFile {
        schema_version: HEIR_DRILL_PACKET_SCHEMA_VERSION.to_owned(),
        packet_id: packet_id.clone(),
        wallet_kind: HEIR_DRILL_WALLET_KIND.to_owned(),
        network: network.as_str().to_owned(),
        purpose: "heir_drill_only".to_owned(),
        external_descriptor: wallet.external_descriptor().to_owned(),
        internal_descriptor: wallet.internal_descriptor().to_owned(),
        first_receive_address: receive.address().to_owned(),
        first_change_address: change.address().to_owned(),
        funding_hint_sat: DEFAULT_DRILL_FUNDING_SAT,
        send_amount_sat: DEFAULT_DRILL_SEND_SAT,
        fee_rate_sat_vb: DEFAULT_DRILL_FEE_RATE_SAT_VB,
        faucet_url: faucet_url.clone(),
        contains_real_funds: false,
        contains_real_user_material: false,
        material_notice:
            "Disposable test wallet for a Lifeboat heir drill. Do not use it for real bitcoin."
                .to_owned(),
    };
    let wallet_json = json_pretty(
        &wallet_file,
        "could not serialize the heir drill wallet file",
    )?;

    let instructions_file = heir_packet_file(
        HEIR_DRILL_PACKET_INSTRUCTIONS_FILE,
        "text/markdown",
        instructions,
    );
    let wallet_packet_file = heir_packet_file(
        HEIR_DRILL_PACKET_WALLET_FILE,
        "application/json",
        wallet_json,
    );
    let payload_files = vec![instructions_file, wallet_packet_file];
    let manifest_files = payload_files
        .iter()
        .map(|file| HeirDrillPacketManifestFile {
            role: heir_packet_file_role(&file.relative_path).to_owned(),
            relative_path: file.relative_path.clone(),
            mime_type: file.mime_type.clone(),
            sha256: file.sha256.clone(),
        })
        .collect::<Vec<_>>();

    let manifest = HeirDrillPacketManifest {
        schema_version: HEIR_DRILL_PACKET_SCHEMA_VERSION.to_owned(),
        packet_id,
        packet_type: "heir_drill_packet".to_owned(),
        created_at: created_at.to_owned(),
        network: network.as_str().to_owned(),
        wallet_kind: HEIR_DRILL_WALLET_KIND.to_owned(),
        instructions_file: HEIR_DRILL_PACKET_INSTRUCTIONS_FILE.to_owned(),
        wallet_file: HEIR_DRILL_PACKET_WALLET_FILE.to_owned(),
        first_receive_address: receive.address().to_owned(),
        first_change_address: change.address().to_owned(),
        faucet_url,
        contains_real_funds: false,
        contains_real_user_material: false,
        includes_disposable_private_material: true,
        files: manifest_files,
    };
    let manifest_json = json_pretty(
        &manifest,
        "could not serialize the heir drill packet manifest",
    )?;
    let mut files = vec![heir_packet_file(
        HEIR_DRILL_PACKET_MANIFEST_FILE,
        "application/json",
        manifest_json,
    )];
    files.extend(payload_files);

    Ok(HeirDrillPacket { manifest, files })
}

/// Generate and write a portable heir drill packet under `output_dir`.
///
/// A fresh subdirectory named `bitcoin-lifeboat-heir-drill-<uuid>` is created so
/// export never overwrites an existing packet file.
pub fn write_heir_drill_packet(
    output_dir: &Path,
    input: HeirDrillPacketInput,
    created_at: &str,
) -> Result<HeirDrillPacketExport, LifeboatError> {
    let packet = generate_heir_drill_packet(input, created_at)?;
    let packet_dir = output_dir.join(format!(
        "{HEIR_DRILL_PACKET_DIR_PREFIX}-{}",
        packet.manifest.packet_id
    ));
    std::fs::create_dir_all(&packet_dir).map_err(|err| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not create the heir drill packet directory")
            .with_source(err)
    })?;

    let mut written = Vec::with_capacity(packet.files.len());
    for file in &packet.files {
        let path = packet_dir.join(&file.relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                LifeboatError::new(ErrorCode::CannotWrite)
                    .with_context("could not create a heir drill packet subdirectory")
                    .with_source(err)
            })?;
        }
        let secret_file = file.relative_path == HEIR_DRILL_PACKET_WALLET_FILE;
        write_new_file(&path, file.contents.as_bytes(), secret_file)?;
        written.push(HeirDrillPacketWrittenFile {
            role: heir_packet_file_role(&file.relative_path).to_owned(),
            relative_path: file.relative_path.clone(),
            path: path.to_string_lossy().into_owned(),
            mime_type: file.mime_type.clone(),
            sha256: file.sha256.clone(),
        });
    }

    Ok(HeirDrillPacketExport {
        packet_dir: packet_dir.to_string_lossy().into_owned(),
        manifest: packet.manifest,
        files: written,
    })
}

/// Generate a public-safe printable receipt for the heir/family drill.
///
/// The receipt is local-only, uses the deterministic pure-Rust PDF renderer, and
/// accepts only enumerated public checklist values. It never accepts descriptors,
/// xpubs, addresses, seed words, passphrases, PSBTs, or transaction hex.
pub fn generate_family_drill_receipt(
    input: FamilyDrillReceiptInput,
    completed_at: &str,
    app_version: &str,
) -> Result<FamilyDrillReceiptArtifact, LifeboatError> {
    if !is_utc_second_timestamp(completed_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("family drill receipt time must be a UTC second timestamp"));
    }
    if app_version.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("family drill receipt app version is required"));
    }

    let packet_id = normalize_optional_packet_id(input.packet_id)?;
    let all_steps_done = FamilyDrillReceiptStep::ALL
        .iter()
        .all(|step| input.completed_steps.contains(step));
    let all_confidence_done = FamilyDrillConfidenceCheck::ALL
        .iter()
        .all(|check| input.confidence_checks.contains(check));
    let result = if !input.user_stopped && all_steps_done && all_confidence_done {
        DrillStepResult::Pass
    } else {
        DrillStepResult::Fail
    };
    let network = input.network.map(PracticeDrillNetwork::as_str);
    let receipt_hash = family_drill_receipt_hash(&FamilyDrillReceiptHashSource {
        schema_version: FAMILY_DRILL_RECEIPT_SCHEMA_VERSION,
        packet_id: packet_id.as_deref(),
        completed_at,
        network,
        result,
        completed_steps: &input.completed_steps,
        confidence_checks: &input.confidence_checks,
        user_stopped: input.user_stopped,
    })?;
    let body = family_drill_receipt_lines(&FamilyDrillReceiptSummary {
        packet_id: packet_id.as_deref(),
        completed_at,
        network,
        result,
        completed_steps: &input.completed_steps,
        confidence_checks: &input.confidence_checks,
        user_stopped: input.user_stopped,
        receipt_hash: &receipt_hash,
    });
    let body_refs = body.iter().map(String::as_str).collect::<Vec<_>>();
    let template = BaseTemplate {
        title: FAMILY_DRILL_RECEIPT_TITLE,
        body: &body_refs,
        footer: RunbookFooter {
            lifeboat_version: app_version,
            report_hash: &receipt_hash,
        },
    };
    let content = render_base_pdf(
        &template,
        PdfBackend::Printpdf,
        PageSize::A4,
        RedactionMode::PublicSafe,
    )?;

    Ok(FamilyDrillReceiptArtifact {
        schema_version: FAMILY_DRILL_RECEIPT_SCHEMA_VERSION.to_owned(),
        format: "pdf".to_owned(),
        redaction: "public-safe".to_owned(),
        mime_type: "application/pdf".to_owned(),
        suggested_filename: FAMILY_DRILL_RECEIPT_FILENAME.to_owned(),
        receipt_hash,
        content,
    })
}

/// Save a completed Practice Mode receive/send drill record after explicit user
/// opt-in. The record is written under `<data_dir>/drills/<uuid>.json` and signed
/// with the per-install Ed25519 key stored in `<data_dir>`.
pub fn save_practice_drill_result(
    data_dir: &Path,
    result: PracticeSendDrillResult,
    completed_at: &str,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    if !result.finalized {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("only finalized practice drills can be saved"));
    }
    if completed_at.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill completion time is required"));
    }

    let payload = practice_drill_payload(result, completed_at)?;
    save_drill_result(data_dir, payload)
}

/// Run a questionnaire-only disaster drill (DS-1..DS-6) without signing.
///
/// The descriptor and known address are screened for secret material before any
/// parsing or derivation. The returned result is not persisted; callers must
/// invoke [`save_disaster_questionnaire_drill_result`] after explicit user opt-in.
pub fn run_disaster_questionnaire_drill(
    input: DisasterQuestionnaireInput,
    started_at: &str,
) -> Result<DisasterQuestionnaireDrillResult, LifeboatError> {
    if input.descriptor.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    if !is_utc_second_timestamp(started_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill start time must be a UTC second timestamp"));
    }

    screen_for_secrets(&input.descriptor)?;
    if let Some(address) = input.known_address.as_deref() {
        screen_for_secrets(address)?;
    }

    let parsed = parse_descriptor(&input.descriptor).ok();
    let steps = disaster_questionnaire_steps(&input, parsed.as_ref());
    let result = if steps
        .iter()
        .all(|step| step.result == DrillStepResult::Pass)
    {
        DrillStepResult::Pass
    } else {
        DrillStepResult::Fail
    };
    let wallet_type = parsed
        .as_ref()
        .map_or_else(|| "unknown".to_owned(), wallet_type_label);
    let report_hash =
        disaster_questionnaire_report_hash(input.scenario, result, &wallet_type, &steps)?;

    Ok(DisasterQuestionnaireDrillResult {
        schema_version: DRILL_RESULT_SCHEMA_VERSION.to_owned(),
        scenario: input.scenario.as_str().to_owned(),
        scenario_title: input.scenario.title().to_owned(),
        started_at: started_at.to_owned(),
        result,
        wallet_type,
        steps,
        report_hash,
    })
}

/// Save a completed questionnaire-only disaster drill after explicit user opt-in.
pub fn save_disaster_questionnaire_drill_result(
    data_dir: &Path,
    result: DisasterQuestionnaireDrillResult,
    completed_at: &str,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    if result.schema_version != DRILL_RESULT_SCHEMA_VERSION {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill schema version is unsupported"));
    }
    if !is_utc_second_timestamp(&result.started_at) || !is_utc_second_timestamp(completed_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill timestamps must be UTC second timestamps"));
    }
    if !is_sha256_tag(&result.report_hash) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill report hash is invalid"));
    }
    if !is_questionnaire_scenario(&result.scenario) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill scenario is unsupported"));
    }
    if questionnaire_scenario_title(&result.scenario) != Some(result.scenario_title.as_str()) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill scenario title is unsupported"));
    }
    if !is_public_wallet_type_label(&result.wallet_type)
        || result
            .steps
            .iter()
            .any(|step| !is_disaster_questionnaire_step(&step.step))
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster drill result contains unsupported public summary fields"));
    }

    let payload = DrillResultPayload {
        schema_version: result.schema_version,
        drill_id: random_uuid_v4(),
        scenario: result.scenario,
        scenario_title: result.scenario_title,
        started_at: result.started_at,
        completed_at: completed_at.to_owned(),
        result: result.result,
        wallet_type: result.wallet_type,
        steps: result.steps,
        report_hash: result.report_hash,
    };
    save_drill_result(data_dir, payload)
}

/// Run a US-089 multisig survivability template without signing.
///
/// The descriptor and known address are screened for secret material before any
/// parsing or report generation. The returned result carries only public
/// readiness status plus the §16.6 survivability verdicts; callers must invoke
/// [`save_multisig_survivability_drill_result`] after explicit user opt-in.
pub fn run_multisig_survivability_drill(
    input: MultisigSurvivabilityDrillInput,
    started_at: &str,
) -> Result<MultisigSurvivabilityDrillResult, LifeboatError> {
    if input.descriptor.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    if !is_utc_second_timestamp(started_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill start time must be a UTC second timestamp"));
    }

    screen_for_secrets(&input.descriptor)?;
    if let Some(address) = input.known_address.as_deref() {
        screen_for_secrets(address)?;
    }

    let parsed = parse_descriptor(&input.descriptor).ok();
    let mut steps = multisig_survivability_steps(input.template, parsed.as_ref());
    steps.push(bool_step("user_did_not_stop", !input.user_stopped));
    let result = if steps
        .iter()
        .all(|step| step.result == DrillStepResult::Pass)
    {
        DrillStepResult::Pass
    } else {
        DrillStepResult::Fail
    };

    let wallet_type = parsed
        .as_ref()
        .map_or_else(|| "unknown".to_owned(), wallet_type_label);
    let (readiness_status, readiness_headline, readiness_score) = parsed
        .as_ref()
        .map(|descriptor| {
            let report = multisig_readiness_report(&input, descriptor, started_at);
            (
                Some(report.score.status),
                Some(report.score.headline),
                Some(report.score.numeric),
            )
        })
        .unwrap_or((None, None, None));
    let survivability = parsed.as_ref().and_then(|descriptor| {
        if template_matches_descriptor(input.template, descriptor) {
            compute_survivability(descriptor)
        } else {
            None
        }
    });
    let report_hash = multisig_survivability_report_hash(MultisigSurvivabilityHashSource {
        template_id: input.template.id(),
        scenario: input.template.scenario(),
        result,
        wallet_type: &wallet_type,
        readiness_status,
        readiness_score,
        survivability: survivability.as_ref(),
        steps: &steps,
    })?;

    Ok(MultisigSurvivabilityDrillResult {
        schema_version: DRILL_RESULT_SCHEMA_VERSION.to_owned(),
        template_id: input.template.id().to_owned(),
        scenario: input.template.scenario().to_owned(),
        scenario_title: input.template.title().to_owned(),
        started_at: started_at.to_owned(),
        result,
        wallet_type,
        readiness_status,
        readiness_headline,
        readiness_score,
        survivability,
        steps,
        report_hash,
    })
}

/// Save a completed US-089 multisig survivability drill after explicit user opt-in.
pub fn save_multisig_survivability_drill_result(
    data_dir: &Path,
    result: MultisigSurvivabilityDrillResult,
    completed_at: &str,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    if result.schema_version != DRILL_RESULT_SCHEMA_VERSION {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill schema version is unsupported"));
    }
    if !is_utc_second_timestamp(&result.started_at) || !is_utc_second_timestamp(completed_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill timestamps must be UTC second timestamps"));
    }
    if !is_sha256_tag(&result.report_hash) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill report hash is invalid"));
    }
    let Some(template) = multisig_template_by_id(&result.template_id) else {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill template is unsupported"));
    };
    if result.scenario != template.scenario() || result.scenario_title != template.title() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill scenario is unsupported"));
    }
    if !is_public_wallet_type_label(&result.wallet_type)
        || result
            .steps
            .iter()
            .any(|step| !is_multisig_survivability_step(&step.step))
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("multisig drill result contains unsupported public summary fields"));
    }

    let payload = DrillResultPayload {
        schema_version: result.schema_version,
        drill_id: random_uuid_v4(),
        scenario: result.scenario,
        scenario_title: result.scenario_title,
        started_at: result.started_at,
        completed_at: completed_at.to_owned(),
        result: result.result,
        wallet_type: result.wallet_type,
        steps: result.steps,
        report_hash: result.report_hash,
    };
    save_drill_result(data_dir, payload)
}

/// Run a US-090 missing-signer drill for a concrete signer index.
///
/// This is an interactive Signet/regtest rehearsal model, not a real multisig
/// spend. The descriptor is screened before parsing, the selected signer is
/// removed from the M-of-N policy, and the result reports whether the remaining
/// signer set can still meet quorum plus the public material categories needed
/// for a safe practice-chain recovery.
pub fn run_missing_signer_drill(
    input: MissingSignerDrillInput,
    started_at: &str,
) -> Result<MissingSignerDrillResult, LifeboatError> {
    if input.descriptor.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty));
    }
    if !is_utc_second_timestamp(started_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("missing-signer drill start time must be a UTC second timestamp"));
    }

    screen_for_secrets(&input.descriptor)?;

    let parsed = parse_descriptor(&input.descriptor).ok();
    let wallet_type = parsed
        .as_ref()
        .map_or_else(|| "unknown".to_owned(), wallet_type_label);
    let plan = parsed
        .as_ref()
        .and_then(|descriptor| missing_signer_plan(descriptor, input.lost_signer_index));

    let (threshold, key_count, remaining_signer_indexes, recovery_possible, required_materials) =
        plan.map_or_else(
            || (0, 0, Vec::new(), false, Vec::new()),
            |plan| {
                (
                    plan.threshold,
                    plan.key_count,
                    plan.remaining_signer_indexes,
                    plan.recovery_possible,
                    plan.required_materials,
                )
            },
        );
    let steps = missing_signer_steps(&input, parsed.as_ref(), recovery_possible);
    let result = if steps
        .iter()
        .all(|step| step.result == DrillStepResult::Pass)
    {
        DrillStepResult::Pass
    } else {
        DrillStepResult::Fail
    };
    let report_hash = missing_signer_report_hash(&MissingSignerHashSource {
        scenario: MISSING_SIGNER_SCENARIO,
        result,
        wallet_type: &wallet_type,
        network: input.network.as_str(),
        threshold,
        key_count,
        lost_signer_index: input.lost_signer_index,
        remaining_signer_indexes: &remaining_signer_indexes,
        recovery_possible,
        required_materials: &required_materials,
        steps: &steps,
    })?;

    Ok(MissingSignerDrillResult {
        schema_version: DRILL_RESULT_SCHEMA_VERSION.to_owned(),
        scenario: MISSING_SIGNER_SCENARIO.to_owned(),
        scenario_title: MISSING_SIGNER_SCENARIO_TITLE.to_owned(),
        started_at: started_at.to_owned(),
        result,
        wallet_type,
        network: input.network.as_str().to_owned(),
        threshold,
        key_count,
        lost_signer_index: input.lost_signer_index,
        remaining_signer_indexes,
        signatures_required: threshold,
        recovery_possible,
        required_materials,
        steps,
        report_hash,
    })
}

/// Save a completed US-090 missing-signer drill after explicit user opt-in.
pub fn save_missing_signer_drill_result(
    data_dir: &Path,
    result: MissingSignerDrillResult,
    completed_at: &str,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    if result.schema_version != DRILL_RESULT_SCHEMA_VERSION {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("missing-signer drill schema version is unsupported"));
    }
    if !is_utc_second_timestamp(&result.started_at) || !is_utc_second_timestamp(completed_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("missing-signer drill timestamps must be UTC second timestamps"));
    }
    if !is_sha256_tag(&result.report_hash) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("missing-signer drill report hash is invalid"));
    }
    if result.scenario != MISSING_SIGNER_SCENARIO
        || result.scenario_title != MISSING_SIGNER_SCENARIO_TITLE
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("missing-signer drill scenario is unsupported"));
    }
    if !matches!(result.network.as_str(), "regtest" | "signet")
        || result.threshold > result.key_count
        || result.key_count > 15
        || result.signatures_required != result.threshold
        || result
            .remaining_signer_indexes
            .iter()
            .any(|index| *index == 0 || *index > result.key_count)
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("missing-signer drill public summary fields are invalid"));
    }
    if !is_public_wallet_type_label(&result.wallet_type)
        || result
            .steps
            .iter()
            .any(|step| !is_missing_signer_step(&step.step))
        || result
            .required_materials
            .iter()
            .any(|material| !is_missing_signer_material(material, result.key_count))
    {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(
                "missing-signer drill result contains unsupported public summary fields",
            ),
        );
    }

    let payload = DrillResultPayload {
        schema_version: result.schema_version,
        drill_id: random_uuid_v4(),
        scenario: result.scenario,
        scenario_title: result.scenario_title,
        started_at: result.started_at,
        completed_at: completed_at.to_owned(),
        result: result.result,
        wallet_type: result.wallet_type,
        steps: result.steps,
        report_hash: result.report_hash,
    };
    save_drill_result(data_dir, payload)
}

/// Start a DS-7..DS-10 disaster signing drill by creating an unsigned practice PSBT.
///
/// The returned PSBT is not persisted. The UI must move it to the signing device
/// by file or QR and later call [`complete_disaster_signing_drill`] with a signed
/// PSBT plus the user's destination-address confirmation.
pub fn start_disaster_signing_drill(
    input: DisasterSigningStartInput,
    started_at: &str,
) -> Result<DisasterSigningStartResult, LifeboatError> {
    if !is_utc_second_timestamp(started_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill start time must be a UTC second timestamp"));
    }

    let network = input.network;
    let mut wallet = DisposableWallet::from_default_practice_seed(network.to_practice_network())?;
    let receive = wallet.receive_address(DRILL_RECEIVE_INDEX);
    apply_local_funding_update(&mut wallet, DEFAULT_DRILL_FUNDING_SAT)?;

    let recipient = wallet.change_address(DRILL_RECIPIENT_INDEX);
    let request = CreatePsbtRequest::new(
        recipient.address().to_owned(),
        DEFAULT_DRILL_SEND_SAT,
        DEFAULT_DRILL_FEE_RATE_SAT_VB,
    );
    let created = create_psbt(&mut wallet, &request)?;

    Ok(DisasterSigningStartResult {
        schema_version: DRILL_RESULT_SCHEMA_VERSION.to_owned(),
        scenario: input.scenario.as_str().to_owned(),
        scenario_title: input.scenario.title().to_owned(),
        started_at: started_at.to_owned(),
        network: network.as_str().to_owned(),
        transport: input.transport.as_str().to_owned(),
        wallet_type: PRACTICE_WALLET_TYPE.to_owned(),
        required_signatures: DISASTER_SIGNING_REQUIRED_SIGNATURES,
        receive_address: receive.address().to_owned(),
        destination_address: recipient.address().to_owned(),
        amount_sat: DEFAULT_DRILL_SEND_SAT,
        fee_rate_sat_vb: DEFAULT_DRILL_FEE_RATE_SAT_VB,
        unsigned_psbt_base64: created.to_base64()?,
    })
}

/// Complete a DS-7..DS-10 disaster signing drill from a signed file or QR PSBT.
///
/// Malformed or under-signed PSBTs are represented as a failing drill result
/// instead of being written automatically. Only invalid timestamps still return a
/// typed error because the resulting DrillResult would be malformed.
pub fn complete_disaster_signing_drill(
    input: DisasterSigningCompleteInput,
) -> Result<DisasterSigningDrillResult, LifeboatError> {
    if !is_utc_second_timestamp(&input.started_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill start time must be a UTC second timestamp"));
    }

    let psbt_present = !input.signed_psbt_base64.trim().is_empty();
    let finalized = if psbt_present {
        finalize_file_psbt(FilePsbtFinalizeInput {
            network: input.network,
            psbt_base64: input.signed_psbt_base64.clone(),
        })
        .ok()
    } else {
        None
    };

    let finalized_txid = finalized
        .as_ref()
        .map_or_else(String::new, |result| result.txid.clone());
    let required_quorum_signed = finalized
        .as_ref()
        .is_some_and(|result| result.inspection.finalized());
    let valid_transaction = finalized
        .as_ref()
        .is_some_and(|result| parse_transaction_hex(&result.transaction_hex).is_ok());
    let destination_output_matches = finalized.as_ref().is_some_and(|result| {
        destination_output_matches(
            &result.inspection,
            &input.expected_destination_address,
            input.expected_amount_sat,
        )
    });

    let steps = vec![
        bool_step("psbt_created", psbt_present),
        bool_step("required_quorum_signed", required_quorum_signed),
        bool_step("psbt_finalized", finalized.is_some()),
        bool_step("valid_transaction", valid_transaction),
        bool_step(
            "destination_confirmed_on_device",
            input.destination_confirmed,
        ),
        bool_step("destination_output_matches", destination_output_matches),
        bool_step("user_did_not_stop", !input.user_stopped),
    ];
    let result = if steps
        .iter()
        .all(|step| step.result == DrillStepResult::Pass)
    {
        DrillStepResult::Pass
    } else {
        DrillStepResult::Fail
    };
    let report_hash = disaster_signing_report_hash(&DisasterSigningHashSource {
        scenario: input.scenario.as_str(),
        network: input.network.as_str(),
        transport: input.transport.as_str(),
        result,
        wallet_type: PRACTICE_WALLET_TYPE,
        required_signatures: DISASTER_SIGNING_REQUIRED_SIGNATURES,
        finalized_txid: &finalized_txid,
        steps: &steps,
    })?;

    Ok(DisasterSigningDrillResult {
        schema_version: DRILL_RESULT_SCHEMA_VERSION.to_owned(),
        scenario: input.scenario.as_str().to_owned(),
        scenario_title: input.scenario.title().to_owned(),
        started_at: input.started_at,
        result,
        wallet_type: PRACTICE_WALLET_TYPE.to_owned(),
        network: input.network.as_str().to_owned(),
        transport: input.transport.as_str().to_owned(),
        required_signatures: DISASTER_SIGNING_REQUIRED_SIGNATURES,
        finalized_txid,
        steps,
        report_hash,
    })
}

/// Save a completed DS-7..DS-10 signing disaster drill after explicit user opt-in.
pub fn save_disaster_signing_drill_result(
    data_dir: &Path,
    result: DisasterSigningDrillResult,
    completed_at: &str,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    if result.schema_version != DRILL_RESULT_SCHEMA_VERSION {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill schema version is unsupported"));
    }
    if !is_utc_second_timestamp(&result.started_at) || !is_utc_second_timestamp(completed_at) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill timestamps must be UTC second timestamps"));
    }
    if !is_sha256_tag(&result.report_hash) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill report hash is invalid"));
    }
    if signing_scenario_title(&result.scenario) != Some(result.scenario_title.as_str())
        || !is_signing_scenario(&result.scenario)
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill scenario is unsupported"));
    }
    if !matches!(result.network.as_str(), "regtest" | "signet")
        || !matches!(result.transport.as_str(), "file" | "qr" | "hwi")
        || !(1..=15).contains(&result.required_signatures)
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("disaster signing drill public summary fields are invalid"));
    }
    if result.result == DrillStepResult::Pass && Txid::from_str(&result.finalized_txid).is_err() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("passed disaster signing drill transaction id is invalid"));
    }
    if !is_public_wallet_type_label(&result.wallet_type)
        || result
            .steps
            .iter()
            .any(|step| !is_disaster_signing_step(&step.step))
    {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(
                "disaster signing drill result contains unsupported public summary fields",
            ),
        );
    }

    let payload = DrillResultPayload {
        schema_version: result.schema_version,
        drill_id: random_uuid_v4(),
        scenario: result.scenario,
        scenario_title: result.scenario_title,
        started_at: result.started_at,
        completed_at: completed_at.to_owned(),
        result: result.result,
        wallet_type: result.wallet_type,
        steps: result.steps,
        report_hash: result.report_hash,
    };
    save_drill_result(data_dir, payload)
}

/// Default application data directory for local drill history.
///
/// Linux follows the PRD's XDG path: `$XDG_DATA_HOME/lifeboat`, or
/// `~/.local/share/lifeboat` when `XDG_DATA_HOME` is unset. macOS and Windows use
/// their platform-equivalent roaming application-data directories.
pub fn default_drill_data_dir() -> Result<PathBuf, LifeboatError> {
    platform_data_home().map(|base| base.join("lifeboat"))
}

/// Verify that a saved record matches the schema and that its Ed25519 signature
/// covers the top-level §19.5 payload fields.
pub fn validate_drill_result_record(record: &DrillResultRecord) -> Result<(), LifeboatError> {
    validate_drill_payload_schema(&record.payload)?;
    if record.signature.algorithm != DRILL_SIGNATURE_ALGORITHM {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record signature algorithm is unsupported"));
    }

    let payload_bytes = drill_payload_signing_bytes(&record.payload)?;
    let expected_hash = sha256_tag(&payload_bytes);
    if record.signature.payload_sha256 != expected_hash {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record payload hash does not match"));
    }

    let public_key_bytes = decode_base64_fixed::<32>(
        &record.signature.public_key,
        "drill record public key is not valid base64",
        "drill record public key has the wrong byte length",
    )?;
    let signature_bytes = decode_base64_fixed::<64>(
        &record.signature.signature,
        "drill record signature is not valid base64",
        "drill record signature has the wrong byte length",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record public key is not a valid Ed25519 key")
            .with_source(err)
    })?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("drill record signature does not verify")
                .with_source(err)
        })
}

/// Broadcast a finalized transaction to a public Signet Esplora endpoint.
///
/// This function performs a real network call through the system curl command.
/// Call it only from an explicit user-confirmed UI path.
pub fn broadcast_signet_transaction(
    input: SignetBroadcastInput,
) -> Result<SignetBroadcastResult, LifeboatError> {
    broadcast_signet_transaction_with(&input, &SystemCurlBroadcaster::default())
}

/// Broadcast through an injected transport. Tests use this to avoid network IO.
pub fn broadcast_signet_transaction_with<B: SignetBroadcaster>(
    input: &SignetBroadcastInput,
    broadcaster: &B,
) -> Result<SignetBroadcastResult, LifeboatError> {
    if input.network != PracticeDrillNetwork::Signet {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("only Signet transactions can be broadcast from Practice Mode"));
    }

    let trimmed = input.transaction_hex.trim();
    let transaction = parse_transaction_hex(trimmed)?;
    let expected_txid = transaction.compute_txid();
    let endpoint_url = input.endpoint.api_url();
    let response = broadcaster.broadcast(endpoint_url, trimmed)?;
    let returned_txid = response.trim();
    let returned_txid = Txid::from_str(returned_txid).map_err(|err| {
        LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context("Signet broadcast endpoint did not return a transaction id")
            .with_source(err)
    })?;
    if returned_txid != expected_txid {
        return Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context("Signet broadcast endpoint returned a different transaction id"));
    }

    Ok(SignetBroadcastResult {
        network: input.network.as_str().to_owned(),
        endpoint: input.endpoint.as_str().to_owned(),
        endpoint_url: endpoint_url.to_owned(),
        txid: returned_txid.to_string(),
    })
}

/// A local PSBT creation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePsbtRequest {
    recipient_address: String,
    amount_sat: u64,
    fee_rate_sat_vb: u64,
}

impl CreatePsbtRequest {
    /// Build a request to pay `amount_sat` to `recipient_address`.
    #[must_use]
    pub fn new(
        recipient_address: impl Into<String>,
        amount_sat: u64,
        fee_rate_sat_vb: u64,
    ) -> Self {
        Self {
            recipient_address: recipient_address.into(),
            amount_sat,
            fee_rate_sat_vb,
        }
    }

    /// Address string as entered or selected by the user.
    #[must_use]
    pub fn recipient_address(&self) -> &str {
        &self.recipient_address
    }

    /// Recipient amount in satoshis.
    #[must_use]
    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    /// Local/user-supplied fee rate in sat/vbyte.
    #[must_use]
    pub const fn fee_rate_sat_vb(&self) -> u64 {
        self.fee_rate_sat_vb
    }
}

/// A PSBT plus its structured local inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtDrill {
    psbt: Psbt,
    inspection: PsbtInspection,
}

impl PsbtDrill {
    /// The PSBT object.
    #[must_use]
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// Consume this wrapper and return the PSBT.
    #[must_use]
    pub fn into_psbt(self) -> Psbt {
        self.psbt
    }

    /// Structured inspection derived from local PSBT data.
    #[must_use]
    pub const fn inspection(&self) -> &PsbtInspection {
        &self.inspection
    }

    /// Export this PSBT as base64, preferring BIP370 v2 for Taproot script-path data.
    pub fn to_base64(&self) -> Result<String, LifeboatError> {
        export_psbt_base64(&self.psbt)
    }

    /// Export this PSBT in legacy BIP174 v0 base64 form.
    #[must_use]
    pub fn to_bip174_base64(&self) -> String {
        self.psbt.to_string()
    }
}

/// A finalized PSBT and the extracted transaction it can rehearse broadcasting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedPsbt {
    psbt: Psbt,
    inspection: PsbtInspection,
    transaction: Transaction,
}

impl FinalizedPsbt {
    /// Finalized PSBT containing final script witness/scriptSig data.
    #[must_use]
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// Structured inspection derived from local PSBT data.
    #[must_use]
    pub const fn inspection(&self) -> &PsbtInspection {
        &self.inspection
    }

    /// Extracted transaction.
    #[must_use]
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Transaction id of the extracted transaction.
    #[must_use]
    pub fn txid(&self) -> Txid {
        self.transaction.compute_txid()
    }

    /// Consensus-encoded transaction bytes for display/export.
    #[must_use]
    pub fn transaction_bytes(&self) -> Vec<u8> {
        serialize(&self.transaction)
    }
}

/// Stable structured PSBT inspection for UI/CLI display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsbtInspection {
    version: u32,
    network: String,
    input_count: usize,
    output_count: usize,
    input_total_sat: u64,
    output_total_sat: u64,
    fee_sat: u64,
    fee_rate_sat_vb: u64,
    txid: String,
    finalized: bool,
    inputs: Vec<PsbtInputInspection>,
    outputs: Vec<PsbtOutputInspection>,
}

impl PsbtInspection {
    /// PSBT global version. US-069 accepts only v0.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Stable network label.
    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Number of unsigned transaction inputs.
    #[must_use]
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of unsigned transaction outputs.
    #[must_use]
    pub const fn output_count(&self) -> usize {
        self.output_count
    }

    /// Total input amount in satoshis, derived from PSBT UTXO records.
    #[must_use]
    pub const fn input_total_sat(&self) -> u64 {
        self.input_total_sat
    }

    /// Total output amount in satoshis.
    #[must_use]
    pub const fn output_total_sat(&self) -> u64 {
        self.output_total_sat
    }

    /// Fee in satoshis (`inputs - outputs`), local-only.
    #[must_use]
    pub const fn fee_sat(&self) -> u64 {
        self.fee_sat
    }

    /// Effective fee rate rounded up to sat/vbyte.
    #[must_use]
    pub const fn fee_rate_sat_vb(&self) -> u64 {
        self.fee_rate_sat_vb
    }

    /// Unsigned transaction id.
    #[must_use]
    pub fn txid(&self) -> &str {
        &self.txid
    }

    /// Whether every input is finalized.
    #[must_use]
    pub const fn finalized(&self) -> bool {
        self.finalized
    }

    /// Per-input inspection, in transaction order.
    #[must_use]
    pub fn inputs(&self) -> &[PsbtInputInspection] {
        &self.inputs
    }

    /// Per-output inspection, in transaction order.
    #[must_use]
    pub fn outputs(&self) -> &[PsbtOutputInspection] {
        &self.outputs
    }
}

/// Per-input PSBT inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsbtInputInspection {
    index: usize,
    previous_output: String,
    sequence: u32,
    amount_sat: u64,
    has_witness_utxo: bool,
    has_non_witness_utxo: bool,
    finalized: bool,
}

impl PsbtInputInspection {
    /// Input index.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Previous outpoint string (`txid:vout`).
    #[must_use]
    pub fn previous_output(&self) -> &str {
        &self.previous_output
    }

    /// nSequence as a consensus integer.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Previous output amount in satoshis.
    #[must_use]
    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    /// Whether the PSBT input carries a witness UTXO.
    #[must_use]
    pub const fn has_witness_utxo(&self) -> bool {
        self.has_witness_utxo
    }

    /// Whether the PSBT input carries a non-witness UTXO.
    #[must_use]
    pub const fn has_non_witness_utxo(&self) -> bool {
        self.has_non_witness_utxo
    }

    /// Whether this input has final script data.
    #[must_use]
    pub const fn finalized(&self) -> bool {
        self.finalized
    }
}

/// Per-output PSBT inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsbtOutputInspection {
    index: usize,
    amount_sat: u64,
    script_pubkey: String,
    address: Option<String>,
}

impl PsbtOutputInspection {
    /// Output index.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Output amount in satoshis.
    #[must_use]
    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    /// Script pubkey as lowercase hex.
    #[must_use]
    pub fn script_pubkey(&self) -> &str {
        &self.script_pubkey
    }

    /// Address, when the script maps to a standard address on the selected network.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

/// Create a BIP174 PSBT v0 from the disposable practice wallet.
pub fn create_psbt(
    wallet: &mut DisposableWallet,
    request: &CreatePsbtRequest,
) -> Result<PsbtDrill, LifeboatError> {
    if request.amount_sat == 0 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT amount must be greater than zero"));
    }
    let fee_rate = FeeRate::from_sat_per_vb(request.fee_rate_sat_vb).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context("PSBT fee rate is too large")
    })?;
    if fee_rate == FeeRate::ZERO {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT fee rate must be greater than zero"));
    }

    let recipient = parse_network_address(request.recipient_address(), wallet.network())?;
    let mut builder = wallet.wallet_mut().build_tx();
    builder
        .add_recipient(
            recipient.script_pubkey(),
            Amount::from_sat(request.amount_sat),
        )
        .fee_rate(fee_rate);
    let psbt = builder.finish().map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice wallet cannot create PSBT with available local funds")
            .with_source(err)
    })?;

    wrap_psbt(psbt, wallet.network())
}

/// Import a base64 BIP174 PSBT v0 or BIP370 PSBT v2 and inspect it.
pub fn import_psbt_base64(input: &str, network: Network) -> Result<PsbtDrill, LifeboatError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputEmpty).with_context("PSBT import text is empty")
        );
    }
    if trimmed.len() > MAX_PSBT_SIZE_BYTES {
        return Err(LifeboatError::new(ErrorCode::InputTooLarge)
            .with_context("PSBT import exceeds the 10 MB limit"));
    }

    let bytes = BASE64_STANDARD.decode(trimmed).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT base64 could not be decoded")
            .with_source(err)
    })?;
    if bytes.len() > MAX_PSBT_SIZE_BYTES {
        return Err(LifeboatError::new(ErrorCode::InputTooLarge)
            .with_context("decoded PSBT import exceeds the 10 MB limit"));
    }

    let psbt = match Psbt::deserialize(&bytes) {
        Ok(psbt) => psbt,
        Err(_) => decode_psbt_v2(&bytes)?,
    };
    wrap_psbt(psbt, network)
}

/// Export a PSBT as base64, selecting BIP370 v2 when Taproot script-path data is present.
pub fn export_psbt_base64(psbt: &Psbt) -> Result<String, LifeboatError> {
    if psbt.version == PSBT_VERSION_V2 || uses_taproot_script_path(psbt) {
        export_psbt_v2_base64(psbt)
    } else {
        Ok(psbt.to_string())
    }
}

/// Export a PSBT in BIP370 v2 base64 form.
pub fn export_psbt_v2_base64(psbt: &Psbt) -> Result<String, LifeboatError> {
    let bytes = encode_psbt_v2(psbt)?;
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Whether the PSBT carries Taproot script-path metadata.
#[must_use]
pub fn uses_taproot_script_path(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        !input.tap_scripts.is_empty()
            || !input.tap_script_sigs.is_empty()
            || input
                .tap_key_origins
                .values()
                .any(|(leaf_hashes, _)| !leaf_hashes.is_empty())
    }) || psbt.outputs.iter().any(|output| {
        output.tap_tree.is_some()
            || output
                .tap_key_origins
                .values()
                .any(|(leaf_hashes, _)| !leaf_hashes.is_empty())
    })
}

/// Validate and inspect a PSBT using only local PSBT data.
pub fn inspect_psbt(psbt: &Psbt, network: Network) -> Result<PsbtInspection, LifeboatError> {
    validate_psbt(psbt)?;

    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    let mut input_total_sat = 0_u64;
    for (index, (txin, input)) in psbt
        .unsigned_tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .enumerate()
    {
        let txout = input_txout(txin.previous_output.vout, input)?;
        let amount_sat = txout.value.to_sat();
        input_total_sat = input_total_sat.checked_add(amount_sat).ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT input amounts overflowed local inspection")
        })?;
        inputs.push(PsbtInputInspection {
            index,
            previous_output: txin.previous_output.to_string(),
            sequence: txin.sequence.to_consensus_u32(),
            amount_sat,
            has_witness_utxo: input.witness_utxo.is_some(),
            has_non_witness_utxo: input.non_witness_utxo.is_some(),
            finalized: input.final_script_sig.is_some() || input.final_script_witness.is_some(),
        });
    }

    let mut outputs = Vec::with_capacity(psbt.unsigned_tx.output.len());
    let mut output_total_sat = 0_u64;
    for (index, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        let amount_sat = txout.value.to_sat();
        output_total_sat = output_total_sat.checked_add(amount_sat).ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT output amounts overflowed local inspection")
        })?;
        outputs.push(PsbtOutputInspection {
            index,
            amount_sat,
            script_pubkey: script_hex(&txout.script_pubkey),
            address: Address::from_script(&txout.script_pubkey, network)
                .map(|address| address.to_string())
                .ok(),
        });
    }

    let fee_sat = input_total_sat
        .checked_sub(output_total_sat)
        .ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT outputs exceed locally known input amounts")
        })?;
    let tx_weight = psbt.unsigned_tx.weight();
    let vbytes = tx_weight.to_vbytes_ceil();
    let fee_rate_sat_vb = if vbytes == 0 {
        0
    } else {
        fee_sat.div_ceil(vbytes)
    };
    let finalized = inputs.iter().all(PsbtInputInspection::finalized);

    Ok(PsbtInspection {
        version: psbt.version,
        network: network_label(network).to_owned(),
        input_count: psbt.unsigned_tx.input.len(),
        output_count: psbt.unsigned_tx.output.len(),
        input_total_sat,
        output_total_sat,
        fee_sat,
        fee_rate_sat_vb,
        txid: psbt.unsigned_tx.compute_txid().to_string(),
        finalized,
        inputs,
        outputs,
    })
}

/// Sign the PSBT with the disposable practice wallet without finalizing it.
pub fn sign_psbt(wallet: &DisposableWallet, mut psbt: Psbt) -> Result<PsbtDrill, LifeboatError> {
    inspect_psbt(&psbt, wallet.network())?;
    let signed_and_finalized = wallet
        .wallet()
        .sign(&mut psbt, signing_options(false))
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("practice wallet could not sign PSBT")
                .with_source(err)
        })?;
    if signed_and_finalized {
        return Err(LifeboatError::new(ErrorCode::Internal)
            .with_context("PSBT signer finalized despite finalize=false"));
    }
    wrap_psbt(psbt, wallet.network())
}

/// Finalize a signed PSBT and extract the transaction.
pub fn finalize_psbt(
    wallet: &DisposableWallet,
    mut psbt: Psbt,
) -> Result<FinalizedPsbt, LifeboatError> {
    inspect_psbt(&psbt, wallet.network())?;
    let finalized = wallet
        .wallet()
        .finalize_psbt(&mut psbt, signing_options(true))
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("practice wallet could not finalize PSBT")
                .with_source(err)
        })?;
    if !finalized {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT does not contain enough signatures to finalize"));
    }
    let inspection = inspect_psbt(&psbt, wallet.network())?;
    let transaction = psbt.clone().extract_tx_fee_rate_limit().map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("finalized PSBT could not be extracted as a transaction")
            .with_source(err)
    })?;
    Ok(FinalizedPsbt {
        psbt,
        inspection,
        transaction,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawKey {
    type_value: u8,
    key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawPair {
    key: RawKey,
    value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawPsbt {
    global: Vec<RawPair>,
    inputs: Vec<Vec<RawPair>>,
    outputs: Vec<Vec<RawPair>>,
}

fn decode_psbt_v2(bytes: &[u8]) -> Result<Psbt, LifeboatError> {
    let raw = decode_raw_psbt_v2(bytes)?;
    let unsigned_tx = reconstruct_v2_unsigned_tx(&raw)?;
    let v0_bytes = encode_v0_psbt_bytes(&raw, &unsigned_tx);
    let mut psbt = Psbt::deserialize(&v0_bytes).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BIP370 PSBT v2 could not be converted for local inspection")
            .with_source(err)
    })?;
    psbt.version = PSBT_VERSION_V2;
    Ok(psbt)
}

fn encode_psbt_v2(psbt: &Psbt) -> Result<Vec<u8>, LifeboatError> {
    validate_psbt(psbt)?;
    let raw =
        decode_raw_psbt_with_counts(&psbt.serialize(), psbt.inputs.len(), psbt.outputs.len())?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"psbt");
    bytes.push(0xff);

    append_pair(
        &mut bytes,
        PSBT_GLOBAL_TX_VERSION,
        &[],
        &serialize(&psbt.unsigned_tx.version),
    );
    let lock_time = psbt.unsigned_tx.lock_time.to_consensus_u32();
    if lock_time != 0 {
        append_pair(
            &mut bytes,
            PSBT_GLOBAL_FALLBACK_LOCKTIME,
            &[],
            &lock_time.to_le_bytes(),
        );
    }
    append_pair(
        &mut bytes,
        PSBT_GLOBAL_INPUT_COUNT,
        &[],
        &serialize(&VarInt(psbt.inputs.len() as u64)),
    );
    append_pair(
        &mut bytes,
        PSBT_GLOBAL_OUTPUT_COUNT,
        &[],
        &serialize(&VarInt(psbt.outputs.len() as u64)),
    );
    append_pair(
        &mut bytes,
        PSBT_GLOBAL_VERSION,
        &[],
        &PSBT_VERSION_V2.to_le_bytes(),
    );
    for pair in raw
        .global
        .iter()
        .filter(|pair| !is_v2_excluded_global(pair))
    {
        append_raw_pair(&mut bytes, pair);
    }
    append_map_separator(&mut bytes);

    for (txin, map) in psbt.unsigned_tx.input.iter().zip(raw.inputs.iter()) {
        append_pair(
            &mut bytes,
            PSBT_IN_PREVIOUS_TXID,
            &[],
            txin.previous_output.txid.as_byte_array(),
        );
        append_pair(
            &mut bytes,
            PSBT_IN_OUTPUT_INDEX,
            &[],
            &txin.previous_output.vout.to_le_bytes(),
        );
        let sequence = txin.sequence.to_consensus_u32();
        if sequence != Sequence::MAX.to_consensus_u32() {
            append_pair(&mut bytes, PSBT_IN_SEQUENCE, &[], &sequence.to_le_bytes());
        }
        for pair in map.iter().filter(|pair| !is_v2_excluded_input(pair)) {
            append_raw_pair(&mut bytes, pair);
        }
        append_map_separator(&mut bytes);
    }

    for (txout, map) in psbt.unsigned_tx.output.iter().zip(raw.outputs.iter()) {
        let amount = i64::try_from(txout.value.to_sat()).map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT output amount is too large for BIP370")
        })?;
        append_pair(&mut bytes, PSBT_OUT_AMOUNT, &[], &amount.to_le_bytes());
        append_pair(
            &mut bytes,
            PSBT_OUT_SCRIPT,
            &[],
            txout.script_pubkey.as_bytes(),
        );
        for pair in map.iter().filter(|pair| !is_v2_excluded_output(pair)) {
            append_raw_pair(&mut bytes, pair);
        }
        append_map_separator(&mut bytes);
    }

    Ok(bytes)
}

fn decode_raw_psbt_v2(bytes: &[u8]) -> Result<RawPsbt, LifeboatError> {
    let global = decode_raw_global(bytes)?;
    let version = required_u32(&global, PSBT_GLOBAL_VERSION, "PSBT_GLOBAL_VERSION")?;
    if version != PSBT_VERSION_V2 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT is not BIP370 version 2"));
    }
    if has_type(&global, PSBT_GLOBAL_UNSIGNED_TX) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BIP370 PSBT v2 must not include PSBT_GLOBAL_UNSIGNED_TX"));
    }

    let input_count =
        required_compact_size(&global, PSBT_GLOBAL_INPUT_COUNT, "PSBT_GLOBAL_INPUT_COUNT")?;
    let output_count = required_compact_size(
        &global,
        PSBT_GLOBAL_OUTPUT_COUNT,
        "PSBT_GLOBAL_OUTPUT_COUNT",
    )?;

    decode_raw_psbt_with_counts(bytes, input_count, output_count)
}

fn decode_raw_global(bytes: &[u8]) -> Result<Vec<RawPair>, LifeboatError> {
    if bytes.len() < 5 || &bytes[0..4] != b"psbt" || bytes[4] != 0xff {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT binary magic header is invalid"));
    }
    let mut cursor = Cursor::new(&bytes[5..]);
    decode_raw_map(&mut cursor)
}

fn decode_raw_psbt_with_counts(
    bytes: &[u8],
    input_count: usize,
    output_count: usize,
) -> Result<RawPsbt, LifeboatError> {
    if bytes.len() < 5 || &bytes[0..4] != b"psbt" || bytes[4] != 0xff {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT binary magic header is invalid"));
    }
    let mut cursor = Cursor::new(&bytes[5..]);
    let global = decode_raw_map(&mut cursor)?;

    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(decode_raw_map(&mut cursor)?);
    }

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(decode_raw_map(&mut cursor)?);
    }

    if cursor.position() != cursor.get_ref().len() as u64 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT contains trailing data after output maps"));
    }

    Ok(RawPsbt {
        global,
        inputs,
        outputs,
    })
}

fn decode_raw_map(cursor: &mut Cursor<&[u8]>) -> Result<Vec<RawPair>, LifeboatError> {
    let mut pairs = Vec::new();
    loop {
        let key_len = read_compact_size(cursor, "PSBT key length")?;
        if key_len == 0 {
            break;
        }
        let key_len = usize::try_from(key_len).map_err(|_| {
            LifeboatError::new(ErrorCode::InputTooLarge)
                .with_context("PSBT key length is too large")
        })?;
        let type_value = read_u8(cursor, "PSBT key type")?;
        let mut key = vec![0_u8; key_len.saturating_sub(1)];
        cursor.read_exact(&mut key).map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT key data is truncated")
                .with_source(err)
        })?;
        let value_len = read_compact_size(cursor, "PSBT value length")?;
        let value_len = usize::try_from(value_len).map_err(|_| {
            LifeboatError::new(ErrorCode::InputTooLarge)
                .with_context("PSBT value length is too large")
        })?;
        let mut value = vec![0_u8; value_len];
        cursor.read_exact(&mut value).map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT value data is truncated")
                .with_source(err)
        })?;

        let raw_key = RawKey { type_value, key };
        if pairs.iter().any(|pair: &RawPair| pair.key == raw_key) {
            return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT map contains a duplicate key"));
        }
        pairs.push(RawPair {
            key: raw_key,
            value,
        });
    }
    Ok(pairs)
}

fn reconstruct_v2_unsigned_tx(raw: &RawPsbt) -> Result<Transaction, LifeboatError> {
    let version = required_i32(
        &raw.global,
        PSBT_GLOBAL_TX_VERSION,
        "PSBT_GLOBAL_TX_VERSION",
    )?;
    let lock_time = determine_v2_lock_time(raw)?;

    let mut input = Vec::with_capacity(raw.inputs.len());
    for map in &raw.inputs {
        let txid_bytes = required_bytes(map, PSBT_IN_PREVIOUS_TXID, "PSBT_IN_PREVIOUS_TXID", 32)?;
        let txid = Txid::from_byte_array(txid_bytes.try_into().map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT_IN_PREVIOUS_TXID must be 32 bytes")
        })?);
        let vout = required_u32(map, PSBT_IN_OUTPUT_INDEX, "PSBT_IN_OUTPUT_INDEX")?;
        let sequence = optional_u32(map, PSBT_IN_SEQUENCE, "PSBT_IN_SEQUENCE")?
            .unwrap_or_else(|| Sequence::MAX.to_consensus_u32());
        input.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::default(),
        });
    }

    let mut output = Vec::with_capacity(raw.outputs.len());
    for map in &raw.outputs {
        let amount = required_i64(map, PSBT_OUT_AMOUNT, "PSBT_OUT_AMOUNT")?;
        let amount = u64::try_from(amount).map_err(|_| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT_OUT_AMOUNT cannot be negative")
        })?;
        let script = required_value(map, PSBT_OUT_SCRIPT, "PSBT_OUT_SCRIPT")?;
        output.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
        });
    }

    Ok(Transaction {
        version: transaction::Version::non_standard(version),
        lock_time,
        input,
        output,
    })
}

fn determine_v2_lock_time(raw: &RawPsbt) -> Result<absolute::LockTime, LifeboatError> {
    let fallback = optional_u32(
        &raw.global,
        PSBT_GLOBAL_FALLBACK_LOCKTIME,
        "PSBT_GLOBAL_FALLBACK_LOCKTIME",
    )?
    .unwrap_or(0);
    let mut heights = Vec::new();
    let mut times = Vec::new();
    let mut can_use_height = true;
    let mut can_use_time = true;

    for map in &raw.inputs {
        let height = optional_u32(
            map,
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
            "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
        )?;
        let time = optional_u32(
            map,
            PSBT_IN_REQUIRED_TIME_LOCKTIME,
            "PSBT_IN_REQUIRED_TIME_LOCKTIME",
        )?;
        if let Some(height) = height {
            if height == 0 || height >= 500_000_000 {
                return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                    .with_context("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME is out of range"));
            }
            heights.push(height);
        }
        if let Some(time) = time {
            if time < 500_000_000 {
                return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                    .with_context("PSBT_IN_REQUIRED_TIME_LOCKTIME is out of range"));
            }
            times.push(time);
        }
        if height.is_none() && time.is_some() {
            can_use_height = false;
        }
        if time.is_none() && height.is_some() {
            can_use_time = false;
        }
    }

    let consensus = if !heights.is_empty() && can_use_height {
        heights.into_iter().max().unwrap_or(fallback)
    } else if !times.is_empty() && can_use_time {
        times.into_iter().max().unwrap_or(fallback)
    } else if heights.is_empty() && times.is_empty() {
        fallback
    } else {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT v2 input locktime requirements are incompatible"));
    };
    Ok(absolute::LockTime::from_consensus(consensus))
}

fn encode_v0_psbt_bytes(raw: &RawPsbt, unsigned_tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"psbt");
    bytes.push(0xff);
    append_pair(
        &mut bytes,
        PSBT_GLOBAL_UNSIGNED_TX,
        &[],
        &serialize_unsigned_tx(unsigned_tx),
    );
    for pair in raw
        .global
        .iter()
        .filter(|pair| !is_v2_excluded_global(pair))
    {
        append_raw_pair(&mut bytes, pair);
    }
    append_map_separator(&mut bytes);
    for map in &raw.inputs {
        for pair in map.iter().filter(|pair| !is_v2_excluded_input(pair)) {
            append_raw_pair(&mut bytes, pair);
        }
        append_map_separator(&mut bytes);
    }
    for map in &raw.outputs {
        for pair in map.iter().filter(|pair| !is_v2_excluded_output(pair)) {
            append_raw_pair(&mut bytes, pair);
        }
        append_map_separator(&mut bytes);
    }
    bytes
}

fn serialize_unsigned_tx(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(serialize(&tx.version));
    bytes.extend(serialize(&tx.input));
    bytes.extend(serialize(&tx.output));
    bytes.extend(serialize(&tx.lock_time));
    bytes
}

fn append_raw_pair(bytes: &mut Vec<u8>, pair: &RawPair) {
    append_pair(bytes, pair.key.type_value, &pair.key.key, &pair.value);
}

fn append_pair(bytes: &mut Vec<u8>, key_type: u8, key_data: &[u8], value: &[u8]) {
    bytes.extend(serialize(&VarInt((key_data.len() + 1) as u64)));
    bytes.push(key_type);
    bytes.extend_from_slice(key_data);
    bytes.extend(serialize(&VarInt(value.len() as u64)));
    bytes.extend_from_slice(value);
}

fn append_map_separator(bytes: &mut Vec<u8>) {
    bytes.push(0);
}

fn is_v2_excluded_global(pair: &RawPair) -> bool {
    pair.key.key.is_empty()
        && matches!(
            pair.key.type_value,
            PSBT_GLOBAL_UNSIGNED_TX
                | PSBT_GLOBAL_TX_VERSION
                | PSBT_GLOBAL_FALLBACK_LOCKTIME
                | PSBT_GLOBAL_INPUT_COUNT
                | PSBT_GLOBAL_OUTPUT_COUNT
                | PSBT_GLOBAL_TX_MODIFIABLE
                | PSBT_GLOBAL_VERSION
        )
}

fn is_v2_excluded_input(pair: &RawPair) -> bool {
    pair.key.key.is_empty()
        && matches!(
            pair.key.type_value,
            PSBT_IN_PREVIOUS_TXID
                | PSBT_IN_OUTPUT_INDEX
                | PSBT_IN_SEQUENCE
                | PSBT_IN_REQUIRED_TIME_LOCKTIME
                | PSBT_IN_REQUIRED_HEIGHT_LOCKTIME
        )
}

fn is_v2_excluded_output(pair: &RawPair) -> bool {
    pair.key.key.is_empty() && matches!(pair.key.type_value, PSBT_OUT_AMOUNT | PSBT_OUT_SCRIPT)
}

fn has_type(pairs: &[RawPair], key_type: u8) -> bool {
    pairs
        .iter()
        .any(|pair| pair.key.type_value == key_type && pair.key.key.is_empty())
}

fn required_value<'a>(
    pairs: &'a [RawPair],
    key_type: u8,
    name: &'static str,
) -> Result<&'a [u8], LifeboatError> {
    optional_value(pairs, key_type, name)?.ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!("{name} is missing"))
    })
}

fn optional_value<'a>(
    pairs: &'a [RawPair],
    key_type: u8,
    name: &'static str,
) -> Result<Option<&'a [u8]>, LifeboatError> {
    if let Some(pair) = pairs.iter().find(|pair| pair.key.type_value == key_type) {
        if !pair.key.key.is_empty() {
            return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context(format!("{name} must not have key data")));
        }
        Ok(Some(&pair.value))
    } else {
        Ok(None)
    }
}

fn required_bytes<'a>(
    pairs: &'a [RawPair],
    key_type: u8,
    name: &'static str,
    len: usize,
) -> Result<&'a [u8], LifeboatError> {
    let value = required_value(pairs, key_type, name)?;
    if value.len() != len {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("{name} has the wrong byte length")));
    }
    Ok(value)
}

fn required_u32(pairs: &[RawPair], key_type: u8, name: &'static str) -> Result<u32, LifeboatError> {
    read_u32(required_bytes(pairs, key_type, name, 4)?, name)
}

fn optional_u32(
    pairs: &[RawPair],
    key_type: u8,
    name: &'static str,
) -> Result<Option<u32>, LifeboatError> {
    optional_value(pairs, key_type, name)?
        .map(|value| {
            if value.len() != 4 {
                return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                    .with_context(format!("{name} has the wrong byte length")));
            }
            read_u32(value, name)
        })
        .transpose()
}

fn required_i32(pairs: &[RawPair], key_type: u8, name: &'static str) -> Result<i32, LifeboatError> {
    let value = required_bytes(pairs, key_type, name, 4)?;
    Ok(i32::from_le_bytes(value.try_into().map_err(|_| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("{name} has the wrong byte length"))
    })?))
}

fn required_i64(pairs: &[RawPair], key_type: u8, name: &'static str) -> Result<i64, LifeboatError> {
    let value = required_bytes(pairs, key_type, name, 8)?;
    Ok(i64::from_le_bytes(value.try_into().map_err(|_| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("{name} has the wrong byte length"))
    })?))
}

fn required_compact_size(
    pairs: &[RawPair],
    key_type: u8,
    name: &'static str,
) -> Result<usize, LifeboatError> {
    let value = required_value(pairs, key_type, name)?;
    let mut cursor = Cursor::new(value);
    let count = read_compact_size(&mut cursor, name)?;
    if cursor.position() != value.len() as u64 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("{name} contains trailing data")));
    }
    usize::try_from(count).map_err(|_| {
        LifeboatError::new(ErrorCode::InputTooLarge).with_context(format!("{name} is too large"))
    })
}

fn read_u32(value: &[u8], name: &'static str) -> Result<u32, LifeboatError> {
    Ok(u32::from_le_bytes(value.try_into().map_err(|_| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("{name} has the wrong byte length"))
    })?))
}

fn read_compact_size(
    cursor: &mut Cursor<&[u8]>,
    context: &'static str,
) -> Result<u64, LifeboatError> {
    VarInt::consensus_decode(cursor)
        .map(|VarInt(value)| value)
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context(format!("{context} is not a compact size integer"))
                .with_source(err)
        })
}

fn read_u8(cursor: &mut Cursor<&[u8]>, context: &'static str) -> Result<u8, LifeboatError> {
    let mut byte = [0_u8; 1];
    cursor.read_exact(&mut byte).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("{context} is truncated"))
            .with_source(err)
    })?;
    Ok(byte[0])
}

fn wrap_psbt(psbt: Psbt, network: Network) -> Result<PsbtDrill, LifeboatError> {
    let inspection = inspect_psbt(&psbt, network)?;
    Ok(PsbtDrill { psbt, inspection })
}

fn validate_psbt(psbt: &Psbt) -> Result<(), LifeboatError> {
    if psbt.version != PSBT_VERSION_V0 && psbt.version != PSBT_VERSION_V2 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("only BIP174 PSBT v0 and BIP370 PSBT v2 are supported in this drill"));
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT input map count does not match unsigned transaction inputs"));
    }
    if psbt.outputs.len() != psbt.unsigned_tx.output.len() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT output map count does not match unsigned transaction outputs"));
    }
    if psbt.unsigned_tx.input.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context("PSBT has no inputs")
        );
    }
    if psbt.unsigned_tx.output.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputInvalidFormat).with_context("PSBT has no outputs")
        );
    }
    if psbt
        .unsigned_tx
        .input
        .iter()
        .any(|txin| !txin.script_sig.is_empty() || !txin.witness.is_empty())
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT unsigned transaction contains script data"));
    }
    for input in &psbt.inputs {
        if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
            return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT input is missing UTXO information"));
        }
    }
    Ok(())
}

fn input_txout(
    vout: u32,
    input: &signet_lab::bitcoin::psbt::Input,
) -> Result<&TxOut, LifeboatError> {
    if let Some(txout) = input.witness_utxo.as_ref() {
        return Ok(txout);
    }
    let previous = input.non_witness_utxo.as_ref().ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT input is missing UTXO information")
    })?;
    previous.output.get(vout as usize).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT non-witness UTXO does not contain the referenced output")
    })
}

fn parse_network_address(
    value: &str,
    network: Network,
) -> Result<Address<NetworkChecked>, LifeboatError> {
    Address::from_str(value)
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("recipient address is not a Bitcoin address")
                .with_source(err)
        })?
        .require_network(network)
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("recipient address is for a different network")
                .with_source(err)
        })
}

/// Apply a synthetic, in-memory funding transaction to a disposable practice
/// wallet. This is for local drills and tests only: it does not call bitcoind,
/// a faucet, an Esplora endpoint, or any other network service.
pub fn apply_local_funding_update(
    wallet: &mut DisposableWallet,
    amount_sat: u64,
) -> Result<OutPoint, LifeboatError> {
    if amount_sat == 0 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice funding amount must be greater than zero"));
    }

    let receive = Address::from_str(wallet.receive_address(DRILL_RECEIVE_INDEX).address())
        .map_err(|err| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("practice receive address could not be parsed")
                .with_source(err)
        })?
        .require_network(wallet.network())
        .map_err(|err| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("practice receive address did not match its network")
                .with_source(err)
        })?;
    let funding_tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: receive.script_pubkey(),
        }],
    };
    let txid = funding_tx.compute_txid();
    let genesis = BlockId {
        height: 0,
        hash: BlockHash::from_slice(wallet.network().chain_hash().as_bytes()).map_err(|err| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("practice network chain hash could not be converted")
                .with_source(err)
        })?,
    };
    let block = BlockId {
        height: 101,
        hash: BlockHash::all_zeros(),
    };
    let anchor = ConfirmationBlockTime {
        block_id: block,
        confirmation_time: 1,
    };
    let mut tx_update = TxUpdate::default();
    tx_update.txs = [Arc::new(funding_tx)].into();
    tx_update.anchors = [(anchor, txid)].into();
    let checkpoint = CheckPoint::from_block_ids([genesis, block]).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("practice funding checkpoint could not be constructed")
    })?;
    let update = Update {
        last_active_indices: [(KeychainKind::External, DRILL_RECEIVE_INDEX)].into(),
        tx_update,
        chain: Some(checkpoint),
    };
    wallet.wallet_mut().apply_update(update).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("practice funding update could not be applied")
            .with_source(err)
    })?;
    Ok(OutPoint { txid, vout: 0 })
}

fn screen_for_secrets(text: &str) -> Result<(), LifeboatError> {
    let report = detect_secret(SecretString::from(text.to_owned()));
    if !report.is_blocked() {
        return Ok(());
    }
    let code = report
        .reason_codes()
        .first()
        .copied()
        .unwrap_or(ErrorCode::RawPrivateKeySuspected);
    Err(LifeboatError::new(code))
}

fn disaster_questionnaire_steps(
    input: &DisasterQuestionnaireInput,
    parsed: Option<&ParsedDescriptor>,
) -> Vec<DrillResultStep> {
    let mut steps = Vec::new();
    match parsed {
        Some(descriptor) => steps.extend(descriptor_drill_steps(input, descriptor)),
        None => {
            steps.push(step("descriptor_parse", DrillStepResult::Fail));
            steps.push(step("derive_expected_addresses", DrillStepResult::Fail));
            steps.push(step("known_address_match", DrillStepResult::Fail));
            if matches!(
                input.scenario,
                DisasterQuestionnaireScenario::Ds5 | DisasterQuestionnaireScenario::Ds6
            ) {
                steps.push(step("multisig_quorum", DrillStepResult::Fail));
            }
        }
    }

    steps.extend(questionnaire_answer_steps(input));
    steps.push(bool_step("user_did_not_stop", !input.user_stopped));
    steps
}

fn descriptor_drill_steps(
    input: &DisasterQuestionnaireInput,
    parsed: &ParsedDescriptor,
) -> Vec<DrillResultStep> {
    let mut check_input = CheckInput::new(parsed).with_network(input.network.to_audit_network());
    let known_address = nonempty_known_address(input);
    if let Some(address) = known_address {
        check_input = check_input.with_known_address(address);
    }
    let checks = run_checks(&check_input);
    let mut steps = vec![
        step("descriptor_parse", DrillStepResult::Pass),
        bool_step(
            "derive_expected_addresses",
            check_result(&checks, "G1") == Some(CheckResult::Pass),
        ),
        bool_step(
            "known_address_match",
            known_address.is_some() && check_result(&checks, "G3") == Some(CheckResult::Pass),
        ),
    ];

    if matches!(
        input.scenario,
        DisasterQuestionnaireScenario::Ds5 | DisasterQuestionnaireScenario::Ds6
    ) {
        steps.push(bool_step(
            "multisig_quorum",
            parsed.multisig_info().is_some(),
        ));
    }
    if input.scenario == DisasterQuestionnaireScenario::Ds5 {
        steps.push(bool_step(
            "available_signers_meet_quorum",
            available_signers_meet_quorum(input.available_signers, parsed),
        ));
    }
    if input.scenario == DisasterQuestionnaireScenario::Ds6 {
        steps.push(bool_step(
            "survives_one_signer_loss",
            compute_survivability(parsed).is_some_and(|s| s.lose_1_signer == "ok"),
        ));
    }
    steps
}

fn multisig_survivability_steps(
    template: MultisigDrillTemplate,
    parsed: Option<&ParsedDescriptor>,
) -> Vec<DrillResultStep> {
    let mut steps = Vec::new();
    match parsed {
        Some(descriptor) => {
            steps.push(step("descriptor_parse", DrillStepResult::Pass));
            steps.push(bool_step(
                "template_matches_descriptor",
                template_matches_descriptor(template, descriptor),
            ));
            steps.push(step("readiness_status_available", DrillStepResult::Pass));
            if template_matches_descriptor(template, descriptor) {
                add_survivability_steps(&mut steps, compute_survivability(descriptor).as_ref());
            } else {
                add_survivability_steps(&mut steps, None);
            }
        }
        None => {
            steps.push(step("descriptor_parse", DrillStepResult::Fail));
            steps.push(step("template_matches_descriptor", DrillStepResult::Fail));
            steps.push(step("readiness_status_available", DrillStepResult::Fail));
            add_survivability_steps(&mut steps, None);
        }
    }
    steps
}

fn add_survivability_steps(
    steps: &mut Vec<DrillResultStep>,
    survivability: Option<&Survivability>,
) {
    steps.push(bool_step(
        "lose_1_signer_survives",
        survivability.is_some_and(|s| s.lose_1_signer == "ok"),
    ));
    steps.push(bool_step(
        "lose_2_signers_survives",
        survivability.is_some_and(|s| s.lose_2_signers == "ok"),
    ));
    steps.push(bool_step(
        "lose_descriptor_backup_survives",
        survivability.is_some_and(|s| s.lose_descriptor_only == "ok_if_xpubs_retained"),
    ));
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MissingSignerPlan {
    threshold: u8,
    key_count: u8,
    remaining_signer_indexes: Vec<u8>,
    recovery_possible: bool,
    required_materials: Vec<MissingSignerRequiredMaterial>,
}

fn missing_signer_steps(
    input: &MissingSignerDrillInput,
    parsed: Option<&ParsedDescriptor>,
    recovery_possible: bool,
) -> Vec<DrillResultStep> {
    let mut steps = Vec::new();
    match parsed {
        Some(descriptor) => {
            steps.push(step("descriptor_parse", DrillStepResult::Pass));
            steps.push(bool_step(
                "multisig_quorum",
                descriptor.multisig_info().is_some(),
            ));
            steps.push(bool_step(
                "lost_signer_in_range",
                lost_signer_in_range(descriptor, input.lost_signer_index),
            ));
            steps.push(bool_step("remaining_quorum_available", recovery_possible));
        }
        None => {
            steps.push(step("descriptor_parse", DrillStepResult::Fail));
            steps.push(step("multisig_quorum", DrillStepResult::Fail));
            steps.push(step("lost_signer_in_range", DrillStepResult::Fail));
            steps.push(step("remaining_quorum_available", DrillStepResult::Fail));
        }
    }
    steps.push(step("practice_chain_selected", DrillStepResult::Pass));
    steps.push(bool_step("user_did_not_stop", !input.user_stopped));
    steps
}

fn missing_signer_plan(
    parsed: &ParsedDescriptor,
    lost_signer_index: u8,
) -> Option<MissingSignerPlan> {
    let info = parsed.multisig_info()?;
    if !lost_signer_in_range(parsed, lost_signer_index) {
        return None;
    }
    let threshold = info.threshold() as u8;
    let key_count = info.key_count() as u8;
    let remaining_signer_indexes: Vec<u8> = (1..=key_count)
        .filter(|index| *index != lost_signer_index)
        .collect();
    let recovery_possible = remaining_signer_indexes.len() >= info.threshold();
    let mut required_materials = vec![
        MissingSignerRequiredMaterial {
            kind: MissingSignerMaterialKind::DescriptorBackup,
            signer_index: None,
        },
        MissingSignerRequiredMaterial {
            kind: MissingSignerMaterialKind::CoordinatorWallet,
            signer_index: None,
        },
        MissingSignerRequiredMaterial {
            kind: MissingSignerMaterialKind::PracticeFunds,
            signer_index: None,
        },
    ];
    required_materials.extend(
        remaining_signer_indexes
            .iter()
            .copied()
            .map(|signer_index| MissingSignerRequiredMaterial {
                kind: MissingSignerMaterialKind::RemainingSigner,
                signer_index: Some(signer_index),
            }),
    );

    Some(MissingSignerPlan {
        threshold,
        key_count,
        remaining_signer_indexes,
        recovery_possible,
        required_materials,
    })
}

fn lost_signer_in_range(parsed: &ParsedDescriptor, lost_signer_index: u8) -> bool {
    parsed.multisig_info().is_some_and(|info| {
        lost_signer_index >= 1 && usize::from(lost_signer_index) <= info.key_count()
    })
}

fn template_matches_descriptor(template: MultisigDrillTemplate, parsed: &ParsedDescriptor) -> bool {
    let Some(info) = parsed.multisig_info() else {
        return false;
    };
    let (threshold, key_count) = template.quorum();
    info.threshold() == threshold && info.key_count() == key_count
}

fn multisig_readiness_report(
    input: &MultisigSurvivabilityDrillInput,
    parsed: &ParsedDescriptor,
    started_at: &str,
) -> report_engine::ReadinessReport {
    let mut report_input = ReportInput::new(parsed, started_at)
        .with_network(input.network.to_audit_network())
        .with_network_confirmed(true)
        .with_declared_wallet_type(DeclaredWalletType::Multisig);
    if let Some(address) = nonempty_multisig_known_address(input) {
        report_input = report_input.with_known_address(address);
    }
    build_report(&report_input)
}

fn questionnaire_answer_steps(input: &DisasterQuestionnaireInput) -> Vec<DrillResultStep> {
    let answers = input.answers;
    match input.scenario {
        DisasterQuestionnaireScenario::Ds1 => vec![
            answer_step(
                "recovery_materials_available",
                answers.recovery_materials_available,
            ),
            answer_step("passphrase_documented", answers.passphrase_documented),
            answer_step(
                "wallet_software_documented",
                answers.wallet_software_documented,
            ),
        ],
        DisasterQuestionnaireScenario::Ds2 => vec![
            answer_step(
                "descriptor_backup_available",
                answers.descriptor_backup_available,
            ),
            answer_step(
                "recovery_materials_available",
                answers.recovery_materials_available,
            ),
            answer_step(
                "wallet_software_documented",
                answers.wallet_software_documented,
            ),
        ],
        DisasterQuestionnaireScenario::Ds3 => vec![
            answer_step(
                "descriptor_backup_available",
                answers.descriptor_backup_available,
            ),
            answer_step(
                "wallet_software_documented",
                answers.wallet_software_documented,
            ),
            answer_step(
                "gap_limit_or_birthdate_documented",
                answers.gap_limit_or_birthdate_documented,
            ),
        ],
        DisasterQuestionnaireScenario::Ds4 => vec![
            answer_step(
                "recovery_materials_available",
                answers.recovery_materials_available,
            ),
            answer_step("passphrase_documented", answers.passphrase_documented),
            answer_step(
                "wallet_software_documented",
                answers.wallet_software_documented,
            ),
            answer_step(
                "gap_limit_or_birthdate_documented",
                answers.gap_limit_or_birthdate_documented,
            ),
        ],
        DisasterQuestionnaireScenario::Ds5 | DisasterQuestionnaireScenario::Ds6 => vec![
            answer_step(
                "descriptor_backup_available",
                answers.descriptor_backup_available,
            ),
            answer_step("signer_locations_known", answers.signer_locations_known),
        ],
    }
}

fn nonempty_multisig_known_address(input: &MultisigSurvivabilityDrillInput) -> Option<&str> {
    input
        .known_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn nonempty_known_address(input: &DisasterQuestionnaireInput) -> Option<&str> {
    input
        .known_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn check_result(checks: &[readiness_score::Check], code: &str) -> Option<CheckResult> {
    checks
        .iter()
        .find(|check| check.code == code)
        .map(|check| check.result)
}

fn available_signers_meet_quorum(available_signers: Option<u8>, parsed: &ParsedDescriptor) -> bool {
    let Some(info) = parsed.multisig_info() else {
        return false;
    };
    let Some(available) = available_signers.map(usize::from) else {
        return false;
    };
    available >= info.threshold() && available <= info.key_count()
}

fn wallet_type_label(parsed: &ParsedDescriptor) -> String {
    if let Some(info) = parsed.multisig_info() {
        return format!("multisig_{}of{}", info.threshold(), info.key_count());
    }
    if parsed.uses_timelock() {
        return "timelock".to_owned();
    }
    if parsed.is_singlesig() {
        return "singlesig".to_owned();
    }
    if parsed.is_taproot() {
        return "taproot".to_owned();
    }
    "unknown".to_owned()
}

fn answer_step(name: &'static str, answer: DisasterAnswer) -> DrillResultStep {
    bool_step(name, answer.is_yes())
}

fn bool_step(name: &'static str, passed: bool) -> DrillResultStep {
    step(
        name,
        if passed {
            DrillStepResult::Pass
        } else {
            DrillStepResult::Fail
        },
    )
}

fn step(name: &'static str, result: DrillStepResult) -> DrillResultStep {
    DrillResultStep {
        step: name.to_owned(),
        result,
    }
}

fn save_drill_result(
    data_dir: &Path,
    payload: DrillResultPayload,
) -> Result<DrillResultSaveOutcome, LifeboatError> {
    validate_drill_payload_schema(&payload)?;
    std::fs::create_dir_all(data_dir).map_err(|err| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not create the drill-history data directory")
            .with_source(err)
    })?;
    let signing_key = load_or_create_drill_signing_key(data_dir)?;
    let record = sign_drill_payload(payload, &signing_key)?;
    validate_drill_result_record(&record)?;

    let drills_dir = data_dir.join(DRILL_RESULTS_DIR_NAME);
    std::fs::create_dir_all(&drills_dir).map_err(|err| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not create the drill-results directory")
            .with_source(err)
    })?;
    let path = drills_dir.join(format!("{}.json", record.payload.drill_id));
    let mut json = serde_json::to_vec_pretty(&record).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the drill result")
            .with_source(err)
    })?;
    json.push(b'\n');
    write_new_file(&path, &json, false)?;

    Ok(DrillResultSaveOutcome {
        path: path.to_string_lossy().into_owned(),
        record,
    })
}

fn practice_drill_payload(
    result: PracticeSendDrillResult,
    completed_at: &str,
) -> Result<DrillResultPayload, LifeboatError> {
    let network = result.network.as_str();
    if network != PracticeDrillNetwork::Regtest.as_str()
        && network != PracticeDrillNetwork::Signet.as_str()
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice drill network is not supported"));
    }
    if Txid::from_str(&result.finalized_txid).is_err() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice drill transaction id is invalid"));
    }

    let drill_id = random_uuid_v4();
    let report_hash = practice_drill_report_hash(&result)?;
    Ok(DrillResultPayload {
        schema_version: DRILL_RESULT_SCHEMA_VERSION.to_owned(),
        drill_id,
        scenario: PRACTICE_PSBT_SCENARIO.to_owned(),
        scenario_title: PRACTICE_PSBT_SCENARIO_TITLE.to_owned(),
        started_at: completed_at.to_owned(),
        completed_at: completed_at.to_owned(),
        result: DrillStepResult::Pass,
        wallet_type: PRACTICE_WALLET_TYPE.to_owned(),
        steps: vec![
            DrillResultStep {
                step: "derive_receive_address".to_owned(),
                result: DrillStepResult::Pass,
            },
            DrillResultStep {
                step: "create_psbt".to_owned(),
                result: DrillStepResult::Pass,
            },
            DrillResultStep {
                step: "sign_psbt".to_owned(),
                result: DrillStepResult::Pass,
            },
            DrillResultStep {
                step: "finalize_psbt".to_owned(),
                result: DrillStepResult::Pass,
            },
        ],
        report_hash,
    })
}

#[derive(Serialize)]
struct FamilyDrillReceiptHashSource<'a> {
    schema_version: &'static str,
    packet_id: Option<&'a str>,
    completed_at: &'a str,
    network: Option<&'a str>,
    result: DrillStepResult,
    completed_steps: &'a [FamilyDrillReceiptStep],
    confidence_checks: &'a [FamilyDrillConfidenceCheck],
    user_stopped: bool,
}

struct FamilyDrillReceiptSummary<'a> {
    packet_id: Option<&'a str>,
    completed_at: &'a str,
    network: Option<&'a str>,
    result: DrillStepResult,
    completed_steps: &'a [FamilyDrillReceiptStep],
    confidence_checks: &'a [FamilyDrillConfidenceCheck],
    user_stopped: bool,
    receipt_hash: &'a str,
}

fn family_drill_receipt_hash(
    source: &FamilyDrillReceiptHashSource<'_>,
) -> Result<String, LifeboatError> {
    let bytes = serde_json::to_vec(source).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the family drill receipt hash source")
            .with_source(err)
    })?;
    Ok(sha256_tag(&bytes))
}

fn family_drill_receipt_lines(summary: &FamilyDrillReceiptSummary<'_>) -> Vec<String> {
    let outcome = match summary.result {
        DrillStepResult::Pass => "pass",
        DrillStepResult::Fail => "fail",
    };
    let packet_id = summary.packet_id.unwrap_or("not recorded");
    let network = summary.network.unwrap_or("not recorded");
    let stopped = if summary.user_stopped { "yes" } else { "no" };

    let mut lines = vec![
        "This is a local receipt for a family drill using fake funds only.".to_owned(),
        "It is not proof that real bitcoin can be recovered.".to_owned(),
        "No network call was made to create this receipt.".to_owned(),
        String::new(),
        "Outcome".to_owned(),
        format!("Result: {outcome}"),
        format!("Completed at: {}", summary.completed_at),
        format!("Packet ID: {packet_id}"),
        format!("Practice network: {network}"),
        format!("Stopped early: {stopped}"),
        format!("Receipt hash: {}", summary.receipt_hash),
        String::new(),
        "Walkthrough steps".to_owned(),
    ];

    for step in FamilyDrillReceiptStep::ALL {
        let mark = if summary.completed_steps.contains(&step) {
            "done"
        } else {
            "not done"
        };
        lines.push(format!("- {mark}: {}", step.label()));
    }

    lines.push(String::new());
    lines.push("Confidence checks".to_owned());
    for check in FamilyDrillConfidenceCheck::ALL {
        let mark = if summary.confidence_checks.contains(&check) {
            "done"
        } else {
            "not done"
        };
        lines.push(format!("- {mark}: {}", check.label()));
    }

    lines.push(String::new());
    lines.push("Safety reminders".to_owned());
    lines.push("- This drill used fake bitcoin only.".to_owned());
    lines.push("- Real seed words, passphrases, and private keys were not needed.".to_owned());
    lines.push("- Bitcoin Lifeboat will never contact the heir or owner.".to_owned());
    lines
}

#[derive(Serialize)]
struct PracticeDrillHashSource<'a> {
    network: &'a str,
    finalized_txid: &'a str,
    amount_sat: u64,
    fee_sat: u64,
    finalized: bool,
    broadcast_available: bool,
}

fn practice_drill_report_hash(result: &PracticeSendDrillResult) -> Result<String, LifeboatError> {
    let source = PracticeDrillHashSource {
        network: &result.network,
        finalized_txid: &result.finalized_txid,
        amount_sat: result.amount_sat,
        fee_sat: result.fee_sat,
        finalized: result.finalized,
        broadcast_available: result.broadcast_available,
    };
    let bytes = serde_json::to_vec(&source).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the practice drill hash source")
            .with_source(err)
    })?;
    Ok(sha256_tag(&bytes))
}

#[derive(Serialize)]
struct DisasterQuestionnaireHashSource<'a> {
    scenario: &'static str,
    result: DrillStepResult,
    wallet_type: &'a str,
    steps: &'a [DrillResultStep],
}

fn disaster_questionnaire_report_hash(
    scenario: DisasterQuestionnaireScenario,
    result: DrillStepResult,
    wallet_type: &str,
    steps: &[DrillResultStep],
) -> Result<String, LifeboatError> {
    let source = DisasterQuestionnaireHashSource {
        scenario: scenario.as_str(),
        result,
        wallet_type,
        steps,
    };
    let bytes = serde_json::to_vec(&source).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the disaster drill hash source")
            .with_source(err)
    })?;
    Ok(sha256_tag(&bytes))
}

#[derive(Serialize)]
struct MultisigSurvivabilityHashSource<'a> {
    template_id: &'static str,
    scenario: &'static str,
    result: DrillStepResult,
    wallet_type: &'a str,
    readiness_status: Option<ReadinessStatus>,
    readiness_score: Option<u32>,
    survivability: Option<&'a Survivability>,
    steps: &'a [DrillResultStep],
}

fn multisig_survivability_report_hash(
    source: MultisigSurvivabilityHashSource<'_>,
) -> Result<String, LifeboatError> {
    let bytes = serde_json::to_vec(&source).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the multisig drill hash source")
            .with_source(err)
    })?;
    Ok(sha256_tag(&bytes))
}

#[derive(Serialize)]
struct MissingSignerHashSource<'a> {
    scenario: &'static str,
    result: DrillStepResult,
    wallet_type: &'a str,
    network: &'static str,
    threshold: u8,
    key_count: u8,
    lost_signer_index: u8,
    remaining_signer_indexes: &'a [u8],
    recovery_possible: bool,
    required_materials: &'a [MissingSignerRequiredMaterial],
    steps: &'a [DrillResultStep],
}

fn missing_signer_report_hash(
    source: &MissingSignerHashSource<'_>,
) -> Result<String, LifeboatError> {
    let bytes = serde_json::to_vec(source).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the missing-signer drill hash source")
            .with_source(err)
    })?;
    Ok(sha256_tag(&bytes))
}

#[derive(Serialize)]
struct DisasterSigningHashSource<'a> {
    scenario: &'static str,
    network: &'static str,
    transport: &'static str,
    result: DrillStepResult,
    wallet_type: &'a str,
    required_signatures: u8,
    finalized_txid: &'a str,
    steps: &'a [DrillResultStep],
}

fn disaster_signing_report_hash(
    source: &DisasterSigningHashSource<'_>,
) -> Result<String, LifeboatError> {
    let bytes = serde_json::to_vec(source).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the disaster signing drill hash source")
            .with_source(err)
    })?;
    Ok(sha256_tag(&bytes))
}

fn destination_output_matches(
    inspection: &PsbtInspection,
    expected_address: &str,
    expected_amount_sat: u64,
) -> bool {
    if expected_address.trim().is_empty() || expected_amount_sat == 0 {
        return false;
    }
    inspection.outputs().iter().any(|output| {
        output.address() == Some(expected_address) && output.amount_sat() == expected_amount_sat
    })
}

fn sign_drill_payload(
    payload: DrillResultPayload,
    signing_key: &SigningKey,
) -> Result<DrillResultRecord, LifeboatError> {
    let payload_bytes = drill_payload_signing_bytes(&payload)?;
    let signature = signing_key.sign(&payload_bytes);
    Ok(DrillResultRecord {
        payload,
        signature: DrillResultSignature {
            algorithm: DRILL_SIGNATURE_ALGORITHM.to_owned(),
            public_key: BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
            payload_sha256: sha256_tag(&payload_bytes),
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        },
    })
}

fn drill_payload_signing_bytes(payload: &DrillResultPayload) -> Result<Vec<u8>, LifeboatError> {
    serde_json::to_vec(payload).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("could not serialize the drill result payload")
            .with_source(err)
    })
}

fn validate_drill_payload_schema(payload: &DrillResultPayload) -> Result<(), LifeboatError> {
    if payload.schema_version != DRILL_RESULT_SCHEMA_VERSION {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record schema version is unsupported"));
    }
    if !is_uuid_v4(&payload.drill_id) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record id is not a UUID v4"));
    }
    if !is_drill_scenario(&payload.scenario) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record scenario is invalid"));
    }
    if payload.scenario_title.trim().is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record scenario title is required"));
    }
    if !is_utc_second_timestamp(&payload.started_at)
        || !is_utc_second_timestamp(&payload.completed_at)
    {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record timestamps must be UTC seconds"));
    }
    if payload.wallet_type.trim().is_empty() || payload.steps.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record wallet type and steps are required"));
    }
    if payload.steps.iter().any(|step| step.step.trim().is_empty()) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record steps are invalid"));
    }
    if !is_sha256_tag(&payload.report_hash) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("drill record report hash is invalid"));
    }
    Ok(())
}

fn load_or_create_drill_signing_key(data_dir: &Path) -> Result<SigningKey, LifeboatError> {
    let path = data_dir.join(DRILL_SIGNING_KEY_FILE_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => signing_key_from_slice(&bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut key_bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut key_bytes);
            match write_new_file(&path, &key_bytes, true) {
                Ok(()) => Ok(SigningKey::from_bytes(&key_bytes)),
                Err(write_err) => {
                    if write_err.code() == ErrorCode::CannotWrite && path.exists() {
                        let bytes = std::fs::read(&path).map_err(|read_err| {
                            LifeboatError::new(ErrorCode::FileNotFound)
                                .with_context("could not read the drill signing key after a race")
                                .with_source(read_err)
                        })?;
                        signing_key_from_slice(&bytes)
                    } else {
                        Err(write_err)
                    }
                }
            }
        }
        Err(err) => Err(LifeboatError::new(ErrorCode::FileNotFound)
            .with_context("could not read the drill signing key")
            .with_source(err)),
    }
}

fn signing_key_from_slice(bytes: &[u8]) -> Result<SigningKey, LifeboatError> {
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        LifeboatError::new(ErrorCode::SchemaMigrationRequired)
            .with_context("drill signing key has the wrong byte length")
    })?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn heir_drill_instructions(network: PracticeDrillNetwork, faucet_url: Option<&str>) -> String {
    let network_note = match network {
        PracticeDrillNetwork::Regtest => {
            "This packet uses regtest, an offline test chain. It cannot spend real bitcoin."
                .to_owned()
        }
        PracticeDrillNetwork::Signet => format!(
            "This packet uses Signet, a public Bitcoin test network. If the app asks for test coins, open this faucet yourself: {}",
            faucet_url.unwrap_or(SIGNET_FAUCET_URL)
        ),
    };

    format!(
        "# Bitcoin Lifeboat Heir Drill\n\n\
This is a practice packet. It uses fake bitcoin only. Do not send real bitcoin to any address in this packet.\n\n\
{network_note}\n\n\
## What Is In This Folder\n\n\
- `{HEIR_DRILL_PACKET_MANIFEST_FILE}` lists the packet files.\n\
- `{HEIR_DRILL_PACKET_WALLET_FILE}` is a fake wallet for this drill.\n\
- `{HEIR_DRILL_PACKET_INSTRUCTIONS_FILE}` is the file you are reading now.\n\n\
## What To Do\n\n\
1. Install Bitcoin Lifeboat on your own computer.\n\
2. Open Heir Drill.\n\
3. Choose Import packet.\n\
4. Pick `{HEIR_DRILL_PACKET_MANIFEST_FILE}` from this folder.\n\
5. Follow the steps in the app.\n\
6. Print the receipt and give it to the owner.\n\n\
## Stop If This Happens\n\n\
Stop if any app, website, chat, phone call, or message asks for real recovery words, a real passphrase, or a private key. Bitcoin Lifeboat will never contact you.\n\n\
This drill proves you can follow the recovery instructions with fake funds. It does not move real bitcoin.\n"
    )
}

fn heir_packet_file(relative_path: &str, mime_type: &str, contents: String) -> HeirDrillPacketFile {
    let sha256 = sha256_tag(contents.as_bytes());
    HeirDrillPacketFile {
        relative_path: relative_path.to_owned(),
        mime_type: mime_type.to_owned(),
        contents,
        sha256,
    }
}

fn heir_packet_file_role(relative_path: &str) -> &'static str {
    match relative_path {
        HEIR_DRILL_PACKET_MANIFEST_FILE => "manifest",
        HEIR_DRILL_PACKET_INSTRUCTIONS_FILE => "instructions",
        HEIR_DRILL_PACKET_WALLET_FILE => "practice_wallet",
        _ => "unknown",
    }
}

fn json_pretty<T: Serialize>(value: &T, context: &'static str) -> Result<String, LifeboatError> {
    let mut json = serde_json::to_string_pretty(value).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context(context)
            .with_source(err)
    })?;
    json.push('\n');
    Ok(json)
}

fn write_new_file(path: &Path, bytes: &[u8], secret_file: bool) -> Result<(), LifeboatError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret_file {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context(format!("could not create `{}`", path.to_string_lossy()))
            .with_source(err)
    })?;
    file.write_all(bytes).map_err(|err| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context(format!("could not write `{}`", path.to_string_lossy()))
            .with_source(err)
    })
}

fn decode_base64_fixed<const N: usize>(
    value: &str,
    decode_context: &'static str,
    len_context: &'static str,
) -> Result<[u8; N], LifeboatError> {
    let decoded = BASE64_STANDARD.decode(value).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(decode_context)
            .with_source(err)
    })?;
    decoded
        .try_into()
        .map_err(|_| LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(len_context))
}

fn random_uuid_v4() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn normalize_optional_packet_id(value: Option<String>) -> Result<Option<String>, LifeboatError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(None);
    }
    if is_uuid_v4(&value) {
        Ok(Some(value))
    } else {
        Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("family drill packet id must be a UUID v4"))
    }
}

fn is_uuid_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| matches!(idx, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
}

fn is_drill_scenario(value: &str) -> bool {
    value.strip_prefix("DS-").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn is_questionnaire_scenario(value: &str) -> bool {
    matches!(value, "DS-1" | "DS-2" | "DS-3" | "DS-4" | "DS-5" | "DS-6")
}

fn is_signing_scenario(value: &str) -> bool {
    matches!(value, "DS-7" | "DS-8" | "DS-9" | "DS-10")
}

fn questionnaire_scenario_title(value: &str) -> Option<&'static str> {
    match value {
        "DS-1" => Some("I lost my hardware wallet"),
        "DS-2" => Some("My laptop died"),
        "DS-3" => Some("My wallet app disappeared"),
        "DS-4" => Some("I have my seed but not my wallet file"),
        "DS-5" => Some("I have my descriptor but not all signers"),
        "DS-6" => Some("One multisig signer is unavailable"),
        _ => None,
    }
}

fn signing_scenario_title(value: &str) -> Option<&'static str> {
    match value {
        "DS-7" => Some("My spouse needs to recover"),
        "DS-8" => Some("I need to verify my hardware wallet can still sign"),
        "DS-9" => Some("I want to test a PSBT signing workflow"),
        "DS-10" => Some("I want to simulate restoring on a clean machine"),
        _ => None,
    }
}

fn multisig_template_by_id(value: &str) -> Option<MultisigDrillTemplate> {
    match value {
        "multisig-2of3" => Some(MultisigDrillTemplate::Multisig2of3),
        "multisig-3of5" => Some(MultisigDrillTemplate::Multisig3of5),
        _ => None,
    }
}

fn is_disaster_questionnaire_step(value: &str) -> bool {
    matches!(
        value,
        "descriptor_parse"
            | "derive_expected_addresses"
            | "known_address_match"
            | "multisig_quorum"
            | "available_signers_meet_quorum"
            | "survives_one_signer_loss"
            | "descriptor_backup_available"
            | "recovery_materials_available"
            | "wallet_software_documented"
            | "passphrase_documented"
            | "gap_limit_or_birthdate_documented"
            | "signer_locations_known"
            | "user_did_not_stop"
    )
}

fn is_multisig_survivability_step(value: &str) -> bool {
    matches!(
        value,
        "descriptor_parse"
            | "template_matches_descriptor"
            | "readiness_status_available"
            | "lose_1_signer_survives"
            | "lose_2_signers_survives"
            | "lose_descriptor_backup_survives"
            | "user_did_not_stop"
    )
}

fn is_missing_signer_step(value: &str) -> bool {
    matches!(
        value,
        "descriptor_parse"
            | "multisig_quorum"
            | "lost_signer_in_range"
            | "remaining_quorum_available"
            | "practice_chain_selected"
            | "user_did_not_stop"
    )
}

fn is_missing_signer_material(material: &MissingSignerRequiredMaterial, key_count: u8) -> bool {
    match material.kind {
        MissingSignerMaterialKind::DescriptorBackup
        | MissingSignerMaterialKind::CoordinatorWallet
        | MissingSignerMaterialKind::PracticeFunds => material.signer_index.is_none(),
        MissingSignerMaterialKind::RemainingSigner => material
            .signer_index
            .is_some_and(|index| index >= 1 && index <= key_count),
    }
}

fn is_disaster_signing_step(value: &str) -> bool {
    matches!(
        value,
        "psbt_created"
            | "required_quorum_signed"
            | "psbt_finalized"
            | "valid_transaction"
            | "destination_confirmed_on_device"
            | "destination_output_matches"
            | "user_did_not_stop"
    )
}

fn is_public_wallet_type_label(value: &str) -> bool {
    matches!(
        value,
        "unknown" | "singlesig" | "taproot" | "timelock" | "practice_singlesig"
    ) || multisig_wallet_type_parts(value).is_some()
}

fn multisig_wallet_type_parts(value: &str) -> Option<(usize, usize)> {
    let rest = value.strip_prefix("multisig_")?;
    let (threshold, key_count) = rest.split_once("of")?;
    let threshold = threshold.parse::<usize>().ok()?;
    let key_count = key_count.parse::<usize>().ok()?;
    if (1..=key_count).contains(&threshold) && key_count <= 15 {
        Some((threshold, key_count))
    } else {
        None
    }
}

fn is_utc_second_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| matches!(idx, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit())
}

fn is_sha256_tag(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn sha256_tag(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex_encode(&digest))
}

#[cfg(target_os = "linux")]
fn platform_data_home() -> Result<PathBuf, LifeboatError> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(xdg));
    }
    home_dir().map(|home| home.join(".local").join("share"))
}

#[cfg(target_os = "macos")]
fn platform_data_home() -> Result<PathBuf, LifeboatError> {
    home_dir().map(|home| home.join("Library").join("Application Support"))
}

#[cfg(target_os = "windows")]
fn platform_data_home() -> Result<PathBuf, LifeboatError> {
    if let Some(appdata) = std::env::var_os("APPDATA").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(appdata));
    }
    home_dir().map(|home| home.join("AppData").join("Roaming"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_data_home() -> Result<PathBuf, LifeboatError> {
    home_dir().map(|home| home.join(".local").join("share"))
}

fn home_dir() -> Result<PathBuf, LifeboatError> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("could not resolve the user data directory")
        })
}

fn signing_options(try_finalize: bool) -> SignOptions {
    SignOptions {
        trust_witness_utxo: true,
        try_finalize,
        ..SignOptions::default()
    }
}

fn parse_transaction_hex(value: &str) -> Result<Transaction, LifeboatError> {
    if value.is_empty() {
        return Err(
            LifeboatError::new(ErrorCode::InputEmpty).with_context("transaction hex is empty")
        );
    }
    let bytes = hex_decode(value)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let transaction = Transaction::consensus_decode(&mut cursor).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("transaction hex could not be decoded")
            .with_source(err)
    })?;
    if cursor.position() != bytes.len() as u64 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("transaction hex has trailing bytes"));
    }
    Ok(transaction)
}

fn hex_decode(value: &str) -> Result<Vec<u8>, LifeboatError> {
    if value.len() % 2 != 0 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("transaction hex must have an even number of characters"));
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("transaction hex contains a non-hex character")
        })?;
        let low = hex_value(pair[1]).ok_or_else(|| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("transaction hex contains a non-hex character")
        })?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "unknown",
    }
}

fn script_hex(script: &ScriptBuf) -> String {
    hex_encode(script.as_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::path::PathBuf;

    use signet_lab::bitcoin::blockdata::transaction;
    use signet_lab::bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use signet_lab::bitcoin::taproot::{LeafVersion, TaprootBuilder};
    use signet_lab::{PracticeNetwork, DEFAULT_PRACTICE_SEED};

    const TEST_SEED: &[u8; 32] = &DEFAULT_PRACTICE_SEED;
    const BIP370_UPDATED_V2: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/psbt/bip370_updated_v2.txt"
    ));

    macro_rules! fixture {
        ($path:expr) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/",
                $path
            ))
            .trim()
        };
    }

    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new(name: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("lifeboat-us075-{}-{n}-{name}", std::process::id()));
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
    fn start_receive_send_drill_returns_network_address_and_faucet_instruction() {
        let regtest =
            start_receive_send_drill(PracticeDrillNetwork::Regtest).expect("regtest drill start");
        assert_eq!(regtest.network, "regtest");
        assert!(regtest.receive_address.starts_with("bcrt1"));
        assert!(regtest.faucet_url.is_none());
        assert_eq!(regtest.receive_index, 0);

        let signet =
            start_receive_send_drill(PracticeDrillNetwork::Signet).expect("signet drill start");
        assert_eq!(signet.network, "signet");
        assert!(signet.receive_address.starts_with("tb1"));
        assert_eq!(signet.faucet_url.as_deref(), Some(SIGNET_FAUCET_URL));
    }

    fn heir_packet_file<'a>(
        packet: &'a HeirDrillPacket,
        relative_path: &str,
    ) -> &'a HeirDrillPacketFile {
        packet
            .files
            .iter()
            .find(|file| file.relative_path == relative_path)
            .expect("packet file exists")
    }

    #[test]
    fn heir_drill_packet_generates_regtest_wallet_and_instructions() {
        let packet = generate_heir_drill_packet(
            HeirDrillPacketInput {
                network: PracticeDrillNetwork::Regtest,
            },
            "2026-05-30T22:00:00Z",
        )
        .expect("heir packet");

        assert_eq!(packet.files.len(), 3);
        assert_eq!(
            packet.manifest.schema_version,
            HEIR_DRILL_PACKET_SCHEMA_VERSION
        );
        assert!(is_uuid_v4(&packet.manifest.packet_id));
        assert_eq!(packet.manifest.packet_type, "heir_drill_packet");
        assert_eq!(packet.manifest.network, "regtest");
        assert_eq!(packet.manifest.wallet_kind, HEIR_DRILL_WALLET_KIND);
        assert!(!packet.manifest.contains_real_funds);
        assert!(!packet.manifest.contains_real_user_material);
        assert!(packet.manifest.includes_disposable_private_material);
        assert!(packet.manifest.first_receive_address.starts_with("bcrt1"));
        assert_eq!(packet.manifest.files.len(), 2);

        let instructions = heir_packet_file(&packet, HEIR_DRILL_PACKET_INSTRUCTIONS_FILE);
        assert_eq!(instructions.mime_type, "text/markdown");
        assert_eq!(
            instructions.sha256,
            sha256_tag(instructions.contents.as_bytes())
        );
        assert!(instructions.contents.contains("fake bitcoin only"));
        assert!(instructions.contents.contains("Stop if any app"));
        assert!(!instructions.contents.contains("xpub"));
        assert!(!instructions.contents.contains("PSBT"));

        let wallet_file = heir_packet_file(&packet, HEIR_DRILL_PACKET_WALLET_FILE);
        let wallet: HeirDrillWalletFile =
            serde_json::from_str(&wallet_file.contents).expect("wallet json");
        assert_eq!(wallet.wallet_kind, HEIR_DRILL_WALLET_KIND);
        assert_eq!(wallet.network, "regtest");
        assert!(wallet.first_receive_address.starts_with("bcrt1"));
        assert!(wallet.first_change_address.starts_with("bcrt1"));
        assert!(wallet.external_descriptor.contains("tprv"));
        assert!(wallet.internal_descriptor.contains("tprv"));
        assert!(!wallet.contains_real_funds);
        assert!(!wallet.contains_real_user_material);
    }

    #[test]
    fn heir_drill_packet_contains_only_test_network_material() {
        let packet = generate_heir_drill_packet(
            HeirDrillPacketInput {
                network: PracticeDrillNetwork::Signet,
            },
            "2026-05-30T22:05:00Z",
        )
        .expect("signet heir packet");
        let wallet_file = heir_packet_file(&packet, HEIR_DRILL_PACKET_WALLET_FILE);
        let wallet: HeirDrillWalletFile =
            serde_json::from_str(&wallet_file.contents).expect("wallet json");

        assert_eq!(packet.manifest.network, "signet");
        assert_eq!(
            packet.manifest.faucet_url.as_deref(),
            Some(SIGNET_FAUCET_URL)
        );
        assert_eq!(wallet.faucet_url.as_deref(), Some(SIGNET_FAUCET_URL));
        assert!(wallet.first_receive_address.starts_with("tb1"));
        assert!(wallet.first_change_address.starts_with("tb1"));
        assert!(!wallet.first_receive_address.starts_with("bc1"));
        assert!(!wallet.first_receive_address.starts_with('1'));
        assert!(!wallet.first_receive_address.starts_with('3'));

        let all_files = packet
            .files
            .iter()
            .map(|file| file.contents.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!all_files.contains("xprv"));
        assert!(!all_files.contains("yprv"));
        assert!(!all_files.contains("zprv"));
        assert!(!all_files.contains("real seed phrase:"));
        assert!(!all_files.contains("real recovery words:"));
        assert!(!all_files.contains("real passphrase:"));
        assert!(all_files.contains("Disposable test wallet"));
    }

    #[test]
    fn write_heir_drill_packet_exports_files_under_a_new_directory() {
        let dir = ScratchDir::new("heir-packet");
        let export = write_heir_drill_packet(
            &dir.path,
            HeirDrillPacketInput {
                network: PracticeDrillNetwork::Regtest,
            },
            "2026-05-30T22:10:00Z",
        )
        .expect("heir packet written");

        let packet_dir = PathBuf::from(&export.packet_dir);
        assert!(packet_dir.starts_with(&dir.path));
        assert!(packet_dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(HEIR_DRILL_PACKET_DIR_PREFIX)));
        assert_eq!(export.files.len(), 3);

        for file in &export.files {
            let path = PathBuf::from(&file.path);
            assert!(path.exists());
            let bytes = std::fs::read(&path).expect("written file");
            assert_eq!(file.sha256, sha256_tag(&bytes));
        }

        let manifest_path = packet_dir.join(HEIR_DRILL_PACKET_MANIFEST_FILE);
        let manifest: HeirDrillPacketManifest =
            serde_json::from_slice(&std::fs::read(manifest_path).expect("manifest file"))
                .expect("manifest json");
        assert_eq!(manifest.packet_id, export.manifest.packet_id);
        assert_eq!(manifest.wallet_file, HEIR_DRILL_PACKET_WALLET_FILE);
        assert_eq!(
            manifest.instructions_file,
            HEIR_DRILL_PACKET_INSTRUCTIONS_FILE
        );
        assert!(packet_dir.join(HEIR_DRILL_PACKET_WALLET_FILE).exists());
    }

    fn all_family_receipt_steps() -> Vec<FamilyDrillReceiptStep> {
        FamilyDrillReceiptStep::ALL.to_vec()
    }

    fn all_family_confidence_checks() -> Vec<FamilyDrillConfidenceCheck> {
        FamilyDrillConfidenceCheck::ALL.to_vec()
    }

    #[test]
    fn family_drill_receipt_generates_public_safe_pdf_offline() {
        let packet = generate_heir_drill_packet(
            HeirDrillPacketInput {
                network: PracticeDrillNetwork::Regtest,
            },
            "2026-05-30T22:30:00Z",
        )
        .expect("heir packet");
        let wallet_file = heir_packet_file(&packet, HEIR_DRILL_PACKET_WALLET_FILE);
        let wallet: HeirDrillWalletFile =
            serde_json::from_str(&wallet_file.contents).expect("wallet json");

        let input = FamilyDrillReceiptInput {
            packet_id: Some(packet.manifest.packet_id.clone()),
            network: Some(PracticeDrillNetwork::Regtest),
            completed_steps: all_family_receipt_steps(),
            confidence_checks: all_family_confidence_checks(),
            user_stopped: false,
        };

        let receipt =
            generate_family_drill_receipt(input.clone(), "2026-05-31T00:50:00Z", "0.1.0-test")
                .expect("receipt");
        let again = generate_family_drill_receipt(input, "2026-05-31T00:50:00Z", "0.1.0-test")
            .expect("receipt rerender");

        assert_eq!(receipt.schema_version, FAMILY_DRILL_RECEIPT_SCHEMA_VERSION);
        assert_eq!(receipt.format, "pdf");
        assert_eq!(receipt.redaction, "public-safe");
        assert_eq!(receipt.mime_type, "application/pdf");
        assert_eq!(receipt.suggested_filename, FAMILY_DRILL_RECEIPT_FILENAME);
        assert!(is_sha256_tag(&receipt.receipt_hash));
        assert!(receipt.content.starts_with(b"%PDF"));
        assert!(receipt.content.ends_with(b"%%EOF\n") || receipt.content.ends_with(b"%%EOF"));
        assert_eq!(receipt.receipt_hash, again.receipt_hash);
        assert_eq!(receipt.content, again.content);

        let pdf_text = String::from_utf8_lossy(&receipt.content);
        for confidential in [
            wallet.external_descriptor.as_str(),
            wallet.internal_descriptor.as_str(),
            "tprv",
            "xprv",
            "seed phrase:",
            "private key:",
            "passphrase:",
            "transaction_hex",
            "signed_psbt",
        ] {
            assert!(
                !pdf_text.contains(confidential),
                "receipt leaked confidential marker `{confidential}`"
            );
        }
    }

    #[test]
    fn family_drill_receipt_records_fail_when_incomplete() {
        let receipt = generate_family_drill_receipt(
            FamilyDrillReceiptInput {
                packet_id: None,
                network: None,
                completed_steps: vec![FamilyDrillReceiptStep::Start],
                confidence_checks: Vec::new(),
                user_stopped: false,
            },
            "2026-05-31T00:55:00Z",
            "0.1.0-test",
        )
        .expect("receipt");

        assert!(is_sha256_tag(&receipt.receipt_hash));

        let pass = generate_family_drill_receipt(
            FamilyDrillReceiptInput {
                packet_id: None,
                network: None,
                completed_steps: all_family_receipt_steps(),
                confidence_checks: all_family_confidence_checks(),
                user_stopped: false,
            },
            "2026-05-31T00:55:00Z",
            "0.1.0-test",
        )
        .expect("pass receipt");

        assert_ne!(receipt.receipt_hash, pass.receipt_hash);
    }

    #[test]
    fn family_drill_receipt_rejects_arbitrary_packet_id_text() {
        let err = generate_family_drill_receipt(
            FamilyDrillReceiptInput {
                packet_id: Some("tprv-not-a-packet-id".to_owned()),
                network: Some(PracticeDrillNetwork::Regtest),
                completed_steps: all_family_receipt_steps(),
                confidence_checks: all_family_confidence_checks(),
                user_stopped: false,
            },
            "2026-05-31T01:00:00Z",
            "0.1.0-test",
        )
        .expect_err("invalid packet id rejected");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn run_receive_send_drill_finalizes_regtest_transaction_without_network() {
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Regtest,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("regtest drill result");

        assert_eq!(result.network, "regtest");
        assert!(result.receive_address.starts_with("bcrt1"));
        assert!(result.recipient_address.starts_with("bcrt1"));
        assert_ne!(result.receive_address, result.recipient_address);
        assert!(!result.unsigned_psbt_base64.is_empty());
        assert!(!result.signed_psbt_base64.is_empty());
        assert!(!result.transaction_hex.is_empty());
        assert_eq!(result.input_total_sat, 125_000);
        assert!(result.output_total_sat < result.input_total_sat);
        assert!(result.fee_sat > 0);
        assert!(result.finalized);
        assert!(!result.broadcast_available);
    }

    #[test]
    fn run_receive_send_drill_uses_signet_addresses_and_allows_separate_broadcast() {
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Signet,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("signet drill result");

        assert_eq!(result.network, "signet");
        assert!(result.receive_address.starts_with("tb1"));
        assert!(result.recipient_address.starts_with("tb1"));
        assert!(result.finalized);
        assert!(result.broadcast_available);
    }

    #[test]
    fn drill_result_is_written_only_by_explicit_save_and_validates_schema_signature() {
        let dir = ScratchDir::new("save");
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Regtest,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("regtest drill result");

        assert!(!dir.path.join(DRILL_RESULTS_DIR_NAME).exists());

        let saved = save_practice_drill_result(&dir.path, result, "2026-05-30T20:00:00Z")
            .expect("record saved");
        let path = PathBuf::from(&saved.path);
        let expected_filename = format!("{}.json", saved.record.payload.drill_id);
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(expected_filename.as_str())
        );
        assert!(path.exists());
        assert!(dir.path.join(DRILL_SIGNING_KEY_FILE_NAME).exists());
        validate_drill_result_record(&saved.record).expect("schema and signature validate");

        let bytes = std::fs::read(path).expect("record file exists");
        let parsed: DrillResultRecord = serde_json::from_slice(&bytes).expect("valid record json");
        validate_drill_result_record(&parsed).expect("written record validates");

        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json value");
        assert_eq!(value["schema_version"], DRILL_RESULT_SCHEMA_VERSION);
        assert_eq!(value["scenario"], PRACTICE_PSBT_SCENARIO);
        assert_eq!(value["scenario_title"], PRACTICE_PSBT_SCENARIO_TITLE);
        assert_eq!(value["result"], "pass");
        assert_eq!(value["wallet_type"], PRACTICE_WALLET_TYPE);
        assert_eq!(value["signature"]["algorithm"], DRILL_SIGNATURE_ALGORITHM);
        assert!(value["signature"]["public_key"].is_string());
        assert!(value["signature"]["signature"].is_string());
    }

    #[test]
    fn drill_result_reuses_the_per_install_signing_key() {
        let dir = ScratchDir::new("key-reuse");
        let first = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Regtest,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("first drill");
        let second = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Signet,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("second drill");

        let first = save_practice_drill_result(&dir.path, first, "2026-05-30T20:00:00Z")
            .expect("first save");
        let second = save_practice_drill_result(&dir.path, second, "2026-05-30T20:01:00Z")
            .expect("second save");

        assert_ne!(
            first.record.payload.drill_id,
            second.record.payload.drill_id
        );
        assert_ne!(first.path, second.path);
        assert_eq!(
            first.record.signature.public_key,
            second.record.signature.public_key
        );
        validate_drill_result_record(&first.record).expect("first validates");
        validate_drill_result_record(&second.record).expect("second validates");
    }

    #[test]
    fn drill_result_signature_detects_tampering() {
        let dir = ScratchDir::new("tamper");
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Regtest,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("drill");
        let saved = save_practice_drill_result(&dir.path, result, "2026-05-30T20:00:00Z")
            .expect("record saved");
        let mut tampered = saved.record;
        tampered.payload.wallet_type = "changed_wallet".to_owned();

        let err = validate_drill_result_record(&tampered).expect_err("tamper rejected");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    fn passing_multisig_questionnaire(
        scenario: DisasterQuestionnaireScenario,
    ) -> DisasterQuestionnaireInput {
        DisasterQuestionnaireInput {
            scenario,
            descriptor: fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt").to_owned(),
            network: DisasterQuestionnaireNetwork::Testnet,
            known_address: Some(fixture!("addresses/known_match_tb1.txt").to_owned()),
            available_signers: Some(2),
            user_stopped: false,
            answers: DisasterQuestionnaireAnswers {
                descriptor_backup_available: DisasterAnswer::Yes,
                signer_locations_known: DisasterAnswer::Yes,
                ..DisasterQuestionnaireAnswers::default()
            },
        }
    }

    fn multisig_survivability_input(
        template: MultisigDrillTemplate,
    ) -> MultisigSurvivabilityDrillInput {
        let descriptor = match template {
            MultisigDrillTemplate::Multisig2of3 => {
                fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt")
            }
            MultisigDrillTemplate::Multisig3of5 => {
                fixture!("descriptors/multisig/wsh_sortedmulti_3of5.txt")
            }
        };
        MultisigSurvivabilityDrillInput {
            template,
            descriptor: descriptor.to_owned(),
            network: DisasterQuestionnaireNetwork::Testnet,
            known_address: None,
            user_stopped: false,
        }
    }

    #[test]
    fn disaster_questionnaire_ds5_passes_with_descriptor_and_quorum() {
        let result = run_disaster_questionnaire_drill(
            passing_multisig_questionnaire(DisasterQuestionnaireScenario::Ds5),
            "2026-05-30T20:10:00Z",
        )
        .expect("questionnaire runs");

        assert_eq!(result.scenario, "DS-5");
        assert_eq!(
            result.scenario_title,
            "I have my descriptor but not all signers"
        );
        assert_eq!(result.result, DrillStepResult::Pass);
        assert_eq!(result.wallet_type, "multisig_2of3");
        assert!(result.steps.iter().any(|step| {
            step.step == "available_signers_meet_quorum" && step.result == DrillStepResult::Pass
        }));
        assert!(is_sha256_tag(&result.report_hash));
    }

    #[test]
    fn disaster_questionnaire_ds5_fails_when_available_signers_are_below_threshold() {
        let mut input = passing_multisig_questionnaire(DisasterQuestionnaireScenario::Ds5);
        input.available_signers = Some(1);

        let result =
            run_disaster_questionnaire_drill(input, "2026-05-30T20:10:00Z").expect("result");

        assert_eq!(result.result, DrillStepResult::Fail);
        assert!(result.steps.iter().any(|step| {
            step.step == "available_signers_meet_quorum" && step.result == DrillStepResult::Fail
        }));
    }

    #[test]
    fn disaster_questionnaire_ds6_uses_analytic_one_signer_survivability() {
        let result = run_disaster_questionnaire_drill(
            passing_multisig_questionnaire(DisasterQuestionnaireScenario::Ds6),
            "2026-05-30T20:10:00Z",
        )
        .expect("questionnaire runs");

        assert_eq!(result.scenario, "DS-6");
        assert_eq!(result.result, DrillStepResult::Pass);
        assert!(result.steps.iter().any(|step| {
            step.step == "survives_one_signer_loss" && step.result == DrillStepResult::Pass
        }));
    }

    #[test]
    fn disaster_questionnaire_save_writes_signed_public_summary_only() {
        let dir = ScratchDir::new("disaster-save");
        let input = passing_multisig_questionnaire(DisasterQuestionnaireScenario::Ds5);
        let result = run_disaster_questionnaire_drill(input, "2026-05-30T20:10:00Z")
            .expect("questionnaire runs");

        assert!(!dir.path.join(DRILL_RESULTS_DIR_NAME).exists());

        let saved =
            save_disaster_questionnaire_drill_result(&dir.path, result, "2026-05-30T20:12:00Z")
                .expect("record saved");

        assert_eq!(saved.record.payload.scenario, "DS-5");
        assert_eq!(saved.record.payload.result, DrillStepResult::Pass);
        validate_drill_result_record(&saved.record).expect("schema and signature validate");

        let bytes = std::fs::read(&saved.path).expect("record file exists");
        let json = String::from_utf8(bytes).expect("utf8 json");
        assert!(!json.contains("tpub"));
        assert!(!json.contains("tb1q"));
    }

    #[test]
    fn disaster_questionnaire_save_rejects_noncanonical_public_summary_fields() {
        let dir = ScratchDir::new("disaster-tamper");
        let input = passing_multisig_questionnaire(DisasterQuestionnaireScenario::Ds5);
        let mut result = run_disaster_questionnaire_drill(input, "2026-05-30T20:10:00Z")
            .expect("questionnaire runs");
        result.scenario_title = "descriptor wsh(sortedmulti(...))".to_owned();

        let err =
            save_disaster_questionnaire_drill_result(&dir.path, result, "2026-05-30T20:12:00Z")
                .expect_err("tampered title rejected");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn multisig_survivability_2of3_reports_expected_loss_outcomes() {
        let result = run_multisig_survivability_drill(
            multisig_survivability_input(MultisigDrillTemplate::Multisig2of3),
            "2026-05-30T20:20:00Z",
        )
        .expect("multisig simulation runs");

        assert_eq!(result.template_id, "multisig-2of3");
        assert_eq!(result.scenario, MULTISIG_2OF3_SCENARIO);
        assert_eq!(result.wallet_type, "multisig_2of3");
        assert_eq!(result.result, DrillStepResult::Fail);
        assert!(result.readiness_status.is_some());
        assert!(is_sha256_tag(&result.report_hash));
        let survivability = result.survivability.expect("2-of-3 survivability");
        assert_eq!(survivability.lose_1_signer, "ok");
        assert_eq!(survivability.lose_2_signers, "fail_expected_for_2of3");
        assert_eq!(survivability.lose_descriptor_only, "ok_if_xpubs_retained");
        assert!(result.steps.iter().any(|step| {
            step.step == "lose_1_signer_survives" && step.result == DrillStepResult::Pass
        }));
        assert!(result.steps.iter().any(|step| {
            step.step == "lose_2_signers_survives" && step.result == DrillStepResult::Fail
        }));
    }

    #[test]
    fn multisig_survivability_3of5_survives_both_signer_loss_templates() {
        let result = run_multisig_survivability_drill(
            multisig_survivability_input(MultisigDrillTemplate::Multisig3of5),
            "2026-05-30T20:21:00Z",
        )
        .expect("multisig simulation runs");

        assert_eq!(result.template_id, "multisig-3of5");
        assert_eq!(result.scenario, MULTISIG_3OF5_SCENARIO);
        assert_eq!(result.wallet_type, "multisig_3of5");
        assert_eq!(result.result, DrillStepResult::Pass);
        assert!(result.readiness_status.is_some());
        let survivability = result.survivability.expect("3-of-5 survivability");
        assert_eq!(survivability.lose_1_signer, "ok");
        assert_eq!(survivability.lose_2_signers, "ok");
        assert_eq!(survivability.lose_descriptor_only, "ok_if_xpubs_retained");
        assert!(result
            .steps
            .iter()
            .all(|step| step.result == DrillStepResult::Pass));
    }

    #[test]
    fn multisig_survivability_save_writes_signed_public_summary_only() {
        let dir = ScratchDir::new("multisig-survivability-save");
        let result = run_multisig_survivability_drill(
            multisig_survivability_input(MultisigDrillTemplate::Multisig3of5),
            "2026-05-30T20:22:00Z",
        )
        .expect("multisig simulation runs");

        let saved =
            save_multisig_survivability_drill_result(&dir.path, result, "2026-05-30T20:23:00Z")
                .expect("record saved");

        assert_eq!(saved.record.payload.scenario, MULTISIG_3OF5_SCENARIO);
        assert_eq!(saved.record.payload.result, DrillStepResult::Pass);
        assert_eq!(saved.record.payload.wallet_type, "multisig_3of5");
        validate_drill_result_record(&saved.record).expect("schema and signature validate");

        let bytes = std::fs::read(&saved.path).expect("record file exists");
        let json = String::from_utf8(bytes).expect("utf8 json");
        assert!(!json.contains("tpub"));
        assert!(!json.contains("tb1q"));
    }

    #[test]
    fn multisig_survivability_template_mismatch_is_a_failed_public_result() {
        let mut input = multisig_survivability_input(MultisigDrillTemplate::Multisig3of5);
        input.descriptor = fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt").to_owned();

        let result =
            run_multisig_survivability_drill(input, "2026-05-30T20:24:00Z").expect("result");

        assert_eq!(result.result, DrillStepResult::Fail);
        assert_eq!(result.wallet_type, "multisig_2of3");
        assert!(result.survivability.is_none());
        assert!(result.steps.iter().any(|step| {
            step.step == "template_matches_descriptor" && step.result == DrillStepResult::Fail
        }));
    }

    fn missing_signer_input(lost_signer_index: u8) -> MissingSignerDrillInput {
        MissingSignerDrillInput {
            descriptor: fixture!("descriptors/multisig/wsh_sortedmulti_2of3.txt").to_owned(),
            network: PracticeDrillNetwork::Regtest,
            lost_signer_index,
            user_stopped: false,
        }
    }

    #[test]
    fn missing_signer_2_of_3_reports_remaining_quorum_and_materials() {
        let result = run_missing_signer_drill(missing_signer_input(2), "2026-05-30T20:30:00Z")
            .expect("missing signer drill runs");

        assert_eq!(result.scenario, MISSING_SIGNER_SCENARIO);
        assert_eq!(result.scenario_title, MISSING_SIGNER_SCENARIO_TITLE);
        assert_eq!(result.result, DrillStepResult::Pass);
        assert_eq!(result.wallet_type, "multisig_2of3");
        assert_eq!(result.network, "regtest");
        assert_eq!(result.threshold, 2);
        assert_eq!(result.key_count, 3);
        assert_eq!(result.lost_signer_index, 2);
        assert_eq!(result.remaining_signer_indexes, vec![1, 3]);
        assert_eq!(result.signatures_required, 2);
        assert!(result.recovery_possible);
        assert!(result.required_materials.iter().any(|material| {
            material.kind == MissingSignerMaterialKind::RemainingSigner
                && material.signer_index == Some(1)
        }));
        assert!(result.required_materials.iter().any(|material| {
            material.kind == MissingSignerMaterialKind::RemainingSigner
                && material.signer_index == Some(3)
        }));
        assert!(result.steps.iter().any(|step| {
            step.step == "remaining_quorum_available" && step.result == DrillStepResult::Pass
        }));
        assert!(is_sha256_tag(&result.report_hash));
    }

    #[test]
    fn missing_signer_fails_when_selected_signer_is_out_of_range() {
        let result = run_missing_signer_drill(missing_signer_input(4), "2026-05-30T20:31:00Z")
            .expect("missing signer drill returns a failed result");

        assert_eq!(result.result, DrillStepResult::Fail);
        assert_eq!(result.threshold, 0);
        assert_eq!(result.key_count, 0);
        assert!(!result.recovery_possible);
        assert!(result.remaining_signer_indexes.is_empty());
        assert!(result.steps.iter().any(|step| {
            step.step == "lost_signer_in_range" && step.result == DrillStepResult::Fail
        }));
    }

    #[test]
    fn missing_signer_save_writes_signed_public_summary_only() {
        let dir = ScratchDir::new("missing-signer-save");
        let result = run_missing_signer_drill(
            MissingSignerDrillInput {
                network: PracticeDrillNetwork::Signet,
                ..missing_signer_input(2)
            },
            "2026-05-30T20:32:00Z",
        )
        .expect("missing signer drill runs");

        let saved = save_missing_signer_drill_result(&dir.path, result, "2026-05-30T20:33:00Z")
            .expect("record saved");

        assert_eq!(saved.record.payload.scenario, MISSING_SIGNER_SCENARIO);
        assert_eq!(saved.record.payload.result, DrillStepResult::Pass);
        assert_eq!(saved.record.payload.wallet_type, "multisig_2of3");
        validate_drill_result_record(&saved.record).expect("schema and signature validate");

        let bytes = std::fs::read(&saved.path).expect("record file exists");
        let json = String::from_utf8(bytes).expect("utf8 json");
        assert!(!json.contains("tpub"));
        assert!(!json.contains("tb1q"));
    }

    fn signed_psbt_for_disaster_start(start: &DisasterSigningStartResult) -> String {
        let (practice_network, bitcoin_network) = match start.network.as_str() {
            "signet" => (PracticeNetwork::Signet, Network::Signet),
            _ => (PracticeNetwork::Regtest, Network::Regtest),
        };
        let wallet = DisposableWallet::from_default_practice_seed(practice_network)
            .expect("practice signer wallet");
        let imported = import_psbt_base64(&start.unsigned_psbt_base64, bitcoin_network)
            .expect("unsigned PSBT imports");
        let signed = sign_psbt(&wallet, imported.into_psbt()).expect("signed disaster PSBT");
        signed.to_base64().expect("signed PSBT base64")
    }

    #[test]
    fn disaster_signing_ds9_file_flow_passes_after_signed_psbt_and_destination_confirmation() {
        let start = start_disaster_signing_drill(
            DisasterSigningStartInput {
                scenario: DisasterSigningScenario::Ds9,
                network: PracticeDrillNetwork::Regtest,
                transport: DisasterSigningTransport::File,
            },
            "2026-05-30T21:00:00Z",
        )
        .expect("signing drill starts");

        assert_eq!(start.scenario, "DS-9");
        assert_eq!(
            start.scenario_title,
            "I want to test a PSBT signing workflow"
        );
        assert_eq!(start.network, "regtest");
        assert_eq!(start.transport, "file");
        assert_eq!(start.required_signatures, 1);
        assert!(start.receive_address.starts_with("bcrt1"));
        assert!(start.destination_address.starts_with("bcrt1"));
        assert!(!start.unsigned_psbt_base64.is_empty());

        let signed_psbt_base64 = signed_psbt_for_disaster_start(&start);
        let result = complete_disaster_signing_drill(DisasterSigningCompleteInput {
            scenario: DisasterSigningScenario::Ds9,
            network: PracticeDrillNetwork::Regtest,
            transport: DisasterSigningTransport::File,
            started_at: start.started_at.clone(),
            signed_psbt_base64,
            expected_destination_address: start.destination_address,
            expected_amount_sat: start.amount_sat,
            destination_confirmed: true,
            user_stopped: false,
        })
        .expect("signing drill completes");

        assert_eq!(result.result, DrillStepResult::Pass);
        assert_eq!(result.wallet_type, PRACTICE_WALLET_TYPE);
        assert_eq!(result.transport, "file");
        assert!(Txid::from_str(&result.finalized_txid).is_ok());
        assert!(result
            .steps
            .iter()
            .all(|step| step.result == DrillStepResult::Pass));
        assert!(result.steps.iter().any(|step| {
            step.step == "destination_confirmed_on_device" && step.result == DrillStepResult::Pass
        }));
        assert!(is_sha256_tag(&result.report_hash));
    }

    #[test]
    fn disaster_signing_fails_when_destination_was_not_confirmed_on_device() {
        let start = start_disaster_signing_drill(
            DisasterSigningStartInput {
                scenario: DisasterSigningScenario::Ds8,
                network: PracticeDrillNetwork::Regtest,
                transport: DisasterSigningTransport::Qr,
            },
            "2026-05-30T21:05:00Z",
        )
        .expect("signing drill starts");
        let signed_psbt_base64 = signed_psbt_for_disaster_start(&start);

        let result = complete_disaster_signing_drill(DisasterSigningCompleteInput {
            scenario: DisasterSigningScenario::Ds8,
            network: PracticeDrillNetwork::Regtest,
            transport: DisasterSigningTransport::Qr,
            started_at: start.started_at,
            signed_psbt_base64,
            expected_destination_address: start.destination_address,
            expected_amount_sat: start.amount_sat,
            destination_confirmed: false,
            user_stopped: false,
        })
        .expect("signing drill completes as failed result");

        assert_eq!(result.result, DrillStepResult::Fail);
        assert_eq!(result.transport, "qr");
        assert!(result.steps.iter().any(|step| {
            step.step == "destination_confirmed_on_device" && step.result == DrillStepResult::Fail
        }));
    }

    #[test]
    fn disaster_signing_save_writes_signed_public_summary_only() {
        let dir = ScratchDir::new("disaster-signing-save");
        let start = start_disaster_signing_drill(
            DisasterSigningStartInput {
                scenario: DisasterSigningScenario::Ds10,
                network: PracticeDrillNetwork::Signet,
                transport: DisasterSigningTransport::File,
            },
            "2026-05-30T21:10:00Z",
        )
        .expect("signing drill starts");
        let destination = start.destination_address.clone();
        let unsigned = start.unsigned_psbt_base64.clone();
        let signed_psbt_base64 = signed_psbt_for_disaster_start(&start);
        let result = complete_disaster_signing_drill(DisasterSigningCompleteInput {
            scenario: DisasterSigningScenario::Ds10,
            network: PracticeDrillNetwork::Signet,
            transport: DisasterSigningTransport::File,
            started_at: start.started_at,
            signed_psbt_base64,
            expected_destination_address: start.destination_address,
            expected_amount_sat: start.amount_sat,
            destination_confirmed: true,
            user_stopped: false,
        })
        .expect("signing drill completes");

        let saved = save_disaster_signing_drill_result(&dir.path, result, "2026-05-30T21:12:00Z")
            .expect("record saved");

        assert_eq!(saved.record.payload.scenario, "DS-10");
        assert_eq!(saved.record.payload.result, DrillStepResult::Pass);
        assert_eq!(saved.record.payload.wallet_type, PRACTICE_WALLET_TYPE);
        validate_drill_result_record(&saved.record).expect("schema and signature validate");

        let bytes = std::fs::read(&saved.path).expect("record file exists");
        let json = String::from_utf8(bytes).expect("utf8 json");
        assert!(!json.contains(&destination));
        assert!(!json.contains(&unsigned));
    }

    #[test]
    fn disaster_signing_supports_all_ds7_through_ds10_scenarios() {
        let scenarios = [
            (
                DisasterSigningScenario::Ds7,
                "DS-7",
                "My spouse needs to recover",
            ),
            (
                DisasterSigningScenario::Ds8,
                "DS-8",
                "I need to verify my hardware wallet can still sign",
            ),
            (
                DisasterSigningScenario::Ds9,
                "DS-9",
                "I want to test a PSBT signing workflow",
            ),
            (
                DisasterSigningScenario::Ds10,
                "DS-10",
                "I want to simulate restoring on a clean machine",
            ),
        ];

        for (scenario, code, title) in scenarios {
            let start = start_disaster_signing_drill(
                DisasterSigningStartInput {
                    scenario,
                    network: PracticeDrillNetwork::Regtest,
                    transport: DisasterSigningTransport::Qr,
                },
                "2026-05-30T21:15:00Z",
            )
            .expect("signing drill starts");

            assert_eq!(start.scenario, code);
            assert_eq!(start.scenario_title, title);
            assert_eq!(start.transport, "qr");
        }
    }

    #[test]
    fn signet_broadcast_posts_to_selected_esplora_endpoint() {
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Signet,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("signet drill result");
        let broadcaster = RecordingBroadcaster::new(result.finalized_txid.clone());

        let broadcast = broadcast_signet_transaction_with(
            &SignetBroadcastInput {
                network: PracticeDrillNetwork::Signet,
                transaction_hex: result.transaction_hex.clone(),
                endpoint: SignetBroadcastEndpoint::Mutinynet,
            },
            &broadcaster,
        )
        .expect("broadcast result");

        assert_eq!(broadcast.network, "signet");
        assert_eq!(broadcast.endpoint, "mutinynet");
        assert_eq!(broadcast.endpoint_url, MUTINYNET_ESPLORA_TX_URL);
        assert_eq!(broadcast.txid, result.finalized_txid);
        assert_eq!(
            broadcaster.calls.borrow().as_slice(),
            &[(MUTINYNET_ESPLORA_TX_URL.to_owned(), result.transaction_hex)]
        );
    }

    #[test]
    fn signet_broadcast_rejects_non_signet_before_network_io() {
        let broadcaster = RecordingBroadcaster::new("0".repeat(64));
        let err = broadcast_signet_transaction_with(
            &SignetBroadcastInput {
                network: PracticeDrillNetwork::Regtest,
                transaction_hex: "02000000000000000000".to_owned(),
                endpoint: SignetBroadcastEndpoint::Mutinynet,
            },
            &broadcaster,
        )
        .expect_err("regtest broadcast must be rejected");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
        assert!(broadcaster.calls.borrow().is_empty());
    }

    #[test]
    fn broadcast_endpoint_list_has_no_mainnet_url() {
        assert_eq!(
            SignetBroadcastEndpoint::Mutinynet.api_url(),
            "https://mutinynet.com/api/tx"
        );
        assert_eq!(
            SignetBroadcastEndpoint::Sprovoost.api_url(),
            "https://signet.bitcoin.sprovoost.nl/api/tx"
        );
    }

    #[test]
    fn signet_broadcast_input_rejects_mainnet_at_deserialization() {
        let input = serde_json::json!({
            "network": "mainnet",
            "transaction_hex": "0200000000",
            "endpoint": "mutinynet"
        });

        let err = serde_json::from_value::<SignetBroadcastInput>(input)
            .expect_err("mainnet is not a supported broadcast network");

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn create_sign_finalize_round_trip_on_regtest() {
        let mut wallet = funded_wallet(125_000);
        let recipient = wallet.change_address(7).address().to_owned();
        let request = CreatePsbtRequest::new(recipient, 60_000, 2);

        let created = create_psbt(&mut wallet, &request).expect("created psbt");
        assert_eq!(created.inspection().version(), 0);
        assert_eq!(created.inspection().network(), "regtest");
        assert_eq!(created.inspection().input_count(), 1);
        assert!(created.inspection().fee_sat() > 0);
        assert!(!created.inspection().finalized());

        let imported = import_psbt_base64(
            &created.to_base64().expect("export created psbt"),
            Network::Regtest,
        )
        .expect("import created psbt");
        assert_eq!(imported.inspection(), created.inspection());

        let signed = sign_psbt(&wallet, imported.into_psbt()).expect("signed psbt");
        assert!(!signed.inspection().finalized());
        assert!(signed
            .psbt()
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty()));

        let finalized = finalize_psbt(&wallet, signed.into_psbt()).expect("finalized psbt");
        assert!(finalized.inspection().finalized());
        assert_eq!(finalized.transaction().input.len(), 1);
        assert_eq!(
            finalized.transaction().compute_txid().to_string(),
            finalized.txid().to_string()
        );
        assert!(!finalized.transaction_bytes().is_empty());
    }

    #[test]
    fn file_psbt_flow_reads_signed_file_and_finalizes_with_practice_wallet() {
        let dir = ScratchDir::new("file-psbt");
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Regtest,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("signed practice psbt");
        let path = dir.path.join("signed.psbt");
        std::fs::write(&path, format!("{}\n", result.signed_psbt_base64))
            .expect("write signed psbt");

        let psbt_base64 = read_psbt_file(&path).expect("read signed psbt");
        assert_eq!(psbt_base64, result.signed_psbt_base64);

        let finalized = finalize_file_psbt(FilePsbtFinalizeInput {
            network: PracticeDrillNetwork::Regtest,
            psbt_base64,
        })
        .expect("finalized imported file psbt");

        assert_eq!(finalized.network, "regtest");
        assert_eq!(finalized.txid, result.finalized_txid);
        assert_eq!(finalized.inspection.network(), "regtest");
        assert!(finalized.inspection.finalized());
        assert!(!finalized.transaction_hex.is_empty());
    }

    #[test]
    fn mainnet_file_psbt_gate_validates_without_broadcast() {
        let result = run_receive_send_drill(PracticeSendDrillInput {
            network: PracticeDrillNetwork::Regtest,
            funding_amount_sat: 125_000,
            amount_sat: 60_000,
            fee_rate_sat_vb: 2,
        })
        .expect("signed practice psbt");

        let validated = validate_mainnet_file_psbt(MainnetFilePsbtValidateInput {
            psbt_base64: result.signed_psbt_base64,
        })
        .expect("mainnet PSBT validation succeeds locally");

        assert_eq!(validated.network, "mainnet");
        assert_eq!(validated.inspection.network(), "mainnet");
        assert_eq!(validated.txid, validated.inspection.txid());
        assert_eq!(validated.finalized, validated.inspection.finalized());
        assert!(!validated.broadcast_available);
    }

    #[test]
    fn import_rejects_malformed_psbt_with_typed_error() {
        let err = import_psbt_base64("not a psbt", Network::Regtest)
            .expect_err("malformed psbt must fail");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn inspect_rejects_unsupported_psbt_version() {
        let mut wallet = funded_wallet(100_000);
        let recipient = wallet.change_address(3).address().to_owned();
        let created = create_psbt(&mut wallet, &CreatePsbtRequest::new(recipient, 50_000, 1))
            .expect("created psbt");
        let mut psbt = created.into_psbt();
        psbt.version = 3;

        let err = inspect_psbt(&psbt, Network::Regtest).expect_err("v3 must fail");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn import_accepts_bip370_v2_fixture() {
        let imported = import_psbt_base64(BIP370_UPDATED_V2, Network::Regtest)
            .expect("official BIP370 fixture imports");

        assert_eq!(imported.inspection().version(), 2);
        assert_eq!(imported.inspection().network(), "regtest");
        assert_eq!(imported.inspection().input_count(), 1);
        assert_eq!(imported.inspection().output_count(), 2);
        assert!(imported.inspection().input_total_sat() > imported.inspection().output_total_sat());
        assert!(imported.psbt().inputs[0].witness_utxo.is_some());
        assert_eq!(
            imported.psbt().unsigned_tx.version,
            transaction::Version::TWO
        );
    }

    #[test]
    fn taproot_script_path_exports_as_v2_and_round_trips() {
        let mut wallet = funded_wallet(125_000);
        let recipient = wallet.change_address(7).address().to_owned();
        let created = create_psbt(&mut wallet, &CreatePsbtRequest::new(recipient, 60_000, 2))
            .expect("created psbt");
        let mut psbt = created.into_psbt();
        attach_taproot_script_path(&mut psbt);

        assert!(uses_taproot_script_path(&psbt));
        let drill = wrap_psbt(psbt.clone(), Network::Regtest).expect("wrapped taproot psbt");
        let exported = drill.to_base64().expect("exported v2 psbt");
        let imported = import_psbt_base64(&exported, Network::Regtest).expect("reimported v2 psbt");

        assert_eq!(imported.inspection().version(), 2);
        assert_eq!(imported.psbt().unsigned_tx, psbt.unsigned_tx);
        assert!(uses_taproot_script_path(imported.psbt()));
        assert_eq!(imported.psbt().inputs[0].tap_scripts.len(), 1);

        let exported_bytes = BASE64_STANDARD.decode(exported).expect("base64");
        let global = decode_raw_global(&exported_bytes).expect("raw global map");
        assert_eq!(
            required_u32(&global, PSBT_GLOBAL_VERSION, "PSBT_GLOBAL_VERSION")
                .expect("global version"),
            2
        );
        assert!(!has_type(&global, PSBT_GLOBAL_UNSIGNED_TX));
    }

    #[test]
    fn create_rejects_wrong_network_recipient() {
        let mut wallet = funded_wallet(100_000);
        let request =
            CreatePsbtRequest::new("tb1qfrwwq2u42a88tx8f2sd69y9grgtyq9cmmpw82v", 50_000, 1);

        let err = create_psbt(&mut wallet, &request)
            .expect_err("signet/testnet address should not pass regtest drill");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn inspect_rejects_missing_utxo_fee_data() {
        let mut wallet = funded_wallet(100_000);
        let recipient = wallet.change_address(3).address().to_owned();
        let created = create_psbt(&mut wallet, &CreatePsbtRequest::new(recipient, 50_000, 1))
            .expect("created psbt");
        let mut psbt = created.into_psbt();
        psbt.inputs[0].witness_utxo = None;
        psbt.inputs[0].non_witness_utxo = None;

        let err = inspect_psbt(&psbt, Network::Regtest).expect_err("missing UTXO must fail");

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    fn funded_wallet(amount_sat: u64) -> DisposableWallet {
        let mut wallet = DisposableWallet::from_seed(PracticeNetwork::Regtest, TEST_SEED)
            .expect("practice wallet");
        apply_local_funding_update(&mut wallet, amount_sat).expect("funding update");
        wallet
    }

    #[derive(Debug)]
    struct RecordingBroadcaster {
        response: String,
        calls: RefCell<Vec<(String, String)>>,
    }

    impl RecordingBroadcaster {
        fn new(response: String) -> Self {
            Self {
                response,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl SignetBroadcaster for RecordingBroadcaster {
        fn broadcast(
            &self,
            endpoint_url: &str,
            transaction_hex: &str,
        ) -> Result<String, LifeboatError> {
            self.calls
                .borrow_mut()
                .push((endpoint_url.to_owned(), transaction_hex.to_owned()));
            Ok(self.response.clone())
        }
    }

    fn attach_taproot_script_path(psbt: &mut Psbt) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[7_u8; 32]).expect("secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let internal_key = keypair.x_only_public_key().0;
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("taproot leaf")
            .finalize(&secp, internal_key)
            .expect("taproot spend info");
        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block");

        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (script, LeafVersion::TapScript));
    }
}
