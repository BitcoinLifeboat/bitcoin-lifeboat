//! `psbt-tools` - root-workspace PSBT file helpers for the CLI.
//!
//! This crate intentionally stays smaller than `psbt-drill`. It can import,
//! validate, inspect, and extract already-finalized PSBT files without BDK or any
//! wallet state, so it builds under the root Rust 1.78 toolchain. Practice-wallet
//! creation, signing, and broadcast remain in the detached `psbt-drill` crate.

use std::io::{Cursor, Read};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use error_taxonomy::{ErrorCode, LifeboatError};
use miniscript::bitcoin::absolute;
use miniscript::bitcoin::blockdata::transaction::{self, Sequence, TxIn};
use miniscript::bitcoin::consensus::encode::{serialize, Decodable};
use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::psbt::Psbt;
use miniscript::bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, VarInt, Witness,
};
use serde::Serialize;

/// Maximum accepted PSBT text or decoded binary size.
pub const MAX_PSBT_SIZE_BYTES: usize = 10 * 1024 * 1024;

const PSBT_VERSION_V0: u32 = 0;
const PSBT_VERSION_V2: u32 = 2;

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

/// PSBT wire format found on import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PsbtEncoding {
    /// BIP174 PSBT v0.
    Bip174V0,
    /// BIP370 PSBT v2.
    Bip370V2,
}

impl PsbtEncoding {
    /// User-facing label for human output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bip174V0 => "BIP174 v0",
            Self::Bip370V2 => "BIP370 v2",
        }
    }
}

/// Coarse signing/finalization state inferred from PSBT maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PsbtLifecycle {
    /// No recognized signatures or final scripts are present.
    Unsigned,
    /// Some signature material is present, but not every input is finalized.
    PartiallySigned,
    /// Every input carries final script data.
    Finalized,
}

impl PsbtLifecycle {
    /// Stable string for human output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::PartiallySigned => "partially_signed",
            Self::Finalized => "finalized",
        }
    }
}

/// Local, non-secret summary of a PSBT file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PsbtInspection {
    /// Supported PSBT version: `0` or `2`.
    pub version: u32,
    /// Original import encoding.
    pub encoding: PsbtEncoding,
    /// Signing/finalization state inferred from the input maps.
    pub lifecycle: PsbtLifecycle,
    /// Unsigned transaction input count.
    pub input_count: usize,
    /// Unsigned transaction output count.
    pub output_count: usize,
    /// Number of inputs with final script data.
    pub finalized_input_count: usize,
    /// Whether every input has witness or non-witness UTXO data.
    pub has_all_utxo_data: bool,
    /// Total locally-known input amount, if every input has UTXO data.
    pub input_total_sat: Option<u64>,
    /// Total unsigned transaction output amount.
    pub output_total_sat: u64,
    /// Locally-computed fee, if every input has UTXO data.
    pub fee_sat: Option<u64>,
    /// Locally-computed fee rate, if every input has UTXO data.
    pub fee_rate_sat_vb: Option<u64>,
    /// Unsigned transaction id.
    pub txid: String,
    /// Per-input public summary.
    pub inputs: Vec<PsbtInputSummary>,
    /// Per-output public summary.
    pub outputs: Vec<PsbtOutputSummary>,
}

/// Per-input public PSBT summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PsbtInputSummary {
    /// Input index.
    pub index: usize,
    /// Previous outpoint.
    pub previous_output: String,
    /// Sequence number.
    pub sequence: u32,
    /// Locally-known input amount, if present.
    pub amount_sat: Option<u64>,
    /// Whether witness UTXO data is present.
    pub has_witness_utxo: bool,
    /// Whether non-witness UTXO data is present.
    pub has_non_witness_utxo: bool,
    /// Whether any recognized signature material is present.
    pub has_signature_material: bool,
    /// Whether this input has final script data.
    pub finalized: bool,
}

/// Per-output public PSBT summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PsbtOutputSummary {
    /// Output index.
    pub index: usize,
    /// Output amount.
    pub amount_sat: u64,
    /// ScriptPubKey as lowercase hex.
    pub script_pubkey: String,
    /// Address for the caller-selected network, when the script maps to one.
    pub address: Option<String>,
}

/// Import a base64 BIP174 v0 or BIP370 v2 PSBT and inspect it.
pub fn inspect_psbt_base64(
    input: &str,
    network: Option<Network>,
) -> Result<PsbtInspection, LifeboatError> {
    let imported = import_psbt_base64(input)?;
    Ok(inspect_imported_psbt(&imported, network))
}

/// Import a base64 BIP174 v0 or BIP370 v2 PSBT.
pub fn import_psbt_base64(input: &str) -> Result<ImportedPsbt, LifeboatError> {
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

    if let Ok(psbt) = Psbt::deserialize(&bytes) {
        if psbt.version == PSBT_VERSION_V0 {
            return Ok(ImportedPsbt {
                psbt,
                encoding: PsbtEncoding::Bip174V0,
            });
        }
    }

    let raw = decode_raw_psbt_v2(&bytes)?;
    let unsigned_tx = reconstruct_v2_unsigned_tx(&raw)?;
    let v0_bytes = encode_v0_psbt_bytes(&raw, &unsigned_tx);
    let mut psbt = Psbt::deserialize(&v0_bytes).map_err(|err| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("BIP370 PSBT v2 could not be converted for local inspection")
            .with_source(err)
    })?;
    psbt.version = PSBT_VERSION_V2;
    Ok(ImportedPsbt {
        psbt,
        encoding: PsbtEncoding::Bip370V2,
    })
}

/// Imported PSBT plus the encoding it arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedPsbt {
    psbt: Psbt,
    encoding: PsbtEncoding,
}

impl ImportedPsbt {
    /// Borrow the decoded PSBT.
    #[must_use]
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// Consume and return the decoded PSBT.
    #[must_use]
    pub fn into_psbt(self) -> Psbt {
        self.psbt
    }

    /// Encoding discovered during import.
    #[must_use]
    pub const fn encoding(&self) -> PsbtEncoding {
        self.encoding
    }

    /// Export in the original imported encoding where possible.
    pub fn to_base64(&self) -> Result<String, LifeboatError> {
        match self.encoding {
            PsbtEncoding::Bip174V0 => Ok(BASE64_STANDARD.encode(self.psbt.serialize())),
            PsbtEncoding::Bip370V2 => export_psbt_v2_base64(&self.psbt),
        }
    }
}

/// Inspect a decoded PSBT using only local PSBT data.
#[must_use]
pub fn inspect_imported_psbt(imported: &ImportedPsbt, network: Option<Network>) -> PsbtInspection {
    inspect_psbt(imported.psbt(), imported.encoding(), network)
}

/// Inspect a decoded PSBT using only local PSBT data.
#[must_use]
pub fn inspect_psbt(
    psbt: &Psbt,
    encoding: PsbtEncoding,
    network: Option<Network>,
) -> PsbtInspection {
    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    let mut input_total_sat = Some(0_u64);
    let mut signature_input_count = 0_usize;
    let mut finalized_input_count = 0_usize;

    for (index, (txin, input)) in psbt
        .unsigned_tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .enumerate()
    {
        let amount_sat =
            input_txout(txin.previous_output.vout, input).map(|txout| txout.value.to_sat());
        input_total_sat = match (input_total_sat, amount_sat) {
            (Some(total), Some(amount)) => total.checked_add(amount),
            _ => None,
        };
        let has_signature_material = !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty();
        if has_signature_material {
            signature_input_count += 1;
        }
        let finalized = input.final_script_sig.is_some() || input.final_script_witness.is_some();
        if finalized {
            finalized_input_count += 1;
        }

        inputs.push(PsbtInputSummary {
            index,
            previous_output: txin.previous_output.to_string(),
            sequence: txin.sequence.to_consensus_u32(),
            amount_sat,
            has_witness_utxo: input.witness_utxo.is_some(),
            has_non_witness_utxo: input.non_witness_utxo.is_some(),
            has_signature_material,
            finalized,
        });
    }

    let outputs: Vec<PsbtOutputSummary> = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .map(|(index, txout)| PsbtOutputSummary {
            index,
            amount_sat: txout.value.to_sat(),
            script_pubkey: script_hex(&txout.script_pubkey),
            address: network.and_then(|net| {
                Address::from_script(&txout.script_pubkey, net)
                    .map(|address| address.to_string())
                    .ok()
            }),
        })
        .collect();
    let output_total_sat = outputs
        .iter()
        .try_fold(0_u64, |total, output| total.checked_add(output.amount_sat))
        .unwrap_or(0);
    let fee_sat = input_total_sat.and_then(|total| total.checked_sub(output_total_sat));
    let vbytes = psbt.unsigned_tx.weight().to_vbytes_ceil();
    let fee_rate_sat_vb = fee_sat.map(|fee| if vbytes == 0 { 0 } else { fee.div_ceil(vbytes) });
    let lifecycle = if finalized_input_count == psbt.inputs.len() && !psbt.inputs.is_empty() {
        PsbtLifecycle::Finalized
    } else if signature_input_count > 0 || finalized_input_count > 0 {
        PsbtLifecycle::PartiallySigned
    } else {
        PsbtLifecycle::Unsigned
    };

    PsbtInspection {
        version: psbt.version,
        encoding,
        lifecycle,
        input_count: psbt.unsigned_tx.input.len(),
        output_count: psbt.unsigned_tx.output.len(),
        finalized_input_count,
        has_all_utxo_data: input_total_sat.is_some(),
        input_total_sat,
        output_total_sat,
        fee_sat,
        fee_rate_sat_vb,
        txid: psbt.unsigned_tx.compute_txid().to_string(),
        inputs,
        outputs,
    }
}

/// Extract a finalized PSBT's transaction as lowercase hex.
pub fn extract_final_tx_hex(input: &str) -> Result<String, LifeboatError> {
    let imported = import_psbt_base64(input)?;
    let inspection = inspect_imported_psbt(&imported, None);
    if inspection.lifecycle != PsbtLifecycle::Finalized {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("PSBT is not finalized; every input needs final script data first"));
    }
    let tx = imported
        .into_psbt()
        .extract_tx_fee_rate_limit()
        .map_err(|err| {
            LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("PSBT could not be extracted as a finalized transaction")
                .with_source(err)
        })?;
    Ok(hex_encode(&serialize(&tx)))
}

/// Export a decoded PSBT as BIP370 v2 base64.
pub fn export_psbt_v2_base64(psbt: &Psbt) -> Result<String, LifeboatError> {
    let bytes = encode_psbt_v2(psbt)?;
    Ok(BASE64_STANDARD.encode(bytes))
}

fn input_txout(vout: u32, input: &miniscript::bitcoin::psbt::Input) -> Option<&TxOut> {
    match (&input.witness_utxo, &input.non_witness_utxo) {
        (Some(witness_utxo), _) => Some(witness_utxo),
        (None, Some(non_witness_utxo)) => non_witness_utxo.output.get(vout as usize),
        (None, None) => None,
    }
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

fn encode_psbt_v2(psbt: &Psbt) -> Result<Vec<u8>, LifeboatError> {
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

    const BIP370_UPDATED_V2: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/psbt/bip370_updated_v2.txt"
    ));

    const BIP174_UPDATED_V0: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/psbt/bip174_updated_v0.txt"
    ));

    #[test]
    fn imports_and_inspects_bip174_v0() {
        let imported = import_psbt_base64(BIP174_UPDATED_V0).expect("valid v0 fixture");
        assert_eq!(imported.encoding(), PsbtEncoding::Bip174V0);
        let inspection = inspect_imported_psbt(&imported, Some(Network::Bitcoin));
        assert_eq!(inspection.version, 0);
        assert_eq!(inspection.input_count, 1);
        assert_eq!(inspection.output_count, 2);
        assert!(inspection.has_all_utxo_data);
        assert_eq!(inspection.lifecycle, PsbtLifecycle::Unsigned);
    }

    #[test]
    fn imports_and_inspects_bip370_v2() {
        let imported = import_psbt_base64(BIP370_UPDATED_V2).expect("valid v2 fixture");
        assert_eq!(imported.encoding(), PsbtEncoding::Bip370V2);
        let inspection = inspect_imported_psbt(&imported, Some(Network::Testnet));
        assert_eq!(inspection.version, 2);
        assert_eq!(inspection.input_count, 1);
        assert_eq!(inspection.output_count, 2);
        assert!(inspection.has_all_utxo_data);
        assert_eq!(inspection.lifecycle, PsbtLifecycle::Unsigned);
    }

    #[test]
    fn v2_round_trip_stays_bip370() {
        let imported = import_psbt_base64(BIP370_UPDATED_V2).expect("valid v2 fixture");
        let exported = imported.to_base64().expect("v2 export");
        let again = import_psbt_base64(&exported).expect("round-tripped v2 fixture");
        assert_eq!(again.encoding(), PsbtEncoding::Bip370V2);
        assert_eq!(again.psbt().unsigned_tx, imported.psbt().unsigned_tx);
    }

    #[test]
    fn malformed_base64_is_typed_input_error() {
        let err = import_psbt_base64("not psbt").expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }
}
