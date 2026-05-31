//! Sparrow wallet JSON importer (PRD §17.9, §24.2).
//!
//! Sparrow's "File > Export Wallet" produces a keystore-based wallet JSON. Unlike
//! Bitcoin Core / Specter, it carries **no** output-descriptor string: instead it
//! has a `policyType` (`SINGLE`/`MULTI`), a `scriptType` (`P2WPKH`, `P2WSH`, …), a
//! `defaultPolicy.numSignaturesRequired` (the multisig threshold `M`), and a
//! `keystores` array — each keystore holding a `keyDerivation` origin
//! (`masterFingerprint` + `derivationPath`) and an `extendedPublicKey`.
//!
//! This importer **assembles** the receive (`/0/*`), change (`/1/*`), and BIP389
//! multipath (`/<0;1>/*`) output descriptors from those parts (Sparrow wallets are
//! inherently multipath — both chains), normalizing any SLIP-132 keys
//! (`vpub`/`upub`/…) to standard `xpub`/`tpub` and computing a fresh BIP380
//! checksum, then reuses descriptor-audit facts for key origins and quorum. The
//! birth time is an epoch `birthDate` (Java `Date` → milliseconds) rendered as ISO
//! 8601; optional `birthHeight` and `gapLimit` carry through.
//!
//! ## Watch-only safety
//! The private-material keystore fields Sparrow can emit for a hot wallet (`seed`,
//! `masterPrivateExtendedKey`, `bip47ExtendedPrivateKey`) are deliberately **not**
//! declared on [`SparrowKeystore`]; with `deny_unknown_fields`, a non-watch-only
//! export is refused (`E-INPUT-003`) rather than ever deserializing secret
//! material. Only the watch-only `extendedPublicKey` is read.

use error_taxonomy::{ErrorCode, LifeboatError};

use crate::{
    analyze_descriptor, classify, epoch_value_to_iso8601, extract_keys, guard_input,
    strip_master_prefix, NormalizedWalletExport, WalletDescriptors,
};

/// A Sparrow wallet export. Strict (`deny_unknown_fields`) so an unexpected key is
/// refused rather than silently ignored (PRD §17.9). A future Sparrow field must
/// be added to the accepted-but-unused list below (see the crate `CLAUDE.md`).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SparrowWallet {
    #[serde(rename = "policyType")]
    policy_type: String,
    #[serde(rename = "scriptType")]
    script_type: String,
    #[serde(rename = "defaultPolicy")]
    default_policy: SparrowPolicy,
    keystores: Vec<SparrowKeystore>,
    /// Java `Date` (epoch milliseconds) → ISO 8601 birth timestamp.
    #[serde(default, rename = "birthDate")]
    birth_date: Option<serde_json::Value>,
    #[serde(default, rename = "birthHeight")]
    birth_height: Option<u64>,
    #[serde(default, rename = "gapLimit")]
    gap_limit: Option<u32>,
    // Accepted but unused (present in real Sparrow exports).
    #[allow(dead_code)]
    #[serde(default)]
    name: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    label: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    network: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "masterWallet")]
    master_wallet: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "childWallets")]
    child_wallets: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "storedBlockHeight")]
    stored_block_height: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "watchLast")]
    watch_last: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "detachedLabels")]
    detached_labels: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "walletConfig")]
    wallet_config: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "walletTables")]
    wallet_tables: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "mixConfig")]
    mix_config: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "utxoMixes")]
    utxo_mixes: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "purposeNodes")]
    purpose_nodes: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    transactions: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "silentPaymentAddresses")]
    silent_payment_addresses: Option<serde_json::Value>,
}

/// Sparrow's wallet policy. Only the multisig threshold is read.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SparrowPolicy {
    /// The multisig threshold `M` (`1` for singlesig).
    #[serde(rename = "numSignaturesRequired")]
    num_signatures_required: u32,
    #[allow(dead_code)]
    #[serde(default)]
    name: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    script: Option<serde_json::Value>,
}

/// One Sparrow keystore. Only the watch-only origin + xpub are read; see the
/// module docs for why private-material fields are intentionally not declared.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SparrowKeystore {
    #[serde(rename = "keyDerivation")]
    key_derivation: SparrowKeyDerivation,
    #[serde(rename = "extendedPublicKey")]
    extended_public_key: String,
    #[allow(dead_code)]
    #[serde(default)]
    label: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    source: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default, rename = "walletModel")]
    wallet_model: Option<serde_json::Value>,
}

/// A keystore's key origin: master fingerprint and the origin derivation path.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SparrowKeyDerivation {
    #[serde(rename = "masterFingerprint")]
    master_fingerprint: String,
    #[serde(rename = "derivationPath")]
    derivation_path: String,
    // Sparrow also serializes the parsed derivation (a list of child numbers);
    // accepted but unused — `derivation_path` is the source of truth here.
    #[allow(dead_code)]
    #[serde(default)]
    derivation: Option<serde_json::Value>,
}

/// A descriptor key's origin annotation and extended key, ready to be joined with
/// a chain suffix (`<0;1>` / `0` / `1`) and `/*`.
struct KeyParts {
    /// `[fingerprint/origin-path]`, or `[fingerprint]` when the path is just `m`.
    origin: String,
    /// The extended public key (`tpub`/`xpub`/SLIP-132 `vpub`/…).
    xpub: String,
}

/// Import a Sparrow wallet JSON export (PRD §17.9, §24.2).
///
/// `version` is the Sparrow version learned out-of-band (it is not in the export
/// file); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` for content that is not valid Sparrow wallet JSON, has no
///   keystores, or uses a policy/script combination this importer cannot assemble.
/// - `E-PARSE-005` when an assembled descriptor carries private-key material — the
///   export is refused before any normalized value is built. (Watch-only exports,
///   the only kind that parse, cannot reach this; the check is defensive.)
pub fn import_sparrow(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let wallet: SparrowWallet = serde_json::from_str(content).map_err(|e| {
        // Report only the structural location, never the content (descriptors and
        // xpubs are confidential and must not leak into errors/logs).
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "not valid Sparrow wallet JSON (at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;

    if wallet.keystores.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Sparrow export contains no keystores"));
    }
    if wallet.policy_type == "SINGLE" && wallet.keystores.len() != 1 {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Sparrow singlesig export must contain exactly one keystore"));
    }

    let parts: Vec<KeyParts> = wallet.keystores.iter().map(key_parts).collect();
    let m = wallet.default_policy.num_signatures_required;

    // Assemble the multipath descriptor (the canonical Sparrow form) and its
    // expanded receive/change branches. `assemble` rejects an unsupported
    // policy/script combination with a typed error.
    let multipath = assemble(&wallet.policy_type, &wallet.script_type, m, &parts, "<0;1>")?;
    let receive = assemble(&wallet.policy_type, &wallet.script_type, m, &parts, "0")?;
    let change = assemble(&wallet.policy_type, &wallet.script_type, m, &parts, "1")?;

    // Refuse private-key material before storing; tolerate other parse problems
    // (the analysis layer reports those). `multisig_info()` / `key_origins()` read
    // correctly off the multipath descriptor (US-009).
    let parsed = analyze_descriptor(&multipath)?;
    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "sparrow".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change: Some(change),
        },
        keys,
        birth_height: wallet.birth_height,
        birth_timestamp: wallet.birth_date.as_ref().and_then(epoch_value_to_iso8601),
        gap_limit: wallet.gap_limit,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}

/// Build the `[origin]xpub` key parts for one keystore.
fn key_parts(keystore: &SparrowKeystore) -> KeyParts {
    let fingerprint = keystore.key_derivation.master_fingerprint.trim();
    let path = strip_master_prefix(&keystore.key_derivation.derivation_path);
    let origin = if path.is_empty() {
        format!("[{fingerprint}]")
    } else {
        format!("[{fingerprint}/{path}]")
    };
    KeyParts {
        origin,
        xpub: keystore.extended_public_key.trim().to_string(),
    }
}

/// Assemble one chain's output descriptor from the Sparrow policy/script type,
/// threshold, and key parts, then normalize SLIP-132 keys and add a BIP380
/// checksum. `chain` is `"<0;1>"` (multipath), `"0"` (receive), or `"1"` (change).
///
/// # Errors
/// `E-INPUT-003` when the policy/script combination is not one the MVP assembles
/// (e.g. a `CUSTOM` miniscript policy, or Taproot multisig).
fn assemble(
    policy_type: &str,
    script_type: &str,
    threshold: u32,
    parts: &[KeyParts],
    chain: &str,
) -> Result<String, LifeboatError> {
    let keys: Vec<String> = parts
        .iter()
        .map(|p| format!("{}{}/{}/*", p.origin, p.xpub, chain))
        .collect();
    let body = match (policy_type, script_type) {
        ("SINGLE", "P2PKH") => format!("pkh({})", keys[0]),
        ("SINGLE", "P2SH_P2WPKH") => format!("sh(wpkh({}))", keys[0]),
        ("SINGLE", "P2WPKH") => format!("wpkh({})", keys[0]),
        ("SINGLE", "P2TR") => format!("tr({})", keys[0]),
        ("MULTI", "P2SH") => format!("sh(sortedmulti({},{}))", threshold, keys.join(",")),
        ("MULTI", "P2SH_P2WSH") => {
            format!("sh(wsh(sortedmulti({},{})))", threshold, keys.join(","))
        }
        ("MULTI", "P2WSH") => format!("wsh(sortedmulti({},{}))", threshold, keys.join(",")),
        _ => {
            return Err(
                LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
                    "unsupported Sparrow wallet configuration ({policy_type} / {script_type})"
                )),
            )
        }
    };
    // Normalize any SLIP-132 keys (vpub/upub/… → tpub/xpub) and (re)compute the
    // BIP380 checksum over the assembled body.
    let normalized = descriptor_audit::normalize_slip132(&body)?;
    descriptor_audit::compute_checksum(normalized.descriptor())
}
