//! Blockstream Jade multisig registered-wallet importer (PRD §17.9, §24.2).
//!
//! Jade exports a registered multisig wallet from the Options / Wallet /
//! Registered Wallets / Export menu as JSON describing the multisig *descriptor
//! object* Jade uses to register the wallet: a `variant` (`wsh(multi(k))` /
//! `sh(multi(k))` /
//! `sh(wsh(multi(k)))`), a `sorted` flag (sortedmulti vs. multi), a `threshold`
//! (`M`), and a `signers` array. Each signer carries a master `fingerprint`, the
//! origin `derivation` to its `xpub`, and an optional `path` suffix applied to the
//! xpub (empty in the normal case). Like Sparrow/Coldcard-JSON this is keystore-
//! based — no ready-made descriptor string — so the importer **assembles** the
//! output descriptor from the parts, normalizes SLIP-132 keys, and computes a
//! BIP380 checksum (reusing the descriptor-audit primitives).
//!
//! ## Field encodings (both accepted)
//! Jade's wire form encodes `fingerprint` as 4 raw bytes and `derivation`/`path` as
//! arrays of BIP32 indices (hardened ≥ 2³¹); a file export commonly uses the more
//! readable hex-string fingerprint and string derivation path. To parse real
//! exports either way, [`fingerprint_hex`] accepts a hex string **or** a 4-byte
//! array, and [`origin_path`] / [`suffix_path`] accept a path string **or** an
//! index array.

use error_taxonomy::{ErrorCode, LifeboatError};
use serde_json::Value;

use crate::{
    analyze_descriptor, classify, extract_keys, guard_input, strip_master_prefix,
    NormalizedWalletExport, WalletDescriptors,
};

/// A Jade registered-wallet export. Strict (`deny_unknown_fields`) so an unexpected
/// key is refused rather than silently ignored (PRD §17.9).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JadeExport {
    descriptor: JadeDescriptor,
    /// Registered-wallet name (≤ 15 chars on device); accepted but unused.
    #[allow(dead_code)]
    #[serde(default)]
    multisig_name: Option<String>,
    /// Network label; accepted but unused (inferred from the descriptor downstream).
    #[allow(dead_code)]
    #[serde(default)]
    network: Option<String>,
}

/// The Jade multisig descriptor object.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JadeDescriptor {
    /// `wsh(multi(k))` / `sh(multi(k))` / `sh(wsh(multi(k)))` (the `(k)` is literal).
    variant: String,
    /// Whether keys are BIP67-sorted (`sortedmulti`) vs. positional (`multi`).
    sorted: bool,
    /// The multisig threshold `M`.
    threshold: u32,
    /// The co-signers, in descriptor key order.
    signers: Vec<JadeSigner>,
    /// Liquid confidential-address key; accepted but unused (Bitcoin-only here).
    #[allow(dead_code)]
    #[serde(default)]
    master_blinding_key: Option<Value>,
}

/// One Jade signer. `fingerprint`/`derivation`/`path` accept either Jade's native
/// index/byte-array wire form or the string form a file export may use.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JadeSigner {
    /// Master key fingerprint — hex string (`"4ba43603"`) or 4-byte array.
    fingerprint: Value,
    /// Origin path from the master to `xpub` — string (`"m/48'/1'/0'/2'"`) or index
    /// array (`[2147483696, …]`).
    derivation: Value,
    /// The signer's account-level extended public key.
    xpub: String,
    /// Path applied to `xpub` to reach the signing key (usually empty); string or
    /// index array. Non-hardened only (an xpub cannot derive hardened children).
    #[serde(default)]
    path: Option<Value>,
}

/// The script wrapper implied by a Jade `variant`.
#[derive(Clone, Copy)]
enum Wrapper {
    /// `wsh(...)`.
    Wsh,
    /// `sh(...)`.
    Sh,
    /// `sh(wsh(...))`.
    ShWsh,
}

/// A signer reduced to the parts needed to assemble a descriptor key.
struct SignerParts {
    /// `[fingerprint/origin-path]`, or `[fingerprint]` when the origin path is empty.
    origin: String,
    /// The extended public key.
    xpub: String,
    /// The (non-hardened) suffix applied to the xpub before the chain, e.g. `/0`, or
    /// empty.
    suffix: String,
}

/// Import a Jade multisig registered-wallet JSON export (PRD §17.9, §24.2).
///
/// `version` is the Jade firmware version learned out-of-band (it is not in the
/// export); pass `None` when unknown.
///
/// # Errors
/// - `E-INPUT-001` / `E-INPUT-002` for empty / oversized content.
/// - `E-INPUT-003` for content that is not a valid Jade export, has no signers, a
///   malformed fingerprint / derivation, or an unsupported `variant`.
/// - `E-PARSE-005` if an assembled descriptor carries private-key material (a
///   watch-only export cannot reach this; the check is defensive).
pub fn import_jade(
    content: &str,
    version: Option<&str>,
) -> Result<NormalizedWalletExport, LifeboatError> {
    guard_input(content)?;

    let export: JadeExport = serde_json::from_str(content).map_err(|e| {
        // Report only the structural location, never the content (xpubs are
        // confidential and must not leak into errors/logs).
        LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(format!(
            "not a valid Jade multisig export (at line {}, column {})",
            e.line(),
            e.column()
        ))
    })?;

    let desc = &export.descriptor;
    if desc.signers.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("Jade multisig export has no signers"));
    }
    let wrapper = wrapper_for(&desc.variant)?;
    let parts: Vec<SignerParts> = desc
        .signers
        .iter()
        .map(signer_parts)
        .collect::<Result<_, _>>()?;

    // Assemble the multipath descriptor (for key/quorum analysis) and the expanded
    // receive/change branches, mirroring the Sparrow keystore assembler.
    let multipath = assemble(wrapper, desc.sorted, desc.threshold, &parts, "<0;1>")?;
    let receive = assemble(wrapper, desc.sorted, desc.threshold, &parts, "0")?;
    let change = assemble(wrapper, desc.sorted, desc.threshold, &parts, "1")?;

    // Refuse private-key material before storing; tolerate other parse problems.
    let parsed = analyze_descriptor(&multipath)?;
    let keys = parsed.as_ref().map(extract_keys).unwrap_or_default();
    let (wallet_type, threshold, key_count) = parsed.as_ref().map_or((None, None, None), classify);

    Ok(NormalizedWalletExport {
        source_wallet: "jade".to_string(),
        source_wallet_version: version.map(str::to_owned),
        imported_at: None,
        descriptors: WalletDescriptors {
            receive: Some(receive),
            change: Some(change),
        },
        keys,
        // Jade exports carry no wallet birth height/time (§24.2).
        birth_height: None,
        birth_timestamp: None,
        gap_limit: None,
        labels: Vec::new(),
        wallet_type,
        threshold,
        key_count,
        raw_source_filename: None,
    })
}

/// Map a Jade `variant` to its script wrapper. Accepts the `multi(k)` and
/// `sortedmulti(k)` spellings (the `sorted` flag, not the variant, selects which).
fn wrapper_for(variant: &str) -> Result<Wrapper, LifeboatError> {
    match variant.trim() {
        "wsh(multi(k))" | "wsh(sortedmulti(k))" => Ok(Wrapper::Wsh),
        "sh(multi(k))" | "sh(sortedmulti(k))" => Ok(Wrapper::Sh),
        "sh(wsh(multi(k)))" | "sh(wsh(sortedmulti(k)))" => Ok(Wrapper::ShWsh),
        other => Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context(format!("unsupported Jade multisig variant ({other})"))),
    }
}

/// Reduce a Jade signer to its descriptor-key parts: `[fingerprint/origin]`, the
/// xpub, and the (usually empty) suffix path.
fn signer_parts(signer: &JadeSigner) -> Result<SignerParts, LifeboatError> {
    let fingerprint = fingerprint_hex(&signer.fingerprint)?;
    let origin_path = origin_path(&signer.derivation)?;
    let origin = if origin_path.is_empty() {
        format!("[{fingerprint}]")
    } else {
        format!("[{fingerprint}/{origin_path}]")
    };
    let suffix = match &signer.path {
        Some(v) => suffix_path(v)?,
        None => String::new(),
    };
    Ok(SignerParts {
        origin,
        xpub: signer.xpub.trim().to_string(),
        suffix,
    })
}

/// Assemble one chain's descriptor from the parts, then normalize SLIP-132 keys and
/// add a BIP380 checksum. `chain` is `"<0;1>"` (multipath), `"0"`, or `"1"`.
fn assemble(
    wrapper: Wrapper,
    sorted: bool,
    threshold: u32,
    parts: &[SignerParts],
    chain: &str,
) -> Result<String, LifeboatError> {
    let keys: Vec<String> = parts
        .iter()
        .map(|p| format!("{}{}{}/{}/*", p.origin, p.xpub, p.suffix, chain))
        .collect();
    let inner = if sorted {
        format!("sortedmulti({},{})", threshold, keys.join(","))
    } else {
        format!("multi({},{})", threshold, keys.join(","))
    };
    let body = match wrapper {
        Wrapper::Wsh => format!("wsh({inner})"),
        Wrapper::Sh => format!("sh({inner})"),
        Wrapper::ShWsh => format!("sh(wsh({inner}))"),
    };
    let normalized = descriptor_audit::normalize_slip132(&body)?;
    descriptor_audit::compute_checksum(normalized.descriptor())
}

/// Decode a Jade `fingerprint` (hex string or 4-byte array) to 8 lowercase hex.
fn fingerprint_hex(value: &Value) -> Result<String, LifeboatError> {
    match value {
        Value::String(s) => {
            let s = s.trim();
            if s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(s.to_lowercase())
            } else {
                Err(invalid("Jade signer fingerprint is not 8 hex characters"))
            }
        }
        Value::Array(items) if items.len() == 4 => {
            let mut hex = String::with_capacity(8);
            for item in items {
                let byte = item
                    .as_u64()
                    .filter(|n| *n <= 0xff)
                    .ok_or_else(|| invalid("Jade signer fingerprint has a non-byte element"))?;
                hex.push_str(&format!("{byte:02x}"));
            }
            Ok(hex)
        }
        _ => Err(invalid(
            "Jade signer fingerprint is neither hex string nor 4 bytes",
        )),
    }
}

/// Decode a Jade origin `derivation` (path string or index array) to the path used
/// inside `[fingerprint/path]` (no leading `m/`; hardened markers as `'`).
fn origin_path(value: &Value) -> Result<String, LifeboatError> {
    match value {
        Value::String(s) => Ok(strip_master_prefix(s).to_string()),
        Value::Array(items) => {
            let segs: Vec<String> = items
                .iter()
                .map(|item| {
                    item.as_u64()
                        .filter(|n| *n <= u64::from(u32::MAX))
                        .map(|n| index_segment(n as u32))
                        .ok_or_else(|| invalid("Jade derivation has a non-u32 index"))
                })
                .collect::<Result<_, _>>()?;
            Ok(segs.join("/"))
        }
        _ => Err(invalid(
            "Jade signer derivation is neither path string nor index array",
        )),
    }
}

/// Decode a Jade xpub-suffix `path` (path string or index array) to a leading-`/`
/// suffix, or empty. Hardened indices are rejected (an xpub has no hardened children).
fn suffix_path(value: &Value) -> Result<String, LifeboatError> {
    match value {
        Value::Null => Ok(String::new()),
        Value::String(s) => {
            let s = s.trim().trim_start_matches('/');
            if s.is_empty() {
                Ok(String::new())
            } else {
                Ok(format!("/{s}"))
            }
        }
        Value::Array(items) => {
            let mut suffix = String::new();
            for item in items {
                let n = item
                    .as_u64()
                    .filter(|n| *n <= u64::from(u32::MAX))
                    .ok_or_else(|| invalid("Jade signer path has a non-u32 index"))?;
                if n >= 0x8000_0000 {
                    return Err(invalid("Jade signer path cannot contain hardened indices"));
                }
                suffix.push('/');
                suffix.push_str(&n.to_string());
            }
            Ok(suffix)
        }
        _ => Err(invalid(
            "Jade signer path is neither path string nor index array",
        )),
    }
}

/// Format a BIP32 index as a path segment, marking hardened indices (≥ 2³¹) with `'`.
fn index_segment(n: u32) -> String {
    if n >= 0x8000_0000 {
        format!("{}'", n - 0x8000_0000)
    } else {
        n.to_string()
    }
}

/// Build an `E-INPUT-003` with a safe, content-free context message.
fn invalid(context: &'static str) -> LifeboatError {
    LifeboatError::new(ErrorCode::InputInvalidFormat).with_context(context)
}
