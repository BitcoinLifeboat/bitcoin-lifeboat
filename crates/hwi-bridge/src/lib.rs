//! `hwi-bridge` - subprocess-only access to the bundled HWI sidecar.
//!
//! Lifeboat never links USB/HID hardware-wallet drivers into the Tauri process.
//! This crate invokes the HWI 3.2+ sidecar as a child process, bounds the wait,
//! and returns typed, leak-free errors. Packaging supplies the sidecar binary via
//! Tauri's `bundle.externalBin`; tests use fake executables so CI does not need a
//! hardware wallet or Python.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use error_taxonomy::{ErrorCode, LifeboatError};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// Tauri `bundle.externalBin` entry for the HWI sidecar.
pub const HWI_TAURI_EXTERNAL_BIN: &str = "binaries/hwi-lifeboat";

/// Sidecar executable stem after Tauri resolves the target-specific suffix.
pub const HWI_SIDECAR_STEM: &str = "hwi-lifeboat";

/// Minimum HWI major/minor version accepted by this bridge.
pub const MIN_HWI_VERSION: HwiVersion = HwiVersion {
    major: 3,
    minor: 2,
    patch: 0,
};

/// Environment variable used by tests and developer builds to override the
/// sidecar path.
pub const HWI_SIDECAR_ENV: &str = "LIFEBOAT_HWI_SIDECAR";

/// Default sidecar timeout. HWI operations are interactive, but the bridge must
/// never leave a stuck child process running forever.
pub const DEFAULT_HWI_TIMEOUT: Duration = Duration::from_secs(30);

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Parsed semantic version from `hwi --version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HwiVersion {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
}

impl HwiVersion {
    /// Parse the first `MAJOR.MINOR[.PATCH]` sequence in a version string.
    #[must_use]
    pub fn parse_from_text(text: &str) -> Option<Self> {
        text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .filter(|part| part.contains('.'))
            .find_map(Self::parse_segment)
    }

    fn parse_segment(segment: &str) -> Option<Self> {
        let mut parts = segment.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().map(str::parse).transpose().ok()?.unwrap_or(0);
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for HwiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Successful HWI subprocess output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HwiOutput {
    /// Process exit code. Signals appear as `None` on Unix.
    pub status_code: Option<i32>,
    /// UTF-8 stdout from HWI. Callers must treat this as confidential metadata.
    pub stdout: String,
    /// UTF-8 stderr from HWI. It is returned only on successful process exit.
    pub stderr: String,
}

/// Hardware-wallet families supported through the HWI sidecar in v0.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HwiDeviceKind {
    /// Ledger Nano devices through the Bitcoin app.
    #[serde(rename = "ledger")]
    Ledger,
    /// Trezor One, Model T, and Safe devices.
    #[serde(rename = "trezor")]
    Trezor,
    /// Shift Crypto BitBox02.
    #[serde(rename = "bitbox02")]
    BitBox02,
    /// Coldcard over USB / virtual disk workflows exposed by HWI.
    #[serde(rename = "coldcard")]
    Coldcard,
}

impl HwiDeviceKind {
    /// HWI's `--device-type` argument for this device family.
    #[must_use]
    pub const fn as_hwi_arg(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Trezor => "trezor",
            Self::BitBox02 => "bitbox02",
            Self::Coldcard => "coldcard",
        }
    }

    fn from_hwi_type(device_type: &str) -> Option<Self> {
        match device_type.trim().to_ascii_lowercase().as_str() {
            "ledger" => Some(Self::Ledger),
            "trezor" => Some(Self::Trezor),
            "bitbox02" | "digitalbitbox" => Some(Self::BitBox02),
            "coldcard" => Some(Self::Coldcard),
            _ => None,
        }
    }
}

/// Bitcoin network argument accepted by HWI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HwiChain {
    /// Bitcoin mainnet (`--chain main`).
    #[serde(rename = "main")]
    Main,
    /// Bitcoin testnet (`--chain test`).
    #[serde(rename = "test")]
    Test,
    /// Bitcoin regtest (`--chain regtest`).
    #[serde(rename = "regtest")]
    Regtest,
    /// Bitcoin Signet (`--chain signet`).
    #[serde(rename = "signet")]
    Signet,
    /// Bitcoin testnet4 (`--chain testnet4`).
    #[serde(rename = "testnet4")]
    Testnet4,
}

impl HwiChain {
    #[must_use]
    pub const fn as_hwi_arg(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Test => "test",
            Self::Regtest => "regtest",
            Self::Signet => "signet",
            Self::Testnet4 => "testnet4",
        }
    }
}

/// Stable non-fatal warning codes surfaced by hardware-wallet checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HwiWarningCode {
    /// `W-DEVICE-FIRMWARE-UNSUPPORTED` — HWI detected a device whose firmware
    /// cannot be used by the bundled sidecar.
    #[serde(rename = "W-DEVICE-FIRMWARE-UNSUPPORTED")]
    DeviceFirmwareUnsupported,
}

impl HwiWarningCode {
    /// Stable warning-code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceFirmwareUnsupported => "W-DEVICE-FIRMWARE-UNSUPPORTED",
        }
    }
}

/// A non-fatal HWI warning that can be shown in a drill result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiWarning {
    /// Stable warning code.
    pub code: HwiWarningCode,
    /// Short label.
    pub title: String,
    /// Secret-free explanation.
    pub description: String,
    /// What the user should do next.
    pub recommended_action: String,
}

impl HwiWarning {
    fn firmware_unsupported(detail: &str) -> Self {
        Self {
            code: HwiWarningCode::DeviceFirmwareUnsupported,
            title: "Device firmware unsupported".to_owned(),
            description: format!("HWI reported unsupported firmware: {detail}"),
            recommended_action:
                "Update the device firmware or use file/QR PSBT exchange for this drill.".to_owned(),
        }
    }
}

/// One device returned by `hwi enumerate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiDevice {
    /// Raw HWI type string, e.g. `"ledger"` or `"trezor"`.
    pub device_type: String,
    /// Lifeboat-supported device family, if this HWI type is in scope.
    pub supported_kind: Option<HwiDeviceKind>,
    /// HWI model string, when supplied.
    pub model: Option<String>,
    /// HWI device path, when supplied. This is passed back as `--device-path`.
    pub path: Option<String>,
    /// Master fingerprint normalized to 8 lowercase hex characters.
    pub fingerprint: Option<String>,
    /// Whether HWI needs a PIN sent before commands can continue.
    pub needs_pin_sent: bool,
    /// Whether HWI needs a passphrase sent before commands can continue.
    pub needs_passphrase_sent: bool,
    /// Secret-free status or error text HWI attached to this enumerate row.
    pub status_message: Option<String>,
    /// Non-fatal warnings derived from the enumerate row.
    pub warnings: Vec<HwiWarning>,
}

impl HwiDevice {
    /// True for Ledger, Trezor, BitBox02, and Coldcard device families.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.supported_kind.is_some()
    }
}

/// Request to read one xpub from a hardware device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiXpubRequest {
    /// Expected master fingerprint used by HWI to select the device.
    pub fingerprint: String,
    /// BIP32 derivation path to read, e.g. `m/84h/1h/0h`.
    pub derivation_path: String,
    /// Optional HWI chain argument. Omit to use HWI's default.
    #[serde(default)]
    pub chain: Option<HwiChain>,
    /// Optional narrowed HWI device type.
    #[serde(default)]
    pub device_type: Option<HwiDeviceKind>,
    /// Optional HWI device path from [`HwiDevice::path`].
    #[serde(default)]
    pub device_path: Option<String>,
}

/// One xpub read from HWI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiDerivedXpub {
    /// Normalized master fingerprint used to select the device.
    pub fingerprint: String,
    /// Normalized derivation path requested.
    pub derivation_path: String,
    /// Xpub returned by HWI. This is Confidential wallet metadata.
    pub xpub: String,
}

/// Request to sign one PSBT through a selected HWI device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiSignPsbtRequest {
    /// Fingerprint used by HWI to select the signing device.
    pub fingerprint: String,
    /// Base64 PSBT to pass to `hwi signtx`. This is Confidential wallet metadata.
    pub psbt_base64: String,
    /// Optional HWI chain argument. Omit to use HWI's default.
    #[serde(default)]
    pub chain: Option<HwiChain>,
    /// Optional narrowed HWI device type.
    #[serde(default)]
    pub device_type: Option<HwiDeviceKind>,
    /// Optional HWI device path from [`HwiDevice::path`].
    #[serde(default)]
    pub device_path: Option<String>,
}

/// Signed PSBT returned by HWI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiSignedPsbt {
    /// Normalized master fingerprint used to select the device.
    pub fingerprint: String,
    /// Signed PSBT returned by HWI. This is Confidential wallet metadata.
    pub psbt_base64: String,
}

/// Descriptor-side key material expected from one hardware signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedHwiKey {
    /// Optional caller label, such as `Signer A`.
    #[serde(default)]
    pub label: Option<String>,
    /// Expected master fingerprint from the descriptor key origin.
    pub fingerprint: String,
    /// Expected derivation path from the descriptor key origin.
    pub derivation_path: String,
    /// Expected descriptor xpub. When absent, verification is fingerprint-only.
    #[serde(default)]
    pub xpub: Option<String>,
    /// Optional HWI chain argument for reading the xpub.
    #[serde(default)]
    pub chain: Option<HwiChain>,
}

/// Result status for one descriptor-key/device check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HwiVerificationStatus {
    /// A supported device with the expected fingerprint was present, and the xpub
    /// matched when the caller supplied one.
    #[serde(rename = "matched")]
    Matched,
    /// HWI returned no devices.
    #[serde(rename = "device_missing")]
    DeviceMissing,
    /// Devices were present, but none had the expected master fingerprint.
    #[serde(rename = "fingerprint_mismatch")]
    FingerprintMismatch,
    /// The fingerprint matched, but the HWI type is not one of v0.4's supported
    /// device families.
    #[serde(rename = "unsupported_device")]
    UnsupportedDevice,
    /// HWI reported unsupported device firmware.
    #[serde(rename = "firmware_unsupported")]
    FirmwareUnsupported,
    /// The fingerprint matched, but the xpub read from HWI differed from the
    /// descriptor's xpub.
    #[serde(rename = "xpub_mismatch")]
    XpubMismatch,
}

/// Verification result for one expected descriptor key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwiVerificationResult {
    /// Optional caller label, such as `Signer A`.
    pub expected_label: Option<String>,
    /// Expected master fingerprint, normalized to lowercase hex.
    pub expected_fingerprint: String,
    /// Expected derivation path.
    pub expected_derivation_path: String,
    /// Final verification status.
    pub status: HwiVerificationStatus,
    /// Whether a connected device had the expected fingerprint.
    pub fingerprint_matches: bool,
    /// Whether the read xpub matched the descriptor xpub. `None` when no xpub was
    /// supplied or no xpub read was attempted.
    pub xpub_matches: Option<bool>,
    /// Matching device, when one was found.
    pub device: Option<HwiDevice>,
    /// Connected device fingerprints observed during the check.
    pub observed_fingerprints: Vec<String>,
    /// Non-fatal warnings for the matching device/check.
    pub warnings: Vec<HwiWarning>,
}

#[derive(Debug, Deserialize)]
struct RawHwiDevice {
    #[serde(rename = "type")]
    device_type: Option<String>,
    model: Option<String>,
    path: Option<String>,
    fingerprint: Option<String>,
    #[serde(default)]
    needs_pin_sent: bool,
    #[serde(default)]
    needs_passphrase_sent: bool,
    error: Option<String>,
}

impl From<RawHwiDevice> for HwiDevice {
    fn from(raw: RawHwiDevice) -> Self {
        let device_type = raw.device_type.unwrap_or_else(|| "unknown".to_owned());
        let supported_kind = HwiDeviceKind::from_hwi_type(&device_type);
        let fingerprint = raw.fingerprint.as_deref().and_then(canonical_fingerprint);
        let warnings = raw
            .error
            .as_deref()
            .and_then(firmware_warning)
            .into_iter()
            .collect::<Vec<_>>();

        Self {
            device_type,
            supported_kind,
            model: raw.model,
            path: raw.path,
            fingerprint,
            needs_pin_sent: raw.needs_pin_sent,
            needs_passphrase_sent: raw.needs_passphrase_sent,
            status_message: raw.error,
            warnings,
        }
    }
}

/// Subprocess-only HWI sidecar bridge.
#[derive(Debug, Clone)]
pub struct HwiSidecar {
    executable: PathBuf,
    timeout: Duration,
}

impl HwiSidecar {
    /// Use exactly this sidecar executable path or program name.
    #[must_use]
    pub fn with_executable(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            timeout: DEFAULT_HWI_TIMEOUT,
        }
    }

    /// Resolve the sidecar path from environment, next-to-exe, then `PATH`.
    #[must_use]
    pub fn auto() -> Self {
        if let Some(path) = std::env::var_os(HWI_SIDECAR_ENV) {
            let candidate = PathBuf::from(path);
            if candidate.is_file() {
                return Self::with_executable(candidate);
            }
        }

        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join(sidecar_exe_name());
                if candidate.is_file() {
                    return Self::with_executable(candidate);
                }
            }
        }

        Self::with_executable(sidecar_exe_name())
    }

    /// Override the subprocess wait timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Return the executable this bridge will invoke.
    #[must_use]
    pub fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    /// Invoke HWI with bounded subprocess execution.
    ///
    /// # Errors
    /// - [`ErrorCode::HwiNotAvailable`] (`E-DEP-002`) when the sidecar is
    ///   missing or cannot be executed.
    /// - [`ErrorCode::Internal`] when HWI exits non-zero, hangs, or returns
    ///   non-UTF-8 output.
    pub fn invoke<I, S>(&self, args: I) -> Result<HwiOutput, LifeboatError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect::<Vec<_>>();
        self.invoke_args(&args)
    }

    /// Run `hwi --version` and require HWI 3.2+.
    pub fn require_supported_version(&self) -> Result<HwiVersion, LifeboatError> {
        let output = self.invoke(["--version"])?;
        let version = HwiVersion::parse_from_text(&output.stdout).ok_or_else(|| {
            LifeboatError::new(ErrorCode::HwiNotAvailable)
                .with_context("HWI sidecar did not report a parseable version")
        })?;
        if version < MIN_HWI_VERSION {
            return Err(LifeboatError::new(ErrorCode::HwiNotAvailable)
                .with_context("HWI sidecar is older than the required 3.2.0"));
        }
        Ok(version)
    }

    /// Run `hwi enumerate` and return normalized Ledger/Trezor/BitBox02/Coldcard
    /// metadata plus any non-fatal firmware warnings.
    pub fn enumerate_devices(&self) -> Result<Vec<HwiDevice>, LifeboatError> {
        let output = self.invoke(["enumerate"])?;
        let value = parse_hwi_json::<Value>(&output.stdout, "HWI enumerate")?;
        if let Some(error) = hwi_json_error_message(&value) {
            return Err(hwi_json_error("HWI enumerate returned an error", error));
        }
        let raw = serde_json::from_value::<Vec<RawHwiDevice>>(value).map_err(|err| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("HWI enumerate did not return a device array")
                .with_source(err)
        })?;
        Ok(raw.into_iter().map(HwiDevice::from).collect())
    }

    /// Run `hwi getxpub <path>` for a selected hardware device.
    pub fn get_xpub(&self, request: &HwiXpubRequest) -> Result<HwiDerivedXpub, LifeboatError> {
        let fingerprint = normalize_fingerprint(&request.fingerprint)?;
        let derivation_path = normalize_derivation_path(&request.derivation_path)?;

        let mut args = Vec::new();
        if let Some(chain) = request.chain {
            args.push(OsString::from("--chain"));
            args.push(OsString::from(chain.as_hwi_arg()));
        }
        args.push(OsString::from("--fingerprint"));
        args.push(OsString::from(&fingerprint));
        if let Some(device_type) = request.device_type {
            args.push(OsString::from("--device-type"));
            args.push(OsString::from(device_type.as_hwi_arg()));
        }
        if let Some(device_path) = normalized_optional(&request.device_path) {
            args.push(OsString::from("--device-path"));
            args.push(OsString::from(device_path));
        }
        args.push(OsString::from("getxpub"));
        args.push(OsString::from(&derivation_path));

        let output = self.invoke_args(&args)?;
        let value = parse_hwi_json::<Value>(&output.stdout, "HWI getxpub")?;
        if let Some(error) = hwi_json_error_message(&value) {
            return Err(hwi_json_error("HWI getxpub returned an error", error));
        }
        let xpub = extract_xpub(&value)?;

        Ok(HwiDerivedXpub {
            fingerprint,
            derivation_path,
            xpub,
        })
    }

    /// Run `hwi signtx <psbt>` for a selected hardware device and return the
    /// signed PSBT string HWI emits.
    pub fn sign_psbt(&self, request: &HwiSignPsbtRequest) -> Result<HwiSignedPsbt, LifeboatError> {
        let fingerprint = normalize_fingerprint(&request.fingerprint)?;
        let psbt_base64 = request.psbt_base64.trim();
        if psbt_base64.is_empty() {
            return Err(LifeboatError::new(ErrorCode::InputEmpty)
                .with_context("HWI signing requires a PSBT"));
        }

        let mut args = Vec::new();
        if let Some(chain) = request.chain {
            args.push(OsString::from("--chain"));
            args.push(OsString::from(chain.as_hwi_arg()));
        }
        args.push(OsString::from("--fingerprint"));
        args.push(OsString::from(&fingerprint));
        if let Some(device_type) = request.device_type {
            args.push(OsString::from("--device-type"));
            args.push(OsString::from(device_type.as_hwi_arg()));
        }
        if let Some(device_path) = normalized_optional(&request.device_path) {
            args.push(OsString::from("--device-path"));
            args.push(OsString::from(device_path));
        }
        args.push(OsString::from("signtx"));
        args.push(OsString::from(psbt_base64));

        let output = self.invoke_args(&args)?;
        let value = parse_hwi_json::<Value>(&output.stdout, "HWI signtx")?;
        if let Some(error) = hwi_json_error_message(&value) {
            return Err(hwi_json_error("HWI signtx returned an error", error));
        }
        let signed = extract_psbt(&value)?;

        Ok(HwiSignedPsbt {
            fingerprint,
            psbt_base64: signed,
        })
    }

    /// Verify descriptor key origins against connected hardware devices by
    /// matching fingerprints, reading each expected xpub path, and comparing the
    /// returned xpub when the caller provides one.
    pub fn verify_expected_xpubs(
        &self,
        expected_keys: &[ExpectedHwiKey],
    ) -> Result<Vec<HwiVerificationResult>, LifeboatError> {
        let devices = self.enumerate_devices()?;
        expected_keys
            .iter()
            .map(|expected| self.verify_expected_xpub(expected, &devices))
            .collect()
    }

    fn invoke_args(&self, args: &[OsString]) -> Result<HwiOutput, LifeboatError> {
        let child = spawn_with_retry(&self.executable, args)?;

        let output = wait_with_output_timeout(child, self.timeout)?;
        decode_output(output)
    }

    fn verify_expected_xpub(
        &self,
        expected: &ExpectedHwiKey,
        devices: &[HwiDevice],
    ) -> Result<HwiVerificationResult, LifeboatError> {
        let expected_fingerprint = normalize_fingerprint(&expected.fingerprint)?;
        let expected_derivation_path = normalize_derivation_path(&expected.derivation_path)?;
        let observed_fingerprints = devices
            .iter()
            .filter_map(|device| device.fingerprint.clone())
            .collect::<Vec<_>>();

        if devices.is_empty() {
            return Ok(HwiVerificationResult {
                expected_label: expected.label.clone(),
                expected_fingerprint,
                expected_derivation_path,
                status: HwiVerificationStatus::DeviceMissing,
                fingerprint_matches: false,
                xpub_matches: None,
                device: None,
                observed_fingerprints,
                warnings: Vec::new(),
            });
        }

        let Some(device) = devices
            .iter()
            .find(|device| device.fingerprint.as_deref() == Some(expected_fingerprint.as_str()))
        else {
            return Ok(HwiVerificationResult {
                expected_label: expected.label.clone(),
                expected_fingerprint,
                expected_derivation_path,
                status: HwiVerificationStatus::FingerprintMismatch,
                fingerprint_matches: false,
                xpub_matches: None,
                device: None,
                observed_fingerprints,
                warnings: Vec::new(),
            });
        };

        let warnings = device.warnings.clone();
        if warnings
            .iter()
            .any(|warning| warning.code == HwiWarningCode::DeviceFirmwareUnsupported)
        {
            return Ok(HwiVerificationResult {
                expected_label: expected.label.clone(),
                expected_fingerprint,
                expected_derivation_path,
                status: HwiVerificationStatus::FirmwareUnsupported,
                fingerprint_matches: true,
                xpub_matches: None,
                device: Some(device.clone()),
                observed_fingerprints,
                warnings,
            });
        }

        let Some(device_type) = device.supported_kind else {
            return Ok(HwiVerificationResult {
                expected_label: expected.label.clone(),
                expected_fingerprint,
                expected_derivation_path,
                status: HwiVerificationStatus::UnsupportedDevice,
                fingerprint_matches: true,
                xpub_matches: None,
                device: Some(device.clone()),
                observed_fingerprints,
                warnings,
            });
        };

        let request = HwiXpubRequest {
            fingerprint: expected_fingerprint.clone(),
            derivation_path: expected_derivation_path.clone(),
            chain: expected.chain,
            device_type: Some(device_type),
            device_path: device.path.clone(),
        };
        let derived = match self.get_xpub(&request) {
            Ok(derived) => derived,
            Err(err) if is_unsupported_firmware_error(&err) => {
                let mut warnings = warnings;
                warnings.push(HwiWarning::firmware_unsupported(
                    "HWI getxpub returned unsupported device firmware",
                ));
                return Ok(HwiVerificationResult {
                    expected_label: expected.label.clone(),
                    expected_fingerprint,
                    expected_derivation_path,
                    status: HwiVerificationStatus::FirmwareUnsupported,
                    fingerprint_matches: true,
                    xpub_matches: None,
                    device: Some(device.clone()),
                    observed_fingerprints,
                    warnings,
                });
            }
            Err(err) => return Err(err),
        };
        let xpub_matches = expected
            .xpub
            .as_deref()
            .map(|expected_xpub| expected_xpub.trim() == derived.xpub);
        let status = if xpub_matches == Some(false) {
            HwiVerificationStatus::XpubMismatch
        } else {
            HwiVerificationStatus::Matched
        };

        Ok(HwiVerificationResult {
            expected_label: expected.label.clone(),
            expected_fingerprint,
            expected_derivation_path,
            status,
            fingerprint_matches: true,
            xpub_matches,
            device: Some(device.clone()),
            observed_fingerprints,
            warnings,
        })
    }
}

impl Default for HwiSidecar {
    fn default() -> Self {
        Self::auto()
    }
}

fn sidecar_exe_name() -> &'static str {
    if cfg!(windows) {
        "hwi-lifeboat.exe"
    } else {
        HWI_SIDECAR_STEM
    }
}

fn map_spawn_error(err: std::io::Error) -> LifeboatError {
    match err.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            LifeboatError::new(ErrorCode::HwiNotAvailable)
                .with_context("the configured HWI sidecar binary is not executable")
                .with_source(err)
        }
        _ => LifeboatError::new(ErrorCode::Internal)
            .with_context("failed to spawn the HWI sidecar subprocess")
            .with_source(err),
    }
}

fn spawn_with_retry(
    executable: &std::path::Path,
    args: &[OsString],
) -> Result<Child, LifeboatError> {
    let mut attempts = 0;
    loop {
        match Command::new(executable)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => return Ok(child),
            Err(err) if executable_file_busy(&err) && attempts < 5 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(map_spawn_error(err)),
        }
    }
}

#[cfg(unix)]
fn executable_file_busy(err: &std::io::Error) -> bool {
    // ETXTBSY. `ErrorKind::ExecutableFileBusy` is still unstable on Rust 1.78.
    err.raw_os_error() == Some(26)
}

#[cfg(not(unix))]
fn executable_file_busy(_err: &std::io::Error) -> bool {
    false
}

fn wait_with_output_timeout(mut child: Child, timeout: Duration) -> Result<Output, LifeboatError> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output().map_err(|err| {
                    LifeboatError::new(ErrorCode::Internal)
                        .with_context("failed to collect HWI sidecar output")
                        .with_source(err)
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(LifeboatError::new(ErrorCode::Internal)
                        .with_context("HWI sidecar subprocess exceeded its timeout"));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LifeboatError::new(ErrorCode::Internal)
                    .with_context("failed while waiting on the HWI sidecar subprocess")
                    .with_source(err));
            }
        }
    }
}

fn decode_output(output: Output) -> Result<HwiOutput, LifeboatError> {
    if !output.status.success() {
        return Err(
            LifeboatError::new(ErrorCode::Internal).with_context(format!(
                "HWI sidecar subprocess exited with status {}",
                format_status(output.status)
            )),
        );
    }

    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("HWI sidecar stdout was not UTF-8")
            .with_source(err)
    })?;
    let stderr = String::from_utf8(output.stderr).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("HWI sidecar stderr was not UTF-8")
            .with_source(err)
    })?;

    Ok(HwiOutput {
        status_code: output.status.code(),
        stdout,
        stderr,
    })
}

fn format_status(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "terminated by signal".to_owned())
}

fn parse_hwi_json<T>(stdout: &str, context: &str) -> Result<T, LifeboatError>
where
    T: DeserializeOwned,
{
    serde_json::from_str(stdout).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context(format!("{context} did not return valid JSON"))
            .with_source(err)
    })
}

fn hwi_json_error_message(value: &Value) -> Option<&str> {
    value.get("error").and_then(Value::as_str)
}

fn hwi_json_error(context: &str, error: &str) -> LifeboatError {
    if is_unsupported_firmware_message(error) {
        return LifeboatError::new(ErrorCode::Internal)
            .with_context(format!("{context}: unsupported device firmware"));
    }
    LifeboatError::new(ErrorCode::Internal).with_context(format!("{context}: {error}"))
}

fn extract_xpub(value: &Value) -> Result<String, LifeboatError> {
    let xpub = value
        .get("xpub")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
        .map(str::trim)
        .filter(|xpub| !xpub.is_empty())
        .ok_or_else(|| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("HWI getxpub response did not include an xpub")
        })?;
    Ok(xpub.to_owned())
}

fn extract_psbt(value: &Value) -> Result<String, LifeboatError> {
    let psbt = value
        .get("psbt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|psbt| !psbt.is_empty())
        .ok_or_else(|| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("HWI signtx response did not include a PSBT")
        })?;
    Ok(psbt.to_owned())
}

fn normalize_fingerprint(fingerprint: &str) -> Result<String, LifeboatError> {
    canonical_fingerprint(fingerprint).ok_or_else(|| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("hardware-wallet fingerprint must be 8 hex characters")
    })
}

fn canonical_fingerprint(fingerprint: &str) -> Option<String> {
    let trimmed = fingerprint.trim();
    if trimmed.len() == 8 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

fn normalize_derivation_path(path: &str) -> Result<String, LifeboatError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(LifeboatError::new(ErrorCode::InputEmpty)
            .with_context("hardware-wallet derivation path was not provided"));
    }
    if !trimmed.starts_with('m') || trimmed.chars().any(char::is_whitespace) {
        return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("hardware-wallet derivation path must be an absolute BIP32 path"));
    }
    Ok(trimmed.to_owned())
}

fn normalized_optional(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn firmware_warning(message: &str) -> Option<HwiWarning> {
    if is_unsupported_firmware_message(message) {
        Some(HwiWarning::firmware_unsupported(message))
    } else {
        None
    }
}

fn is_unsupported_firmware_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("unsupported") && lower.contains("firmware")
}

fn is_unsupported_firmware_error(err: &LifeboatError) -> bool {
    matches!(
        err.context(),
        Some(context) if is_unsupported_firmware_message(context)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    fn unique_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lifeboat-hwi-bridge-{tag}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_fake_sidecar(dir: &std::path::Path, body: &str) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(format!(
            "fake-hwi-{}.sh",
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn parses_hwi_version_from_cli_output() {
        assert_eq!(
            HwiVersion::parse_from_text("hwi 3.2.1\n"),
            Some(HwiVersion {
                major: 3,
                minor: 2,
                patch: 1
            })
        );
        assert_eq!(
            HwiVersion::parse_from_text("HWI version 3.2"),
            Some(HwiVersion {
                major: 3,
                minor: 2,
                patch: 0
            })
        );
        assert_eq!(HwiVersion::parse_from_text("not a version"), None);
    }

    #[test]
    fn missing_sidecar_is_e_dep_002() {
        let err = HwiSidecar::with_executable("/nonexistent/lifeboat-hwi-sidecar")
            .invoke(["--version"])
            .expect_err("missing sidecar must be typed");
        assert_eq!(err.code(), ErrorCode::HwiNotAvailable);
    }

    #[cfg(unix)]
    #[test]
    fn invokes_sidecar_as_subprocess() {
        let dir = unique_test_dir("invoke");
        let log = dir.join("argv.txt");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'hwi 3.2.0\\n'\n",
            log.display()
        );
        let fake = write_fake_sidecar(&dir, &script);

        let output = HwiSidecar::with_executable(fake)
            .invoke(["--device-type", "trezor", "enumerate"])
            .expect("fake sidecar succeeds");

        assert_eq!(output.stdout, "hwi 3.2.0\n");
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "--device-type\ntrezor\nenumerate\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn enumerates_supported_hwi_device_families() {
        let dir = unique_test_dir("enumerate");
        let fake = write_fake_sidecar(
            &dir,
            r#"#!/bin/sh
cat <<'JSON'
[
  {"type":"ledger","model":"ledger_nano_s_plus","path":"ledger-path","fingerprint":"A1B2C3D4","needs_pin_sent":false,"needs_passphrase_sent":true},
  {"type":"trezor","model":"trezor_safe_5","path":"trezor-path","fingerprint":"11112222"},
  {"type":"bitbox02","model":"bitbox02","path":"bitbox-path","fingerprint":"33334444"},
  {"type":"coldcard","model":"coldcard","path":"coldcard-path","fingerprint":"55556666"},
  {"type":"keepkey","model":"keepkey","path":"keepkey-path","fingerprint":"77778888"}
]
JSON
"#,
        );

        let devices = HwiSidecar::with_executable(fake)
            .enumerate_devices()
            .expect("fake enumerate succeeds");

        assert_eq!(devices.len(), 5);
        assert_eq!(devices[0].supported_kind, Some(HwiDeviceKind::Ledger));
        assert_eq!(devices[0].fingerprint.as_deref(), Some("a1b2c3d4"));
        assert!(devices[0].needs_passphrase_sent);
        assert_eq!(devices[1].supported_kind, Some(HwiDeviceKind::Trezor));
        assert_eq!(devices[2].supported_kind, Some(HwiDeviceKind::BitBox02));
        assert_eq!(devices[3].supported_kind, Some(HwiDeviceKind::Coldcard));
        assert_eq!(devices[4].supported_kind, None);
        assert!(!devices[4].is_supported());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn get_xpub_uses_hwi_selector_arguments() {
        let dir = unique_test_dir("get-xpub");
        let log = dir.join("argv.txt");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '{{\"xpub\":\"tpub-from-device\"}}\\n'\n",
            log.display()
        );
        let fake = write_fake_sidecar(&dir, &script);

        let derived = HwiSidecar::with_executable(fake)
            .get_xpub(&HwiXpubRequest {
                fingerprint: "A1B2C3D4".to_owned(),
                derivation_path: "m/84h/1h/0h".to_owned(),
                chain: Some(HwiChain::Signet),
                device_type: Some(HwiDeviceKind::Ledger),
                device_path: Some("ledger-path".to_owned()),
            })
            .expect("fake getxpub succeeds");

        assert_eq!(derived.fingerprint, "a1b2c3d4");
        assert_eq!(derived.derivation_path, "m/84h/1h/0h");
        assert_eq!(derived.xpub, "tpub-from-device");
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "--chain\nsignet\n--fingerprint\na1b2c3d4\n--device-type\nledger\n--device-path\nledger-path\ngetxpub\nm/84h/1h/0h\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sign_psbt_uses_hwi_signtx_selector_arguments() {
        let dir = unique_test_dir("sign-psbt");
        let log = dir.join("argv.txt");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '{{\"psbt\":\"cHNidP8signed\"}}\\n'\n",
            log.display()
        );
        let fake = write_fake_sidecar(&dir, &script);

        let signed = HwiSidecar::with_executable(fake)
            .sign_psbt(&HwiSignPsbtRequest {
                fingerprint: "A1B2C3D4".to_owned(),
                psbt_base64: "cHNidP8unsigned".to_owned(),
                chain: Some(HwiChain::Test),
                device_type: Some(HwiDeviceKind::Trezor),
                device_path: Some("trezor-path".to_owned()),
            })
            .expect("fake signtx succeeds");

        assert_eq!(signed.fingerprint, "a1b2c3d4");
        assert_eq!(signed.psbt_base64, "cHNidP8signed");
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "--chain\ntest\n--fingerprint\na1b2c3d4\n--device-type\ntrezor\n--device-path\ntrezor-path\nsigntx\ncHNidP8unsigned\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn hwi_emulator_smoke(kind: HwiDeviceKind, device_type: &str, tag: &str) {
        let dir = unique_test_dir(tag);
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "enumerate" ]; then
  cat <<'JSON'
[
  {{"type":"{device_type}","model":"{tag}-simulator","path":"{tag}-path","fingerprint":"A1B2C3D4"}}
]
JSON
  exit 0
fi
case "$*" in
  *"getxpub"*) printf '{{"xpub":"tpub-{tag}"}}\n' ;;
  *"signtx"*) printf '{{"psbt":"cHNidP8{tag}Signed"}}\n' ;;
  *) printf '{{"error":"unexpected fake HWI command"}}\n' ;;
esac
"#
        );
        let fake = write_fake_sidecar(&dir, &script);
        let sidecar = HwiSidecar::with_executable(fake);
        let devices = sidecar
            .enumerate_devices()
            .expect("simulated HWI enumerate succeeds");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].supported_kind, Some(kind));

        let derived = sidecar
            .get_xpub(&HwiXpubRequest {
                fingerprint: "a1b2c3d4".to_owned(),
                derivation_path: "m/84h/1h/0h".to_owned(),
                chain: Some(HwiChain::Test),
                device_type: Some(kind),
                device_path: Some(format!("{tag}-path")),
            })
            .expect("simulated HWI getxpub succeeds");
        assert_eq!(derived.xpub, format!("tpub-{tag}"));

        let signed = sidecar
            .sign_psbt(&HwiSignPsbtRequest {
                fingerprint: "a1b2c3d4".to_owned(),
                psbt_base64: "cHNidP8unsigned".to_owned(),
                chain: Some(HwiChain::Test),
                device_type: Some(kind),
                device_path: Some(format!("{tag}-path")),
            })
            .expect("simulated HWI signtx succeeds");
        assert_eq!(signed.psbt_base64, format!("cHNidP8{tag}Signed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn hwi_emulator_smoke_trezor() {
        hwi_emulator_smoke(HwiDeviceKind::Trezor, "trezor", "trezor");
    }

    #[cfg(unix)]
    #[test]
    fn hwi_emulator_smoke_coldcard() {
        hwi_emulator_smoke(HwiDeviceKind::Coldcard, "coldcard", "coldcard");
    }

    #[cfg(unix)]
    #[test]
    fn hwi_emulator_smoke_bitbox02() {
        hwi_emulator_smoke(HwiDeviceKind::BitBox02, "bitbox02", "bitbox02");
    }

    #[cfg(unix)]
    #[test]
    fn verifies_fingerprint_and_xpub_match_mismatch_cases() {
        let dir = unique_test_dir("verify");
        let fake = write_fake_sidecar(
            &dir,
            r#"#!/bin/sh
if [ "$1" = "enumerate" ]; then
  cat <<'JSON'
[
  {"type":"ledger","model":"ledger","path":"ledger-path","fingerprint":"4BA43603"},
  {"type":"trezor","model":"trezor","path":"trezor-path","fingerprint":"6e37edb9"}
]
JSON
  exit 0
fi
case "$*" in
  *"--fingerprint 4ba43603"*) printf '{"xpub":"tpub-match"}\n' ;;
  *"--fingerprint 6e37edb9"*) printf '{"xpub":"tpub-other"}\n' ;;
  *) printf '{"error":"unexpected fake HWI selector"}\n' ;;
esac
"#,
        );

        let results = HwiSidecar::with_executable(fake)
            .verify_expected_xpubs(&[
                ExpectedHwiKey {
                    label: Some("Signer A".to_owned()),
                    fingerprint: "4ba43603".to_owned(),
                    derivation_path: "m/48h/1h/0h/2h".to_owned(),
                    xpub: Some("tpub-match".to_owned()),
                    chain: Some(HwiChain::Test),
                },
                ExpectedHwiKey {
                    label: Some("Signer B".to_owned()),
                    fingerprint: "6e37edb9".to_owned(),
                    derivation_path: "m/48h/1h/0h/2h".to_owned(),
                    xpub: Some("tpub-expected".to_owned()),
                    chain: Some(HwiChain::Test),
                },
                ExpectedHwiKey {
                    label: Some("Signer C".to_owned()),
                    fingerprint: "ffffffff".to_owned(),
                    derivation_path: "m/48h/1h/0h/2h".to_owned(),
                    xpub: Some("tpub-missing".to_owned()),
                    chain: Some(HwiChain::Test),
                },
            ])
            .expect("verification stays isolated to fake sidecar");

        assert_eq!(results[0].status, HwiVerificationStatus::Matched);
        assert!(results[0].fingerprint_matches);
        assert_eq!(results[0].xpub_matches, Some(true));
        assert_eq!(results[1].status, HwiVerificationStatus::XpubMismatch);
        assert!(results[1].fingerprint_matches);
        assert_eq!(results[1].xpub_matches, Some(false));
        assert_eq!(
            results[2].status,
            HwiVerificationStatus::FingerprintMismatch
        );
        assert!(!results[2].fingerprint_matches);
        assert_eq!(
            results[2].observed_fingerprints,
            vec!["4ba43603".to_owned(), "6e37edb9".to_owned()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_firmware_is_a_warning_not_a_crash() {
        let dir = unique_test_dir("firmware");
        let fake = write_fake_sidecar(
            &dir,
            r#"#!/bin/sh
cat <<'JSON'
[
  {"type":"trezor","model":"trezor_one","path":"trezor-path","fingerprint":"1234ABCD","error":"Unsupported firmware version 0.9.0"}
]
JSON
"#,
        );

        let results = HwiSidecar::with_executable(fake)
            .verify_expected_xpubs(&[ExpectedHwiKey {
                label: Some("Signer A".to_owned()),
                fingerprint: "1234abcd".to_owned(),
                derivation_path: "m/84h/1h/0h".to_owned(),
                xpub: Some("tpub-unused".to_owned()),
                chain: Some(HwiChain::Test),
            }])
            .expect("unsupported firmware is reported as a structured result");

        assert_eq!(
            results[0].status,
            HwiVerificationStatus::FirmwareUnsupported
        );
        assert_eq!(results[0].warnings.len(), 1);
        assert_eq!(
            results[0].warnings[0].code,
            HwiWarningCode::DeviceFirmwareUnsupported
        );
        assert_eq!(
            results[0].warnings[0].code.as_str(),
            "W-DEVICE-FIRMWARE-UNSUPPORTED"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn getxpub_unsupported_firmware_is_a_verification_warning() {
        let dir = unique_test_dir("firmware-getxpub");
        let fake = write_fake_sidecar(
            &dir,
            r#"#!/bin/sh
if [ "$1" = "enumerate" ]; then
  cat <<'JSON'
[
  {"type":"ledger","model":"ledger","path":"ledger-path","fingerprint":"abcdef12"}
]
JSON
  exit 0
fi
printf '{"error":"Unsupported firmware version for getxpub"}\n'
"#,
        );

        let results = HwiSidecar::with_executable(fake)
            .verify_expected_xpubs(&[ExpectedHwiKey {
                label: Some("Signer A".to_owned()),
                fingerprint: "abcdef12".to_owned(),
                derivation_path: "m/84h/1h/0h".to_owned(),
                xpub: Some("tpub-unused".to_owned()),
                chain: Some(HwiChain::Test),
            }])
            .expect("getxpub firmware errors stay isolated");

        assert_eq!(
            results[0].status,
            HwiVerificationStatus::FirmwareUnsupported
        );
        assert_eq!(
            results[0].warnings[0].code,
            HwiWarningCode::DeviceFirmwareUnsupported
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_nonzero_exit_is_isolated() {
        let dir = unique_test_dir("nonzero");
        let fake = write_fake_sidecar(&dir, "#!/bin/sh\nprintf 'boom\\n' >&2\nexit 42\n");

        let err = HwiSidecar::with_executable(fake)
            .invoke(["enumerate"])
            .expect_err("non-zero HWI exit must not panic");

        assert_eq!(err.code(), ErrorCode::Internal);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_timeout_is_bounded() {
        let dir = unique_test_dir("timeout");
        let fake = write_fake_sidecar(&dir, "#!/bin/sh\nsleep 10\n");

        let start = Instant::now();
        let err = HwiSidecar::with_executable(fake)
            .with_timeout(Duration::from_millis(120))
            .invoke(["enumerate"])
            .expect_err("timed-out HWI sidecar must error");

        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(start.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn supported_version_check_requires_hwi_3_2_plus() {
        let dir = unique_test_dir("version");
        let old = write_fake_sidecar(&dir, "#!/bin/sh\nprintf 'hwi 3.1.9\\n'\n");
        let err = HwiSidecar::with_executable(old)
            .require_supported_version()
            .expect_err("old HWI must be rejected");
        assert_eq!(err.code(), ErrorCode::HwiNotAvailable);

        let current = write_fake_sidecar(&dir, "#!/bin/sh\nprintf 'hwi 3.2.0\\n'\n");
        let version = HwiSidecar::with_executable(current)
            .require_supported_version()
            .expect("HWI 3.2 is supported");
        assert_eq!(version, MIN_HWI_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
