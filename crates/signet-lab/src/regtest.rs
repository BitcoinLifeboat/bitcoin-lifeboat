//! Offline regtest node orchestration for practice drills.
//!
//! This module is deliberately split into two explicit steps:
//!
//! 1. Cache a `bitcoind` binary only when the caller passes
//!    [`DownloadApproval::ExplicitUserRequest`].
//! 2. Start that binary with regtest-only, loopback-only, no-peer flags.
//!
//! Constructing configs or clients never downloads anything and never opens a
//! non-loopback socket. The only network-capable production type is
//! [`CurlBitcoindDownloader`], and it is inert unless passed into
//! [`BitcoindCache::ensure_bitcoind`] with explicit user approval.

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use error_taxonomy::{ErrorCode, LifeboatError};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use zeroize::Zeroize;

const LOCALHOST: &str = "127.0.0.1";
const RPC_READY_POLL: Duration = Duration::from_millis(100);
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// User approval state for a bitcoind download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadApproval {
    /// The user explicitly requested the one-time download.
    ExplicitUserRequest,
    /// No user action occurred, so a missing binary must not trigger a network
    /// call.
    NotApproved,
}

/// A single bitcoind binary download request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoindDownload {
    url: String,
    expected_sha256: Option<String>,
}

impl BitcoindDownload {
    /// Build a download request. `expected_sha256`, when provided, is the
    /// lowercase hex SHA256 of the final binary.
    pub fn new(url: impl Into<String>, expected_sha256: Option<String>) -> Self {
        Self {
            url: url.into(),
            expected_sha256,
        }
    }

    /// Source URL for the bitcoind binary.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Optional expected SHA256 hash in lowercase hex.
    #[must_use]
    pub fn expected_sha256(&self) -> Option<&str> {
        self.expected_sha256.as_deref()
    }
}

/// Downloader abstraction used to keep user-consent gating testable.
pub trait BitcoindDownloader {
    /// Download the requested binary into `destination`.
    fn download(&self, request: &BitcoindDownload, destination: &Path)
        -> Result<(), LifeboatError>;
}

/// Production HTTP(S) downloader backed by the system `curl` command.
///
/// This avoids adding a TLS stack to the Rust dependency graph while still
/// keeping the download inside the explicit user-request flow. It performs no
/// work unless a caller passes it to [`BitcoindCache::ensure_bitcoind`] after
/// explicit user approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlBitcoindDownloader {
    curl_path: PathBuf,
}

impl Default for CurlBitcoindDownloader {
    fn default() -> Self {
        Self {
            curl_path: PathBuf::from("curl"),
        }
    }
}

impl CurlBitcoindDownloader {
    /// Use a specific curl-compatible executable.
    #[must_use]
    pub fn new(curl_path: impl Into<PathBuf>) -> Self {
        Self {
            curl_path: curl_path.into(),
        }
    }
}

impl BitcoindDownloader for CurlBitcoindDownloader {
    fn download(
        &self,
        request: &BitcoindDownload,
        destination: &Path,
    ) -> Result<(), LifeboatError> {
        let status = Command::new(&self.curl_path)
            .arg("--fail")
            .arg("--location")
            .arg("--silent")
            .arg("--show-error")
            .arg("--output")
            .arg(destination)
            .arg(request.url())
            .stdin(Stdio::null())
            .status()
            .map_err(|err| {
                LifeboatError::new(ErrorCode::NetworkUnreachable)
                    .with_context("user-requested bitcoind download could not start")
                    .with_source(err)
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("user-requested bitcoind download failed"))
        }
    }
}

/// Cached local bitcoind binary metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoindInstall {
    path: PathBuf,
    downloaded_now: bool,
}

impl BitcoindInstall {
    /// Path to the cached binary.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this call downloaded the binary.
    #[must_use]
    pub const fn downloaded_now(&self) -> bool {
        self.downloaded_now
    }
}

/// One-time cache for the user-approved bitcoind binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoindCache {
    dir: PathBuf,
}

impl BitcoindCache {
    /// Create a bitcoind cache rooted at `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Expected cached binary path for the current platform.
    #[must_use]
    pub fn binary_path(&self) -> PathBuf {
        self.dir.join(bitcoind_binary_name())
    }

    /// Ensure the bitcoind binary exists in the cache.
    ///
    /// If the binary is already cached this returns without consulting the
    /// downloader, even when `approval` is [`DownloadApproval::NotApproved`].
    /// If it is missing, the downloader is called only with
    /// [`DownloadApproval::ExplicitUserRequest`].
    pub fn ensure_bitcoind<D: BitcoindDownloader>(
        &self,
        request: &BitcoindDownload,
        approval: DownloadApproval,
        downloader: &D,
    ) -> Result<BitcoindInstall, LifeboatError> {
        let final_path = self.binary_path();
        if final_path.is_file() {
            return Ok(BitcoindInstall {
                path: final_path,
                downloaded_now: false,
            });
        }

        if approval != DownloadApproval::ExplicitUserRequest {
            return Err(LifeboatError::new(ErrorCode::UnexpectedNetworkCall)
                .with_context("bitcoind download requires explicit user request"));
        }

        fs::create_dir_all(&self.dir).map_err(cannot_write)?;
        let tmp_path = self
            .dir
            .join(format!("{}.download", bitcoind_binary_name()));
        if tmp_path.exists() {
            fs::remove_file(&tmp_path).map_err(cannot_write)?;
        }

        downloader.download(request, &tmp_path)?;
        if let Some(expected) = request.expected_sha256() {
            verify_sha256(&tmp_path, expected)?;
        }
        mark_executable(&tmp_path)?;
        fs::rename(&tmp_path, &final_path).map_err(cannot_write)?;

        Ok(BitcoindInstall {
            path: final_path,
            downloaded_now: true,
        })
    }
}

/// Configuration for a local offline regtest bitcoind instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegtestConfig {
    bitcoind_path: PathBuf,
    data_dir: PathBuf,
    rpc_port: u16,
    rpc_user: String,
    rpc_password: String,
    ready_timeout: Duration,
}

impl RegtestConfig {
    /// Build a config with a free loopback RPC port and random local RPC
    /// password.
    pub fn new(
        bitcoind_path: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
    ) -> Result<Self, LifeboatError> {
        Self::with_rpc_port(bitcoind_path, data_dir, reserve_loopback_port()?)
    }

    /// Build a config with a caller-chosen loopback RPC port.
    pub fn with_rpc_port(
        bitcoind_path: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
        rpc_port: u16,
    ) -> Result<Self, LifeboatError> {
        Ok(Self {
            bitcoind_path: bitcoind_path.into(),
            data_dir: data_dir.into(),
            rpc_port,
            rpc_user: "lifeboat".to_owned(),
            rpc_password: random_rpc_password()?,
            ready_timeout: DEFAULT_READY_TIMEOUT,
        })
    }

    /// Override the startup RPC readiness timeout.
    #[must_use]
    pub fn with_ready_timeout(mut self, timeout: Duration) -> Self {
        self.ready_timeout = timeout;
        self
    }

    /// Path to the bitcoind binary.
    #[must_use]
    pub fn bitcoind_path(&self) -> &Path {
        &self.bitcoind_path
    }

    /// Data directory for the regtest chain state.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Loopback RPC port.
    #[must_use]
    pub const fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    /// Loopback RPC client derived from this config.
    #[must_use]
    pub fn rpc_client(&self) -> RegtestRpcClient {
        RegtestRpcClient::new(
            self.rpc_port,
            self.rpc_user.clone(),
            self.rpc_password.clone(),
        )
    }

    /// Arguments passed to bitcoind. This is public so tests and UI adapters can
    /// verify the offline contract without spawning a process.
    #[must_use]
    pub fn bitcoind_args(&self) -> Vec<String> {
        vec![
            "-regtest=1".to_owned(),
            "-server=1".to_owned(),
            format!("-datadir={}", self.data_dir.display()),
            format!("-rpcbind={LOCALHOST}"),
            format!("-rpcallowip={LOCALHOST}"),
            format!("-rpcport={}", self.rpc_port),
            format!("-rpcuser={}", self.rpc_user),
            format!("-rpcpassword={}", self.rpc_password),
            "-listen=0".to_owned(),
            "-listenonion=0".to_owned(),
            "-connect=0".to_owned(),
            "-dnsseed=0".to_owned(),
            "-fixedseeds=0".to_owned(),
            "-discover=0".to_owned(),
            "-upnp=0".to_owned(),
            "-natpmp=0".to_owned(),
            "-fallbackfee=0.00001000".to_owned(),
            "-printtoconsole=1".to_owned(),
        ]
    }
}

/// A running local regtest bitcoind process.
pub struct RegtestNode {
    child: Child,
    rpc: RegtestRpcClient,
}

impl RegtestNode {
    /// Spawn bitcoind, wait for local RPC readiness, and return a managed node.
    pub fn start(config: &RegtestConfig) -> Result<Self, LifeboatError> {
        fs::create_dir_all(config.data_dir()).map_err(cannot_write)?;

        let mut command = Command::new(config.bitcoind_path());
        command
            .args(config.bitcoind_args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command.spawn().map_err(|err| {
            let code = if err.kind() == std::io::ErrorKind::NotFound {
                ErrorCode::FileNotFound
            } else {
                ErrorCode::Internal
            };
            LifeboatError::new(code)
                .with_context("failed to start local regtest bitcoind")
                .with_source(err)
        })?;

        let mut node = Self {
            child,
            rpc: config.rpc_client(),
        };
        if let Err(err) = node.wait_until_ready(config.ready_timeout) {
            let _ = node.shutdown();
            return Err(err);
        }
        Ok(node)
    }

    /// Local RPC client for the node.
    #[must_use]
    pub const fn rpc(&self) -> &RegtestRpcClient {
        &self.rpc
    }

    /// Whether the child process is still running.
    pub fn is_running(&mut self) -> Result<bool, LifeboatError> {
        self.child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|err| {
                LifeboatError::new(ErrorCode::Internal)
                    .with_context("failed to inspect regtest bitcoind process")
                    .with_source(err)
            })
    }

    /// Terminate the child process.
    pub fn shutdown(&mut self) -> Result<(), LifeboatError> {
        match self.child.try_wait().map_err(internal_error)? {
            Some(_) => Ok(()),
            None => {
                self.child.kill().map_err(internal_error)?;
                self.child.wait().map_err(internal_error)?;
                Ok(())
            }
        }
    }

    fn wait_until_ready(&self, timeout: Duration) -> Result<(), LifeboatError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.rpc.get_block_count().is_ok() {
                return Ok(());
            }
            thread::sleep(RPC_READY_POLL);
        }
        Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context("local regtest RPC did not become ready"))
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Minimal loopback-only Bitcoin Core JSON-RPC client for regtest drills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegtestRpcClient {
    rpc_port: u16,
    rpc_user: String,
    rpc_password: String,
}

impl RegtestRpcClient {
    /// Build a loopback RPC client.
    #[must_use]
    pub fn new(rpc_port: u16, rpc_user: String, rpc_password: String) -> Self {
        Self {
            rpc_port,
            rpc_user,
            rpc_password,
        }
    }

    /// Human-readable local RPC endpoint.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://{LOCALHOST}:{}", self.rpc_port)
    }

    /// Read the current regtest block height.
    pub fn get_block_count(&self) -> Result<u64, LifeboatError> {
        let value = self.call("getblockcount", Vec::new())?;
        value.as_u64().ok_or_else(|| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("bitcoind getblockcount returned non-numeric result")
        })
    }

    /// Mine `count` blocks to `address` on the local regtest node.
    pub fn mine_blocks(&self, count: u16, address: &str) -> Result<Vec<String>, LifeboatError> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let value = self.call("generatetoaddress", vec![json!(count), json!(address)])?;
        let hashes = value.as_array().ok_or_else(|| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("bitcoind generatetoaddress returned non-array result")
        })?;
        hashes
            .iter()
            .map(|hash| {
                hash.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    LifeboatError::new(ErrorCode::Internal)
                        .with_context("bitcoind generatetoaddress returned non-string hash")
                })
            })
            .collect()
    }

    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, LifeboatError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "lifeboat-regtest",
            "method": method,
            "params": params,
        })
        .to_string();
        let auth = basic_auth(&self.rpc_user, &self.rpc_password);
        let request = format!(
            "POST / HTTP/1.1\r\n\
             Host: {LOCALHOST}:{port}\r\n\
             Authorization: Basic {auth}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {length}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            port = self.rpc_port,
            length = body.len()
        );

        let mut stream = TcpStream::connect((LOCALHOST, self.rpc_port)).map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("local regtest RPC connection failed")
                .with_source(err)
        })?;
        stream.write_all(request.as_bytes()).map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("local regtest RPC write failed")
                .with_source(err)
        })?;
        stream.flush().map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("local regtest RPC flush failed")
                .with_source(err)
        })?;

        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(|err| {
            LifeboatError::new(ErrorCode::NetworkUnreachable)
                .with_context("local regtest RPC read failed")
                .with_source(err)
        })?;
        parse_rpc_response(&response, method)
    }
}

fn parse_rpc_response(response: &str, method: &str) -> Result<Value, LifeboatError> {
    let mut lines = response.lines();
    let status = lines.next().ok_or_else(|| {
        LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context("local regtest RPC returned an empty response")
    })?;
    if !status.contains(" 200 ") {
        return Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context(format!("local regtest RPC rejected {method}")));
    }
    let (_, body) = response.split_once("\r\n\r\n").ok_or_else(|| {
        LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context("local regtest RPC returned malformed HTTP")
    })?;
    let value: Value = serde_json::from_str(body).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("local regtest RPC returned malformed JSON")
            .with_source(err)
    })?;
    if !value.get("error").unwrap_or(&Value::Null).is_null() {
        return Err(LifeboatError::new(ErrorCode::Internal)
            .with_context(format!("bitcoind RPC method failed: {method}")));
    }
    value.get("result").cloned().ok_or_else(|| {
        LifeboatError::new(ErrorCode::Internal).with_context("bitcoind RPC response omitted result")
    })
}

fn verify_sha256(path: &Path, expected: &str) -> Result<(), LifeboatError> {
    let bytes = fs::read(path).map_err(file_not_found)?;
    let actual = sha256::Hash::hash(&bytes).to_string();
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(LifeboatError::new(ErrorCode::NetworkUnreachable)
            .with_context("downloaded bitcoind checksum did not match"));
    }
    Ok(())
}

fn mark_executable(path: &Path) -> Result<(), LifeboatError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path).map_err(file_not_found)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        fs::set_permissions(path, permissions).map_err(cannot_write)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn reserve_loopback_port() -> Result<u16, LifeboatError> {
    let listener = TcpListener::bind((LOCALHOST, 0)).map_err(|err| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("failed to reserve local regtest RPC port")
            .with_source(err)
    })?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(internal_error)
}

fn random_rpc_password() -> Result<String, LifeboatError> {
    let mut bytes = [0_u8; 16];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("failed to read OS randomness for regtest RPC password")
    })?;
    let password = hex_encode(&bytes);
    bytes.zeroize();
    Ok(password)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn basic_auth(user: &str, password: &str) -> String {
    base64_encode(format!("{user}:{password}").as_bytes())
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        let n = (u32::from(first) << 16) | (u32::from(second) << 8) | u32::from(third);

        encoded.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}

fn bitcoind_binary_name() -> &'static str {
    if cfg!(windows) {
        "bitcoind.exe"
    } else {
        "bitcoind"
    }
}

fn file_not_found(err: std::io::Error) -> LifeboatError {
    LifeboatError::new(ErrorCode::FileNotFound)
        .with_context("regtest bitcoind file was not readable")
        .with_source(err)
}

fn cannot_write(err: std::io::Error) -> LifeboatError {
    LifeboatError::new(ErrorCode::CannotWrite)
        .with_context("regtest bitcoind cache path was not writable")
        .with_source(err)
}

fn internal_error(err: std::io::Error) -> LifeboatError {
    LifeboatError::new(ErrorCode::Internal)
        .with_context("local regtest process operation failed")
        .with_source(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct FakeDownloader {
        calls: Arc<Mutex<u8>>,
        payload: Vec<u8>,
    }

    impl FakeDownloader {
        fn calls(&self) -> u8 {
            *self.calls.lock().expect("calls lock")
        }
    }

    impl BitcoindDownloader for FakeDownloader {
        fn download(
            &self,
            _request: &BitcoindDownload,
            destination: &Path,
        ) -> Result<(), LifeboatError> {
            let mut calls = self.calls.lock().expect("calls lock");
            *calls += 1;
            fs::write(destination, &self.payload).map_err(cannot_write)
        }
    }

    #[test]
    fn bitcoind_download_requires_explicit_user_request() {
        let dir = unique_temp_dir("no-download");
        let cache = BitcoindCache::new(&dir);
        let downloader = FakeDownloader::default();
        let request = BitcoindDownload::new("https://example.invalid/bitcoind", None);

        let err = cache
            .ensure_bitcoind(&request, DownloadApproval::NotApproved, &downloader)
            .expect_err("missing binary without user approval must fail");

        assert_eq!(err.code(), ErrorCode::UnexpectedNetworkCall);
        assert_eq!(downloader.calls(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bitcoind_download_is_cached_after_first_user_request() {
        let dir = unique_temp_dir("download-once");
        let cache = BitcoindCache::new(&dir);
        let payload = b"fake-bitcoind".to_vec();
        let expected_hash = sha256::Hash::hash(&payload).to_string();
        let downloader = FakeDownloader {
            calls: Arc::new(Mutex::new(0)),
            payload,
        };
        let request =
            BitcoindDownload::new("https://example.invalid/bitcoind", Some(expected_hash));

        let first = cache
            .ensure_bitcoind(&request, DownloadApproval::ExplicitUserRequest, &downloader)
            .expect("first download");
        let second = cache
            .ensure_bitcoind(&request, DownloadApproval::NotApproved, &downloader)
            .expect("cached binary");

        assert!(first.downloaded_now());
        assert!(!second.downloaded_now());
        assert_eq!(first.path(), second.path());
        assert_eq!(downloader.calls(), 1);
        assert_eq!(
            fs::read(second.path()).expect("cached file"),
            b"fake-bitcoind"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bitcoind_download_rejects_checksum_mismatch() {
        let dir = unique_temp_dir("bad-checksum");
        let cache = BitcoindCache::new(&dir);
        let downloader = FakeDownloader {
            calls: Arc::new(Mutex::new(0)),
            payload: b"fake-bitcoind".to_vec(),
        };
        let request = BitcoindDownload::new(
            "https://example.invalid/bitcoind",
            Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
        );

        let err = cache
            .ensure_bitcoind(&request, DownloadApproval::ExplicitUserRequest, &downloader)
            .expect_err("checksum mismatch");

        assert_eq!(err.code(), ErrorCode::NetworkUnreachable);
        assert!(!cache.binary_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn regtest_bitcoind_args_are_loopback_and_offline() {
        let config = RegtestConfig::with_rpc_port("/tmp/bitcoind", "/tmp/lifeboat-regtest", 18443)
            .expect("config");
        let args = config.bitcoind_args();

        assert!(args.contains(&"-regtest=1".to_owned()));
        assert!(args.contains(&"-server=1".to_owned()));
        assert!(args.contains(&"-listen=0".to_owned()));
        assert!(args.contains(&"-listenonion=0".to_owned()));
        assert!(args.contains(&"-connect=0".to_owned()));
        assert!(args.contains(&"-dnsseed=0".to_owned()));
        assert!(args.contains(&"-fixedseeds=0".to_owned()));
        assert!(args.contains(&"-discover=0".to_owned()));
        assert!(args.contains(&"-upnp=0".to_owned()));
        assert!(args.contains(&"-natpmp=0".to_owned()));
        assert!(args.iter().any(|arg| arg == "-rpcbind=127.0.0.1"));
        assert!(args.iter().any(|arg| arg == "-rpcallowip=127.0.0.1"));
        assert_eq!(config.rpc_client().endpoint(), "http://127.0.0.1:18443");
    }

    #[test]
    fn regtest_start_mine_and_offline_contract_uses_loopback_only() {
        let dir = unique_temp_dir("regtest-flow");
        fs::create_dir_all(&dir).expect("temp dir");
        let bitcoind = write_fake_bitcoind(&dir);
        let rpc = FakeRpcServer::start();
        let config = RegtestConfig::with_rpc_port(&bitcoind, dir.join("chain"), rpc.port())
            .expect("config")
            .with_ready_timeout(Duration::from_secs(2));

        let mut node = RegtestNode::start(&config).expect("node starts against fake RPC");
        assert!(node.is_running().expect("process status"));
        let address = "bcrt1qpracticeaddress0000000000000000000000000000000";
        let hashes = node.rpc().mine_blocks(3, address).expect("mine blocks");
        let count = node.rpc().get_block_count().expect("block count");
        let requests = rpc.requests();

        assert_eq!(hashes.len(), 3);
        assert_eq!(count, 3);
        assert!(requests.iter().all(|request| request.peer_is_loopback));
        assert!(requests
            .iter()
            .any(|request| request.method == "generatetoaddress"));
        node.shutdown().expect("shutdown");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rpc_client_handles_zero_block_mine_without_rpc_call() {
        let rpc = FakeRpcServer::start();
        let client = RegtestRpcClient::new(rpc.port(), "user".into(), "pass".into());

        let hashes = client
            .mine_blocks(0, "bcrt1qpracticeaddress")
            .expect("zero blocks");

        assert!(hashes.is_empty());
        assert!(rpc.requests().is_empty());
    }

    struct FakeRpcServer {
        port: u16,
        requests: Arc<Mutex<Vec<FakeRpcRequest>>>,
    }

    impl FakeRpcServer {
        fn start() -> Self {
            let listener = TcpListener::bind((LOCALHOST, 0)).expect("bind fake rpc");
            let port = listener.local_addr().expect("addr").port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let thread_requests = Arc::clone(&requests);
            thread::spawn(move || {
                let mut block_count = 0_u64;
                for stream in listener.incoming() {
                    let stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let peer_is_loopback = stream
                        .peer_addr()
                        .map(|addr| addr.ip().is_loopback())
                        .unwrap_or(false);
                    if !handle_rpc_stream(
                        stream,
                        peer_is_loopback,
                        &thread_requests,
                        &mut block_count,
                    ) {
                        break;
                    }
                }
            });
            Self { port, requests }
        }

        const fn port(&self) -> u16 {
            self.port
        }

        fn requests(&self) -> Vec<FakeRpcRequest> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    #[derive(Debug, Clone)]
    struct FakeRpcRequest {
        method: String,
        peer_is_loopback: bool,
    }

    fn handle_rpc_stream(
        mut stream: TcpStream,
        peer_is_loopback: bool,
        requests: &Arc<Mutex<Vec<FakeRpcRequest>>>,
        block_count: &mut u64,
    ) -> bool {
        let buffer = read_http_request(&mut stream);
        let Some((_, body)) = buffer.split_once("\r\n\r\n") else {
            return false;
        };
        let request: Value = serde_json::from_str(body).expect("request json");
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .expect("method")
            .to_owned();
        requests
            .lock()
            .expect("requests lock")
            .push(FakeRpcRequest {
                method: method.clone(),
                peer_is_loopback,
            });
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let response = match method.as_str() {
            "getblockcount" => {
                json!({"result": *block_count, "error": null, "id": "lifeboat-regtest"})
            }
            "generatetoaddress" => {
                let count = params.first().and_then(Value::as_u64).unwrap_or(0);
                *block_count += count;
                let hashes = (0..count)
                    .map(|idx| format!("regtest-block-{idx}"))
                    .collect::<Vec<_>>();
                json!({"result": hashes, "error": null, "id": "lifeboat-regtest"})
            }
            _ => {
                json!({"result": null, "error": {"code": -32601, "message": "missing"}, "id": "lifeboat-regtest"})
            }
        };
        write_http_response(&mut stream, &response.to_string());
        true
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let bytes_read = stream.read(&mut chunk).expect("read request");
            if bytes_read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..bytes_read]);
            if request_is_complete(&buffer) {
                break;
            }
        }
        String::from_utf8(buffer).expect("utf8 request")
    }

    fn request_is_complete(buffer: &[u8]) -> bool {
        let Some(header_end) = find_header_end(buffer) else {
            return false;
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let length = content_length(&headers);
        buffer.len() >= header_end + 4 + length
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    }

    fn write_http_response(stream: &mut TcpStream, body: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    fn write_fake_bitcoind(dir: &Path) -> PathBuf {
        let path = dir.join(bitcoind_binary_name());
        #[cfg(unix)]
        {
            fs::write(&path, "#!/bin/sh\nsleep 30\n").expect("fake bitcoind");
            mark_executable(&path).expect("executable");
        }
        #[cfg(windows)]
        {
            fs::write(&path, "@echo off\r\nping -n 30 127.0.0.1 > nul\r\n").expect("fake bitcoind");
        }
        path
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        path.push(format!(
            "lifeboat-signet-lab-{label}-{}-{now}",
            std::process::id()
        ));
        path
    }
}
