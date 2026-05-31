//! Typst subprocess backend (US-031, the preferred render path).
//!
//! Renders a `.typ` template by invoking a **bundled `typst` binary as an
//! out-of-process subprocess**. Typst is deliberately NOT a crate dependency
//! (it pulls a very large tree and raises the MSRV well past the pinned 1.78);
//! the binary and the Inter / JetBrains Mono fonts are populated by the
//! release/packaging step (US-064), so in dev/CI this path reports
//! [`ErrorCode::TypstNotBundled`] (`E-DEP-001`) and the engine falls back to the
//! pure-Rust [`printpdf_backend`](crate::printpdf_backend).
//!
//! The template reads its data from a `data.json` file written alongside it;
//! fonts are supplied via `--font-path`.
//!
//! ## Safety / determinism
//! - The child's stdin/stdout/stderr are all [`Stdio::null`]: a Typst diagnostic
//!   could echo a descriptor or xpub (private mode), and §13 forbids logging
//!   confidential material — so the child is silenced and errors report only the
//!   process outcome, never its output.
//! - `SOURCE_DATE_EPOCH=0` is set so Typst's own embedded metadata is
//!   reproducible.
//! - The wait is **bounded and foreground** ([`wait_with_timeout`]): it polls
//!   [`Child::try_wait`] and kills + reaps the child on the deadline. There is no
//!   background `pgrep`/watch loop (the Ralph hang anti-pattern documented in the
//!   project `CLAUDE.md`); a hung Typst is killed and surfaced as an error.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use error_taxonomy::{ErrorCode, LifeboatError};

/// Default render timeout: generous for a cold Typst start, but bounded so a
/// hung child can never wedge the caller (or the autonomous build loop).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Environment variable that overrides the Typst binary location.
const TYPST_BIN_ENV: &str = "LIFEBOAT_TYPST_BIN";

/// How often [`wait_with_timeout`] polls the child for completion.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Renders a Typst template by shelling out to a `typst` binary.
#[derive(Debug, Clone)]
pub struct TypstBackend {
    binary: BinarySource,
}

#[derive(Debug, Clone)]
enum BinarySource {
    /// Use exactly this path (tests / explicit configuration).
    Explicit(PathBuf),
    /// Resolve automatically at render time: env → next-to-exe → PATH.
    Auto,
}

impl TypstBackend {
    /// Use exactly `path` as the Typst binary.
    #[must_use]
    pub fn with_binary(path: PathBuf) -> Self {
        Self {
            binary: BinarySource::Explicit(path),
        }
    }

    /// Resolve the Typst binary automatically at render time.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            binary: BinarySource::Auto,
        }
    }

    /// Render `template_src` (with its `data_json` sidecar) to PDF bytes.
    ///
    /// # Errors
    /// - [`ErrorCode::TypstNotBundled`] (`E-DEP-001`) when no binary is found.
    /// - [`ErrorCode::CannotWrite`] (`E-FS-002`) when a scratch file cannot be
    ///   written.
    /// - [`ErrorCode::Internal`] when the child fails, times out, or produces no
    ///   output file.
    pub fn render(
        &self,
        template_src: &str,
        data_json: &str,
        fonts_dir: Option<&Path>,
        timeout: Duration,
    ) -> Result<Vec<u8>, LifeboatError> {
        let binary = self.resolve_binary().ok_or_else(|| {
            LifeboatError::new(ErrorCode::TypstNotBundled)
                .with_context("no bundled `typst` binary found")
        })?;

        let scratch = ScratchDir::new()?;
        let template_path = scratch.join("runbook.typ");
        let data_path = scratch.join("data.json");
        let output_path = scratch.join("runbook.pdf");
        write_file(&template_path, template_src.as_bytes())?;
        write_file(&data_path, data_json.as_bytes())?;

        let mut cmd = Command::new(binary);
        cmd.arg("compile")
            .arg("--root")
            .arg(scratch.path())
            .arg(&template_path);
        if let Some(fonts) = fonts_dir {
            cmd.arg("--font-path").arg(fonts);
        }
        // The output path MUST be the final argument (`typst compile IN OUT`).
        cmd.arg(&output_path)
            .env("SOURCE_DATE_EPOCH", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(LifeboatError::new(ErrorCode::TypstNotBundled)
                    .with_context("the configured `typst` binary does not exist"));
            }
            Err(_) => {
                return Err(LifeboatError::new(ErrorCode::Internal)
                    .with_context("failed to spawn the `typst` subprocess"));
            }
        };

        let status = wait_with_timeout(&mut child, timeout)?;
        if !status.success() {
            return Err(LifeboatError::new(ErrorCode::Internal)
                .with_context("the `typst` subprocess exited with a non-zero status"));
        }

        std::fs::read(&output_path).map_err(|_| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("the `typst` subprocess produced no output file")
        })
    }

    /// The binary path to invoke, or `None` if none is configured. An explicit
    /// path is returned as-is; a missing file is reported at spawn time as
    /// `E-DEP-001`. The `Auto` resolution falls back to `typst` on `PATH`.
    fn resolve_binary(&self) -> Option<PathBuf> {
        match &self.binary {
            BinarySource::Explicit(path) => Some(path.clone()),
            BinarySource::Auto => {
                if let Some(env) = std::env::var_os(TYPST_BIN_ENV) {
                    let p = PathBuf::from(env);
                    if p.is_file() {
                        return Some(p);
                    }
                }
                if let Ok(exe) = std::env::current_exe() {
                    if let Some(dir) = exe.parent() {
                        let candidate = dir.join(typst_exe_name());
                        if candidate.is_file() {
                            return Some(candidate);
                        }
                    }
                }
                // Last resort: rely on PATH. A missing `typst` → NotFound → E-DEP-001.
                Some(PathBuf::from("typst"))
            }
        }
    }
}

fn typst_exe_name() -> &'static str {
    if cfg!(windows) {
        "typst.exe"
    } else {
        "typst"
    }
}

/// Wait for `child` to exit, bounded by `timeout`. Foreground polling: never
/// backgrounds, never `pgrep`s. On the deadline (or a wait error) the child is
/// killed and reaped and an `E-INTERNAL` error is returned.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus, LifeboatError> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(LifeboatError::new(ErrorCode::Internal)
                        .with_context("the `typst` subprocess exceeded its render timeout"));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LifeboatError::new(ErrorCode::Internal)
                    .with_context("failed while waiting on the `typst` subprocess"));
            }
        }
    }
}

/// A unique temporary directory, removed on drop. Hand-rolled instead of the
/// `tempfile` crate, whose `fastrand` → `getrandom 0.4` subtree uses edition
/// 2024 and cannot build on the pinned Rust 1.78 toolchain.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Result<Self, LifeboatError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("lifeboat-runbook-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&path).map_err(|_| {
            LifeboatError::new(ErrorCode::CannotWrite)
                .with_context("could not create a scratch directory for the typst render")
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), LifeboatError> {
    std::fs::write(path, bytes).map_err(|_| {
        LifeboatError::new(ErrorCode::CannotWrite)
            .with_context("could not write a typst scratch file")
    })
}
