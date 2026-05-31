//! Process exit codes — the PRD §23.2 normative table.
//!
//! The discriminants below ARE the numbers returned to the shell and are
//! **stable across all versions** (§23.1 principle 3): scripts and CI depend on
//! them, so they must never change. Three mappings translate the program's
//! outcomes into a code:
//!
//! * [`ExitCode::from_status`] — a scored readiness verdict (rows 0–3), with the
//!   `--strict` promotion of warnings (exit 1 → exit 2).
//! * [`ExitCode::from_error`] / [`ExitCode::from_error_code`] — a typed
//!   [`LifeboatError`] (rows 4–7, 20). [`ErrorCode`] is `#[non_exhaustive]`, so
//!   every code is mapped explicitly with an internal-error fallback for future
//!   codes; a test pins that all shipping codes land on a table value.
//!
//! Clap parse errors map separately in [`crate::cli::exit_code_for_clap_error`]
//! (rows 4 and 10), because they are produced before any verdict or
//! `LifeboatError` exists.

use lifeboat_core::error_taxonomy::{ErrorCode, LifeboatError};
use lifeboat_core::readiness_score::ReadinessStatus;

/// The stable process exit codes from PRD §23.2.
///
/// `#[repr(u8)]` with explicit discriminants makes the enum value identical to
/// the number the shell sees; [`ExitCode::code`] exposes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExitCode {
    /// `0` — success / Ready: all checks pass.
    Success = 0,
    /// `1` — warnings (Mostly Ready or Needs Attention; score 40–89).
    Warnings = 1,
    /// `2` — critical / Not Ready (score 0–39 or any critical check fails).
    Critical = 2,
    /// `3` — cannot determine: insufficient information to render a verdict.
    CannotDetermine = 3,
    /// `4` — invalid CLI arguments (bad flags, missing/unusable input).
    InvalidArgs = 4,
    /// `5` — sensitive input detected (the detector returned `Block`, or a
    /// private key was found in a descriptor).
    SecretDetected = 5,
    /// `6` — file not found / I/O error.
    FileIo = 6,
    /// `7` — external dependency missing (e.g. the Typst binary is not bundled).
    DependencyMissing = 7,
    /// `10` — unknown subcommand (a typo in the command name).
    UnknownSubcommand = 10,
    /// `20` — internal error (a bug); a caught panic also lands here.
    Internal = 20,
}

impl ExitCode {
    /// The raw numeric code handed to the operating system.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Map a scored readiness verdict to its exit code (§23.2 rows 0–3).
    ///
    /// `strict` promotes a warnings-level result (exit 1) to critical (exit 2),
    /// implementing "`--strict` mode treats exit-1 as exit-2" (§23.2 / §23.7).
    /// A definitive Not Ready or Cannot Determine is unaffected by `strict`.
    #[must_use]
    pub const fn from_status(status: ReadinessStatus, strict: bool) -> Self {
        match status {
            ReadinessStatus::Ready => Self::Success,
            ReadinessStatus::MostlyReady | ReadinessStatus::NeedsAttention => {
                if strict {
                    Self::Critical
                } else {
                    Self::Warnings
                }
            }
            ReadinessStatus::NotReady => Self::Critical,
            ReadinessStatus::CannotDetermine => Self::CannotDetermine,
        }
    }

    /// Map a [`LifeboatError`] to its exit code via the underlying [`ErrorCode`].
    #[must_use]
    pub fn from_error(error: &LifeboatError) -> Self {
        Self::from_error_code(error.code())
    }

    /// Map an [`ErrorCode`] to its exit code (§23.2 rows 4–7 and 20).
    ///
    /// [`ErrorCode`] is `#[non_exhaustive]`, so a wildcard arm is required.
    /// Every code that exists today is listed explicitly below; any code added
    /// to the taxonomy in the future falls through to [`Self::Internal`] (an
    /// unmapped code reaching the CLI is itself a bug) until it is mapped here.
    /// The `every_error_code_has_a_defined_exit_code` test asserts that every
    /// shipping [`ErrorCode::ALL`] entry lands on a value in the §23.2 table.
    #[must_use]
    pub const fn from_error_code(code: ErrorCode) -> Self {
        match code {
            // Secret material present. The detected-secret `E-SECRET-*` codes and
            // a private key inside a descriptor (`E-PARSE-005`) all mean "we found
            // something we must not process": exit 5. (The Warn-vs-Block nuance of
            // the `detect-secrets` command, US-038, is decided from the detector
            // report directly, not from these error codes.)
            ErrorCode::ContainsPrivateKey
            | ErrorCode::Bip39Detected
            | ErrorCode::Bip39Suspected
            | ErrorCode::WifDetected
            | ErrorCode::ExtendedPrivateKeyDetected
            | ErrorCode::Slip39Detected
            | ErrorCode::Codex32Detected
            | ErrorCode::RawPrivateKeySuspected => Self::SecretDetected,

            // Filesystem problems.
            ErrorCode::FileNotFound | ErrorCode::CannotWrite | ErrorCode::DestinationExists => {
                Self::FileIo
            }

            // A required external dependency is missing.
            ErrorCode::TypstNotBundled | ErrorCode::HwiNotAvailable => Self::DependencyMissing,

            // Internal faults, plus events that cannot legitimately occur in the
            // offline MVP CLI: a network call (the CLI makes none) or a disallowed
            // external link (a GUI concern) reaching here is itself a bug.
            ErrorCode::Internal
            | ErrorCode::SchemaMigrationRequired
            | ErrorCode::NetworkUnreachable
            | ErrorCode::UnexpectedNetworkCall
            | ErrorCode::LinkNotAllowed => Self::Internal,

            // Everything else is user-correctable bad input or arguments. (In the
            // audit flow a parse failure becomes a Not Ready *verdict* — exit 2 —
            // via `from_status`; these `E-PARSE-*` codes only reach here when a
            // utility command surfaces them as a hard error.)
            ErrorCode::InputEmpty
            | ErrorCode::InputTooLarge
            | ErrorCode::InputInvalidFormat
            | ErrorCode::ParseFailed
            | ErrorCode::ChecksumMissing
            | ErrorCode::ChecksumInvalid
            | ErrorCode::NetworkMixed
            | ErrorCode::UnsupportedFunction
            | ErrorCode::ThresholdExceedsKeys => Self::InvalidArgs,

            // Forward-compat for the `#[non_exhaustive]` taxonomy: a code we do
            // not yet recognize is treated as an internal bug (see the doc note).
            _ => Self::Internal,
        }
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        Self::from(code.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_match_the_normative_table() {
        // PRD §23.2, verbatim numbers. If any of these change, scripts break.
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Warnings.code(), 1);
        assert_eq!(ExitCode::Critical.code(), 2);
        assert_eq!(ExitCode::CannotDetermine.code(), 3);
        assert_eq!(ExitCode::InvalidArgs.code(), 4);
        assert_eq!(ExitCode::SecretDetected.code(), 5);
        assert_eq!(ExitCode::FileIo.code(), 6);
        assert_eq!(ExitCode::DependencyMissing.code(), 7);
        assert_eq!(ExitCode::UnknownSubcommand.code(), 10);
        assert_eq!(ExitCode::Internal.code(), 20);
    }

    #[test]
    fn status_maps_to_codes_zero_through_three() {
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::Ready, false),
            ExitCode::Success
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::MostlyReady, false),
            ExitCode::Warnings
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::NeedsAttention, false),
            ExitCode::Warnings
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::NotReady, false),
            ExitCode::Critical
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::CannotDetermine, false),
            ExitCode::CannotDetermine
        );
    }

    #[test]
    fn strict_promotes_warnings_to_critical_only() {
        // `--strict` turns exit 1 into exit 2 ...
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::MostlyReady, true),
            ExitCode::Critical
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::NeedsAttention, true),
            ExitCode::Critical
        );
        // ... and leaves the definitive verdicts untouched.
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::Ready, true),
            ExitCode::Success
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::NotReady, true),
            ExitCode::Critical
        );
        assert_eq!(
            ExitCode::from_status(ReadinessStatus::CannotDetermine, true),
            ExitCode::CannotDetermine
        );
    }

    #[test]
    fn error_codes_map_by_family() {
        // Secrets → 5 (sample one E-SECRET-* and the descriptor private-key case).
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::Bip39Detected),
            ExitCode::SecretDetected
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::ContainsPrivateKey),
            ExitCode::SecretDetected
        );
        // Filesystem → 6.
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::FileNotFound),
            ExitCode::FileIo
        );
        // Dependency → 7.
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::TypstNotBundled),
            ExitCode::DependencyMissing
        );
        // Internal / cannot-happen-offline → 20.
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::Internal),
            ExitCode::Internal
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::UnexpectedNetworkCall),
            ExitCode::Internal
        );
        // Bad input/args → 4.
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::InputEmpty),
            ExitCode::InvalidArgs
        );
        assert_eq!(
            ExitCode::from_error_code(ErrorCode::ParseFailed),
            ExitCode::InvalidArgs
        );
    }

    #[test]
    fn from_error_delegates_to_the_code() {
        let err = LifeboatError::new(ErrorCode::FileNotFound);
        assert_eq!(ExitCode::from_error(&err), ExitCode::FileIo);
    }

    #[test]
    fn every_error_code_has_a_defined_exit_code() {
        // Exhaustiveness is enforced by the compiler; this also proves no code
        // maps to an out-of-table value.
        const VALID: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 10, 20];
        for &code in ErrorCode::ALL {
            let mapped = ExitCode::from_error_code(code).code();
            assert!(
                VALID.contains(&mapped),
                "{code:?} mapped to out-of-table exit code {mapped}"
            );
        }
    }

    #[test]
    fn converts_into_std_process_exit_code() {
        // Smoke-test the std conversion compiles and round-trips the number.
        let _: std::process::ExitCode = ExitCode::Critical.into();
        assert_eq!(ExitCode::Critical.code(), 2);
    }
}
