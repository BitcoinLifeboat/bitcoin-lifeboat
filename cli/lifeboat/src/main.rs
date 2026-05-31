//! `lifeboat` — the Bitcoin Lifeboat command-line interface.
//!
//! US-035 builds the CLI *shell*: the [`clap`]-based command surface with the
//! global flags (`--json` / `--no-color` / `--quiet` / `--verbose`, plus clap's
//! `--help` / `--version`), the PRD §23.2 exit-code table, the verbatim §15.7
//! "not a wallet" banner in `--help`, and a panic handler that turns a crash
//! into a friendly message and exit code 20. The subcommands are named so they
//! appear in help and a typo yields exit 10; their handlers land in US-036–038.
//!
//! All Bitcoin/scoring/report logic is reached through the [`lifeboat_core`]
//! façade — the CLI never parses descriptors or does crypto itself.

mod cli;
mod commands;
mod exit;

use clap::FromArgMatches;

use crate::cli::{Cli, Commands, GlobalArgs};
use crate::exit::ExitCode;

/// Where a crashed run tells the user to file a bug. Built from the package
/// `repository` (PRD §30.6 single source of truth — it still carries the
/// `__GH_ORG__` placeholder until release configuration swaps it in).
const REPO_ISSUES_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/issues");

fn main() -> std::process::ExitCode {
    install_panic_hook();
    // Catch any panic from the run and convert it to the §23.2 internal-error
    // code instead of the process aborting with the platform default.
    run_caught(|| run(std::env::args_os())).into()
}

/// Run the CLI to completion and return its exit code.
///
/// Generic over the argument iterator so tests can drive it directly. Parsing,
/// help, and version are handled here; clap writes help/version to stdout and
/// errors to stderr, and the resulting [`ExitCode`] follows §23.2.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let matches = match cli::build_command().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) => {
            // `--help` / `--version` print to stdout; real errors to stderr.
            let _ = error.print();
            return cli::exit_code_for_clap_error(error.kind());
        }
    };

    let parsed = match Cli::from_arg_matches(&matches) {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = error.print();
            return ExitCode::InvalidArgs;
        }
    };

    // Resolve the color policy for the program's own output. US-035 has no
    // colored output yet; this fixes the decision the subcommands (US-036+) use.
    let _use_color = cli::use_color(
        parsed.global.no_color,
        cli::no_color_env(),
        cli::stdout_is_terminal(),
    );

    match parsed.command {
        None => print_root_help(),
        Some(command) => dispatch(command, &parsed.global),
    }
}

/// Bare `lifeboat`: print the long help (which carries the §15.7 banner) and
/// succeed.
fn print_root_help() -> ExitCode {
    let mut command = cli::build_command();
    let _ = command.print_long_help();
    ExitCode::Success
}

/// Dispatch a recognized subcommand.
///
/// Each command runs its handler and prints the result. Handlers that build a
/// report or stamp an import time read the wall clock and package version here, at
/// the boundary, and pass them in so the output stays a pure function of its
/// inputs. `--verbose` (unless `--quiet`) emits a one-line diagnostic naming the
/// command.
fn dispatch(command: Commands, global: &GlobalArgs) -> ExitCode {
    if global.verbose && !global.quiet {
        eprintln!("(verbose) running `{}`", command.name());
    }
    match command {
        Commands::AuditDescriptor(args) => emit(commands::run_audit_descriptor(
            &args,
            global,
            &commands::now_iso8601(),
            lifeboat_core::report_engine::APP_VERSION,
            std::io::stdin().lock(),
        )),
        Commands::ReportJson(args) => emit(commands::run_report_json(
            &args,
            &commands::now_iso8601(),
            lifeboat_core::report_engine::APP_VERSION,
            std::io::stdin().lock(),
        )),
        // US-037 utilities: pure functions of their flags (no clock / report).
        Commands::DeriveAddresses(args) => emit(commands::run_derive_addresses(&args, global)),
        Commands::CompareAddress(args) => emit(commands::run_compare_address(&args, global)),
        Commands::Checksum(args) => emit(commands::run_checksum(&args, global)),
        // US-038: detect-secrets reads from a file or stdin; parse-export reads a
        // file and stamps the import time at the boundary.
        Commands::DetectSecrets(args) => emit(commands::run_detect_secrets(
            &args,
            global,
            std::io::stdin().lock(),
        )),
        Commands::ParseExport(args) => emit(commands::run_parse_export(
            &args,
            global,
            &commands::now_iso8601(),
        )),
        // US-039: generate-runbook is a pure function of its flags + the app
        // version (no clock; the report hash is a placeholder, §17.10.4).
        // completions/man render off the live `build_command()` clap tree.
        Commands::GenerateRunbook(args) => emit(commands::run_generate_runbook(
            &args,
            lifeboat_core::report_engine::APP_VERSION,
        )),
        Commands::Psbt(args) => emit(commands::run_psbt(&args, global)),
        Commands::VerifyBuild(args) => emit(commands::run_verify_build(&args, global)),
        Commands::Completions(args) => emit(commands::run_completions(&args)),
        Commands::Man => emit(commands::run_man()),
    }
}

/// Print a handler's [`CommandOutput`] to the real streams and return its exit
/// code. stdout carries the audit result / report; stderr carries refusals and
/// operational errors.
fn emit(output: commands::CommandOutput) -> ExitCode {
    use std::io::Write;
    print!("{}", output.stdout);
    let _ = std::io::stdout().flush();
    eprint!("{}", output.stderr);
    output.code
}

/// Run `f`, converting any panic into [`ExitCode::Internal`] (§23.2 row 20).
fn run_caught<F>(f: F) -> ExitCode
where
    F: FnOnce() -> ExitCode + std::panic::UnwindSafe,
{
    std::panic::catch_unwind(f).unwrap_or(ExitCode::Internal)
}

/// Install a dependency-free panic hook (in place of `human-panic`; see
/// `Cargo.toml` for why the crate is not used).
///
/// On panic it prints a friendly, **payload-free** message to stderr telling the
/// user this is a bug and how to report it. The panic *payload* is deliberately
/// never printed: for this app it could contain a descriptor or xpub, and §13.6
/// forbids persisting or logging confidential data. Only the panic *location*
/// (our own `file:line`) and the version are shown, both safe to share.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(
            || "an unknown location".to_owned(),
            |loc| format!("{}:{}", loc.file(), loc.line()),
        );
        eprintln!();
        eprintln!("lifeboat hit an internal error and had to stop. This is a bug, not");
        eprintln!("something you did wrong.");
        eprintln!();
        eprintln!("Please report it at {REPO_ISSUES_URL} so we can fix it.");
        eprintln!("Describe what you were doing, but NEVER paste a real seed phrase,");
        eprintln!("passphrase, or private key into the report.");
        eprintln!();
        eprintln!(
            "Safe technical details: lifeboat v{} panicked at {location}.",
            env!("CARGO_PKG_VERSION"),
        );
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_request_exits_success() {
        assert_eq!(run(["lifeboat", "--version"]), ExitCode::Success);
    }

    #[test]
    fn help_request_exits_success() {
        assert_eq!(run(["lifeboat", "--help"]), ExitCode::Success);
    }

    #[test]
    fn bare_invocation_prints_help_and_exits_success() {
        assert_eq!(run(["lifeboat"]), ExitCode::Success);
    }

    #[test]
    fn unknown_subcommand_exits_10() {
        assert_eq!(run(["lifeboat", "frobnicate"]), ExitCode::UnknownSubcommand);
        assert_eq!(run(["lifeboat", "frobnicate"]).code(), 10);
    }

    #[test]
    fn unknown_flag_exits_4() {
        assert_eq!(run(["lifeboat", "--nope"]), ExitCode::InvalidArgs);
        assert_eq!(run(["lifeboat", "--nope"]).code(), 4);
    }

    #[test]
    fn parse_export_with_a_missing_file_is_a_file_error_not_a_stub() {
        // parse-export is implemented in US-038; a missing file is a real file
        // error (exit 6), proving the handler is wired (no more exit-20 stub) and
        // does not panic. This avoids reading stdin (unlike detect-secrets).
        let code = run([
            "lifeboat",
            "--json",
            "parse-export",
            "--file",
            "/nonexistent/lifeboat/does-not-exist.json",
        ]);
        assert_eq!(code, ExitCode::FileIo);
        assert_eq!(code.code(), 6);
    }

    #[test]
    fn implemented_command_audits_an_inline_descriptor() {
        // End-to-end through `run`: a watch-only singlesig descriptor on testnet
        // produces a scored verdict (not the not-implemented stub, exit 20).
        let descriptor = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/descriptors/singlesig/wpkh_valid.txt"
        ))
        .trim();
        let code = run([
            "lifeboat",
            "--json",
            "audit-descriptor",
            "--descriptor",
            descriptor,
            "--network",
            "testnet",
        ]);
        assert_ne!(code, ExitCode::Internal, "the handler must be wired");
        assert_ne!(code, ExitCode::UnknownSubcommand);
    }

    #[test]
    fn a_panic_during_the_run_becomes_exit_20() {
        // The default panic hook prints to (captured) stderr; the value we assert
        // is that the unwind is caught and mapped to the §23.2 internal code.
        let code = run_caught(|| panic!("simulated internal bug"));
        assert_eq!(code, ExitCode::Internal);
        assert_eq!(code.code(), 20);
    }

    #[test]
    fn issues_url_is_built_from_the_package_repository() {
        assert!(REPO_ISSUES_URL.ends_with("/issues"));
        assert!(REPO_ISSUES_URL.starts_with("https://"));
    }
}
