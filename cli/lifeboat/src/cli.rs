//! The `clap` command surface: global flags, the subcommand list, the `--help`
//! banner, and the color policy.
//!
//! US-035 establishes the *shell* — global flags, exit-code plumbing, the §15.7
//! banner. The [`Commands`] variants name the MVP commands so `--help` lists
//! them and a mistyped command yields exit 10; their handlers (and per-command
//! flags) are filled in by US-036–US-038.

use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::exit::ExitCode;

/// `lifeboat` — test whether a Bitcoin self-custody recovery plan actually works.
#[derive(Debug, Parser)]
#[command(
    name = "lifeboat",
    version,
    about = "Test whether your Bitcoin self-custody recovery plan actually works (offline).",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Flags accepted before or after any subcommand.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The chosen subcommand, or `None` when invoked bare (`lifeboat`).
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Flags available globally (before or after a subcommand).
///
/// Every field is `global = true` so `lifeboat --json audit-descriptor` and
/// `lifeboat audit-descriptor --json` behave identically.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable ANSI colors (also honored via the `NO_COLOR` environment variable).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Suppress non-essential output.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Enable verbose (INFO-level) logging to stderr.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

/// The Bitcoin network to derive on, as accepted by `--network` (§17.10.1).
///
/// A CLI-local enum (kebab-cased by `clap`: `mainnet`/`testnet`/`signet`/
/// `regtest`) so the command surface does not leak a `rust-bitcoin` type; the
/// handler maps it to `address_derive::Network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    /// Bitcoin mainnet.
    Mainnet,
    /// The public test network.
    Testnet,
    /// The Signet test network.
    Signet,
    /// A local regression-test network.
    Regtest,
}

/// Which derivation chain(s) to operate on, as accepted by `--chain` (§17.10.2).
///
/// A CLI-local enum (kebab-cased by `clap`: `receive`/`change`/`both`) so the
/// command surface does not leak the `address_derive::Chain` type; the handler
/// maps `Receive`/`Change` to it and expands `Both` to both chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ChainArg {
    /// External / receive chain only (BIP44 chain index `0`).
    Receive,
    /// Internal / change chain only (BIP44 chain index `1`).
    Change,
    /// Both the receive and change chains (the §17.10.2 default).
    Both,
}

/// The redaction mode for `generate-runbook` (PRD §17.10.4 / §17.7).
///
/// A CLI-local enum (kebab-cased by `clap`: `public-safe`/`private`) so the
/// command surface does not leak the `report_engine::RedactionMode` type; the
/// handler maps it across. `public-safe` is the default (§14.3 / §17.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RunbookModeArg {
    /// Hide the descriptor and hardware-wallet models (the safe default).
    PublicSafe,
    /// Reveal the descriptor and device models (an explicit choice).
    Private,
}

/// The output format for `generate-runbook` (PRD §17.10.4).
///
/// Kebab-cased by `clap` to `pdf`/`md`/`txt`/`html`; `pdf` is the default. The
/// engine renders PDF and Markdown natively; `txt` and `html` are derived from
/// the Markdown by the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RunbookFormatArg {
    /// A printable PDF (the default; requires `--output`, being binary).
    Pdf,
    /// CommonMark Markdown.
    Md,
    /// Plain text (the Markdown with its markup stripped).
    Txt,
    /// A self-contained HTML document.
    Html,
}

/// The shell to emit a completion script for (`completions`, US-039).
///
/// The five shells named by the story. `clap_complete` ships generators for
/// bash/zsh/fish/powershell; nushell comes from `clap_complete_nushell`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    /// GNU Bash.
    Bash,
    /// Z shell.
    Zsh,
    /// fish.
    Fish,
    /// PowerShell (kept lowercase `powershell`, not clap's default `power-shell`).
    #[value(name = "powershell")]
    PowerShell,
    /// Nushell.
    Nushell,
}

/// Flags shared by `audit-descriptor` and `report-json` (PRD §17.10.1 / §17.10.5).
///
/// Exactly one descriptor source is required (`--file` / `--stdin` /
/// `--descriptor`), enforced as a mutually-exclusive required `clap` group. The
/// global `--json` / `--no-color` / `--quiet` / `--verbose` flags ([`GlobalArgs`])
/// are not redeclared here.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
#[command(group(
    ArgGroup::new("descriptor_source")
        .required(true)
        .args(["file", "stdin", "descriptor"]),
))]
pub struct AuditArgs {
    /// Read the descriptor from a file.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Read the descriptor from standard input.
    #[arg(long)]
    pub stdin: bool,

    /// Inline descriptor (avoid in shell history; prefer `--stdin`).
    #[arg(long, value_name = "STRING")]
    pub descriptor: Option<String>,

    /// Compare a known address against the derived range.
    #[arg(long, value_name = "ADDR")]
    pub known_address: Option<String>,

    /// Override the inferred network (`mainnet`/`testnet`/`signet`/`regtest`).
    #[arg(long, value_name = "NET")]
    pub network: Option<NetworkArg>,

    /// Number of receive/change addresses to derive into the report sample.
    #[arg(long, value_name = "N", default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub derive_count: u32,

    /// Exit non-zero on warnings (CI mode): promote a warnings verdict (exit 1)
    /// to critical (exit 2).
    #[arg(long)]
    pub strict: bool,

    /// Pin the scoring-engine version (default: latest).
    #[arg(long, value_name = "VER")]
    pub scoring_engine: Option<String>,
}

/// Flags for `derive-addresses` (PRD §17.10.2).
///
/// The descriptor must be **watch-only** (it is screened for secret material
/// before parsing). `--network` is not in the §17.10.2 signature, but a `tpub`
/// is shared by testnet/signet/regtest and the PRD forbids guessing which one
/// (§16.5); it is offered as an optional override and is *required* only when the
/// network cannot be inferred (a mainnet `xpub` infers `mainnet` on its own).
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct DeriveArgs {
    /// The watch-only output descriptor to derive from.
    #[arg(long, value_name = "STRING")]
    pub descriptor: String,

    /// Number of addresses to derive per chain (1..=1000).
    #[arg(long, value_name = "N", default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub count: u32,

    /// Which chain(s) to derive: `receive`, `change`, or `both`.
    #[arg(long, value_enum, default_value = "both")]
    pub chain: ChainArg,

    /// Resolve the network when it cannot be inferred (a `tpub` is ambiguous).
    #[arg(long, value_name = "NET")]
    pub network: Option<NetworkArg>,
}

/// Flags for `compare-address` (PRD §17.10.3).
///
/// `--search-range` is the per-chain depth searched first; on a miss the search
/// transparently expands to the full gap limit (1000) per §17.5. The network is
/// resolved exactly as for [`DeriveArgs`].
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct CompareArgs {
    /// The watch-only output descriptor to search.
    #[arg(long, value_name = "STRING")]
    pub descriptor: String,

    /// The address to look for in the descriptor's derived range.
    #[arg(long, value_name = "ADDR")]
    pub address: String,

    /// Per-chain addresses to search before expanding to the full gap limit.
    #[arg(long, value_name = "N", default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub search_range: u32,

    /// Resolve the network when it cannot be inferred (a `tpub` is ambiguous).
    #[arg(long, value_name = "NET")]
    pub network: Option<NetworkArg>,
}

/// Flags for `checksum` (PRD §17.10.8): exactly one of `--validate` / `--compute`
/// (a required, mutually-exclusive `clap` group). Each takes the descriptor whose
/// BIP380 checksum is to be validated or computed.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
#[command(group(
    ArgGroup::new("checksum_op")
        .required(true)
        .args(["validate", "compute"]),
))]
pub struct ChecksumArgs {
    /// Validate a descriptor's checksum (exit 0 iff present and valid).
    #[arg(long, value_name = "DESC")]
    pub validate: Option<String>,

    /// Compute a descriptor's checksum and print `descriptor#xxxxxxxx`.
    #[arg(long, value_name = "DESC")]
    pub compute: Option<String>,
}

/// Flags for `detect-secrets` (PRD §17.10.6).
///
/// Screens input for pasted Bitcoin secrets. The input comes from `--file` or
/// standard input; with neither flag it reads standard input (the §17.10 "pipe
/// text via stdin" path), so `--stdin` is an explicit opt-in. The two sources are
/// mutually exclusive. The global `--json` selects the §19.4 DetectorReport JSON.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
#[command(group(
    ArgGroup::new("secret_source").args(["file", "stdin"]),
))]
pub struct DetectSecretsArgs {
    /// Scan a file's contents (instead of standard input).
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Scan standard input (the default when no `--file` is given).
    #[arg(long)]
    pub stdin: bool,
}

/// A wallet-export format for `parse-export` (PRD §17.10.7).
///
/// Kebab-cased by `clap` to the §17.10.7 value list
/// (`auto`/`sparrow`/`specter`/`coldcard`/`nunchuk`/`jade`/`liana`/`core`).
/// `Auto` sniffs the content; `Coldcard` accepts both the JSON "Generic Wallet
/// Export" and the descriptor-file text export. A CLI-local enum so the surface
/// does not leak a `wallet-imports` type; the handler maps it to the importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Detect the format by sniffing the file content.
    Auto,
    /// Sparrow keystore-based wallet JSON.
    Sparrow,
    /// Specter wallet-settings JSON.
    Specter,
    /// Coldcard export (Generic Wallet JSON or descriptor-file text).
    Coldcard,
    /// Nunchuk BSMS (BIP129) text record.
    Nunchuk,
    /// Blockstream Jade registered-multisig JSON.
    Jade,
    /// Liana encrypted `.bed` backup (needs `--decryption-input`).
    Liana,
    /// Bitcoin Core `listdescriptors` JSON.
    Core,
}

/// Flags for `parse-export` (PRD §17.10.7).
///
/// `--file` is required; `--format` selects the importer (default `auto`).
/// `--decryption-input` supplies a wallet xpub that can open an encrypted export
/// (Liana `.bed`) and may be repeated; other formats ignore it. (`--decryption-input`
/// is not in the §17.10.7 signature but is required to open an encrypted backup —
/// the same kind of necessary, documented addition as US-037's `--network`.)
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ParseExportArgs {
    /// The wallet-export file to parse and normalize.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// The export format (default: auto-detect by content).
    #[arg(long, value_enum, default_value = "auto")]
    pub format: ExportFormat,

    /// A wallet xpub that can decrypt an encrypted export (Liana `.bed`); repeatable.
    #[arg(long = "decryption-input", value_name = "XPUB")]
    pub decryption_inputs: Vec<String>,
}

/// Flags for `generate-runbook` (PRD §17.10.4).
///
/// `--template` selects one of the bundled runbook templates (the owner
/// singlesig/multisig set and the heir/workshop/business set). `--descriptor` is
/// optional: when given it is screened for secrets and used to pre-fill the
/// wallet summary and signer list; when omitted the runbook is a blank template
/// for manual fill-in. `--mode` defaults to `public-safe`, `--format` to `pdf`.
/// `--output` writes to a file (required for `pdf`, which is binary).
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct GenerateRunbookArgs {
    /// The template id, e.g. `singlesig-basic` or `heir-multisig-2of3`.
    #[arg(long, value_name = "ID")]
    pub template: String,

    /// A watch-only descriptor used to pre-fill the runbook (optional).
    #[arg(long, value_name = "STRING")]
    pub descriptor: Option<String>,

    /// Write the runbook to this file instead of standard output.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Redaction mode (default: `public-safe`).
    #[arg(long, value_enum, default_value = "public-safe")]
    pub mode: RunbookModeArg,

    /// Output format (default: `pdf`).
    #[arg(long, value_enum, default_value = "pdf")]
    pub format: RunbookFormatArg,
}

/// Flags for `completions` (US-039): the shell to generate a completion script
/// for, as a required positional (e.g. `lifeboat completions bash`).
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct CompletionsArgs {
    /// The shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: CompletionShell,
}

/// Nested PSBT command surface (US-077).
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct PsbtArgs {
    /// The PSBT operation to run.
    #[command(subcommand)]
    pub command: PsbtCommand,
}

/// PSBT file operations that do not require wallet state.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum PsbtCommand {
    /// Inspect a base64 BIP174 v0 or BIP370 v2 PSBT file.
    Inspect(PsbtInspectArgs),
    /// Validate that a PSBT file is parseable and supported.
    Validate(PsbtValidateArgs),
    /// Extract the transaction from an already-finalized PSBT.
    ExtractTx(PsbtExtractTxArgs),
}

/// Flags for `psbt inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct PsbtInspectArgs {
    /// Base64 PSBT file to inspect.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Decode output addresses on this network when possible.
    #[arg(long, value_name = "NET")]
    pub network: Option<NetworkArg>,
}

/// Flags for `psbt validate`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct PsbtValidateArgs {
    /// Base64 PSBT file to validate.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Decode output addresses on this network when possible.
    #[arg(long, value_name = "NET")]
    pub network: Option<NetworkArg>,
}

/// Flags for `psbt extract-tx`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct PsbtExtractTxArgs {
    /// Base64 finalized PSBT file.
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Write the extracted transaction hex to a file instead of stdout.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

/// Flags for `verify-build` (US-098).
///
/// The release version is positional so the common command is
/// `lifeboat verify-build v0.1.0`. By default the command reads `SHA256SUMS` in
/// the current directory (or fetches it from the configured GitHub Release if the
/// file is absent) and checks local files whose names appear in that manifest.
/// `--artifact` narrows the check to one or more explicit local files.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct VerifyBuildArgs {
    /// Release tag to verify, for example `v0.1.0-alpha.1`.
    #[arg(value_name = "VERSION")]
    pub version: String,

    /// Local artifact to hash and compare. Repeat for multiple artifacts.
    #[arg(long = "artifact", value_name = "PATH")]
    pub artifacts: Vec<PathBuf>,

    /// Published SHA256SUMS file. Defaults to ./SHA256SUMS, then the release URL.
    #[arg(long, value_name = "PATH")]
    pub checksums: Option<PathBuf>,

    /// Override the release download base URL that contains SHA256SUMS.
    #[arg(long, value_name = "URL")]
    pub release_base_url: Option<String>,
}

/// The MVP subcommands. Variant names render to kebab-case (`AuditDescriptor` →
/// `audit-descriptor`). Handlers arrive in the stories noted on each variant;
/// implemented commands carry their flags as [`AuditArgs`].
#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum Commands {
    /// Audit a wallet output descriptor for recovery readiness (US-036).
    AuditDescriptor(AuditArgs),
    /// Emit the full machine-readable readiness report as JSON (US-036).
    ReportJson(AuditArgs),
    /// Derive receive/change addresses from a descriptor (US-037).
    DeriveAddresses(DeriveArgs),
    /// Check whether an address belongs to a descriptor (US-037).
    CompareAddress(CompareArgs),
    /// Validate or compute a descriptor checksum (US-037).
    Checksum(ChecksumArgs),
    /// Scan input for sensitive material without echoing it (US-038).
    DetectSecrets(DetectSecretsArgs),
    /// Parse and normalize a wallet export file (US-038).
    ParseExport(ParseExportArgs),
    /// Generate a recovery / inheritance runbook (US-039).
    GenerateRunbook(GenerateRunbookArgs),
    /// Inspect and validate PSBT files for recovery drills (US-077).
    Psbt(PsbtArgs),
    /// Compare local build artifacts to the release SHA256SUMS (US-098).
    VerifyBuild(VerifyBuildArgs),
    /// Print a shell-completion script for the CLI (US-039).
    Completions(CompletionsArgs),
    /// Print the manual page (roff) for the CLI (US-039).
    Man,
}

impl Commands {
    /// The kebab-case name the user typed, for diagnostics.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AuditDescriptor(_) => "audit-descriptor",
            Self::ReportJson(_) => "report-json",
            Self::DeriveAddresses(_) => "derive-addresses",
            Self::CompareAddress(_) => "compare-address",
            Self::Checksum(_) => "checksum",
            Self::DetectSecrets(_) => "detect-secrets",
            Self::ParseExport(_) => "parse-export",
            Self::GenerateRunbook(_) => "generate-runbook",
            Self::Psbt(_) => "psbt",
            Self::VerifyBuild(_) => "verify-build",
            Self::Completions(_) => "completions",
            Self::Man => "man",
        }
    }
}

/// Build the augmented `clap` command with the §15.7 "not a wallet" banner.
///
/// The banner text is the single-source [`NOT_A_WALLET`] const, reused verbatim
/// (never re-transcribed) and injected at runtime via `before_long_help` so it
/// appears in `lifeboat --help` (long help). Both `main` and the help/banner
/// tests build the command through here so they cannot drift.
///
/// [`NOT_A_WALLET`]: lifeboat_core::report_engine::NOT_A_WALLET
#[must_use]
pub fn build_command() -> clap::Command {
    Cli::command().before_long_help(lifeboat_core::report_engine::NOT_A_WALLET)
}

/// Decide whether ANSI color should be used for the program's own output.
///
/// Color is enabled only when it is not explicitly disabled — by `--no-color`
/// (`no_color_flag`) or by a non-empty `NO_COLOR` environment variable
/// (`no_color_env`) — *and* the output stream is a terminal (`is_terminal`), so
/// piped/redirected output is never colored. Pure function for testability; the
/// live wrappers [`no_color_env`] and [`stdout_is_terminal`] read the
/// environment and the stdout handle.
#[must_use]
pub fn use_color(no_color_flag: bool, no_color_env: bool, is_terminal: bool) -> bool {
    !no_color_flag && !no_color_env && is_terminal
}

/// Whether the `NO_COLOR` environment variable disables color.
///
/// Per the `NO_COLOR` convention, color is disabled when the variable is present
/// **and** non-empty (an empty value does not disable color).
#[must_use]
pub fn no_color_env() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
}

/// Whether standard output is connected to a terminal.
#[must_use]
pub fn stdout_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Map a `clap` parse failure to its exit code (§23.2 rows 4 and 10).
///
/// A `--help`/`--version` request is an intentional, successful invocation
/// (exit 0, after clap prints the text); a mistyped subcommand is exit 10;
/// anything else is a bad-arguments error (exit 4).
#[must_use]
pub fn exit_code_for_clap_error(kind: ErrorKind) -> ExitCode {
    match kind {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => ExitCode::Success,
        ErrorKind::InvalidSubcommand => ExitCode::UnknownSubcommand,
        _ => ExitCode::InvalidArgs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_command_definition_is_valid() {
        // `debug_assert` walks the whole command tree and panics on a malformed
        // definition (duplicate flags, bad arg relationships, etc.).
        build_command().debug_assert();
    }

    #[test]
    fn parses_each_global_flag() {
        let cli = Cli::try_parse_from(["lifeboat", "--json"]).unwrap();
        assert!(cli.global.json);
        assert!(!cli.global.no_color);
        assert!(cli.command.is_none());

        let cli = Cli::try_parse_from(["lifeboat", "--no-color"]).unwrap();
        assert!(cli.global.no_color);

        let cli = Cli::try_parse_from(["lifeboat", "--quiet"]).unwrap();
        assert!(cli.global.quiet);

        let cli = Cli::try_parse_from(["lifeboat", "--verbose"]).unwrap();
        assert!(cli.global.verbose);
    }

    #[test]
    fn short_flags_and_combinations_parse() {
        let cli = Cli::try_parse_from(["lifeboat", "-q"]).unwrap();
        assert!(cli.global.quiet);

        let cli = Cli::try_parse_from(["lifeboat", "-v"]).unwrap();
        assert!(cli.global.verbose);

        // Several global flags together.
        let cli = Cli::try_parse_from(["lifeboat", "--json", "--no-color", "--verbose"]).unwrap();
        assert!(cli.global.json && cli.global.no_color && cli.global.verbose);
    }

    #[test]
    fn global_flags_work_before_and_after_a_subcommand() {
        // `audit-descriptor` now requires a descriptor source, so supply one.
        let before = Cli::try_parse_from([
            "lifeboat",
            "--json",
            "audit-descriptor",
            "--descriptor",
            "DESC",
        ])
        .unwrap();
        let after = Cli::try_parse_from([
            "lifeboat",
            "audit-descriptor",
            "--descriptor",
            "DESC",
            "--json",
        ])
        .unwrap();
        assert!(before.global.json && after.global.json);
        assert!(matches!(before.command, Some(Commands::AuditDescriptor(_))));
        assert!(matches!(after.command, Some(Commands::AuditDescriptor(_))));
    }

    #[test]
    fn every_mvp_subcommand_parses_to_its_variant() {
        // `detect-secrets` parses bare (it defaults to reading standard input).
        let detect = Cli::try_parse_from(["lifeboat", "detect-secrets"]).unwrap();
        assert!(matches!(detect.command, Some(Commands::DetectSecrets(_))));
        assert_eq!(detect.command.as_ref().unwrap().name(), "detect-secrets");

        // `parse-export` carries flags and requires a `--file` source.
        let parse = Cli::try_parse_from(["lifeboat", "parse-export", "--file", "w.json"]).unwrap();
        assert!(matches!(parse.command, Some(Commands::ParseExport(_))));
        assert_eq!(parse.command.as_ref().unwrap().name(), "parse-export");

        // `audit-descriptor` / `report-json` carry flags and require a source.
        let audit =
            Cli::try_parse_from(["lifeboat", "audit-descriptor", "--descriptor", "DESC"]).unwrap();
        assert!(matches!(audit.command, Some(Commands::AuditDescriptor(_))));
        assert_eq!(audit.command.as_ref().unwrap().name(), "audit-descriptor");

        let report =
            Cli::try_parse_from(["lifeboat", "report-json", "--descriptor", "DESC"]).unwrap();
        assert!(matches!(report.command, Some(Commands::ReportJson(_))));
        assert_eq!(report.command.as_ref().unwrap().name(), "report-json");

        // The US-037 utilities carry flags too; each maps to its kebab name.
        let derive =
            Cli::try_parse_from(["lifeboat", "derive-addresses", "--descriptor", "DESC"]).unwrap();
        assert!(matches!(derive.command, Some(Commands::DeriveAddresses(_))));
        assert_eq!(derive.command.as_ref().unwrap().name(), "derive-addresses");

        let compare = Cli::try_parse_from([
            "lifeboat",
            "compare-address",
            "--descriptor",
            "DESC",
            "--address",
            "ADDR",
        ])
        .unwrap();
        assert!(matches!(compare.command, Some(Commands::CompareAddress(_))));
        assert_eq!(compare.command.as_ref().unwrap().name(), "compare-address");

        let checksum = Cli::try_parse_from(["lifeboat", "checksum", "--compute", "DESC"]).unwrap();
        assert!(matches!(checksum.command, Some(Commands::Checksum(_))));
        assert_eq!(checksum.command.as_ref().unwrap().name(), "checksum");

        let psbt = Cli::try_parse_from([
            "lifeboat",
            "psbt",
            "inspect",
            "--file",
            "fixtures/psbt/bip174_updated_v0.txt",
        ])
        .unwrap();
        assert!(matches!(psbt.command, Some(Commands::Psbt(_))));
        assert_eq!(psbt.command.as_ref().unwrap().name(), "psbt");

        let verify = Cli::try_parse_from(["lifeboat", "verify-build", "v0.1.0"]).unwrap();
        assert!(matches!(verify.command, Some(Commands::VerifyBuild(_))));
        assert_eq!(verify.command.as_ref().unwrap().name(), "verify-build");
    }

    #[test]
    fn psbt_subcommands_parse() {
        let inspect = Cli::try_parse_from([
            "lifeboat",
            "psbt",
            "inspect",
            "--file",
            "unsigned.psbt",
            "--network",
            "signet",
        ])
        .unwrap();
        let Some(Commands::Psbt(args)) = inspect.command else {
            panic!("expected psbt command");
        };
        let PsbtCommand::Inspect(args) = args.command else {
            panic!("expected psbt inspect");
        };
        assert_eq!(args.file, PathBuf::from("unsigned.psbt"));
        assert_eq!(args.network, Some(NetworkArg::Signet));

        let validate =
            Cli::try_parse_from(["lifeboat", "psbt", "validate", "--file", "updated.psbt"])
                .unwrap();
        assert!(matches!(
            validate.command,
            Some(Commands::Psbt(PsbtArgs {
                command: PsbtCommand::Validate(_)
            }))
        ));

        let extract = Cli::try_parse_from([
            "lifeboat",
            "psbt",
            "extract-tx",
            "--file",
            "final.psbt",
            "--output",
            "tx.hex",
        ])
        .unwrap();
        assert!(matches!(
            extract.command,
            Some(Commands::Psbt(PsbtArgs {
                command: PsbtCommand::ExtractTx(_)
            }))
        ));
    }

    #[test]
    fn verify_build_parses_version_and_optional_sources() {
        let cli = Cli::try_parse_from([
            "lifeboat",
            "verify-build",
            "v0.1.0-alpha.1",
            "--artifact",
            "bitcoin-lifeboat-v0.1.0-alpha.1-linux.AppImage",
            "--artifact",
            "bitcoin-lifeboat-v0.1.0-alpha.1-source.tar.gz",
            "--checksums",
            "SHA256SUMS",
            "--release-base-url",
            "https://example.invalid/releases/download/v0.1.0-alpha.1",
        ])
        .unwrap();
        let Some(Commands::VerifyBuild(args)) = cli.command else {
            panic!("expected verify-build");
        };
        assert_eq!(args.version, "v0.1.0-alpha.1");
        assert_eq!(args.artifacts.len(), 2);
        assert_eq!(
            args.checksums.as_deref(),
            Some(std::path::Path::new("SHA256SUMS"))
        );
        assert_eq!(
            args.release_base_url.as_deref(),
            Some("https://example.invalid/releases/download/v0.1.0-alpha.1")
        );
    }

    #[test]
    fn derive_addresses_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "lifeboat",
            "derive-addresses",
            "--descriptor",
            "DESC",
            "--count",
            "5",
            "--chain",
            "receive",
            "--network",
            "signet",
        ])
        .unwrap();
        let Some(Commands::DeriveAddresses(args)) = cli.command else {
            panic!("expected derive-addresses");
        };
        assert_eq!(args.descriptor, "DESC");
        assert_eq!(args.count, 5);
        assert_eq!(args.chain, ChainArg::Receive);
        assert_eq!(args.network, Some(NetworkArg::Signet));
    }

    #[test]
    fn derive_addresses_defaults_count_to_10_and_chain_to_both() {
        let cli =
            Cli::try_parse_from(["lifeboat", "derive-addresses", "--descriptor", "DESC"]).unwrap();
        let Some(Commands::DeriveAddresses(args)) = cli.command else {
            panic!("expected derive-addresses");
        };
        assert_eq!(args.count, 10);
        assert_eq!(args.chain, ChainArg::Both);
        assert_eq!(args.network, None);
    }

    #[test]
    fn derive_addresses_requires_a_descriptor() {
        assert!(Cli::try_parse_from(["lifeboat", "derive-addresses"]).is_err());
    }

    #[test]
    fn derive_count_rejects_out_of_range() {
        assert!(Cli::try_parse_from([
            "lifeboat",
            "derive-addresses",
            "--descriptor",
            "DESC",
            "--count",
            "0",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "lifeboat",
            "derive-addresses",
            "--descriptor",
            "DESC",
            "--count",
            "1001",
        ])
        .is_err());
    }

    #[test]
    fn compare_address_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "lifeboat",
            "compare-address",
            "--descriptor",
            "DESC",
            "--address",
            "tb1qexample",
            "--search-range",
            "50",
            "--network",
            "testnet",
        ])
        .unwrap();
        let Some(Commands::CompareAddress(args)) = cli.command else {
            panic!("expected compare-address");
        };
        assert_eq!(args.descriptor, "DESC");
        assert_eq!(args.address, "tb1qexample");
        assert_eq!(args.search_range, 50);
        assert_eq!(args.network, Some(NetworkArg::Testnet));
    }

    #[test]
    fn compare_address_requires_descriptor_and_address() {
        // Missing --address.
        assert!(
            Cli::try_parse_from(["lifeboat", "compare-address", "--descriptor", "DESC"]).is_err()
        );
        // Missing --descriptor.
        assert!(Cli::try_parse_from(["lifeboat", "compare-address", "--address", "ADDR"]).is_err());
    }

    #[test]
    fn checksum_requires_exactly_one_operation() {
        // Neither --validate nor --compute → error.
        assert!(Cli::try_parse_from(["lifeboat", "checksum"]).is_err());
        // Both → error (the group is mutually exclusive).
        assert!(Cli::try_parse_from([
            "lifeboat",
            "checksum",
            "--validate",
            "DESC",
            "--compute",
            "DESC",
        ])
        .is_err());
        // Exactly one → ok.
        assert!(Cli::try_parse_from(["lifeboat", "checksum", "--validate", "DESC"]).is_ok());
        assert!(Cli::try_parse_from(["lifeboat", "checksum", "--compute", "DESC"]).is_ok());
    }

    #[test]
    fn audit_requires_exactly_one_descriptor_source() {
        // No source → error.
        assert!(Cli::try_parse_from(["lifeboat", "audit-descriptor"]).is_err());
        // Two sources → error (the group is mutually exclusive).
        assert!(Cli::try_parse_from([
            "lifeboat",
            "audit-descriptor",
            "--descriptor",
            "DESC",
            "--stdin",
        ])
        .is_err());
        // Exactly one → ok.
        assert!(Cli::try_parse_from(["lifeboat", "audit-descriptor", "--stdin"]).is_ok());
    }

    #[test]
    fn audit_parses_all_shared_flags() {
        let cli = Cli::try_parse_from([
            "lifeboat",
            "audit-descriptor",
            "--descriptor",
            "DESC",
            "--known-address",
            "tb1qexample",
            "--network",
            "signet",
            "--derive-count",
            "7",
            "--strict",
            "--scoring-engine",
            "0.1.0",
        ])
        .unwrap();
        let Some(Commands::AuditDescriptor(args)) = cli.command else {
            panic!("expected audit-descriptor");
        };
        assert_eq!(args.descriptor.as_deref(), Some("DESC"));
        assert_eq!(args.known_address.as_deref(), Some("tb1qexample"));
        assert_eq!(args.network, Some(NetworkArg::Signet));
        assert_eq!(args.derive_count, 7);
        assert!(args.strict);
        assert_eq!(args.scoring_engine.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn derive_count_rejects_zero_and_overflow() {
        assert!(
            Cli::try_parse_from(["lifeboat", "report-json", "--stdin", "--derive-count", "0"])
                .is_err()
        );
        assert!(Cli::try_parse_from([
            "lifeboat",
            "report-json",
            "--stdin",
            "--derive-count",
            "100000",
        ])
        .is_err());
    }

    #[test]
    fn unknown_flag_and_unknown_subcommand_are_distinct_errors() {
        let unknown_flag =
            Cli::try_parse_from(["lifeboat", "--definitely-not-a-flag"]).unwrap_err();
        assert_eq!(
            exit_code_for_clap_error(unknown_flag.kind()),
            ExitCode::InvalidArgs
        );

        let unknown_cmd = Cli::try_parse_from(["lifeboat", "frobnicate"]).unwrap_err();
        assert_eq!(unknown_cmd.kind(), ErrorKind::InvalidSubcommand);
        assert_eq!(
            exit_code_for_clap_error(unknown_cmd.kind()),
            ExitCode::UnknownSubcommand
        );
    }

    #[test]
    fn help_and_version_requests_map_to_success() {
        let help = Cli::try_parse_from(["lifeboat", "--help"]).unwrap_err();
        assert_eq!(exit_code_for_clap_error(help.kind()), ExitCode::Success);

        let version = Cli::try_parse_from(["lifeboat", "--version"]).unwrap_err();
        assert_eq!(exit_code_for_clap_error(version.kind()), ExitCode::Success);
    }

    #[test]
    fn long_help_contains_the_verbatim_not_a_wallet_banner() {
        let rendered = build_command().render_long_help().to_string();
        // The whole §15.7 paragraph must appear verbatim in `--help`.
        assert!(
            rendered.contains(lifeboat_core::report_engine::NOT_A_WALLET),
            "long help is missing the verbatim §15.7 banner:\n{rendered}"
        );
        assert!(rendered.contains("is not a wallet"));
    }

    #[test]
    fn version_string_is_the_package_version() {
        let rendered = build_command().render_version();
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn detect_secrets_parses_bare_and_with_a_source() {
        // Bare: defaults to standard input.
        let bare = Cli::try_parse_from(["lifeboat", "detect-secrets"]).unwrap();
        assert!(matches!(bare.command, Some(Commands::DetectSecrets(_))));
        // `--file` or `--stdin` individually are fine.
        assert!(Cli::try_parse_from(["lifeboat", "detect-secrets", "--stdin"]).is_ok());
        assert!(Cli::try_parse_from(["lifeboat", "detect-secrets", "--file", "in.txt"]).is_ok());
        // The two sources are mutually exclusive.
        assert!(Cli::try_parse_from(
            ["lifeboat", "detect-secrets", "--file", "in.txt", "--stdin",]
        )
        .is_err());
    }

    #[test]
    fn parse_export_requires_a_file_and_defaults_format_to_auto() {
        // Missing `--file` → error.
        assert!(Cli::try_parse_from(["lifeboat", "parse-export"]).is_err());

        let cli = Cli::try_parse_from(["lifeboat", "parse-export", "--file", "w.json"]).unwrap();
        let Some(Commands::ParseExport(args)) = cli.command else {
            panic!("expected parse-export");
        };
        assert_eq!(args.format, ExportFormat::Auto);
        assert!(args.decryption_inputs.is_empty());
    }

    #[test]
    fn parse_export_parses_format_and_repeated_decryption_inputs() {
        let cli = Cli::try_parse_from([
            "lifeboat",
            "parse-export",
            "--file",
            "w.bed",
            "--format",
            "liana",
            "--decryption-input",
            "tpubAAA",
            "--decryption-input",
            "tpubBBB",
        ])
        .unwrap();
        let Some(Commands::ParseExport(args)) = cli.command else {
            panic!("expected parse-export");
        };
        assert_eq!(args.format, ExportFormat::Liana);
        assert_eq!(args.decryption_inputs, vec!["tpubAAA", "tpubBBB"]);
    }

    #[test]
    fn every_export_format_value_parses_and_unknown_is_rejected() {
        for value in [
            "auto", "sparrow", "specter", "coldcard", "nunchuk", "jade", "liana", "core",
        ] {
            assert!(
                Cli::try_parse_from(
                    ["lifeboat", "parse-export", "--file", "w", "--format", value,]
                )
                .is_ok(),
                "--format {value} should parse"
            );
        }
        // A format not in the §17.10.7 list (auto handles it) is rejected.
        assert!(Cli::try_parse_from([
            "lifeboat",
            "parse-export",
            "--file",
            "w",
            "--format",
            "electrum",
        ])
        .is_err());
    }

    #[test]
    fn color_policy_honors_flag_env_and_tty() {
        // On only when nothing disables it and we are at a terminal.
        assert!(use_color(false, false, true));
        // `--no-color` disables.
        assert!(!use_color(true, false, true));
        // `NO_COLOR` disables.
        assert!(!use_color(false, true, true));
        // Piped output (not a terminal) is never colored.
        assert!(!use_color(false, false, false));
    }

    #[test]
    fn generate_runbook_parses_flags_and_defaults() {
        // Template only: mode defaults to public-safe, format to pdf.
        let cli = Cli::try_parse_from([
            "lifeboat",
            "generate-runbook",
            "--template",
            "singlesig-basic",
        ])
        .unwrap();
        let Some(Commands::GenerateRunbook(args)) = cli.command else {
            panic!("expected generate-runbook");
        };
        assert_eq!(args.template, "singlesig-basic");
        assert_eq!(args.mode, RunbookModeArg::PublicSafe);
        assert_eq!(args.format, RunbookFormatArg::Pdf);
        assert!(args.descriptor.is_none());
        assert!(args.output.is_none());

        // All flags, including private mode and the md format.
        let cli = Cli::try_parse_from([
            "lifeboat",
            "generate-runbook",
            "--template",
            "heir-multisig-2of3",
            "--descriptor",
            "DESC",
            "--output",
            "out.md",
            "--mode",
            "private",
            "--format",
            "md",
        ])
        .unwrap();
        let Some(Commands::GenerateRunbook(args)) = cli.command else {
            panic!("expected generate-runbook");
        };
        assert_eq!(args.template, "heir-multisig-2of3");
        assert_eq!(args.descriptor.as_deref(), Some("DESC"));
        assert_eq!(args.output.as_deref(), Some(std::path::Path::new("out.md")));
        assert_eq!(args.mode, RunbookModeArg::Private);
        assert_eq!(args.format, RunbookFormatArg::Md);
    }

    #[test]
    fn generate_runbook_requires_a_template() {
        assert!(Cli::try_parse_from(["lifeboat", "generate-runbook"]).is_err());
    }

    #[test]
    fn generate_runbook_rejects_an_unknown_format() {
        assert!(Cli::try_parse_from([
            "lifeboat",
            "generate-runbook",
            "--template",
            "singlesig-basic",
            "--format",
            "docx",
        ])
        .is_err());
    }

    #[test]
    fn completions_parses_every_named_shell() {
        for (value, expected) in [
            ("bash", CompletionShell::Bash),
            ("zsh", CompletionShell::Zsh),
            ("fish", CompletionShell::Fish),
            ("powershell", CompletionShell::PowerShell),
            ("nushell", CompletionShell::Nushell),
        ] {
            let cli = Cli::try_parse_from(["lifeboat", "completions", value]).unwrap();
            let Some(Commands::Completions(args)) = cli.command else {
                panic!("expected completions for {value}");
            };
            assert_eq!(args.shell, expected);
        }
        // A required positional: bare `completions` errors; an unknown shell errors.
        assert!(Cli::try_parse_from(["lifeboat", "completions"]).is_err());
        assert!(Cli::try_parse_from(["lifeboat", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn man_parses_as_a_bare_subcommand() {
        let cli = Cli::try_parse_from(["lifeboat", "man"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Man)));
        assert_eq!(cli.command.as_ref().unwrap().name(), "man");
    }
}
