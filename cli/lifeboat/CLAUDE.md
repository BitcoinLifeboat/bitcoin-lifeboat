# cli/lifeboat — the `lifeboat` command-line interface

Binary crate (`[[bin]] lifeboat`) built on clap 4. US-035 established the shell;
US-036–US-038 add subcommand handlers. Three modules:

- `exit.rs` — the PRD §23.2 exit-code table (`ExitCode`) and the verdict/error mappings.
- `cli.rs`  — the clap command surface, the `--help` banner, the color policy, the clap-error mapping.
- `main.rs` — entry point, the panic hook, `run()`, and `dispatch()`.

## Hard rules

- **Consume `lifeboat-core` ONLY.** All Bitcoin/scoring/report/detector logic is
  reached through the `lifeboat_core::<crate>` façade (US-034). The CLI never
  parses descriptors, derives addresses, validates checksums, detects secrets, or
  does crypto itself (Codebase Pattern: all Bitcoin logic lives in Rust core
  crates; the CLI is a presentation layer).
- **Exit codes are stable forever (§23.1).** Never change an `ExitCode`
  discriminant. They are the script/CI contract.
- **Reuse, don't re-transcribe normative text.** The `--help` banner is
  `report_engine::NOT_A_WALLET` (§15.7), injected via `build_command()`. Any
  rendered output a later story adds MUST pass `report_engine::passes_anti_overclaim_lint`.

## Exit codes (`exit.rs`) — US-036+ MUST reuse these, not re-derive

- `ExitCode` is `#[repr(u8)]`; `code()` is the number the shell sees. §23.2:
  `0` Ready · `1` warnings · `2` critical/not-ready · `3` cannot-determine ·
  `4` invalid-args · `5` secret-detected · `6` file/IO · `7` dep-missing ·
  `10` unknown-subcommand · `20` internal/panic.
- `ExitCode::from_status(status, strict)` — a scored verdict → rows 0–3.
  `strict` promotes warnings (1) → critical (2); `--strict` "treats exit-1 as
  exit-2" and leaves NotReady/CannotDetermine alone. **The audit/report commands
  drive their exit code through here** (a parse failure becomes a NotReady
  *verdict* = exit 2, not a raw error).
- `ExitCode::from_error(&LifeboatError)` / `from_error_code(ErrorCode)` — a hard
  error → rows 4–7/20. `ErrorCode` is `#[non_exhaustive]`, so the match lists all
  current codes explicitly + `_ => Internal`; `every_error_code_has_a_defined_exit_code`
  pins that every shipping code lands on a table value. `E-SECRET-*` and
  `E-PARSE-005` (private key) → 5; `E-FS-*` → 6; `E-DEP-*` → 7; internal +
  can't-happen-offline (network/link) → 20; the rest → 4.
- `cli::exit_code_for_clap_error(kind)` — clap parse failures → rows 4/10.
  `DisplayHelp`/`DisplayVersion` → 0 (after clap prints), `InvalidSubcommand` →
  10, everything else → 4.

## Command surface (`cli.rs`)

- `Cli` (Parser) = `GlobalArgs` (flattened) + `Option<Commands>`. Bare `lifeboat`
  → `command: None` → prints long help (with the banner), exit 0.
- `GlobalArgs` fields are all `#[arg(global = true)]` so a flag works before OR
  after a subcommand. **Read every global flag somewhere** or `-D warnings` trips
  `field is never read` (clap WRITES them; a write is not a read): `dispatch`
  reads `json`/`quiet`/`verbose`, `run` reads `no_color` via `use_color`.
- `Commands` variants render to kebab-case (`AuditDescriptor` → `audit-descriptor`).
  US-035 ships them as **unit-variant stubs** so `--help` lists them and a typo →
  exit 10. **US-036+ replace a variant with a struct variant carrying its flags
  and implement the handler in `dispatch`** (changing a unit→struct variant is a
  clean edit; `Commands::name()` must keep returning the kebab string).
- `build_command()` returns the augmented `clap::Command` with the banner; both
  `main` and the banner test go through it so they can't drift.
- Color: `use_color(no_color_flag, no_color_env, is_terminal)` is the pure
  decision (off if `--no-color`, or a non-empty `NO_COLOR`, or not a TTY); the
  live wrappers are `no_color_env()` / `stdout_is_terminal()`. clap's own
  help/error coloring already honors `NO_COLOR` via anstream.

## Command handlers (`commands.rs`) — US-036+

- **Handlers are pure and return a `CommandOutput { stdout, stderr, code }`**;
  `main::emit` does the actual printing. So a handler is unit-tested by calling
  it and asserting on the struct — no process spawn, no stream capture. The CLI
  is a bin (no lib), so end-to-end tests live in `#[cfg(test)]` here, not in
  `tests/`.
- **`created_at` and `app_version` are parameters**, not read from the clock /
  `CARGO_PKG_VERSION` inside the handler — so tests pin them (`"2024-01-15T…"`,
  `"0.1.0"`) and golden output stays byte-identical. `main` reads the wall clock
  via `commands::now_iso8601()` (Hinnant `civil_from_days`, no date crate — same
  approach as `wallet-imports`) and passes `report_engine::APP_VERSION`.
- **The pipeline is shared** (`prepare_report`): validate `--scoring-engine` →
  resolve input (`--file`/`--stdin`/`--descriptor`) → **screen for secrets BEFORE
  parsing** → `parse_descriptor` → `build_report`. `audit-descriptor` then renders
  human (or report JSON under global `--json`); `report-json` always emits report
  JSON.
- **Secret screening reuses `detect_secret(SecretString)`** (never re-wrap). A
  `Block` → exit 5 and the input is never echoed (only its `E-SECRET-*` reason
  code is reported); `Warn`/`Allow` proceed (a watch-only descriptor is `Allow`).
- **A parse failure is a Not Ready *verdict* (exit 2)**, not a raw error — routed
  through `ExitCode::Critical` (= `from_status(NotReady)`). report-json emits a
  compact `{"status":"not_ready","error":{…}}` object for unparseable input (a
  §19.1 report needs a parsed descriptor); golden tests cover only valid fixtures.
- **Leak-free errors**: error/verdict messages use only `ErrorCode` catalog text
  (`as_str`/`title`/`description`/`action`) and our own safe context (a file
  path) — never the descriptor, the secret, or a chained library error. Small
  machine-readable JSON objects are built with `serde_json::json!` (proper
  escaping), not by hand.
- **`--derive-count`** is honored by an additive `ReportInput::with_derive_count`
  in `report-engine` (defaults to the engine's internal sample, so existing
  callers/snapshots are byte-identical; it changes `report_hash` but not
  `input_hash`). The CLI defaults it to 10 (§17.10.1).
- **Exit codes go through §23.2 / `ExitCode::from_status`** (the local §17.10.1
  table in the PRD conflicts with §23.2; §23.2 is canonical and cross-version
  stable, already pinned in `exit.rs`). `--strict` promotes a warnings verdict
  (1) to critical (2) and leaves NotReady/CannotDetermine alone.
- **Tests**: insta snapshots for human + report-json output (`src/snapshots/`,
  regenerate with `INSTA_UPDATE=always cargo +1.78.0 test -p lifeboat`); plus a
  determinism test (two runs byte-identical), an equals-`build_report` test, and
  an anti-overclaim-lint assertion over the rendered human output. Shared audit
  flags are a single `AuditArgs` flattened into both struct variants.

## Utility commands (`commands.rs`) — US-037 (`derive-addresses` / `compare-address` / `checksum`)

- **Pure `(args, &GlobalArgs) -> CommandOutput`** — no `created_at`/`app_version`
  params: these utilities do **not** build a §19.1 report, so dispatch passes only
  `&args, global` (no clock read). They still screen every descriptor input for
  secrets via `screen_for_secrets` before parsing/processing.
- **`checksum --compute` MUST screen first.** It echoes the descriptor back, so an
  `xprv` has to be `Block`ed (exit 5, never printed) *before* `compute_checksum`
  runs — `checksum_blocks_a_secret_descriptor_before_echoing_it` pins this. Same
  applies to `--validate`. `compare-address` screens **both** the descriptor and
  the `--address`.
- **Network resolution (`resolve_network`).** §17.10.2/§17.10.3 don't list
  `--network`, but a `tpub` is shared by testnet/signet/regtest and §16.5 forbids
  guessing — so an optional `--network` override was added; `resolve_network`
  returns the override, else `parsed.network()` (a mainnet `xpub` self-infers),
  else an **exit-4 refusal** ("pass --network …"). Never default-guess the network.
- **`compare-address` exit codes are COMMAND-LOCAL (§17.10.3): `0` match, `1` no
  match, `2` invalid-for-network** — NOT the audit `from_status` mapping. They
  coincide numerically with `ExitCode::{Success, Warnings, Critical}`, reused for
  their *values* (with a comment). The only `ErrorCode::InputInvalidFormat` source
  is `compare_known_address`'s address validation → that maps to exit 2.
- **`--search-range` is the fast-path depth, not a hard cap.** It is passed as
  `compare_known_address`'s `count`; on a miss the engine still expands to the full
  gap limit (1000) per §17.5. Don't reimplement a bounded search in the CLI.
- **`checksum --validate`: `0` valid / `1` missing / `4` invalid.** `Ok(Missing)`
  is a warning → exit 1 (assigned directly, not an error); `Err(ChecksumInvalid)` →
  `ExitCode::from_error` → 4. `--compute` round-trips: computing the checksum of a
  body reproduces the canonical fixture (`…#r6yctejg`), so a fixture doubles as the
  golden answer with no new test data.
- **Utility JSON uses `serde_json::json!`** (a `Value`/`BTreeMap`, so keys come out
  **alphabetically sorted** — deterministic), distinct from the §19.1 report's
  struct-order `Serialize`. `json!` interpolates any `Serialize` (e.g.
  `Vec<&DerivedAddress>`), same as the US-036 error objects.
- A `tpub` fixture has `network() == None`, so derive/compare tests **must** pass
  `--network testnet`; an inferred-network test (`…requires_a_network…`) asserts the
  exit-4 refusal. A P2WPKH (singlesig) address can never collide with a P2WSH
  (multisig) range — use that for a guaranteed `compare-address` miss.

## Screening commands (`commands.rs`) — US-038 (`detect-secrets` / `parse-export`)

- **`detect-secrets` emits the §19.4 DetectorReport JSON, which is NOT the
  detector crate's derived `serde` shape.** The crate serializes a finding as a
  `[secret, range]` tuple (`{"findings":[…],"action":…}`); §19.4 *flattens* each
  finding to `{"kind", <metadata…>, "byte_range":[start,end]}` and adds top-level
  `schema_version` + `user_facing_message`. So the CLI BUILDS the §19.4 JSON via
  `detector_report_json`/`finding_json` (with `json!`, alphabetically-sorted keys
  → deterministic) instead of serializing the report. If US-042 (Tauri) needs the
  same shape, promote these to a crate method rather than duplicating. The xprv
  variant's inner `XprvKind` is emitted as `xprv_kind` (the `kind` key is the
  secret discriminator).
- **`detect-secrets` exit codes are COMMAND-LOCAL (§17.10.6): `5` Block / `1`
  Warn-only / `0` Allow** — `exit_code_for_action`, NOT `from_status`. They reuse
  `ExitCode::{SecretDetected,Warnings,Success}` for their value (mirrors the
  detector crate's own `cli_exit_code`).
- **Input is a secret by assumption.** Read from `--file` or stdin (default; no
  flag needed — `--stdin` is explicit opt-in), wrap in `SecretString`, and screen
  via `detect_secret` (consumes + zeroizes). NEVER echo content: human output
  shows only the finding `kind` + byte range + the leak-free `E-SECRET-*` reason
  code; the §19.4 `user_facing_message` is the crate's verbatim Block headline
  (Warn/Allow use short CLI-authored copy — the crate has a headline only for
  Block). A no-leak test feeds real secret fixtures and greps the output.
- **`parse-export` reads `--file` ONLY (no stdin/inline; §17.10.7).** Screen the
  whole file content with `screen_for_secrets` BEFORE importing — a secret-bearing
  export Blocks (exit 5) and is never normalized/echoed. Then dispatch by
  `--format` (a CLI-local `ExportFormat` ValueEnum = the 8 §17.10.7 friendly names
  `auto`/sparrow/specter/coldcard/nunchuk/jade/liana/core; `electrum`/`bluewallet`/
  `passport` are reachable only via `auto`). `coldcard` picks JSON vs descriptor-file
  by a leading `{`. **`liana` needs `--decryption-input <XPUB>` (repeatable)** — a
  documented addition beyond the §17.10.7 signature (like US-037's `--network`),
  because a `.bed` is encrypted to its recipient xpubs; without it `import_liana_bed`
  (and `import_auto`) returns `E-INPUT-003` → exit 4.
- **`parse-export` emits the §19.3 `NormalizedWalletExport` directly** via
  `serde_json::to_string` (a crate-owned serde type whose declared field order IS
  the §19.3 key order — unlike the detector report, this one matches). The importer
  leaves `imported_at` / `raw_source_filename` to the caller; `run_parse_export`
  stamps them (`imported_at` from `now_iso8601()` at the boundary, filename =
  basename) so the handler stays deterministic given a fixed time param. Human
  output shows source/type/quorum + per-key fingerprint+path (NOT xpubs or the full
  descriptors — those are `--json` only; fingerprints/paths are shown both modes per
  the §14.3 redaction rules).
- **Tests**: parse-export/detect-secrets read real fixture FILE PATHS at runtime
  (`fixture_file(rel)` → repo-root `fixtures/`), not `include_str!` embeds. A
  per-format loop asserts each §17.10.7 format normalizes its fixture to the right
  `source_wallet`. Snapshots: the §19.4 Allow JSON (safe — no findings) and the
  §19.3 core JSON / sparrow human. Block-path coverage uses direct assertions over
  a secret fixture (no secret-derived snapshot committed).

## Runbook & shell-integration commands (`commands.rs`) — US-039 (`generate-runbook` / `completions` / `man`)

- **`generate-runbook` (§17.10.4)** renders a bundled `runbook-engine` template to
  `pdf` (default) / `md` / `txt` / `html`, in `public-safe` (default) or `private`
  mode. It is a **pure `(args, app_version) -> CommandOutput`** — no clock read: the
  footer `report_hash` is the constant `RUNBOOK_PLACEHOLDER_REPORT_HASH`
  (`sha256:00…00`), because a standalone CLI runbook accompanies no saved report, and
  `next_drill` is blank — so output is byte-deterministic for given args.
- **Templates** resolve via `resolve_template(id)`, which scans `OwnerTemplate::ALL`
  then `HeirTemplate::ALL` by `.name()` (the id list never drifts as templates are
  added). Unknown id → `invalid_args` (exit 4) listing valid ids (`known_template_ids`).
- **`--descriptor` is optional** (templates can be blank for manual fill-in). When
  given it is **screened for secrets first** (`screen_and_parse` → Block = exit 5,
  never written into the runbook), then pre-fills the wallet summary M/N
  (`multisig_info()`, cast `usize`→`u32`) and the signer list (`key_origins()` →
  `Signer::new(label, fingerprint_hex().unwrap_or_default(), derivation_path_display().unwrap_or_default())`).
  Script type + passphrase default come from `template_defaults()`.
- **PDF is binary** → `--format pdf` **requires `--output`** (else exit 4: a PDF can't
  go to a terminal via the `String` `CommandOutput.stdout`). `--output` writes bytes
  with `std::fs::write` (failure → `CannotWrite` → exit 6) + a confirmation line;
  without it, a text runbook streams to stdout. PDF uses `PdfBackend::Auto` (printpdf
  fallback → always works, no Typst binary needed).
- **`txt`/`html` are derived from the Markdown** by conservative converters:
  `markdown_to_text` strips ATX `#`, `**`, `` ` `` and code-fence delimiters but
  **leaves `*`/`_` alone** so a descriptor wildcard (`/0/*`) or path is never
  corrupted; `markdown_to_html` maps block structure to HTML with inline text
  **escaped + verbatim** (no inline-emphasis parsing — same no-corruption reason). A
  test asserts md/txt/html all pass `passes_anti_overclaim_lint`.
- **`completions <shell>` / `man`** are generated from the live `build_command()` clap
  tree (so they never drift; a test asserts the bash completion contains
  `generate-runbook`). `completions` uses `clap_complete::generate` with
  `clap_complete::shells::{Bash,Zsh,Fish,PowerShell}` and
  `clap_complete_nushell::Nushell` (clap_complete ships no nushell generator); `man`
  uses `clap_mangen::Man::new(cmd).render(buf)` → roff. `CompletionShell::PowerShell`
  carries `#[value(name = "powershell")]` (clap would otherwise kebab it to
  `power-shell`).
- **MSRV-1.78 dep pins (root `Cargo.toml`)**: `clap_complete = "=4.5.38"`,
  `clap_mangen = "=0.2.24"`, `clap_complete_nushell = "=4.5.5"`. The **latest**
  releases (clap_complete ≥ 4.6.0, clap_mangen ≥ 0.3.0, nushell ≥ 4.6.0) require
  `edition2024` (rustc 1.85), which 1.78's Cargo cannot parse — same class as the
  `clap_builder = "=4.5.57"` pin. **The crates.io `rust_version` field is NOT a
  reliable edition2024 signal** (clap_mangen 0.2.33 declares `rust_version 1.74` yet
  its manifest uses `edition2024` and fails to parse on 1.78) — verify by building.

## PSBT commands (`psbt inspect` / `validate` / `extract-tx`) — US-077

- The root CLI stays Rust 1.78 and reaches PSBT file logic through
  `lifeboat_core::psbt_tools`. Do not add BDK or `psbt-drill` as a CLI
  dependency; practice-wallet create/sign/finalize remains detached.
- `psbt inspect` and `psbt validate` accept base64 BIP174 v0 and BIP370 v2 files.
  `--network` only decodes output addresses; it must not be guessed from PSBT
  contents.
- `psbt extract-tx` must check `PsbtLifecycle::Finalized` before calling
  rust-bitcoin extraction. The library can serialize an unsigned transaction
  shell, so the CLI has to enforce the recovery-drill finalization boundary.

## Build verification (`verify-build`) — US-098

- `verify-build VERSION` is a release-artifact hash checker, not a builder. It
  compares local files to release `SHA256SUMS` entries by basename. With no
  `--artifact`, it scans the current directory for files named in `SHA256SUMS`;
  tests should pass explicit `--artifact` paths to avoid changing process cwd.
- The command reads `--checksums`, then `./SHA256SUMS`, then fetches
  `${CARGO_PKG_REPOSITORY}/releases/download/<VERSION>/SHA256SUMS` with system
  `curl`. That network path is user-initiated by the command; do not add an
  always-on HTTP client or background update check.
- SHA-256 lives in the CLI (`sha2.workspace = true`) because this is release
  packaging verification, not Bitcoin logic. Keep descriptor parsing, addresses,
  PSBT semantics, and secret detection behind `lifeboat_core`.

## Dispatch note (`main.rs`)

After US-098 all **12** top-level commands are implemented, so there is **no `dispatch_stub`**.
`--quiet`/`--verbose` are now read in `dispatch` (a `--verbose && !--quiet`
diagnostic line) — if you remove that, those flags lose their only reader and
`-D warnings` trips `field is never read` (the global-flag dead-code trap). The
command result on stdout is never suppressed by `--quiet` (it is the essential
output); `--quiet` only silences the verbose diagnostic.

## Panic handling (`main.rs`) — NOT human-panic

`human-panic` (named by §23.2) is deliberately NOT used:

1. **MSRV.** Its 2026 dependency tree fights the hard-pinned 1.78 on every front
   (uuid→getrandom 0.4, toml→toml_writer/indexmap 2.14, anstream 1.0,
   backtrace 0.3.76/addr2line→rustc 1.81/1.82). It would need ~6 fragile
   transitive pins.
2. **Secret hygiene.** human-panic writes a crash-report FILE containing the
   panic message, which here could carry a descriptor/xpub — violating "never
   persist confidential data" (§13.6).

Instead: `install_panic_hook()` prints a friendly, **payload-free** message
(location + version only, NEVER `info.payload()`) and `main` wraps the run in
`run_caught` (`catch_unwind` → `ExitCode::Internal`). Same precedent as US-031
hand-rolling `ScratchDir` over `tempfile`. The bug-report URL is
`concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")` (keeps the `__GH_ORG__`
placeholder until release config swaps it). Revisit adopting human-panic when the
toolchain channel moves past 1.78 (MSRV-RISK).

## Testing

- Drive `run(args)` directly (it is generic over the arg iterator) to assert
  end-to-end exit codes without spawning a process.
- `Cli::try_parse_from([...])` for flag/subcommand parsing; `build_command().debug_assert()`
  validates the whole command tree; `build_command().render_long_help().to_string()`
  for the banner.
- A panic test uses `run_caught(|| panic!(...))` → `ExitCode::Internal`.
