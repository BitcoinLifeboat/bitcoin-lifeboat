# desktop-commands — the §21.3 command layer (learnings)

GUI-agnostic logic for every Tauri command (PRD §21.3). The `#[tauri::command]`
wrappers in `apps/desktop/src-tauri/src/commands.rs` are thin and delegate here.

## Why this crate exists (don't move the logic into `src-tauri`)

`apps/desktop/src-tauri` can't build without the webkit2gtk/GTK system libs, so
logic placed there is untestable in the fast gate and in libs-less sandboxes. This
crate has **no `tauri` dep**, so it builds and is exercised by
`cargo test --workspace` (Rust 1.78). It depends only on `lifeboat-core` (+
`secrecy`, `serde`). It is a normal member of the **repo-root** workspace; the
detached `src-tauri` workspace reaches it by path dep (`../../../crates/...`), and
its `workspace = true` deps still resolve against the repo root.

## Conventions (mirror the CLI's `commands.rs`)

- **Reuse the core surface through `lifeboat_core::*`** — `parse_descriptor`,
  `derive_addresses`, `compare_known_address`, `validate_checksum`,
  `compute_checksum`, `detect_secret`, `build_report`. Add NO Bitcoin logic here.
- **Screen before processing (§13.5).** Every pasted descriptor/address goes
  through `screen_for_secrets` (wraps in `SecretString`, runs `detect_secret`)
  BEFORE parsing. A `Block` becomes a typed `E-SECRET-*` `LifeboatError` carrying
  only the code — never the content. `compute_checksum`/`audit` must screen first
  because they echo/derive from the input.
- **Validate at the boundary.** `ensure_nonempty` rejects blank input as
  `E-INPUT-001` (note: core `validate_checksum("")` returns `Missing`, so the
  boundary guard is what makes empty input a uniform error).
- **Ambiguous network → typed error, never a guess (§16.5).** `resolve_network`
  returns `E-INPUT-003` (closest user-correctable code; precise reason in
  `.with_context`) when a `tpub` has no override.
- **Determinism (§19/§27).** `audit_descriptor` takes `created_at` + `app_version`
  as params; tests pin them, the wrapper supplies `now_iso8601()` + the crate
  version. Never read the clock inside the report path.

## Boundary types

Inputs are `Deserialize` DTOs (`DescriptorAuditInput`, `AddressDeriveInput`,
`AddressCompareInput`) with `NetworkArg`/`ChainArg` enums (snake_case, validated at
deserialize). Outputs (`DerivedAddressList`, `AddressCompareResult`,
`ChecksumValidation`, plus re-exported `ReadinessReport`/`DetectorReport`) are all
`Serialize`. Re-export any nested field type a consumer must name (`Chain`,
`DetectedSecret`, `MatchLocation`, `ErrorCode`, `Severity`).

## Miniscript policy visualization (US-088)

`render_miniscript_policy_dot` follows the same boundary rules as the descriptor
commands: reject blank input, run `screen_for_secrets` first, then delegate to
`lifeboat_core::miniscript_viz::descriptor_to_dot`. Keep the UI-facing command
here, not in `src-tauri`, so redacted DOT output is tested under the root Rust 1.78
gate. The returned string is already public-safe DOT; the desktop UI may draw it,
but must not derive policy facts itself.

`render_liana_recovery_tree` (US-091) follows the same boundary but delegates to
`lifeboat_core::miniscript_viz::liana_recovery_tree`. It returns the public-safe
DOT plus typed path summaries; keep path extraction in Rust and let the UI format
only those returned fields.

For US-092 countdowns, call `render_liana_recovery_tree_at_block` with an optional
caller-supplied current block height. The command still does only boundary work
(blank-input check + secret screen) and delegates the actual `older` / `after`
math to `miniscript-viz`; do not add chain lookups or block-height fetching here.

## Errors serialize leak-free

`LifeboatError` has a manual `serde::Serialize` in `error-taxonomy` that emits
`{code, severity, title, description, action, i18n_key, context}` and **never** the
chained `source` (which can quote a descriptor/secret). That's why commands can
return `Result<_, LifeboatError>` straight to Tauri. If you add a command that
attaches `.with_context(...)`, keep the context secret-free (paths/structural hints
only).

## Test pattern

Integration tests (`tests/commands.rs`) use the published BIP-49/84 vectors for the
documented "abandon … about" mnemonic (cross-checked by `address-derive`), the repo
`fixtures/` (tpub for the ambiguous-network path, `contains_xprv` for the
secret-screen-before-parse path), and that same documented mnemonic for detection —
never a real secret (§27). Assert the exact `err.code()` on every bad-input path,
and serialize each `Ok` output to confirm the §21.3 "outputs serializable to JSON".

## US-043 — output / import / IO tranche

The second command set (`generate_report`, `generate_runbook`,
`parse_wallet_export`, `save_export`, `check_external_link`, `app_info`):

- **Exports honor redaction (§17.7).** `generate_report` builds the report exactly
  like `audit_descriptor`, then serializes with redaction applied — JSON via
  `report.redact(mode).to_json[_pretty]()`, Markdown via `report.to_markdown_mode(mode)`
  (which redacts internally and adds the private-xpub warning). This is the *export*
  path, so it redacts; the CLI's `report-json` is the raw machine output and does not.
  Outputs carry a deterministic, **date-free** `suggested_filename` (a date would
  break §27 byte-determinism).
- **The link allowlist is generated at build time (no hardcoded org/domain).**
  `build.rs` reads the repo-root `project.config.toml` (`github.url_base` +
  `site.domain`) with a tiny std-only TOML scalar extractor (no `toml` dep / MSRV
  exposure) and emits `LIFEBOAT_GH_URL_BASE` / `LIFEBOAT_SITE_DOMAIN` via
  `cargo:rustc-env`; `lib.rs` reads them with `env!`. Change the config → the
  allowlist (and `app_info`'s URLs) change with no code edit. `check_external_link`
  is **exact-match** on the fixed project URLs, the Signet faucet
  `https://faucet.mutinynet.com/`, plus an `https://<domain>/docs/` prefix, so
  look-alike hosts (`<domain>.evil.example`, `faucet.mutinynet.com.evil.example`)
  and non-`https` are rejected. The
  build-script env reaches the lib (and the lib bakes the allowlist into
  `external_link_allowlist()`), so integration tests assert via that fn — they don't
  need the env var themselves and stay independent of the actual config values.
- **IO lives in the trusted core, by path (testable).** `parse_wallet_export` /
  `save_export` use `std::fs` directly (no Tauri AppHandle/scope needed), so the
  "honors the chosen path" and "reads + normalizes a file" tests run under the core
  gate. `parse_wallet_export` size-guards via `wallet_imports::MAX_EXPORT_SIZE_BYTES`,
  screens for secrets BEFORE `import_auto`, and stamps `imported_at` (boundary clock)
  + `raw_source_filename`. Read failure → `E-FS-001`; write failure → `E-FS-002`;
  oversized → `E-INPUT-002`.
- **`open_external_link` is split deliberately.** The allowlist *decision*
  (`check_external_link`) is here (tested); the OS-browser *launch* is in
  `src-tauri/commands.rs` via a plain per-OS `std::process::Command` (xdg-open /
  open / rundll32), **not** a Tauri shell/opener plugin — the §13.7 capability set
  grants the webview none and the security gate enforces it exactly. The webview can
  only *request* a link; the core vets it then passes it as a single non-shell arg.
- **Runbook helpers are duplicated from the CLI (hoist candidate).**
  `resolve_template` / `template_defaults` / `build_runbook_data` /
  `signers_from_descriptor` / `RUNBOOK_PLACEHOLDER_REPORT_HASH` mirror
  `cli/lifeboat/src/commands.rs`. Kept identical (not shared) to avoid touching the
  committed CLI; if a third consumer appears, hoist them into `runbook-engine`. PDF
  uses `PdfBackend::Auto`, which falls back to the pure-Rust renderer when no Typst
  binary is bundled — so it needs no external dependency and is deterministic in
  tests (assert the `%PDF` magic).
- **Temp files in tests:** a hand-rolled `ScratchFile` over `std::env::temp_dir()`
  (process id + atomic counter), cleaned up on `Drop`. The workspace deliberately
  avoids the `tempfile` crate (it would change the 1.78-pinned tree).
