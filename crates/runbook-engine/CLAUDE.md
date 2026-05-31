# runbook-engine

PDF + (later) Markdown recovery/inheritance runbooks. US-031 built the **base PDF
pipeline**; US-032/033 add the owner/heir/workshop/business templates on top, and
US-093 completes the `liana-timelock` inheritance template.

## Architecture (US-031)

Two backends behind `RunbookEngine::render_pdf(template, backend, page_size, mode)`:

- **Typst** (`typst_cli::TypstBackend`, preferred) — shells out to a bundled
  `typst` binary as an out-of-process **subprocess**. Typst is NOT a crate
  dependency (huge tree, MSRV well past 1.78). The binary + Inter/JetBrains Mono
  fonts are populated by the release/packaging step (US-064), so in dev/CI this
  path returns `E-DEP-001` (`ErrorCode::TypstNotBundled`).
- **printpdf** (`printpdf_backend`, pure-Rust fallback) — no binary, no font
  files (base-14 fonts). Always works, so `cargo test` exercises THIS path.
- `PdfBackend::Auto` runs Typst, falls back to printpdf **only** on `E-DEP-001`
  (any other Typst error propagates). `Typst`/`Printpdf` force one backend.

`BaseTemplate { title, body: &[&str], footer: RunbookFooter { lifeboat_version,
report_hash } }` is the render input. US-032/033 extend this same shape; reuse it,
don't fork it.

## Determinism is the hard part (PRD §19/§27: same input → byte-identical PDF)

The caller stamps `lifeboat_version` + `report_hash` (this crate NEVER reads the
clock/env for content). printpdf has three nondeterministic fields, all
neutralized in `printpdf_backend`:

1. `/CreationDate`, `/ModDate`, XMP date all default to `now_utc()` → pin all
   three with `.with_creation_date/.with_mod_date/.with_metadata_date(OffsetDateTime::UNIX_EPOCH)`.
2. XMP packet has its own random ids → `PdfConformance::default()` has
   `requires_xmp_metadata = false`, so no XMP is emitted (don't switch to a
   conformance that requires XMP without re-checking determinism).
3. trailer `/ID = [document_id, instance_id]` — both `random_character_string_32()`
   with NO setter → after `save_to_bytes`, reload via printpdf's re-exported
   `printpdf::lopdf`, `doc.trailer.set("ID", Array[fixed, fixed])`, `save_to`.
   lopdf serializes objects in id order, so the reparse+re-save is deterministic
   within AND across processes (verified by running the pinned-hash test in 3
   separate processes).

**Pinned hash**: `PINNED_A4_PUBLIC_SHA256` in `src/lib.rs` tests locks the A4
public-safe render. Regenerate ONLY on a deliberate layout change or a
printpdf/lopdf bump: run the test, copy the `left:` value from the assert panic.
The byte-determinism test (render twice, assert equal) is what proves the /ID
fix actually works — keep it.

## MSRV pins (root `[workspace.dependencies]`) — see the MSRV-RISK rule

- `printpdf = "=0.7.0"` (last 0.7.x) + `time = "=0.3.36"`, both
  `default-features = false`. printpdf's default `time` (0.3.47) pulls
  `time-core 0.1.8` / `deranged 0.5.x`, which use edition 2024 (rust 1.85) and
  the pinned 1.78 Cargo can't even parse during resolution. `time =0.3.36` is the
  last with `time-core 0.1.2` / `deranged 0.3.x` and satisfies printpdf's
  `time ^0.3.25`. printpdf's only default feature is wasm-only `js-sys`, so
  `default-features = false` is safe on native and keeps `OffsetDateTime =
  time::OffsetDateTime`. Revisit WITH the toolchain channel, never bump alone.

## Hang-safety + secret hygiene (typst subprocess)

- `wait_with_timeout` polls `Child::try_wait` in the FOREGROUND and kills+reaps on
  the deadline → `E-INTERNAL`. NO background `pgrep`/watch loop (the Ralph hang
  anti-pattern in the project CLAUDE.md). A timeout test (150ms timeout vs a
  10s-sleep fake `typst`) proves the kill is bounded.
- Child stdin/stdout/stderr = `Stdio::null()`: a Typst diagnostic could echo a
  descriptor/xpub in private mode (§13 forbids logging secrets), so the child is
  silenced and errors report only the process outcome. Same reason `printpdf`
  errors are mapped to a static-context `E-INTERNAL` and NOT `.with_source()`'d.
- `data.json` (which may carry confidential content in private mode) is written to
  a hand-rolled `ScratchDir` (pid+atomic counter, removed on `Drop`) — NOT
  `tempfile` (its `fastrand`/`getrandom 0.4` subtree is edition 2024 / rust 1.85).
- Tests drive a FAKE `typst` shell script (`#[cfg(unix)]`) for the success and
  timeout paths, since real typst isn't installed. The output path MUST be the
  last CLI arg (`typst compile IN … OUT`); the fake script writes to its last arg.

## Reuse from report-engine (don't re-transcribe)

`DISCLAIMER_SHORT` (verbatim §15.6, footer), `RedactionMode` (re-exported here),
`passes_anti_overclaim_lint`, `APP_VERSION`. The footer is ASCII-only (base-14
fonts + determinism are simplest over ASCII); `DISCLAIMER_SHORT` is already ASCII.

## Owner templates (US-032) — one source, three renderers

`src/owner.rs` is the SINGLE SOURCE OF TRUTH for the four owner runbooks
(`OwnerTemplate::{SinglesigBasic,SinglesigPassphrase,Multisig2of3,Multisig3of5}`).
`build_sections(template, &RunbookData, mode) -> Vec<RunbookSection>` produces the
sixteen §9.5 sections (fixed order 1..16) as typed `Block`s
(`Para|Bullet|Check|Step|Code`); three renderers consume that ONE structure so the
forms can never drift:

- `render_owner_markdown` (re-exported) — §17.8 Markdown; snapshot-tested.
- `RunbookEngine::render_owner_pdf` → `owner::pdf_body_lines` flattened into the
  US-031 `BaseTemplate` → the deterministic printpdf backend (the tested path).
- the four `templates/runbooks/<name>.typ` files render `owner::sections_json`
  (`[{index,heading,blocks:[{kind,text,n}]}]`). They are DATA-DRIVEN (differ only
  by a subtitle line) and selected by `owner_typ_source(template)` =
  `OwnerTemplate::name()`; `include_str!` forces them to exist at compile time.

`RunbookData` is the §17.8 variable bag (`wallet_summary`, `descriptor`, `signers`,
`drill_date`, `next_drill`, `report_hash`, `lifeboat_version`, `has_passphrase`,
`wallet_software`) — all caller-supplied (determinism). **Forbidden content is
structural**: there is NO field for a seed, passphrase value, private key, or
free-text location; locations are always labeled blank fields, the passphrase is a
bool "exists".

Mode only changes section 6 (descriptor: full `Code` block in `private` vs the
`DESCRIPTOR_REDACTED_PLACEHOLDER` const in `public-safe`) and section 7 (the
hardware-wallet `device_model`, §9.5 item 15: shown in `private`, hidden in
`public-safe`). Fingerprints + paths are NOT xpubs → shown in both modes.
`privacy_banner()` returns the §14.3 `XPUB_PRIVACY_WARNING` for a `private` runbook
whose descriptor contains an xpub prefix (none in `public-safe`, none for a
raw-pubkey descriptor). The §15.6 disclaimer (§16) and descriptor are `Code` blocks
→ fenced in Markdown / `raw()` in Typst → bytes preserved.

`ascii_fold` folds the printpdf body to ASCII (base-14 fonts can't encode the
banner's ⚠️ → "WARNING:", other non-ASCII → `?`); the Markdown/Typst paths keep
full Unicode. Reuse this for any future printpdf text with possibly-Unicode input.

Tests: 8 Markdown insta snapshots (4 templates × 2 modes) in `owner::tests`, plus
ONE `owner_pdf_sha256` snapshot in `lib.rs::tests` that pins all 8 PDFs BY HASH and
asserts render-twice byte-determinism (cleaner than 8 hand-copied `PINNED_*`
consts). Behavioral tests cover the 16-section count, descriptor/device/banner
redaction, the §16.8 lint over every rendered form, and forbidden-content.

GOTCHA (timing flake): the `<3 s` budget tests are wall-clock and can be starved
when the long `sensitive-input-detector` fuzz-property integration test (~21 s)
saturates CPUs during a parallel `cargo test --workspace` —
`largest_owner_template_renders_under_3s` takes the BEST of three renders to stay
green. printpdf renders in ~16 ms, so the budget has a ~180× margin; a single-shot
assert is what flakes, not the render.

## Heir / education / Liana templates (US-033 + US-093)

`src/heir.rs` is the single source of truth for the heir, education, business, and
Liana timelock runbooks. `HeirTemplate::ALL` is the authoritative registry; CLI and
desktop command layers scan it by `.name()`, so adding a template here makes the
backend accept the id. React dropdowns and i18n strings are still hardcoded and
must be updated separately.

`liana-timelock` is a full heir-facing template, not a stub. It opens with the heir
disclaimer/glossary, renders the same 16-section shape, and covers primary path,
timelocked recovery path, block-height blanks, trusted-helper blanks, and the
public-safe/private descriptor split. Keep it in the `HeirTemplate` family unless
there is a new runbook family abstraction.

## History

US-031 was once implemented in an interrupted iteration whose new files were
untracked and lost (only a façade `lib.rs` survived in a stash); prd.json was
left marking it `passes:true` with no commit. This crate is the faithful
reconstruction from that surviving façade + the AC. If you see a mismatch between
prd.json notes and the tree again, check `git fsck`/stash before assuming.
