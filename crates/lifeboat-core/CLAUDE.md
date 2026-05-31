# lifeboat-core

The public API **façade** (US-034). It contains **no logic** — only re-exports —
so the CLI (`cli/lifeboat`, US-035+) and the Tauri desktop app (US-041+) build
against one identical surface (PRD §20).

## Conventions

- **Crate-name re-exports.** `src/lib.rs` is just `pub use <crate>;` for each of
  the root-workspace core crates, so a path is identical whether you depend on the crate
  directly or through the façade:
  `lifeboat_core::report_engine::build_report` == `report_engine::build_report`.
  When a new core crate is added to the §20 graph, add one `pub use` line here
  (and a `<crate>.workspace = true` dep in `Cargo.toml`) — nothing else.
- **No business logic, no wrapper fns.** Do not add convenience functions that
  re-implement or re-wire core behavior; consumers call the re-exported APIs
  directly. Keeping it pure re-exports is what makes the façade safe to depend on.
- **No GUI dependency, ever.** Neither this crate nor any core crate may depend
  on `tauri` (PRD §13.7/§20). `tests/no_tauri.rs` enforces this by reading each
  core crate's `Cargo.toml` — it inspects the **manifests, not `Cargo.lock`**, so
  it stays correct once US-041 adds the desktop app (whose `tauri` dep is
  legitimate and lives in a separate, non-core crate). To add a crate to the
  guard, extend `CORE_CRATES`.

## Testing a façade

Integration tests in `tests/` are a **separate crate that depends only on
`lifeboat-core` (plus std)** — NOT on the underlying analysis crates. So
`use lifeboat_core::<crate>::Item;` compiling is itself proof that the re-export
works; you need no dev-dependencies. Reach every core item through
`lifeboat_core::<crate>::…`.

`clippy -D warnings` gotcha: `assert!(SOME_CONST > 0)` is constant-folded and
trips `clippy::assertions_on_constants` (it becomes `assert!(true)`). Use
`assert_eq!(CONST, value)` instead — the `assert_eq!` form is not flagged even
when both operands are consts.

## Real core entry points (verified against source — don't trust summaries)

These bit a prior exploration that guessed wrong; use the actual signatures:

- **Report:** `report_engine::build_report(&ReportInput) -> ReadinessReport` is
  **infallible** (there is no `assemble_report`, and it does not return
  `Result`). Build the input with `ReportInput::new(&parsed_descriptor, created_at)`
  then `.with_*`. Markdown is the method `ReadinessReport::to_markdown()` /
  `to_markdown_mode(mode)`; JSON is `ReadinessReport::to_json()`; redaction is the
  method `ReadinessReport::redact(mode)`.
- **Runbooks are template-based.** There is **no** `generate_runbook` and **no**
  `Runbook`/`RunbookInput` type. Use `OwnerTemplate`/`HeirTemplate` + `RunbookData`
  with `RunbookEngine::render_owner_pdf` / `render_heir_pdf` (PDF bytes) or the
  free `render_owner_markdown` / `render_heir_markdown` (Markdown).
- **Parse:** `descriptor_audit::parse_descriptor(&str) -> Result<ParsedDescriptor, LifeboatError>`.
- **Detect:** `sensitive_input_detector::detect(&str) -> DetectorReport`
  (infallible; report has only discriminants + byte ranges, never the secret).
