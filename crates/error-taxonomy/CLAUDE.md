# error-taxonomy

The single typed error vocabulary. Every crate maps failures to `LifeboatError`,
which wraps a stable `ErrorCode`. Codes mirror PRD Appendix C; user-facing text
mirrors PRD Appendix D.

## How to use it from another crate

- Construct: `LifeboatError::new(ErrorCode::ParseFailed)`, or `ErrorCode::X.into()`.
- Add safe context: `.with_context("...")` — **never** put secret material
  (seed words, xprv, raw descriptors) in context; it is logged and surfaced.
- Chain a library error: `.with_source(miniscript_err)` (any `Error + Send + Sync + 'static`).
- Read: `.code()`, `.severity()`, `.i18n_key()`, `.context()`.

## How to add or change a code (keep these four in lockstep)

1. Add a variant to `ErrorCode` (descriptive name, doc line with the `E-XXX-NNN`).
2. Add it to `ErrorCode::ALL` (catalog order).
3. Add a `meta()` match arm with code/severity/title/description/action/i18n_key
   (`i18n_key` is always `"errors.<CODE>"`).
4. Add the matching entry to `strings/en.json` under `errors`.
5. Add the matching Fluent message to every `strings/{en,es,de,fr}.ftl` file as
   `errors-<CODE>` with `.title`, `.description`, and `.action` attributes.

The `en_json_catalog_mirrors_every_code` test fails the build if `meta()` text and
`en.json` drift, or if `en.json` has stale/missing entries — so all four stay in sync.
Bump the count assertion in `all_codes_are_present_and_unique` when the catalog grows.
The Fluent tests also fail if any locale is missing a message/attribute or has a
dead key.

## Fluent/i18n (since US-097)

- Rust-side localized error text is resolved with Project Fluent through
  `localize_error(code, locale) -> LocalizedError`. It is bundled-only and never
  fetches translations at runtime.
- The canonical logical key remains `errors.<CODE>.<field>` to match i18next.
  Fluent stores the same key as message id `errors-<CODE>` plus attributes
  `.title`, `.description`, and `.action` because Fluent message ids do not use
  dot-separated paths.
- `SUPPORTED_FLUENT_LOCALES` is `en/es/de/fr`; region tags normalize by primary
  language (`fr-CA` -> `fr`), and unsupported locales fall back to English.
- Keep `fluent-bundle =0.16.0` and `unic-langid =0.9.5` pinned from the root
  workspace. `unic-langid 0.9.6` selects `tinystr 0.8`, which requires Rust 1.82
  and breaks the root Rust 1.78 MSRV.

## Conventions / gotchas

- `meta()` is the single source of truth; `en.json` is a generated-by-hand mirror.
- `ErrorCode` is `#[non_exhaustive]` (adding codes is not a breaking change) and
  serializes as its code string (`"E-PARSE-001"`), not the variant name.
- `Severity` serializes snake_case (`user_correctable | warning | critical | security | internal`).
- No `unwrap`/`panic` outside `#[cfg(test)]`.
- thiserror 1.x accepts `#[source] Option<Box<dyn Error + Send + Sync + 'static>>` —
  used here for optional source chaining.
