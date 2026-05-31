# report-engine — notes for future iterations

The **report orchestration layer** (US-028+). It assembles the PRD §19.1
`ReadinessReport` from the lower analysis crates and emits deterministic,
byte-identical JSON. US-029 renders the same data as Markdown; US-030 adds the
`public-safe` redaction mode + the anti-overclaim lint.

## Public API (US-028)
- `build_report(&ReportInput) -> ReadinessReport` is the single entry. It is the
  **orchestrator**: it runs `readiness_score`'s `run_checks` /
  `evaluate_critical_failures` / `compute_score` / `map_status` /
  `compute_survivability` over the parsed descriptor, derives addresses via
  `address_derive`, and assembles every §19.1 field. **Infallible** (the whole
  scoring stack is): address-derivation errors degrade to empty address lists
  (the G-checks already encode the outcome), and a malformed known address is
  treated as "not provided". No `error-taxonomy` dep — sub-results are `.ok()`d.
- `ReportInput<'a>` is `Copy`, built with `ReportInput::new(receive, created_at)`
  + `with_*` (mirrors the `readiness_score` context builders). It holds the
  **union** of the four readiness contexts' signals; `build_report` constructs
  `CheckInput`/`CriticalContext`/`ScoringContext`/`StatusContext` from it and
  feeds the SAME checklist/declared-type/etc. to each (the duplication the
  readiness-score CLAUDE.md anticipated).
- `with_derive_count(n)` (US-036) sets how many receive/change addresses the
  report samples; it **defaults to `REPORT_ADDRESS_COUNT`**, so callers that don't
  set it (and every existing snapshot) are byte-identical. It is report *content*
  (changes `report_hash`) but not wallet *identity* (`input_hash` is unchanged),
  so the same wallet still correlates across sample sizes. The CLI `--derive-count`
  threads through here.
- `ReadinessReport::to_json()` / `to_json_pretty()` are the canonical
  serializations. `to_json()` (compact `serde_json::to_string`) is the
  byte-identical §19.1 form. Both use a documented `.expect()` — serialization of
  this closed type cannot fail (same sanctioned-panic precedent as the detector's
  regex compile); the determinism tests exercise it.

## Determinism (the whole point — PRD §19/§27)
- **Caller stamps the ambient values.** `created_at` is required by
  `ReportInput::new`; `app_version` defaults to `APP_VERSION`
  (`env!("CARGO_PKG_VERSION")`) and is overridable. NEVER read the clock here —
  same rule as `wallet-imports` leaving `imported_at` to its caller. Two runs
  with the same `ReportInput` produce identical bytes (tested).
- **Field order == §19.1.** `serde` serializes struct fields in declaration
  order, so the struct field order IS the JSON key order. Keep
  `ReadinessReport`'s fields in §19.1 order.
- **Reuse the upstream serde types directly** in the report (`Check`,
  `CriticalIssue`, `ScoringAuditEntry`, `Survivability`, `DerivedAddress`,
  `KnownAddressMatch`) — they already serialize to the §19.1 shapes. Only the
  report-OWNED objects are defined here (`WalletSummary`, `DescriptorEntry`,
  `ReportKey`, `ReportAddresses`, `Score`, `WarningDetail`, `PassItem`,
  `NextStep`), all `rename_all="snake_case"`.

## Hashes
- `sha256_prefixed(bytes) -> "sha256:<64 hex>"`. `sha2` was ALREADY in
  `[workspace.dependencies]` + `Cargo.lock` (the detector's `build.rs` uses it),
  so consuming it as a normal dep added only the `report-engine → sha2` edge, no
  new versions. Build the hex with a `const HEX` table + `push` loop — NOT
  `map(|b| format!()).collect()` (`clippy::format_collect`, in `-D warnings`) and
  NOT `write!` (returns a `#[must_use]` `Result` → `unused_must_use`).
- `report_hash` = `sha256_prefixed` of the report serialized **with
  `report_hash` blanked to `""`** (build struct → blank → serialize → hash →
  fill). A verifier blanks the field and recomputes (tested). The final
  `to_json()` re-serializes with the real hash; that differs from the hashed
  bytes only in that one field, by design.
- `input_hash` = hash of a private `HashInput` struct = the CANONICAL descriptors
  (`'`/`h` differences hash the same) + network + known address + the context
  signals. It **excludes** `created_at`/`app_version`, so the same wallet
  correlates across time/versions (tested: changing `created_at` does NOT change
  it; changing the network DOES).

## US-028 owns the user-facing COPY (the analysis crates expose codes/facts only)
- **Warnings[]** are derived from `ScoringResult.scoring_audit` (same fired
  codes, same §16.4 order). `warning_text(WarningCode)` is the single table of
  `{title, description, recommended_fix, action, effort}` for all active codes —
  authored here, NOT in readiness-score. `every_warning_code_has_complete_text`
  locks it. `W-NO-CHANGE-DESC`'s description/fix are the §19.1 verbatim text.
- **next_steps[]** = one per critical (in §16.3 order, via `critical_step`) THEN
  one per fired warning (via `warning_text(..).action/effort`), priority 1..n.
  Order matches `critical_issues` then `scoring_audit`.
- **passes[]** = report-local `P-…` codes derived from PASSING checks: `A1`→
  `P-DESC-PARSEABLE`, `A2`→`P-CHECKSUM-VALID`, multisig+`D2`→`P-THRESHOLD-CLEAR`
  (`M-of-N`), `G3`→`P-ADDRESS-MATCH` (with the match location). Reproduces the
  §19.1 example for a matched 2-of-3. These are NOT in any §16 catalog.
- **anti_actions** = the 3 fixed §19.1 strings. **next_drill_recommendation** =
  `created_at` date + 12 months (score ≥ 70) or + 6 months (< 70), day-clamped;
  dependency-free month math (`add_months`/`days_in_month`/`is_leap_year`),
  `None` if `created_at` isn't a parseable `YYYY-MM-DD…`.

## Redaction modes (US-028 fills the fields; US-030 owns the MODE switch)
- `build_report` always populates BOTH the full (`raw`, `xpub`, `canonical`) and
  redacted (`raw_redacted`, `xpub_redacted`) forms — the complete `private`-mode
  report. `redact_xpub` = §14.3 `first6 + "..." + last4` (extended keys are ASCII
  Base58 → byte slicing safe); `redact_raw` replaces each `key_origins().xpub()`
  in the raw with its redacted form (origin/path preserved).
- **US-030: `RedactionMode {PublicSafe(default), Private}` + `ReadinessReport::
  redact(mode) -> ReadinessReport`.** `Private` is the identity on a freshly built
  report. `PublicSafe` (the §17.7 default): drops every full `xpub`
  (`skip_serializing_if = "Option::is_none"` ⇒ the JSON OMITS the field, per the
  §19.1 line-2044 convention; `xpub_redacted` stays), sets each descriptor `raw`
  to its `raw_redacted`, redacts the `canonical` text in place via
  `redact_xpubs_in_place(&mut s, &xpubs)` (the wallet's keys[] xpubs — there is NO
  precomputed `canonical_redacted`, and a change branch is the same wallet so it
  shares the keys), and truncates `receive_derived`/`change_derived` to 1 per
  chain (§9.5 "first 1 only"). **LEAK CHECK:** the full xpub lives in `raw`,
  `raw_redacted`(already done), `xpub`, and **`canonical`** — miss any and a test
  catches it (`public_safe_mode_redacts_xpubs_descriptor_and_addresses` greps the
  JSON for every `key_origins().xpub()`). addresses/fingerprints/paths are not
  xpubs.
- **HASH SEMANTICS across modes:** `redact` recomputes `report_hash` over the
  emitted bytes (blank→serialize→hash→fill, same as `build_report`) so EITHER
  mode self-verifies by blank-and-recompute; `input_hash` is left untouched →
  mode-independent, so a wallet's public-safe and private exports share it
  (correlation) while their `report_hash` differ.
- The §19.1 JSON differs between modes ONLY by: the `xpub` key present/omitted,
  `raw`/`canonical` full-vs-redacted values, and the address-list length. Adding
  `skip_serializing_if` to `xpub` does NOT change the existing all-xpub
  fixtures' bytes (no `None` to skip) → the US-029 Markdown snapshots and the
  hash tests are unaffected.

## §14.3 xpub privacy warning + `to_markdown_mode`
- `XPUB_PRIVACY_WARNING` is the verbatim §14.3 block (flush-left literal, leading
  `\` swallows the newline — same style as `DISCLAIMER_*`). Stored WITHOUT `> `;
  rendered as a blockquote. US-031/032 (runbook) must reuse this const.
- `ReadinessReport::to_markdown_mode(mode)` renders the §15.10 Markdown for a
  mode: it `redact`s self first (so the rendered `report_hash` line matches that
  mode's JSON), then in **Private** mode, when `contains_xpub()`, prepends the
  §14.3 warning as a leading blockquote. `public-safe` shows only `xpub6...XXXX`
  and needs no warning. The plain `to_markdown()` (the US-029 body renderer) is
  unchanged and stays the snapshot target — `to_markdown_mode` wraps it.
- The §14.3 prepend is a Markdown/human-export concern; JSON carries the xpubs as
  structured data (private mode) without a prose prepend.

## §16.8 anti-overclaim lint (reusable)
- `BANNED_OVERCLAIM_PHRASES` (4 lowercased substrings) + `find_overclaim(text) ->
  Option<&'static str>` + `passes_anti_overclaim_lint(text) -> bool` are the
  reusable §16.8 guard ("wallet is safe"/"bitcoin is secure"/"recovery is
  guaranteed"/"you can recover"). `pub` so US-031/032 (runbook) and US-036/042
  (CLI/UI) lint their rendered output. Enforced here by tests over EVERY authored
  `warning_text`/`critical_step` string AND both render modes of two reports; the
  verbatim §15.6/§15.8 disclaimers PASS (they negate the claim — "does not mean
  your bitcoin\nis safe", and the newline means even "bitcoin is safe" wouldn't
  substring-match anyway; the banned term is "bitcoin is secure").

## script_type / wallet_type
- `script_type_str` combines `descriptor_type()` (miniscript's `DescriptorType`,
  NOT re-exported by descriptor-audit → this crate needs the `miniscript` dep,
  same as readiness-score's C4) with `multisig_info().kind()` to split
  `multi`/`sortedmulti` (e.g. `Wsh` + `Multi` → `"wsh(multi)"`, `WshSortedMulti`
  → `"wsh(sortedmulti)"`). For richer supported policies, read
  `ParsedDescriptor::uses_miniscript()` and emit `wsh(miniscript)`,
  `sh(miniscript)`, `sh(wsh(miniscript))`, or `miniscript`.
- `wallet_type_str`: `is_multisig()`→`"multisig"`, else `is_singlesig()`→
  `"singlesig"`, else `is_taproot()`→`"taproot"`, else `uses_timelock()`→
  `"timelock"`, else `null`.
- `wallet_summary.uses_miniscript` and `wallet_summary.uses_timelock` come directly
  from descriptor-audit facts. A Liana-style descriptor should report
  `wallet_type="timelock"` and `script_type="wsh(miniscript)"` with no preview
  warning or scoring deduction.

## Disclaimers
- `DISCLAIMER_SHORT`/`DISCLAIMER_LONG` are the §15.6 text **verbatim, with
  newlines** (`\n` + `\` line-continuation in the const). US-029/US-031 must
  reuse these consts for verbatim reproduction (D14). The anti-overclaim
  guardrail test scopes the banned-phrase check to GENERATED text only — the
  long disclaimer deliberately contains "is safe" to NEGATE the claim.

## Markdown report (US-029)
- `ReadinessReport::to_markdown(&self) -> String` renders the human-readable
  PRD §15.10 report. It is a **pure function of `self`** (which is already
  deterministic), so the Markdown is deterministic too — same input ⇒
  byte-identical output, far under the 64 KB ceiling. It reads NOTHING the JSON
  doesn't already hold; do not recompute analysis here.
- **Order is normative.** The ten §15.10 items render as `## 1.`…`## 10.`
  headings IN ORDER (status, passed, needs attention, failed, missing, next
  steps, NOT to do, when again, disclaimer, version+hash), then the verbatim
  §15.8 "What this report cannot tell you" block and the §15.6 long disclaimer
  (footer). `markdown_answers_the_ten_section_15_10_items_in_order` locks it.
- **VERBATIM blocks reuse the `pub` consts** — `NOT_A_WALLET` (§15.7, header
  blockquote), `REPORT_CANNOT_TELL` (§15.8), `DISCLAIMER_SHORT`/`DISCLAIMER_LONG`
  (§15.6). They render inside ```` ``` ```` fenced blocks so the exact bytes
  (indentation, line breaks) survive Markdown. US-031/US-032 (runbook) MUST reuse
  these same consts, not re-transcribe the text.
- **`REPORT_CANNOT_TELL` is written flush-left** (a leading `\` swallows the
  opening newline) because its 2-space bullet indents and 4/5-space parenthetical
  continuation indents are part of the text. rustfmt leaves string-literal
  CONTENTS untouched, so flush-left content passes `fmt --check` (the existing
  `DISCLAIMER_*` consts already do this). Don't use the `\n\` continuation style
  for indented text — `\`+newline strips the next line's leading whitespace.
- **Warnings split across two §15.10 sections** via `warning_section(WarningCode)`
  → `Missing` (absent artifact/datum/document: 9 codes incl. NoChangeDesc,
  NoKnownAddress, NoBirthHeight…) vs `NeedsAttention` (risky condition / activity
  not done: 4 codes — NoRecentDrill, NoHwTest, SameLocationBackup, NoMultipath).
  The match is EXHAUSTIVE (no
  `_` arm) so a new §16.4 code must be categorized; `…buckets_are_stable` pins
  9+4. Each warning renders in exactly ONE section (no duplication). US-073 lifted
  the Taproot preview warning and US-074 lifted the Miniscript-in-wsh preview
  warning, but `wallet_summary.uses_taproot` / `uses_miniscript` remain report facts.
- **§16.6 survivability** renders as three bullets in the Status section for
  multisig only (`self.survivability.is_some()`), per §16.6 "alongside the main
  status". `survives_label`/`descriptor_survives_label` map the verdict strings.
- **Anti-overclaim.** The WHOLE Markdown — including the verbatim disclaimers —
  passes the §16.8 banned-phrase check: the disclaimers say "bitcoin is
  safe"/"wallet is recoverable", NOT the banned exact phrases. US-030 promoted
  the inline check into the reusable `passes_anti_overclaim_lint` (see the
  §16.8 section above); `markdown_never_overclaims` and
  `authored_copy_and_both_render_modes_pass_the_lint` call it over both modes.

## insta snapshots (US-029) — MSRV-1.78 pin
- `insta` is pinned to **`=1.44.3`** in root `[workspace.dependencies]`. insta
  1.45.0+ adds a `tempfile` dep → `fastrand` → `getrandom 0.4.2`, and getrandom
  0.4.2 uses **edition 2024** (rust 1.85) so 1.78's Cargo can't even PARSE its
  manifest during resolution. 1.44.3 (deps: only `once_cell` + `similar` + opt
  `console`) requires `similar ^2.1.0`, which auto-caps `similar` below the
  rust-1.85 `similar 3.x` (no separate similar pin needed), and `console ^0.15.4`
  — both 1.78-safe. Per MSRV-RISK, revisit with the toolchain channel.
- Snapshots live in `crates/report-engine/src/snapshots/`
  (`report_engine__tests__<name>.snap`). Regenerate with
  `INSTA_UPDATE=always cargo +1.78.0 test -p report-engine`, then COMMIT the
  `.snap` files; plain `cargo test` compares (no env var) and the gate passes.
  `cargo-insta` is NOT installed (its MSRV is too new) — use the env var, not
  `cargo insta accept`.
- Snapshot tests **pin `app_version` via `.with_app_version("0.1.0")`** so the
  rendered version line + the `report_hash` (which covers `app_version`) stay
  stable across a future workspace version bump. The fixtures + `created_at`
  (CREATED_AT) are already fixed, so the snapshot is fully deterministic.

## Golden corpus + snapshot harness (US-040)
- The permanent determinism corpus is the **integration test**
  `tests/golden_corpus.rs` (NOT the lib `#[cfg(test)]` module) — an integration
  test is a separate crate that sees only the PUBLIC API + the crate's deps
  (`descriptor_audit`, `address_derive`, `readiness_score`), so building the whole
  corpus through it also proves the public surface is sufficient. Its 56 scenarios
  live in one `corpus() -> Vec<(&'static str, ReadinessReport)>`; every report goes
  through a `build()` helper that pins `app_version` to `"0.1.0"`.
- **Golden files** are `fixtures/reports/<name>.json` = `to_json_pretty()` + a
  trailing `\n`. The test ASSERTS byte-equality by default and REGENERATES when
  `REGEN_GOLDEN` is set (`std::env::var_os`), mirroring the insta
  `INSTA_UPDATE=always` workflow: `REGEN_GOLDEN=1 cargo +1.78.0 test -p
  report-engine --test golden_corpus`, review, commit. A missing fixture FAILS
  (so an un-committed scenario is caught). Document the format + the §27
  anonymization checklist in `fixtures/reports/README.md`.
- **What's reachable:** only descriptors that PARSE get a full report
  (`build_report` requires a `ParsedDescriptor`). Reachable §16.3 criticals are
  duplicate-xpub, wallet-type-mismatch, passphrase-undocumented,
  change-desc-required-missing, address-mismatch. Parse-failure criticals
  (E-PARSE-003/004/005/007) are the **CLI's** compact-error JSON, not a report —
  keep them out of this corpus (documented in the README). Status recipes:
  Cannot-Determine = a tpub descriptor with NO `with_network`; Ready/MostlyReady
  need the multipath fixture (single-path always carries `W-NO-CHANGE-DESC -15`);
  Ready also needs a self-derived matching `--known-address` (D8). To force a
  `C-ADDRESS-MISMATCH`, feed a *foreign* wallet's derived address as the known one.
- **Anonymization guard** (`corpus_is_anonymized_never_mainnet`) walks the TYPED
  report (not a JSON substring grep — fingerprint hex can contain "bc1"): every
  `network ∈ {testnet,signet,regtest,null}`, every `keys[].xpub` starts `tpub`,
  no derived address starts `bc1`/`1`/`3`. **Coverage** is test-enforced
  (`corpus_covers_the_required_categories`): all 5 statuses, all reachable
  criticals, a warning spread, both survivability cases — use `Vec` + `.contains`,
  NOT `BTreeSet` (`ReadinessStatus`/`CriticalCode`/`WarningCode` derive `Eq` but
  not `Ord`).
- **insta manifest snapshot** (`tests/snapshots/golden_corpus__corpus_manifest.snap`)
  is one line per fixture (status, numeric, counts, `input_hash`, `report_hash`).
  It is the single-diff overview of the whole corpus — a byte change anywhere
  shows up as a `report_hash` diff. It does NOT duplicate the per-file goldens.

## Test conventions
- The `fixture!` macro reads repo-root `fixtures/...` (same as the other crates).
- For the end-to-end "Ready" case, mint a multipath singlesig in-test (rewrite a
  fixture's `/0/*`→`/<0;1>/*` + `compute_checksum`) so there is no
  `W-NO-CHANGE-DESC`, then **self-derive** `receive[0]` and feed it back as the
  known address (D8 match → `G3 Pass`, numeric 100, `Ready`).
- Check results by stable string (`c.code.as_str() == "C-DUPLICATE-XPUB"`) — no
  need to import the upstream enum variants.
