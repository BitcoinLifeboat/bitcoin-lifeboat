# Golden ReadinessReport corpus

Each `*.json` file here is a frozen [`ReadinessReport`](../../crates/report-engine)
(PRD §19.1) built from a committed descriptor fixture under a fixed context. The
corpus is the project's permanent proof that reports are **deterministic**: the
same descriptor + context + `app_version` + `scoring_engine_version` always
serialize to byte-identical JSON (PRD §19 / §27).

The corpus is generated and checked by
[`crates/report-engine/tests/golden_corpus.rs`](../../crates/report-engine/tests/golden_corpus.rs).
Do not hand-edit these files.

## File format

- One file per scenario; the filename is the scenario name (e.g.
  `multisig_2of3_multipath_ready_full.json`).
- Contents are `ReadinessReport::to_json_pretty()` plus a trailing newline.
  Pretty-printing keeps diffs reviewable; the product ships the compact
  `to_json()`, which the reproducibility test pins separately.
- Field order is the §19.1 key order (serde emits struct fields in declaration
  order), so the file doubles as a readable example of the report shape.
- `created_at` is pinned to `2024-01-15T00:00:00Z` and `app_version` to `0.1.0`
  in every scenario, so the bytes never drift with the wall clock or a workspace
  version bump. `scoring_engine_version` is `0.1.0`.

## Regenerating

After a **deliberate** scoring or format change, regenerate and review the diff:

```sh
# Rewrite every fixtures/reports/*.json from the current engine:
REGEN_GOLDEN=1 cargo +1.78.0 test -p report-engine --test golden_corpus
# Refresh the at-a-glance manifest snapshot:
INSTA_UPDATE=always cargo +1.78.0 test -p report-engine --test golden_corpus
```

Then inspect the diff and commit it. A change here that you did **not** intend
is a determinism regression — investigate before regenerating. The manifest
snapshot (`crates/report-engine/tests/snapshots/golden_corpus__corpus_manifest.snap`)
shows one line per fixture (status, score, counts, `report_hash`), so any byte
change surfaces as a `report_hash` diff in a single place.

## Anonymization checklist (required for every fixture)

The corpus must never contain real or mainnet material. The
`corpus_is_anonymized_never_mainnet` test enforces this, but verify by hand when
adding a scenario:

- [ ] **Never mainnet.** Networks are `testnet` / `signet` / `regtest` (or
      `null` for cannot-determine). No `bitcoin` network, no `xpub…` key, no
      `bc1…` / `1…` / `3…` address.
- [ ] **No private material.** Built only from watch-only descriptors. No seed
      phrase, xprv/tprv, WIF, or any secret — the source descriptors are the
      committed `fixtures/descriptors/**` files, all minted from fixed synthetic
      test seeds (see `crates/descriptor-audit/CLAUDE.md`).
- [ ] **No personal data.** Labels, contacts, and free text are synthetic.
- [ ] **Deterministic inputs only.** Pin `created_at` and `app_version`; never
      read the clock, the environment, or random state.

## Coverage

The catalog in `golden_corpus.rs` spans every category the readiness engine can
produce, enforced by `corpus_covers_the_required_categories`:

- **Wallet kinds:** singlesig (pkh / wpkh / sh(wpkh) / multipath), multisig
  (2-of-3, 3-of-5, multipath), and Taproot (key-path and script-path).
- **All five §16.2 statuses:** Ready, Mostly Ready, Needs Attention, Not Ready,
  Cannot Determine.
- **Every reachable §16.3 critical:** duplicate xpub, wallet-type mismatch,
  undocumented passphrase, missing required change descriptor, address mismatch.
- **§16.4 warnings**, including same-location-backup and BIP389 multipath
  coverage, plus the survivability dimension (present for multisig, absent for
  singlesig).

## What is *not* here

Parse failures (invalid checksum → `E-PARSE-003`, contains xprv → `E-PARSE-005`,
threshold > keys → `E-PARSE-007`, mixed networks → `E-PARSE-004`) have **no full
ReadinessReport**: `build_report` requires a parsed descriptor. The CLI emits a
compact `{"status":"not_ready","error":{…}}` for those instead, and that path is
covered by the `lifeboat` CLI crate's own tests, not by this corpus.
