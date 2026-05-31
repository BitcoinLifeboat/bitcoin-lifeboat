# readiness-score — notes for future iterations

The **scoring/orchestration layer**. It consumes the typed *facts* from
`descriptor-audit` and `address-derive` and turns them into the §9.1 / §16
readiness verdict. It NEVER re-parses or re-derives Bitcoin primitives — it only
calls those crates' public entry points. Built up across US-019..US-022.

## Public API (US-019)
- `run_checks(&CheckInput) -> Vec<Check>` is the single entry. **Infallible**:
  it always returns exactly 24 checks in fixed order A1..G3; an upstream error
  (e.g. a derivation refusal) becomes a `Fail`/`Unknown` result, never a
  propagated error. No `error-taxonomy` dep for that reason.
- `CheckInput<'a>` is built with `CheckInput::new(&parsed)` (or
  `CheckInput::parse_failed()` when parsing failed) + `with_*` builders:
  `with_network`, `with_change_descriptor`, `with_declared_wallet_type`,
  `with_network_confirmed`, `with_known_address`, `with_address_count`. It's
  `Copy` (holds only references + small values).
- `Check { code, category, result, title }` — crate-owned serde type
  (`rename_all` not needed; fields already snake/camel-free), field order matches
  the §19.1 `checks[]` example. `CheckResult { Pass, Warn, Fail, Na, Unknown }`
  serializes snake_case → `"pass"/"warn"/"fail"/"na"/"unknown"` (`Na` → `"na"`,
  `Unknown` → `"unknown"`). `DeclaredWalletType { Singlesig, Multisig }` (B2 input).
- `DEFAULT_ADDRESS_COUNT = 10` (§17.4).

## The check catalog is the single source of truth
- `const CATALOG: [(&str,&str,&str); 24]` holds `(code, category, title)` for
  every check, in A1..G3 order. `compute_results()` returns `[CheckResult; 24]`
  in the **same** order; `run_checks` zips them. To add/change a check, edit BOTH
  in lockstep (kept honest by `catalog_is_24_checks_in_a1_to_g3_order`).
- `category` values (snake_case): `descriptor_parse` (A1), `descriptor_checksum`
  (A2/A3), `normalization` (A4), `script_type` (B1/B2), `key_origin` (C1–C4),
  `wallet_type` (D1), `multisig_quorum` (D2–D5), `receive_descriptor` (E1),
  `change_descriptor` (E2–E4), `network` (F1/F2), `address_derivation` (G1–G3).
  These honor the 3 anchors the §19.1 example pins (A1=`descriptor_parse`,
  A2=`descriptor_checksum`, E2=`change_descriptor`).
- `title` is the FIXED §9.1 check wording, result-INDEPENDENT (so goldens are
  deterministic). NOTE: §19.1 shows E2's title as "Change descriptor missing" —
  that is the *warning* phrasing (the `W-NO-CHANGE-DESC` title US-021 emits), not
  the check title. The check title stays "Change descriptor present"; the `warn`
  result conveys "not present". Don't make titles result-dependent.

## Result semantics = the fact→scoring split (universal rule)
This crate decides `pass/warn/fail/na/unknown`; **US-020 maps `Fail`→§16.3
critical codes, US-021 maps `Warn`→§16.4 weights**. The check→code map the later
stories rely on:
- `A1 Fail` → `C-DESC-PARSE-FAIL`; `A2 Warn` → `W-NO-DESC-CHECKSUM` (-5);
  `D4 Fail` → `C-DUPLICATE-XPUB`; `D5 Fail` → `C-KEY-COUNT-BELOW-THRESHOLD`;
  `B2 Fail` → `C-WALLET-TYPE-MISMATCH`; `E2 Warn` → `W-NO-CHANGE-DESC` (-15);
  `G3 Fail` → `C-ADDRESS-MISMATCH`; `F1 Unknown` → §16.5 Cannot Determine (US-022).
- `fail` = §16.3 critical condition; `warn` = §16.4 deduction; `na` = doesn't
  apply (multisig check on singlesig, checksum-validity when none present);
  `unknown` = insufficient input (ambiguous network, derivation with no network).

## Per-check gotchas (read before touching a check)
- **A3** (checksum valid) is `Pass` when present, `Na` when absent — an *invalid*
  checksum is fatal at parse (`E-PARSE-003`), so a `ParsedDescriptor` with a
  present checksum always has a valid one.
- **A4** is a normalization ROUND-TRIP (`normalize(raw)==canonical` AND
  `normalize(canonical)==canonical`), NOT a literal `raw==canonical`. All fixtures
  use `'` markers and `canonical()` uses `h`, so a literal compare would `fail`
  every real descriptor. The §9.1 parenthetical "(normalization round-trip)" is
  the operative definition.
- **C4** does the §17.6 item-6 cross-check (`descriptor-audit` explicitly defers
  it here): a key's `standard_path()` scheme must match the script type
  (`expected_scheme`: pkh→BIP44, sh(wpkh)→BIP49, wpkh→BIP84, taproot→BIP86,
  multisig→BIP48; others → no expectation). `Na` if no key carries a path; `Warn`
  on the first non-standard OR mismatched path. Uses `DescriptorType` (hence the
  `miniscript` dep) only for the three singlesig variants; multisig/taproot go via
  the `is_multisig()`/`is_taproot()` booleans to avoid naming sortedmulti variants.
- **F1/F2 are `Unknown` for every committed fixture** — they are all `tpub`, and a
  `tpub` is genuinely ambiguous across testnet/signet/regtest (`network_inference()
  .is_determinable()` is `false`), so the network is NOT determinable *from the
  descriptor*. `F1 Pass` requires a mainnet `xpub` (determined). `F2` is `Na` when
  determinable, `Pass` when `network_confirmed`, else `Unknown`. NOTE the two are
  distinct inputs: `with_network(..)` is the derivation target (G checks);
  `with_network_confirmed(true)` is the F2 signal. Supplying a network to derive
  on does NOT auto-satisfy F2.
- **G1–G3 need a resolved network**: `input.network` else `parsed.network()`
  (only mainnet resolves). With neither, G1=`Unknown`, G2/G3=`Na`-or-`Unknown`.
  No-`*` (fixed) descriptors derive count=1 (else `derive_chain` refuses count>1).
- **E2–E4 change branch**: `uses_multipath()` OR an explicit `with_change_descriptor`.
  Multipath `<0;1>` → expand → branch0=receive, branch1=change; E3 compares
  `desc_type()` of the two branches, E4 is a structural `Pass` for the 2-branch case
  (BIP389 guarantees "differ only in chain index"). The explicit-pair E4 is `Unknown`
  (rigorous path diffing deferred — no fixture yet).
- **B2** only fails on a CLEAR singlesig↔multisig contradiction; Taproot / richer
  policies are not failed against a declaration (avoids false mismatch).
- **D1** treats supported timelock Miniscript as a detected wallet type. The source
  fact is `ParsedDescriptor::uses_timelock()` from `descriptor-audit`; do not
  inspect descriptor text here.

## Test conventions
- `fixture!` wraps `include_str!` → the path MUST be a string literal. You cannot
  loop `for path in [...] { fixture!(path) }` — build an array of
  `(label, fixture!("literal"))` and loop over the contents instead.
- All committed descriptor fixtures are `tpub`; supply `with_network(Network::Testnet)`
  so the G checks derive. `Network` is re-exported from `address_derive`.
- To get a determinable (mainnet) descriptor without committing a mainnet key, lift
  a fixture `tpub` (`key_origins()[0].xpub()`) and re-version it to `xpub` by swapping
  the 4 Base58Check version bytes (`miniscript::bitcoin::base58` decode/swap/encode —
  the US-011 trick), then `compute_checksum`. See `to_mainnet_xpub` in tests.
- The singlesig fixtures (pkh/wpkh/sh_wpkh) all produce an identical 24-result
  vector; the multisig fixtures (2of3/3of5) another; `multipath_2of3` differs only in
  E2/E3/E4/G2 (change present). These full-vector asserts are the AC's "expected
  per-check results".

## US-020 — §16.3 critical failures + the H1–H9 checklist
- **Public API:** `evaluate_critical_failures(checks: &[Check], &CriticalContext) ->
  Vec<CriticalIssue>` and `forced_status(&[CriticalIssue]) -> Option<ReadinessStatus>`
  (`Some(NotReady)` iff non-empty, else `None` = "not forced; US-022 computes from
  the score"). Both **infallible** (the crate stays non-`Result`). `checks` is the
  SAME `run_checks` output the report's `checks[]` uses — the orchestrator runs it
  once and feeds both. For "no descriptor" inputs (detected secret, loose xpubs)
  pass an empty slice `&[]`.
- **The 12 codes each fire by exactly ONE rule, in §16.3 table order**, so the
  result is deterministic and duplicate-free (reports must be byte-identical).
  Source-of-truth text = `CriticalCode::meta()`, transcribed verbatim from the
  §16.3 table (`code`→`as_str()`, Check→`title()`, Description→`description()`).
  `CriticalIssue{code,title,description}` is the §19.1 `critical_issues[]` entry;
  `ReadinessStatus` (5 §16.2 variants, snake_case == §19.1 `score.status`:
  `not_ready` etc.) is introduced here but US-022 owns the score→status mapping,
  the §16.5 Cannot-Determine triggers, and the `Ready`/D8 known-address rule.
- **Check→code map (reads `run_checks` results):** `B2 Fail`→`C-WALLET-TYPE-MISMATCH`;
  `D4 Fail`→`C-DUPLICATE-XPUB`; `D5 Fail`→`C-KEY-COUNT-BELOW-THRESHOLD` (defensive —
  parse already rejects M>N so D5 is always Pass on a parsed descriptor); `G3 Fail`
  →`C-ADDRESS-MISMATCH`; `E2 Warn` + `change_descriptor_required`→
  `C-CHANGE-DESC-REQUIRED-MISSING` (E2 Warn == "not provided AND not multipath" ==
  the §16.3 condition).
- **Parse-time criticals key off `CriticalContext.parse_failure: Option<ErrorCode>`,
  NOT a check.** `E-PARSE-003`(`ChecksumInvalid`)→`C-DESC-CHECKSUM-INVALID`,
  `E-PARSE-005`(`ContainsPrivateKey`)→`C-DESC-CONTAINS-XPRV`,
  `E-PARSE-007`(`ThresholdExceedsKeys`)→`C-KEY-COUNT-BELOW-THRESHOLD`, anything else
  →`C-DESC-PARSE-FAIL`. These conditions never reach a `ParsedDescriptor` (the parser
  refuses with the `E-*` code), so this layer re-emits the matching `C-*` — the
  "doubles-as-an-E-code" half of the fact→scoring split. The caller passes
  `err.code()` from the failed `parse_descriptor`. THIS is why `error-taxonomy` is
  now a dep; it does NOT make the crate fallible (same precedent as the detector in
  US-016).
- **The two multisig criticals are disambiguated to never double-fire:**
  `C-MULTISIG-THRESHOLD-MISSING` = declared multisig AND descriptor parsed AND
  `D2 == Na` (no extractable M-of-N: Taproot key-path / richer policy) AND
  `B2 != Fail` (the `!= Fail` guard is essential — a declared-multisig *singlesig*
  descriptor is `B2 Fail` → `C-WALLET-TYPE-MISMATCH`, not threshold-missing).
  `C-MULTISIG-NO-DESCRIPTOR` = the explicit `with_multisig_descriptor_missing(true)`
  wizard signal (the user chose multisig but supplied only loose xpubs, so there is
  NO descriptor to analyze — no A–G check can express it).
- **Passphrase is modeled by a dedicated `Passphrase{Absent,Documented,Undocumented}`
  signal, NOT H4.** H4 ("documented *whether* a passphrase exists", yes/no) cannot
  express the §16.3 condition "a passphrase exists AND the heir packet omits it";
  only `Passphrase::Undocumented` → `C-PASSPHRASE-UNDOCUMENTED`. The wizard's
  passphrase sub-flow populates it directly.
- **`RecoveryChecklist` (H1–H9, every field `Option<Answer>`; `None` = unanswered /
  not-applicable like H2/H3 on singlesig) is accepted here** (`CriticalContext::
  with_checklist` / `.checklist()`) but US-020 only needs the passphrase signal for a
  critical; **US-021 reads `.checklist()` for the §16.4 warning weights** (e.g. H9
  `No` → `W-NO-RECENT-DRILL`). `Answer{Yes,No,Unsure}` serde snake_case.
- **`CriticalContext` mirrors `CheckInput`:** `Copy`, `Default`/`new()` + `with_*`
  builders. `declared_wallet_type` is duplicated here (also on `CheckInput` for B2)
  because the threshold-missing rule combines the declaration with the check results.
- **Tests:** one per code asserting the issue list AND `forced_status ==
  Some(NotReady)`; plus a clean wallet (empty + `None`), accumulation/ordering, the
  serde-rename↔`as_str` parity over `CriticalCode::ALL`, and the §19.1/snake_case
  shapes. Fixtures that drive the parse criticals self-check the `ErrorCode` first
  (`invalid_checksum.txt`→`ChecksumInvalid`, `threshold_exceeds_keys.txt`→
  `ThresholdExceedsKeys`, `contains_xprv.txt`→`ContainsPrivateKey`).

## US-021 — §16.4 warning weights and the numeric score
- **Public API:** `compute_score(checks: &[Check], &ScoringContext) -> ScoringResult`
  (**infallible** — the crate stays non-`Result`). Score starts at **100**, each
  fired warning subtracts its `WarningCode::impact()` (a negative weight), and the
  running total is clamped to `[0, 100]`. `ScoringResult { numeric: u32,
  scoring_audit: Vec<ScoringAuditEntry> }` — US-021 owns ONLY `score.numeric` +
  the §19.1 `scoring_audit`; the qualitative `status`/`headline` is US-022 and the
  richer `warnings[]` text (title/description/recommended_fix) is US-028.
- **`WarningCode` = the 13 active §16.4 codes; `meta()` is the single source of truth for
  the exact weights** (transcribed verbatim from the §16.4 table: `code` /
  `condition` (the "Check" column) / `impact`). serde per-variant `rename` to the
  `"W-…"` string, locked to `as_str()` by a parity test over `WarningCode::ALL`.
  **`ALL` is in §16.4 TABLE ORDER, which is also the order `compute_score` evaluates
  AND emits them** → the audit trail is deterministic (reports must be byte-identical).
  The mechanics mirror US-020's `CriticalCode` exactly.
- **The 13 active warnings come from THREE sources, all read here (never re-derived later):**
  1. **A–G check results:** `A2 == Warn` → `W-NO-DESC-CHECKSUM`; `E2 == Warn` →
     `W-NO-CHANGE-DESC`; `A1 == Pass && G3 == Na` → `W-NO-KNOWN-ADDRESS` (`G3 == Na`
     ⟺ no known address supplied; the `A1 == Pass` gate stops it firing on a
     parse-fail where every check is `Na`).
  2. **Descriptor facts on the context** (`ScoringContext::with_descriptor(parsed,
     has_explicit_change)` sets them so the crate still "reads the fact"):
     `is_singlesig() && has_explicit_change && !uses_multipath()` → `W-NO-MULTIPATH`.
     US-073 lifted the Taproot preview warning and US-074 lifted the
     Miniscript-in-wsh preview warning; supported Taproot and Liana-style timelock
     descriptors no longer affect scoring.
  3. **User/wizard answers:** the H1 / H5–H9 `RecoveryChecklist` entries, plus the
     three signals that are NOT H questions (`emergency_contact_named`,
     `hardware_signed_recently`, `backup_same_location`).
- **`RecoveryChecklist` → warnings (only 6 of the 9 H's have a §16.4 weight):** H1
  `physical_copies`→`W-NO-PRINTED-BACKUP`, H5 `wallet_software_documented`→
  `W-WALLET-SW-UNDOCUMENTED`, H6 `gap_limit_documented`→`W-NO-GAP-LIMIT`, H7
  `birth_height_documented`→`W-NO-BIRTH-HEIGHT`, H8 `heir_instructions_written`→
  `W-NO-HEIR-INSTRUCTIONS`, H9 `recent_drill`→`W-NO-RECENT-DRILL`. **H2/H3** (multisig
  completeness — feed US-022 survivability) and **H4** (passphrase — the US-020
  `C-PASSPHRASE-UNDOCUMENTED` critical) carry NO warning weight.
- **"Each skip = warning" (§9.1):** `not_confirmed(answer) = answer != Some(Answer::
  Yes)` — only an explicit `Yes` suppresses a checklist warning; `No`, `Unsure`, AND
  unanswered (`None`, skipped) all FIRE it. The two "good-thing-confirmed" bools
  (`emergency_contact_named`, `hardware_signed_recently`) default to `false` → fire;
  `backup_same_location` is inverted (fires on `true`) and defaults `false` → no fire.
  So `ScoringContext::default()` is the conservative "nothing answered" baseline.
- **C4 path-scheme precedence:** Taproot descriptors expect BIP86 even when a
  `multi_a` leaf also makes them multisig-shaped. Check `parsed.is_taproot()`
  before `parsed.is_multisig()` when deriving the expected scheme; legacy P2WSH
  multisig remains BIP48.
- **The thirteen active weights sum to -92**, so the realistic numeric range is `[8, 100]`;
  the clamp's 0 floor is DEFENSIVE (unreachable via the active warnings) — there is no
  natural test that floors it, so don't expect one.
- **`SCORING_ENGINE_VERSION = "0.1.0"`** is a `pub const` (the §19.1 TOP-LEVEL
  `scoring_engine_version`, NOT inside the `score{}` object); weights are NOT
  user-configurable (§16.7 — score-shopping). US-028 stamps the const into the report.
- **`ScoringContext` mirrors `CriticalContext`** (`Copy`, `Default`/`new()` + `with_*`
  builders). Its `RecoveryChecklist` is DUPLICATED with `CriticalContext`'s — the
  orchestrator (US-028) sets the SAME checklist on both, exactly like
  `declared_wallet_type` is duplicated across `CheckInput`/`CriticalContext`.
- **Tests:** weight-table lock (`impact()` per code + `ALL` order + sum==-92), the
  serde-rename↔`as_str` parity, a fully-prepared wallet → 100/empty-audit, one
  warning fired in isolation for each active code (impact + running_score), the
  "only Yes suppresses" matrix, the §19.1 `scoring_audit` shape (single entry +
  the W-NO-CHANGE-DESC→W-NO-RECENT-DRILL 85/75 example), all-active-warnings
  reconstructing numeric==8 in table order, and a `run_checks`→`compute_score` integration. Synthetic
  `Check`s (a `scoring_check(code,result)` helper) isolate scoring from fixtures —
  `compute_score` only reads A1/A2/E2/G3, so a 4-element checks vec is enough.
- **NOTE for US-022:** consume `ScoringResult.numeric` + `forced_status(&criticals)`;
  when `forced_status` is `None`, map `numeric` → `ReadinessStatus` per §16.2 (Ready
  also needs zero criticals + a D8 known-address match). §16.6 multisig survivability
  (`lose_1_signer`/…) is a SEPARATE dimension, not a warning. (Done — see below.)

## US-022 — §16.2 status, §16.5 Cannot Determine, §16.6 survivability
- **Public API:** `map_status(checks: &[Check], numeric: u32, criticals: &[CriticalIssue],
  &StatusContext) -> ReadinessStatus`; `compute_survivability(&ParsedDescriptor) ->
  Option<Survivability>`; `ReadinessStatus::headline() -> &'static str`. All
  **infallible** (the crate stays non-`Result`). The §19.1 `score` object is assembled
  by US-028 as `{numeric` (US-021)`, status:` `map_status(..)`, `headline:`
  `status.headline()}`; the `survivability` object is SEPARATE and present only for
  multisig.
- **`map_status` precedence (do NOT reorder):** (1) `forced_status(criticals)` — any
  §16.3 critical ⇒ `NotReady`, *regardless of score AND of any §16.5 signal* (a
  definitive finding beats "insufficient info"); (2) `cannot_determine(..)` ⇒
  `CannotDetermine`; (3) numeric band: `Ready` 90–100, `MostlyReady` 70–89,
  `NeedsAttention` 40–69, `NotReady` 0–39. **`Ready` ALSO requires the D8 match
  (`G3 == Pass`)** — a 90+ score without a confirmed known address falls to
  `MostlyReady` (and since no-known-address fires `W-NO-KNOWN-ADDRESS` -10, 90 is the
  practical ceiling without D8). "Zero criticals" for `Ready` is guaranteed by step 1's
  early return, not re-checked.
- **`headline()`** returns the §15.10/§19.1 Title-Case string (`"Ready"`,
  `"Mostly Ready"`, `"Needs Attention"`, `"Not Ready"`, `"Cannot Determine"`); the
  snake_case `serde` form is the `status` field. Two distinct representations.
- **The four §16.5 Cannot-Determine triggers split by source:** condition 1 (network
  undeterminable) is DERIVED from checks = `F1 == Unknown && F2 != Pass && G1 == Unknown`
  (G1 Unknown ⟺ no resolvable network; supplying `with_network(..)` makes G1 Pass/Fail
  and lifts it, so a tpub with a chosen derivation network is NOT cannot-determine).
  Condition 2 (key origin ENTIRELY absent) is a descriptor fact set via
  `StatusContext::with_descriptor(&parsed)` → `key_origins_entirely_absent` (ALL keys
  lack both fingerprint AND path; PARTIAL origins do not trigger it — checks C1/C2 can't
  express "entirely" vs "partial", which is why it's a context flag not a check).
  Conditions 3 (`with_unrecognized_export`) and 4 (`with_wizard_aborted`) are explicit
  wizard signals. **CRITICAL for US-027/028:** an unrecognized *import file* must pass
  NO parse-failure critical — it is `CannotDetermine`, distinct from a broken
  *descriptor* (`C-DESC-PARSE-FAIL` ⇒ `NotReady`). `StatusContext` mirrors
  `ScoringContext`/`CriticalContext` (`Copy`, `new()`/`Default` + `with_*`).
- **Survivability (§16.6) is analytical, not a drill:** `compute_survivability` reads
  `multisig_info()` (so `None` for singlesig, Taproot key-path, and richer policies —
  they get other dimensions later) and answers M-of-N quorum math. `lose_k` is `"ok"`
  iff `N - k >= M` (saturating), else `"fail_expected_for_<M>of<N>"` (the loss is
  inherent to the quorum, not a defect). `lose_descriptor_only` is the constant
  `"ok_if_xpubs_retained"` (a standard multisig descriptor rebuilds from xpubs + quorum
  + script type). The verdict fields are `String` (NOT an enum) because
  `"fail_expected_for_2of3"` is parametric in M/N. `tested: true` whenever the object
  exists — the analytical quorum evaluation IS the §16.6 test (the v0.2 DS-6 signing
  drill exercises the same scenarios with real signatures and reuses this shape).
  Matches the §19.1 example byte-for-byte for a 2-of-3.
- **Tests:** numeric-band boundaries (89/90, 69/70, 39/40) with a synthetic `G3==Pass`
  check for the `Ready` gate; the D8 requirement (95 + G3 Pass ⇒ Ready, 95 + G3 Na ⇒
  MostlyReady); criticals force NotReady over a perfect score AND over a §16.5 signal;
  one test per §16.5 trigger (condition 1 via a no-network tpub fixture, condition 2 via
  a bare mainnet-xpub built with `to_mainnet_xpub` + `compute_checksum`, 3/4 via the
  flags); an end-to-end `Ready` (multipath 2-of-3 + matched `known_match_tb1` + full
  context ⇒ 100 + D8); survivability for 2-of-3 (matches §19.1) and 3-of-5 (survives
  both), plus `None` for singlesig and Taproot key-path.

## Dependencies
- `descriptor-audit`, `address-derive`, `miniscript` (for `DescriptorType`), `serde`,
  and (since US-020) `error-taxonomy` — used ONLY to read a parse failure's
  `ErrorCode` and map it to the precise parse-time `C-*` critical. The crate is still
  infallible: `run_checks` / `evaluate_critical_failures` / `forced_status` /
  `compute_score` / `map_status` / `compute_survivability` never return `Result`.
  US-021 and US-022 added NO new dependency. `serde_json` is dev-only (JSON-shape lock
  tests).
