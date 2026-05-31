# descriptor-audit — notes for future iterations

Output-descriptor parsing/validation/analysis. Built up across US-003..US-011,
US-073, and US-074.

## Entry point and the shared type
- `parse_descriptor(&str) -> Result<ParsedDescriptor, LifeboatError>` is the single
  parse entry. Order matters: trim → empty? `E-INPUT-001` → reject `combo`/`addr`/`raw`
  (`E-PARSE-006`) **before** miniscript → `Descriptor::<DescriptorPublicKey>::from_str`
  (`E-PARSE-001` on failure) → `sanity_check()` (`E-PARSE-001` on failure).
- `ParsedDescriptor` keeps the user's `raw()` input verbatim (PRD §17.3) plus the typed
  `descriptor()` (`Descriptor<DescriptorPublicKey>`). **Extend analysis by adding
  methods/fields here** (checksum US-004, canonical/normalize US-005, M-of-N US-006,
  key origins US-008, multipath US-009, taproot/xprv US-010, network US-011,
  Miniscript/timelock US-074) — don't add parallel parse functions.
- Unsupported-function rejection must run before miniscript, or the user gets a generic
  `E-PARSE-001` instead of the specific `E-PARSE-006`. The check is `name(` prefix on the
  trimmed string (these are top-level-only functions).

## Checksums (US-004)
- Public API: `validate_checksum(&str) -> Result<ChecksumStatus, LifeboatError>` and
  `compute_checksum(&str) -> Result<String, LifeboatError>`. Reused by the CLI `checksum`
  command (US-037) and the Tauri `validate_checksum`/`compute_checksum` commands (US-042) —
  don't reimplement checksum logic in those layers.
- `parse_descriptor` calls `validate_checksum` **before** `from_str`, so a transcription
  error gets the specific critical `E-PARSE-003` (`ChecksumInvalid`) instead of a generic
  `E-PARSE-001`. The verdict is stored on `ParsedDescriptor::checksum_status()`.
- `ChecksumStatus` has only `Present`/`Missing`. An *invalid* checksum is fatal
  (`E-PARSE-003`) so it never produces a `ParsedDescriptor`. `Missing` is non-fatal and maps
  to the warning `W-NO-DESC-CHECKSUM` (`E-PARSE-002`, -5) — US-019/US-021 read
  `checksum_status()` to emit that warning; this crate does NOT score.
- miniscript checksum module is `miniscript::descriptor::checksum` (`pub`):
  - `verify_checksum(s) -> Result<&str, Error>` returns `Ok` when there is **no** `#`
    (it's permissive about absence), and `Err` on mismatch/bad-length/non-charset char. So
    detect presence yourself first with `s.contains('#')`, then call verify only when present.
  - `Engine::new()` + `engine.input(body)?` + `engine.checksum() -> String` computes the
    8-char checksum. `compute_checksum` strips any existing `#...` (`rfind('#')`) and recomputes,
    so it is idempotent. Checksum chars are lowercase bech32 (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`).
- To mint an `invalid_checksum.txt` fixture: copy a `*_valid.txt`, flip ONE checksum char to
  another bech32 char (e.g. `...#r6yctejg` -> `...#r6yctejq`). The `present-invalid` test
  asserting `E-PARSE-003` self-checks that you actually broke it.

## Normalization (US-005)
- Public API: `normalize(&str) -> Result<String, LifeboatError>` (free fn) and
  `ParsedDescriptor::canonical() -> &str` (stored at parse time). `normalize(x)` is just
  `parse_descriptor(x)?.canonical().to_owned()`; both go through one private
  `canonicalize(&Descriptor<..>)`. This is `descriptors.*.canonical` in the §19.1 report.
- Canonical form = `Descriptor::to_string()` with `'` → `h`, then a **freshly recomputed**
  checksum. Recompute is mandatory: `'` and `h` are different characters in the BIP380
  checksum input charset, so swapping markers invalidates the appended checksum. The
  one-liner `compute_checksum(&descriptor.to_string().replace('\'', "h"))` works because
  `compute_checksum` strips the stale `#...` and recomputes over the `h`-body.
- Why a blind global `'`→`h` replace is safe: in a descriptor `'` only ever appears as a
  hardened-derivation marker (keys are hex/base58/bech32; the checksum charset excludes `'`),
  so it touches exactly those markers. The §19.1 example confirms canonical uses `h`
  (`[abc...h/48h/0h/0h/2h]`, path `m/48h/0h/0h/2h`).
- §17.3 has 5 steps; US-005 does steps 1–3 (to_string + checksum + marker). Steps 4
  (multipath `<0;1>` expansion) and 5 (`sortedmulti` lexicographic ordering) are US-009/US-006.
- To prove `'`/`h` equivalence in tests without a second fixture set, rewrite a `'`-fixture
  to its `h`-form with a fresh checksum (`compute_checksum(&body.replace('\'', "h"))`) and
  assert both normalize identically. Round-trip stability = `normalize(normalize(x)) == normalize(x)`.

## Multisig (US-006)
- Public API on `ParsedDescriptor`: `multisig_info() -> Option<MultisigInfo>` and `is_multisig()`.
  `MultisigInfo` exposes `threshold()` (M), `key_count()` (N), `kind()`
  (`MultisigKind::{Multi,SortedMulti}` + `is_sorted()`/`as_str()`), `is_sorted_multi()`,
  `keys()` (`&[DescriptorPublicKey]`, descriptor order), and `keys_lexicographically_sorted()`.
  US-007 (duplicate-xpub / threshold integrity) and US-008 (key origins) build on `keys()`.
- `multi` and `sortedmulti` are represented **differently** by rust-miniscript — extraction must handle both:
  - `sortedmulti` → a dedicated `SortedMultiVec` (`.k()`=M, `.n()`=N, `.pks()`=keys), reached via
    `WshInner::SortedMulti` / `ShInner::SortedMulti`. Generic over Ctx (`Segwitv0` for wsh, `Legacy` for sh) —
    write one `fn from_sorted_multi<Ctx: ScriptContext>(…)`.
  - `multi` → a `Miniscript` whose **root** `Terminal` is `Terminal::Multi(Threshold)` (`.k()`=M, `.data()`=keys),
    reached via `WshInner::Ms` / `ShInner::Ms` / `Bare::as_inner()`. Match `ms.as_inner()`; any non-`Multi` root
    (timelocks, `or_d`, Liana) is **not** a plain multisig → return `None`. US-074
    exposes those as `uses_miniscript()`/`uses_timelock()` facts, not as M-of-N.
  - So walk the wrappers `Descriptor::{Wsh,Sh,Bare}` (and `Sh(ShInner::Wsh(..))`) down to the leaf. Types live at
    `miniscript::descriptor::{WshInner,ShInner,SortedMultiVec}` and `miniscript::{Terminal,Miniscript,ScriptContext}`.
- PARSE GOTCHAS (confirmed empirically): top-level `multi(M,…)` parses as `Descriptor::Bare` (sanity OK), but bare
  `sortedmulti(…)` **does not parse** ("unrecognized name") — `sortedmulti` only exists inside `sh`/`wsh`. The §17.2
  table lists bare `sortedmulti` but it isn't a real miniscript form. `desc_type()` is `…SortedMulti` for sortedmulti
  but just `Wsh`/`Sh`/`ShWsh` for `multi` (so type alone can't give M/N — extract from the inner).
- ORDERING: miniscript **preserves** sortedmulti key order in `to_string()` (two orderings → different checksums; it
  does NOT re-sort). BIP67's funds-affecting sort is on the **derived** pubkeys per index, not the descriptor xpubs, so
  `keys_lexicographically_sorted()` is a descriptor-**text** diagnostic (are the written keys tidy), comparing
  `key_body` (the key with any `[origin]` stripped), NOT a correctness check. §17.3 step-5 re-sorting in `canonicalize`
  is intentionally **not** done (not required by US-006; would change the canonical string; reordering sortedmulti is
  safe but deferred).
- Fixtures `fixtures/descriptors/multisig/wsh_sortedmulti_{2of3,3of5}.txt`: BIP48 native-segwit-multisig
  (`/48h/1h/0h/2h`), distinct tpubs from fixed seeds `[i+1; 32]` (i=0..5), keys sorted by xpub body, single path
  `/0/*` (multipath `<0;1>` is US-009). Mint via the throwaway-example trick from US-003 (build the string, parse,
  print `to_string()` for the checksummed canonical).

## Multisig integrity (US-007)
- Three self-inconsistency checks, wired into the `parse_descriptor` spine. They fire at
  three DIFFERENT stages because rust-miniscript treats each case differently (verified
  empirically with a throwaway example — regenerate the same way if you need to recheck):
  - **Quorum bounds `1 <= M <= N <= 15`** → `E-PARSE-007` (`ThresholdExceedsKeys`). Checked
    by `check_quorum_bounds(trimmed)` **before `from_str`**, because miniscript rejects
    `M > N` ("invalid threshold 4-of-3; cannot have k > n") and `M = 0` ("k > 0") with a
    GENERIC error (→ vague `E-PARSE-001`) and SILENTLY ACCEPTS `N > 15` in `wsh`. A textual
    pre-check is the only way all three map to the specific code. `extract_quorum` finds
    `multi(` (which also matches the tail of `sortedmulti(`; `multi_a(` does NOT contain it),
    then counts commas at the multi's paren depth: first arg = M, remaining = N keys. Safe
    because descriptor keys never contain `(`/`)`/`,` (xpubs, hex, `[origin]`, `/`paths,
    `<a;b>` multipath are all comma/paren-free).
  - **Mixed networks** → `E-PARSE-004` (`NetworkMixed`), HARD error. miniscript PARSES +
    SANITY-CHECKS a testnet+mainnet `sortedmulti` FINE, so we detect it ourselves AFTER
    `from_str` via `check_single_network` (collect each key's `NetworkKind` with
    `descriptor.for_each_key`, error if >1 distinct). `NetworkKind` is only Main vs Test
    (testnet/signet/regtest share version bytes — finer split is US-011).
  - **Duplicate xpub** → NON-FATAL FACT (`ParsedDescriptor::has_duplicate_keys()` +
    `MultisigInfo::has_duplicate_keys()`), NOT an error. There is NO E-code for it; it maps to
    the §16.3 critical CONDITION `C-DUPLICATE-XPUB`, which US-020 (readiness-score) emits from
    this fact. §17.6 lists duplicate-xpub as a multisig ANALYSIS OUTPUT, so the descriptor
    must still parse. GOTCHA: miniscript's `sanity_check` REJECTS exact repeats ("Miniscript
    contains repeated pubkeys or pubkeyhashes"), so `parse_descriptor` tolerates a
    sanity-check failure IFF we detected duplicates ourselves; any OTHER sanity failure stays
    fatal `E-PARSE-001`. This swallow also handles same-xpub-DIFFERENT-path (which miniscript
    does NOT flag but `key_identity` does), since then sanity passes and we just record the fact.
- `key_identity` dedups by the xpub ALONE (strips `[origin]` and `/path`), so the same xpub
  under two derivation paths counts as a duplicate — that is the "illusory quorum" (§16.3).
- The asymmetry (mixed→E-code error, M>N→E-code error, duplicate→C-code fact) is intentional
  and matches both the US-007 acceptance text and §16.3/§17.6: descriptor-audit produces typed
  ERRORS where an E-code exists and unusable input must be refused; it produces FACTS for
  critical CONDITIONS that the scoring layer judges. A mixed-network desc can't derive (which
  chain?) so it's fatal; a duplicate-key desc still derives (just weak) so it's analyzed + flagged.
- Fixtures: `fixtures/descriptors/multisig/{duplicate_xpub,threshold_exceeds_keys}.txt` and
  `fixtures/descriptors/invalid/network_mixed.txt`. Built from the 2-of-3 fixture's keys. The
  mainnet key for `network_mixed` was minted WITHOUT secp256k1 by parsing a testnet key and
  flipping `DescriptorPublicKey::XPub(dx).xkey.network = NetworkKind::Main` then `to_string()`
  (Display recomputes the base58check checksum from the new version bytes). `threshold_exceeds_keys`
  does NOT parse, so its checksum was minted with `compute_checksum(body)` (checksum is over the
  text, no semantic parse) — the usual "parse + to_string" minting trick can't be used there.

## Key origins (US-008)
- Public API on `ParsedDescriptor`: `key_origins() -> Vec<KeyOrigin>` (one per key, in
  descriptor order), `hardened_marker_style() -> HardenedMarkerStyle`, and
  `hardened_markers_consistent() -> bool`. `KeyOrigin` exposes `index()`, `fingerprint()`
  (`Option<Fingerprint>`) + `fingerprint_hex()` (8 lowercase hex), `derivation_path()`
  (`Option<&DerivationPath>`, the ORIGIN path m→account) + `derivation_path_display()`
  (§19.1 `m/48h/0h/0h/2h` form), `xpub()` (`Option<&str>`, the extended key string),
  `has_fingerprint()`/`has_derivation_path()`/`key_origin_present()` (the last = both
  present, with a NON-EMPTY path), and `standard_path()`/`is_standard_path()`.
- This crate ONLY extracts/classifies. The §9.1 checks C1–C4 (US-019) and §19.1 `keys[]`
  redaction (US-030) consume these; standard-path-vs-script-type cross-check is US-019's job.
- Order: `key_origins()` uses the new shared `collect_keys()` (= `for_each_key`, descriptor
  order). Verified: a sortedmulti's keys come out in WRITTEN order (the 2-of-3 fixture yields
  fingerprints `4ba43603, 6e37edb9, 8dfc9b34`), matching `multisig_info().keys()`.
- `DescriptorPublicKey` origin access (miniscript 13): each variant has
  `.origin: Option<(Fingerprint, DerivationPath)>`. `XPub`/`MultiXPub` also have `.xkey`
  (the `bip32::Xpub`; `xkey.to_string()` is the xpub) and a derivation path
  (`x.derivation_path` / `m.derivation_paths.paths()` for multipath); `Single` has NO xpub.
  A bare key (`wpkh(tpub.../0/*)`) → `origin = None`; a fingerprint-only origin (`[abc12345]`)
  → `Some((fp, <empty path>))`, so `has_fingerprint()` true but `has_derivation_path()` false.
- `bip32::DerivationPath` GOTCHAS: NO `Deref` to `[ChildNumber]`, so `.iter()` is unavailable —
  iterate with `(&path).into_iter()` (yields `&ChildNumber`); it DOES have an inherent
  `.is_empty()`. Display omits the `m/` prefix and uses `'` (e.g. `48'/1'/0'`), so the §19.1
  form is `format!("m/{path}").replace('\'', "h")`. `Fingerprint` Display = 8 lowercase hex.
- Standard-path classification (`classify_standard_path`): require ALL components hardened, then
  match (purpose, len): `(44|49|84|86, 3)` and `(48, 4)`. The BIP48 script-type subfield value
  is NOT validated (any 4-hardened `48h/...` is BIP48). `tr(...)` parses in miniscript
  and is supported after US-073, so BIP86 detection works today.
- Hardened-marker consistency WITHOUT scanning for `h` (which also appears in base58/bech32):
  count total hardened components from the TYPED paths (`total_hardened`), count `'` in `raw`
  (every `'` in a valid descriptor is a hardened marker — the char is absent from keys and the
  checksum charset). `h`-markers = total − apostrophes ⇒ None (total 0) / Apostrophe (==total) /
  H (0) / Mixed (between). Computed from `raw`, since `canonical` always uses `h`.
- `enum_variant_names` does NOT fire for `StandardPath::{Bip44,Bip49,Bip84,Bip86,Bip48}` (the
  shared `Bip` prefix is fine) — no `#[allow]` needed; verified under `-D warnings`.
- TEST TRICK (no new fixtures): build origin variants by stripping `[origin]` off a fixture
  key's `to_string()` (everything after the first `]`) to get `tpub.../0/*`, then prepend a
  custom `[fp/path]`. Parse the result WITHOUT a checksum — `ChecksumStatus::Missing` is
  non-fatal, so you skip checksum bookkeeping. Mint a Mixed-marker case with
  `raw.replacen('\'', "h", 1)` over a checksum-stripped fixture body.

## Multipath / BIP389 (US-009)
- Public API on `ParsedDescriptor`: `uses_multipath() -> bool` (computed on demand via
  `descriptor.is_multipath()`; surfaced as `wallet_summary.uses_multipath` in §19.1) and
  `expand_multipath() -> Result<Vec<Descriptor<DescriptorPublicKey>>, LifeboatError>`.
- `expand_multipath` is just `self.descriptor.clone().into_single_descriptors()` with the
  miniscript error mapped to `E-PARSE-001`. miniscript guarantees the result is **never empty**:
  a non-multipath descriptor returns `vec![itself]`. Order follows the written multipath
  indices, so for the conventional `<0;1>` form `expanded[0]` = receive (…/0/*), `expanded[1]`
  = change (…/1/*). Consumers (address-derive US-017, readiness E2/E3/E4 US-019, report
  receive/change US-028) read `.first()`/`.get(1)` — don't re-derive the convention elsewhere.
- Canonical/raw **preserve** the multipath form (`<0;1>` stays intact); expansion is a separate
  "for analysis" step and does NOT fold into `canonicalize` (§17.3 step 4 is expansion-for-
  analysis, not a normalization rewrite). The report shows the canonical *multipath* string.
- WHY the parse spine already handles multipath unchanged (no edits to `parse_descriptor`
  were needed): `<`, `;`, `>` are all valid BIP380 descriptor-charset chars (miniscript's
  `checksum::CHAR_MAP` maps ASCII 59/60/62), so `compute_checksum`/`canonicalize` accept a
  multipath body; `extract_quorum`'s comma-at-depth-1 counting is unaffected (`<0;1>` has no
  `,`/`(`/`)`); `multisig_info()` reads `SortedMultiVec`/`Terminal::Multi` regardless of whether
  the keys are `MultiXPub`. miniscript also REJECTS at `from_str` any multipath whose keys
  disagree on the number of indices (e.g. `<0;1>` with `<0;1;2>`), so a surviving
  `ParsedDescriptor` always expands cleanly — the `expand_multipath` error arm is unreachable
  in practice but keeps the call panic-free.
- miniscript derivation facts (reused by address-derive US-017): a multipath
  `Descriptor::at_derivation_index(i)` ERRORS ("contains multi-path derivations"); an expanded
  single-path branch's `at_derivation_index(i)` returns `Descriptor<DefiniteDescriptorKey>`,
  whose `.address(Network)` yields the address. That err-vs-ok split is the cleanest in-test
  proof that a branch is "derivable" — no secp/network setup needed for the err check.
- Fixture `fixtures/descriptors/multisig/multipath_2of3.txt`: the existing
  `wsh_sortedmulti_2of3.txt` with each `/0/*` rewritten to `/<0;1>/*`, re-minted through the
  throwaway-example trick (build no-checksum string → `from_str` → print `to_string()` for the
  BIP380 `#checksum`). NICE PROPERTY used as a test cross-check: its `/0` expansion is
  byte-identical to `wsh_sortedmulti_2of3.txt` (`#c2yhzrq7`), and the `/1` branch is `#al0du9sk`.

## Private-key refusal + Taproot preview (US-010)
- **xprv blocking**: `parse_descriptor` calls `reject_private_keys(trimmed)` **first**
  (right after the empty check, before everything else — a private key is the most
  security-critical problem). It returns critical `E-PARSE-005` (`ContainsPrivateKey` /
  §16.3 `C-DESC-CONTAINS-XPRV`). Placement is first so a descriptor that is *also*
  e.g. `combo(...)` or checksum-broken still reports the private-key reason.
- WHY textual, not parse-based: `Descriptor::<DescriptorPublicKey>::from_str` rejects an
  xprv with a GENERIC, misleading error ("public keys must be 64, 66 or 130 characters")
  → would surface as vague `E-PARSE-001`. AND the `E-PARSE-005` contract is that Lifeboat
  *refuses to process* secret material — so we recognize the key's SHAPE and refuse
  **without Base58-decoding it or running secp on it**. `Descriptor::parse_descriptor(&secp, s)`
  *would* walk the tree (returns `(Descriptor<DescriptorPublicKey>, KeyMap)`; non-empty
  KeyMap ⇒ private keys present) but it does an EC operation on the secret — deliberately
  NOT used here. Confirmed empirically with a throwaway example (deleted).
- Detection (`contains_extended_private_key`): scan for any prefix in
  `EXTENDED_PRIVATE_KEY_PREFIXES` (`xprv`/`tprv`/`yprv`/`zprv`/`uprv`/`vprv` + SLIP-132
  uppercase `Yprv`/`Zprv`/`Uprv`/`Vprv`, per §13.5.3) that sits at a KEY BOUNDARY
  (`is_key_boundary`: start-of-string or immediately after `(`, `,`, `]`) AND is followed by
  ≥100 alphanumeric chars (`has_key_length_after`; real extended keys have ~107 trailing).
  - NO FALSE POSITIVES on valid watch-only descriptors: the boundary chars `(`/`,`/`]` never
    appear inside a Base58 key body, so a `prv` substring can only match at a real key start,
    and public keys never start with a `prv` prefix. `watch_only_descriptors_are_never_flagged_as_private`
    locks this across every public fixture. The length floor avoids flagging incidental `tprv` in garbage.
- SCOPE: only EXTENDED private keys (that's exactly what `C-DESC-CONTAINS-XPRV` names). **Raw**
  private keys (WIF, raw hex) are the `sensitive-input-detector` crate's job (US-014/US-015),
  which runs on every paste BEFORE a descriptor reaches this parser. A WIF that arrives here
  still fails (`from_str` → "key too short" → `E-PARSE-001`), just not with a specific code.
- **Taproot support**: `ParsedDescriptor::is_taproot()` = `matches!(desc_type(), DescriptorType::Tr)`.
  `tr(KEY)` and `tr(KEY,{multi_a(...)})` parse and derive as supported descriptors. US-073 lifted
  the scoring preview warning. `multisig_info()` returns `MultisigKind::MultiA` only for a single
  Taproot `multi_a` script-path leaf; key-path Taproot and richer Taproot trees stay valid but do
  not expose one M-of-N fact. `key_origins()` extracts both the internal key and leaf keys.
  `extract_quorum`/`check_quorum_bounds` checks `multi_a(` directly because it is not caught by the
  legacy `multi(`/`sortedmulti(` search.
- Fixtures: `fixtures/descriptors/invalid/contains_xprv.txt` (a `wpkh([origin]tprv.../0/*)` minted
  from a fixed testnet seed — NEVER mainnet — with a valid checksum via `compute_checksum(body)`,
  since `to_string()` can't be used: it won't parse an xprv); `fixtures/descriptors/taproot/{tr_keypath,
  tr_scriptpath_multi_a}.txt` (BIP86 `m/86h/1h/0h`, 3 distinct testnet keys, `'` markers + checksum
  via the throwaway-example `to_string()` trick).

## Miniscript / timelock policies (US-074)
- Public facts on `ParsedDescriptor`: `uses_miniscript()` and `uses_timelock()`. These
  are the source of truth for report summaries, D1 wallet-type detection, and import
  classification. Consumers should read these facts; do not parse `or_d`/`older` text
  in downstream crates.
- `uses_miniscript()` means "richer policy than singlesig or plain quorum." Plain
  `multi(...)` / `sortedmulti(...)` are already represented by `multisig_info()`, so
  they deliberately return `false` here. Taproot support has `is_taproot()` and
  Taproot `multi_a` quorum facts, so those are not counted as legacy `wsh` Miniscript.
- `uses_timelock()` recursively walks Miniscript `Terminal` values and returns `true`
  for `Terminal::After(_)` and `Terminal::Older(_)`, including nested `and_v`, `or_d`,
  threshold, and Taproot leaves. A Liana policy still has `multisig_info() == None`
  because it is a recovery policy, not one plain M-of-N quorum.
- Fixture `fixtures/descriptors/timelock/liana_basic.txt` is a Liana-style
  `wsh(or_d(pk(K),and_v(v:pkh(R),older(65535))))` descriptor with BIP389
  `<0;1>` multipath. Pinned checksums: multipath `#d3zjscz4`, receive `/0/*`
  `#uny393kd`, change `/1/*` `#s0952kd2`. Derivation vectors live in
  `address-derive`; report/scoring/import tests consume the same fixture end to end.

## Network inference + SLIP-132 (US-011)
- **Network inference** is a FACT on `ParsedDescriptor`: `network_inference() -> NetworkInference`
  and the shorthand `network() -> Option<Network>`. `NetworkInference` is
  `Determined(Network)` | `AmbiguousTestNetwork` | `NoExtendedKeys` with `network()`,
  `is_determinable()`, `candidates() -> Vec<Network>`. This crate does NOT decide the network or
  apply the default — readiness-score US-022 maps `!is_determinable()` to the §16.5 "Cannot
  Determine" status (same fact→scoring split as checksum/taproot).
- THE KEY REALITY (PRD §17.4): extended-key version bytes only distinguish **mainnet** (`xpub`,
  unique → `Determined(Network::Bitcoin)`) from the **test family** (`tpub`). testnet, signet,
  and regtest SHARE the `tpub` version bytes, so any `tpub` descriptor is `AmbiguousTestNetwork`
  — never guess one (regtest addresses differ: `bcrt` hrp). `miniscript::bitcoin::NetworkKind` is
  exactly this Main-vs-Test split; `infer_network` reads the first key's `NetworkKind`
  (`parse_descriptor` already guaranteed a single network via `check_single_network`). A
  raw-pubkey descriptor (`Single`) has no version bytes → `NoExtendedKeys`.
- **SLIP-132 normalization** is a STANDALONE free fn `normalize_slip132(&str) ->
  Result<Slip132Normalization, _>` (NOT wired into `parse_descriptor`). It rewrites public
  `ypub`/`zpub`/`Ypub`/`Zpub` → `xpub` and `upub`/`vpub`/`Upub`/`Vpub` → `tpub` by swapping the 4
  Base58Check version bytes (key material untouched), matched at a key boundary (reuses
  `is_key_boundary`). The wallet-import layer (US-023+) / CLI call it BEFORE `parse_descriptor`
  (rust-bitcoin's `Xpub::from_str` rejects SLIP-132 version bytes outright). It is kept out of the
  parse spine on purpose: rewriting a key body would invalidate a user's BIP380 `#checksum`
  computed over the original SLIP-132 text. When it rewrites ≥1 key it returns a freshly computed
  checksum (`compute_checksum`); with no SLIP-132 key it returns the trimmed input verbatim.
- API facts: `miniscript::bitcoin::base58::{decode_check(&str)->Result<Vec<u8>,_>,
  encode_check(&[u8])->String}`; an extended key decodes to 78 bytes (`EXTENDED_KEY_LEN`), version
  in `[0..4]`, key data in `[45..78]`. `Network` Display = `bitcoin`/`testnet`/`signet`/`regtest`
  (the §19.1 `network` strings). Standard version bytes: xpub `0488b21e`, tpub `043587cf`.
- TEST TRICK (no new fixtures, and never a real mainnet key): lift a valid `tpub` from a fixture
  via `parse_descriptor(...).key_origins()[0].xpub()`, then re-version it with a tiny
  decode/swap/encode helper to mint a synthetic xpub/zpub/vpub at runtime. Round-trips prove
  normalization (zpub→xpub, vpub→tpub). Hardcoding a Base58 literal is fragile — a wrong checksum
  makes `decode_check` panic (learned the hard way).
- CLIPPY GOTCHA: building a hex string with `iter().map(|b| format!("{b:02x}")).collect()` trips
  `clippy::format_collect` (in `clippy::all`, so `-D warnings` fails it even though `cargo test`
  only warns). Use `write!(s, "{b:02x}")` into a `String` (the lint's own suggestion).

## Errors
- Always `error_taxonomy` codes (see that crate's CLAUDE.md). Chain the miniscript error
  via `.with_source(e)` — miniscript errors describe script structure, never key
  material, so they're safe to surface. Add only secret-free `.with_context(...)`.

## Dependencies
- Reach rust-bitcoin through `miniscript::bitcoin` (e.g. `miniscript::bitcoin::bip32`);
  no direct `bitcoin` dep is needed for this crate.

## Fixtures (reused by US-004/005 and address-derive/report tests later)
- Live at **repo-root** `fixtures/descriptors/...` (NOT under the crate). Read them in
  tests with the `fixture!` macro:
  `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/", $path)).trim()`.
- Keys are derived from a **fixed testnet seed → tpub**. Never mainnet (PRD §27 / US-040
  anonymization rule). To mint a valid fixture: build the descriptor with no checksum,
  parse it, and print `descriptor.to_string()` — miniscript appends a valid BIP380
  `#checksum`. (A throwaway `examples/` binary did this in US-003; regenerate the same way.)

## miniscript gotchas
- `descriptor.desc_type()` → `DescriptorType` (`Pkh`/`Wpkh`/`ShWpkh`/`Wsh`/`Tr`/…); used
  for classification and `is_singlesig()`.
- A "sigless" descriptor (only timelocks, no key — e.g.
  `wsh(and_v(v:after(100),after(500000000)))`) **parses but fails `sanity_check`** with
  `AnalysisError(SiglessBranch)`. Handy as a parseable-but-insane test case.
- `to_string()` emits `'` hardened markers and appends a valid `#checksum`; US-005's
  `normalize`/`canonical` rewrites `'`→`h` and recomputes the checksum (see Normalization).
