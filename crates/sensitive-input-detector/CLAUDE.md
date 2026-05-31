# sensitive-input-detector

Screens user-pasted/imported text for Bitcoin secrets **before** it reaches any
parser, so Lifeboat (a watch-only tool) never processes a real seed/key. Spec:
`docs/PRD-v2.md` §13.5. Skeleton + safe API: US-012. Detectors: US-013..US-016.

## The no-leak invariant (load-bearing — never weaken)

`detect(&str) -> DetectorReport` returns **only** discriminants + byte ranges,
never secret content. This is structural: no field on any returned type holds
input text — `DetectedSecret` carries metadata (language, word_count, network,
threshold, …); `ByteRange { start, end }` carries indices. The report is the
**only** value that crosses the Tauri boundary to JS (§13.5.8).

- When you add a detector, NEVER add a field that stores a slice/copy of the
  matched input. Return a `ByteRange` into the original and let the caller slice
  if it must (it won't — the whole point is the JS side gets ranges, not text).
- `report_contains_no_secret_substring` locks this: it builds a report over a
  synthetic secret and asserts neither `Debug` nor JSON contains it. Extend it in
  US-013+ with reports built from *real* detections (run `detect` on a test
  vector, assert the report's JSON omits the vector). Keep the assertion needles
  (`"marker"`, etc.) out of the report by construction.

## Public API (locked in US-012 so US-013..016 are purely additive)

- `detect(input: &str) -> DetectorReport` — infallible, panic-free, no state. The
  single entry point; each detector pushes `Finding`s here and folds the action.
- `detect_secret(secret: SecretString) -> DetectorReport` — the recommended
  entry: exposes the secret only for the `detect` call, then drops the
  `SecretString` (zeroize). Tauri/CLI MUST call this, not reimplement wrapping.
- `DetectorReport { findings: Vec<Finding>, action: DetectorAction }`
  (`Finding = (DetectedSecret, ByteRange)`). Predicates `is_blocked/is_warning/is_allowed`; `allow()` constructor.
- `DetectorAction { Allow, Warn, Block }` — **`#[derive(Ord)]` with declaration
  order `Allow < Warn < Block`**, so combine many findings with `actions.into_iter().max()` / `acc = acc.max(x)`. Don't reorder the variants.
- `DetectedSecret { Bip39{language,word_count,checksum_valid}, Wif{network,compressed}, Xprv{kind,network}, RawHexPrivKey, Slip39{share_count_in_input}, Codex32{threshold}, None }`.
- Metadata enums: `Bip39Language` (10 official lists), `Network` (Mainnet/Testnet), `XprvKind` (Xprv/Yprv/Zprv/Tprv/Uprv/Vprv).

## Conventions / gotchas

- **Self-owned types, not rust-bitcoin types, for anything in the report.** The
  report serializes to JS, so its types must be stable + serde-friendly + not
  `#[non_exhaustive]`. `Network` is a LOCAL enum (Mainnet/Testnet), not
  `bitcoin::Network`. US-014's WIF/xprv detection uses `bitcoin::PrivateKey::from_wif` / `bitcoin::bip32::Xpriv::from_str` (whose `.network` is `NetworkKind`, Main/Test only — same 2-way limit) and **maps** the result to this `Network`. Test nets (testnet/signet/regtest) share version bytes ⇒ all report `Testnet` (same lesson as descriptor-audit US-011).
- **`detect` is infallible** (`-> DetectorReport`, no `Result`). It never errors;
  "found nothing" is `DetectorReport::allow()`. So this crate does NOT depend on
  `error-taxonomy`. Keep it that way — a detector that can't decide returns no
  finding, it does not error.
- **Detectors decide the action at find-time**, because the action depends on
  context not just the variant (BIP39 checksum-valid ⇒ Block vs invalid ⇒ Warn
  §13.5.1; raw-hex context heuristic ⇒ Block/Warn/none §13.5.4). Don't try to
  derive action purely from the `DetectedSecret` variant.
- **Zeroize secret-derived buffers.** Any `String`/`Vec` derived from the input
  must be `zeroize::Zeroizing<_>` so it wipes on drop — never rely on plain
  `Drop`. US-013's `mnemonic.rs` wraps every per-token normalized string, the
  intermediate NFKD buffer in `normalize`, and the joined candidate phrase. The
  reported `ByteRange` indexes the ORIGINAL input, so findings still carry no
  text.
- **serde shape is snake_case and locked** by `json_shape_is_stable_snake_case`
  (`raw_hex_priv_key`, `{"codex32":{"threshold":2}}`, `"block"`, …). US-042's JS
  reads these tags — adding a variant is fine, renaming one is a breaking change.
- **`clippy::enum_variant_names`** fires on `XprvKind` (shared `prv` *suffix*
  strips to valid idents X/Y/Z/…), so it carries a justified `#[allow]`. (Cf.
  descriptor-audit `StandardPath::Bip44..` where it does NOT fire — a shared
  *prefix* stripping to digit-leading non-idents.) Only add the allow where the
  lint actually fires under `-D warnings`.
- **Tests use synthetic non-secret markers**, never real or even test-vector
  seeds for the skeleton. US-013+ must use only documented BIP39/SLIP-39/codex32
  **test vectors** (never real seeds), per §27 / US-040 anonymization.

## Internal detector architecture (since US-013)

- **One module per detector, one `Collector` to fold.** `detect()` builds a
  `pub(crate) Collector { findings, action }` and calls each detector's
  `scan(input, &mut collector)` in turn (`mnemonic::scan` today; US-014/015 add
  `wif::scan`/`xprv::scan`/`raw_hex::scan`/… alongside). `Collector::push(secret,
  range, action)` appends the finding AND folds the action with `.max()` (`Allow
  < Warn < Block`). Detectors NEVER build a `DetectorReport` themselves and never
  decide the final verdict — they just push. Name detector modules so they don't
  shadow the extern crates they use (the BIP39 module is `mnemonic`, not `bip39`,
  so `bip39::Mnemonic` keeps resolving to the crate).

## BIP39 detection (US-013, §13.5.1)

- **Wordlists are vendored + integrity-pinned, NOT loaded from the `bip39`
  crate.** `wordlists/bip39/*.txt` (10 files, 2048 lines each, newline-terminated)
  were dumped from `bip39::Language::word_list()` so they are byte-identical to
  what the checksum validator uses — prefix detection and checksum can't drift.
  `build.rs` recomputes each file's SHA256 (via the `sha2` BUILD-dependency) and
  fails the build on mismatch; the pins are the canonical bitcoin/bips hashes
  (english.txt = `2f5eed53…dbda`). To re-vendor: temporarily add an example that
  writes `Language::word_list()` to the files, run it, `sha256sum`, update the
  pins, delete the example (same throwaway-`examples/` trick as descriptor-audit
  fixtures).
- **The vendored non-English lists are NFKD (decomposed).** e.g. Spanish `ábaco`
  is stored `61 cc 81 …` ("a" + U+0301). So `normalize()` = `nfkd().to_lowercase()`
  produces the SAME form as the wordlist entry — exact `&'static str` membership
  works with no per-entry normalization. (If a future list weren't NFKD-stable,
  build `words`/`prefixes` from `normalize(word)` instead.)
- **Checksum via `bip39::Mnemonic::parse_in_normalized(lang, phrase)`** (NOT
  `from_phrase`, which the PRD names but is the old crate's API). It splits on
  `split_whitespace()`, needs EXACT words (else `Err(UnknownWord)`), and assumes
  the input is already NFKD — which ours is. `Ok` ⇒ checksum valid ⇒ Block;
  `Err(InvalidChecksum)` with all-exact words ⇒ Warn. Join the normalized window
  with a single ASCII space; Japanese to_string() also uses ASCII space.
- **Language detection is a u16 bitmask AND across the window.** Per token,
  precompute `(exact_mask, prefix_mask)` over the 10 lists (bit i = list i in the
  `RAW_WORDLISTS`/`Bip39Language` order); a window's candidate languages = AND of
  its tokens' masks. `prefix` = first 4 Unicode SCALARS (the BIP39 uniqueness
  property), char-boundary safe. Prefer the largest window that Blocks; else the
  largest that Warns; advance past a matched window to avoid nested duplicates.
- **`bip39::Language::ALL`** (the deprecated fn is `all()`); the enum is NOT
  `#[non_exhaustive]`, so a 10-arm match needs no catch-all (a catch-all trips
  `unreachable_patterns` under `-D warnings`). Variants are `SimplifiedChinese`/
  `TraditionalChinese` (our tags are `ChineseSimplified`/`ChineseTraditional`).
- **Simplified⇄Traditional Chinese share low-index words at identical
  positions**, so the all-zero vector is a VALID mnemonic in both; the detector
  reports the lower-indexed (Simplified). Tests must accept either Chinese variant
  for that vector. Every other language's all-zero vector is unambiguous.
- **Test vectors are generated, never hardcoded.** `Mnemonic::from_entropy_in(lang,
  &[0u8; 16|32])` mints the canonical all-zero 12/24-word vector for any language
  (documented, never a real seed). For an invalid-checksum Warn case, swap the
  last word to index-0 (checksum nibble → 0, but the all-zero checksum is 3 ⇒
  invalid for every language) — but DON'T assert the exact language for that
  degenerate repeated-word phrase (use distinct words when the language must be
  pinned). Committed corpus: `fixtures/secrets/bip39_{english_12,english_24,
  japanese_12}.txt` (read via the repo-root `../../fixtures/` include_str! path).

## WIF + extended private keys (US-014, §13.5.2-.3)

- **`regex-lite` is the detector's regex engine** (`src/wif.rs`, `src/xprv.rs`).
  Chosen over `regex` because it pulls NO transitive deps (no aho-corasick/memchr;
  Cargo.lock grew by one line) and its MSRV (1.65) clears the workspace's 1.78. It
  supports the ASCII `\b`/char-class/`{n,m}`/alternation syntax these patterns use.
  US-015 (raw-hex `\b[0-9a-fA-F]{64}\b`, codex32 `\bms1…`) should reuse it.
- **Patterns are kept VERBATIM from the PRD** for auditability and compiled ONCE
  via `OnceLock` + `Regex::new(PATTERN).expect("BUG: …")`. The `.expect` is on a
  fixed literal (a programmer bug, never a runtime condition on user data) and is
  pinned by a `pattern_compiles` test in each module — this is the sanctioned
  exception to "no panics outside tests". `scan()` stays infallible.
- **Bitcoin types come via `miniscript::bitcoin`** (the workspace convention — see
  the root patterns): added `miniscript.workspace = true` to the crate. Do NOT add
  `bitcoin.workspace = true` (`=0.32.5`) — it would force a workspace-wide bitcoin
  DOWNGRADE from the miniscript-resolved 0.32.7. The skeleton stayed bitcoin-free
  (US-012); this is the first story that needs it.
- **WIF (§13.5.2):** one combined regex (4 alternatives: `5`/`9` ⇒ 51 chars
  uncompressed, `[KL]`/`c` ⇒ 52 compressed) → `PrivateKey::from_wif` →
  `DetectorAction::Block`. Network + `compressed` are read from the DECODED key
  (`map_network(NetworkKind)` → local `Network`), never inferred from which branch
  matched. A shape match that fails `from_wif` is a look-alike ⇒ no action.
- **Extended private keys (§13.5.3): verify via `base58::decode_check` + a
  version-byte table, NOT `Xpriv::from_str`.** This is a DELIBERATE, security-
  driven deviation from the AC's named API: `Xpriv::from_str` only knows the two
  standard versions and REJECTS every SLIP-132 prefix (`yprv`/`zprv`/`uprv`/`vprv`
  + uppercase) with `Error::UnknownVersion` (verified empirically) — relying on it
  would silently MISS a real SLIP-132 xprv, a false negative (security bug) for a
  secret detector. `decode_check` (checksum-validate → require 78 bytes → look up
  the 4-byte version) covers all ten prefixes uniformly AND is strictly safer: it
  never builds a `SecretKey` or does an EC op, so the secret is refused by SHAPE,
  not processed (the US-010 / §13.5 invariant). The version table in
  `extended_private_kind` lists ONLY private versions, so an extended PUBLIC key
  (xpub `0x0488B21E`, …) is never misread as a secret. Zeroize the decoded bytes.
- **Embedded-in-descriptor (criterion 3) needs NO descriptor parsing.** The
  whole-input regex scan already finds an xprv inside `wpkh([…]xprv…/0/*)` because
  the key sits at a word boundary (`]`/`(`/`,` before, `/` after). Do NOT parse the
  descriptor to "walk the key tree" — miniscript's `parse_descriptor(&secp,…)`
  (the only variant that accepts private keys) DERIVES pubkeys = processes the
  secret, violating §13.5. Shape-scan + `decode_check` is the safe equivalent.
- **Fixtures `fixtures/secrets/{wif_mainnet,xprv_mainnet}.txt`** were minted
  deterministically from a fixed synthetic `[0x11; 32]` scalar/seed (NEVER a real
  key, §27) and WRITTEN by the throwaway probe (`std::fs::write`), not hand-
  transcribed. SLIP-132 variants are minted in-test via a `reversion(key, version)`
  helper (`decode_check` → swap the 4 version bytes → `encode_check`), the same
  trick as descriptor-audit US-011 — so no second fixture set is needed.

## raw-hex + SLIP-39 + codex32 (US-015, §13.5.4-.6)

- **raw-hex (`raw_hex.rs`, §13.5.4) is context-gated, and the only detector that
  copies NOTHING.** Pattern `\b[0-9a-fA-F]{64}\b` (verbatim) is far too common
  (SHA256/txid/merkle root), so the verdict comes from *surrounding* (non-secret)
  bytes: a context keyword (`priv`/`key`/`secret`/`wif`, case-insensitive) within
  the 32 chars before the match ⇒ `Block`; else alone on its own line ≤ 80 bytes
  ⇒ `Warn`; else nothing. `Block` is checked first (it beats `Warn` when both
  apply). Because it never decodes or slices the matched value (only a `ByteRange`
  + the surrounding text), there is NO secret-derived buffer to zeroize — unlike
  every other detector. When walking back 32 bytes for the keyword scan, snap
  `from` up to a `char_boundary` first so a multibyte input can't panic the slice.
- **SLIP-39 (`slip39.rs`, §13.5.5): implement RS1024 directly; do NOT use the
  named `slip-0039` crate.** That crate (`slip39` on crates.io) is **GPL-3.0**
  (banned by `deny.toml`), and its Apache lib `sssmc39` *reconstructs* the secret
  (+ pulls `rand 0.6`/`tiny-bip39`/`failure`) — both disqualifying. RS1024 is a
  pure checksum over the share's 10-bit word indices (customization string
  `b"shamir"`, polymod `== 1`); validating it reveals/combines nothing, the same
  "recognize by shape, never process" stance as US-014's xprv `decode_check`. The
  GEN constants + algorithm are in `rs1024_polymod`; they were verified against the
  official trezor vectors before coding. Vendor the 1024-word list to
  `wordlists/slip0039/wordlist.txt` (SHA256-pinned in `build.rs`), windows 33 then
  20 (largest-first), all-in-wordlist **and** RS1024-valid ⇒ `Block`. Zeroize the
  lowercased tokens and every `Vec<u16>` of indices. `share_count_in_input` = the
  number of distinct shares found in the whole input (two-pass: collect ranges,
  then push with the final count). NOTE: `gen` is a reserved keyword in edition
  2024 — don't name a loop var `gen` (rust-analyzer flags it; use `g`).
- **codex32 (`codex.rs`, §13.5.6): module is named `codex`, not `codex32`,** so
  the `codex32` *crate* keeps resolving inside it (same no-shadow rule as
  `mnemonic` ≠ `bip39`). Validate with `codex32::Codex32String::from_string`
  (owned `String`): it checks length + bech32 checksum **and** rejects mixed case
  (`Error::InvalidCase`) — so the detector needn't re-check case. `Ok` ⇒ `Block`.
  Read the non-secret `threshold` (k) from `candidate.as_bytes()[3]` (the digit
  after the 3-byte `ms1`/`MS1`); `Parts` fields are ALL private and the only
  public accessor `Parts::data()` extracts the SECRET — never call it (nor
  `interpolate_at`/`from_seed`). One transient owned `String` per candidate is
  unavoidable (the crate's API), dropped at iteration end like US-014's transient
  `PrivateKey`; the crate does no EC work.
- **The PRD §13.5.6 codex32 regex is BROKEN — it matches none of the official
  vectors.** Verified empirically: `…{45,125}…` excludes the canonical 48-char
  k=0 128-bit secret (only 44 body chars after `ms1[0-9]`), and its lowercase-only
  body misses uppercase codex32 (`from_string` accepts uppercase). The detector
  uses the PRD pattern as the lowercase alternative with the floor widened
  **45 → 44**, plus an **uppercase mirror** alternative; each alt is single-case
  so a mixed-case string matches neither (and `from_string` re-checks). A
  too-narrow detector that misses a real secret is a security bug (the US-014
  lesson) — fix the pattern, don't ship the verbatim non-functional one.
- **`build.rs` now verifies BOTH wordlist families** via a shared `verify(base,
  rel, expected)` helper: the 10 BIP39 files **and** the SLIP-0039 file
  (SHA256 `bcc4555…eec3`). Confirmed it fails the build on a 1-char tamper and
  passes on restore. The SLIP-0039 word *order* is independently confirmed by the
  RS1024 official-vector tests (a misplaced word breaks the indices).
- **Official test vectors only** (`slip39_share_20w.txt`, `codex32_128bit.txt`,
  and the in-test 33-word + uppercase/k3 vectors): documented SLIP-0039 (trezor
  `vectors.json`) and codex32 (the crate's own BIP-93 vectors), never real seeds
  (§27). SLIP-39 words overlap BIP39, so a share's words may also trip an
  incidental BIP39 prefix-`Warn`; SLIP-39 tests therefore assert on the
  *SLIP-39-typed* findings (a `slip39_findings` filter), not `findings.len()==1`.

## Action semantics & user-facing messages (US-016, §13.5.7)

- A finding's message comes from a stable `E-SECRET-*` `ErrorCode` via
  `DetectedSecret::error_code() -> Option<ErrorCode>` (BIP39 splits on
  `checksum_valid`: valid→`Bip39Detected`/E-SECRET-001, invalid→`Bip39Suspected`/
  E-SECRET-002; Wif→003, Xprv→004, RawHexPrivKey→007, Slip39→005, Codex32→006).
  Render `code.title()/description()/action()/i18n_key()` from `error-taxonomy` —
  do NOT restate the copy here (the catalog has the parity test; a second copy
  would drift). This is why the crate now depends on `error-taxonomy` (the
  earlier "does NOT depend on error-taxonomy" note is superseded). The dep does
  NOT make `detect` fallible — it still returns `DetectorReport`, never `Result`.
- `DetectorAction::headline()` → the verbatim §13.5.7 Block dialog (Warn/Allow →
  `None`). `DetectorAction::cli_exit_code()` → Block 5 / Warn 1 / Allow 0
  (§17.10.6, for US-036). `WARN_OVERRIDE_PHRASE` = the §13.5.7 confirm phrase.
- `DetectorReport::reason_codes()` → distinct codes, first-seen order (the
  "reason logged without the secret content"). All message text is static; the
  `messages_never_contain_detected_content` test re-checks over REAL detections.

## Fuzzing (US-016, §13.5.10)

- Four `cargo-fuzz` targets in the **detached** `fuzz/` workspace (its own empty
  `[workspace]` table + parent `exclude = ["fuzz"]`; needs nightly +
  `libfuzzer-sys`, so it is OUTSIDE the stable gate — verified empirically that
  `cargo build/clippy/test --workspace` never touch it; `cargo metadata` may
  still list it, which is cosmetic): `fuzz_detector_arbitrary` (no panic),
  `fuzz_detector_false_positive` (clean corpus → zero Block),
  `fuzz_detector_false_negative` (mints valid BIP39 from entropy via
  `Mnemonic::from_entropy_in` across all `Language::ALL` → must Block),
  `fuzz_descriptor_with_xprv` (embedded xprv → must Block). Run:
  `cargo +nightly fuzz run <t> -- -max_total_time=60` (install cargo-fuzz with
  `cargo +nightly install cargo-fuzz` — it needs edition2024, i.e. cargo ≥ 1.85,
  so the default 1.78 toolchain can't build it).
- The SAME four invariants are enforced deterministically under `cargo test` by
  `tests/fuzz_properties.rs` (fixed-seed xorshift, no `rand`). That is the real
  guarantee the gate checks every iteration; the cargo-fuzz crate is the CI
  artifact (5 min/PR, 1 h/release). When changing a detector, keep both in sync.
- Keep fuzz "must Block" target bodies non-spurious: embed valid secrets at
  guaranteed word boundaries (`(`/`,`/newline) so a "must Block" assertion can't
  fail on a boundary technicality, and MINT valid inputs (false-negative) rather
  than asserting over libfuzzer mutations (which usually break validity).
