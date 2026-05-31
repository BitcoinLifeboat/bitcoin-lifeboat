# wallet-imports — agent notes

Importers normalize watch-only wallet exports into one shared
`NormalizedWalletExport` (PRD §17.9, §19.3). Established in US-023 (Bitcoin Core);
US-024+ add Sparrow, Specter, Coldcard, Nunchuk, Liana, Jade, Passport.

## Shared output type (§19.3)
`NormalizedWalletExport` and its nested `WalletDescriptors` / `WalletKey` /
`WalletLabel` are **crate-owned `serde` types with `snake_case` fields** — the
value crosses the Tauri→JS boundary (`parse_wallet_export`, §19.1/§19.3 rule), so
never put rust-bitcoin types in it. `WalletKey` mirrors the §19.1 `keys[]` shape
(index, fingerprint, derivation_path, xpub, key_origin_present) minus the
report-layer redaction (US-030). `WalletLabel` uses `#[serde(rename = "type")]` /
`rename = "ref"` because `type`/`ref` can't be field idents.

## Importer recipe (reuse this shape for every wallet)
1. `guard_input(content)?` — empty → `E-INPUT-001`, `> MAX_EXPORT_SIZE_BYTES`
   (10 MB) → `E-INPUT-002`. Always first, before parsing.
2. Parse with **strict** `serde_json` (`#[serde(deny_unknown_fields)]` on every
   wire struct). On failure return `E-INPUT-003` with a context string carrying
   **only** `e.line()`/`e.column()` — NEVER the raw serde message or any content
   (descriptors/xpubs are confidential and must not leak into errors/logs).
3. Extract the descriptor(s) (receive/change), birth hint, labels, etc.
4. For each stored descriptor call `analyze_descriptor(desc)?`: it returns
   `Err(E-PARSE-005)` ONLY for private-key material (refuse before storing —
   never surface a secret), `Ok(Some(parsed))` on success, and `Ok(None)` for any
   other parse failure (TOLERATE it — keep the raw descriptor; the analysis layer
   reports `C-DESC-PARSE-FAIL`). Do not hard-fail the import on a malformed-but-
   secret-free descriptor; an unrecognized *file* is CannotDetermine, a broken
   *descriptor* is NotReady (readiness-score §16.5 split).
5. `extract_keys(&parsed)` and `classify(&parsed)` reuse `descriptor-audit` facts
   (`key_origins()`, `multisig_info()`, `is_singlesig()`) — NEVER re-parse a
   descriptor by hand. Use the receive descriptor (change shares the same keys).

## Determinism / caller-set fields
The importer leaves `imported_at` and `raw_source_filename` as `None` — the CLI
(US-036) / Tauri (US-042) caller stamps them. This keeps importing pure and
fixture tests deterministic. `unix_to_iso8601(secs)` (Hinnant civil-from-days, no
deps) converts a Unix birth time to the `YYYY-MM-DDTHH:MM:SSZ` form §19.3 shows;
reuse it for any wallet that exports a Unix timestamp (Liana). Sparrow exports an
ISO date already; Specter exports a block height (→ `birth_height`).

## Bitcoin Core specifics (§17.12, §24.2)
`listdescriptors` output carries **no version field**, so `import_bitcoin_core`
takes `core_version: Option<&str>` supplied out-of-band (RPC
`getnetworkinfo.subversion` like `/Satoshi:30.0.0/`, or the user). 30.x →
`E-INPUT-003` with the verbatim §17.12 message as context; 29.x/None/other majors
proceed. `core_major_version` extracts the leading integer (handles `v30.1` and
the `/Satoshi:.../` subversion). Selection: skip `active=false`; first
`internal=false` = receive, first `internal=true` = change; birth = max integer
`timestamp` among **active** entries (`"now"` strings are ignored).

## Sparrow specifics (US-024, §24.2) — descriptor ASSEMBLY
Sparrow's "File > Export Wallet" JSON is **keystore-based**: it carries **no**
descriptor string. The importer assembles them from `policyType` (`SINGLE`/
`MULTI`), `scriptType` (`P2PKH`/`P2SH_P2WPKH`/`P2WPKH`/`P2TR`/`P2SH`/`P2SH_P2WSH`/
`P2WSH`), `defaultPolicy.numSignaturesRequired` (= `M`), and `keystores[]` (each a
`keyDerivation` {`masterFingerprint`, `derivationPath`} + `extendedPublicKey`).
For each chain (`"<0;1>"` multipath, `"0"` receive, `"1"` change) build keys
`[fp/path]xpub/{chain}/*` (strip `m/`), wrap per the policy/script table
(`MULTI` ⇒ `sortedmulti(M,…)`; the wrapper is `wsh`/`sh(wsh(…))`/`sh(…)`/`wpkh`/
`sh(wpkh(…))`/`pkh`/`tr`), then `descriptor_audit::normalize_slip132(body)` (vpub/
upub/… → tpub/xpub) → `compute_checksum`. **Cross-check**: a reconstructed
descriptor is byte-identical to the existing descriptor fixtures (singlesig
receive == `wpkh_valid.txt` `#r6yctejg`; multisig receive == `wsh_sortedmulti_2of3
.txt` `#c2yhzrq7`; multipath == `multipath_2of3.txt` `#79rtg74s`) because
`compute_checksum` uses miniscript's engine, same as the `to_string()` minting —
so a test asserting `receive == include_str!(fixture).trim()` proves assembly is
correct, no new fixture minting. Analyze the **multipath** form for keys/quorum
(`multisig_info()`/`key_origins()` read it fine, US-009); store the expanded
receive/change. `SINGLE` must have exactly 1 keystore; empty keystores or an
unsupported policy/script combo (`CUSTOM`, Taproot multisig) → `E-INPUT-003`
(typed, never a panic). Birth: `birthDate` is a Java `Date` (epoch **ms**) → use
`epoch_value_to_iso8601` (ms-vs-s split at 1e11; also takes a string ISO or
integer); `birthHeight` → `birth_height`; `gapLimit` → `gap_limit`.
**Watch-only safety**: do NOT declare the private keystore fields (`seed`,
`masterPrivateExtendedKey`, `bip47ExtendedPrivateKey`) — `deny_unknown_fields`
then refuses a non-watch-only export (`E-INPUT-003`) instead of deserializing
secret material. Gson omits null fields, so watch-only exports (which lack these)
still parse.

## Specter specifics (US-024, §24.2) — descriptor-based
Specter's "Wallet > Settings > Export" JSON is `{ label, blockheight, descriptor,
devices:[{type,label}] }`. `descriptor` is the **receive** descriptor (single-path
`/0/*`, `h` markers); Specter does not export the change branch
(specter-desktop#2494) → `change` stays `None` unless a newer export supplies an
explicit `change_descriptor`. `blockheight` → `birth_height` (no birth timestamp).
Reuse the receive descriptor for keys/quorum (no assembly needed — it already has
the descriptor).

## Shared assembly / multipath helpers (lib.rs)
Three `pub(crate)` helpers in `lib.rs` are reused across importers — call them, do
not re-roll:
- `strip_master_prefix(path)` — drop a leading `m/`/`M`/bare `m` from a derivation
  path to get the origin path for `[fingerprint/path]` (Sparrow **and** Coldcard).
- `normalize_multipath_shorthand(desc)` — rewrite the `/**` shorthand to
  `/<0;1>/*`. **rust-miniscript REJECTS `/**`** (E-PARSE-001; verified), so any
  BIP129/Coldcard template using it must be rewritten before `parse_descriptor`.
  `/**` is defined as equivalent to `/<0;1>/*` (BIP129). A `#checksum` on a `/**`
  template is over the shorthand and is invalidated by the rewrite, so the helper
  **drops the trailing checksum** (everything from the first `#`); a descriptor that
  doesn't use `/**` is returned trimmed and unchanged (its checksum stays valid).
- `expand_receive_change(&parsed)` — expand a (possibly multipath) `ParsedDescriptor`
  into `(receive, Option<change>)` strings via `expand_multipath()` + `to_string()`.
  **Verified byte-identical fact**: `expand_multipath()[0].to_string()` equals the
  committed single-path fixture (`<0;1>` 2-of-3 → `wsh_sortedmulti_2of3.txt`
  `#c2yhzrq7`; `[1]` is the `/1/*` change, `#al0du9sk`) — so an importer fed a
  multipath descriptor reproduces the canonical fixtures exactly, no new minting.
  Index 0 = receive, index 1 = change (US-009). Single-path → `(itself, None)`.

## Coldcard specifics (US-025, §24.2) — two formats
Coldcard has **two** importers (`source_wallet = "coldcard"`):
- `import_coldcard_json` (Generic Wallet Export JSON, **singlesig**): like Sparrow it
  has no descriptor string — it lists standard account branches `bip44`/`bip49`/
  `bip84`/`bip86`, each with `deriv` (origin path) + account `xpub`, plus a top-level
  master `xfp`. The importer **assembles** `[xfp/deriv]xpub/{0,1}/*` wrapped per the
  chosen branch (`pkh`/`sh(wpkh)`/`wpkh`/`tr`) → `normalize_slip132` → `compute_checksum`
  (the singlesig arm of Sparrow's `assemble`). **Branch priority** when several are
  present: `bip84` → `bip86` → `bip49` → `bip44` (most modern widely-supported first).
  **GOTCHA**: Coldcard emits `xfp` UPPERCASE (`71348C8A`) but descriptors use lowercase
  hex — `.to_lowercase()` the fingerprint or the assembled body/checksum won't match
  the fixtures. Cross-check: bip84 reproduces `wpkh_valid.txt` `#r6yctejg`, bip49 →
  `sh_wpkh_valid.txt`, bip44 → `pkh_valid.txt` (the three singlesig fixtures share the
  fp-71348c8a seed). `bip48_1`/`bip48_2` (multisig account xpubs) are accepted-but-
  unused — multisig comes via the descriptor file or BSMS, not this singlesig export.
- `import_coldcard_descriptor(content, sig, version)` (descriptor `.txt` + optional
  `.sig`, singlesig **or** multisig): strip `#`-comment and blank lines (a `#` only
  starts a comment — a descriptor's `#checksum` is mid/end-of-line, never line-start),
  `normalize_multipath_shorthand` each line; **1 line** → multipath expands to
  receive/change, single-path is receive as-written; **2 lines** → receive then change;
  0 or >2 → E-INPUT-003. The `.sig` is accepted for the file-pair API but **NOT
  cryptographically verified** in the MVP (no overclaim — descriptor authenticity is
  the user's known-address comparison later); `let _ = sig;` documents the deliberate
  non-use (unused fn params don't warn, but the discard makes intent explicit).

## Nunchuk BSMS specifics (US-025, §24.2) — BIP129
`import_nunchuk_bsms` (`source_wallet = "nunchuk"`). BSMS "descriptor record" is
line-positional: line 1 `BSMS <version>` (require the `BSMS` marker via
`split_whitespace().next() == Some("BSMS")`; accept any version token — only 1.0
exists), line 2 the descriptor template (`/**` + checksum), line 3 path restrictions
(`/0/*,/1/*`), line 4 first address. Lines 3–4 are **informational** — the first
address is NOT verified against the descriptor (that's the later known-address step,
which needs a network; verifying here would pull in `address-derive` for no AC gain).
Rewrite line 2 with `normalize_multipath_shorthand` (drops the `/**` checksum) →
`analyze_descriptor` → `expand_receive_change` → byte-identical 2-of-3 receive
`#c2yhzrq7`. **Malformed vs broken split**: a missing `BSMS` header / no descriptor
line → E-INPUT-003 (unrecognized FILE); a well-formed record whose descriptor merely
fails to parse is **tolerated** (`Ok(None)` → keep raw, `wallet_type = None`) — matches
the §16.5 split (unrecognized FILE = CannotDetermine, broken DESCRIPTOR = NotReady).

## Descriptor-file importers share `parse_descriptor_file` (US-026)
Coldcard's descriptor file and Passport both export the *same* text shape, so the
line parsing lives in one shared `pub(crate) fn parse_descriptor_file(content) ->
Result<(receive, Option<change>, Option<ParsedDescriptor>)>` in `lib.rs` — call it,
don't re-roll. It drops `#`-comment and blank lines, `normalize_multipath_shorthand`s
each remaining line, then: **1 line** → a multipath descriptor expands to
receive/change (`expand_receive_change`), a single-path one is receive as-written;
**2 lines** → receive then change; **0 / >2** → `E-INPUT-003`. It refuses xprv
material (`E-PARSE-005`) and tolerates other parse failures (`parsed = None`, raw
kept). `import_coldcard_descriptor` (minus its `.sig`) and `import_passport` both
`guard_input` then delegate to it and only differ in the `source_wallet` label.

## Liana `.bed` specifics (US-026, §24.2) — the decryption-input flow
`import_liana_bed(content, decryption_inputs: &[&str], version)` — note the **extra
`decryption_inputs` argument** (the user's own xpubs), unique to Liana. The real
`.bed` ("Bitcoin Encrypted Descriptor") encrypts the descriptor to **all** its
xpubs; holding any one decrypts it. The MVP **models that access-control flow** and
does NOT implement the encrypted-descriptor BIP cryptography (documented in the
module, no over-claim — like the Coldcard `.sig`): the envelope is JSON
`{recipients:[xpub…], payload:<hex of descriptor>, timestamp, …}`; the importer
requires ≥1 supplied input to be a recipient, else `E-INPUT-003` ("none of the
provided keys can decrypt"); empty `decryption_inputs` is also `E-INPUT-003`. On a
match it `decode_hex_to_string`s the payload (dependency-free hex; payload is text,
never a secret) → standard recipe. A Liana descriptor is an `or_d()` **timelock
policy** → `multisig_info()` is `None`, `is_singlesig()` false, and
`uses_timelock()` true, so `classify` returns `wallet_type = "timelock"` with no
threshold/key_count. `key_origins()` still yields the primary+recovery keys. Birth =
`timestamp` (Unix s) via `epoch_value_to_iso8601`. There is **no** Appendix-C
"decryption failed" code, so all its file-level refusals reuse `E-INPUT-003`
(consistent with every other importer).

## Jade specifics (US-026, §24.2) — multisig registered-wallet JSON, keystore-based
`import_jade` reads a nested `{descriptor:{variant,sorted,threshold,signers[]}}`
object (Jade's documented registration shape) and **assembles** like Sparrow
(parts → `wsh/sh/sh(wsh)` + `sortedmulti`(when `sorted`)/`multi` →
`normalize_slip132` → `compute_checksum`; assemble `<0;1>`/`0`/`1`, analyze the
multipath). `variant` is `wsh(multi(k))` / `sh(multi(k))` / `sh(wsh(multi(k)))` (the
`(k)` is literal; the `sorted` **bool**, not the variant, picks sortedmulti) — accept
the `sortedmulti(k)` spelling too. **Both field encodings are accepted** because
Jade's wire form differs from a readable file export: `fingerprint` = hex string OR
4-byte array (→ 8 lowercase hex); `derivation` (origin path) = string OR BIP32 index
array (hardened ≥ 2³¹ → `'` marker, via `index_segment`); `path` (xpub suffix,
usually `[]`) = string OR **non-hardened** index array (hardened path → `E-INPUT-003`,
an xpub has no hardened children). A malformed fingerprint/derivation or unsupported
`variant`/no-signers is a structural `E-INPUT-003` (reject), not a tolerated broken
descriptor. **Cross-check (no new minting)**: int-array `[2147483696,1+2³¹,0+2³¹,2+2³¹]`
→ `48'/1'/0'/2'`, so the fixture reproduces `wsh_sortedmulti_2of3.txt` `#c2yhzrq7`
byte-for-byte. `master_blinding_key` (Liquid) accepted-but-unused.

Stable Clippy (newer than the root 1.78 pin) enforces `doc_lazy_continuation` under
`-D warnings`. In module docs, do not continue a paragraph with a line that starts
with `>` (for example, menu paths like `Options > ...` split across lines), or Clippy
will treat it as a malformed blockquote. Reword those as slash-separated paths or keep
the `>` characters away from the start of a continued doc line.

## Passport specifics (US-026, §24.2) — descriptor file (like Coldcard)
`import_passport(content, version)` = `guard_input` + the shared
`parse_descriptor_file` labelled `source_wallet = "passport"`. No `.sig` (that's
Coldcard). The fixture is a multipath singlesig `wpkh(...)/<0;1>/*` with `#` comment
lines → expands byte-identically to `wpkh_valid.txt` `#r6yctejg` (receive) + `/1/*`
change. (QR import is v0.3; file-only in the MVP.)

## Electrum + BlueWallet (US-027, §24.2) — Tier-2 multisig TEXT workarounds
Both are **Coldcard-style line-oriented text parsers** (the AC's "Coldcard-style text
parsers"), not strict-serde JSON — Electrum's native wallet file uses dynamic
`x1/`/`x2/` keys that fight `deny_unknown_fields`, so a text layout is the right
shape, and BlueWallet's vault export *is* literally the Coldcard multisig setup text.
- `import_bluewallet` (`source_wallet = "bluewallet"`): the real Coldcard multisig
  setup file — `#` comments, header fields `Name:`/`Policy: M of N`/`Derivation:` (one
  BIP48 origin path shared by all cosigners)/`Format: P2WSH|P2SH-P2WSH|P2SH`, then
  `<8-hex fingerprint>: <xpub>` cosigner lines. A line is a cosigner iff its key part
  is 8 hex chars (else it's a header field; unknown header fields are ignored — text
  is lenient, unlike the strict JSON importers). `Format:` selects the wrapper.
- `import_electrum` (`source_wallet = "electrum"`): `wallet_type: NofM` (Electrum's
  real field; `"2of3"` ⇒ M=2,N=3) + bare `[fingerprint/origin-path]xpub` key lines.
  Script type is INFERRED from the BIP48 path's final hardened index (`2'`⇒P2WSH,
  `1'`⇒P2SH-P2WSH, `0'`⇒P2SH; trust only a genuine `48'`-purpose 4-level origin, else
  default P2WSH) — Electrum encodes the script type in the path, not a separate field.
Both validate STRUCTURE → `E-INPUT-003` (missing Policy/Derivation/Format or
wallet_type; cosigner count ≠ N; unparseable quorum; unsupported Format) but TOLERATE
a broken-but-secret-free descriptor (the §16.5 file-vs-descriptor split), and refuse
private-key material `E-PARSE-005` (the `?` on `assemble_sortedmulti` propagates it).
Documented as Tier-2 workarounds (best-effort; user confirms a known address after).

## Shared multisig assembler `assemble_sortedmulti` (US-027, lib.rs)
`assemble_sortedmulti(script: MultisigScript, m, keys: &[String]) -> (receive,
Option<change>, Option<ParsedDescriptor>)` is the multisig sibling of Sparrow's
private `assemble`: it takes `[origin]xpub` key expressions (caller fixes the order —
`sortedmulti` preserves WRITTEN order, US-006), builds the `<0;1>` multipath body,
`normalize_slip132` → `compute_checksum` → `analyze_descriptor` → `expand_receive_change`.
Reused by BlueWallet + Electrum. **Byte-identical cross-check, no new minting**: feed
the canonical 2-of-3 keys (`4ba43603`/`6e37edb9`/`8dfc9b34` @ `48'/1'/0'/2'`) in that
order with P2WSH and the receive reproduces `wsh_sortedmulti_2of3.txt` `#c2yhzrq7` and
change `#al0du9sk` exactly. (Sparrow's `assemble` stays separate — it also handles
SINGLE/singlesig and is keyed on Sparrow's vocabulary; don't merge, no behavior gain.)

## Format auto-detection `detect_format` / `import_auto` (US-027, lib.rs)
`detect_format(content) -> Result<WalletFormat, LifeboatError>` (the `--format auto`
back end, US-036) sniffs by content; unknown → `E-INPUT-003` (after `guard_input`, so
empty → `E-INPUT-001`). **JSON** (`trim_start().starts_with('{')`): match unique
top-level keys WITH their surrounding quotes (`"\"descriptor\""` never matches
`"\"descriptors\""`), in this ORDER (specific→general): `liana_backup_version`/
`recipients`+`payload` → Liana; `policyType`+`keystores` → Sparrow; `multisig_name`/
`signers` → Jade; `devices`+`descriptor` → Specter; `descriptors` → BitcoinCore; `xfp`
→ ColdcardJson. **Text**: a `BSMS`-first-token line → NunchukBsms; a `wallet_type:`
field → Electrum; `Policy:`+`Format:` fields → BlueWallet; a line starting with a
descriptor function (`wpkh(`/`wsh(`/`sh(`/…) → DescriptorFile. **Coldcard descriptor
file and Passport are the SAME text shape** → one `DescriptorFile` variant (auto-detect
*cannot* and need not distinguish them; both parse via `parse_descriptor_file`).
Locked by `detect_format_routes_every_existing_fixture` (all 12 committed fixtures).
`import_auto` dispatches with default args; **Liana cannot be auto-imported** (needs
the user's decryption xpubs) → it returns `E-INPUT-003` directing the caller to
`import_liana_bed`. When adding a new format, add a sniff rule AND extend that test.

## Versions are out-of-band
Neither Sparrow nor Specter (nor Core) embeds its app version in the export, so
every importer takes `version: Option<&str>` supplied by the caller (like Core's
`core_version`) and records it as `source_wallet_version`; pass `None` when
unknown.

## deny_unknown_fields + unused fields
A strict wire struct must declare every field real exports emit (Bitcoin Core:
`wallet_name`, `range`, `next`, `next_index`) so they're accepted — but fields
you don't read trigger `dead_code` under `-D warnings`. Mark each
`#[allow(dead_code)]` with a one-line "present in real output, accepted but
unused" note. Model a field that is int-or-string (Core `timestamp`) as
`Option<serde_json::Value>` + `.as_i64()` rather than a custom untagged enum (an
unread enum payload also trips `dead_code`).

## Fixtures
`fixtures/wallet_exports/*.json` (repo root). Reuse existing descriptor fixtures'
keys (e.g. the wpkh receive desc is `fixtures/descriptors/singlesig/wpkh_valid.txt`,
checksum `#r6yctejg`); mint a `/1/*` change variant's checksum with a throwaway
`examples/` binary calling `descriptor_audit::compute_checksum(body)`, then delete
it. Keys are always testnet `tpub`, never mainnet (§27). Read in tests with
`include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/...", ))`.
