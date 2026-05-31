# address-derive — notes for future iterations

Receive/change address derivation from a parsed descriptor (US-017) plus
known-address comparison (§17.5, US-018) on top.

## Public API
- `derive_addresses(parsed: &ParsedDescriptor, network: Network, count: u32) ->
  Result<DerivedAddresses, LifeboatError>` is the main entry. It expands multipath
  and splits receive/change. Pass `DEFAULT_ADDRESS_COUNT` (10) for the §17.4 default.
- `derive_chain(descriptor: &Descriptor<DescriptorPublicKey>, network, chain, count)
  -> Result<Vec<DerivedAddress>, _>` is the engine/primitive: derive `count`
  addresses (indices `0..count`) from ONE single-path descriptor, labeled `chain`.
  Use it for the **explicit change descriptor** case (US-028's "Add change
  descriptor" / §17.appendix explicit pair): parse the change descriptor and call
  `derive_chain(.., Chain::Change, n)`.
- `compare_known_address(parsed, network, address: &str, count) ->
  Result<KnownAddressMatch, _>` is the §17.5 known-address comparison (US-018). It
  validates the address parses for `network`, then searches the first `count`
  receive AND change addresses, transparently expanding to `MAX_ADDRESS_COUNT`
  (1000) of each on a miss. `derive_at(descriptor, network, index) -> Address` is
  the shared single-index primitive (used by both `derive_chain` and the search).
- Types (all crate-owned serde, `rename_all = "snake_case"`, for the JS boundary):
  - `Chain { Receive, Change }` → serializes `"receive"`/`"change"` (the §19.1
    `chain` field); `as_str()` / `Display`.
  - `DerivedAddress { index: u32, address: String, chain: Chain }` → one
    `addresses.*_derived` entry: `{"index":0,"address":"bc1q…","chain":"receive"}`.
  - `DerivedAddresses { receive_derived, change_derived }` → the §19.1 `addresses`
    object (minus `known_address_match`, see below).
  - `KnownAddressMatch { provided: String, matched: bool, matched_at:
    Option<MatchLocation> }` → the §19.1 `addresses.known_address_match`:
    `{"provided":"bc1q…","matched":true,"matched_at":{"index":3,"chain":"receive"}}`
    (a miss is `matched:false, matched_at:null` — the field is always present, never
    skipped). `MatchLocation { index: u32, chain: Chain }`.
  - `AddressExpectation { ToMatch, ToNotMatch }` + `KnownAddressMatch::
    meets_expectation(exp) -> bool` is the §17.5 "expected NOT to match" support
    (rule out a wrong-wallet import): `ToMatch` met iff `matched`; `ToNotMatch` met
    iff `!matched`.
- `Network` is re-exported (`pub use miniscript::bitcoin::Network`) — it IS
  rust-bitcoin's 4-variant enum (the same type `ParsedDescriptor::network()` returns
  and `Descriptor::address()` takes), so no mapping is needed.

## The §17.4 derivation refusals (where each is enforced)
- **xprv present** and **mixed networks** are NOT re-checked here: they are refused
  upstream by `parse_descriptor` (`E-PARSE-005` / `E-PARSE-004`), so a
  `ParsedDescriptor` can never carry them. xprv is also structurally impossible —
  `Descriptor<DescriptorPublicKey>` holds only public keys. Tests assert
  `parse_descriptor` refuses the `contains_xprv` / `network_mixed` fixtures (proving
  derivation is unreachable for them), rather than feeding them to the engine.
- **no `*` wildcard AND count > 1** is enforced in `derive_chain`
  (`ErrorCode::InputTooLarge`): a fixed descriptor describes a single address.
  `count == 1` on a fixed descriptor is allowed (derives that one address).
- **count range** `1..=MAX_ADDRESS_COUNT` (1000) is also `InputTooLarge`. There is
  no dedicated derivation E-code in Appendix C; `InputTooLarge` is the closest
  user-correctable code, and the precise reason rides in `.with_context(...)`. If a
  later story adds an Appendix-C derivation code, migrate these two call sites.

## Multipath = the receive/change split
- `derive_addresses` calls `parsed.expand_multipath()` (never empty; US-009). For a
  `<0;1>` descriptor, branch 0 → `receive_derived`, branch 1 → `change_derived`. A
  single-path descriptor yields only `receive_derived`; `change_derived` is empty
  (matches the §19.1 example for a single-path wpkh). Read `.first()`/`.get(1)` — do
  NOT re-derive "index 0 = receive" (the convention is documented once on
  `expand_multipath`).
- `derive_chain` rejects a multipath descriptor (`is_multipath()` → `E-INTERNAL-001`)
  — expand first. (The main entry never triggers this; only a misusing caller would.)

## Known-address comparison (§17.5, US-018)
- **A miss is a FACT, never an error.** `compare_known_address` returns
  `KnownAddressMatch { matched: false }` when the address is not in the range — it
  does NOT return `Err`. C-ADDRESS-MISMATCH is a §16.3 critical CONDITION with no
  Appendix-C E-code, so (per the universal fact→scoring split) readiness-score
  US-020 is the ONLY layer that maps a miss → C-ADDRESS-MISMATCH and forces "Not
  Ready". Returning an error would also break the `ToNotMatch` flow (where a miss is
  the *success* case) and the §19.1 `matched:false` report shape. Errors here are
  reserved for genuinely unusable input (see below).
- **Errors:** empty address → `E-INPUT-001`; an address that does not parse, or
  parses but is invalid for the requested `network` (§17.5 step 1), → `E-INPUT-003`
  (`InputInvalidFormat`) with the precise reason in `.with_context`. There is no
  address-specific Appendix-C code; `E-INPUT-003` is the closest user-correctable
  one (same "no dedicated code, ride context" convention as `derive_chain`'s
  `InputTooLarge`). Count out of `1..=MAX_ADDRESS_COUNT` → `InputTooLarge`.
- **Two-phase search, receive before change.** Per §17.5 the search does the first
  `count` of each chain, then transparently expands to `MAX_ADDRESS_COUNT`; within
  each phase receive is searched before change. For all realistic descriptors
  (receive/change derive disjoint addresses) the two-phase order is unobservable,
  but it is deterministic and documented. The search short-circuits on the first
  hit (`derive_at` per index), so a hit at a low index does not derive 1000×2.
- **Address API (rust-bitcoin 0.32, via `miniscript::bitcoin`):**
  `addr_str.parse::<Address<NetworkUnchecked>>()` then
  `.require_network(network) -> Result<Address, _>` does BOTH validations of §17.5
  step 1 (parses + right network) in one step; both error types are
  `Send+Sync+'static` (chain with `.with_source`). Compare derived vs. target as
  `Address == Address` (PartialEq) — both are `NetworkChecked` for the same
  `network`, so equality is well-defined (no string round-trip needed). Imports:
  `miniscript::bitcoin::{Address, address::NetworkUnchecked}`.
- **Fixtures** live at repo-root `fixtures/addresses/`: `known_match_bc1.txt` is a
  published BIP84 vector (receive index 1, no probe needed); `known_match_tb1.txt`
  was minted from `wsh_sortedmulti_2of3.txt` (testnet receive index 2) via a
  throwaway `examples/probe_us018.rs` and is **self-checked** in the test (asserted
  equal to a fresh derivation, so a wrong baked value fails loudly).
- **Scope:** `compare_known_address` searches the parsed descriptor's own chains
  (receive + multipath change). A *separately-supplied* change descriptor is not
  searched here — the report layer (US-028) can drive `derive_chain(.., Change, n)`
  + its own comparison if needed.

## miniscript derivation facts (13.0.0)
- `Descriptor::has_wildcard() -> bool` (true iff some key has `*`). A no-wildcard
  descriptor's `at_derivation_index(i)` ignores `i` and returns the same address for
  every index — hence the count>1 refusal.
- `Descriptor::<DescriptorPublicKey>::at_derivation_index(u32) ->
  Result<Descriptor<DefiniteDescriptorKey>, ConversionError>`; multipath input errors.
- `Descriptor::<DefiniteDescriptorKey>::address(Network) -> Result<Address, _>`. No
  secp context argument — miniscript handles the EC derivation internally. A script
  type with no address (bare `pk`/`multi`, outside the §17.4 supported set) errors
  (mapped to `E-INTERNAL-001`). Both error types are `Send+Sync+'static`, so chain
  them with `.with_source(e)`.

## Network is the caller's decision
- `derive_*` take a concrete `Network`; address ENCODING (bc/tb/bcrt HRP) depends on
  the network, not the key. The caller resolves `parsed.network_inference()` (mainnet
  `xpub` = determined; `tpub` = ambiguous across testnet/signet/regtest, user
  confirms — §16.5) and passes the result. This crate never guesses, and (by design,
  matching the AC's scope) does not reject a network/descriptor family mismatch.

## Known-answer test vectors
- The BIP44/49/84/86 account xpubs for the documented "abandon … about" mnemonic are
  baked as consts and asserted against the published BIP address vectors (BIP49
  `37VucY…`, BIP84 `bc1qcr8te…`/`bc1qnjg…`/`bc1q8c6f…`, BIP86 `bc1p5cyx…`). They were
  derived + verified by a throwaway `examples/probe_vectors.rs` (mnemonic→seed→xpub
  via a temporary `bip39` dev-dep, then deleted) so they are not hand-transcribed.
  Regenerate the same way if you need new singlesig vectors. Multisig correctness is
  cross-checked via the US-009 byte-identity property (the `multipath_2of3` `/0`
  branch == the standalone `wsh_sortedmulti_2of3` fixture).
- Taproot is first-class after US-073: `tr(KEY)` is locked to the BIP86 vector, and
  `fixtures/descriptors/taproot/tr_scriptpath_multi_a.txt` pins script-path `multi_a`
  derivation with explicit receive-address assertions. Address derivation still uses
  the same Miniscript `Descriptor::address(network)` path; no Taproot-specific
  address encoder lives in this crate.
- Liana-style timelock descriptors are first-class after US-074. The fixture
  `fixtures/descriptors/timelock/liana_basic.txt` derives through the same
  multipath expansion + `Descriptor::address(network)` path as multisig; no
  Liana-specific address encoder lives here. The receive/change index-0/1 test
  vectors are pinned in `liana_timelock_fixture_derives_receive_and_change`.

## criterion on Rust 1.78 (also unblocks the CLI's clap, US-036)
- The bench (`benches/derive.rs`, `harness = false`) proves the §17.4/§28 budget
  (<200ms for 100 singlesig); `cargo bench -p address-derive` measured ~6.7ms. The
  `cargo test` gate ALSO enforces it deterministically (`derives_100_singlesig_under_200ms`).
- Latest clap 4.6 / clap_lex 1.1 / half 2.7 / rayon 1.12 raise their MSRV to
  1.80–1.85 (clap_lex 1.1 even uses edition 2024, which 1.78's Cargo can't PARSE).
  Fixes, in the root `[workspace.dependencies]`:
  - `clap_builder = "=4.5.57"` and `half = "=2.4.1"` (manifest pins — a manifest
    constraint is the ONLY way to stop the resolver reading clap_lex 1.1's
    edition-2024 manifest on a re-resolve). `clap` pins `=clap_builder`, so this
    cascades to clap 4.5.57 + clap_lex 0.7.x. Consumed as unused dev-deps of this
    crate (`clap_builder.workspace = true`, `half.workspace = true`).
  - `criterion = { ..., default-features = false, features = ["cargo_bench_support"] }`
    drops the `rayon` (rust 1.80) and `plotters` subtrees entirely — unneeded for a
    timing bench. **`default-features = false` must be set on the WORKSPACE dep**;
    setting it on the inheriting `criterion.workspace = true` is ignored (cargo warns).
  - rayon dropped out, so no rayon pin is needed. Per the MSRV-RISK rule, revisit
    these pins together with the toolchain channel, never bump alone.
