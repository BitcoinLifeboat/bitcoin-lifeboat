# Descriptor Audit

An output descriptor is a watch-only description of how a wallet derives
addresses and spends coins. It can include script type, xpubs, fingerprints,
derivation paths, wildcards, and a checksum. It must not contain seed words or
private keys.

## Supported Descriptor Shapes

The MVP supports:

- `pkh(KEY)`
- `wpkh(KEY)`
- `sh(wpkh(KEY))`
- `wsh(multi(M,KEY,...))`
- `wsh(sortedmulti(M,KEY,...))`
- `sh(multi(M,KEY,...))`
- `sh(wsh(sortedmulti(M,KEY,...)))`
- BIP389 multipath receive/change expressions such as `/<0;1>/*`
- Taproot `tr(KEY)` and simple `tr(KEY,{multi_a(...)})` in preview mode

Unsupported forms such as `combo()`, `addr()`, and `raw()` return
`E-PARSE-006`.

## Import Flow

1. Screen the pasted text or file content with the sensitive-input detector.
2. Reject any seed phrase, xprv, WIF, SLIP-39 share, codex32 secret, or risky raw
   private-key hex.
3. Validate a present BIP380 checksum.
4. Parse with rust-miniscript.
5. Run descriptor sanity checks.
6. Normalize to a canonical descriptor string.
7. Extract facts for scoring and reports.

The parser preserves both the raw input and the canonical form. Reports use both:
raw input for user traceability, canonical form for deterministic output.

## Checks and Facts

Descriptor audit records facts. Readiness scoring decides whether those facts
are passes, warnings, or critical issues.

Facts include:

- Descriptor type.
- Checksum present or missing.
- Canonical descriptor.
- Multisig threshold M and key count N.
- `multi` vs `sortedmulti`.
- Duplicate xpubs.
- Key origin fingerprint and derivation path.
- Hardened marker style.
- Standard BIP44, BIP49, BIP84, BIP86, or BIP48 account paths.
- Network inference from xpub/tpub version bytes.
- BIP389 multipath usage.
- Taproot preview usage.

## Checksums

BIP380 descriptors should include a `#xxxxxxxx` checksum. A missing checksum is
non-fatal and becomes a warning. An invalid checksum is a critical parse error
because it means the descriptor text may have changed.

The CLI can validate or compute a checksum:

```sh
lifeboat checksum --validate '<descriptor#checksum>'
lifeboat checksum --compute '<descriptor without checksum>'
```

Avoid inline descriptors in shell history for real wallets. Prefer `--stdin` or
a local file when possible.

## Key Origins

A key origin records the master fingerprint and derivation path, for example:

```text
[d34db33f/48h/0h/0h/2h]xpub.../0/*
```

The report renders the path as `m/48h/0h/0h/2h`. Missing origins do not always
make a descriptor invalid, but they can prevent Lifeboat from determining enough
context for a readiness result.

## Network Inference

Mainnet xpub version bytes identify mainnet. Test-family tpub version bytes are
shared by testnet, Signet, and regtest, so Lifeboat will not guess. The user must
choose the network when inference is ambiguous.

SLIP-132 public keys such as ypub, zpub, upub, and vpub are normalized at import
time when the user explicitly imports a wallet export. The parser does not
silently rewrite an already supplied descriptor because that would invalidate the
checksum the user may be verifying.

## Known-Address Comparison

The strongest MVP check is a known receive address match. Lifeboat derives a
range of receive and change addresses from the descriptor and compares the user's
known address. A mismatch is a critical issue because it means the descriptor may
not describe the wallet the user thinks it describes.

## Troubleshooting

- `E-PARSE-001`: copy the full descriptor, including the outer function such as
  `wpkh(` or `wsh(`.
- `E-PARSE-002`: add or compute the descriptor checksum.
- `E-PARSE-003`: re-export the descriptor; do not manually repair it unless you
  can independently verify the result.
- `E-PARSE-004`: do not mix mainnet and test-network keys.
- `E-PARSE-005`: export watch-only xpub metadata instead of private keys.
- `E-PARSE-006`: use a supported descriptor shape.
- `E-PARSE-007`: check the multisig threshold and key count.

See [Error codes](error-codes.md) for the full catalog.

