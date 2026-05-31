# CLI Reference

The `lifeboat` CLI uses the same Rust core crates as the desktop app. It is a
presentation layer around descriptor audit, address derivation, import parsing,
report generation, runbook generation, and secret detection.

## Global Flags

```text
--version              Print version
--help, -h             Print help
--json                 Emit machine-readable JSON where supported
--no-color             Disable ANSI color
--quiet, -q            Suppress non-essential output
--verbose, -v          Enable INFO-level logging without secrets
```

Global flags work before or after a subcommand.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Success or Ready |
| 1 | Warnings, Mostly Ready, or command-local no-match result |
| 2 | Critical or command-local invalid-for-network result |
| 3 | Cannot Determine |
| 4 | Invalid arguments or correctable input error |
| 5 | Sensitive input detected and rejected |
| 6 | File or IO error |
| 7 | Missing external dependency |
| 10 | Unknown subcommand |
| 20 | Internal error or panic path |

`audit-descriptor` and `report-json` route scored results through the readiness
status mapping. Utility commands may use command-local meanings when documented.

## audit-descriptor

```text
lifeboat audit-descriptor [--file PATH | --stdin | --descriptor STRING]
                           [--known-address ADDR]
                           [--network mainnet|testnet|signet|regtest]
                           [--derive-count N]
                           [--strict]
                           [--scoring-engine VER]
                           [--json]
```

Exactly one descriptor source is required. Prefer `--stdin` or `--file` for real
wallet metadata so the descriptor does not land in shell history. `--strict`
promotes a warning result to a critical exit code for CI.

## report-json

```text
lifeboat report-json [--file PATH | --stdin | --descriptor STRING]
                     [--known-address ADDR]
                     [--network mainnet|testnet|signet|regtest]
                     [--derive-count N]
                     [--scoring-engine VER]
```

Emits the deterministic `ReadinessReport` JSON shape described in
[JSON schemas](json-schemas.md).

## derive-addresses

```text
lifeboat derive-addresses --descriptor STRING
                           [--count N]
                           [--chain receive|change|both]
                           [--network mainnet|testnet|signet|regtest]
                           [--json]
```

Default count is 10. Default chain is `both`. A tpub descriptor needs
`--network` because tpub version bytes do not distinguish testnet, Signet, and
regtest.

## compare-address

```text
lifeboat compare-address --descriptor STRING
                         --address ADDR
                         [--search-range N]
                         [--network mainnet|testnet|signet|regtest]
                         [--json]
```

Exit code 0 means a match was found. Exit code 1 means no match was found in the
searched range. Exit code 2 means the address is invalid for the resolved
network.

## checksum

```text
lifeboat checksum --validate DESC
lifeboat checksum --compute DESC
```

`--validate` exits 0 only when a checksum is present and valid. `--compute`
prints the descriptor with a BIP380 checksum appended. Inputs are screened before
the descriptor is echoed.

## detect-secrets

```text
lifeboat detect-secrets [--file PATH | --stdin] [--json]
```

With no `--file`, the command reads standard input. It never echoes input
content. Block findings exit 5, warning-only findings exit 1, and allow exits 0.

## parse-export

```text
lifeboat parse-export --file PATH
                      [--format auto|sparrow|specter|coldcard|nunchuk|jade|liana|core]
                      [--decryption-input XPUB ...]
                      [--json]
```

The file is screened for secrets before import. `--decryption-input` is used for
Liana `.bed` backups and may be repeated.

## generate-runbook

```text
lifeboat generate-runbook --template ID
                          [--descriptor STRING]
                          [--output PATH]
                          [--mode public-safe|private]
                          [--format pdf|md|txt|html]
```

`public-safe` is the default. `pdf` is the default format and requires
`--output` because it is binary. A descriptor can prefill wallet summary fields
after secret screening.

Known template IDs include owner templates such as `singlesig-basic`,
`singlesig-passphrase`, `multisig-2of3`, `multisig-3of5`, and heir templates
such as `heir-singlesig-basic`, `heir-multisig-2of3`, and
`liana-timelock`.

## psbt

```text
lifeboat psbt inspect --file PATH [--network mainnet|testnet|signet|regtest] [--json]
lifeboat psbt validate --file PATH [--network mainnet|testnet|signet|regtest] [--json]
lifeboat psbt extract-tx --file PATH [--output PATH] [--json]
```

`inspect` and `validate` accept base64 BIP174 v0 and BIP370 v2 PSBT files.
`--network` is used only to decode output addresses; Lifeboat does not guess a
test network from PSBT contents.

`extract-tx` writes the transaction hex only when every PSBT input is finalized.
It refuses unsigned or partly signed PSBTs.

## verify-build

```text
lifeboat verify-build VERSION
                      [--artifact PATH ...]
                      [--checksums PATH]
                      [--release-base-url URL]
                      [--json]
```

Compares local artifact SHA-256 hashes to a release `SHA256SUMS` file. If
`--checksums` is omitted, the command reads `./SHA256SUMS`; if that file is not
present, it fetches `SHA256SUMS` from the configured GitHub Release for
`VERSION`.

With no `--artifact`, it checks local files in the current directory whose names
appear in `SHA256SUMS`. Exit code 0 means every checked artifact matched. Exit
code 2 means at least one artifact differed or had no published hash.

## completions and man

```text
lifeboat completions bash|zsh|fish|powershell|nushell
lifeboat man
```

These commands print shell completion scripts or a roff manual page to stdout.
