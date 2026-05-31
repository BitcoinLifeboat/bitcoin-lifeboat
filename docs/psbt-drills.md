# PSBT Drills

Partially Signed Bitcoin Transactions (PSBTs) let a wallet, signer, and recovery
tool pass an unsigned or partly signed transaction between devices without
sharing seed words or private keys. Lifeboat uses PSBTs for rehearsal workflows:
create a practice transaction, inspect it, sign it with practice wallet state,
finalize it, and record the drill result only when you choose to save it.

Normal Lifeboat flows still do not ask for real seed phrases. Practice Mode uses
the documented test mnemonic only, and the sensitive-input detector runs before
descriptor or drill input is processed.

## What Lifeboat Supports in v0.2

- BIP174 PSBT v0 import and inspection.
- BIP370 PSBT v2 import and inspection.
- Regtest and Signet practice receive/send drills.
- Local signing and finalization through the detached `psbt-drill` Rust crate.
- Optional Signet broadcast only after a visible confirmation that names the
  endpoint.
- CLI inspection of PSBT files through `lifeboat psbt`.

Mainnet broadcast is not part of Lifeboat. For mainnet transactions, use your
wallet or coordinator after you have independently reviewed what you are signing.

## QR PSBT Exchange

Practice Mode can show an unsigned practice PSBT as QR frames and scan a signed
PSBT back from an air-gapped signer. The QR transport is handled by the Rust
`qr-psbt` crate:

- New outbound frames use `ur:psbt`.
- Legacy `ur:crypto-psbt` is accepted only when importing a signed PSBT from an
  older signer.
- BBQr PSBT parts are supported for devices that use that format.
- Camera capture decodes QR payload strings locally. The app does not upload
  images or call a signing service.

After enough signed QR frames are scanned, Lifeboat validates and finalizes the
PSBT through the same local drill path used by file-based exchange. A successful
QR import proves the practice PSBT could be reconstructed and finalized; it does
not certify a real hardware wallet, firmware version, backup card, or mainnet
transaction.

## CLI Inspection

Inspect a PSBT file:

```sh
lifeboat psbt inspect --file updated.psbt --network signet
```

Emit machine-readable JSON:

```sh
lifeboat --json psbt inspect --file updated.psbt --network testnet
```

Validate that a PSBT is parseable and supported:

```sh
lifeboat psbt validate --file updated.psbt
```

Extract a transaction only after every PSBT input is finalized:

```sh
lifeboat psbt extract-tx --file finalized.psbt --output tx.hex
```

`extract-tx` refuses unfinalized PSBTs. That guard exists because a library can
often serialize an unsigned transaction shell, but a recovery drill needs the
final script data before an extracted transaction is meaningful.

## Reading the Inspection Output

The inspection output shows:

- PSBT encoding: `BIP174 v0` or `BIP370 v2`.
- Lifecycle: `unsigned`, `partially_signed`, or `finalized`.
- Input and output counts.
- How many inputs are finalized.
- Locally computed fee data when every input includes UTXO data.
- Output amounts and decoded addresses when you pass `--network`.

If fee data is unknown, the PSBT is missing local UTXO information for at least
one input. Lifeboat does not call a fee API or a chain service to fill that gap.

## Desktop Practice Flow

Practice Mode handles the end-to-end drill in the desktop app:

1. Pick `regtest` or `signet`.
2. Start the practice wallet and display a receive address.
3. Fund the practice wallet with synthetic regtest funds or, for Signet, use the
   browser-opened faucet link.
4. Create a local PSBT.
5. Sign and finalize it with practice wallet state.
6. Save the drill result only if you want a local signed record.

The saved drill record stores the public drill summary and signature envelope. It
does not store PSBT base64, transaction hex, descriptors, xpubs, addresses, seed
words, or passphrases.

## Fixtures for Developers

The committed PSBT fixtures live in `fixtures/psbt/`:

- `bip174_updated_v0.txt`
- `bip370_updated_v2.txt`

Use them for parser and CLI tests. Do not add fixtures generated from real wallet
activity.
