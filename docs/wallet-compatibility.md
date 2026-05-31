# Wallet Compatibility

Lifeboat needs watch-only wallet metadata. The best input is a wallet export that
contains receive and change descriptors with key origins. A raw seed phrase or
private key is never required.

## Tier Definitions

| Tier | Meaning |
| --- | --- |
| Tier 1 | First-class support. Lifeboat ships an importer and fixture tests. |
| Tier 2 | Manual workaround documented. Users paste a descriptor or export through another coordinator. |
| Tier 3 | Not usable directly in the MVP. Users are directed to a supported coordinator path. |

## v0.1 Matrix

| Wallet | Minimum version | Tier | Export | Receive and change | Origin info | Birth hint |
| --- | --- | --- | --- | --- | --- | --- |
| Bitcoin Core | 29.0+ (not 30.0/30.1) | 1 | `listdescriptors` JSON | Yes | Yes | Timestamp only |
| Sparrow | 2.5.0+ | 1 | Sparrow JSON | Yes, often multipath | Yes | ISO date |
| Specter Desktop | 2.1.0+ | 1 | Specter JSON | Receive only in tested export | Yes | Block height |
| Liana | 13.0+ | 1 | `.bed` backup | Yes | Yes | Timestamp |
| Nunchuk | 1.9+ | 1 | BSMS (BIP129) | Yes | Yes | No |
| Coldcard | Current firmware | 1 | Generic Wallet Export JSON or descriptor file | Yes | Yes | No |
| Passport Core | 2025+ | 1 | Descriptor file | Yes | Yes | No |
| Jade | 1.0.38+ | 1 | Registered wallet JSON | Yes | Yes | No |
| Electrum | 4.5.6+ | 2 | Coldcard-style multisig text workaround | Partial | Partial | No |
| BlueWallet | Current | 2 | Coldcard-style vault text | Partial | Partial | No |
| SeedSigner | 0.8.x | 2 | Signer only | Not applicable | Not applicable | Not applicable |
| Trezor Suite | Current | 2 | xpub copy/paste | Manual | Manual | No |
| Ledger Live | Current | 3 | None usable directly | No | No | No |

## v0.3 PSBT Signing Transport Matrix

This matrix covers PSBT exchange paths for practice signing drills. It is not a
real-device certification. For each device, Lifeboat creates or imports the PSBT
locally, displays the unsigned payload, and validates the signed payload after it
comes back.

| Device or project | File exchange | QR exchange | Notes |
| --- | --- | --- | --- |
| Coldcard | SD card `.psbt` | QR where supported by the device workflow | Use file exchange as the baseline path; QR support depends on the signer mode and firmware family. |
| Passport Core | microSD `.psbt` | QR | Use microSD for larger PSBTs when QR transfer is slow or the signer splits many frames. |
| SeedSigner | Not a primary path | QR | SeedSigner is treated as a signer-only device; Lifeboat does not ask for seed words. |
| Jade | microSD on Jade Plus | QR | Jade Plus can use microSD. Standard Jade workflows should use QR. |
| Foundation / Krux | Not a primary path | QR | Use the device's PSBT QR signing flow and scan the signed PSBT back into Lifeboat. |

The supported QR formats are `ur:psbt` and BBQr. Lifeboat accepts legacy
`ur:crypto-psbt` only for import compatibility. If a QR-only signer cannot scan
the displayed PSBT or its signed output does not decode, use the file-based PSBT
flow where the device supports removable storage.

## v0.4 Hardware Wallet Drill Matrix

Hardware Wallet Drill adds the optional HWI sidecar path for USB devices. The
full drill procedure and release checklist live in
[Hardware Wallet Drill](hardware-wallet-drill.md).

| Device | File | QR | HWI sidecar | Manual release status |
| --- | --- | --- | --- | --- |
| Trezor | Via coordinator export/import | Not primary | Yes | Pending real-device check |
| Coldcard | Yes | Where supported by firmware | Yes, where HWI supports the mode | Pending real-device check |
| BitBox02 | Via coordinator export/import | Not primary | Yes | Pending real-device check |
| Jade | Jade Plus microSD where available | Yes | No in this release | Pending real-device check |
| Ledger | Via coordinator export/import | Not primary | Yes | Pending real-device check |

Device discovery is not a pass condition by itself. A manual release check must
confirm PSBT signing, destination confirmation on the device, and signed-PSBT
validation back in Lifeboat.

## Tier 1 Export Instructions

### Bitcoin Core 29.x

Use RPC or console:

```sh
bitcoin-cli listdescriptors true
```

Save the JSON output to a local file and import it with `lifeboat parse-export
--format core`. Bitcoin Core 30.0 and 30.1 descriptors are rejected in the MVP
because of incompatible export behavior noted in the importer.

### Sparrow 2.5+

Open the wallet and choose `File > Export Wallet`. Save the Sparrow JSON export.
Lifeboat reconstructs descriptors from the policy, script type, keystores, and
birth metadata. Do not export or paste seed material.

### Specter Desktop 2.1+

Open `Wallet > Settings > Export` and save the wallet JSON. The tested Specter
export provides the receive descriptor. If your version exports a separate
change descriptor, keep both with the wallet backup.

### Liana 13+

Export the `.bed` backup from Liana. The MVP models the encrypted descriptor
flow and requires one of your wallet xpubs as a decryption input. That xpub is
watch-only metadata. Do not enter a seed phrase or passphrase.

### Nunchuk 1.9+

Use `Wallet > More > Export wallet config > BSMS`. Save the BSMS text file and
import it with `--format nunchuk` or auto-detect. Lifeboat rewrites the BIP129
`/**` shorthand to BIP389 multipath form for analysis.

### Coldcard

For singlesig, use the Generic Wallet Export JSON. For multisig or descriptor
backup, use the descriptor export file. If a `.sig` accompanies the descriptor
file, keep it with your backup. The MVP records the file pair but does not claim
to verify the signature.

### Passport Core

Export the descriptor file. File import is supported in the MVP. QR import is a
later hardware-wallet milestone.

### Jade

Export the registered multisig wallet JSON from Jade. Lifeboat assembles the
descriptor from the variant, threshold, sorted flag, and signer records.

## Tier 2 Workarounds

Electrum and BlueWallet can provide Coldcard-style text for multisig setups.
Import that text if available. If the export is incomplete, use Sparrow or
Specter as an intermediary and export a full descriptor from there.

SeedSigner is a signer rather than a wallet coordinator. Use it with a supported
coordinator and export the coordinator's wallet metadata.

Trezor Suite can expose xpubs, but the user may need to construct the descriptor
manually from wallet type, derivation path, xpub, and checksum. Prefer exporting
through Sparrow or Specter when possible.

## Tier 3

Ledger Live does not export the descriptor metadata Lifeboat needs in the MVP.
Register the Ledger-backed wallet in Sparrow or Specter, then export from that
coordinator.

## Contributor Notes

Add wallet support by creating a fixture under `fixtures/wallet_exports/`, adding
a strict importer in `crates/wallet-imports`, documenting the menu path here, and
adding tests that normalize the fixture into `NormalizedWalletExport`.

Record the wallet version, operating system if relevant, and export path. Do not
commit real wallet metadata.
