# Hardware Wallet Drill

Hardware Wallet Drill is the v0.4 signing rehearsal for devices and device
emulators. It creates a fake-funds PSBT, moves it through one signing path, and
validates the signed PSBT when it comes back.

The important rule:

**Device detected is not wallet recoverable.** A device listing only proves that
the HWI sidecar or QR/file workflow can see something. The drill still requires
PSBT signing, destination confirmation on the device, and signed-PSBT validation.

## Signing Paths

| Path | What Lifeboat does | What the signer does |
| --- | --- | --- |
| File | Saves an unsigned `.psbt` to a user-chosen path and imports the signed file. | Signs by SD card, microSD, USB disk, or coordinator import/export. |
| QR | Displays UR or BBQr PSBT frames and scans signed frames back from the device. | Scans the unsigned PSBT and shows signed PSBT frames. |
| HWI sidecar | Runs the bundled HWI sidecar as a subprocess and asks it to sign the PSBT. | Signs through HWI-compatible USB support. |

The desktop webview never parses PSBTs, derives addresses, or talks to USB
devices directly. File and QR signing reuse the PSBT drill layer. USB signing is
limited to the subprocess-only HWI bridge.

## HWI Scope

The HWI path supports the same USB families as the bridge:

- Ledger
- Trezor
- BitBox02
- Coldcard

Jade is covered through QR and file workflows in this release. Lifeboat does not
add in-process HID, USB, Python, or vendor SDK dependencies to the Tauri process.

If the HWI sidecar is missing, Lifeboat returns `E-DEP-002`. If HWI exits
non-zero, times out, or returns malformed output, Lifeboat returns
`E-INTERNAL-001` without exposing raw device output in the UI.

## CI Emulator Smoke

CI runs a hardware-wallet smoke matrix:

| CI target | Covered path |
| --- | --- |
| Trezor | HWI-compatible enumerate, getxpub, and signtx subprocess flow |
| Coldcard | HWI-compatible enumerate, getxpub, and signtx subprocess flow |
| BitBox02 | HWI-compatible enumerate, getxpub, and signtx subprocess flow |
| Jade | QR PSBT encode/decode and image-decoder flow |

The hosted CI job uses deterministic emulator fixtures for the command contract.
Release testing still needs manual device checks, because CI cannot prove that a
particular physical device, cable, firmware, camera, SD card, or operating-system
USB stack will behave the same way for every user.

## Manual Device Matrix

Record real-device checks before each release. Use testnet, Signet, regtest, or
throwaway practice funds only.

Stable releases require the machine-readable matrix at
`docs/hardware-wallet-device-matrix.json`. Copy
`docs/hardware-wallet-device-matrix.template.json`, fill in real firmware, host
OS, tester, date, and evidence references, then run:

```sh
scripts/verify-release-gates.sh --tag v1.0.0
```

| Device | Firmware tested | Host OS | Path tested | Result | Tester | Date | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Trezor | TBD | TBD | HWI sidecar | Pending | TBD | TBD | Emulator smoke runs in CI. |
| Coldcard | TBD | TBD | File, HWI where available | Pending | TBD | TBD | File exchange remains the baseline. |
| BitBox02 | TBD | TBD | HWI sidecar | Pending | TBD | TBD | Emulator smoke runs in CI. |
| Jade | TBD | TBD | QR, file where available | Pending | TBD | TBD | QR smoke runs in CI. |
| Ledger | TBD | TBD | HWI sidecar | Pending | TBD | TBD | Supported by HWI bridge, but not in the current emulator matrix. |

For each manual entry, record the exact app build, operating system, firmware,
transport path, and whether the signed PSBT validated. Do not record seed words,
passphrases, private keys, full descriptors, xpubs, signer locations, or mainnet
transaction data in the matrix.
