# hwi-bridge

This crate is the hardware-wallet boundary for HWI.

- Keep HWI access subprocess-only. Do not add `hidapi`, `rusb`, `rust-hwi`,
  PyO3, or any in-process USB/HID dependency here or in `src-tauri`.
- Missing or non-executable sidecar binaries map to `E-DEP-002`
  (`ErrorCode::HwiNotAvailable`). Non-zero HWI exits and timeouts map to
  `E-INTERNAL-001` with secret-free context.
- The child process wait is bounded with foreground `try_wait` polling. Do not
  replace it with a background process or `pgrep -f` watcher.
- Tauri packaging declares the sidecar as `bundle.externalBin:
  "binaries/hwi-lifeboat"`. The capability scope name must match that string.
- US-085 device verification flow: call `hwi enumerate`, match the descriptor's
  expected 8-hex master fingerprint, then call `getxpub <origin path>` with the
  matched device type/path and compare the returned xpub in Rust. Do not parse or
  compare xpubs in React.
- US-086 HWI signing uses the same selector boundary, then calls
  `signtx <psbt>` and reads the returned `psbt` field. Keep PSBT signing as a
  subprocess command here; do not move signing into React or add in-process USB.
- Supported USB families are exactly Ledger, Trezor, BitBox02, and Coldcard.
  Other HWI device types may be listed but verify as `unsupported_device`.
  Unsupported firmware is a structured `W-DEVICE-FIRMWARE-UNSUPPORTED` warning,
  not a panic or broad dependency failure.
