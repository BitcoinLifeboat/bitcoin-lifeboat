# HWI sidecar slot

Release packaging fills this directory with the target-specific HWI sidecar
declared by `tauri.conf.json`:

```json
"externalBin": ["binaries/hwi-lifeboat"]
```

Tauri expects the file to be suffixed with the target triple, for example
`hwi-lifeboat-x86_64-unknown-linux-gnu` or
`hwi-lifeboat-x86_64-pc-windows-msvc.exe`. From the repository root, use:

```sh
scripts/install-hwi-sidecar.sh --target x86_64-unknown-linux-gnu
scripts/verify-hwi-sidecar.sh --target x86_64-unknown-linux-gnu
```

The sidecar must be HWI 3.2 or newer. Lifeboat talks to it only as a child
process. Do not add Python, USB, HID, or vendor device libraries to the Tauri
process.

This repository does not commit generated sidecar binaries. Local tests use fake
executables through `crates/hwi-bridge`, so the normal quality gate does not need
HWI installed.
