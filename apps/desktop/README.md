# Bitcoin Lifeboat — Desktop App

Tauri 2 desktop shell for Bitcoin Lifeboat. The webview (Vite + React +
TypeScript) is a thin presentation layer; **all Bitcoin logic lives in the Rust
core crates** and is exposed to the UI through Tauri commands (wired in US-042).

## Layout

```
apps/desktop/
├── index.html, vite.config.ts, tsconfig.json   # Vite + React + TS frontend
├── tailwind.config.js, postcss.config.js        # Tailwind 3 (colors centralized in config)
├── src/                                          # UI: i18n, store, layout, pages, theme (US-044)
├── scripts/verify-capabilities.mjs               # security gate (§13.7/§13.8/§13.10)
└── src-tauri/                                     # Rust side (DETACHED Cargo workspace)
    ├── tauri.conf.json                           # CSP (§13.8), window, no updater
    ├── capabilities/default.json                 # locked-down permissions (§13.7)
    ├── binaries/                                  # packaged HWI sidecar slot (release-filled)
    └── src/{main,lib}.rs                          # runtime bootstrap
```

## Security model (NORMATIVE — do not relax without a security review)

- **Capabilities** are exactly the PRD §13.7 set for this milestone:
  `core:default`, `dialog` open/save, `fs` read/write scoped to `$DIALOG_PATH`,
  `os` platform/version, `process:allow-exit`, mobile camera take-picture, and
  `shell:allow-execute` scoped to the bundled HWI sidecar path
  (`binaries/hwi-lifeboat`). Nothing broader: no `http`, shell open/spawn/kill,
  clipboard, notification, global shortcut, webview creation, process spawn, or
  camera video recording.
- **CSP** is the strict PRD §13.8 policy in `tauri.conf.json → app.security.csp`
  (no `unsafe-eval`, no remote origins).
- **No auto-updater** (§13.10), ever.

Run the machine-checkable gate any time you touch the capability file or CSP:

```bash
npm run verify:security      # node scripts/verify-capabilities.mjs
```

## Develop / build

The frontend builds anywhere Node runs:

```bash
npm install
npm run typecheck            # tsc --noEmit
npm test                     # vitest run (jsdom)
npm run build                # tsc --noEmit && vite build -> dist/
```

The **Rust/Tauri** build needs the Linux desktop system libraries (webkit2gtk +
GTK 3). On Debian/Ubuntu:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
  libsoup-3.0-dev libjavascriptcoregtk-4.1-dev build-essential \
  libssl-dev librsvg2-dev libayatana-appindicator3-dev
```

Verify them from the repository root before a local Linux bundle build:

```bash
scripts/check-native-desktop-deps.sh
```

Then, from `src-tauri/` (which pins its own toolchain via `rust-toolchain.toml`):

```bash
cargo build                  # or: cargo tauri dev  (with @tauri-apps/cli installed)
```

For release-style reproducible bundles, run from the repo root:

```bash
scripts/reproducible-tauri-build.sh --target x86_64-unknown-linux-gnu --bundles appimage,deb
```

That wrapper sets `SOURCE_DATE_EPOCH` from the commit timestamp, disables Cargo
incremental state, and remaps local Rust paths before invoking the pinned Tauri
CLI.

> The core Rust workspace at the repo root stays pinned to Rust 1.78 and is a
> **separate** Cargo workspace; this desktop app is excluded from it so the core
> quality gate never needs the GUI toolchain or system libraries.

## HWI sidecar packaging

Hardware-wallet USB support runs through a bundled HWI sidecar, not in-process
USB/HID code. Release packaging installs the official Bitcoin Core HWI artifact
at the Tauri sidecar path declared in `src-tauri/tauri.conf.json`.

Tauri requires a target-suffixed filename under `src-tauri/binaries/`, for
example:

```text
src-tauri/binaries/hwi-lifeboat-x86_64-unknown-linux-gnu
src-tauri/binaries/hwi-lifeboat-aarch64-apple-darwin
src-tauri/binaries/hwi-lifeboat-x86_64-pc-windows-msvc.exe
```

Install and verify the sidecar for a release target from the repository root:

```bash
scripts/install-hwi-sidecar.sh --target x86_64-unknown-linux-gnu
scripts/verify-hwi-sidecar.sh --target x86_64-unknown-linux-gnu
```

The install script verifies pinned SHA256 values for the HWI 3.2.0 release
archive and extracted binary before renaming it for Tauri. Developer and CI tests
use fake sidecar executables through `crates/hwi-bridge`; they do not require
HWI, Python, or a hardware wallet.
