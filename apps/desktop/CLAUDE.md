# apps/desktop frontend — conventions (since US-044)

The webview is a **thin presentation layer**. All Bitcoin logic lives in the Rust
core and is reached via Tauri commands (US-042/043). The frontend MUST NOT parse
descriptors, derive addresses, validate checksums, detect secrets, score, or do
crypto. Do not add `bitcoinjs-lib` / `@scure/btc-signer` (a CI lint will fail).

## Stack & layout
- Vite + React 18 + TypeScript 5 (strict; no `any`, no `as` outside tests).
- **Tailwind 3** (NOT 4 — config model differs). All colors live in
  `tailwind.config.js → theme.extend.colors`; never hardcode a hex in a component.
  Status badge colors are `status.*` (§22.3), network banner colors `network.*`
  (§22.4), brand surface `brand.*`. `darkMode: "class"` — toggle the `dark` class
  on `<html>` via `src/theme/theme.ts` (`applyTheme`), driven by the prefs store.
- `src/i18n/` — i18next + react-i18next, **synchronous** init with bundled
  locale JSON files (no network backend). ALL user-facing copy comes from i18n
  keys; no hardcoded strings in components. Add a key to `en.json`, mirror it in
  every bundled locale, and use `t("…")`.
- `src/store/` — Zustand. Two stores, deliberately split by data classification:
  - `session.ts` (**Confidential**): descriptor, known address, report, derived
    addresses — current screen only. It is a PLAIN store: **never** wrap it in the
    `persist` middleware and never write its data to localStorage / sessionStorage
    / IndexedDB. `session.test.ts` fails the build if anything does. Call `reset()`
    on screen exit / "Save and quit".
  - `prefs.ts` (**Public**): theme, language. Only Public prefs may persist, and
    the channel is the Tauri settings file (US-054), **not** web storage. In-memory
    until US-054 wires the settings-file command.
- Routing: **HashRouter** (robust in the Tauri webview, which serves from a custom
  protocol — not a history-API origin). `App.tsx` holds the route table; the §22.1
  sidebar nav lives in `src/layout/AppLayout.tsx`. Each screen is a file under
  `src/pages/` (placeholders today; US-045..US-055 fill them). Routes:
  `/`, `/readiness-check`, `/audit-multisig`, `/heir-runbook`, `/generate-runbook`,
  `/learn`, `/settings`. HashRouter opts into the v7 future flags to silence warns.

## Onboarding gate (since US-045)
- The §15.2 five-screen first-launch flow lives in `src/onboarding/Onboarding.tsx`.
  It is **not** a route: `App.tsx` renders `<Onboarding/>` while the Public
  `prefs.onboardingComplete` flag is false, and the routed app (whose Home is
  "Screen 5") once it is true. Completing or skipping calls
  `setOnboardingComplete(true)`. `onboardingComplete` is a Public pref (persists
  via the settings file in US-054; until then it resets each launch).
- Screens 1–4 are internal `useState` steps (Welcome, Safety Promise, Goal, Mode
  Confirmation). Screen 2's "I understand." checkbox gates Continue; Skip appears
  only when `step > 2` (§15.2 "skippable only after Screen 2"). Screen 4 shows
  only for real-wallet-audit goals (`GOALS[].requiresModeConfirmation`); Practice
  Mode / CLI finish after Screen 3.
- **Verbatim NORMATIVE copy (§15.2 screens, §15.6 disclaimers, §15.7 not-a-wallet)
  still comes from i18n keys** — store the exact words under an `en.json` key and
  `t()` it; don't hardcode. Tests assert the rendered English, so a copy edit that
  breaks verbatim text fails a test. Any screen that gates an action behind a
  shared Public flag should follow this gate-in-`App.tsx` pattern (not a route),
  so the main shell never renders until the precondition holds.

## Shared UI primitives (since US-046)
- **Icons**: `src/components/icons.tsx` is a dependency-free inline-SVG set
  (`BookIcon`, `ShieldIcon`, `FamilyIcon`, `PrinterIcon`, `PlayIcon`, and the
  US-047 status glyphs `CheckCircleIcon`, `AlertTriangleIcon`, `XCircleIcon`,
  `HelpCircleIcon`). All are **decorative** (`aria-hidden`, stroke
  `currentColor`) — the adjacent text carries meaning; color comes from a
  Tailwind `text-*` class on the wrapper. Reuse / extend this file rather than
  adding an icon package.
- **Navigation cards** (§22.2 Home dashboard, `src/pages/Home.tsx`): render an
  active card as a React Router `<Link>` (it gets `role="link"`, so a test finds
  it by `name` regex over the title and asserts its `href`); render a
  disabled/"coming later" card as a non-link `<div aria-disabled>` (so
  `queryByRole("link", …)` is null). Drive a card grid from a data array of
  `{ to, icon, base }` where `base` is an i18n key prefix and each card reads
  `${base}.title|.description|.time|.materials` — keeps all copy in `en.json`.
- **Banners + status badges** (since US-047, `src/components/`): `NetworkBanner`
  (§22.4), `SafetyBanner` (§22.6), `StatusBadge` (§22.3). Each maps a domain
  value → a `Record<…, { labelKey, classes, Icon? }>` of **full literal Tailwind
  class strings** — never build a class like `bg-network-${n}` (Tailwind's
  content scanner only keeps literals; a dynamic name compiles to nothing). The
  `network.*` / `status.*` color tokens live in `tailwind.config.js`.
- **Network vocabulary**: `WalletNetwork` (`store/session.ts`) is
  `"bitcoin" | "testnet" | "signet" | "regtest"` — it mirrors the Rust core's
  `Network` serialization, so **mainnet is `"bitcoin"`, not `"mainnet"`**;
  `NetworkBanner` is the only place that maps `"bitcoin"` → the MAINNET label +
  red. The current network is `useSessionStore(s => s.network)` (defaults to
  mainnet; US-049/050 set it from the network the Rust core infers — once a
  descriptor has cleared the detector and reached `audit_descriptor` — and the
  banner recolors. The US-048 wizard shell does not parse descriptors, so it does
  not infer the network).
- **§22.3 status colors are WCAG-AA-verified _on white_** → `StatusBadge` keeps
  `bg-white` in both light and dark mode and uses the status token as
  text/border/icon, so the verified contrast always holds. Convey status with
  text **and** icon shape (not color alone).
- **Wallet-data chrome is wired in `AppLayout.tsx`**, gated on
  `WALLET_DATA_PATHS` (readiness-check / audit-multisig / heir-runbook /
  generate-runbook) via `useLocation()`. Home / Learn / Settings show no banners.
  Banners are non-dismissible (no close control — a `queryByRole("button")` null
  check guards that). `NetworkBanner` uses `role="status"` so a recolor announces
  to assistive tech; `SafetyBanner` uses `role="note"`.

## Multi-step wizard (since US-048)
- The §22.8 Readiness Check is a **reusable** component `src/pages/ReadinessWizard.tsx`
  (the `ReadinessCheck` page is a one-line wrapper passing
  `defaultWalletType="singlesig"`). The §22.11 **Audit Multisig** screen (US-053)
  renders the same `<ReadinessWizard defaultWalletType="multisig" />` — do not
  fork a second wizard.
- **Shell vs. heavy steps**: US-048 is only the 8-step shell — step indicator,
  Back/Next with per-step `nextDisabled` gating (steps 1/2/3 require input; 4–6
  are optional; 7/8 are terminal), the §22.9 sample link, "Save and quit", and
  capture of the recovery answers. The Rust-core steps are owned by later stories
  and fill the existing seams: **step 3** descriptor import + sensitive-input
  block dialog (US-049), **step 7** report viewer (US-050), **step 8** export
  controls (US-051). Keep that split — don't pull core calls into the shell.
- **Confidential input stays local in the shell**: the descriptor / known address
  live in component `useState` (dropped on unmount), **not** the session store —
  US-049 owns the safe commit (detect-before-process, then `setDescriptor`). The
  wizard follows `Onboarding.tsx`: all working state is local `useState`; step
  bodies are inline `{step === N && …}` blocks; the component stays mounted across
  steps so Back/Next preserves answers.
- **"Save and quit"** (`useNavigate("/")` + `useSessionStore().reset()`) is the
  §22.8 clean exit: local state vanishes on unmount and `reset()` clears anything
  later steps wrote to the session store. Test it with a `MemoryRouter` whose `/`
  route renders a sentinel, then assert the sentinel appears + web storage stays
  empty (the §22.11 invariant).
- **§9.1 "each skip = warning"** is a UI **preview**, not scoring: a recovery
  question that applies to the wallet type but is not answered `"yes"` is listed
  under the review's warnings. `multisigOnly` questions (H2/H3) are not applicable
  to a singlesig wallet (excluded from warnings there). Never compute W-codes /
  weights / the numeric score in the frontend — that is the Rust core (US-021);
  the wizard only captures answers and previews which will warn.
- **Recovery questions** are a `<fieldset>` per question (`<legend>` = the
  question text → testable via `getByRole("group", { name })`, then
  `within(group).getByRole("radio", { name: "Yes" })`). Answers are a
  `Record<id, "yes"|"no"|"unsure">`; absent = skipped; a "Clear answer" button
  re-skips.
- **Sample descriptors** are inert frontend constants (the committed test-network
  fixtures — tpub, never mainnet) chosen by wallet type; loading one shows the
  §22.9 `[ SAMPLE ]` badge and is cleared the moment the user edits the field.

## Tauri command client + sensitive-input screening (since US-049)
- **`src/tauri/commands.ts` is THE seam to the Rust core.** `withGlobalTauri` is
  false, so `invoke` is imported from `@tauri-apps/api/core` (no `window.__TAURI__`).
  Every command is a typed wrapper here returning a **crate-owned snake_case serde
  type** (mirror the Rust shape exactly — e.g. `DetectorReport.findings` is a
  `[DetectedSecret, ByteRange]` tuple = JSON array; externally-tagged enum variants
  are `{ "<tag>": {…} }`, unit variants the bare string). Future commands
  (US-050 `generate_report`, US-051 `save_export`) extend THIS file. Component
  tests `vi.mock("../tauri/commands", …)` (with `vi.hoisted` for the mock fn) so
  the jsdom suite never touches the IPC bridge and drives verdicts directly.
- **Screen every paste/file/drop BEFORE processing (§13.5 / §17.1).** Step 3 of the
  wizard runs `detectSensitiveInput` on the candidate text from each import path.
  `Block` → clear the field + open the §22.7 dialog, never store the text; `Warn` →
  keep the (public) descriptor but gate Next behind the §13.5.7 override checkbox
  ("I confirm this is not a real secret"); `Allow` → keep it and mark
  `screenedClean`. The descriptor is committed to the session store
  (`setDescriptor`) only AFTER a clean screen — the "behind the detector" commit.
  Manual typing is **not** screened per keystroke (only paste/file/drop are, plus a
  Next-time backstop for typed text); a trusted `[ SAMPLE ]` skips screening.
- **§13.5.9 point 2**: overwrite the JS variable passed to `invoke` (`input = ""`)
  immediately after the call returns. The descriptor field itself legitimately
  holds the public descriptor on `Allow`/`Warn`; on `Block` it is cleared.
- **`SensitiveInputDialog.tsx` (§22.7)** is presentational: render it whenever
  `detected` is non-null (pass `null` to hide). It CANNOT be dismissed by Escape
  (an `onKeyDown` swallows Escape — only "I understand" calls `onAcknowledge`), and
  it shows only a NON-secret **category** derived from the `DetectedSecret`
  discriminant (e.g. "a 12-word BIP39 seed phrase"), never the secret content.
- **File read uses `FileReader`** (`readFileText`), not `Blob.text()` — jsdom lacks
  `text()` and some older WebKitGTK builds do too. The user explicitly chose the
  file, so this needs **no Tauri fs capability** (the HTML File API gives content,
  not a path).
- **Drag-and-drop needs `"dragDropEnabled": false`** on the window in
  `tauri.conf.json` (Tauri 2 camelCase for `drag_drop_enabled`). With Tauri's
  default interception ON, the webview's HTML5 drop events for files don't fire.
  Turning it off is also the more locked-down choice for us: HTML5 drop yields a
  `File` (content only), never an OS path. It is a window-config key (not a
  capability/CSP/updater change), so `verify-capabilities.mjs` stays 23/23.
- **`@tauri-apps/api`** is pinned to match the Tauri crate (2.11.x). The vite bundle
  grew (~80 kB gz → it now includes the IPC client) — expected.

## Miniscript policy tree (since US-088)
- `renderMiniscriptPolicyDot` is the only frontend seam for policy visualization.
  It returns redacted GraphViz DOT from Rust (`miniscript-viz` through
  `desktop-commands`); React must not parse descriptors or Miniscript text.
- `src/components/PolicyTree.tsx` renders only the deterministic DOT shape emitted
  by `miniscript-viz` (`nN [label="..."]`, `nA -> nB`). Do not add GraphViz/Wasm
  renderers or relax CSP unless the Rust DOT contract changes and the story
  explicitly calls for it.
- The Readiness wizard review step owns the policy tree display for now. The Liana
  sample descriptor is selected when wallet type is `"liana"`; the multisig sample
  remains selected for `"multisig"`.
- For Liana wallets (US-091), the review step calls `renderLianaRecoveryTree`
  instead of the generic DOT command. Rust returns both DOT and typed path
  summaries; React may format counts/timelock estimates but must not infer paths
  from descriptor text or parse Miniscript/DOT for business facts.
- The Liana current-block field (US-092) passes an optional `currentBlockHeight`
  into `renderLianaRecoveryTree`. React only parses the numeric input and formats
  the returned `path.countdown`; Rust computes `active_in_blocks` / `active_at_block`
  from typed `older` / `after` constraints. Do not fetch block height from the UI
  or compute timelock deltas in React.

## Heir walkthrough copy (since US-095)
- Heir-facing walkthrough copy lives under `pages.heirWalkthrough` in
  `src/i18n/en.json` and is checked by
  `scripts/verify-heir-walkthrough-copy.mjs`. Keep it plain and short enough for
  Flesch-Kincaid grade <= 8.0, and repeat the exact anti-scam phrase
  "we will never contact you" at least twice.
- The `/heir-walkthrough` page is a local-state UI checklist only. It should not
  parse packet files, descriptors, wallet files, PSBTs, or secrets in React.
  Future packet/receipt logic should stay behind typed Rust/Tauri commands.
- US-096 receipt export keeps the same boundary: React maps local checklist state
  to typed enum ids, calls `generateFamilyDrillReceipt`, then writes the returned
  PDF bytes through `showSaveDialog` + `saveExport`. When packet import lands,
  pass only the manifest packet UUID/network to the receipt command, never wallet
  file data or free-text notes.

## i18n locale bundles (since US-097)
- Supported desktop locales are declared once in `src/i18n/index.ts`
  (`SUPPORTED_LOCALES`) and imported as bundled JSON resources. Region-specific
  tags normalize to the primary supported language (`es-MX` -> `es`); unsupported
  tags fall back to English. The Settings language selector must render from
  `SUPPORTED_LOCALES`, not from a hand-written option list.
- Locale files under `src/i18n/{en,es,de,fr}.json` must keep identical key sets.
  `scripts/verify-i18n.mjs` fails on missing/dead keys, translation overclaims,
  and hardcoded JSX text/accessibility labels. It is wired into
  `npm run verify:guardrails`, `npm run verify:security`, `npm run build`, and
  `npm test` through `test:guardrails`.
- New visible copy still starts in English first. Add the English key, add the
  same key to every locale (fallback English is acceptable temporarily only when
  the key exists everywhere), and keep any safety promise wording negated so the
  overclaim lint does not trip.

## Practice Mode seed field (since US-067)
- `src/pages/PracticeMode.tsx` is the **only** BIP39 seed field in the desktop app.
  Keep it read-only, pre-filled with the canonical documented mnemonic
  `abandon ... about`, and reachable from the Home Practice card at
  `/practice-mode`.
- Paste handling still calls `detectSensitiveInput` before deciding what to do.
  The canonical documented practice mnemonic may be reloaded after screening; any
  checksum-valid mnemonic that is not documented stays out of component state and
  opens the hard-block dialog with the exact `practice-seeds.md` message.
- The documented allowlist lives in two places today: the page constant in
  `PracticeMode.tsx` and the user-facing `docs/practice-seeds.md` / embedded
  Learn copy. Update them together if another test vector is ever accepted.
- Use `text-slate-950` on the amber `PRACTICE-ONLY` badge. Real Chromium axe
  checks fail white text on `status.needs-attention` even if jsdom does not catch
  it.

## Practice Mode receive/send drill (since US-071)
- Keep the React page thin: it calls `startPracticeDrill`, `runPracticeSendDrill`,
  `broadcastSignetTransaction`, `savePracticeDrillResult`, and `openExternalLink`;
  it never creates PSBTs, derives addresses, signs/saves records, or contacts a
  faucet itself.
- Signet faucet handling is browser-only. The UI displays the Rust-returned
  address and opens `faucet.mutinynet.com` via `openExternalLink`; no `fetch`, HTTP
  client, or frontend network call belongs here.
- US-072 Signet broadcast is a separate confirmation after local finalization.
  The page must show `Network call to https://mutinynet.com/api/tx` (or the chosen
  Signet endpoint) before invoking `broadcastSignetTransaction`. Regtest never
  renders a broadcast button, and no frontend code should add `fetch`, HTTP
  clients, or a mainnet endpoint.
- US-075 DrillResult history is opt-in only. Render "Save this drill result" only
  after a completed drill, do not invoke `savePracticeDrillResult` automatically,
  and keep the saved-record schema/signature/path handling inside Rust.
- US-081 QR PSBT exchange extends the same Practice Mode result panel. The page
  calls `encodePsbtQrFrames`, `capturePsbtQrPayloads`, `decodePsbtQrPayloads`,
  then `finalizeFilePsbt`; React only displays Rust-returned SVG frames, cycles
  them, and passes scanned payload strings back to Rust. Keep browser verification
  in the Playwright Tauri mock as a display-plus-scan round trip, not as frontend
  QR or PSBT parsing.

## Disaster Drill questionnaire (since US-076)
- `src/pages/DisasterDrill.tsx` stays a thin DS-1..DS-6 questionnaire UI. It calls
  `detectSensitiveInput` before `runDisasterQuestionnaireDrill`, never parses
  descriptors, derives addresses, computes quorum/survivability, or decides
  pass/fail in React.
- The page asks only public yes/no/unsure facts and counts. Do not add free-text
  signer locations, seed words, passphrases, private keys, or wallet-file
  contents. The Rust result is saved only after the user clicks "Save this drill
  result" via `saveDisasterQuestionnaireDrillResult`.
- The DS-5 Playwright path is the browser verification: use the sample descriptor,
  run "I have my descriptor but not all signers", assert the pass result, then save
  the local DrillResult. Keep it in the no-network e2e suite.
- US-090 extends this page with the missing-signer drill. The UI chooses a
  1-based signer number and regtest/Signet practice chain, then calls
  `runMissingSignerDrill`; React must not compute quorum or required materials.
  The browser verification is the Playwright path that selects "Missing signer
  drill", uses the 2-of-3 sample, loses signer 2, checks remaining signer 1+3,
  and saves through `saveMissingSignerDrillResult`.

## Disaster Drill signing (since US-082)
- DS-7..DS-10 use the existing Practice Mode PSBT transports but save through the
  disaster-signing result commands: `startDisasterSigningDrill`,
  `completeDisasterSigningDrill`, and `saveDisasterSigningDrillResult`.
- React must not inspect or finalize PSBTs. It saves/imports files, displays QR
  frames returned by Rust, scans payload strings, and passes the signed PSBT back
  to Rust with the destination-confirmation checkbox state.
- The DS-9 Playwright path is the browser verification for signing drills: select
  QR transport, start the drill, confirm the destination, scan the signed QR PSBT,
  assert the pass result, then save the local DrillResult.
- Mainnet PSBT file handling (US-083) is a separate validation-only path inside
  `DisasterDrill.tsx`. It uses component-local acknowledgement state, calls
  `validateMainnetFilePsbt`, and must not call `startDisasterSigningDrill`,
  `completeDisasterSigningDrill`, or `broadcastSignetTransaction`.

## Hardware Wallet Drill (since US-086)
- `src/pages/HardwareWalletDrill.tsx` is a thin UI over the same disaster-signing
  DrillResult path. File and QR transport use the existing PSBT commands; HWI
  transport calls `enumerateHwiDevices`, then `signHwiPsbt`, then
  `completeDisasterSigningDrill` with transport `hwi`.
- Keep the warning "Device detected is not wallet recoverable." visible in this
  flow. Device enumeration alone is never a pass condition; the pass/fail result
  comes from signed-PSBT validation and destination confirmation.
- The frontend may render device metadata returned by Rust, but it must not parse
  HWI JSON, inspect PSBTs, compare xpubs, or touch USB/HID APIs. Browser
  verification belongs in the Playwright Tauri mock (`hardware-wallet-drill.spec.ts`).

## Tests
- **Vitest + jsdom + @testing-library/react.** `vite.config.ts` carries the `test`
  block (it imports `defineConfig` from `vitest/config`). `src/test/setup.ts`
  registers jest-dom matchers, initializes i18n, and runs RTL `cleanup` after each
  test. `globals: false` — import `describe/it/expect/vi` from `vitest` explicitly.
- Run: `npm test` (`vitest run`) / `npm run test:watch`.
- The §22.11 "no Confidential data in web storage" invariant is enforced by
  `src/store/session.test.ts` — keep it green; extend it if you add Confidential
  fields.

## Quality gate for a UI story
`npm run typecheck` + `npm test` + `npm run build` + `npm run verify:security`
(24/24 after the scoped camera check was added). The native `cargo build` / window launch
still needs the GTK/webkit `-dev` libs (absent in CI sandbox); a render-level
check via the testing-library suite is the runnable substitute here. See the repo
`progress.txt` "M2 DESKTOP" note.

## Frontend guardrails (since US-058)
- `npm run verify:security` is now two gates: `verify:capabilities` (the existing
  §13.7/§13.8/§13.10 Tauri posture check) and `verify:guardrails`
  (`scripts/verify-frontend-guardrails.mjs`).
- `verify:guardrails` is dependency-free and also runs in `npm run build`. It scans
  `src/`, `e2e/`, and root frontend config files for forbidden Bitcoin/crypto
  imports, dynamic code execution (`eval`, `Function`, string timers), web-storage
  writes, positive "funds/wallet are safe" claims, analytics snippets, and updater
  config/dependencies. It checks `package.json`, `src-tauri/tauri.conf.json`, and
  `src-tauri/Cargo.toml` for dependency/config regressions.
- Guardrail samples live in `scripts/verify-frontend-guardrails.test.mjs` and run
  before Vitest via `npm test`. Add new guardrail cases there first so every rule
  proves both "clean tree passes" and "violating sample fails".
- The "safe funds" lint allows negated normative disclaimers such as "We never
  claim your funds are safe" and "does not tell you that your bitcoin is
  protected"; avoid adding positive wallet/funds safety language anywhere in
  frontend copy or docs.

## Report viewer (since US-050)
- **`src/components/ReportViewer.tsx`** renders a §19.1 `ReadinessReport` (the
  `auditDescriptor` result) as the in-app report. It is **presentational** — it
  takes a `report` prop and runs no IPC / Bitcoin logic. Layout follows §22.5
  (one-sentence plain-English summary, §22.3 `StatusBadge`, a default-closed
  `<details>` "Show technical details" expander per §15.9, an action-oriented
  recommended-fix block, a `<Link to="/learn">` "Learn more", and a "Copy
  explanation" button) and the §15.10 section ORDER (passed → needs attention →
  failed → missing → next steps → anti-actions → run-again → disclaimer →
  version+hash). Every report ALSO ends with the **verbatim §15.8** "What this
  report cannot tell you" block, stored in the `report.cannotTell` i18n key — keep
  it byte-for-byte (it mirrors the Rust `report-engine` `REPORT_CANNOT_TELL`).
- **"What is missing"** (§15.10 item 5) is derived from `checks` whose
  `result === "unknown"` (e.g. network undetermined) — there is no dedicated
  report field.
- **Report TS types live in `src/tauri/commands.ts`** (`ReadinessReport` + its
  sub-types, mirroring the core snake_case serde shape exactly: `critical_issues`
  are `{code,title,description}`, `check.result` ∈ `pass|warn|fail|na|unknown`,
  singlesig `wallet_summary.threshold`/`key_count` are `null`). Get the structured
  report from **`auditDescriptor(input)`** — NOT `generate_report` (which returns a
  formatted export string; that lands with the export UI in US-051).
- **Wizard step 7 (`ReadinessWizard.tsx`)** generates the report via a `useEffect`
  keyed on `step === 7` (calls `auditDescriptor` with the screened descriptor +
  optional known address) and renders `<ReportViewer>` below the input summary.
  Tests that reach step 7 must mock `auditDescriptor` (add it to the `vi.mock`
  factory + a `vi.hoisted` `auditMock`, `mockResolvedValue(sampleReport)` in
  `beforeEach`). **`src/test/sampleReport.ts`** is the shared, typed
  `ReadinessReport` fixture both `ReportViewer.test.tsx` and the wizard suite use.

## Report export (since US-051)
- **Wizard step 8** offers three formats — **PDF / Markdown / JSON** — in the
  default `public-safe` mode or, behind the §9.5 confirmation, `private`.
- **Report PDF is the §17.7.4 "Print to PDF" path, NOT a backend renderer.**
  `generate_report` only renders `json` / `json_pretty` / `markdown` (its
  `ReportArtifact.content` is a `String`, not bytes); true PDF generation belongs to
  the **runbook** engine (§17.8), not the report. So the export UI does PDF with
  `window.print()` over a **public-safe** print region — never invent a report-PDF
  backend or fake a `.pdf` save. (PRD §10.3 #21 lists "PDF export of report"; §17.7.4
  is the authoritative *how*: the in-app report view doubles as print-optimized HTML.)
- **Print isolation lives in `styles.css`** as `.lifeboat-print-area` + an
  `@media print` block (hide `body *` via `visibility`, reveal only the print area,
  force black-on-white). Render `<div className="lifeboat-print-area">
  <ReportViewer report={report} hideTechnicalDetails /></div>` on step 8; it is
  `display:none` on screen and the only thing the OS print dialog inks. jsdom ignores
  CSS, so the region is still queryable in tests — the PDF test asserts
  `window.print` was called (spy it via `vi.spyOn(window, "print")`).
- **`ReportViewer` gained `hideTechnicalDetails?: boolean`** (default `false`). The
  on-screen viewer keeps the `<details>` expander; the print region sets it `true` so
  the **xpub-bearing canonical descriptor never reaches a printed PDF** — printed
  reports are public-safe by construction, independent of the redaction toggle.
- **`commands.ts` adds `generateReport(input, format)`, `saveExport(path, content)`,
  and `showSaveDialog(options)`.** Markdown/JSON flow = `generateReport` (honors
  `redaction`) → `showSaveDialog` (suggested filename + filters) → `saveExport`.
  `save_export` takes `Vec<u8>`, so encode the artifact text:
  `Array.from(new TextEncoder().encode(artifact.content))`.
- **The OS save dialog is reached WITHOUT a new npm dep**: `showSaveDialog` calls
  `invoke("plugin:dialog|save", { options })` over the existing `@tauri-apps/api/core`
  bridge. `tauri-plugin-dialog` is already registered in `src-tauri/src/lib.rs` and
  `dialog:allow-save` is already in `capabilities/default.json`, so the dialog works
  and **`verify:security` stays 23/23** — do NOT add `@tauri-apps/plugin-dialog` or
  widen capabilities for this.
- **Serde literals (verify, don't assume): `RedactionMode` is _kebab-case_**
  (`"public-safe"` | `"private"`), while `ReportFormat` is _snake_case_
  (`"json"` | `"json_pretty"` | `"markdown"`). The UI maps "JSON" → `"json_pretty"`
  (human-readable file) and the private toggle → `"private"`.
- **`ExportPrivacyDialog.tsx` (§9.5)** mirrors `SensitiveInputDialog` (alertdialog,
  verbatim warning from the `dialogs.exportPrivacy.warning` key) but is a
  *confirmation*, not a hard block: one **confirm** button switches to private; a
  Cancel button, the backdrop, and **Escape** all cancel back to the safe
  `public-safe` default (Escape is honored here, not swallowed, because the fallback
  is the safe state). The private toggle never flips until the user confirms — and it
  is hidden for the PDF format (replaced by a "PDF is public-safe" note).

## Runbook generator (since US-052)
- **`src/pages/GenerateRunbook.tsx`** is the standalone runbook generator (route
  `/generate-runbook`): a template chooser, an optional descriptor pre-fill, the
  §9.5 mode toggle, a format selector, a live Markdown preview, and export via the
  OS save dialog. The dedicated **guided heir flow** (§31.2) is the separate
  `HeirRunbook.tsx` / `/heir-runbook` screen (US-053) — it MUST reuse this same
  `generateRunbook` command + the notes below, not re-implement them.
- **Runbook PDF is a REAL backend document — NOT the report's print-to-PDF path.**
  `RunbookFormat` is `"pdf" | "markdown"` and `generate_runbook` returns
  `RunbookArtifact.content` as a **byte array** (`Vec<u8>` → `number[]`) for BOTH
  formats. So export = `generateRunbook(input)` → `showSaveDialog` → **`saveExport(path,
  artifact.content)` (pass the bytes straight through — do NOT `TextEncoder`-encode,
  unlike the report whose `content` is a `String`).** For the live preview, render
  Markdown (`format: "markdown"`) and decode with
  `new TextDecoder().decode(new Uint8Array(artifact.content))`.
- **Template ids are the core's `OwnerTemplate::name()` / `HeirTemplate::name()`**
  (kebab-case): 4 owner (`singlesig-basic`, `singlesig-passphrase`, `multisig-2of3`,
  `multisig-3of5`) + 7 heir/education (`heir-singlesig-basic`,
  `heir-singlesig-passphrase`, `heir-multisig-2of3`, `heir-multisig-3of5`,
  `liana-timelock`, `meetup-workshop`, `business-treasury`). An unknown id is
  `E-INPUT-003`. The
  chooser is a `<select>` with one `<optgroup>` per family; each option label is an
  i18n key `pages.generateRunbook.templates.<id>` (hyphens are fine — i18next splits
  only on `.`).
- **The only "fill" input is the optional descriptor** (it pre-fills the wallet
  summary + signer table). Per §9.5 the app never accepts seed / passphrase /
  location free-text — those stay as printed blanks the owner completes by hand
  (state this with the `descriptor.blankNote` copy). The descriptor is screened with
  the same US-049 detect-before-process flow (paste auto-screens; `Block` → clear +
  `SensitiveInputDialog`; `Warn` → inline override; `Allow` → apply). `appliedDescriptor`
  (the screened value) — not the raw field — drives the preview/export, and editing
  the field un-applies it so an unscreened edit never reaches the core.
- **No capability/plugin change**: reuses the US-051 `showSaveDialog` (`plugin:dialog|save`)
  + `saveExport` + the already-registered `generate_runbook` command (US-043). The
  §9.5 gate reuses `ExportPrivacyDialog` unchanged. `verify:security` stays 23/23.
  Unlike the report PDF, the runbook private toggle is offered for BOTH formats (the
  backend redacts the PDF too), so there is no print-region / `hideTechnicalDetails`
  detour here.

## Heir runbook flow (since US-053)
- **`src/pages/HeirRunbook.tsx`** (`/heir-runbook`) is the §31.2 **guided** inheritance
  flow — a 3-step wizard (1 choose plan → 2 wallet details + location guidance → 3
  preview + export), distinct from the single-page `GenerateRunbook.tsx`. It **reuses
  the same `generateRunbook` command** and the US-052 descriptor screening / preview /
  export plumbing verbatim (the sample constants + the `importCandidate`/`handlePaste`/
  `loadSample`/`confirmWarn` screening fns are replicated, the accepted in-codebase
  pattern — see the US-043 "REPLICATED, hoist if a 3rd consumer appears" note; if a 3rd
  runbook screen lands, hoist these to a shared `useDescriptorScreening` hook).
- **Only the heir-recovery templates** (`heir-singlesig-basic`,
  `heir-singlesig-passphrase`, `heir-multisig-2of3`, `heir-multisig-3of5`,
  `liana-timelock`) — the §9.4/US-093 inheritance subset. The `meetup-workshop` /
  `business-treasury` education templates stay in the standalone generator; this is
  the inheritance flow.
- **SAFETY — the app NEVER captures a signer LOCATION as free-text** (nor a seed /
  passphrase / private key). `RunbookGenerationInput` has no location field and the
  runbook `RunbookData` bag structurally forbids free-text locations (US-032): the
  rendered heir runbook emits **labeled blank lines** ("Signer A is kept at: ____",
  "Trusted helper to call: ____") the owner fills in **by hand after printing** (§9.4 /
  §31.2 step 8). So "signer-location fields" in the AC = the step-2 **guidance panel**
  ("Write WHERE each item is — never WHAT it is" + the never-write-secrets reminder +
  "fill the blanks by hand"), NOT input boxes. The preview (step 3) shows those blanks.
  Do not add location inputs or send location text to `generate_runbook`.
- **Public-safe by default** (the heir hands this to family); `private` (reveals xpubs)
  is gated by the same `ExportPrivacyDialog`. The live preview useEffect is keyed on
  `[step, template, appliedDescriptor, redaction]` and **early-returns unless on the
  review step**, so it only renders the heir plan once the owner reaches step 3.
- **No capability/plugin/i18n-dep change**: reuses `generateRunbook` + `showSaveDialog`
  + `saveExport` + the two dialogs. New copy lives under `pages.heirRunbook.*` in
  `en.json`. `verify:security` stays 23/23. Test pattern mirrors `GenerateRunbook.test.tsx`
  (mock `../tauri/commands`, `vi.hoisted` fns) but **navigates Back/Next** between steps
  (`goToReview` helper); the §31.2 "create a heir 2-of-3 runbook" verification = the test
  that picks `heir-multisig-2of3`, asserts the blank-field preview, and exports public-safe
  PDF (the native GUI walk is still un-runnable here — gtk/webkit `-dev` absent).

## In-app docs viewer (since US-055)
- **`src/pages/Learn.tsx`** (`/learn`) is a two-pane docs viewer: a nav list of pages
  (left) + the rendered Markdown (right). It runs NO Bitcoin logic — it just selects and
  displays bundled text. Page set + order live in **`src/content/docs/index.ts`**
  (`DOC_PAGES: {id, titleKey, content}[]`); each page's body is a `*.md` file imported as
  a raw string via **Vite's `?raw` query** (typed by `vite/client`'s `*?raw` ambient
  module — no custom `.d.ts`). The docs are **bundled, never fetched** (offline, no
  network). To add a page: drop `src/content/docs/<id>.md` + a registry row + a
  `pages.learn.docs.<id>` i18n label. Keep `id` a single lowercase token so it doubles as
  an intra-doc link target.
- **`src/components/MarkdownView.tsx`** is the strict renderer. One shared `markdown-it`
  (dep `markdown-it` ^14 + `@types/markdown-it`; pure-JS, no network, no eval, so CSP/
  `verify:security` stay 23/23) configured `{ html: false, linkify: false, typographer:
  false }` + `md.disable("image", true)`. `html:false` is the §28.4 "strict allowlist, no
  HTML" rule: raw tags in the source are **escaped to inert text**, never DOM (a test
  asserts `<script>`/`<b>` in the source produce no element + survive as text). Rendered
  via `dangerouslySetInnerHTML` — SAFE only because `html:false` + the content is trusted
  bundled docs; do NOT feed user/wallet data through it.
- **Every link is intercepted** (the §22.11 "no external content other than the allowlist"
  rule): the container's `onClick` does `event.target.closest("a")` + `preventDefault()`
  ALWAYS (the webview never navigates), then routes — `http(s)://` → `openExternalLink(href)`
  (the Rust allowlist vets it, off-list = E-LINK-001 swallowed); a relative/bare id
  (`glossary`, `./descriptors.md`) → `onNavigate(id)` for in-app page switching; anything
  else ignored. So docs links reach the network ONLY through the allowlisted command.
  markdown content links to allowlisted URLs only (`https://bitcoinlifeboat.org/docs/…`;
  the domain is the config value, not a placeholder).
- `.markdown-body` typographic CSS lives in `src/styles.css` under `@layer components`
  (markdown-it emits class-less HTML) — colors via `@apply` Tailwind tokens (brand/slate),
  light/dark parity through explicit `.dark .markdown-body …` selectors (avoid `dark:`
  inside `@apply`). Anti-overclaim: docs prose must avoid the §16.8 banned phrases
  ("wallet is safe", "bitcoin is secure", "recovery is guaranteed", "you can recover").
  Test pattern mirrors the others (mock `../tauri/commands` → `openExternalLink`); the
  jsdom "raw HTML is escaped" test is the runnable substitute for the AC's browser walk
  (native GUI still un-runnable — gtk/webkit `-dev` absent).

## Accessibility — WCAG 2.2 AA (since US-056)
- **axe-core runs in the vitest suite** (`src/a11y.test.tsx` + the `expectNoAxeViolations`
  helper in `src/test/axe.ts`; dep `axe-core`, pure-JS, no network → `verify:security`
  stays 23/23). It is the **runnable substitute** for the §27 / NFR-A11Y-4 "axe-core runs
  in E2E" gate while the native webview + Playwright E2E can't run here (US-057 adds the
  real-browser run; the SAME WCAG rule set runs in both). The helper scopes to the WCAG
  tags (`wcag2a/2aa/21a/21aa/22aa`) so axe **best-practice** rules (`region`,
  `landmark-one-main`, `page-has-heading-one`) don't fire. **`color-contrast` is disabled
  in jsdom** (no layout/canvas to measure pixels) — contrast is instead held by the
  WCAG-AA-verified `tailwind.config.js` color tokens and re-checked in the real-browser E2E.
- **Render every screen inside `<AppLayout>`** (via `MemoryRouter` routes, exactly as
  `App.tsx` mounts them) so the WCAG-tagged **page-level** rules pass: `bypass` (needs the
  skip link / landmark), and the nav+main landmarks. `src/test/setup.ts` sets
  `document.documentElement.lang="en"` + `document.title` (jsdom starts blank) so
  `html-has-lang` / `document-title` reflect `index.html`. Onboarding renders standalone but
  has its own `<section aria-label>` landmark + `<h1>`, so it passes too. **Sanity-check the
  axe harness has teeth** (a throwaway `<input>`-with-no-label render must FAIL the helper)
  before trusting a green sweep.
- **Skip link + main landmark** live in `AppLayout.tsx`: the first focusable element is
  `<a href="#main-content" className="sr-only focus:not-sr-only …">` (Tailwind `sr-only` +
  `focus:not-sr-only` = hidden until keyboard-focused), and `<main id="main-content"
  tabIndex={-1}>` is its target. Copy is the `a11y.skipToContent` i18n key.
- **Large-text mode (§15.5 item 7)** is a **persisted Public pref** `textScale`
  (`"normal"|"large"|"larger"`). `theme.ts applyTextScale()` sets the root (`<html>`)
  `font-size` to `100%/150%/200%`, so all **rem-based** Tailwind sizing scales together —
  apply it from `main.tsx` at startup, an `AppLayout` effect on change, and the Settings
  radios. It rides the **same settings-file channel** as theme: the Rust
  `desktop_commands::Settings` gained a `text_scale` field (serde enum `TextScaleSetting`).
- **Adding a Public pref = wire it in BOTH places.** Rust `Settings` fields are all
  `#[serde(default)]`, so a new field is **backward/forward compatible** (a pre-existing
  v1 file with no `text_scale` loads at the default — no `SETTINGS_SCHEMA_VERSION` bump,
  `load_settings` is field-tolerant). But you MUST add the field to the Rust struct +
  `Default` **and** the TS `Settings` interface + `prefs.ts` (`applySettings`/`toSettings`)
  + the `clearAllData` reset literal in `Settings.tsx`, or `saveSettings` drops it on write.
  The desktop-commands tests pin the exact JSON key set (`settings_file_uses_snake_case_…`)
  and a round-trip literal — update them in lockstep. `desktop-commands` is a **core 1.78
  crate**, so this Rust change is fully verifiable here (`cargo test -p desktop-commands`).
- **Global a11y CSS in `styles.css`**: a base-layer `:focus-visible` ring (`@apply outline
  outline-2 outline-offset-2 outline-brand` — token, never a hex) gives every keyboard-
  focused control a visible indicator (§15.5 item 4); a `@media (prefers-reduced-motion:
  reduce)` block neutralizes animations/transitions/scroll (§15.5 item 8 / NFR-A11Y-7).
- **Status is conveyed text + icon + color already** (`StatusBadge`, US-047) — keep that
  triple; never add color-only status. Icons stay `aria-hidden` (text carries meaning).

## Playwright E2E + no-network proof (since US-057)
- **Run browser E2E from `apps/desktop`** with `npm run e2e`. The suite lives under
  `e2e/` and uses `playwright.config.ts` to start the Vite dev server on
  `127.0.0.1:1420` and drive system Chrome headlessly. `tsconfig.json` includes
  `playwright.config.ts` + `e2e`, so `npm run typecheck` covers the E2E harness too.
- **The browser test is a thin UI test over a mocked Tauri IPC boundary.**
  `e2e/support/tauri.ts` installs `window.__TAURI_INTERNALS__.invoke` before page load and
  returns fixed, typed responses for `load_settings`, `detect_sensitive_input`,
  `audit_descriptor`, `generate_report`, `generate_runbook`, `plugin:dialog|save`, and
  `save_export`. Do not put Bitcoin parsing/scoring/secret-detection logic in the mock; it
  is only a browser substitute for the Rust commands, using inert fixture-shaped data.
- **E2E coverage currently walks the two §25.1 flows:** full Readiness Check to a
  public-safe JSON export, and heir-runbook generation to a public-safe PDF export. Both
  call `expectNoAxeViolations(page)` from `@axe-core/playwright` with the same WCAG tag
  set as the vitest helper, but in real Chromium so `color-contrast` stays enabled.
- **No-network proof:** `npm run e2e:no-network` runs the same Playwright suite inside a
  Linux network namespace. It tries `unshare -n` first, then falls back to
  `bubblewrap --unshare-net` (the working path in this sandbox). The child process reads
  `/proc/net/dev` and fails unless only `lo` is exposed; the Playwright route guard also
  fails any browser request outside loopback/data/blob URLs. This proves the app's browser
  flow has no hidden TCP/UDP egress while still allowing the local Vite harness.
- **Generated Playwright artifacts are ignored** (`apps/desktop/test-results/`,
  `apps/desktop/playwright-report/`). Remove them before checking status if you need a
  clean tree; they are not part of the implementation.
