# PRD: Bitcoin Lifeboat — v2.0

## Open-source Bitcoin recovery rehearsal and inheritance drill toolkit

**Version:** 2.0 (production-ready, all v1 open questions resolved)
**Product type:** Open-source desktop application + CLI + documentation site
**Primary platform:** Desktop — macOS, Windows, Linux
**Future platform:** Mobile companion (deferred until desktop v1.0 ships)
**License:** **MIT** (with DCO — Developer Certificate of Origin — for contributions; no CLA)
**Core stack (pinned):**

- Tauri **2.11.x**
- Rust **1.78+** (workspace MSRV)
- React **18.x** + TypeScript **5.x** + Tailwind CSS **3.x**
- `rust-bitcoin` **0.32.5**
- `rust-miniscript` **13.0.0**
- `zeroize` **1.8.x** + `secrecy` **0.10.x**
- HWI **3.2.x** (via subprocess sidecar, starting v0.4 — not MVP)

**Project mission:** Help every Bitcoiner prove they can recover before they need to recover.

**v2 status:** Every open question in `questions_v1.txt` has been answered. This document is the canonical implementation specification.

---

# 0. How to Read This Document

This PRD is the single source of truth for the Bitcoin Lifeboat implementation. A coding LLM (or human team) should be able to build the MVP from this document without further architectural decisions.

Sections marked **NORMATIVE** must be followed exactly. Sections marked **INFORMATIVE** explain the reasoning behind decisions. Sections marked **OPTIONAL** describe accepted but non-mandatory choices.

Appendix A maps every question in `questions_v1.txt` to the section that answers it.

---

# 1. Executive Summary

## 1.1 Product Name

**Bitcoin Lifeboat** (final; no rename).

## 1.2 Tagline

**Practice losing your bitcoin before it happens.**

## 1.3 Core Promise

Bitcoin Lifeboat is a free, open-source, local-first desktop app and CLI that helps Bitcoin users test whether their self-custody recovery plan actually works — without trusting a company, uploading secrets, or risking real funds.

## 1.4 One-Sentence Description

Bitcoin Lifeboat is an open-source recovery rehearsal engine for Bitcoin self-custody that guides users through safe disaster-recovery drills using descriptors, PSBTs, Signet/regtest, hardware signers (post-MVP), printed runbooks, and inheritance checklists.

## 1.5 Strategic Positioning

Bitcoin Lifeboat is:

> A local-first diagnostic, rehearsal, and education tool for Bitcoin recovery readiness.

It is **not** a wallet, custody provider, seed phrase manager, inheritance legal service, or recovery company.

## 1.6 Non-Negotiable Public Promise

Bitcoin Lifeboat makes **four** non-negotiable promises that must appear in onboarding, README, website, and SECURITY.md:

1. **We never ask for your real seed phrase.** The app has no field for entering a real BIP39/SLIP-39 mnemonic in normal use.
2. **We never connect to the internet without your action.** No telemetry, no auto-update, no remote calls by default.
3. **We never persist your wallet metadata.** Imports stay in memory; you choose where to export.
4. **We never claim your funds are safe.** Reports are diagnostic aids, not guarantees of recovery.

These four promises define the trust model and gate every implementation decision.

---

# 2. Key Decisions (Question Resolutions)

This section answers the top-level decisions from `questions_v1.txt §30 ("Can't Ship Without")`. Every other answer follows from these.

| # | Decision Point | Answer |
|---|----------------|--------|
| D1 | Exact MVP | **Descriptor audit + readiness report + runbook generator + CLI.** No Signet/PSBT/HWI/Heir-drill in MVP. |
| D2 | Seed/private-key entry | **Completely banned in MVP and v1.0.** Detector blocks paste; advanced mode does NOT unlock seed entry. |
| D3 | Descriptors/xpubs treated as sensitive | **Yes.** Both classified as `Confidential` in privacy taxonomy (§13.4). Reports redact xpubs by default. |
| D4 | Default storage | **None.** No project files, no recent-file history, no logs by default in MVP. Opt-in only. |
| D5 | Default network behavior | **No network calls.** Including no update checks. Online actions require user-initiated click. |
| D6 | Descriptor types in v0.1 | `pkh`, `wpkh`, `sh(wpkh)`, `wsh`, `multi`, `sortedmulti`, `wsh(sortedmulti)`, `sh(wsh(sortedmulti))`. Taproot **detected but flagged "preview support"** in v0.1; full Taproot in v0.2. |
| D7 | Missing change descriptor | **Warning, not critical.** Reduces score by 15; does not force "Not Ready". |
| D8 | Known-address comparison required for "Ready" | **Yes.** Without a successful known-address match, max status is "Mostly Ready". |
| D9 | Numeric scoring | **Included (0–100) but always paired with qualitative status.** Status is the headline; score is the detail. |
| D10 | Officially supported wallets in v0.1 | Bitcoin Core 29.x, Sparrow 2.5+, Specter 2.1+, Liana 13+, Nunchuk 1.9+, Coldcard (current firmware), Passport Core, Jade. Tier 2 (manual): Electrum, BlueWallet, SeedSigner, Trezor Suite. Tier 3 (unsupported): Ledger Live (no descriptor export). |
| D11 | OS platforms at first release | **macOS (universal), Windows (x86_64), Linux (x86_64 AppImage + .deb).** ARM64 Linux best-effort. |
| D12 | CLI in MVP | **Yes, first-class.** Same Rust core; CLI ships independently of desktop. |
| D13 | Release signing standard | **minisign (user-facing) + Sigstore cosign keyless (auditor transparency).** macOS notarization + Windows OV code signing. NO Tauri auto-updater. |
| D14 | Mandatory disclaimer language | See §15.6 — three exact strings reproduced verbatim in every report and runbook. |
| D15 | "This is not a wallet" wording | See §15.7 — appears in onboarding, every report header, and CLI `--help`. |
| D16 | Sensitive-input rejection | Format-specific detectors with checksum validation (§13.5). Detect-then-refuse: detected secrets are never written to disk, never echoed, never logged. |
| D17 | Runbook share-safe mode | Two modes: `public-safe` (redacted xpubs/addresses, default) and `private` (full content, requires explicit toggle). |
| D18 | Heir Mode in MVP | **Static template only (printable PDF/Markdown).** Full interactive drill deferred to v0.6. |
| D19 | Signet in MVP | **Not in MVP.** Signet rehearsal engine = v0.2. |
| D20 | Target first user | **Multisig / serious self-custody user.** Beginner UX is welcomed but multisig descriptor audit is the MVP's center of gravity. |

The rest of this document operationalizes these 20 decisions.

---

# 3. Background and Technical Rationale

## 3.1 Standards Referenced (NORMATIVE)

| Standard | Purpose | Lifeboat Use |
|----------|---------|--------------|
| **BIP32** | HD derivation | Address derivation, path validation |
| **BIP39** | Mnemonic seed | Detection only; never accepted as input |
| **BIP44/49/84/86** | Account paths | Derivation path inference |
| **BIP125** | RBF | Future PSBT drill (v0.2) |
| **BIP129** | BSMS multisig setup | Import format (Nunchuk, Coldcard, etc.) |
| **BIP141** | Segregated Witness | Script type analysis |
| **BIP174** | PSBT v0 | v0.2 drill mode |
| **BIP325** | Signet | v0.2 rehearsal network |
| **BIP329** | Wallet labels | Import support (Sparrow, Liana, BitBox) |
| **BIP370** | PSBT v2 | v0.2 import; v0.3 export when Taproot |
| **BIP380** | Output descriptors + checksum | Core descriptor format |
| **BIP382** | wsh expression | Multisig parsing |
| **BIP383** | multi/sortedmulti expressions | Multisig parsing |
| **BIP386** | tr() Taproot descriptors | v0.2 full support |
| **BIP388** | Wallet policies (hardware) | Awareness only; convert to descriptor on import |
| **BIP389** | Multipath descriptors `<0;1>` | Required parsing (Sparrow, Liana use this) |
| **BIP-93** | codex32 | Detection only |
| **SLIP-39** | Shamir backup | Detection only |
| **SLIP-132** | xpub version bytes (ypub/zpub) | Normalize on import |

## 3.2 Library Choices (NORMATIVE)

**Why rust-bitcoin + rust-miniscript directly, not BDK:**

The MVP is descriptor analysis and address derivation — not wallet state, UTXO tracking, or chain sync. BDK's strengths (chain clients, persistence layer, transaction building) are unused weight. Using `rust-bitcoin 0.32.5` + `rust-miniscript 13.0.0` directly yields:

- Smaller binary (~3–5 MB savings)
- Fewer transitive dependencies (no `bdk_chain`, `bdk_esplora`, `rusqlite`)
- Direct API stability (BDK is on 3.0; rust-bitcoin/rust-miniscript are battle-tested at 0.32 / 13.0)
- No accidental persistence (BDK assumes a wallet DB)

For v0.2 (Signet drill engine) we revisit: BDK's chain source clients become useful when we need to fund and broadcast Signet UTXOs. At that point we add `bdk_wallet` as a separate crate dependency in `crates/signet-lab/` only.

## 3.3 Stack Decision Tree (INFORMATIVE)

Tauri v2 was chosen over Electron, Wails, and pure-Rust GUI (Slint/egui) for these reasons:

| Option | Why Not |
|--------|---------|
| Electron | Bundles Chromium (~100 MB), shell/fs by default, security model is opt-out |
| Wails | Forces Go-based Bitcoin libraries (`btcsuite`) which lag rust-bitcoin/miniscript |
| Slint | Excellent security posture (no webview), but slower UI iteration; revisit for v2.0 if team direction shifts |
| egui | Same as Slint; less mature accessibility |
| **Tauri v2** | Native Rust backend, OS webview (no bundled Chromium), capability-based security, ~3–10 MB binary, mature Bitcoin Rust ecosystem |

We acknowledge the Tauri webview attack surface (WebKitGTK on Linux is the weakest link). Mitigations in §13.

---

# 4. Product Thesis

## 4.1 Core Insight

Bitcoin self-custody advice usually says **"back up your seed phrase."** Bitcoin Lifeboat says **"prove your backup works."** That is the category shift.

## 4.2 Cultural Narrative

The Bitcoin community has **"not your keys, not your coins."** Bitcoin Lifeboat adds **"not tested, not recoverable."**

## 4.3 Behavioral Norm

The project normalizes an annual ritual: **every Bitcoiner should run one recovery drill per year.** This grounds the future **Bitcoin Recovery Day** community initiative (post-v1.0).

---

# 5. Goals

## 5.1 Product Goals

1. Make Bitcoin recovery rehearsal safe, understandable, and repeatable.
2. Help users discover missing recovery materials before real disaster.
3. Teach users that seed words alone may not be enough for multisig or advanced wallets.
4. Help heirs and family members rehearse recovery without exposing real funds.
5. Give educators and meetups a polished tool for hands-on self-custody workshops.
6. Provide developers and wallet projects with a CLI-based recovery test harness.
7. Strengthen Bitcoin adoption by reducing fear of self-custody loss.

## 5.2 Technical Goals

1. Build a local-first desktop app for macOS, Windows, Linux.
2. Keep all critical Bitcoin logic in Rust.
3. Never handle real private keys in any normal user flow.
4. Use descriptors as the primary wallet metadata format.
5. Use PSBTs for transaction-signing drills (post-MVP).
6. Use Signet/regtest for practice funds and rehearsal (post-MVP).
7. Integrate with hardware wallets via file-based PSBT (default) and HWI sidecar (optional, v0.4).
8. Generate human-readable readiness reports.
9. Generate printable recovery runbooks.
10. Provide a CLI with equivalent core functionality.
11. Ship deterministic, byte-for-byte stable JSON reports for known fixtures.

## 5.3 Community Goals

1. Fully open source under MIT.
2. Build trust with conservative security design.
3. Useful even without commercial partners.
4. No monetization, tokens, cloud accounts, telemetry, vendor lock-in.
5. Encourage wallet maintainers, educators, and meetup organizers to adopt it.

---

# 6. Non-Goals

Bitcoin Lifeboat must **not** become:

1. A Bitcoin wallet for storing funds.
2. A seed phrase vault.
3. A cloud backup service.
4. A paid recovery service.
5. A legal inheritance planning service.
6. A multisig coordinator (it audits coordinators' output; it is not one).
7. A social recovery service.
8. A watchtower.
9. A blockchain explorer.
10. A commercial SaaS.
11. A tool that asks normal users to type real seed words.
12. A tool that encourages beginners to practice with mainnet bitcoin.
13. A tool that requires accounts.
14. A tool that uploads wallet metadata to a server by default.
15. A tool that tracks users.
16. A Lightning Network recovery tool (Bitcoin L1 only).
17. A general-purpose Bitcoin app — the product is specifically and only recovery rehearsal.

---

# 7. Target Users

The MVP is **prioritized for the Multisig / Serious Self-Custody user (D20)**. Other personas are supported but secondary.

## 7.1 Primary Persona — Multisig / Serious Self-Custody User

- Owns Bitcoin in hardware wallet + Sparrow / Bitcoin Core / Specter / Liana / Nunchuk.
- Uses singlesig with passphrase OR multisig (2-of-3, 3-of-5).
- Knows what a descriptor is (or will, after onboarding).
- Pain: not sure recovery would work end-to-end.
- Primary value: **"Tell me whether my backup is actually complete."**

## 7.2 Secondary Persona — Beginner Self-Custody User

- Single hardware wallet, no passphrase, no multisig.
- May not know what a descriptor is.
- Pain: hopes recovery would work but has never tested.
- Primary value: **"Show me what to back up that I'm not backing up."**

The MVP UX is layered: Beginner cards on the home screen; advanced multisig audit one click deeper.

## 7.3 Secondary Persona — Spouse / Heir / Executor

- Non-technical.
- May need to help recover funds after death, incapacity, emergency.
- Pain: instructions are intimidating; fears making fatal mistakes.
- MVP value: **printable runbook** they can read on paper.
- Post-v0.6 value: interactive Heir Drill.

## 7.4 Secondary Persona — Bitcoin Educator / Meetup Organizer

- Runs workshops or meetups.
- Pain: teaching recovery is hard because real funds are dangerous.
- MVP value: meetup workshop runbook template + CLI for live demos.

## 7.5 Secondary Persona — Wallet Developer

- Builds Bitcoin wallet software.
- Pain: needs test harness for descriptor, PSBT, recovery flows.
- MVP value: **CLI + golden JSON fixtures + stable schema versions** they can wire into CI.

---

# 8. Core Product Concept

Bitcoin Lifeboat has five product modes. **Only modes 1 and 5 ship in MVP.** Modes 2–4 are post-MVP.

| # | Mode | MVP? | Ships in |
|---|------|------|----------|
| 1 | **Readiness Check Mode** | YES | v0.1 |
| 2 | **Practice Mode** | NO | v0.2 |
| 3 | **Disaster Drill Mode** | NO | v0.3 |
| 4 | **Heir Mode (interactive)** | NO | v0.6 |
| 5 | **Runbook Generator** | YES | v0.1 |

The MVP is therefore: **a descriptor-audit + report + runbook tool, plus CLI.**

---

# 9. Product Modes (Detailed)

## 9.1 Readiness Check Mode (MVP)

### Purpose
Audit whether a real wallet's recovery metadata appears complete **without requiring private keys**.

### Allowed Inputs (NORMATIVE)

The Readiness Check accepts only the following input types. Anything else is rejected by the sensitive-input detector (§13.5).

1. Output descriptor (BIP380), with or without `#checksum`.
2. xpubs (`xpub...`, `ypub...`, `zpub...`, `tpub...`, `upub...`, `vpub...`).
3. Master fingerprints (8 hex chars).
4. Derivation paths (`m/48h/0h/0h/2h` style).
5. Watch-only wallet export files (Sparrow JSON, Specter JSON, Coldcard Generic JSON, Liana `.bed` (encrypted), Nunchuk BSMS, Jade JSON, Bitcoin Core `listdescriptors` output).
6. Known receive address for comparison.
7. Quorum metadata user enters in form fields (threshold, key count).
8. Wallet type label (e.g., "Sparrow", "Liana").
9. User-typed recovery notes (free-form prose).

### Rejected Inputs

- Any BIP39 mnemonic (12/15/18/21/24 words from any BIP39 language).
- WIF private keys.
- xprv/yprv/zprv/tprv/uprv/vprv extended private keys.
- Raw hex private keys (gated by context heuristics — see §13.5.4).
- SLIP-39 shares.
- codex32 secrets.
- Free-form passphrases entered into any field (treated as secrets if pasted into a normal text field; only acceptable in a labeled `<input type="password">` for the optional "I have a passphrase, document its existence (not value)" toggle).

### Analysis Checks (NORMATIVE)

The Readiness Check runs these checks in order. Each check produces one of: `pass`, `warn`, `fail`, `na` (not applicable), `unknown` (could not determine).

```
A. Descriptor parse
   A1. Descriptor parses as BIP380
   A2. Descriptor checksum present
   A3. Descriptor checksum valid (if present)
   A4. Descriptor canonical form matches user input (normalization round-trip)

B. Script type
   B1. Script type identified (pkh / wpkh / sh(wpkh) / wsh / tr / etc.)
   B2. Script type matches user-declared wallet type (if any)

C. Key origin
   C1. Master fingerprint present for every key
   C2. Derivation path present for every key
   C3. Hardened markers consistent (h vs ')
   C4. Account-level derivation looks standard (BIP44/49/84/86/48)

D. Singlesig vs Multisig
   D1. Wallet type detected (singlesig | multisig | timelock | unknown)
   D2. For multisig: threshold and key count extracted
   D3. For multisig: sortedmulti vs multi flagged
   D4. For multisig: no duplicate xpubs
   D5. For multisig: threshold sanity (1 <= M <= N <= 15)

E. Receive + change
   E1. Receive descriptor present
   E2. Change descriptor present (via BIP389 multipath OR explicit pair)
   E3. Receive and change derive same script type
   E4. Receive and change differ only in BIP44 chain index

F. Network
   F1. Network determinable from descriptor (mainnet | testnet | signet | regtest)
   F2. If undeterminable, user confirmed network

G. Address derivation
   G1. First N receive addresses derive without error (N=10 default)
   G2. First N change addresses derive without error (if change descriptor present)
   G3. User-provided known address matches an address in the derived range

H. Recovery completeness (user-answered checklist)
   H1. User has at least 2 physical copies of recovery materials (yes/no/unsure)
   H2. User can name where each signer is located (yes/no/unsure) [multisig only]
   H3. User has tested at least M of N signers in the last 12 months (yes/no/unsure) [multisig only]
   H4. User has documented whether a passphrase exists (yes/no)
   H5. User has documented (locally) which wallet software is needed for recovery (yes/no)
   H6. User has documented gap limit setting (yes/no)
   H7. User has documented wallet birth height OR creation date (yes/no)
   H8. User has heir/executor instructions written down (yes/no)
   H9. User has run a recovery drill in the last 12 months (yes/no)
```

### Output

A `ReadinessReport` JSON object conforming to the schema in §19. Rendered formats: in-app summary screen, Markdown, JSON, PDF runbook.

## 9.2 Practice Mode (v0.2)

### Purpose
Teach users how Bitcoin recovery works using safe, disposable wallets and non-mainnet funds.

### Default Network
Regtest (offline, deterministic). Signet available for users who explicitly opt in.

### Practice-Mode-Only Seed Entry

Practice Mode is **the only mode in the application** where a BIP39 seed phrase field exists. The field is:
- Visually marked with a yellow "PRACTICE ONLY" border.
- Pre-filled with a **canonical practice mnemonic** (deterministic, well-known test vectors: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`).
- Detector still runs: if the user pastes a seed that is NOT one of the documented test vectors AND has a valid checksum, the app shows a hard-block dialog: *"This looks like a real mnemonic, not a practice one. Practice Mode only accepts the documented test seeds. See practice-seeds.md."*

This pattern — pre-filled with a known test seed + detector for "this is real" — is the answer to §4 Q2-3: how to distinguish real from practice.

### MVP Status
**Not in MVP.** All wallet generation, signing, and broadcast for practice happens in v0.2.

## 9.3 Disaster Drill Mode (v0.3)

### Purpose
Guide the user through a specific failure scenario and test whether the recovery plan survives.

### Supported Scenarios (v0.3)

```
DS-1  "I lost my hardware wallet"
DS-2  "My laptop died"
DS-3  "My wallet app disappeared"
DS-4  "I have my seed but not my wallet file"
DS-5  "I have my descriptor but not all signers"
DS-6  "One multisig signer is unavailable"
DS-7  "My spouse needs to recover"
DS-8  "I need to verify my hardware wallet can still sign"
DS-9  "I want to test a PSBT signing workflow"
DS-10 "I want to simulate restoring on a clean machine"
```

DS-1, DS-2, DS-3, DS-4, DS-5, DS-6 are **questionnaire + descriptor-completeness audits** (no signing required).

DS-7, DS-8, DS-9, DS-10 require **Signet/regtest signing** — v0.3 ships when those work end-to-end.

### Drill Pass/Fail Definition

A drill **passes** when:
1. The descriptor parses, validates, and derives the expected addresses.
2. For signing scenarios: a PSBT created by Lifeboat is signed by the required quorum of devices/keys and finalized to a valid transaction.
3. The user confirms the destination address visually on each signing device.

A drill **fails** when any of the above does not complete OR the user signals "I had to stop."

### Drill History (Local Only)

Drill results are stored locally only when the user clicks "Save this drill result." Storage location: `~/.local/share/lifeboat/drills/*.json` (XDG conventions; equivalent on macOS/Windows). Each drill record is signed with a per-install random key so users can audit their drill history without trusting external timestamps.

Drill history is **not** synced anywhere.

## 9.4 Heir Mode (v0.6)

### MVP Heir Support

MVP ships **static, printable heir runbook templates** (PDF + Markdown):
- `heir-singlesig-basic.md` — for owners of a single hardware wallet with no passphrase.
- `heir-singlesig-passphrase.md` — for owners with a BIP39 passphrase.
- `heir-multisig-2of3.md` — for 2-of-3 multisig owners.
- `heir-multisig-3of5.md` — for 3-of-5 multisig owners.
- `heir-liana-timelock.md` — for Liana inheritance-style timelock setups.

Each template has blank fields the user fills in by hand (signer locations, wallet software names, contact info), with explicit instructions: **"Do not write seed phrases, private keys, or passphrases into this document. Write where the heir can find those, not what they are."**

### v0.6 Heir Drill (Interactive)

In v0.6, the owner generates a heir drill packet (regtest/Signet test wallet + instructions) that the heir runs on their own computer. The heir's app reports drill outcome back to the owner via printable receipt (no network).

### Heir UX Language

Heir-facing copy is written at a US **8th-grade reading level** (Flesch-Kincaid grade ≤ 8.0). Plain English. No words like "xpub", "descriptor", "PSBT" without inline expansion. Glossary inline.

Examples:

> Your goal is to prove you can follow the recovery instructions using fake funds. You are not touching real bitcoin. You should never type real recovery words into a website.

> If anyone calls or messages claiming to be from Bitcoin Lifeboat, hang up. We will never contact you. We do not know who you are.

## 9.5 Runbook Generator (MVP)

### Purpose

Generate printable, redacted, human-readable recovery plans.

### Output Formats (MVP)

1. **PDF** — generated via `typst` (preferred) or `printpdf` Rust crate (fallback). Typst gives better typography and is easier to template. See §17.6 for rationale.
2. **Markdown** — direct file write.
3. **Plain text** — direct file write.
4. **JSON** (developer-oriented machine-readable form) — for wallet developers / CI integration.

PDF generation MUST complete in under 3 seconds for the largest MVP template (multisig with 5 cosigners, full annotations).

### Runbook Templates (MVP)

```
runbook-singlesig-basic
runbook-singlesig-passphrase
runbook-multisig-2of3
runbook-multisig-3of5
runbook-liana-timelock          (v0.5 fully; v0.1 stub only)
runbook-heir-singlesig-basic
runbook-heir-singlesig-passphrase
runbook-heir-multisig-2of3
runbook-heir-multisig-3of5
runbook-meetup-workshop          (15-attendee workshop kit)
runbook-business-treasury        (corporate self-custody)
```

### Required Sections in Every Runbook

1. Safety warning ("Never enter seed words into a website").
2. "Do not panic" section.
3. "Stop and call a trusted helper" instructions.
4. Required materials checklist.
5. Wallet type summary.
6. Descriptor backup reminder.
7. Signer/device checklist.
8. Passphrase existence reminder ("a passphrase exists" — but never the passphrase itself).
9. Emergency contacts (blank fields the user fills in).
10. Wallet software dependency list.
11. Verification steps.
12. Stop conditions.
13. Date of last successful drill.
14. Next recommended drill date.
15. Lifeboat version + report hash (for reproducibility).
16. Mandatory disclaimer (§15.6).

### Forbidden Content in Auto-Generated Runbooks

1. Real seed words.
2. Real passphrases.
3. Private keys (in any form).
4. Sensitive location details — runbook generator does not accept location free-text and will not write it to the document. User fills in by hand on paper.
5. Cloud storage instructions as the default.

### Share-Safe vs Private Modes (NORMATIVE)

Every runbook exports in two modes:

| Mode | xpubs | derived addresses | descriptor checksum | descriptor full text |
|------|-------|-------------------|---------------------|----------------------|
| `public-safe` (default) | redacted to `xpub6...XXXX` (first 6, last 4) | first 1 only, fully shown | shown | redacted with `[descriptor redacted, see private export]` |
| `private` | full | first 5 shown | shown | shown |

The mode is set per export. The `private` mode requires an explicit toggle and a single-button confirmation dialog: **"This export contains your wallet's public-key material. xpubs reveal your full transaction history. Only store this where you store your seed backups."**

---

# 10. MVP Scope (Authoritative)

## 10.1 MVP Name

**Bitcoin Lifeboat v0.1 — Recovery Readiness MVP**

## 10.2 MVP Goal

Ship a polished desktop app and CLI that can audit wallet recovery readiness using public descriptor metadata, generate a clear recovery report, and produce printable runbooks.

## 10.3 MVP MUST Include (Acceptance Gate)

### Desktop App

1. Tauri **2.11.x** shell.
2. React 18 + TypeScript 5 + Tailwind 3 frontend.
3. Rust core (workspace).
4. Local-only operation; no network calls at all in MVP.
5. No account creation.
6. No telemetry.
7. No cloud sync.
8. No seed phrase entry in any flow.
9. Readiness wizard flow (§15.2).
10. Descriptor import — paste, file picker (`.txt`, `.json`, `.bed`, `.psbt`-for-future), drag-and-drop.
11. Descriptor parser (§3.1 BIP380, §3.2 rust-miniscript 13.0.0).
12. Descriptor checksum validation; "compute checksum" helper for descriptors that lack one.
13. Singlesig vs multisig detection.
14. Multisig quorum analysis (threshold, key count, sorted/unsorted, duplicate detection).
15. xpub / fingerprint / derivation-path extraction and display.
16. Address derivation preview (first 10 receive + first 10 change).
17. Known-address comparison.
18. Readiness score (0–100) + qualitative status (Ready / Mostly Ready / Needs Attention / Not Ready / Cannot Determine).
19. Critical / warning / pass report structure.
20. Sensitive-input detector covering BIP39 (10 languages), WIF, xprv/yprv/zprv/tprv/uprv/vprv, raw hex priv key, SLIP-39, codex32.
21. Markdown + JSON + PDF export of report.
22. Markdown + PDF export of runbook (singlesig-basic, singlesig-passphrase, multisig-2of3, multisig-3of5, heir variants of each, meetup-workshop, business-treasury).
23. Public-safe and private export modes.
24. In-app docs for: descriptors, checksums, multisig, xpubs, recovery basics, safety rules.
25. Wallet-export import helpers for: Bitcoin Core (`listdescriptors` JSON), Sparrow `.json`, Specter `.json`, Liana `.bed` (with user-provided decryption inputs), Nunchuk BSMS, Coldcard Generic JSON + descriptor-file + .sig, Passport descriptor, Jade JSON.

### CLI

The CLI ships in MVP and is first-class (D12).

1. `lifeboat audit-descriptor`
2. `lifeboat derive-addresses`
3. `lifeboat compare-address`
4. `lifeboat generate-runbook`
5. `lifeboat report-json`
6. `lifeboat detect-secrets` (utility command; pipe text via stdin; outputs detector findings)
7. `lifeboat parse-export` (parse a wallet export file into normalized descriptor JSON)
8. `lifeboat checksum` (compute or validate a BIP380 descriptor checksum)

### Docs Site

1. Mission ("What Bitcoin Lifeboat is and is not").
2. Download page (signed releases with checksums).
3. GitHub link.
4. Safety model summary.
5. "Never enter your real seed phrase online" prominent warning.
6. Recovery Day explainer.
7. User guide (step-by-step Readiness Check walkthrough).
8. Developer guide (CLI usage, JSON schema, fixture format).
9. Wallet compatibility guide (Tier 1/2/3 with export instructions per wallet).
10. Reproducible build instructions (aspirational, marked "experimental").
11. SECURITY.md (PGP key + responsible disclosure process).
12. Threat model document.

## 10.4 MVP MUST NOT Include

1. Mainnet signing of any kind.
2. Seed phrase input (even in advanced mode).
3. Cloud backup or sync.
4. Mobile app.
5. Legal inheritance workflow.
6. Paid services or tiers.
7. Automatic wallet import via HTTP / API (no integration with any wallet's running daemon).
8. Hardware-wallet device drivers (no USB/HID access; no HWI).
9. Signet faucet integration (no automatic faucet calls).
10. Transaction broadcast on any network.
11. Bitcoin Core RPC integration.
12. Auto-update.
13. Telemetry or crash reporting (panics surface as friendly errors locally; user opts in to copy the diagnostic to a file they then attach manually).
14. Internet access of any kind (offline-by-default; an "About > Check for updates" link opens the user's browser at the GitHub releases page — the app itself does not fetch).

## 10.5 MVP Out-of-Scope That Lands in v0.2

1. Disposable Signet/regtest wallet generation.
2. PSBT creation, import, validate, finalize.
3. Optional Signet broadcast (user-initiated, with visible warning banner).
4. Drill pass/fail records.

## 10.6 MVP Acceptance Sign-Off

The MVP ships when **all 25 items in §10.3 Desktop App + all 8 CLI commands + all 12 docs items + all 20 acceptance criteria in §27** are demonstrably implemented and pass CI.

---

# 11. Post-MVP Roadmap

Concrete version targets. Each version has a single coherent theme.

## 11.1 v0.2 — Signet Drill Engine

Adds:

1. Disposable Signet wallet generation (`bdk_wallet 3.x` added as `crates/signet-lab/` dependency).
2. Regtest mode with bundled `bitcoind` regtest mode (downloaded once at user request; not bundled in installer).
3. Signet receive/send test flows.
4. PSBT v0 (BIP174) creation, import, validate, finalize.
5. PSBT v2 (BIP370) import support; v2 export when Taproot script-path is used.
6. Optional Signet broadcast (Esplora endpoint at `mutinynet.com` or `signet.bitcoin.sprovoost.nl`; user-opt-in; visible "Network call to X" confirmation).
7. Drill pass/fail report records.
8. Faucet user instructions (the app shows the address + "open faucet.mutinynet.com" link in the OS browser; **the app never calls the faucet itself**).

## 11.2 v0.3 — Hardware Wallet File/QR Drill

Adds:

1. File-based PSBT exchange UI (write `.psbt` to user-chosen folder; read signed `.psbt` back).
2. QR PSBT exchange — UR (BCR-2020-005/006) AND BBQr formats. Rust deps: `ur` crate (`dspicher/ur-rs`), `bbqr-rust` (`satoshiportal/bbqr-rust`), `rqrr` for QR decoding, `nokhwa` for camera capture.
3. Supported-device documentation: Coldcard (SD + QR), Passport Core (microSD + QR), SeedSigner (QR), Jade (QR + microSD on Plus), Foundation/Krux (QR).
4. Device compatibility matrix doc.
5. Mainnet PSBT support is still off by default; users must explicitly enable "I want to sign a mainnet PSBT in the file-based flow" and acknowledge the warning each session.

## 11.3 v0.4 — Optional HWI Sidecar (USB Devices)

Adds:

1. HWI 3.2+ bundled via Tauri sidecar (`externalBin`) — Python interpreter via `python-build-standalone`, HWI packed with `PyInstaller --onedir`.
2. USB-only device support: Ledger Nano (Bitcoin app 2.x), Trezor (One/T/Safe), BitBox02, ColdCard via USB Virtual Disk.
3. Device fingerprint verification ("does this device's xpub match my descriptor's expected fingerprint").
4. **No** in-process USB/HID access from Tauri. Subprocess only. Failure domain isolation.
5. Hardware Wallet Drill Mode UI.

## 11.4 v0.5 — Multisig + Liana / Timelock Deep Drill

Adds:

1. 2-of-3 multisig drill templates and survivability simulation.
2. 3-of-5 multisig drill templates.
3. Missing-signer drill ("simulate losing signer 2").
4. Liana descriptor full miniscript visualization (recovery path tree, time-to-recovery).
5. Liana timelock countdown ("based on your descriptor and the current block, your recovery path is active in N blocks").
6. Miniscript policy visual tree using `rust-miniscript`'s `Liftable` trait + a `policy_to_dot` helper writing GraphViz the UI then renders.

## 11.5 v0.6 — Interactive Heir Mode

Adds:

1. Heir drill packet generation (regtest wallet + instructions + step-by-step UI walkthrough on the heir's machine).
2. Plain-English walkthrough with progress checkmarks.
3. Heir confidence checklist.
4. Emergency stop conditions surfaced contextually.
5. Family drill report (printable receipt the heir gives the owner).
6. Mobile companion planning kicks off (mobile starts in v1.1).

## 11.6 v1.0 — Bitcoin Recovery Day Release

Adds:

1. Polished cross-platform installers (signed, notarized).
2. Reproducible builds with publicly verifiable hashes (Bitcoin-Core-style Guix or Tauri-deterministic approach).
3. Public workshop kit (slides, sample descriptors, instructor guide).
4. Meetup organizer guide.
5. Translation framework (Fluent (`fluent-rs`) or `i18next`; languages TBD by translator demand).
6. Full wallet compatibility documentation.
7. Public launch site.
8. Bitcoin Recovery Day materials (date selected by community, e.g., Bitcoin Pizza Day mirror in winter).
9. Security audit (paid engagement with established Bitcoin auditors — likely candidates: Spiral, Anchorage, NCC Group, or a community fund).
10. Reproducible build verification guide.

## 11.7 v1.1+ — Mobile Companion (Phone-Side Heir Drill)

Scope deferred until after v1.0 ship. Mobile is a **companion** to the desktop app, never a replacement. See §22.

---

# 12. Platform Strategy

## 12.1 Desktop First (Pillar)

Desktop is the primary product because recovery workflows require:

1. Hardware-wallet USB connections (future).
2. Local files (descriptor imports, PDF exports).
3. PSBT import/export (future).
4. Printing.
5. Offline operation.
6. Bitcoin Core integration (future).
7. Advanced multisig workflows.

## 12.2 Supported OSes for v0.1

| OS | Architecture | Format | Tier |
|----|--------------|--------|------|
| macOS | Universal (arm64 + x86_64) | `.dmg`, notarized | 1 |
| Windows | x86_64 | `.msi`, OV-signed | 1 |
| Linux | x86_64 | AppImage, `.deb` | 1 |
| Linux | aarch64 | AppImage | Best-effort |
| Linux | x86_64 | Flatpak | v0.2 |
| Linux | x86_64 | Arch AUR (community-maintained) | v0.3 |

CLI binaries ship as standalone for each platform plus `cargo install lifeboat-cli` from crates.io.

## 12.3 Mobile (Deferred, v1.1+)

### Mobile Stack (Tentative)

Tauri 2 mobile (Android + iOS) using the same Rust core. The UI is a stripped-down view: runbook viewer, QR scan, drill checklist. No descriptor editing, no signing, no seed entry.

### Mobile Non-Goals

1. Mainnet coordination.
2. Seed phrase manager.
3. Hardware-wallet pairing (mobile cannot reliably USB-host most signers).
4. Replacement for desktop app.

### Mobile Distribution

- Android: F-Droid (priority) + GitHub APK direct download. Play Store deferred to v1.2.
- iOS: deferred until v1.2 minimum; TestFlight only.
- Fake-app risk: documented in onboarding; recovery operations require the user to verify the app's signature against the website-published hash.

---

# 13. Security Model

## 13.1 Highest-Level Rule (Re-Stated)

**Bitcoin Lifeboat must not ask users to enter real seed phrases in any normal user flow.** Practice Mode (v0.2) is the only place where a BIP39 field exists, and it is pre-filled with a known test mnemonic and protected by a "this looks real" hard-block.

Every entry point — onboarding, every report header, every CLI `--help` — repeats:

```
Bitcoin Lifeboat does not need your real seed phrase.
Never type real recovery words into a website.
Drills use descriptors, hardware wallets, PSBTs, and test wallets.
```

## 13.2 Trust Model (NORMATIVE)

The user trusts Bitcoin Lifeboat with:

1. **Public wallet metadata** (descriptors, xpubs, fingerprints, derivation paths). These are classified `Confidential` (§13.4).
2. **Knowledge of what wallets they use** (Sparrow, Coldcard, etc.).
3. **A receive address they own** for verification.

The user does **not** trust Bitcoin Lifeboat with:

1. Real seed phrases (the app cannot ask for or accept them).
2. Real private keys (the app cannot ask for or accept them).
3. Real passphrases (the app records only "a passphrase exists", never the value).
4. Custody of funds (the app never custodies).
5. Internet contact with their wallet metadata (no network calls in MVP).

The user **does have to trust**:

1. The release artifact they downloaded (mitigated by signed releases, reproducible builds, transparency logs).
2. Their OS and webview being patched.
3. The Bitcoin Rust libraries (`rust-bitcoin`, `rust-miniscript`) for descriptor correctness.

These are documented in the threat model (`docs/threat-model.md`).

## 13.3 Threat Model

Documented threats and Lifeboat's response:

| # | Threat | Response |
|---|--------|----------|
| T1 | Phishing site impersonating Lifeboat | Documented; download page is canonical; SECURITY.md lists official channels |
| T2 | Malicious build / supply chain | minisign signatures + cosign transparency log; reproducible builds aspirational |
| T3 | Clipboard leakage | Never auto-read clipboard; sensitive-input detector runs on all paste; secrets are zeroized before any other action |
| T4 | Accidental seed phrase paste | Detector blocks; UI shows "this looks like a secret" warning + refuses to process |
| T5 | Compromised npm/cargo dependency | `cargo deny`, `cargo audit`, `npm audit`; pinned versions; Dependabot with mandatory two-maintainer review |
| T6 | Malicious update server | **No auto-update.** User pulls releases manually from GitHub |
| T7 | Hardware wallet spoofing | Beyond MVP scope; v0.4+: device fingerprint verification |
| T8 | User confuses testnet vs mainnet | Visual banner everywhere: `MAINNET` red, `SIGNET` yellow, `REGTEST` gray; lock testnet broadcast behind explicit toggle |
| T9 | Heir accidentally exposes real secrets in drill | Heir drill uses regtest only; UI repeatedly reminds "no real funds here" |
| T10 | False sense of security from incomplete drill | Reports always state which scenarios were NOT tested; "passing" a Readiness Check is explicitly not "your wallet is safe" |
| T11 | Webview RCE via XSS | Strict CSP (§13.7); IPC isolation pattern; capability-scoped fs |
| T12 | Memory disclosure (paged-out secrets) | `zeroize` on all secret types; webview limit acknowledged in docs |
| T13 | Coerced disclosure ("$5 wrench attack") | Out of scope; documented as a category Lifeboat cannot mitigate |
| T14 | Forensic recovery of files on disk | Default = no persistence; opt-in only; users with extreme threats are told to use full-disk encryption |
| T15 | Updater key compromise | No updater. Eliminates the threat category |
| T16 | Code-signing cert theft | OV cert key on HSM in CI signing service (Azure Trusted Signing / SSL.com eSigner); revocation procedure in SECURITY.md |
| T17 | Maintainer account takeover | Two-maintainer review for security-sensitive PRs; signed Git commits; protected branches |
| T18 | Tauri webview CVE (WebKitGTK etc.) | Pin Tauri 2.11+; release advisories on stale builds; users warned to run patched OS |
| T19 | Malicious wallet export file | Parse in sandboxed Rust; never `eval`/execute; reject files over 10 MB; JSON parsed with `serde_json` strict mode |
| T20 | Side-channel from logs | Logs disabled by default; when enabled, scrubbed of any field marked `Confidential` |

## 13.4 Privacy Classification of Data (NORMATIVE)

Every field the app handles is classified at one of three levels:

| Level | Examples | Default Treatment |
|-------|----------|-------------------|
| `Public` | Wallet type name (e.g., "Sparrow"), script type label, drill date | Logged at INFO; shown in reports |
| `Confidential` | Descriptors, xpubs, fingerprints, derived addresses, wallet labels, signer location notes | Never logged; redacted in public-safe exports; held in `SecretString` while in transit |
| `Secret` | BIP39 mnemonic, WIF, xprv, passphrase, raw priv hex, SLIP-39 share, codex32 secret | **REJECTED** at the detector; never processed, never echoed, never written to disk |

Every Rust function that accepts a `Confidential` or `Secret` value takes a `SecretString` or `Confidential<T>` newtype that:
- Implements `Zeroize` and `ZeroizeOnDrop`.
- Implements `Debug` as `"<redacted>"`.
- Cannot be `serde::Serialize`d to non-redacted output without an explicit `.expose_secret()`.

## 13.5 Sensitive-Input Detector (NORMATIVE)

The detector is a Rust crate (`crates/sensitive-input-detector/`) called from both desktop and CLI. It accepts a `&str` and returns:

```rust
pub enum DetectedSecret {
    Bip39 { language: Bip39Language, word_count: u8, checksum_valid: bool },
    Wif { network: Network, compressed: bool },
    Xprv { kind: XprvKind, network: Network }, // xprv/yprv/zprv/tprv/uprv/vprv
    RawHexPrivKey, // 64-hex-char with context heuristic match
    Slip39 { share_count_in_input: u8 },
    Codex32 { threshold: u8 },
    None,
}

pub struct DetectorReport {
    pub findings: Vec<(DetectedSecret, ByteRange)>,
    pub action: DetectorAction, // Block | Warn | Allow
}
```

### 13.5.1 BIP39 Detection

- Bundle all 10 BIP39 wordlists from `bitcoin/bips/bip-0039/`.
- Vendor wordlists; pin each file's SHA256 in `build.rs`.
- Tokenize on whitespace + comma + newline + ideographic space (U+3000).
- Normalize NFKD, lowercase.
- Slide a window of {12, 15, 18, 21, 24} tokens.
- For each window, attempt language detection via 4-char prefix matching.
- If all tokens are in the wordlist for one language, attempt checksum validation via `bip39` crate `Mnemonic::from_phrase`.
- **Action matrix:**
  - Checksum valid → `Block`. UI shows hard-stop dialog.
  - Checksum invalid, ≥12 tokens all in wordlist → `Warn`. UI shows soft warning with override (override requires typing "I confirm this is not a real seed").
  - Fewer than 12 valid tokens → no action (too noisy).

### 13.5.2 WIF Detection

Regex (anchored at word boundaries):

```
mainnet uncompressed: \b5[1-9A-HJ-NP-Za-km-z]{50}\b
mainnet compressed:   \b[KL][1-9A-HJ-NP-Za-km-z]{51}\b
testnet:              \b9[1-9A-HJ-NP-Za-km-z]{50}\b  |  \bc[1-9A-HJ-NP-Za-km-z]{51}\b
```

Match → Base58Check verify via `bitcoin::PrivateKey::from_wif`. Valid → `Block`. Invalid → no action.

### 13.5.3 Extended Private Key Detection

Regex:

```
\b(?:x|y|z|Y|Z|t|u|v|U|V)prv[1-9A-HJ-NP-Za-km-z]{107,108}\b
```

Match → Base58Check verify via `bitcoin::bip32::Xpriv::from_str`. Valid → `Block`. Also detect xprv inside descriptors (parse descriptor, walk key tree, flag if any key is private).

### 13.5.4 Raw Hex Private Key Detection

Regex: `\b[0-9a-fA-F]{64}\b`.

High false-positive rate (SHA256 hashes match). Apply context heuristic:
- If the input is on its own line, length ≤ 80 chars → `Warn`.
- If the input is preceded within 32 chars by `priv`, `key`, `secret`, `wif` (case-insensitive) → `Block`.
- Otherwise → no action.

### 13.5.5 SLIP-39 Detection

- Vendor SLIP-39 wordlist (1024 words from `satoshilabs/slips/slip-0039/wordlist.txt`).
- Window size: 20 or 33 tokens.
- All-in-wordlist + RS1024 checksum validation via `slip-0039` crate.
- Match → `Block`.

### 13.5.6 codex32 / BIP-93 Detection

- Regex: `\b(?:ms|MS)1[0-9][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{45,125}\b`.
- Case must not be mixed (codex32 forbids).
- Validate via `codex32` crate.
- Match → `Block`.

### 13.5.7 Detector Action Semantics

| Action | Desktop UI | CLI |
|--------|------------|-----|
| `Block` | Full-screen dialog: "This looks like a real Bitcoin secret. Lifeboat does not need this. Input cleared." Field cleared. Detector reason logged (without the secret content). | exit code 5; stderr message |
| `Warn` | In-line warning with "I confirm this is not a real secret" override | warning to stderr; continues |
| `Allow` | normal | normal |

### 13.5.8 Memory Handling

- Detector receives input as `&str`.
- The caller wraps the input in `SecretString` BEFORE calling the detector.
- Detector returns `DetectorReport` containing only `ByteRange` indices and `DetectedSecret` discriminant — **never** the secret content.
- Caller zeroizes the input regardless of result.
- Tauri command boundary: only `DetectorReport` crosses; the original string is held in Rust `SecretString`, never returned to JS.

### 13.5.9 Webview Memory Limitation

Tauri/webview memory cannot be reliably wiped (acknowledged limitation). Mitigations:

1. Use `<input type="password">` for any field that could contain secrets so the DOM does not cache history.
2. JS variable is overwritten with empty string immediately after `invoke()`.
3. Onboarding documents: "Restart Bitcoin Lifeboat after working with sensitive material if you are extremely paranoid."
4. Code review forbids React state holding any value classified `Confidential` for longer than the user's current interaction.

### 13.5.10 Fuzzing

The detector ships with `cargo-fuzz` targets:

- `fuzz_detector_arbitrary_bytes` — random inputs must not panic.
- `fuzz_detector_false_positive` — corpus of English Wikipedia + Linux dictionary; must yield zero `Block` results.
- `fuzz_detector_false_negative` — corpus of valid BIP39 (all languages), WIF, xprv, SLIP-39, codex32 test vectors; must `Block` 100%.
- `fuzz_detector_descriptor_with_xprv` — descriptors with embedded xprvs; must `Block`.

CI runs each fuzz target for 5 minutes per PR; release branches run 1 hour.

## 13.6 Data Storage Defaults (NORMATIVE)

| Data | MVP Default | User Override |
|------|-------------|---------------|
| Descriptor input | In memory only | None |
| Reports | Export-on-demand only | None |
| Runbooks | Export-on-demand only | None |
| Drill history | Not stored | v0.3+: opt-in |
| Recent-file history | Not stored | v0.2+: opt-in |
| Logs | OFF by default | "Diagnostic mode" toggle (logs to `lifeboat-diagnostic.log` in user-chosen location; scrubs Confidential data; never includes secret-classified data) |
| App settings | Yes (theme, language) | Only Public-classified preferences |
| Clipboard | Never read automatically | None |

Settings file location:
- macOS: `~/Library/Application Support/com.bitcoinlifeboat.app/settings.json`
- Windows: `%APPDATA%\com.bitcoinlifeboat.app\settings.json`
- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/lifeboat/settings.json`

Schema: `{ "version": 1, "theme": "system|light|dark", "language": "en|es|...", "diagnostics_enabled": false, "show_advanced_details": false }`.

## 13.7 Tauri Capabilities (NORMATIVE)

`src-tauri/capabilities/default.json`:

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "description": "Local-only Bitcoin Lifeboat desktop capabilities",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "dialog:allow-open",
    "dialog:allow-save",
    {
      "identifier": "fs:allow-read-file",
      "allow": [{ "path": "$DIALOG_PATH" }]
    },
    {
      "identifier": "fs:allow-write-file",
      "allow": [{ "path": "$DIALOG_PATH" }]
    },
    "os:allow-platform",
    "os:allow-version",
    "process:allow-exit"
  ]
}
```

**Explicitly NOT included:** `http:*`, `shell:*`, `clipboard-manager:*`, `notification:*`, `global-shortcut:*`, `window:allow-create`, `process:allow-spawn`, `path:allow-resolve`, `webview:allow-create-webview`.

Future versions add permissions narrowly:
- v0.3 hardware: nothing for file-based PSBT (uses dialog). QR uses camera; that requires Tauri camera plugin (`tauri-plugin-camera`).
- v0.4 hardware: `shell:allow-execute` scoped to the HWI sidecar binary path only.

## 13.8 Content Security Policy (NORMATIVE)

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
connect-src 'self' ipc: http://ipc.localhost;
img-src 'self' data: asset: tauri:;
font-src 'self';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
form-action 'none';
worker-src 'self' blob:;
```

- No `'unsafe-eval'`, no `'wasm-unsafe-eval'` unless a future feature explicitly needs Wasm (revisit at v0.5 if Miniscript visualization uses Wasm-rendered SVG).
- `style-src 'unsafe-inline'` only because Tailwind injects styles; revisit pruning after MVP ships.
- `connect-src` includes only Tauri's IPC channel and `'self'`.

## 13.9 Release Signing (NORMATIVE)

| Artifact | Primary Signature | Transparency |
|----------|------------------|--------------|
| macOS `.dmg` | Apple Developer ID Application + notarytool | cosign keyless via GitHub Actions OIDC |
| Windows `.msi` | OV code signing certificate (cloud HSM via Azure Trusted Signing or SSL.com eSigner) | cosign keyless |
| Linux AppImage | `gpg --detach-sign` + minisign | cosign keyless |
| Linux `.deb` | `dpkg-sig` + minisign | cosign keyless |
| CLI binaries | minisign (per platform) | cosign keyless |
| Source tarball | minisign + cosign keyless | cosign keyless |

The minisign public key is published in three places: (1) website, (2) `SECURITY.md` in repo, (3) tagged Git commit. Key rotation is documented and a 1-year rotation cadence is established with overlapping validity.

## 13.10 No Auto-Updater (NORMATIVE)

Bitcoin Lifeboat **does NOT** include the Tauri updater plugin. Rationale:

1. A recovery tool is most often used at moments of crisis — the moment when silent updates are most dangerous.
2. Updater key compromise is a real risk class (Tauri GHSA-2rcp-jvr4-r259 demonstrated leak via env var misconfiguration).
3. The user benefit (convenience) does not justify the centralized trust requirement.

What the app does instead:
- The About screen shows: "You are running version 0.X.Y. The latest version is checked from GitHub when you click here." Clicking opens the user's browser at `https://github.com/<org>/bitcoin-lifeboat/releases` — the **app itself never makes the HTTP request**.
- Critical-vulnerability advisories are published on the website and via the project's security mailing list / RSS feed.
- The website hash for the current release is shown in `lifeboat about` CLI output.

## 13.11 No Telemetry, No Crash Reporting (NORMATIVE)

The MVP ships with no telemetry, no crash-report upload, no analytics. Panic hooks scrub Confidential and Secret data and write to a local file (`lifeboat-crash-<timestamp>.txt`) ONLY when the user has enabled diagnostic mode. The user attaches that file manually to a GitHub issue if they choose.

The CLI uses `human-panic` crate to format crash output to stderr without exfiltration.

## 13.12 Reproducible Builds (Aspirational, v1.0 Target)

Reproducible builds are a **v1.0 target**, not an MVP blocker. The build pipeline must already be structured so reproducibility is achievable:

- `Cargo.lock` committed.
- `package-lock.json` committed.
- `RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME=~"` set in CI.
- `SOURCE_DATE_EPOCH` set from Git commit timestamp.
- Node version pinned in `.nvmrc`.
- All build steps documented in `docs/reproducible-builds.md`.

Full deterministic bundling of DMG/MSI/AppImage is a v1.0 milestone with its own design doc.

## 13.13 Security Disclosure (NORMATIVE)

- `SECURITY.md` includes:
  - PGP key fingerprint + key block.
  - Disclosure route: GitHub private vulnerability reporting through the repository Security tab.
  - 90-day disclosure window.
  - No bug bounty in pre-v1.0 (documented). Bounty considered post-audit.
  - Public advisory format: GHSA + RSS feed on website.
- Two-maintainer review required for any PR touching: descriptor parser, detector, release pipeline, capability/permissions config, CSP.
- Signed Git commits required for all maintainer pushes (GitHub branch protection).

---

# 14. Privacy Model

## 14.1 Local-First Default

Bitcoin Lifeboat operates entirely on the user's machine. No data transit by default.

## 14.2 Data Classification (Recap)

Per §13.4: `Public`, `Confidential`, `Secret`. The detector enforces the boundary against `Secret`. The export modes (public-safe vs private) enforce the boundary against `Confidential`.

## 14.3 xpub Privacy Education (NORMATIVE)

Whenever a report or runbook includes an xpub in `private` mode, the export prepends:

> ⚠️ This document contains an extended public key (xpub).
> An xpub reveals every receive AND change address for this wallet,
> past and future. Anyone with this xpub can see your wallet's
> entire transaction history on the blockchain.
> Store this where you store your seed backup. Do not email it,
> do not upload it, do not share it on chat.

In `public-safe` mode the xpub is shown only as `xpub6...XXXX` (first 6 + last 4 characters).

## 14.4 Network Behavior Summary

| Capability | MVP | v0.2 | v0.3 | v0.4 |
|-----------|-----|------|------|------|
| Auto network calls | ❌ | ❌ | ❌ | ❌ |
| User-initiated update check | ❌ (browser-redirect only) | ✅ (opens browser) | ✅ | ✅ |
| Signet broadcast (user-initiated) | ❌ | ✅ (with banner) | ✅ | ✅ |
| Mainnet broadcast | ❌ FOREVER | ❌ FOREVER | ❌ FOREVER | ❌ FOREVER |
| Tor / SOCKS proxy support | ❌ | considered | ✅ | ✅ |
| In-app docs fetch | ❌ (docs embedded) | ❌ | ❌ | ❌ |
| External link clicks | open user's browser | open user's browser | open user's browser | open user's browser |

"Mainnet broadcast forever ❌" is a hard product rule: Lifeboat is a rehearsal tool, not a coordinator. Mainnet broadcast belongs in Sparrow, Specter, Liana, Nunchuk — Lifeboat will export a signed PSBT and tell the user where to broadcast it.

## 14.5 Settings Toggles (User-Visible)

| Toggle | Default | Effect |
|--------|---------|--------|
| Diagnostic logging | OFF | Enables INFO-level logs to user-chosen file with Confidential-data scrubbing |
| Show advanced technical details | OFF | Reveals expanders with descriptor internals, Miniscript trees, etc. |
| Remember recent files (v0.2+) | OFF | Stores last 5 file paths in settings (not file contents) |
| Theme | system | system/light/dark |
| Language | system | en/de/es/... when translations ship |

There is no "I know what I'm doing" toggle that bypasses safety warnings. Override is per-warning, per-instance, and requires typed confirmation.

---

# 15. UX Principles and Copy

## 15.1 Tone

The app's voice is:

1. Calm.
2. Clear.
3. Serious without being alarmist.
4. Non-technical by default, precise when needed.
5. Explicit about risk.
6. Never condescending.
7. Never claims certainty about user's funds.

## 15.2 First-Launch Flow (NORMATIVE)

Five screens. Skippable only after Screen 2.

**Screen 1 — Welcome**

```
Bitcoin Lifeboat

Bitcoin Lifeboat helps you test whether your Bitcoin recovery plan
works before disaster happens.

It is not a wallet.
It does not custody funds.
It does not need your real seed phrase.

[Continue]
```

**Screen 2 — Safety Promise**

```
Before we start, our four promises:

1. We never ask for your real seed phrase.
2. We never connect to the internet without your action.
3. We never store your wallet metadata.
4. We never claim your funds are safe.

[ I understand. Continue. ]
```

(The "I understand" checkbox is required to advance.)

**Screen 3 — Goal**

```
What do you want to do?

[ ] Check my backup plan
[ ] Audit my multisig setup
[ ] Create a family/heir runbook
[ ] Generate a recovery runbook
[ ] Learn how recovery works (Practice Mode — v0.2)
[ ] Use developer tools (CLI)
```

**Screen 4 — Mode Confirmation**

If user chose a real-wallet audit:

```
This mode uses public wallet metadata only.
Public metadata = descriptors, xpubs, fingerprints, derivation paths.

Do not paste:
  - Seed words / mnemonic
  - Private keys (WIF, hex)
  - Extended private keys (xprv, yprv, zprv)
  - Passphrases

If you paste a secret by accident, Lifeboat will detect it,
refuse to process it, and clear the field.

[ Continue ]
```

**Screen 5 — Home Dashboard**

(see §21 UI Requirements)

## 15.3 UX Metaphor

Disaster-preparedness language throughout:

- "Fire drill"
- "Lifeboat"
- "Readiness Check"
- "Emergency plan"
- "Recovery runbook"
- "Drill result"
- "Practice mode"

## 15.4 Status Words (NORMATIVE)

Statuses use these exact words; do not invent variants.

| Status | When | Color |
|--------|------|-------|
| `Ready` | All critical checks pass; known address matched; recent drill | Green |
| `Mostly Ready` | All critical checks pass; minor warnings | Light green |
| `Needs Attention` | One or more warnings; no critical failures | Amber |
| `Not Ready` | One or more critical failures | Red |
| `Cannot Determine` | Insufficient information (e.g., user did not provide known address AND descriptor is ambiguous) | Gray |

Color is always paired with text and an icon (per §15.5 accessibility).

## 15.5 Accessibility (NORMATIVE)

1. WCAG 2.2 AA target.
2. Minimum text contrast 4.5:1 normal, 3:1 large text.
3. Status communicated via text + color + icon — never color alone.
4. Full keyboard navigation (tab order matches visual order; focus indicators visible).
5. ARIA labels on all interactive elements.
6. Screen-reader tested with NVDA (Windows), VoiceOver (macOS), Orca (Linux).
7. Large-text mode (1.5x and 2x scaling).
8. Reduced-motion respected (`prefers-reduced-motion`).
9. Dark mode + light mode + system.
10. Reports are screen-reader friendly (HTML semantics; PDFs tagged).
11. No flashing content.
12. "Copy explanation" button on every status row so users can paste into their notes.

## 15.6 Mandatory Disclaimer Language (NORMATIVE, VERBATIM)

These three strings appear verbatim in every report, runbook, and app screen that produces output.

**Short disclaimer (report header):**

```
This report is a diagnostic aid. It is not legal, tax, financial,
or security advice. Bitcoin Lifeboat cannot guarantee that any
wallet is recoverable.
```

**Long disclaimer (report footer + runbook back page):**

```
About this document

Bitcoin Lifeboat is an open-source diagnostic and rehearsal tool.
This document reflects only the information you provided. It cannot
detect missing materials Lifeboat was not asked to check, it cannot
verify the physical location or condition of your backups, and it
cannot predict the future condition of your hardware wallets.

A "Ready" status means the metadata you provided appears complete
for the scenarios Lifeboat tested. It does not mean your bitcoin
is safe. It does not mean recovery will succeed in a real emergency.

You are responsible for verifying recovery end-to-end on a test
network before trusting your real wallet. Consult an attorney for
estate planning. Consult a tax professional for tax implications.

Bitcoin Lifeboat does not custody funds, does not contact you,
does not call you, and does not ask for your seed phrase.

If anyone claiming to be from Bitcoin Lifeboat contacts you, it
is a scam. Hang up.
```

**Heir runbook disclaimer (first page of heir runbooks):**

```
You are reading a recovery plan written by someone who trusts you
to help. This document does not contain bitcoin. It does not contain
secret recovery words. It only contains instructions.

You will not be able to recover anything using only this document.
You will also need:
  - The wallet's hardware device(s) or backup card(s)
  - Any secret words the owner wrote down separately (if they did)
  - Patience: never let anyone rush you

If anyone tells you they can help you "decrypt" or "unlock" this
plan for a fee, hang up. They cannot. They are a scammer.

If you get stuck, stop. Take your time. Find a trusted person who
understands Bitcoin and ask for help. The owner has likely listed
a trusted helper on this page.
```

## 15.7 "Not a Wallet" Language (NORMATIVE, VERBATIM)

The phrase **"Bitcoin Lifeboat is not a wallet"** appears in:

1. Onboarding Screen 1.
2. Top of every report.
3. README first paragraph.
4. Website homepage hero.
5. CLI `--help` output banner.
6. About screen.

Full canonical paragraph:

```
Bitcoin Lifeboat is not a wallet, not a custody service, not a
seed phrase manager, not an inheritance legal service, and not a
recovery company. It is a free, open-source diagnostic tool that
helps you test whether your recovery plan works.
```

## 15.8 "What This Report Cannot Tell You" Section

Every report ends with this section (verbatim):

```
What this report CANNOT tell you

  - Whether your hardware wallets still work.
    (Lifeboat did not power them on. Run a Disaster Drill in v0.3.)
  - Whether your seed words are still legible on the paper/metal.
    (Go check. In person. Today.)
  - Whether the location you store backups in is still safe.
    (Lifeboat cannot see your closet.)
  - Whether your heirs can find the materials.
    (Run a Heir Drill in v0.6, or talk to them now.)
  - Whether your passphrase is correct.
    (Lifeboat does not know your passphrase. Test it on a
     low-value wallet first.)
  - Whether the wallet software you depend on will still exist
    when you need it.
    (Print this report. Print the descriptor. Make recovery
     possible without specific software.)
```

## 15.9 Avoid Jargon on First Layer

Surface language prefers:

> "Can your wallet be recovered?"

over:

> "Validate solvability of descriptor-derived scriptPubKeys."

Expand into technical detail behind an expandable section labeled "Show technical details" (off by default; persists across sessions only when the user toggles "Show advanced technical details" in settings).

## 15.10 Every Report Must Answer (NORMATIVE)

Every report (in-app, Markdown, PDF, JSON) answers, in this order:

1. **Status** (Ready / Mostly Ready / Needs Attention / Not Ready / Cannot Determine)
2. **What passed**
3. **What needs attention**
4. **What failed**
5. **What is missing**
6. **What to do next** (prioritized list, with effort estimate per item)
7. **What NOT to do** (anti-actions, e.g., "do not email this xpub")
8. **When to run this again** (recommend within 12 months; sooner if score < 70)
9. **Disclaimer** (§15.6 short form)
10. **Lifeboat version + report hash** (for reproducibility / forensic correlation)

---

# 16. Readiness Scoring

## 16.1 Why Both Numeric Score AND Qualitative Status

Some users (§7.1 multisig power user) want a number to chart progress over time. Some users (§7.2 beginner) need a clear pass/fail. The MVP gives both, with the **qualitative status as the headline** and the numeric score as a sub-detail.

Reports never say "your wallet is 87% safe." They say:

> Status: Mostly Ready (score 87/100). One important warning, no critical failures.

## 16.2 Status Categories (NORMATIVE)

```
Ready              90–100  (and all critical checks pass + known address matched)
Mostly Ready       70–89
Needs Attention    40–69
Not Ready          0–39    OR any critical check fails
Cannot Determine   N/A     (insufficient information)
```

`Ready` requires both numeric ≥ 90 AND zero critical failures AND a successful known-address match (D8).

## 16.3 Critical Failures (NORMATIVE — force "Not Ready")

Any of these forces status `Not Ready` regardless of numeric score:

| Code | Check | Description |
|------|-------|-------------|
| `C-DESC-PARSE-FAIL` | Descriptor failed to parse | The descriptor as provided is not a valid BIP380 expression |
| `C-DESC-CHECKSUM-INVALID` | Descriptor checksum present but invalid | One or more characters differ from canonical form |
| `C-MULTISIG-NO-DESCRIPTOR` | Multisig wallet identified but full descriptor missing | User answered "multisig" but provided only xpubs without quorum |
| `C-MULTISIG-THRESHOLD-MISSING` | Multisig threshold cannot be determined | Descriptor or user input lacks M-of-N |
| `C-KEY-COUNT-BELOW-THRESHOLD` | Threshold > number of keys in descriptor | Descriptor is self-inconsistent |
| `C-DUPLICATE-XPUB` | Same xpub appears multiple times | Quorum is illusory |
| `C-ADDRESS-MISMATCH` | User's known address does not match any address in the derived range | Descriptor is wrong, or address belongs to another wallet |
| `C-WALLET-TYPE-MISMATCH` | User declared wallet type does not match descriptor's script type | Descriptor is wrong, or user confused about their setup |
| `C-CHANGE-DESC-REQUIRED-MISSING` | A wallet that requires change descriptor lacks one AND the descriptor is non-multipath AND BIP389 expansion is impossible | Single-line descriptor with no change branch |
| `C-PASSPHRASE-UNDOCUMENTED` | User indicated a passphrase exists but heir instructions do not mention it | Heir cannot recover without knowing a passphrase exists |
| `C-SECRET-DETECTED` | Sensitive-input detector found a real secret in the input | Input rejected; user must remove and retry |
| `C-DESC-CONTAINS-XPRV` | Descriptor includes an extended private key | App refuses to process; user must remove xprv and use xpub instead |

## 16.4 Warnings (reduce score, do not fail)

| Code | Check | Score Impact |
|------|-------|--------------|
| `W-NO-DESC-CHECKSUM` | Descriptor lacks `#checksum` | -5 |
| `W-NO-CHANGE-DESC` | Change descriptor not provided AND not multipath | -15 |
| `W-NO-BIRTH-HEIGHT` | No wallet creation date / block height documented | -5 |
| `W-NO-GAP-LIMIT` | Gap limit not documented | -3 |
| `W-NO-KNOWN-ADDRESS` | User did not provide a known address | -10 |
| `W-NO-PRINTED-BACKUP` | User answers "no" to "Do you have a printed descriptor backup?" | -8 |
| `W-NO-RECENT-DRILL` | No drill in last 12 months (or never) | -10 |
| `W-NO-HEIR-INSTRUCTIONS` | No heir instructions written | -8 |
| `W-NO-EMERGENCY-CONTACT` | No emergency contact named | -3 |
| `W-NO-HW-TEST` | Hardware wallet not signed anything in past 12 months | -8 |
| `W-SAME-LOCATION-BACKUP` | User answers "yes" to "Are your backup and your device in the same location?" | -10 |
| `W-WALLET-SW-UNDOCUMENTED` | User did not document which wallet software is needed | -5 |
| `W-TAPROOT-PREVIEW` | Descriptor uses Taproot in v0.1 (preview-only support) | -5 (informational; lifted in v0.2) |
| `W-NO-MULTIPATH` | Singlesig descriptor uses two separate descriptors instead of BIP389 multipath | -2 |

Numeric score starts at 100 and is reduced by warnings. Score is clamped to [0, 100].

## 16.5 Cannot Determine (NORMATIVE)

Status is `Cannot Determine` when:

1. Descriptor parses but network cannot be inferred AND user did not declare network.
2. Descriptor parses but key origin info is entirely absent AND user did not provide it manually.
3. User imported a wallet export file the app does not recognize.
4. User aborted the wizard before reaching the address-comparison step.

The report explains what specifically was missing and what to do.

## 16.6 Wallet-Type-Specific Scoring (NORMATIVE)

Multisig wallets get an additional dimension: **survivability**. The Readiness Check answers:

- Lose 1 signer → can you still recover?
- Lose 2 signers → can you still recover?
- Lose descriptor backup → can you still recover from xpubs?

These are reported as "Survives 1 / Survives 2 / Survives both signer loss and descriptor loss" alongside the main status.

Singlesig wallets do not get a survivability score (single point of failure by definition).

Timelock wallets (Liana, v0.5+) get a recovery-time-window dimension.

## 16.7 Scoring is Transparent

The scoring algorithm is documented in `docs/scoring.md` with every weight and check listed. The JSON report includes a `scoring_audit` section showing exactly which checks fired and how each affected the score:

```json
"scoring_audit": [
  { "code": "W-NO-CHANGE-DESC", "impact": -15, "after": 85 },
  { "code": "W-NO-KNOWN-ADDRESS", "impact": -10, "after": 75 }
]
```

Scoring weights are **NOT user-configurable** in MVP (would create score-shopping). They are versioned with the scoring engine (`scoring_engine_version: "0.1.0"` in the report).

## 16.8 Anti-Overclaim Language (NORMATIVE)

The app **never** uses the word "safe" about user wallets. Banned terms:

- "Your wallet is safe."
- "Your bitcoin is secure."
- "Recovery is guaranteed."
- "You can recover."

Approved alternatives:

- "Your backup appears complete for the scenarios we tested."
- "The metadata you provided passed all checks."
- "Ready for the tested scenario."
- "Your descriptor parses and your known address matches."

This rule is enforced by a lint check on translation strings.

---

# 17. Functional Requirements

## 17.1 Descriptor Import

The app accepts descriptors via:

1. **Paste** into a text area (single descriptor or BIP389 multipath).
2. **File picker** — `.txt`, `.json`, `.bed` (Liana), `.descriptor` (Coldcard).
3. **Drag-and-drop** of supported file types onto the app window.

Multi-descriptor input (e.g., two separate descriptors for receive and change) is supported by either:
- Pasting both, separated by newline; OR
- Using "Add change descriptor" button after pasting the receive descriptor.

## 17.2 Descriptor Parser

Parses (via `rust-miniscript 13.0.0`):

| Function | v0.1 | v0.2 |
|----------|------|------|
| `pkh(KEY)` | ✅ | ✅ |
| `wpkh(KEY)` | ✅ | ✅ |
| `sh(wpkh(KEY))` | ✅ | ✅ |
| `wsh(EXPR)` | ✅ | ✅ |
| `sh(wsh(EXPR))` | ✅ | ✅ |
| `multi(M, KEY1, ...)` | ✅ | ✅ |
| `sortedmulti(M, KEY1, ...)` | ✅ | ✅ |
| `wsh(multi(...))` | ✅ | ✅ |
| `wsh(sortedmulti(...))` | ✅ | ✅ |
| `sh(multi(...))` | ✅ | ✅ |
| `sh(wsh(sortedmulti(...)))` | ✅ | ✅ |
| `tr(KEY)` (key-path only) | Preview | ✅ |
| `tr(KEY, {SCRIPT_TREE})` | Preview | ✅ |
| `tr(KEY, {multi_a(...)})` | Preview | ✅ |
| Miniscript inside `wsh(...)` (e.g., `or_d`, `and_v`, `older`, `after`) | Preview | ✅ |
| Liana-style `wsh(or_d(pk(K),and_v(v:pkh(R),older(N))))` | Preview | ✅ |
| BIP389 multipath `<0;1>/*` | ✅ | ✅ |
| Combo / `addr()` / `raw()` | ❌ (rejected) | ❌ (rejected) |

"Preview" means the descriptor parses, address derivation works, but a `W-TAPROOT-PREVIEW` or `W-MINISCRIPT-PREVIEW` warning fires. The user is told the support exists but is not yet exhaustively tested against all hardware wallets.

## 17.3 Descriptor Normalization

On import, every descriptor is normalized:

1. Compute canonical form using `rust-miniscript`'s `Descriptor::to_string()`.
2. Compute/verify checksum using `descriptor::checksum::desc_checksum`.
3. Normalize hardened markers (`h` and `'` are equivalent; canonical form uses `h`).
4. Expand `<0;1>` multipath into receive + change for analysis (preserve original for display).
5. Validate that `wsh(sortedmulti(...))` sorts keys lexicographically.

The original input is preserved alongside the normalized form so the user sees their own input echoed correctly.

## 17.4 Address Derivation

| Behavior | Default | Configurable |
|----------|---------|--------------|
| First-N receive addresses | 10 | Yes (1–1000) |
| First-N change addresses | 10 | Yes (1–1000) |
| Network inference | from descriptor key version bytes | Yes (user override required if ambiguous) |
| Output format | bech32 / base58 per descriptor | N/A |
| Display | full address shown in app; redacted in `public-safe` exports | Per-export choice |

Derivation refuses to proceed if:
- Descriptor key version bytes are inconsistent (mainnet + testnet keys mixed).
- Descriptor lacks `*` wildcard AND user requested >1 address.
- Descriptor includes xprv (block; force user to remove).

## 17.5 Known-Address Comparison

User enters one or more addresses they know belong to their wallet. The app:

1. Validates each address parses for the inferred network.
2. Searches the first N receive AND change addresses for a match.
3. If found, reports the derivation index (`m/.../0/3` for example) and chain (receive/change).
4. If not found in first N, expands search to first 1000 addresses (transparent to user).
5. If still not found, reports `C-ADDRESS-MISMATCH` (critical).

User can also compare an address **explicitly expected NOT to match** — useful for ruling out wrong-wallet imports.

## 17.6 Multisig Analysis

For multisig descriptors, the app reports:

1. M (threshold) of N (key count).
2. `multi` vs `sortedmulti` (with explanation of difference and recommendation).
3. Per-key: fingerprint, derivation path, xpub (with redaction toggle), wallet-label (if user provides).
4. Duplicate-xpub check.
5. Mixed-network check (all keys same network).
6. Standard-path check (per-key path matches BIP48 for multisig, BIP84 for native segwit singlesig, etc.).
7. Wallet birth height (user-provided, optional).
8. Watch-only reconstruction viability: "Could a fresh Bitcoin Core node, given only this descriptor, reconstruct the wallet?" (yes/no per BDK semantics).

## 17.7 Report Generation

### 17.7.1 Markdown Report

Generated server-side (Rust) from a strict template; deterministic for a given input + scoring engine version. Always under 64 KB.

### 17.7.2 JSON Report

See §19 for schema. Schema version is `0.1.0` in MVP. Backward-compatible additions bump the minor version. Breaking changes bump the major version.

### 17.7.3 PDF Report

Generated via **Typst** (preferred — `typst-cli` invoked as Rust subprocess OR `typst` crate when stable). Fallback: **`printpdf`** crate for environments without Typst.

Why Typst: better typography for runbooks, simpler template language than LaTeX, no external dependency to install on user's machine (the binary is bundled). `printpdf` is the fallback if Typst bundling fails on a target platform.

PDF features required:
- Embedded fonts (Inter for sans, JetBrains Mono for code).
- Tagged PDF for accessibility (when supported by chosen library).
- Page numbers, table of contents for long runbooks.
- Print-optimized A4 + US Letter variants.
- Footer with disclaimer + Lifeboat version + report hash on every page.

### 17.7.4 HTML / Print-Optimized

The in-app report view doubles as print-optimized HTML; users can "Print to PDF" via OS print dialog as a backup path.

## 17.8 Runbook Generation

Runbooks use the same generation pipeline as reports (Markdown → PDF). Templates live in `templates/runbooks/*.tex` (Typst) and `*.md`.

Template variables:

- `{{wallet_summary}}` — script type, threshold, key count.
- `{{descriptor}}` — full descriptor (private mode only).
- `{{descriptor_redacted}}` — redacted form (public-safe mode).
- `{{signer_list}}` — table of signers with fingerprints + paths.
- `{{drill_date}}` — last successful drill date (blank if none).
- `{{next_drill}}` — recommended next drill date (drill_date + 12 months).
- `{{report_hash}}` — SHA256 of the JSON report this runbook accompanies.
- `{{lifeboat_version}}` — semver.

User-fillable blank fields are rendered as labeled lines ("Signer A location: __________________").

## 17.9 Wallet Export Importers (NORMATIVE)

Per-wallet importers in `crates/wallet-imports/`. Each importer:

1. Validates file MIME and size (< 10 MB).
2. Parses with `serde_json` strict mode (no unknown-field tolerance).
3. Extracts descriptor(s), key origin, optional birth height, optional labels.
4. Returns a `NormalizedWalletExport` struct shared with the rest of the analyzer.

Supported importers in MVP:

| Wallet | Format | File extension | MVP |
|--------|--------|----------------|-----|
| Bitcoin Core | `listdescriptors` JSON | `.json` | ✅ |
| Sparrow | Sparrow JSON | `.json` | ✅ |
| Specter Desktop | Specter wallet JSON | `.json` | ✅ |
| Liana | Encrypted descriptor backup | `.bed` | ✅ (asks user for decryption inputs) |
| Nunchuk | BSMS (BIP129) | `.bsms` / `.txt` | ✅ |
| Coldcard | Generic Wallet Export | `.json` | ✅ |
| Coldcard | Descriptor + sig file | `.txt` + `.sig` | ✅ |
| Passport Core | Descriptor export | `.txt` / QR | ✅ (file only in MVP; QR in v0.3) |
| Jade | Multisig registered wallet | `.json` | ✅ |
| BlueWallet multisig vault | Coldcard-style text | `.txt` | Tier 2 manual workaround (parser ships, but documented as workaround) |
| Electrum multisig export | Coldcard-style text | `.txt` | Tier 2 manual workaround |
| Generic BIP380 paste | text | — | ✅ |

Tier 3 (not supported because they don't export usable descriptors): Ledger Live, Trezor Suite. Documentation tells users to import their account into Sparrow or Specter first, then export from there.

## 17.10 CLI Commands (NORMATIVE)

Binary name: **`lifeboat`** (D12). Installed as a standalone binary AND via `cargo install lifeboat-cli` AND bundled with desktop app (the desktop installer places the CLI on PATH on macOS/Linux; opt-in on Windows).

### 17.10.1 `lifeboat audit-descriptor`

```
lifeboat audit-descriptor [OPTIONS]

OPTIONS:
  --file <PATH>             Read descriptor from file
  --stdin                   Read descriptor from stdin
  --descriptor <STRING>     Inline descriptor (avoid in shell history; prefer --stdin)
  --known-address <ADDR>    Compare against a known address
  --network <NET>           mainnet|testnet|signet|regtest (overrides inferred)
  --derive-count <N>        Number of addresses to derive (default 10)
  --json                    Output machine-readable JSON instead of human text
  --no-color                Disable ANSI colors
  --strict                  Exit non-zero on warnings (CI mode)
  --scoring-engine <VER>    Pin scoring engine version (default: latest)

EXIT CODES:
  0   Ready
  1   Mostly Ready (warnings only)
  2   Needs Attention
  3   Not Ready
  4   Cannot Determine
  5   Sensitive input detected (input rejected)
  10  Invalid CLI arguments
  20  Internal error
```

### 17.10.2 `lifeboat derive-addresses`

```
lifeboat derive-addresses --descriptor <STRING|FILE> --count <N> [--chain receive|change|both] [--json]
```

Output: address list with derivation index, network, and chain (receive/change). Default `--chain both`.

### 17.10.3 `lifeboat compare-address`

```
lifeboat compare-address --descriptor <STRING|FILE> --address <ADDR> [--search-range <N>] [--json]
```

Exit codes: 0 = match found, 1 = no match within range, 2 = address invalid for inferred network.

### 17.10.4 `lifeboat generate-runbook`

```
lifeboat generate-runbook --template <TEMPLATE_ID> --output <PATH> [--mode public-safe|private] [--format pdf|md|txt|html] [--descriptor <STRING|FILE>]
```

Template IDs: `singlesig-basic`, `singlesig-passphrase`, `multisig-2of3`, `multisig-3of5`, `heir-*`, `meetup-workshop`, `business-treasury`.

Default mode: `public-safe`. Default format: `pdf`.

### 17.10.5 `lifeboat report-json`

```
lifeboat report-json --descriptor <STRING|FILE> [--known-address <ADDR>] [--network <NET>] [--derive-count <N>] [--scoring-engine <VER>]
```

Output: ReadinessReport JSON to stdout (see §19.1).

### 17.10.6 `lifeboat detect-secrets`

```
lifeboat detect-secrets [--file <PATH>] [--stdin] [--json]
```

Output: DetectorReport JSON. Exit code 5 if any `Block` finding, 1 if only `Warn`, 0 otherwise.

### 17.10.7 `lifeboat parse-export`

```
lifeboat parse-export --file <PATH> [--format auto|sparrow|specter|coldcard|nunchuk|jade|liana|core] [--json]
```

Output: NormalizedWalletExport JSON.

### 17.10.8 `lifeboat checksum`

```
lifeboat checksum [--validate <DESC>] [--compute <DESC>]
```

`--validate`: exits 0 if checksum present and valid, non-zero otherwise.
`--compute`: outputs descriptor with appended `#xxxxxxxx` checksum.

### 17.10.9 Global Flags

```
--version              Print version
--help, -h             Print help
--json                 Machine-readable output (where applicable)
--no-color             Disable ANSI colors
--quiet, -q            Suppress non-essential output
--verbose, -v          More detail (no secrets ever logged)
```

### 17.10.10 CLI Stability

CLI output formats are versioned:

- Human-readable output may change between minor versions (warning shown in changelog).
- `--json` output is **stable within a major version**. Breaking JSON changes bump major version.
- Exit codes are **stable across all versions**.
- `lifeboat report-json` output is byte-deterministic for fixture inputs at a pinned `--scoring-engine` version. Golden tests assert this.

## 17.11 Man Pages and Shell Completions

- Man pages auto-generated from `clap` via `clap_mangen`; installed by the `.deb` and `cargo install`.
- Shell completions auto-generated via `clap_complete` (bash, zsh, fish, PowerShell, nushell).
- Homebrew formula (post-v0.1) installs both.

## 17.12 Bitcoin Core Wallet Export Compatibility Detail

For `listdescriptors` output: parse JSON array, identify `active=true` entries, separate by `internal=false` (receive) and `internal=true` (change). Use the latest `timestamp` as wallet birth-time hint.

For Bitcoin Core 30.x: rejected by the app with a clear message ("Bitcoin Core 30.x has known wallet bugs; please use 29.x or wait for 30.2+").

---

# 18. Non-Functional Requirements

## 18.1 Security NFRs

| ID | Requirement |
|----|-------------|
| NFR-SEC-1 | Zero outbound network calls in MVP unless explicitly user-initiated |
| NFR-SEC-2 | All secret-classified data zeroized within 100ms of last use |
| NFR-SEC-3 | All release artifacts signed with minisign + cosign keyless |
| NFR-SEC-4 | `cargo audit` runs on every PR; CI fails on any advisory ≥ Medium |
| NFR-SEC-5 | `cargo deny` runs on every PR; advisories, licenses, sources, bans all enforced |
| NFR-SEC-6 | `npm audit` runs on every PR; CI fails on any High/Critical |
| NFR-SEC-7 | Tauri capabilities are the minimum set per §13.7; no broader permissions |
| NFR-SEC-8 | CSP per §13.8; CI lints CSP file |
| NFR-SEC-9 | No `eval`, `Function()`, `setTimeout(string)`, `setInterval(string)` in JS |
| NFR-SEC-10 | All Tauri commands validate inputs at the boundary; return typed errors |
| NFR-SEC-11 | Signed Git commits required for maintainer pushes |
| NFR-SEC-12 | Two-maintainer review required for security-sensitive paths (defined in CODEOWNERS) |

## 18.2 Privacy NFRs

| ID | Requirement |
|----|-------------|
| NFR-PRV-1 | App operates locally; no metadata leaves the machine without explicit user action |
| NFR-PRV-2 | Reports generated locally |
| NFR-PRV-3 | User manually controls every export destination |
| NFR-PRV-4 | No analytics |
| NFR-PRV-5 | No hidden network calls (verified by integration test: tcpdump shows no traffic during MVP flows) |
| NFR-PRV-6 | No crash-report upload (user opts in to local file + manual upload) |
| NFR-PRV-7 | xpubs treated as Confidential; redacted in public-safe exports |
| NFR-PRV-8 | Detector findings never include secret content in logs/errors |

## 18.3 Accessibility NFRs

| ID | Requirement |
|----|-------------|
| NFR-A11Y-1 | WCAG 2.2 AA on every screen |
| NFR-A11Y-2 | Keyboard navigation complete; no mouse-only paths |
| NFR-A11Y-3 | Screen-reader tested on NVDA, VoiceOver, Orca |
| NFR-A11Y-4 | Contrast ratios verified by automated CI (`axe-core`) |
| NFR-A11Y-5 | Status conveyed by text + color + icon |
| NFR-A11Y-6 | Large-text mode at 1.5x and 2x |
| NFR-A11Y-7 | `prefers-reduced-motion` respected |
| NFR-A11Y-8 | No flashing content above 3 Hz |

## 18.4 Reliability NFRs

| ID | Requirement |
|----|-------------|
| NFR-REL-1 | Graceful handling of malformed descriptors (no panic, clear error) |
| NFR-REL-2 | Clear error messages for every documented error code |
| NFR-REL-3 | No app crashes on any documented input |
| NFR-REL-4 | Unit tests for parser, detector, scorer ≥ 80% line coverage |
| NFR-REL-5 | Integration tests for every Tier-1 wallet importer |
| NFR-REL-6 | Golden fixtures (descriptor → expected JSON report) for ≥ 50 cases |
| NFR-REL-7 | Deterministic report output (same input + scoring engine version + Lifeboat version = byte-identical JSON) |

## 18.5 Portability NFRs

| ID | Requirement |
|----|-------------|
| NFR-PORT-1 | macOS Universal `.dmg` |
| NFR-PORT-2 | Windows x86_64 `.msi` |
| NFR-PORT-3 | Linux AppImage x86_64 |
| NFR-PORT-4 | Linux `.deb` (v0.1) |
| NFR-PORT-5 | Linux Flatpak (v0.2) |
| NFR-PORT-6 | Linux ARM64 best-effort AppImage |
| NFR-PORT-7 | CLI binaries for each desktop target |
| NFR-PORT-8 | CLI via `cargo install lifeboat-cli` |

## 18.6 Performance NFRs (NORMATIVE)

Targets measured on baseline hardware (M1 Mac, 8 GB RAM; or comparable x86_64).

| Operation | Target |
|-----------|--------|
| Descriptor parse | < 100 ms |
| Address derivation, 100 addresses, singlesig | < 200 ms |
| Address derivation, 100 addresses, 3-of-5 multisig | < 500 ms |
| Address derivation, 1000 addresses, singlesig | < 2 s |
| Full Readiness Check flow (input → report) | < 1 s for typical input |
| PDF report generation | < 3 s |
| App cold launch | < 3 s |
| App memory footprint at idle | < 200 MB |
| Bundle size (desktop installer, per OS) | < 30 MB |

## 18.7 Internationalization

- MVP ships **English only**.
- All user-facing strings live in `apps/desktop/src/i18n/en.json` and `crates/.../strings/en.json`.
- Translation framework: Project Fluent (`fluent-rs`) preferred for Rust side; `i18next` for React side. Strings keyed identically across both.
- v1.0 target: at least 3 community translations live.
- CI lint: no hardcoded user-facing strings outside i18n files.

---

# 19. Data Structures

## 19.1 ReadinessReport JSON Schema (NORMATIVE)

```json
{
  "schema_version": "0.1.0",
  "app_version": "0.1.0",
  "scoring_engine_version": "0.1.0",
  "created_at": "2026-05-28T00:00:00Z",
  "mode": "readiness_check",
  "input_hash": "sha256:abc123...",
  "report_hash": "sha256:def456...",
  "network": "bitcoin",

  "wallet_summary": {
    "wallet_type": "multisig",
    "script_type": "wsh(sortedmulti)",
    "threshold": 2,
    "key_count": 3,
    "has_receive_descriptor": true,
    "has_change_descriptor": false,
    "uses_multipath": false,
    "uses_taproot": false,
    "uses_miniscript": false,
    "uses_timelock": false,
    "passphrase_documented": false
  },

  "descriptors": {
    "receive": {
      "raw": "wsh(sortedmulti(2,[abc...]xpub.../0/*,[def...]xpub.../0/*,[ghi...]xpub.../0/*))#chksum",
      "raw_redacted": "wsh(sortedmulti(2,[abc...]xpub6...XXXX/0/*,[def...]xpub6...XXXX/0/*,[ghi...]xpub6...XXXX/0/*))#chksum",
      "canonical": "wsh(sortedmulti(2,[abc...h/48h/0h/0h/2h]xpub.../0/*,...))#chksum",
      "checksum_present": true,
      "checksum_valid": true,
      "parse_status": "ok"
    },
    "change": null
  },

  "keys": [
    {
      "index": 0,
      "fingerprint": "abc12345",
      "derivation_path": "m/48h/0h/0h/2h",
      "xpub": "xpub6...redacted-in-public-safe...",
      "xpub_redacted": "xpub6...XXXX",
      "key_origin_present": true
    }
  ],

  "addresses": {
    "receive_derived": [
      {"index": 0, "address": "bc1q...", "chain": "receive"},
      {"index": 1, "address": "bc1q...", "chain": "receive"}
    ],
    "change_derived": [],
    "known_address_match": {
      "provided": "bc1q...",
      "matched": true,
      "matched_at": {"index": 3, "chain": "receive"}
    }
  },

  "score": {
    "numeric": 75,
    "status": "mostly_ready",
    "headline": "Mostly Ready"
  },

  "checks": [
    {"code": "A1", "category": "descriptor_parse", "result": "pass", "title": "Descriptor parses as BIP380"},
    {"code": "A2", "category": "descriptor_checksum", "result": "pass", "title": "Descriptor checksum present"},
    {"code": "E2", "category": "change_descriptor", "result": "warn", "title": "Change descriptor missing"}
  ],

  "critical_issues": [],

  "warnings": [
    {
      "code": "W-NO-CHANGE-DESC",
      "title": "Change descriptor missing",
      "description": "A complete recovery backup should include both receive and change descriptors. Without the change descriptor, an empty wallet restore will not see funds returned to change addresses.",
      "recommended_fix": "Export both descriptors from your wallet software. In Sparrow: File > Export Wallet > Output Descriptor. In Bitcoin Core: listdescriptors true."
    }
  ],

  "passes": [
    {"code": "P-DESC-PARSEABLE", "title": "Descriptor parsed successfully"},
    {"code": "P-CHECKSUM-VALID", "title": "Descriptor checksum is valid"},
    {"code": "P-THRESHOLD-CLEAR", "title": "Multisig threshold identified as 2-of-3"},
    {"code": "P-ADDRESS-MATCH", "title": "Known address matched at receive index 3"}
  ],

  "scoring_audit": [
    {"code": "W-NO-CHANGE-DESC", "impact": -15, "running_score": 85},
    {"code": "W-NO-RECENT-DRILL", "impact": -10, "running_score": 75}
  ],

  "survivability": {
    "tested": true,
    "lose_1_signer": "ok",
    "lose_2_signers": "fail_expected_for_2of3",
    "lose_descriptor_only": "ok_if_xpubs_retained"
  },

  "next_steps": [
    {"priority": 1, "action": "Export your change descriptor.", "effort": "5 min"},
    {"priority": 2, "action": "Print two copies of the descriptor backup.", "effort": "10 min"},
    {"priority": 3, "action": "Run a Disaster Drill in Lifeboat v0.3 when available.", "effort": "future"}
  ],

  "anti_actions": [
    "Do not email the descriptor.",
    "Do not store the descriptor in cloud notes apps.",
    "Do not photograph this report and send it on chat."
  ],

  "next_drill_recommendation": "2027-05-28",

  "disclaimer_short": "This report is a diagnostic aid. It is not legal, tax, financial, or security advice. Bitcoin Lifeboat cannot guarantee that any wallet is recoverable.",
  "disclaimer_long": "About this document...[verbatim from §15.6]"
}
```

### Field Conventions

- All timestamps ISO-8601 UTC.
- All hashes prefixed with algorithm (`sha256:`).
- All addresses shown in canonical form (lowercase bech32, mixed-case base58).
- `xpub` fields contain the FULL xpub when mode = private; the redacted form is in `xpub_redacted` regardless. The `public-safe` export simply uses `xpub_redacted` everywhere and omits the `xpub` field.

## 19.2 RunbookTemplate JSON Schema

```json
{
  "template_id": "multisig_2of3_basic",
  "template_version": "0.1.0",
  "title": "2-of-3 Multisig Recovery Runbook",
  "audience": "owner",
  "language": "en",
  "page_size": "a4",
  "sections": [
    {
      "id": "safety",
      "title": "Safety Rules",
      "body_markdown": "Never type seed words into a website..."
    },
    {
      "id": "materials",
      "title": "Required Materials",
      "items": [
        "Signer A (hardware wallet, location: __________)",
        "Signer B (hardware wallet, location: __________)",
        "Wallet descriptor backup (location: __________)",
        "Clean computer with Bitcoin Lifeboat installed",
        "Destination address (write here: __________)"
      ]
    }
  ],
  "blank_fields": ["signer_a_location", "signer_b_location", "descriptor_location"]
}
```

## 19.3 NormalizedWalletExport Schema

```json
{
  "source_wallet": "sparrow",
  "source_wallet_version": "2.5.1",
  "imported_at": "2026-05-28T00:00:00Z",
  "descriptors": {
    "receive": "...",
    "change": "..."
  },
  "keys": [...],
  "birth_height": 815000,
  "birth_timestamp": "2024-01-15T00:00:00Z",
  "gap_limit": 20,
  "labels": [
    {"type": "addr", "ref": "bc1q...", "label": "Cold storage"}
  ],
  "wallet_type": "multisig",
  "threshold": 2,
  "key_count": 3,
  "raw_source_filename": "wallet.json"
}
```

## 19.4 DetectorReport Schema

```json
{
  "schema_version": "0.1.0",
  "action": "block",
  "findings": [
    {
      "kind": "bip39",
      "language": "english",
      "word_count": 12,
      "checksum_valid": true,
      "byte_range": [142, 213]
    }
  ],
  "user_facing_message": "This looks like a real Bitcoin seed phrase. Lifeboat does not need this. The input has been cleared."
}
```

**Note: `byte_range` is only present in the API result; it is NEVER serialized to logs or exported reports.**

## 19.5 DrillResult Schema (v0.3+)

```json
{
  "schema_version": "0.1.0",
  "drill_id": "uuid-v4",
  "scenario": "DS-6",
  "scenario_title": "One multisig signer unavailable",
  "started_at": "2026-05-28T10:00:00Z",
  "completed_at": "2026-05-28T10:42:00Z",
  "result": "pass",
  "wallet_type": "multisig_2of3",
  "steps": [
    {"step": "import_descriptor", "result": "pass"},
    {"step": "sign_with_2_signers", "result": "pass"},
    {"step": "finalize_psbt", "result": "pass"}
  ],
  "report_hash": "sha256:..."
}
```

---

# 20. Repository Structure (NORMATIVE)

```
bitcoin-lifeboat/
├── README.md
├── LICENSE                          # MIT
├── SECURITY.md                      # PGP key, disclosure address, 90-day window
├── CONTRIBUTING.md                  # DCO required, code style, review process
├── CODE_OF_CONDUCT.md               # Contributor Covenant 2.1
├── ROADMAP.md                       # links to milestones, not feature list
├── CHANGELOG.md                     # Keep-a-Changelog format
├── CODEOWNERS                       # security-sensitive paths require 2 maintainers
├── Cargo.toml                       # workspace
├── Cargo.lock                       # committed
├── rust-toolchain.toml              # pins Rust 1.78 (MSRV)
├── .nvmrc                           # pins Node version
├── deny.toml                        # cargo-deny config
│
├── apps/
│   ├── desktop/                     # Tauri app
│   │   ├── src-tauri/
│   │   │   ├── Cargo.toml
│   │   │   ├── tauri.conf.json
│   │   │   ├── capabilities/
│   │   │   │   └── default.json
│   │   │   ├── icons/
│   │   │   └── src/
│   │   │       ├── main.rs          # Tauri commands wiring core crates
│   │   │       └── error.rs
│   │   ├── src/                     # React/TS
│   │   │   ├── App.tsx
│   │   │   ├── pages/
│   │   │   ├── components/
│   │   │   ├── i18n/en.json
│   │   │   └── lib/
│   │   ├── package.json
│   │   ├── package-lock.json
│   │   ├── vite.config.ts
│   │   ├── tailwind.config.js
│   │   └── tsconfig.json
│   │
│   └── docs-site/                   # Astro static site
│       ├── astro.config.mjs
│       ├── src/
│       └── public/
│
├── crates/
│   ├── lifeboat-core/               # facade re-exports + shared types
│   ├── descriptor-audit/            # parsing, normalization, checksum
│   ├── readiness-score/             # scoring engine + audit trail
│   ├── address-derive/              # derivation, known-address comparison
│   ├── wallet-imports/              # per-wallet importers
│   ├── sensitive-input-detector/    # secret detection
│   ├── report-engine/               # JSON, Markdown, HTML rendering
│   ├── runbook-engine/              # Typst-based PDF generation
│   ├── error-taxonomy/              # error codes + i18n keys
│   ├── psbt-drill/                  # v0.2
│   ├── signet-lab/                  # v0.2 (bdk_wallet dep here)
│   ├── hwi-bridge/                  # v0.4 (subprocess sidecar wrapper)
│   ├── qr-psbt/                     # v0.3 (ur + bbqr)
│   └── miniscript-viz/              # v0.5 (Liana visualization)
│
├── cli/
│   └── lifeboat/                    # binary crate
│       ├── Cargo.toml
│       ├── src/
│       │   ├── main.rs
│       │   ├── commands/
│       │   │   ├── audit_descriptor.rs
│       │   │   ├── derive_addresses.rs
│       │   │   ├── compare_address.rs
│       │   │   ├── generate_runbook.rs
│       │   │   ├── report_json.rs
│       │   │   ├── detect_secrets.rs
│       │   │   ├── parse_export.rs
│       │   │   └── checksum.rs
│       │   ├── output.rs            # JSON vs human output
│       │   └── exit_codes.rs
│       └── tests/
│
├── fixtures/
│   ├── descriptors/
│   │   ├── singlesig/
│   │   │   ├── wpkh_valid.txt
│   │   │   ├── pkh_valid.txt
│   │   │   ├── sh_wpkh_valid.txt
│   │   │   ├── tr_key_path.txt          # Taproot
│   │   │   └── invalid_checksum.txt
│   │   ├── multisig/
│   │   │   ├── wsh_sortedmulti_2of3.txt
│   │   │   ├── wsh_sortedmulti_3of5.txt
│   │   │   ├── multipath_2of3.txt       # BIP389
│   │   │   ├── duplicate_xpub.txt
│   │   │   └── threshold_exceeds_keys.txt
│   │   ├── timelock/
│   │   │   └── liana_basic.txt          # v0.5 testing
│   │   ├── invalid/
│   │   │   ├── contains_xprv.txt
│   │   │   ├── unparseable.txt
│   │   │   └── network_mixed.txt
│   │   └── taproot/
│   │       ├── tr_keypath.txt
│   │       └── tr_scriptpath_multi_a.txt
│   ├── wallet_exports/
│   │   ├── bitcoin_core_listdescriptors.json
│   │   ├── sparrow_singlesig.json
│   │   ├── sparrow_multisig.json
│   │   ├── specter_multisig.json
│   │   ├── liana_v13_backup.bed
│   │   ├── nunchuk_bsms.txt
│   │   ├── coldcard_generic.json
│   │   ├── coldcard_descriptor.txt
│   │   ├── passport_descriptor.txt
│   │   ├── jade_multisig.json
│   │   ├── bluewallet_vault.txt
│   │   └── electrum_multisig.txt
│   ├── addresses/
│   │   ├── known_match_bc1.txt
│   │   └── known_match_tb1.txt
│   ├── secrets/                       # used by detector fuzzer ONLY
│   │   ├── bip39_english_12.txt
│   │   ├── bip39_english_24.txt
│   │   ├── bip39_japanese_12.txt
│   │   ├── wif_mainnet.txt
│   │   ├── xprv_mainnet.txt
│   │   ├── slip39_share_20w.txt
│   │   └── codex32_128bit.txt
│   ├── reports/
│   │   ├── singlesig_ready.json
│   │   ├── multisig_warn_no_change.json
│   │   ├── multisig_not_ready_missing_threshold.json
│   │   └── cannot_determine_ambiguous_network.json
│   └── runbooks/
│       ├── singlesig_basic_expected.pdf  # hash only; PDF binary in CI artifact
│       └── multisig_2of3_expected.md
│
├── docs/
│   ├── safety-model.md
│   ├── threat-model.md
│   ├── architecture.md
│   ├── descriptor-audit.md
│   ├── scoring.md
│   ├── psbt-drills.md                  # v0.2 doc
│   ├── signet-practice.md              # v0.2 doc
│   ├── hardware-wallet-drill.md        # v0.3 doc
│   ├── heir-mode.md
│   ├── recovery-day.md
│   ├── wallet-compatibility.md
│   ├── reproducible-builds.md
│   ├── cli-reference.md
│   ├── json-schemas.md
│   └── error-codes.md
│
├── templates/
│   └── runbooks/
│       ├── singlesig-basic.typ
│       ├── singlesig-passphrase.typ
│       ├── multisig-2of3.typ
│       ├── multisig-3of5.typ
│       ├── heir-singlesig-basic.typ
│       ├── heir-singlesig-passphrase.typ
│       ├── heir-multisig-2of3.typ
│       ├── heir-multisig-3of5.typ
│       ├── meetup-workshop.typ
│       ├── business-treasury.typ
│       └── liana-timelock.typ          # v0.5
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── release.yml
│   │   ├── security.yml
│   │   ├── fuzz.yml
│   │   └── docs.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── security_concern.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml
│
└── fuzz/
    ├── Cargo.toml
    ├── fuzz_targets/
    │   ├── fuzz_descriptor_parser.rs
    │   ├── fuzz_detector_arbitrary.rs
    │   ├── fuzz_detector_false_positive.rs
    │   ├── fuzz_detector_false_negative.rs
    │   └── fuzz_descriptor_with_xprv.rs
    └── corpus/
```

### Crate Dependency Graph (NORMATIVE)

```
lifeboat-cli ─────┐
                  ├──► lifeboat-core
desktop (Tauri) ──┘            │
                               ├──► descriptor-audit ────► rust-miniscript, rust-bitcoin
                               ├──► readiness-score ────► (none external)
                               ├──► address-derive ─────► rust-miniscript
                               ├──► wallet-imports ─────► serde_json, descriptor-audit
                               ├──► sensitive-input-detector ──► zeroize, bip39, bitcoin
                               ├──► report-engine ──────► serde, handlebars
                               ├──► runbook-engine ─────► typst (bundled binary)
                               └──► error-taxonomy ─────► thiserror
```

No crate depends on Tauri. Tauri lives only in `apps/desktop/src-tauri/`.

---

# 21. Architecture

## 21.1 High-Level (NORMATIVE)

```
┌─────────────────────────────────────────────────────────────┐
│  Desktop UI (React + TS + Tailwind, inside Tauri webview)   │
│  ─────────────────────────────────────────────────────────  │
│  • Pages: Home, Readiness Check, Multisig Audit,            │
│    Create Heir Runbook, Generate Runbook, Learn, Settings   │
│  • State: zustand store (in-memory; no localStorage of      │
│    Confidential data)                                       │
│  • i18n: i18next                                            │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Tauri IPC (typed commands)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Tauri Command Layer (Rust, src-tauri/src/)                 │
│  ─────────────────────────────────────────────────────────  │
│  • Translates JSON args → Rust types                        │
│  • Wraps Confidential values in SecretString                │
│  • Maps errors to LifeboatError → JSON                      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Rust Core Crates (no Tauri dependency)                     │
│  ─────────────────────────────────────────────────────────  │
│  descriptor-audit │ readiness-score │ address-derive       │
│  wallet-imports   │ sensitive-input-detector               │
│  report-engine    │ runbook-engine                          │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  External (only when user-initiated)                        │
│  ─────────────────────────────────────────────────────────  │
│  • OS file dialog → file read/write                         │
│  • PDF export to user-chosen path                           │
│  • Browser launch for help links (uses OS handler)          │
└─────────────────────────────────────────────────────────────┘
```

## 21.2 Core Design Rule

The frontend **must never implement Bitcoin logic.** Every operation on a descriptor, key, address, or report happens in Rust.

The frontend's only responsibilities:
- Render UI.
- Collect inputs.
- Pass typed messages to Rust via Tauri commands.
- Display typed results.

Specifically forbidden in the frontend:
- Descriptor parsing.
- Address derivation.
- Checksum validation.
- Secret detection.
- Score calculation.
- PDF generation.
- Cryptographic operations of any kind.

This is enforced by CI: any frontend file importing `bitcoinjs-lib`, `@scure/btc-signer`, or similar fails the build.

## 21.3 Tauri Commands (NORMATIVE)

The full command surface for MVP:

```rust
// In apps/desktop/src-tauri/src/commands.rs

#[tauri::command]
async fn audit_descriptor(input: DescriptorAuditInput)
    -> Result<ReadinessReport, LifeboatError>;

#[tauri::command]
async fn derive_addresses(input: AddressDeriveInput)
    -> Result<DerivedAddressList, LifeboatError>;

#[tauri::command]
async fn compare_address(input: AddressCompareInput)
    -> Result<AddressCompareResult, LifeboatError>;

#[tauri::command]
async fn detect_sensitive_input(input: String)
    -> Result<DetectorReport, LifeboatError>;

#[tauri::command]
async fn parse_wallet_export(file_path: String)
    -> Result<NormalizedWalletExport, LifeboatError>;

#[tauri::command]
async fn validate_checksum(descriptor: String)
    -> Result<ChecksumValidation, LifeboatError>;

#[tauri::command]
async fn compute_checksum(descriptor: String)
    -> Result<String, LifeboatError>;

#[tauri::command]
async fn generate_report(input: ReportGenerationInput, format: ReportFormat)
    -> Result<ReportArtifact, LifeboatError>;

#[tauri::command]
async fn generate_runbook(input: RunbookGenerationInput)
    -> Result<RunbookArtifact, LifeboatError>;

#[tauri::command]
async fn save_export(path: String, content: Vec<u8>)
    -> Result<(), LifeboatError>;

#[tauri::command]
async fn open_external_link(url: String)
    -> Result<(), LifeboatError>;  // delegates to OS; URL validated against allowlist

#[tauri::command]
async fn get_app_info()
    -> Result<AppInfo, LifeboatError>;
```

All inputs validated at the boundary. All outputs serializable to JSON. All errors are typed `LifeboatError` (§Appendix C).

### External Link Allowlist

`open_external_link` accepts only URLs matching:

```
https://github.com/<org>/bitcoin-lifeboat
https://github.com/<org>/bitcoin-lifeboat/releases
https://github.com/<org>/bitcoin-lifeboat/issues
https://bitcoinlifeboat.org
https://bitcoinlifeboat.org/docs/*
```

Any other URL returns error `E-LINK-NOT-ALLOWED`.

## 21.4 State Management

### Rust Side

Stateless. Each Tauri command receives all inputs needed; returns results. No global mutable state except:
- Tauri's `AppHandle`.
- Read-only configuration loaded at startup.

### React Side

State store: **Zustand** (lightweight, TypeScript-first).

Confidential-classified data lives only in the store while the user is on the screen that produced it. Navigating away clears it. The store is **never** persisted to localStorage, sessionStorage, or IndexedDB.

Public-classified data (theme, language, advanced-toggle) persists to Tauri's settings file via the `os` plugin path.

## 21.5 Error Handling Architecture

Every error in the system has:

1. A stable error code (`E-XXX-NNN`).
2. A typed Rust variant in `LifeboatError`.
3. An i18n key for user-facing display.
4. A documentation entry in `docs/error-codes.md`.
5. A "what to do" recommendation.

Error code taxonomy:

```
E-INPUT-*    User input errors (correctable by user)
E-PARSE-*    Descriptor/file parsing errors
E-SECRET-*   Sensitive input detection
E-NETWORK-*  Network-related (never fires in MVP without user action)
E-FS-*       File system errors
E-INTERNAL-* Internal bugs (file a GitHub issue)
E-DEP-*      External dependency errors (e.g., Typst missing)
E-LINK-*     External link safety
```

See Appendix C for the complete error catalog.

---

# 22. UI Requirements

## 22.1 Primary Navigation

Left sidebar OR home dashboard cards:

```
Home
├── Run a Readiness Check
├── Audit Multisig Setup
├── Create Heir Runbook
├── Generate Runbook
├── Learn
└── Settings
```

Settings includes: theme, language, advanced details toggle, diagnostic mode toggle, recent files toggle (v0.2+), about, clear all local data button.

## 22.2 Dashboard Cards (Home)

Five cards, in this order, with these exact labels:

1. **"Check My Backup Plan"** — primary entry to Readiness Check
2. **"Audit My Multisig Setup"** — same flow with multisig-first wizard
3. **"Create a Family Drill / Heir Runbook"** — heir runbook generator
4. **"Print a Recovery Runbook"** — runbook generator for any template
5. **"Practice Recovery Safely"** — disabled in MVP, label changes to "Available in v0.2"

Each card has:
- Title (large, sans-serif)
- One-sentence description (medium)
- Status icon (book / shield / family / printer / play)
- Estimated time ("~5 minutes")
- Required materials hint ("You'll need: your wallet descriptor")

## 22.3 Status UI

Use status badges:

| Badge | Color | Icon | Text |
|-------|-------|------|------|
| Ready | Green (`#0f7a3f`) | ✓ in circle | Ready |
| Mostly Ready | Light green (`#5aa36b`) | ✓ in circle | Mostly Ready |
| Needs Attention | Amber (`#c87a00`) | ! in triangle | Needs Attention |
| Not Ready | Red (`#b91c1c`) | ✕ in circle | Not Ready |
| Cannot Determine | Gray (`#6b7280`) | ? in circle | Cannot Determine |

Color values verified against WCAG AA (4.5:1 contrast on white).

## 22.4 Network Banner (NORMATIVE)

The current network is displayed as a banner across the top of every screen handling wallet data:

```
[ MAINNET ]   red banner
[ TESTNET ]   yellow banner
[ SIGNET  ]   yellow banner
[ REGTEST ]   gray banner
```

The banner is impossible to dismiss. It changes color the instant network changes.

## 22.5 Report Section Layout

Every report section includes:

1. Plain-English summary (one sentence).
2. Status badge (per §22.3).
3. "Show technical details" expander (default closed).
4. Recommended fix block (action-oriented).
5. "Learn more" link to in-app docs.
6. "Copy explanation" button.

## 22.6 Safety Banner

Visible in all real-wallet audit modes:

```
┌─────────────────────────────────────────────────────────────┐
│ ⚠  Do not paste seed words, private keys, or passphrases.   │
│   This mode needs only your public wallet metadata          │
│   (descriptor, xpubs, derivation paths).                    │
└─────────────────────────────────────────────────────────────┘
```

Persistent at top of the input area. Not dismissible.

## 22.7 Sensitive-Input Block Dialog

When the detector returns `Block`:

```
┌─────────────────────────────────────────────────────────────┐
│  ✕  This looks like a real Bitcoin secret                   │
│                                                              │
│  Bitcoin Lifeboat does not need seed phrases, private keys, │
│  or passphrases for this check.                             │
│                                                              │
│  For your safety, what you pasted has been cleared. The     │
│  app did not store or transmit it.                          │
│                                                              │
│  What we detected: a 12-word BIP39 mnemonic with valid      │
│  checksum.                                                  │
│                                                              │
│  What to do:                                                 │
│   1. Close this dialog                                       │
│   2. Open your wallet software                              │
│   3. Export the OUTPUT DESCRIPTOR (not the seed)            │
│   4. Paste the descriptor here                              │
│                                                              │
│  Need help? Learn how to export descriptors from popular    │
│  wallets: [Sparrow] [Bitcoin Core] [Specter] [Coldcard]     │
│                                                              │
│                                              [ I understand ]│
└─────────────────────────────────────────────────────────────┘
```

The detected secret content is never displayed. The dialog cannot be dismissed by pressing Escape (must click "I understand").

## 22.8 Wizard Layout

The Readiness Check wizard has 8 steps:

```
1. Choose wallet type (singlesig / multisig / Liana / unsure)
2. Choose input method (paste / file / use sample)
3. Paste or load descriptor (with safety banner)
4. Optional: provide known receive address
5. Optional: provide passphrase-exists Y/N (never the value)
6. Optional: answer 9 recovery-completeness questions (skippable; each skip = warning)
7. Review report
8. Export (PDF / Markdown / JSON / both modes)
```

Each step has Back / Next, an indicator (Step 3 of 8), and a "Save and quit" button (does not actually save Confidential data; just exits cleanly).

## 22.9 Empty States and Sample Data

Every input that requires wallet data has a **"Use sample descriptor"** link. Clicking loads a known-good fixture so the user can experience the flow before pasting their own data. Sample descriptors are clearly marked `[ SAMPLE ]` in the UI.

## 22.10 Dark Mode + Light Mode

Both modes match WCAG AA contrast. System mode follows OS preference. User can override in Settings.

## 22.11 What Lives on Each Screen

| Screen | What it does | What it doesn't do |
|--------|--------------|-------------------|
| Home | Cards + recent reports list (v0.2+) | No descriptors visible here |
| Readiness Check wizard | Walks user through audit | Does not store anything between sessions |
| Audit Multisig | Same wizard, multisig-first defaults | Does not coordinate signing |
| Create Heir Runbook | Template chooser + blank-fill UI | Does not contact heirs |
| Generate Runbook | Standalone runbook generator | Does not run a drill |
| Learn | In-app docs | Does not link to external content other than the allowlist |
| Settings | Theme, language, advanced toggle, diagnostic toggle | Does not have "import all my data" feature |

---

# 23. CLI Requirements (Extended)

## 23.1 CLI Style

The CLI is **serious, scriptable, predictable.**

Principles:

1. Default output is human-readable. `--json` switches to machine-readable.
2. JSON output is **stable within a major version**.
3. Exit codes are stable across all versions.
4. No interactive prompts by default. Add `--interactive` to opt in.
5. No network access in any command in MVP.
6. Secrets are never written to terminal output; the detector runs on all `--descriptor` arguments and `--file` contents.

## 23.2 Exit Code Table (NORMATIVE)

| Code | Meaning | Triggered By |
|------|---------|--------------|
| 0 | Success / Ready | All checks pass; no warnings (or `--strict` not set and only warnings) |
| 1 | Warnings (Mostly Ready or Needs Attention) | Score 40–89 |
| 2 | Critical / Not Ready | Score 0–39 OR any critical check fails |
| 3 | Cannot Determine | Insufficient info to render verdict |
| 4 | Invalid CLI arguments | Bad flags, missing required args |
| 5 | Sensitive input detected | Detector returned `Block` |
| 6 | File not found / I/O error | Filesystem error |
| 7 | External dependency missing | Typst not bundled / not found |
| 10 | Unknown subcommand | typo in command |
| 20 | Internal error (bug) | panic caught; file an issue |

`--strict` mode treats exit-1 as exit-2 (useful in CI).

## 23.3 Output Formatting

### Human Output

- Uses ANSI colors by default (disable with `--no-color` or `NO_COLOR=1`).
- Uses Unicode box-drawing for tables.
- Status badges are colored.
- Errors go to stderr; successful output to stdout.

### JSON Output

- Strict JSON (no comments, no trailing commas).
- UTF-8.
- Pretty-printed when stdout is a TTY; minified when piped (unless `--pretty` is set).
- Deterministic key order.

### Logging

- `--verbose` enables INFO-level logging to stderr.
- `--debug` enables DEBUG-level (still scrubs Confidential).
- Secrets are NEVER logged. The detector blocks them before they reach a log.

## 23.4 Distribution

| Channel | Status |
|---------|--------|
| GitHub Releases (binary download) | v0.1 |
| `cargo install lifeboat-cli` | v0.1 |
| Bundled with desktop installer (PATH) | v0.1 |
| Homebrew formula (`brew install bitcoin-lifeboat`) | v0.2 |
| Debian `.deb` (apt repo) | v0.2 |
| Arch AUR | v0.3 (community-maintained) |
| Nix package | v0.3 (community-maintained) |
| Scoop bucket (Windows) | v0.3 |

## 23.5 Man Pages

Generated via `clap_mangen` build script. Installed by:
- `.deb`: `/usr/share/man/man1/lifeboat.1`
- Homebrew: standard formula install
- `cargo install`: not auto-installed; documented manual step

## 23.6 Shell Completions

Generated via `clap_complete`. Available via:

```
lifeboat completions bash      > /etc/bash_completion.d/lifeboat
lifeboat completions zsh       > "${fpath[1]}/_lifeboat"
lifeboat completions fish      > ~/.config/fish/completions/lifeboat.fish
lifeboat completions powershell > $PROFILE
lifeboat completions nushell   > ~/.config/nushell/completions/lifeboat.nu
```

## 23.7 CI Integration

Wallet developers can use the CLI in their CI:

```yaml
- name: Verify wallet export compatibility
  run: |
    ./my-wallet export > export.json
    lifeboat parse-export --file export.json --json > parsed.json
    lifeboat audit-descriptor --file parsed.json --strict --json
```

The `--strict` flag fails CI on any warning. The `--json` output is the contract.

## 23.8 Reproducibility

`lifeboat report-json --descriptor <fixture> --scoring-engine 0.1.0` produces byte-identical JSON across all platforms for any fixture in `fixtures/descriptors/`. Golden tests in CI enforce this for the ~50 fixtures shipped with MVP.

---

# 24. Wallet Compatibility Matrix (NORMATIVE)

## 24.1 Tier Definitions

- **Tier 1**: First-class support. App ships an importer; round-trip tests in CI.
- **Tier 2**: Manual workaround documented; users export descriptor and paste manually.
- **Tier 3**: Cannot be supported without upstream fixes; user is told why and given the Sparrow/Specter escape hatch.

## 24.2 v0.1 Matrix

| Wallet | Min version | Tier | Export format | Receive+change? | Origin info? | Birth height? | Notes |
|--------|-------------|------|---------------|-----------------|--------------|---------------|-------|
| Bitcoin Core | 29.0+ (NOT 30.0 / 30.1) | 1 | `listdescriptors` JSON | yes (separate active descriptors) | yes | timestamp only | RPC call OR file paste |
| Sparrow | 2.5.0+ | 1 | Sparrow JSON | yes (multipath) | yes | ISO date | File > Export Wallet |
| Specter Desktop | 2.1.0+ | 1 | Specter JSON | yes | yes | `blockheight` | Wallet > Settings > Export |
| Liana | 13.0+ | 1 | `.bed` (encrypted) | yes | yes | timestamp | User provides decryption inputs (own xpubs) |
| Nunchuk | 1.9+ | 1 | BSMS (BIP129) | yes | yes | no | Wallet > More > Export wallet config > BSMS |
| Coldcard | current firmware | 1 | Generic Wallet Export JSON + Descriptor + .sig | yes | yes | no | SD: Advanced > Export Wallet > Descriptor |
| Passport Core | 2025+ | 1 | Descriptor file / QR | yes | yes | no | QR in v0.3; file in MVP |
| Jade | 1.0.38+ | 1 | Multisig registered wallet JSON | yes | yes | no | Options > Wallet > Registered Wallets > Export |
| Electrum | 4.5.6+ | 2 | Coldcard-style text (multisig) | partial | partial | no | Use Sparrow/Specter as intermediary, or paste raw descriptor |
| BlueWallet | current | 2 | Coldcard-style text | partial | partial | no | Same workaround as Electrum |
| SeedSigner | 0.8.x | 2 | (signer only, not a coordinator) | N/A | N/A | N/A | Use as signer with another coordinator |
| Trezor Suite | current | 2 | xpub copy/paste | no (manual) | no (manual) | no | Construct descriptor manually with template |
| Ledger Live | current | 3 | None usable | no | no | no | Tell user: register Ledger in Sparrow/Specter, export from there |

## 24.3 Export Instructions (User-Facing Docs)

`docs/wallet-compatibility.md` contains step-by-step instructions for each Tier-1 wallet:

- Exact menu paths.
- Screenshots (in v0.2+; text-only acceptable for MVP).
- Sample output snippets.
- Notes on which fields the wallet does and does not export.

## 24.4 Compatibility Testing

For each Tier-1 wallet, the project maintains:

- A real exported file (anonymized, mainnet replaced with regtest where possible) in `fixtures/wallet_exports/`.
- An integration test that imports the file and asserts the resulting `NormalizedWalletExport` has correct fields.
- A documented "tested with wallet version X.Y.Z on date Z" record in `docs/wallet-compatibility.md`.

Wallet version coverage is re-tested quarterly. Quarterly retest is a maintainer task; community contributors can submit updated fixtures.

## 24.5 Adding New Wallet Support

Contribution guide for adding a new wallet importer:

1. Add real export fixture(s) to `fixtures/wallet_exports/`.
2. Add importer module in `crates/wallet-imports/src/`.
3. Add integration test asserting NormalizedWalletExport correctness.
4. Update `docs/wallet-compatibility.md` with export instructions.
5. Update the matrix in this PRD.

A new importer requires 2-maintainer review (Confidential-data handling).

---

# 25. Testing Requirements

## 25.1 Test Categories

| Category | Where | Threshold |
|----------|-------|-----------|
| Unit (Rust) | `crates/**/src/` inline + `crates/**/tests/` | ≥ 80% line coverage per crate |
| Integration (Rust) | `crates/**/tests/integration/` | Every Tauri command + every CLI command |
| Snapshot (Rust) | via `insta` crate | ≥ 50 golden ReadinessReport fixtures |
| Fuzz (Rust) | `fuzz/` | All listed targets, 5 min/PR, 1 hour/release |
| Component (React) | `apps/desktop/src/**/__tests__/` | Every page + every interactive component |
| E2E (Playwright via webdriver) | `apps/desktop/e2e/` | Full Readiness Check flow + Heir runbook generation |
| Accessibility (axe-core) | runs in E2E | Zero AA violations |
| Security (cargo audit + cargo deny + npm audit) | per PR | Zero High/Critical |
| Reproducibility | golden JSON output | byte-identical |

## 25.2 Required Unit Tests (per crate)

- **descriptor-audit**: parsing of every BIP380 expression in §17.2, checksum validation, normalization round-trip, sortedmulti ordering, duplicate-xpub detection, key-origin extraction.
- **readiness-score**: each warning and each critical check produces correct status, scoring algorithm transparency, "Cannot Determine" conditions, multisig survivability calculation.
- **address-derive**: address derivation for every script type, network inference, known-address comparison hit/miss across receive/change.
- **sensitive-input-detector**: BIP39 detection for all 10 languages (12/15/18/21/24 words; checksum valid + invalid), WIF detection (mainnet + testnet, compressed + uncompressed), xprv detection (all kinds, both networks), raw hex with context, SLIP-39, codex32, false-positive corpus (English Wikipedia, Linux dictionary, large descriptor files).
- **wallet-imports**: each Tier-1 wallet fixture imports correctly, malformed files rejected with typed errors.
- **report-engine**: JSON schema validity, Markdown rendering, anti-action lint (no banned words like "safe"), deterministic output.
- **runbook-engine**: Typst compilation for every template, blank-field rendering, mode toggle (public-safe vs private).

## 25.3 Required Integration Tests

- Full Readiness Check on each Tier-1 wallet fixture; expected ReadinessReport JSON pinned in `fixtures/reports/`.
- Sensitive-input detector blocks every fixture in `fixtures/secrets/`.
- CLI commands produce expected exit codes and JSON for fixture inputs.
- File size limit enforcement (10 MB) for wallet imports.
- Malformed JSON imports fail gracefully with typed error.

## 25.4 Snapshot Tests

Use the `insta` crate. Snapshots committed to git. CI runs `insta test --review` in fail-on-diff mode.

Snapshot targets:
- ReadinessReport JSON for each fixture descriptor.
- Markdown report for each fixture.
- DetectorReport for each fixture secret.
- Human CLI output for `audit-descriptor --no-color` on each fixture.

PDF snapshots are by SHA256 hash of generated content; visual regression handled by a separate manual review milestone.

## 25.5 Fuzz Targets

Run on every PR for 5 minutes; on every release-tagged build for 1 hour each. Corpus committed under `fuzz/corpus/`.

```
fuzz_descriptor_parser            (rust-miniscript Descriptor::from_str)
fuzz_detector_arbitrary           (random byte slices → must not panic)
fuzz_detector_false_positive      (English corpus → zero Block)
fuzz_detector_false_negative      (mutated valid secrets → must Block)
fuzz_descriptor_with_xprv         (descriptors containing private keys)
fuzz_wallet_export_json_sparrow   (mutated Sparrow JSON)
fuzz_wallet_export_json_specter   (mutated Specter JSON)
fuzz_bsms_parser                  (mutated BSMS)
fuzz_typst_template_input         (template variables)
fuzz_cli_args                     (random argv)
```

## 25.6 Cross-Platform CI Matrix

```yaml
matrix:
  os: [macos-14, macos-13, windows-latest, ubuntu-22.04, ubuntu-24.04]
  rust: [stable, 1.78.0]
  node: [20.x, 22.x]
```

Every matrix entry runs unit + integration + snapshot tests. Linux ARM64 best-effort via cross-compilation in a separate job.

## 25.7 Security Scanning

- `cargo audit` — runs on every PR; fail on Medium+
- `cargo deny check advisories` — same
- `cargo deny check licenses` — fail on disallowed license (allowed list: MIT, Apache-2.0, BSD-2/3, ISC, Unlicense, MPL-2.0; no GPL transitive deps allowed)
- `cargo deny check sources` — fail on dependencies not from crates.io or vetted Git
- `cargo deny check bans` — fail on banned crate version
- `npm audit --audit-level=high` — fail on High/Critical
- `osv-scanner` — scans Cargo.lock + package-lock.json against OSV.dev
- `gitleaks` — scans repo for accidentally committed secrets
- `semgrep` — runs the project ruleset (`semgrep-rules/rust-bitcoin.yml` if available; otherwise default ruleset)

## 25.8 No-Network Verification Test

Run the full E2E suite under `unshare -n` (Linux) or `pktap` filter and assert zero TCP/UDP egress. This test runs on every release-tagged build.

## 25.9 Test Data Policy

- All fixture descriptors use **regtest** or **signet** keys (never mainnet).
- BIP39 detector test cases use the documented test vectors from the BIP39 spec — never real seeds.
- No screenshot of real wallet data is committed.
- Anonymization checklist in `CONTRIBUTING.md`.

## 25.10 Performance Tests

Benchmarks via `criterion`. Targets enforced in CI (within 20% tolerance):

- Descriptor parse: < 100 ms (target), < 120 ms (CI ceiling).
- Address derivation, 100 receive + 100 change, 3-of-5 multisig: < 500 ms.
- Full Readiness Check flow: < 1 s.
- PDF runbook generation: < 3 s.

Regressions fail CI.

## 25.11 Hardware Wallet Test Strategy (v0.3+)

For v0.3+:
- Maintain a manually curated compatibility matrix: each device tested at each release.
- CI runs against device emulators where available (Trezor emulator, Coldcard simulator, Jade emulator, BitBox02 simulator).
- Real-device testing tracked in `docs/wallet-compatibility.md` with date + tester.

## 25.12 What Tests Do NOT Cover

- Whether a real hardware wallet works (we test descriptor/PSBT compatibility, not device physics).
- Whether the user's printed paper is still legible.
- Real mainnet PSBT signing (never).

---

# 26. Release Requirements

## 26.1 MVP Release Artifacts

| Artifact | Format | Signed by | Channel |
|----------|--------|-----------|---------|
| macOS desktop | Universal `.dmg` | Apple Developer ID + notarytool + minisign + cosign | GitHub Releases |
| Windows desktop | `.msi` | OV cert (cloud HSM) + minisign + cosign | GitHub Releases |
| Linux desktop | AppImage | minisign + cosign (+ optional GPG) | GitHub Releases |
| Linux desktop | `.deb` | dpkg-sig + minisign + cosign | GitHub Releases |
| CLI binary | per platform | minisign + cosign | GitHub Releases |
| Source tarball | `.tar.gz` | minisign + cosign | GitHub Releases |
| Cargo crate | crates.io | crates.io OIDC | crates.io |
| Checksums file | SHA256SUMS | minisign + cosign | GitHub Releases |
| SBOM | SPDX + CycloneDX JSON | cosign attestation | GitHub Releases |
| Release notes | Markdown | — | GitHub Releases body |
| Build provenance | SLSA L3 attestation | cosign keyless | GitHub Releases |

## 26.2 Versioning

Semantic versioning. Schema and CLI versions tracked independently from app version when behavior may differ:

```
App version:          0.1.0, 0.2.0, ...
Report schema:        0.1.0   (bumped on JSON breaking changes)
Runbook schema:       0.1.0
Scoring engine:       0.1.0   (bumped on scoring weight/algorithm change)
CLI surface:          0.1.0   (bumped on flag changes; CLI exit codes never break)
```

## 26.3 Release Channels

| Channel | Audience | Stability promise |
|---------|----------|-------------------|
| Alpha (`0.x.0-alpha.N`) | Maintainers, early testers | None |
| Beta (`0.x.0-beta.N`) | Community testers | Functionality works; bugs expected |
| Stable (`0.x.0`) | All users | Production-ready for the MVP scope; security-supported |

Pre-v1.0: every release is labeled "Alpha" or "Beta" on the website with a yellow banner. v1.0 is the first "Stable" release and depends on the security audit.

## 26.4 Release Process

1. Tag commit with `vX.Y.Z`.
2. GitHub Actions release workflow:
   - Cross-platform build matrix.
   - Run full test suite.
   - Sign artifacts (macOS notarize, Windows OV-sign, minisign all).
   - Upload to GitHub Release with auto-generated changelog.
   - Publish cosign attestations (build provenance, SBOM).
   - `cargo publish` for CLI crate.
3. Two-maintainer approval required to dispatch the release workflow (GitHub Environments + protection rules).
4. Update download page on website.
5. Send security mailing list announcement.

## 26.5 Reproducible Build Roadmap

- v0.1: build instructions documented; reproducibility not yet asserted.
- v0.4: Rust core hashes reproducible.
- v1.0: full Tauri bundle reproducibility (Guix-style or Nix-based).
- v1.0: public verification script: `lifeboat verify-build vX.Y.Z` matches official hashes.

## 26.6 Old Release Deprecation

- Security advisories published for any release with a known critical vulnerability.
- Old releases remain downloadable on GitHub but are labeled "deprecated" on the website.
- Latest version + minus-one are security-supported. Older versions are end-of-life.

## 26.7 Update Notification (Non-Updater)

Since there is no auto-update (D13, §13.10), users learn about new releases via:

1. About screen shows current version + opens GitHub releases page on click.
2. Website download page.
3. RSS feed of releases.
4. Security mailing list for critical advisories.
5. Project Twitter/Mastodon/Nostr accounts (community-managed).

## 26.8 Code Signing Cost Budget

| Item | Annual cost | Notes |
|------|-------------|-------|
| Apple Developer Program | $99 | Required for notarization |
| Windows OV code signing certificate | ~$300 | Issued by Sectigo or SSL.com; cloud HSM |
| Domain (bitcoinlifeboat.org) | ~$15 | Registrar TBD |
| GitHub Actions minutes | $0 (OSS allotment) | Public repo = free |
| Cosign/Sigstore | $0 | Public good infra |
| **Total annual** | **~$415** | Funded via community donations / sponsor budget |

Project should announce funding sources transparently. No commercial backers in pre-v1.0.

---

# 27. Acceptance Criteria for MVP

The MVP ships when **every** item below is demonstrably implemented and passes CI.

## 27.1 Functional Acceptance

1. ✅ User can download a signed installer for macOS, Windows, and Linux from GitHub Releases.
2. ✅ User can launch the app on each supported OS without errors.
3. ✅ User can paste a valid singlesig descriptor and see a parsed Readiness Report.
4. ✅ User can paste a valid 2-of-3 multisig descriptor and see a Readiness Report identifying threshold and key count.
5. ✅ App detects and blocks BIP39 mnemonic paste (all 10 languages).
6. ✅ App detects and blocks WIF private key paste.
7. ✅ App detects and blocks xprv paste.
8. ✅ App detects and blocks SLIP-39 share paste.
9. ✅ App detects and blocks codex32 paste.
10. ✅ App validates BIP380 descriptor checksum where present.
11. ✅ App computes and adds a checksum when descriptor lacks one (with user confirmation).
12. ✅ App derives first 10 receive addresses + first 10 change addresses correctly.
13. ✅ User can compare a known address and see hit/miss with derivation index.
14. ✅ App generates qualitative status + numeric score per §16.
15. ✅ App lists critical issues, warnings, and passes per §16.3–16.4.
16. ✅ App generates Markdown report with all required sections (§15.10).
17. ✅ App generates JSON report conforming to the schema (§19.1).
18. ✅ App generates PDF runbook (singlesig-basic) under 3 seconds.
19. ✅ App offers public-safe and private export modes.
20. ✅ CLI executes `audit-descriptor`, `derive-addresses`, `compare-address`, `generate-runbook`, `report-json`, `detect-secrets`, `parse-export`, `checksum` per §17.10.
21. ✅ Unit tests pass for all crates ≥ 80% coverage.
22. ✅ Integration tests pass for all Tier-1 wallet importers.
23. ✅ Snapshot tests pass for ≥ 50 fixture descriptors.
24. ✅ Fuzz targets run for 5 minutes per PR without panics.
25. ✅ No-network-egress test passes.
26. ✅ Accessibility audit (axe-core) reports zero AA violations.

## 27.2 Documentation Acceptance

27. ✅ README explains: what Lifeboat is, what it is not, four promises, install instructions, link to docs.
28. ✅ SECURITY.md includes PGP key, disclosure address, 90-day window.
29. ✅ Threat model document covers T1–T20 from §13.3.
30. ✅ CLI reference doc generated from `clap` + reviewed for clarity.
31. ✅ JSON schemas documented in `docs/json-schemas.md`.
32. ✅ Error codes documented in `docs/error-codes.md`.
33. ✅ Wallet compatibility doc covers all Tier-1 + Tier-2 wallets with export instructions.
34. ✅ Reproducible builds doc explains current state (aspirational) and target.
35. ✅ Docs explain users should not enter real seed phrases.
36. ✅ "What this report cannot tell you" section appears in every report.

## 27.3 Release Acceptance

37. ✅ GitHub Release contains: signed installers per platform, signed CLI binaries, checksums file, SBOM, source tarball, release notes.
38. ✅ minisign signatures verify against the published public key.
39. ✅ cosign attestations exist for build provenance.
40. ✅ Two-maintainer approval recorded in release dispatch logs.

## 27.4 Anti-Acceptance (Things That Must NOT Exist)

41. ❌ No `bitcoinjs-lib`, `@scure/btc-signer`, or similar in frontend dependencies.
42. ❌ No `localStorage.setItem` for Confidential data.
43. ❌ No outbound network call during E2E suite (verified by network capture).
44. ❌ No string containing "safe" claiming user funds are safe.
45. ❌ No advanced-mode toggle that enables seed-phrase entry in non-Practice flows.
46. ❌ No analytics SDK in any form.
47. ❌ No auto-updater plugin in Tauri config.
48. ❌ No `eval`, `Function()`, or dynamic code execution in JS.

---

# 28. Documentation Requirements

## 28.1 User Docs (Shipped in MVP)

Embedded in-app AND on the docs site:

1. **What Bitcoin Lifeboat is** — one-page overview.
2. **What Bitcoin Lifeboat is not** — explicit non-promises.
3. **The four promises** (§1.6) — re-stated, with explanation.
4. **How to run a Readiness Check** — step-by-step.
5. **How to export a descriptor from your wallet** — per-wallet pages for Tier-1 wallets.
6. **Why seed phrases may not be enough** — descriptor education.
7. **What a descriptor is** — plain-English explainer with examples.
8. **What a PSBT is** — plain-English explainer (v0.2 relevance flagged).
9. **What Signet is** — plain-English explainer (v0.2 relevance).
10. **How to create a recovery runbook** — step-by-step.
11. **How to run a family drill** — heir runbook walkthrough.
12. **What xpubs reveal about your wallet** — privacy education.
13. **How to verify the installer signature** — for paranoid users.
14. **What to do if the Readiness Check fails** — recovery action plan.
15. **What to do if you accidentally pasted a real secret** — incident response.
16. **Bitcoin Recovery Day** — community initiative explainer.

## 28.2 Developer Docs (Shipped in MVP)

1. **Architecture overview** — §21.
2. **Crate responsibilities** — what each crate does, dependency graph.
3. **CLI reference** — auto-generated from clap.
4. **JSON schemas** — all schemas in §19.
5. **Test fixtures** — how to add a new fixture; format spec.
6. **How to add wallet compatibility** — step-by-step contributor guide.
7. **How to add a runbook template** — Typst template format.
8. **How to build from source** — toolchain, dependencies, common pitfalls.
9. **Security model** — pointer to §13 in this PRD + the threat model doc.
10. **Contribution guide** — DCO, PR template, code style, review process.
11. **Error codes reference** — Appendix C.
12. **Scoring rubric** — §16 expanded with examples.

## 28.3 Safety Docs (Shipped in MVP)

1. Never enter your seed phrase online.
2. Why Lifeboat avoids seed entry.
3. What public wallet metadata means (vs. private).
4. What metadata can reveal (xpub → transaction history).
5. How to store runbooks safely.
6. How to run drills with fake funds.
7. What to do if recovery fails.
8. When to ask for expert help (and how to find one without getting scammed).
9. The "$5 wrench" attack — what Lifeboat cannot help with.
10. Verifying a download is real.

## 28.4 Doc Format and Versioning

- All docs in Markdown under `docs/`.
- Docs site uses **Astro** with a docs theme (Starlight).
- Embedded in-app docs are the same Markdown files rendered via `markdown-it` with strict allowlist (no HTML).
- Docs are versioned with releases. Old version docs remain accessible.
- Docs available offline (embedded in app + downloadable site bundle).

## 28.5 What Embedded Docs vs Website-Only

| Content | In-app | Website |
|---------|--------|---------|
| User guide | ✅ | ✅ |
| CLI reference | ✅ (as man page) | ✅ |
| Per-wallet export instructions | ✅ | ✅ |
| Safety education | ✅ | ✅ |
| Architecture (devs) | ❌ | ✅ |
| Threat model | summary in-app; full on website | ✅ |
| Reproducible builds | ❌ | ✅ |
| Release notes | ✅ (current release) | ✅ (all releases) |
| Contributor guide | ❌ | ✅ |

---

# 29. Branding and Community

## 29.1 Brand Principles

1. Non-commercial.
2. Open-source.
3. Bitcoin-only.
4. Conservative security posture.
5. Respectful of existing wallets — explicitly not a competitor.
6. Educational but not condescending.
7. Practical over ideological.

## 29.2 Core Message

```
Bitcoin Lifeboat helps you test your recovery plan before disaster happens.
```

## 29.3 Secondary Message

```
Don't trust your backup. Test your backup.
```

## 29.4 Visual Identity (Guidance, Not Mandate)

- Color: deep blue + warm white + safety-orange accent.
- Typography: Inter for sans, JetBrains Mono for code.
- Iconography: nautical/safety theme (lifeboat, life preserver, checklist).
- No skeuomorphism.
- No "crypto bro" aesthetic — this is for serious self-custody users, families, educators.

## 29.5 Community Movement

**Bitcoin Recovery Day** (post-v1.0):

> Once a year, run a recovery drill.

Recovery Day materials:
- Workshop slide deck.
- Meetup organizer guide.
- Sample descriptors for live demos.
- Heir drill packet template.
- Press kit.

Date proposal: TBD with community input post-v1.0 launch.

## 29.6 Governance

| Decision class | Process |
|----------------|---------|
| Roadmap | Public RFC on GitHub; final call by lead maintainer |
| Security-critical PRs | Two-maintainer review (CODEOWNERS) |
| Release dispatch | Two-maintainer approval |
| Dependency upgrades (Bitcoin/crypto crates) | Two-maintainer review |
| Translation review | Native-speaker reviewer + maintainer sign-off |
| New wallet importer | Two-maintainer review (Confidential-data handling) |
| Controversial UX choices | Public discussion + lead maintainer call |

Pre-v1.0 the project is led by an individual maintainer. Post-v1.0, transition to a foundation or steward organization is on the roadmap (the choice is not pre-committed here).

## 29.7 Community Channels

| Channel | Purpose |
|---------|---------|
| GitHub Discussions | Q&A, feature requests |
| GitHub Issues | Bugs, security advisories |
| Security mailing list | Critical-advisory broadcast |
| RSS feed (releases) | Auto-notifications |
| Optional Matrix room | Community chat (community-moderated) |

**No Discord, no Telegram in pre-v1.0.** Reasons: both have scam-bot problems and ephemeral history. Matrix is preferred for its open protocol and persistent history. Decision can be revisited.

## 29.8 Anti-Scam Posture (NORMATIVE)

The app, docs, and website repeat these messages prominently:

> Bitcoin Lifeboat will never:
>   • Contact you first.
>   • Ask for your seed phrase.
>   • Charge you for recovery.
>   • Call you on the phone.
>   • Send you Telegram or Discord messages.
>
> Anyone claiming otherwise is a scammer. Hang up.

Maintainers will **refuse to help users recover real mainnet funds** in any community channel. Support boundary is: "We can help you understand what your descriptor says. We cannot help you recover your specific wallet. Please consult a qualified self-custody professional."

## 29.9 Trademark and Name

- Project name "Bitcoin Lifeboat" is held by the project (entity TBD pre-v1.0).
- Logo and visual identity licensed CC-BY-SA.
- Modified builds must NOT use the official name or logo without permission. Forks must rename.
- Commercial services may bundle Lifeboat unmodified under MIT, but cannot represent themselves as official.

---

# 30. Coding LLM Implementation Instructions

This section is the **build playbook** for a coding LLM (or human team) implementing the MVP.

## 30.1 Build Order (NORMATIVE)

Implement in this order. Each step is independently testable.

1. **Workspace scaffold** — `Cargo.toml` workspace, pin Rust 1.78, pin dependencies per §3.2.
2. **`error-taxonomy` crate** — `LifeboatError` enum, error code constants, i18n keys.
3. **`descriptor-audit` crate** — descriptor parsing, normalization, checksum (BIP380). Tests: every fixture in `fixtures/descriptors/`.
4. **`sensitive-input-detector` crate** — BIP39/WIF/xprv/SLIP-39/codex32 detection. Tests: §13.5.10 fuzz targets + fixture corpus.
5. **`address-derive` crate** — derivation + known-address comparison. Tests: golden fixtures.
6. **`readiness-score` crate** — scoring engine + audit trail. Tests: golden ReadinessReport JSON for each fixture.
7. **`wallet-imports` crate** — one importer at a time, Tier 1 order: Bitcoin Core → Sparrow → Specter → Coldcard → Nunchuk → Liana → Jade → Passport.
8. **`report-engine` crate** — JSON + Markdown rendering. Snapshot tests with `insta`.
9. **`runbook-engine` crate** — Typst template compilation. Bundle Typst binary in build script.
10. **`lifeboat-core` facade crate** — re-exports the public API surface.
11. **`lifeboat` CLI binary** — all 8 commands per §17.10. Snapshot tests for human + JSON output.
12. **Tauri app shell** — `apps/desktop/src-tauri/` with capabilities + CSP per §13.7–13.8.
13. **Tauri commands** — wire the 13 commands from §21.3.
14. **React UI scaffold** — pages, routing, i18n, Zustand store.
15. **Welcome / safety-promise / goal screens** (§15.2).
16. **Readiness Check wizard** (§22.8).
17. **Report viewer + export UI**.
18. **Runbook generator UI**.
19. **Settings page**.
20. **Learn (in-app docs viewer)** rendering embedded Markdown.
21. **Docs site (Astro)** — content from `docs/`, hosted on GitHub Pages or Cloudflare Pages.
22. **CI workflows** — `ci.yml`, `security.yml`, `fuzz.yml`, `docs.yml`.
23. **Release workflow** — `release.yml` with signing per §26.
24. **Polish, accessibility audit, performance verification**.
25. **MVP release candidate** — internal review against §27 acceptance criteria.
26. **Public beta** — community testing.
27. **v0.1.0 stable release**.

## 30.2 Do NOT Implement in MVP

1. Mainnet signing.
2. Seed phrase entry (any context).
3. HWI integration / USB device drivers.
4. Cloud sync.
5. Mobile app.
6. Auto-import from running wallet daemons.
7. Legal forms.
8. Network blockchain scanning.
9. Remote analytics.
10. Paid features.
11. Auto-updater.
12. Crash reporting upload.
13. Practice Mode (deferred to v0.2).
14. Signet drill engine (deferred to v0.2).
15. Lightning Network anything (forever).

## 30.3 Engineering Priorities (in order)

1. **Safety first** — every decision tilts toward false-positives in secret detection; every default toward no-persistence and no-network.
2. **Correctness second** — Bitcoin logic is right or it does not ship.
3. **Clarity third** — error messages, scoring transparency, UX copy all readable.
4. **UX polish fourth** — visual polish matters but cannot trump safety/correctness.
5. **Advanced integrations later** — HWI, Signet, multisig deep drill all post-MVP.

## 30.4 Definition of Done (per feature)

Every feature requires:

1. Unit tests.
2. Integration test if it crosses a crate boundary.
3. Snapshot or fixture if it produces user-facing output.
4. Typed error handling — no `unwrap()` or `panic!()` outside test code.
5. User-facing plain-English explanation surfaced in UI/CLI/docs.
6. Technical detail explanation where useful (behind expander).
7. No secret persistence.
8. No unexpected network behavior.
9. Documentation update (`docs/` or in-code).
10. i18n key for any user-visible string.

## 30.5 Coding Style

### Rust
- `rustfmt` enforced (CI lint).
- `clippy --deny warnings` enforced.
- No `unsafe` outside `sensitive-input-detector` zeroize paths, and even there documented + reviewed.
- `thiserror` for error enums, `anyhow` for prototyping/scripts only.
- `serde` for serialization with `deny_unknown_fields` on incoming JSON.
- Module-level docs (`//!`) on every crate.

### TypeScript/React
- ESLint + Prettier enforced.
- `strict` TypeScript mode.
- No `any`. No `as` assertions outside tests.
- Component files under 200 lines (split otherwise).
- Hooks pattern; no class components.

### CSS/Tailwind
- Utility-first; component classes when shared.
- No inline styles in components (use Tailwind).
- Custom colors centralized in `tailwind.config.js`.

## 30.6 What the Coding LLM Should Ask the User Before Building

For implementation choices NOT specified in this PRD, the coding LLM should ask the user:

1. The GitHub organization / repository name to create the repo under.
2. The domain name for `bitcoinlifeboat.org` (or alternative).
3. The maintainer's PGP key for `SECURITY.md`.
4. Whether to fund the Apple Developer Program + Windows OV cert now or defer to beta.
5. Whether to use Astro Starlight, Next.js, or another docs framework.
6. Whether to host the docs site on GitHub Pages, Cloudflare Pages, or Vercel.

For everything else specified in this PRD, the coding LLM proceeds without asking.

## 30.7 What the Coding LLM Should NOT Do

1. Do NOT introduce frameworks not specified (e.g., do NOT add Redux, MobX, or other state managers — use Zustand).
2. Do NOT add abstractions for "future flexibility" beyond what the PRD requires.
3. Do NOT add silent fallbacks. Every error path is named.
4. Do NOT silently widen Tauri capabilities to make something work — file an issue or escalate.
5. Do NOT add network calls without explicit user-action gating.
6. Do NOT bypass the sensitive-input detector for any reason.
7. Do NOT add an "advanced mode" that unlocks seed entry.
8. Do NOT write content claiming user wallets are "safe."

## 30.8 Reference Implementation Hints

- `rust-miniscript`'s `Descriptor<DescriptorPublicKey>::from_str()` is the parse entry point.
- `Descriptor::sanity_check()` validates internal consistency.
- BIP389 multipath `<0;1>` is expanded by calling `derive_descriptor()` for each index.
- For the detector, the `bip39` crate's `Mnemonic::from_phrase()` does checksum validation across languages.
- For Typst: bundle the `typst-cli` binary in `crates/runbook-engine/bin/` and invoke as subprocess.
- For the CSP: use Tauri's `with_csp` builder; do not hand-edit `index.html`.
- For Zeroize: derive `ZeroizeOnDrop` on every Confidential newtype.

---

# 31. Example User Stories

## 31.1 Story: Multisig Backup Audit (Primary)

**As** a 2-of-3 multisig user
**I want** to check whether my backup is complete
**So that** I do not discover missing recovery metadata during an emergency.

**Flow:**

1. User opens Bitcoin Lifeboat.
2. User clicks "Audit My Multisig Setup."
3. App shows safety banner: "Do not paste seed words..."
4. User pastes their `wsh(sortedmulti(2,...))` descriptor.
5. App parses, identifies 2-of-3 multisig.
6. App notices receive descriptor present but change descriptor missing.
7. User enters known receive address: `bc1q...`.
8. App confirms match at receive index 3.
9. App generates report with status "Mostly Ready" (score 75).
10. User exports PDF runbook in `public-safe` mode.

**Resulting Report (excerpt):**

```
Status: Mostly Ready (75/100)

Your receive descriptor parses and matches your known address.

Needs Attention:
  • Change descriptor missing (-15)
    Recommended fix: Export both descriptors from your wallet.
    In Sparrow: File > Export Wallet > Output Descriptor.

  • No drill in last 12 months (-10)
    Recommended fix: Run a Disaster Drill when v0.3 ships.

Next steps:
  1. Export your change descriptor. (5 min)
  2. Print two copies of the descriptor backup. (10 min)

What this report CANNOT tell you:
  • Whether your hardware wallets still work.
  • Whether your seed words are still legible.
  ...
```

## 31.2 Story: Heir Runbook (Secondary)

**As** an owner with a non-technical spouse
**I want** to print a runbook my spouse can use to recover
**So that** my family does not lose access if I die or am incapacitated.

**Flow:**

1. User clicks "Create a Family Drill / Heir Runbook."
2. App asks: "Which template?"
3. User chooses "Heir runbook — 2-of-3 multisig."
4. App asks for wallet metadata (optional descriptor, signer locations).
5. User fills in: signer A at home, signer B at lawyer's office, signer C at safe deposit box.
6. App shows preview with blank fields for owner's hand-completion.
7. User exports PDF in `public-safe` mode.
8. User prints, fills in hand-written details ("My lawyer's name is...").
9. User stores printed runbook with the heir.

**Resulting Runbook (first page excerpt):**

```
HEIR RECOVERY PLAN — 2-of-3 Multisig

You are reading a recovery plan written by someone who trusts you to help.
This document does not contain bitcoin. It does not contain secret recovery words.

You will need:
  • Signer A — location: at home, in fireproof safe
  • Signer B — location: at [LAWYER NAME]'s office
  • Signer C — location: in safe deposit box at [BANK NAME]

Wallet software: Sparrow Wallet (download from sparrowwallet.com).
Wallet descriptor backup: [stored at: _______________________]

If you get stuck, stop. Call [TRUSTED HELPER]: _______________________.

If anyone says they can "help unlock" this for a fee, hang up. They cannot.
```

## 31.3 Story: Wallet Developer CI Check

**As** a wallet developer
**I want** to verify my wallet's exported descriptor parses cleanly
**So that** my users can use Lifeboat to audit their backups.

**Flow:**

```bash
# In wallet repo's CI
$ my-wallet export --to /tmp/wallet.json
$ lifeboat parse-export --file /tmp/wallet.json --json > /tmp/parsed.json
$ lifeboat audit-descriptor --file /tmp/parsed.json --strict --json > /tmp/report.json
$ jq '.score.status' /tmp/report.json
"ready"
$ echo $?
0
```

If `--strict` and any warning fires, exit code is non-zero — CI catches it.

---

# 32. Example MVP UI Copy

## 32.1 Welcome

```
Bitcoin Lifeboat

Bitcoin Lifeboat helps you test whether your Bitcoin recovery plan
actually works.

It is not a wallet.
It does not custody funds.
It does not need your real seed phrase.

Use it to check your backup plan, audit recovery metadata, and create
a printable recovery runbook.
```

## 32.2 Sensitive Input Warning

```
✕ This looks like secret wallet material.

Bitcoin Lifeboat does not need seed phrases, private keys, or
passphrases for this check.

For your safety, this input was not processed.

What we detected: a 12-word BIP39 mnemonic with valid checksum.

What to do instead:
   1. Open your wallet software.
   2. Export the OUTPUT DESCRIPTOR (not the seed).
   3. Paste the descriptor here.

[ I understand ]
```

## 32.3 Not Ready Result

```
Status: Not Ready

Your backup plan is missing critical information. In a real emergency,
you may not be able to reconstruct this wallet.

The most important issue:
  Your multisig descriptor is missing or incomplete. With only the
  xpubs you provided, Lifeboat cannot determine the M-of-N threshold.

Recommended next step:
  Export your full wallet descriptor from your wallet software and
  store printed copies separately from your seed backups.

This report is a diagnostic aid. It is not legal, tax, financial,
or security advice. Bitcoin Lifeboat cannot guarantee that any
wallet is recoverable.
```

## 32.4 Ready Result

```
Status: Ready (94/100)

Your backup plan passed every check Lifeboat can run on the metadata
you provided.

This does not mean your bitcoin is safe.
It means: the descriptor you provided parses, validates, matches your
known address, and survives the multisig scenarios we tested.

You still need to:
  • Verify your hardware wallets still power on.
  • Verify your seed words are still legible.
  • Verify the location you store backups is still safe.
  • Verify your heirs can find the materials.

Lifeboat cannot check any of these for you.

Recommended next drill: 2027-05-28 (or sooner if you change your setup).
```

---

# 33. Long-Term Vision

Bitcoin Lifeboat should become the default open-source recovery rehearsal toolkit for the Bitcoin ecosystem.

Long-term support:

1. Descriptor-based wallet backup metadata standards.
2. PSBT signing drills (v0.2+).
3. Hardware wallet compatibility testing (v0.3+).
4. Liana/timelock inheritance drills (v0.5+).
5. Miniscript policy visualization (v0.5+).
6. Signet-based recovery labs (v0.2+).
7. Meetup workshop kits (v1.0).
8. Heir training packets (v0.6+).
9. Annual Recovery Day campaigns (post-v1.0).
10. Wallet developer test fixtures (v0.1+).
11. Translation into many languages (v1.0+).
12. Mobile companion app (v1.1+).
13. Fully reproducible builds (v1.0).
14. Security audit (v1.0).
15. Integration guides for major wallets (v0.1+).

---

# 34. Final Product Positioning

Bitcoin Lifeboat is described publicly as:

> **Bitcoin Lifeboat is a free, open-source desktop app and CLI that helps you test your Bitcoin recovery plan before disaster happens. It uses output descriptors, PSBTs (post-MVP), hardware-wallet workflows (post-MVP), Signet practice drills (post-MVP), and printable runbooks to help users, families, and educators prove that self-custody recovery actually works — without uploading secrets or risking real funds.**

The simplest public message:

> **Don't trust your backup. Test your backup.**

---

# 35. License

## 35.1 Code License

**MIT License** for all source code.

Rationale:
- Bitcoin ecosystem precedent (`rust-bitcoin` is dual MIT/Apache; many wallets are MIT).
- Minimum friction for adoption.
- Permits both hobbyist and commercial reuse.

## 35.2 Dependency License Compatibility

Allowed transitive licenses (enforced via `cargo deny check licenses`):

- MIT
- Apache-2.0
- BSD-2-Clause, BSD-3-Clause
- ISC
- Unlicense / 0BSD
- MPL-2.0 (file-level copyleft only)
- CC0-1.0
- Zlib

Disallowed:
- GPL-2.0, GPL-3.0 (project-wide copyleft incompatible with MIT)
- AGPL-3.0
- Any "non-commercial" license
- Any custom license not in the SPDX allowlist

## 35.3 Contribution Agreement

**DCO** (Developer Certificate of Origin), not CLA. Contributors sign off commits with `git commit -s`. Documented in `CONTRIBUTING.md`.

## 35.4 Documentation License

Docs (including this PRD) under **CC-BY-SA-4.0**.

## 35.5 Logo and Visual Identity

CC-BY-SA-4.0; commercial reuse permitted with attribution and share-alike.

The name "Bitcoin Lifeboat" itself is **NOT** under the open license — modified or forked builds may not use the name.

---

# Appendix A: Question-to-Section Index

This index maps every question from `questions_v1.txt` to the section that resolves it.

## A.1 Core Product Definition (§1)

| Q | Question | Answer Location | Verdict |
|---|----------|-----------------|---------|
| 1 | Desktop, CLI, or shared core? | §2 D12, §21 | Shared Rust core; desktop AND CLI are first-class |
| 2 | First target user? | §2 D20, §7.1 | Multisig / serious self-custody user |
| 3 | First successful user outcome? | §31.1 | "I pasted my descriptor and got a Readiness Report" |
| 4 | Audit / simulator / drill wizard? | §2 D1 | Descriptor audit + runbook in MVP; drill wizard in v0.3 |
| 5 | Watch-only or PSBT signing? | §2 D1 | Watch-only readiness in MVP; PSBT signing in v0.2 |
| 6 | Create wallets for practice? | §9.2 | Yes, in v0.2 Practice Mode only |
| 7 | Derive addresses from descriptors? | §17.4 | Yes |
| 8 | Connect to Bitcoin node? | §10.4, §11.1 | No in MVP; optional regtest connection in v0.2 |
| 9 | Internet access in MVP? | §2 D5, §14.4 | No |
| 10 | Bitcoin-only forever? | §6 #16 | Yes, L1 Bitcoin only |
| 11 | Lightning excluded? | §6 #16 | Yes, excluded forever |
| 12 | Taproot in MVP? | §17.2, §16.4 | Preview support (parses + derives, with `W-TAPROOT-PREVIEW` warning); full in v0.2 |
| 13 | Miniscript/timelock when? | §11.4–11.5 | Detected in MVP; full Liana/timelock drill in v0.5 |
| 14 | Readiness checker or trainer? | §2 D1, §8 | MVP = readiness checker; trainer in v0.2 (Practice Mode) and v0.3 (Disaster Drill) |
| 15 | What does app refuse to do? | §6, §10.4 | All 17 non-goals enumerated |
| 16 | Public non-negotiable promise? | §1.6 | The four promises |
| 17 | Final name? | §1.1 | Yes, "Bitcoin Lifeboat" final |
| 18 | Domain? | §30.6 | Coding LLM asks user; default proposal `bitcoinlifeboat.org` |
| 19 | "Safe for beginners" claim? | §16.8 | Banned; we say "safer than experimenting manually" |
| 20 | What does production-ready mean? | §27 | All 48 acceptance criteria in §27 |

## A.2 MVP Scope Boundaries (§2)

| Q | Question | Answer Location |
|---|----------|-----------------|
| 1 | Minimum valuable v0.1? | §10.2, §10.3 |
| 2 | Only descriptor parsing + report? | §10.3 (plus runbook generator + CLI) |
| 3 | PDF generation? | §10.3 #21 (Yes — Markdown + JSON + PDF) |
| 4 | Tauri GUI or CLI first? | §30.1 (Core first → CLI second → Tauri shell third) |
| 5 | Win + macOS + Linux day 1? | §12.2 (Yes, all three Tier 1) |
| 6 | Docs site? | §10.3 Docs Site |
| 7 | Example descriptors? | §22.9 (Yes, "Use sample descriptor" button) |
| 8 | Interactive tutorials? | §10.3 #24 (in-app docs in MVP; full tutorials post-MVP) |
| 9 | Fake/practice wallet? | §9.2 (v0.2) |
| 10 | Signet? | §2 D19, §11.1 (v0.2) |
| 11 | regtest? | §11.1 (v0.2) |
| 12 | Bitcoin Core RPC? | §10.4 #11 (No in MVP) |
| 13 | HWI? | §11.3 (v0.4, optional) |
| 14 | Hardware wallet detection? | §11.3 (v0.4) |
| 15 | Mainnet beyond descriptor analysis? | §14.4 (No, forever no mainnet broadcast) |
| 16 | "Don't paste seed words" detector? | §13.5 (Yes, full secret detector) |
| 17 | Save reports locally? | §13.6 (No by default; user exports on demand) |
| 18 | Remember sessions? | §13.6 (No in MVP) |
| 19 | Update checking? | §13.10 (No auto-update; manual via browser-redirect) |
| 20 | What's deferred to v0.2? | §10.5 |

## A.3 Trust Model (§3)

| Q | Answer Location |
|---|-----------------|
| 1 | §13.2 — full trust model statement |
| 2 | §13.2 (Never in normal use; Practice Mode only with known test seeds) |
| 3 | Same |
| 4 | Same |
| 5 | Same |
| 6 | §13.6 (No in MVP; opt-in v0.2+) |
| 7 | §13.6 (No in MVP; opt-in v0.2+) |
| 8 | §13.6 (No in MVP; opt-in v0.2+) |
| 9 | §13.6 (No in MVP; opt-in v0.2+) |
| 10 | §13.6 (Settings only, no Confidential data) |
| 11 | §13.6 (Logging OFF by default) |
| 12 | §13.6, §13.11 (Yes, possible — therefore disabled by default) |
| 13 | §13.6 (Yes, disabled by default) |
| 14 | §13.6 (MVP default is "paranoid mode"; no opt-out toggle needed) |
| 15 | §10.4 #14 (Yes, offline by default) |
| 16 | §15.2 (Welcome screen + safety promise screen; not on every launch after dismiss) |
| 17 | §15.2 (Yes — Screen 2 "I understand" required) |
| 18 | §15.7 (Yes, every report and onboarding) |
| 19 | §15.6 (Yes, in long disclaimer) |
| 20 | §13.3 (Yes, before v1.0) |

## A.4 Secret Handling Policy (§4)

| Q | Answer Location |
|---|-----------------|
| 1 | §2 D2 (Yes, in all normal flows) |
| 2 | §9.2 (Only Practice Mode v0.2, only with documented test seeds) |
| 3 | §9.2 (Hard-block via checksum; test seeds whitelisted) |
| 4 | §13.5.1 (Yes — checksum-valid BIP39 always blocks) |
| 5 | §13.5.1 (Yes, in any input field) |
| 6 | §13.5.2 (Yes) |
| 7 | §13.5.3 (Yes) |
| 8 | §13.5.4 (Yes, with context gating to manage FP) |
| 9 | §13.5.5 (Yes) |
| 10 | §13.5.6 (Yes) |
| 11 | §13.5 (Free-form passphrase detection is intentionally NOT done — see §13.5; passphrases go in labeled password fields only) |
| 12 | §13.5.8 (Yes via SecretString) |
| 13 | §13.5 (Block paste in fields where secrets shouldn't be; allow in Practice Mode seed field) |
| 14 | §13.5 (Yes via paste handler) |
| 15 | §13.5 (Never automatically) |
| 16 | §13.6 (No) |
| 17 | §22.7 (Field cleared on detector block; report-generation flow clears after export) |
| 18 | §13.11 (Disabled by default; opt-in writes local file only) |
| 19 | §13.11 (Yes, scrubs Confidential/Secret) |
| 20 | §13.5.10 (Yes, all listed fuzz targets) |

## A.5 Wallet Metadata Support (§5)

| Q | Answer Location |
|---|-----------------|
| 1 | §17.2 (BIP380 formats listed in detail) |
| 2 | §17.1 (Both — paired and BIP389 multipath supported) |
| 3 | §24.2 (Yes, Tier 1) |
| 4 | §24.2 (Yes, Tier 1) |
| 5 | §24.2 (Yes, Tier 1) |
| 6 | §24.2 (Yes, Tier 1, Liana 13+) |
| 7 | §24.2 (Yes, Tier 1) |
| 8 | §24.2 (Yes, Tier 1) |
| 9 | §24.2 (Tier 2 in MVP — signer-only; Tier 1 in v0.3 for QR) |
| 10 | §24.2 (Yes, Tier 1) |
| 11 | §24.2 (Yes, Tier 1) |
| 12 | §24.2 (Tier 2 — manual workaround) |
| 13 | §24.2 (Tier 2 — manual workaround) |
| 14 | §17.9 (Both — generic descriptor paste always works; wallet-specific importers for Tier 1) |
| 15 | §17.9 (No — strict JSON parsing; unknown formats rejected) |
| 16 | §17.9 (Rejected with typed error; no heuristic partial parsing) |
| 17 | §17.3 (Yes — canonical normalization on import) |
| 18 | §19.1 (Yes — `descriptors.receive.raw` preserves original; `canonical` shows normalized) |
| 19 | §13.4, §17.7 (Yes — public-safe mode redacts by default) |
| 20 | §14.3 (Yes — xpub privacy disclaimer in every export) |

## A.6 Descriptor Analysis (§6)

| Q | Answer Location |
|---|-----------------|
| 1 | §17.2 (Listed in priority order) |
| 2 | §17.2 (Yes in MVP) |
| 3 | §17.2 (Yes in MVP) |
| 4 | §17.2 (Preview in MVP; full v0.2) |
| 5 | §17.2 (Preview-parse in MVP; full v0.2 then v0.5 for Liana) |
| 6 | §13.5, §16.4 (Yes with `W-NO-DESC-CHECKSUM` warning; "compute checksum" helper) |
| 7 | §16.3 (Invalid checksum = critical `C-DESC-CHECKSUM-INVALID`) |
| 8 | §17.4 (Non-wildcard supported but with single-address-only constraint) |
| 9 | §17.4 (Yes supported) |
| 10 | §17.3 (Yes — `h` and `'` normalized) |
| 11 | §16.4 (Warning if missing fingerprint via `W-NO-KEY-ORIGIN`-implied; not critical) |
| 12 | §16.4 (Warning, not critical) |
| 13 | §16.4 (Warning, not critical) |
| 14 | §16.4 (Warning `-15`; not critical) |
| 15 | §16.4 (Warning `-5`) |
| 16 | §16.4 (Warning `-3`) |
| 17 | §13.5.3 (Yes — `C-DESC-CONTAINS-XPRV` critical block) |
| 18 | Same |
| 19 | §22.5 (Yes — every check has plain-English summary) |
| 20 | §15.8 (Yes — "What this report cannot tell you" section) |

## A.7 Address Derivation and Verification (§7)

| Q | Answer Location |
|---|-----------------|
| 1 | §17.4 (Yes, mainnet derivation supported — for analysis, not signing) |
| 2 | §17.4 (Yes) |
| 3 | §17.4 (From descriptor key version bytes by default) |
| 4 | §17.4 (User must explicitly choose) |
| 5 | §17.4 (Yes when ambiguous) |
| 6 | §17.4 (Default 10) |
| 7 | §17.4 (Yes, 1–1000 configurable) |
| 8 | §17.4 (Both by default) |
| 9 | §17.4 (Yes when change descriptor present) |
| 10 | §17.5 (One or many) |
| 11 | §16.3 (`C-WALLET-TYPE-MISMATCH` critical) |
| 12 | §17.4 (Refuses to proceed if mixed) |
| 13 | §17.4 (Yes for xpub-only descriptors) |
| 14 | §17.7, §19.1 (Yes in private mode; redacted in public-safe) |
| 15 | §17.7 (Yes — public-safe redacts) |
| 16 | §14.3 (Yes — every xpub export has privacy warning) |
| 17 | §15.8 ("Copy explanation" button per-section; no formal certificate) |
| 18 | §16.3 (Yes — `C-ADDRESS-MISMATCH` critical) |
| 19 | §16.2 (Required for `Ready` per D8) |
| 20 | §15.8 ("What this report cannot tell you" explicitly notes) |

## A.8 Readiness Scoring (§8)

| Q | Answer Location |
|---|-----------------|
| 1 | §16.1 (Yes, paired with qualitative status) |
| 2 | §16.1 (Acknowledged; mitigation: qualitative status is the headline) |
| 3 | §16.1 (No, but qualitative dominates) |
| 4 | §16.3 (12 critical conditions) |
| 5 | §16.5 (4 conditions) |
| 6 | §16.2 (Score 90–100 + zero criticals + known-address match) |
| 7 | §16.3 (Warning, not critical — `W-NO-CHANGE-DESC` -15) |
| 8 | §16.2, §2 D8 (Yes — Ready requires known-address match) |
| 9 | §16.4 (`W-NO-RECENT-DRILL` -10; not critical) |
| 10 | §16.4 (`W-NO-HEIR-INSTRUCTIONS` -8) |
| 11 | §16.4 (`W-SAME-LOCATION-BACKUP` -10) |
| 12 | §16.4 (Implicit in passphrase-undocumented critical for multisig; warning otherwise) |
| 13 | §16.6 (Yes — multisig adds survivability dimension) |
| 14 | §16.6 (Yes per-type rubrics) |
| 15 | §16.7 (Yes — `docs/scoring.md` + `scoring_audit` in JSON) |
| 16 | §16.7 (NO — not user-configurable in MVP) |
| 17 | §16.7 (Yes — `scoring_audit` array) |
| 18 | §17.10.5 (Yes — `report-json` outputs full audit) |
| 19 | §16.8 (Yes — "ready for the tested scenario" language) |
| 20 | §16.8 (Banned terms list + approved alternatives) |

## A.9 Disaster Drill Design (§9)

| Q | Answer Location |
|---|-----------------|
| 1 | §9.3 (Questionnaire-only DS-1 through DS-6 in v0.3) |
| 2 | §9.3 (DS-7 through DS-10 require signing — v0.3 ships when those work) |
| 3 | §9.3 (Pass = descriptor parses, validates, derives expected addresses; signing scenarios = PSBT signed + finalized) |
| 4 | §9.3 (Yes for DS-1 through DS-6) |
| 5 | §9.3 (Yes for v0.3 DS-1 through DS-6) |
| 6 | §9.3 (Yes for DS-7 through DS-10) |
| 7 | §9.3 (Yes — DS-1 is descriptor-completeness questionnaire) |
| 8 | §9.3 (DS-3 — yes restore to neutral watch-only) |
| 9 | §9.3 (DS-6 simulates M-of-N survivability) |
| 10 | §9.4 (Heir scenarios use regtest only with fake materials) |
| 11 | §9.4 (Yes — fake regtest wallet generated for heir drills v0.6) |
| 12 | §9.3 (Yes — opt-in only) |
| 13 | §9.3 (Local only; signed with per-install key) |
| 14 | §9.3 (Yes — drill records can be exported) |
| 15 | §9.3 (Drill recommendations annual; records persist with date) |
| 16 | §9.3 (Yes — recommend within 12 months) |
| 17 | §13.6 (No system calendar integration in MVP; documented "set a reminder" instruction) |
| 18 | N/A — no reminders in MVP |
| 19 | §9.3 ("Drill receipt" PDF in v0.3+; not a "certificate" to avoid overclaim) |
| 20 | §9.3 (Acknowledged; receipt is local + redacted; no public verification) |

## A.10 Signet and Regtest Strategy (§10)

| Q | Answer Location |
|---|-----------------|
| 1 | §11.1 (v0.2) |
| 2 | §11.1 (v0.2) |
| 3 | §11.1 (Downloaded once at user request; not bundled) |
| 4 | §11.1 (No — bundled regtest preferred) |
| 5 | §11.1 (Optional in v0.2 via user-initiated click) |
| 6 | §11.1 (Esplora endpoints, user-opt-in only) |
| 7 | §11.1, §14.4 (Yes for v0.2 with explicit user gate) |
| 8 | §11.1 (regtest = local; Signet = network) |
| 9 | §11.1 (Yes — regtest is offline) |
| 10 | §11.1 (regtest = default for offline practice) |
| 11 | §11.1 (Signet = default for WAN-realistic practice) |
| 12 | §11.1 (User browser link to faucet; app never calls) |
| 13 | §11.1 (No — privacy concern) |
| 14 | §11.1 (Yes — avoid faucet API integration; user goes to browser) |
| 15 | §28.1 (User docs explain how) |
| 16 | §22.4 (Network banner) |
| 17 | §22.4 (Banner cannot be dismissed; color-coded) |
| 18 | §10.4 (Mainnet broadcast forever ❌) |
| 19 | §14.4 (Yes — forever) |
| 20 | §11.1 (regtest chain state can cache via bundled `bitcoind`; Signet is stateless from app POV) |

## A.11 PSBT Drill Requirements (§11)

| Q | Answer Location |
|---|-----------------|
| 1 | §11.1 (v0.2) |
| 2 | §11.1 (Yes) |
| 3 | §11.1 (Yes) |
| 4 | §11.1 (Yes) |
| 5 | §11.1 (Yes) |
| 6 | §11.1 (Yes, user-opt-in) |
| 7 | §10.4, §14.4 (Never — forever no) |
| 8 | §11.1 (Both v0 and v2) |
| 9 | §11.1 (Yes) |
| 10 | §13.6 (Opt-in storage only) |
| 11 | §13.6 (Logs scrubbed) |
| 12 | §11.1 (Yes — inspect inputs/outputs in UI) |
| 13 | §11.1 (Yes — fees + outputs explained) |
| 14 | §11.1 (Yes for v0.2) |
| 15 | §11.1 (No external APIs — fee estimation from local heuristics or user input) |
| 16 | §11.2 (No — file-based PSBT in v0.3 works without HW) |
| 17 | §11.2 (Yes — UR + BBQr in v0.3) |
| 18 | §11.2 (Yes — primary in v0.3) |
| 19 | §11.2 (Yes — animated UR fountain codes) |
| 20 | §9.3 (Pass = signed by required quorum, finalized to valid tx, destination verified) |

## A.12 Hardware Wallet Support (§12)

| Q | Answer Location |
|---|-----------------|
| 1 | §11.3 (Optional in v0.4; not strictly required for v1.0) |
| 2 | §11.3 (Not in MVP) |
| 3 | §11.3 (Yes — subprocess sidecar) |
| 4 | §11.3 (No — explicit rejection of rust-hwi PyO3 in-process) |
| 5 | §11.3 (Yes — bundled via `python-build-standalone` + PyInstaller) |
| 6 | §11.3 (No — bundled for users) |
| 7 | §11.3 (No — bundled) |
| 8 | §11.3 (Ledger, Trezor, BitBox02, Coldcard USB Virtual Disk) |
| 9 | §11.2 (Coldcard via SD + QR in v0.3 before USB in v0.4) |
| 10 | §11.2 (Yes — SeedSigner via QR in v0.3) |
| 11 | §11.2 (USB and QR in v0.3; both supported) |
| 12 | §11.3 (Yes in v0.4) |
| 13 | §11.3 (Yes in v0.4) |
| 14 | §11.2, §11.3 (Yes — QR in v0.3; USB Virtual Disk in v0.4) |
| 15 | §11.3 (Yes in v0.4) |
| 16 | §11.3 (Yes — HWI 3.2+ provides this) |
| 17 | §11.3 (Yes — emit `W-DEVICE-FIRMWARE-UNSUPPORTED`) |
| 18 | §11.3 (Yes — Lifeboat never writes vendor-specific code; subprocess to HWI) |
| 19 | §21.5 (Typed error taxonomy with plain-English mapping) |
| 20 | §11.3 (Doc: "device detected" ≠ "wallet recoverable"; report says so explicitly) |

## A.13 Heir Mode (§13)

| Q | Answer Location |
|---|-----------------|
| 1 | §9.4 (Static templates only in MVP) |
| 2 | §9.4 (Yes — runbook template only in MVP) |
| 3 | §9.4 (No — heir mode uses fake regtest wallets in v0.6) |
| 4 | §9.4 (Yes — fake practice wallets) |
| 5 | §9.4 (8th-grade reading level) |
| 6 | §9.4 (Inline expansion for any technical term) |
| 7 | §9.4 (Yes — "do not panic") |
| 8 | §29.8 (Yes — anti-scam guidance) |
| 9 | §9.4 (Yes — "Stop and call a trusted helper" required) |
| 10 | §17.8 (Yes — blank fillable field) |
| 11 | §13.6 (Stored locally only if user enables persistence; not by default) |
| 12 | §9.5 ("executor/attorney overview" runbook template in v0.2; basic version in MVP) |
| 13 | §15.6 (Yes — heir disclaimer verbatim) |
| 14 | §15.6 (Yes — explicit "consult an attorney" language) |
| 15 | §28.3 (Yes — safety doc explains "when to ask for expert help") |
| 16 | §17.8 (Yes — templates have user-fillable blank fields) |
| 17 | §17.8 (Yes — Markdown source) |
| 18 | §9.5 (Yes in v0.6 — "envelope label" template) |
| 19 | §9.5 (Yes — "next drill date" in every runbook) |
| 20 | §9.4 (Yes — never shows balances; never queries chain) |

## A.14 Runbook Generation (§14)

| Q | Answer Location |
|---|-----------------|
| 1 | §9.5 (List of templates) |
| 2 | §17.8 (Yes — structured templates) |
| 3 | §17.7.3 (Markdown source; PDF via Typst) |
| 4 | §17.7.3 (Typst primary; printpdf fallback) |
| 5 | §17.8 (Yes in v0.3 for PSBT QR; v0.1 prints fingerprint hash as QR optionally) |
| 6 | §17.8 (Yes in private mode; redacted in public-safe) |
| 7 | §17.8 (Yes — toggleable) |
| 8 | §17.7, §19.1 (Yes — public-safe redacts) |
| 9 | §19.1 (One full address in public-safe; first 5 in private) |
| 10 | §17.8 (Yes — labeled blanks) |
| 11 | §9.5 (Yes — storage-location blank with privacy warning) |
| 12 | §9.5 (Yes — privacy warning inline) |
| 13 | §9.5 (Yes — passphrase existence noted, never value) |
| 14 | §9.5 (Yes — signer inventory) |
| 15 | §9.5 (Yes — hardware wallet model in private mode; redacted in public-safe) |
| 16 | §9.5 (Yes — last drill date) |
| 17 | §9.5 (Yes — next drill date) |
| 18 | §9.5 (Yes — app version) |
| 19 | §9.5 (Yes — report hash) |
| 20 | §9.5 (Yes — public-safe vs private modes) |

## A.15 UX and Accessibility (§15)

| Q | Answer Location |
|---|-----------------|
| 1 | §9.4 (8th-grade for heir; ~10th-grade for owner) |
| 2 | §15.9 (Beginner default; advanced via expanders + persistent toggle) |
| 3 | §15.9 (Yes — expanders) |
| 4 | §15.9 (Yes — inline definitions + glossary) |
| 5 | §15.9 (Yes — glossary in Learn section) |
| 6 | §15.5 (Yes — text + icon + color) |
| 7 | §22.10 (Yes — dark/light/system) |
| 8 | §15.5 (Yes — 1.5x and 2x scaling) |
| 9 | §15.5 (Yes) |
| 10 | §15.5 (Yes — NVDA/VoiceOver/Orca tested) |
| 11 | §15.5 (Yes — semantic HTML + tagged PDFs) |
| 12 | §15.5 (Yes — "Copy explanation" button) |
| 13 | §22.6 (Persistent banners) |
| 14 | §14.5 (Per-warning override with typed confirmation; no global "I know what I'm doing" toggle) |
| 15 | §14.5 (No — explicitly rejected) |
| 16 | §15.4 ("Not Ready" with detail; never softer than warranted) |
| 17 | §15.4 ("Needs Attention" or "Not Ready"; never bare "fail") |
| 18 | §15.2 (Brief 5-screen onboarding; in-depth lesson in Learn) |
| 19 | §15.9 (Yes in Learn section; deferred for in-flow MVP — too much work) |
| 20 | §22.9 (Yes — "Use sample descriptor" button on every input) |

## A.16 Privacy Model (§16)

| Q | Answer Location |
|---|-----------------|
| 1 | §13.4 (Classification table) |
| 2 | §13.4 (Yes — Confidential) |
| 3 | §13.4 (Yes — Confidential) |
| 4 | §13.4 (Yes — contains derived addresses + xpubs) |
| 5 | §13.4 (Yes — Confidential in private mode; redacted in public-safe) |
| 6 | §13.6 (Yes by default) |
| 7 | §13.6 (Yes — opt-in v0.2+) |
| 8 | §13.6 (Yes — post-MVP) |
| 9 | §17.7 (Yes — `public-safe` vs `private` labels) |
| 10 | §22.7 (Implicit — public-safe is default; user toggles private with confirmation dialog) |
| 11 | §17.7 (No print warning in MVP since print uses OS dialog; v0.2 adds) |
| 12 | §17.7 (Yes — public-safe mode is default share-safe) |
| 13 | §14.3 (Yes — every export warns) |
| 14 | §13.10 (No — no auto-update) |
| 15 | §28.4 (No — docs embedded; no in-app remote fetch) |
| 16 | §28.4 (Yes — docs embedded) |
| 17 | §21.3 (External link allowlist; user clicks open in OS browser) |
| 18 | §21.3 (No additional warning beyond URL display) |
| 19 | §14.4 (Yes — full table in Settings + this PRD) |
| 20 | §14.5 (No explicit toggle — MVP default is fully offline; v0.2+ adds toggle) |

## A.17 App Storage and Project Files (§17)

| Q | Answer Location |
|---|-----------------|
| 1 | §13.6 (No project files in MVP) |
| 2 | N/A (post-MVP `.lifeboat.json`) |
| 3 | Post-MVP design (encrypted project files in v0.2+) |
| 4 | Post-MVP design |
| 5 | §13.4 (Never store Secret; Confidential opt-in only) |
| 6 | §13.6 (No in MVP; opt-in v0.2+) |
| 7 | §13.6 (Yes — disabled by default forever) |
| 8 | §13.6 (Yes — settings file is the only persistence) |
| 9 | §13.6 (Yes — JSON) |
| 10 | §13.6 (Per-OS paths listed) |
| 11 | §13.6 (No — export only on demand) |
| 12 | §13.6 (Temporary files immediately deleted on close; runbooks written to user-chosen path) |
| 13 | §13.6 (Yes) |
| 14 | §13.6 (No in MVP; opt-in v0.2+ via diagnostic mode toggle) |
| 15 | §13.6 (WARN level when enabled; INFO with `--verbose`) |
| 16 | §13.11 (Yes — Confidential scrubbed) |
| 17 | §13.6 (Yes — "Clear all local data" button in Settings) |
| 18 | §17.10 (CLI is inherently portable; desktop "portable mode" deferred) |
| 19 | §17.10 (CLI binaries are USB-portable; desktop portable mode in v0.2+) |
| 20 | §26.2 (Settings file has `version` field; migrations on schema bump) |

## A.18 Desktop Distribution (§18)

| Q | Answer Location |
|---|-----------------|
| 1 | §12.2 (macOS, Windows, Linux at launch) |
| 2 | §13.9, §26.1 (Yes) |
| 3 | §26.8 ($99/yr budgeted) |
| 4 | §26.8 (~$300/yr OV cert; cloud HSM) |
| 5 | §26.1 (OV-signed; SmartScreen reputation built over time) |
| 6 | §12.2 (AppImage in MVP) |
| 7 | §12.2 (v0.2) |
| 8 | §12.2 (Yes in MVP) |
| 9 | §12.2 (v0.3 community-maintained) |
| 10 | §26.7 (GitHub Releases + dedicated download page) |
| 11 | §26.7 (Website links to GitHub assets; mirrors checksums) |
| 12 | §26.7 (Yes — checksums on page) |
| 13 | §26.7 (Yes — signatures on page) |
| 14 | §13.12 (Aspirational v1.0) |
| 15 | §26.4 (Yes — GitHub Actions only) |
| 16 | §26.4 (CI only; never maintainer-local) |
| 17 | §26.4 (Cloud HSM via Azure Trusted Signing / SSL.com eSigner) |
| 18 | §26.4 (Two-maintainer approval) |
| 19 | §13.13 (Documented revocation in SECURITY.md) |
| 20 | §13 (signed releases + transparency log + reproducible builds aspirational) |

## A.19 Auto-Update Policy (§19)

| Q | Answer Location |
|---|-----------------|
| 1 | §13.10 (No) |
| 2 | §13.10 (N/A — no checks at all) |
| 3 | §13.10 (Browser-redirect only) |
| 4 | §13.10 (Update metadata on GitHub) |
| 5 | §13.9 (Yes — signed releases) |
| 6 | §13.10 (No update server) |
| 7 | §26.4 (Yes — release notes auto-generated) |
| 8 | §26.4 (Users can skip releases — no enforcement) |
| 9 | §26.6 (Yes — security advisory format) |
| 10 | §13.10 (Never — no auto-install) |
| 11 | §13.10 (No updater at all) |
| 12 | §13.10 (N/A — no updater) |
| 13 | §13.10 (Yes — verification instructions in download page) |
| 14 | §13.9 (minisign + cosign keyless; not Tauri updater signatures) |
| 15 | §13.9 (Public key published in three places) |
| 16 | §13.9 (1-year rotation cadence with overlap) |
| 17 | §13.3, T15 (Eliminated by not having updater) |
| 18 | N/A — no update check |
| 19 | §14.4 (Tor/SOCKS in v0.3+) |
| 20 | §13.12 (Reproducible builds aspirational v1.0) |

## A.20 CLI Design (§20)

| Q | Answer Location |
|---|-----------------|
| 1 | §2 D12 (Yes — first-class) |
| 2 | §23.4 (Both — separate binary + bundled with desktop installer) |
| 3 | §17.10 (`lifeboat`) |
| 4 | §17.10.10 (Yes — stable within major version) |
| 5 | §23.3 (Yes — human is default) |
| 6 | §17.10 (Yes — `--json` on every relevant command) |
| 7 | §23.1 (Yes — no network in MVP) |
| 8 | §23.2 (Yes) |
| 9 | §23.2 (Exit code table) |
| 10 | §17.10 (Yes — `generate-runbook`) |
| 11 | §17.10 (Yes — `derive-addresses`) |
| 12 | §17.10 (Yes — `detect-secrets`) |
| 13 | §11.1 (v0.2) |
| 14 | §11.3 (v0.4) |
| 15 | §17.11 (Yes — clap_mangen) |
| 16 | §17.11 (Yes — clap_complete) |
| 17 | §23.4 (v0.2) |
| 18 | §23.4 (Yes — v0.2 .deb) |
| 19 | §23.7 (Yes — CI integration example) |
| 20 | §23.8 (Yes — golden tests enforce) |

## A.21 Error Handling (§21)

| Q | Answer Location |
|---|-----------------|
| 1 | §21.5 (Error taxonomy) |
| 2 | §21.5 (E-INPUT-*) |
| 3 | §21.5 (E-INTERNAL-*) |
| 4 | §21.5 (E-SECRET-*) |
| 5 | Appendix C (Plain-English messages per code) |
| 6 | Appendix C |
| 7 | Appendix C |
| 8 | Appendix C |
| 9 | Appendix C |
| 10 | Appendix C |
| 11 | §22.5 (Yes — expanders) |
| 12 | §22.5 (Yes — links to in-app docs) |
| 13 | §22.5 (Yes — Copy buttons) |
| 14 | §13.11 (Crash dialogs scrub Confidential; user opts in to attach log) |
| 15 | §13.11 (Logs included if user enables diagnostic mode + agrees) |
| 16 | §13.11 (Yes — warning to scrub before sharing) |
| 17 | §13.11 (Yes — `human-panic` formats friendly errors) |
| 18 | §21.5 (Yes — `thiserror` enums) |
| 19 | §21.5 (Yes — error code passed verbatim) |
| 20 | §21.5 (Yes — documented in `docs/error-codes.md`) |

## A.22 Testing and Verification (§22)

| Q | Answer Location |
|---|-----------------|
| 1 | §25.1 (≥ 80% line coverage per crate) |
| 2 | §25.5 (Listed targets) |
| 3 | §25.5 (Yes) |
| 4 | §25.5 (Yes — false-positive + false-negative + arbitrary) |
| 5 | §25.4 (Yes — `insta` snapshots) |
| 6 | §25.4 (PDF by hash; visual regression manual) |
| 7 | §25.4 (Yes) |
| 8 | §25.4 (Yes — 50+ golden fixtures) |
| 9 | §25.2 (Yes — cross-checked with Bitcoin Core test vectors) |
| 10 | §25.2 (Yes for descriptor parsing) |
| 11 | §25.11 (Yes for v0.4+ HWI) |
| 12 | §25.11 (Emulator-based in CI) |
| 13 | §25.11 (Yes — compatibility matrix tracked manually) |
| 14 | Same |
| 15 | §25.6 (Yes — regtest integration) |
| 16 | §25.6 (Signet integration runs only on release-tagged builds) |
| 17 | §25.1 (Yes — Playwright/WebDriver E2E) |
| 18 | §25.1 (Yes — every Tauri command) |
| 19 | §25.6 (Yes — full matrix) |
| 20 | §25.7 (Yes — `cargo audit`, `cargo deny`, `npm audit`, OSV, gitleaks, semgrep) |

## A.23 Dependencies and Supply Chain (§23)

| Q | Answer Location |
|---|-----------------|
| 1 | §3.2 (rust-bitcoin 0.32.5, rust-miniscript 13.0.0) |
| 2 | §3.2 (Pinned in Cargo.toml) |
| 3 | §20 (Cargo.lock committed; vendoring not required; SBOM published) |
| 4 | §20 (Yes — committed) |
| 5 | §25.7 (Yes — `npm audit` enforced) |
| 6 | §25.7 (Yes — bundle-size budget; component lib limited) |
| 7 | §25.7 (Yes) |
| 8 | §25.7 (Yes) |
| 9 | §25.7 (Yes) |
| 10 | §25.7 (Yes — Dependabot enabled) |
| 11 | §29.6 (Two-maintainer review for Bitcoin/crypto deps; not automatic) |
| 12 | §29.6 (Same) |
| 13 | §13.7 (Yes — minimized Tauri plugins) |
| 14 | §13.7 (Allowed list specified) |
| 15 | §13.8 (Yes — strict CSP, no remote) |
| 16 | §13.8 (Yes) |
| 17 | §13.8 (Yes — no `eval`, no remote scripts) |
| 18 | §35.2 (Yes — `cargo deny check licenses`) |
| 19 | §35.2 (Yes — only vetted Bitcoin crates) |
| 20 | §26.1 (Yes — SPDX + CycloneDX SBOM published per release) |

## A.24 Security Review and Audit (§24)

| Q | Answer Location |
|---|-----------------|
| 1 | §11.6 (Internal review before public beta; external audit pre-v1.0) |
| 2 | §11.6 (Paid audit before v1.0) |
| 3 | §11.6 (Established Bitcoin auditors — Spiral, Anchorage, NCC Group, or community fund) |
| 4 | §29.6 (Tauri experts review capability config) |
| 5 | §29.6 (UX safety review by team + community) |
| 6 | §29.6 (Hardware-wallet flows reviewed before v0.3 ships) |
| 7 | §13.13 (Bounty considered post-audit) |
| 8 | §13.13 (Yes — `SECURITY.md`) |
| 9 | §13.13 (Yes — PGP key in SECURITY.md) |
| 10 | §11.6 (v1.0 release gated on audit) |
| 11 | §11.6, §26.3 (Yes — "Alpha"/"Beta" banner on pre-v1.0 releases) |
| 12 | §17.2 (Taproot/Miniscript preview-only until tested) |
| 13 | §26.3 (Yes — Alpha/Beta labels) |
| 14 | §26.3 (Yes) |
| 15 | §26.6 (GHSA + RSS) |
| 16 | §13.13, §26.6 (Security mailing list + RSS) |
| 17 | §26.6 (Old releases marked deprecated) |
| 18 | §26.1 (Yes — release notes include security impact) |
| 19 | §16.8 (Yes — banned) |
| 20 | §16.8 ("Diagnostic", "ready for the tested scenario", "passes the checks") |

## A.25 Legal and Disclaimer (§25)

| Q | Answer Location |
|---|-----------------|
| 1 | §35.1 (MIT) |
| 2 | §35.1 (MIT specifically) |
| 3 | §35.2 (Disallowed list enforced) |
| 4 | §15.6 (Yes — short + long disclaimer) |
| 5 | §15.6 (Yes — verbatim) |
| 6 | §15.6 (Yes — heir disclaimer) |
| 7 | §15.6 (Yes — "consult an attorney" language) |
| 8 | §15.6 (Yes — "consult a tax professional") |
| 9 | §15.6 (Yes — no jurisdiction-specific advice) |
| 10 | §16.8 (Yes — banned) |
| 11 | §15.6 (Yes — every report) |
| 12 | §15.6 (Yes — every runbook) |
| 13 | §28.1 (Yes — website includes disclaimers) |
| 14 | §35.3 (No — DCO not CLA) |
| 15 | §35.3 (Yes — DCO) |
| 16 | §29.9 (Yes — trademark guidelines) |
| 17 | §29.9 (Project entity TBD pre-v1.0; foundation post-v1.0) |
| 18 | §29.9 (Yes — MIT permits commercial use) |
| 19 | §29.9 (Yes — but cannot use name without permission) |
| 20 | §29.9 (Yes — modified builds must rename) |

## A.26 Community and Governance (§26)

| Q | Answer Location |
|---|-----------------|
| 1 | §29.6 (Lead maintainer TBD; named in CODEOWNERS) |
| 2 | §29.6 (Individual pre-v1.0; foundation transition post-v1.0) |
| 3 | §29.6 (Maintainers per CODEOWNERS) |
| 4 | §29.6 (Two-maintainer for security-sensitive) |
| 5 | §26.4 (Yes — two-maintainer release approval) |
| 6 | §29.6 (Yes for Bitcoin/crypto deps) |
| 7 | §26.4 (Yes — two-maintainer release) |
| 8 | §29.6 (RFC + lead maintainer call) |
| 9 | §29.6 (Public RFC + community input) |
| 10 | §29.6 (Lead maintainer call) |
| 11 | §29.7 (Matrix + GitHub Discussions; no Discord/Telegram pre-v1.0) |
| 12 | §29.8 (Maintainers refuse to give recovery advice for real funds) |
| 13 | §29.8 (Yes — explicit refusal documented) |
| 14 | §29.8 (Support boundary documented) |
| 15 | §29.8 (Anti-scam posture; "we never contact you first") |
| 16 | §29.8 (Yes — repeated everywhere) |
| 17 | §29.8 (Yes — anti-scam doc) |
| 18 | §29.6 (Yes — `CONTRIBUTING.md` includes security rules) |
| 19 | §29.6 (Yes — native-speaker review) |
| 20 | §18.7, §29.6 (CI lint + native-speaker review for translations) |

## A.27 Documentation Requirements (§27)

Already mapped above in §28.

## A.28 Compatibility Matrix (§28)

Already mapped above in §24.2.

## A.29 Future Mobile Companion (§29)

| Q | Answer Location |
|---|-----------------|
| 1 | §12.3 (Yes — v1.1+) |
| 2 | §12.3 (Android first via F-Droid) |
| 3 | §12.3 (iOS in v1.2) |
| 4 | §12.3 (Tauri 2 mobile preferred) |
| 5 | §12.3 (Yes — shared Rust core) |
| 6 | §12.3 (Mostly — checklist + viewer + QR scan) |
| 7 | §12.3 (Yes — QR PSBT) |
| 8 | §12.3 (Yes — runbook viewer) |
| 9 | §12.3 (Storage opt-in only) |
| 10 | §12.3 (Read-only — no editing) |
| 11 | §12.3 (Yes — QR transport) |
| 12 | §12.3 (No — mobile cannot reliably host USB devices) |
| 13 | §12.3 (No — never seed input on mobile) |
| 14 | §12.3 (Yes — offline mode default) |
| 15 | §12.3 (F-Droid primary) |
| 16 | §12.3 (Play Store v1.2; iOS App Store v1.2+) |
| 17 | §12.3 (Documented signature verification + checksum mirroring) |
| 18 | §12.3 (Documented; users verify against website hash) |
| 19 | §12.3 (Yes — deferred until desktop v1.0) |
| 20 | §12.3 (Heir-side drill viewer + portable runbook reference) |

## A.30 "Can't Ship Without" (§30)

Already answered in §2 D1–D20.

---

# Appendix B: Library Versions and Citations

## B.1 Core Rust Dependencies (Pinned)

| Crate | Version | Source | Purpose |
|-------|---------|--------|---------|
| `rust-bitcoin` | 0.32.5 | crates.io | Bitcoin types, addresses, networks |
| `rust-miniscript` | 13.0.0 | crates.io | Descriptor parsing, Miniscript, Taproot |
| `bip39` | latest (English + multilang feature flags) | crates.io | BIP39 checksum validation in detector |
| `slip-0039` (or equivalent) | latest | crates.io | SLIP-39 detection |
| `codex32` | latest | crates.io | BIP-93 codex32 detection |
| `zeroize` | 1.8.x | crates.io | Memory zeroization |
| `secrecy` | 0.10.x | crates.io | `SecretString`, `SecretBox<T>` |
| `serde` | 1.x | crates.io | Serialization |
| `serde_json` | 1.x | crates.io | JSON I/O |
| `thiserror` | 1.x | crates.io | Error enums |
| `anyhow` | 1.x | crates.io | Prototyping / scripts only (NOT in library code) |
| `tracing` | 0.1.x | crates.io | Structured logging |
| `tracing-subscriber` | 0.3.x | crates.io | Log filtering, scrubbing |
| `clap` | 4.x | crates.io | CLI parsing |
| `clap_mangen` | latest | crates.io | Man pages |
| `clap_complete` | latest | crates.io | Shell completions |
| `human-panic` | 2.x | crates.io | Friendly panic output |
| `printpdf` | latest | crates.io | PDF fallback (when Typst unavailable) |
| `qrcode` | latest | crates.io | QR generation (runbook fingerprint QR; PSBT QR in v0.3) |
| `rqrr` | latest | crates.io | QR decoding (v0.3) |
| `nokhwa` | latest | crates.io | Camera capture (v0.3) |
| `ur` | latest (`dspicher/ur-rs`) | crates.io | UR (BCR-2020-005) PSBT QR (v0.3) |
| `bbqr` | latest | crates.io | BBQr PSBT QR (v0.3) |
| `bdk_wallet` | 3.x | crates.io | Wallet state (v0.2 signet-lab only) |
| `insta` | 1.x | crates.io | Snapshot tests |
| `criterion` | 0.5.x | crates.io | Benchmarks |
| `cargo-fuzz` (dev) | latest | crates.io | Fuzz harness |
| `cargo-deny` (dev) | latest | crates.io | License/advisory/source enforcement |
| `cargo-audit` (dev) | latest | crates.io | Vulnerability scan |

## B.2 Tauri Stack

| Crate / Package | Version |
|-----------------|---------|
| `tauri` | 2.11.x |
| `@tauri-apps/api` | 2.11.x |
| `@tauri-apps/cli` | 2.11.x |
| `tauri-plugin-dialog` | matched to Tauri 2.11.x |
| `tauri-plugin-os` | matched |
| `tauri-plugin-fs` | matched (dialog-scoped) |
| `tauri-plugin-camera` (v0.3+) | matched |
| `tauri-plugin-hid` (v0.4+, only if direct USB chosen) | NOT used in MVP/v0.3/v0.4 — subprocess HWI preferred |

## B.3 Frontend Stack

| Package | Version |
|---------|---------|
| `react` | 18.x |
| `react-dom` | 18.x |
| `typescript` | 5.x |
| `vite` | 5.x |
| `tailwindcss` | 3.x |
| `zustand` | 4.x |
| `i18next` | 23.x |
| `react-i18next` | 14.x |
| `@radix-ui/react-*` | latest per component |
| `lucide-react` | latest |
| `markdown-it` | 14.x (strict, no HTML) |
| `vitest` | 1.x |
| `@playwright/test` | 1.x |
| `@axe-core/playwright` | latest |

## B.4 Build / CI Tooling

| Tool | Purpose |
|------|---------|
| `tauri-action` (GitHub Action) | Multi-platform Tauri builds |
| `sigstore/cosign` | Keyless transparency-log signing |
| `jedisct1/minisign` | Ed25519 release signatures |
| `apple/notarytool` | macOS notarization |
| Azure Trusted Signing / SSL.com eSigner | Windows OV cert HSM signing |
| `aquasecurity/trivy` | Container/dependency scanning (optional) |
| `google/osv-scanner` | OSV.dev vulnerability scan |
| `gitleaks/gitleaks` | Secret scanning of repo |
| `returntocorp/semgrep` | Static analysis |

## B.5 BIP / SLIP References

All BIPs at `https://github.com/bitcoin/bips/`.

| BIP | Title |
|-----|-------|
| BIP32 | Hierarchical Deterministic Wallets |
| BIP39 | Mnemonic code for generating deterministic keys |
| BIP44 | Multi-Account Hierarchy for Deterministic Wallets |
| BIP49 | Derivation scheme for P2WPKH-nested-in-P2SH |
| BIP84 | Derivation scheme for P2WPKH |
| BIP86 | Key Derivation for Single Key P2TR Outputs |
| BIP-93 | codex32: Checksummed mnemonic code for Bitcoin |
| BIP125 | Opt-in Full Replace-by-Fee Signaling |
| BIP129 | Bitcoin Secure Multisig Setup (BSMS) |
| BIP141 | Segregated Witness (Consensus layer) |
| BIP174 | Partially Signed Bitcoin Transaction Format (PSBT v0) |
| BIP325 | Signet |
| BIP329 | Wallet Labels Export Format |
| BIP370 | PSBT Version 2 |
| BIP380 | Output Script Descriptors General Operation |
| BIP382 | wsh() Output Script Descriptors |
| BIP383 | multi() and sortedmulti() Output Script Descriptors |
| BIP386 | tr() Output Script Descriptors |
| BIP388 | Wallet Policies for descriptor wallets |
| BIP389 | Multipath descriptor expressions |

| SLIP | Title |
|------|-------|
| SLIP-39 | Shamir's Secret-Sharing for Mnemonic Codes |
| SLIP-132 | Registered HD version bytes for BIP-0032 |

| Other Specs | Title |
|-------------|-------|
| BCR-2020-005 | Uniform Resources (UR) |
| BCR-2020-006 | Registry of Uniform Resource (UR) Types |
| BBQr | Better Bitcoin QR specification (coinkite/BBQr) |

---

# Appendix C: Error Code Catalog

## C.1 Format

Every error has:

```
Code:        E-XXX-NNN
Severity:    user_correctable | warning | critical | security
Title:       short human-readable label
Description: plain-English description
Action:      what the user should do
```

## C.2 Input Errors (E-INPUT-*)

```
E-INPUT-001 / user_correctable
Title:       Empty input
Description: No descriptor or file was provided.
Action:      Paste a descriptor or choose a file.

E-INPUT-002 / user_correctable
Title:       Input too large
Description: The file exceeds the 10 MB limit.
Action:      Trim the file or contact support if it should be smaller.

E-INPUT-003 / user_correctable
Title:       Invalid file format
Description: The file's content does not match any known wallet export format.
Action:      Confirm the file is a descriptor (.txt, .json) or supported wallet export.
```

## C.3 Parse Errors (E-PARSE-*)

```
E-PARSE-001 / user_correctable
Title:       Descriptor cannot be parsed
Description: The text you provided is not a valid BIP380 descriptor.
Action:      Confirm you copied the full descriptor including any leading `wsh(`/`wpkh(`. If you're unsure, see the per-wallet export instructions.

E-PARSE-002 / warning
Title:       Descriptor checksum missing
Description: BIP380 descriptors should include a `#xxxxxxxx` checksum.
Action:      Add the checksum (Lifeboat can compute one) or re-export from your wallet.

E-PARSE-003 / critical
Title:       Descriptor checksum invalid
Description: The descriptor's checksum does not match its content. The descriptor may have been transcribed incorrectly.
Action:      Re-export the descriptor from your wallet software.

E-PARSE-004 / critical
Title:       Descriptor mixes networks
Description: The descriptor contains keys from multiple Bitcoin networks (e.g., mainnet and testnet).
Action:      This is almost always a mistake. Re-export the descriptor and verify it contains only mainnet keys (or only testnet, if intentional).

E-PARSE-005 / critical
Title:       Descriptor contains private keys
Description: The descriptor includes an extended private key (xprv/yprv/zprv/tprv/uprv/vprv) or a raw private key. Lifeboat refuses to process descriptors that contain secret material.
Action:      Re-export the descriptor in watch-only form (xpub instead of xprv).

E-PARSE-006 / user_correctable
Title:       Unsupported descriptor function
Description: The descriptor uses a function Lifeboat does not yet support in this version (e.g., raw(), addr()).
Action:      Use a wallet that exports a supported descriptor (wpkh, wsh, sh(wpkh), multi, sortedmulti).

E-PARSE-007 / warning
Title:       Multisig threshold exceeds key count
Description: The descriptor specifies M-of-N where M > N, which can never be satisfied.
Action:      Confirm the descriptor; this likely indicates a transcription error.
```

## C.4 Secret Detection Errors (E-SECRET-*)

```
E-SECRET-001 / security
Title:       BIP39 mnemonic detected
Description: The input contains a sequence of words matching a BIP39 wordlist with a valid checksum. Lifeboat does not accept seed phrases.
Action:      Export the OUTPUT DESCRIPTOR (not the seed) from your wallet software and paste it instead.

E-SECRET-002 / security
Title:       Possible BIP39 mnemonic detected
Description: The input contains a sequence of BIP39 words; the checksum did not validate but the pattern is suspicious.
Action:      If you intended to paste a descriptor and this is a false positive, type "I confirm this is not a real seed" to proceed.

E-SECRET-003 / security
Title:       Private key (WIF) detected
Description: The input matches the WIF private key format. Lifeboat does not accept private keys.
Action:      Use the corresponding public key or xpub instead.

E-SECRET-004 / security
Title:       Extended private key detected
Description: The input contains an xprv / yprv / zprv / tprv / uprv / vprv. Lifeboat does not accept extended private keys.
Action:      Use the corresponding xpub / ypub / zpub / tpub / upub / vpub instead.

E-SECRET-005 / security
Title:       SLIP-39 share detected
Description: The input appears to be a SLIP-39 Shamir backup share.
Action:      Lifeboat does not need SLIP-39 shares. Use your wallet's output descriptor.

E-SECRET-006 / security
Title:       codex32 secret detected
Description: The input appears to be a codex32 (BIP-93) secret.
Action:      Lifeboat does not need codex32 secrets. Use your wallet's output descriptor.

E-SECRET-007 / security
Title:       Possible raw private key detected
Description: The input contains a 64-character hex string in a suspicious context (e.g., adjacent to the word "private" or "key").
Action:      Confirm this is not a private key. If you intended a transaction ID or block hash, it should not appear in this field.
```

## C.5 File System Errors (E-FS-*)

```
E-FS-001 / user_correctable
Title:       File not found
Description: The file path you provided does not exist or is not readable.
Action:      Verify the path and permissions, then try again.

E-FS-002 / user_correctable
Title:       Cannot write to destination
Description: The destination path is not writable.
Action:      Choose a different destination or check permissions.

E-FS-003 / warning
Title:       Destination file exists
Description: A file already exists at the destination.
Action:      Confirm overwrite or choose a different name.
```

## C.6 Network Errors (E-NETWORK-*)

```
E-NETWORK-001 / user_correctable
Title:       Network unreachable
Description: The user-initiated network call failed.
Action:      Verify your internet connection or try again later.

E-NETWORK-002 / security
Title:       Unexpected network call attempted
Description: Internal: A component attempted a network call without explicit user action.
Action:      This is a bug. Please file an issue at the GitHub repository.
```

## C.7 External Dependency Errors (E-DEP-*)

```
E-DEP-001 / internal
Title:       Typst not bundled
Description: PDF generation requires the bundled Typst binary, which was not found.
Action:      Reinstall Lifeboat. If the issue persists, file an issue.

E-DEP-002 / internal
Title:       HWI not available
Description: Hardware wallet operations require the HWI sidecar binary (v0.4+), which was not found.
Action:      Reinstall the version of Lifeboat that includes HWI, or use file-based PSBT.
```

## C.8 Link Safety Errors (E-LINK-*)

```
E-LINK-001 / security
Title:       External link not allowed
Description: The link is not in the project's allowlist of external URLs.
Action:      Verify the link manually in your browser if you trust it.
```

## C.9 Internal Errors (E-INTERNAL-*)

```
E-INTERNAL-001 / internal
Title:       Unexpected error
Description: An unexpected internal error occurred.
Action:      Please file an issue at the GitHub repository with the reproduction steps.

E-INTERNAL-002 / internal
Title:       Schema migration required
Description: The settings file uses a format from an older version of Lifeboat.
Action:      Lifeboat will attempt to migrate. If that fails, delete the settings file.
```

---

# Appendix D: i18n String Catalog (English)

All user-facing strings live in `apps/desktop/src/i18n/en.json` and `crates/error-taxonomy/strings/en.json`.

Structure:

```json
{
  "onboarding": {
    "welcome": {
      "title": "Bitcoin Lifeboat",
      "body": "Bitcoin Lifeboat helps you test whether your Bitcoin recovery plan works before disaster happens.\n\nIt is not a wallet.\nIt does not custody funds.\nIt does not need your real seed phrase.",
      "continue": "Continue"
    },
    "safety_promise": {
      "title": "Before we start, our four promises:",
      "promise_1": "We never ask for your real seed phrase.",
      "promise_2": "We never connect to the internet without your action.",
      "promise_3": "We never store your wallet metadata.",
      "promise_4": "We never claim your funds are safe.",
      "checkbox_label": "I understand.",
      "continue": "Continue"
    }
  },
  "home": {
    "card_check_backup": {
      "title": "Check My Backup Plan",
      "description": "Audit whether your wallet's recovery metadata appears complete.",
      "time_estimate": "~5 minutes",
      "materials": "You'll need: your wallet descriptor."
    }
  },
  "wizard": {
    "safety_banner": "Do not paste seed words, private keys, or passphrases. This mode needs only your public wallet metadata.",
    "step_indicator": "Step {{current}} of {{total}}"
  },
  "status": {
    "ready": "Ready",
    "mostly_ready": "Mostly Ready",
    "needs_attention": "Needs Attention",
    "not_ready": "Not Ready",
    "cannot_determine": "Cannot Determine"
  },
  "errors": {
    "E-PARSE-001": {
      "title": "Descriptor cannot be parsed",
      "description": "The text you provided is not a valid BIP380 descriptor.",
      "action": "Confirm you copied the full descriptor including any leading `wsh(`/`wpkh(`. See per-wallet export instructions."
    },
    "E-SECRET-001": {
      "title": "BIP39 mnemonic detected",
      "description": "The input contains a sequence of words matching a BIP39 wordlist with a valid checksum. Lifeboat does not accept seed phrases.",
      "action": "Export the OUTPUT DESCRIPTOR (not the seed) from your wallet software and paste it instead."
    }
  },
  "disclaimers": {
    "short": "This report is a diagnostic aid. It is not legal, tax, financial, or security advice. Bitcoin Lifeboat cannot guarantee that any wallet is recoverable.",
    "long": "About this document\n\nBitcoin Lifeboat is an open-source diagnostic and rehearsal tool. This document reflects only the information you provided. ..."
  }
}
```

i18n lint rules in CI:

- No string concatenation for user-facing text (use placeholders `{{var}}`).
- No hardcoded English in `.tsx` / `.rs` outside of fallback constants.
- Every key referenced in code must exist in `en.json`.
- Every key in `en.json` must be referenced somewhere (no dead strings).

---

# Appendix E: Source Research Citations

The following resources informed v2 decisions (all accessed 2026-05-28):

## Bitcoin Libraries
- `rust-bitcoin` 0.32.5 — `crates.io/crates/bitcoin`
- `rust-miniscript` 13.0.0 — `github.com/rust-bitcoin/rust-miniscript/blob/master/CHANGELOG.md`
- `bdk_wallet` 3.0.0 — `crates.io/crates/bdk_wallet`
- BIP380 (descriptors): `github.com/bitcoin/bips/blob/master/bip-0380.mediawiki`
- BIP386 (tr): `bips.xyz/386`
- BIP129 (BSMS): `github.com/bitcoin/bips/blob/master/bip-0129.mediawiki`
- BIP389 (multipath): `bips.dev/389`
- Liana recovery: `github.com/wizardsardine/liana/blob/master/doc/RECOVER.md`

## Tauri
- Tauri 2.0 stable: `v2.tauri.app/blog/tauri-20/`
- Capabilities: `v2.tauri.app/security/capabilities/`
- Updater plugin: `v2.tauri.app/plugin/updater/`
- GHSA-2rcp-jvr4-r259 updater key leak: `github.com/tauri-apps/tauri/security/advisories/GHSA-2rcp-jvr4-r259`
- Issue #7585 multi-pubkey rotation: `github.com/tauri-apps/tauri/issues/7585`
- Bishop Fox "Beyond Electron": `bishopfox.com/blog/beyond-electron-attacking-alternative-desktop-application-frameworks`

## Wallet Exports
- Bitcoin Core listdescriptors: `bitcoincore.org/en/doc/29.0.0/rpc/wallet/listdescriptors/`
- Sparrow features: `sparrowwallet.com/features/`
- Specter docs: `docs.specter.solutions/desktop/`
- Liana 13.0 release: `wizardsardine.com/blog/liana-13.0-release/`
- Nunchuk recovery: `resources.nunchuk.io/wallet-recovery/`
- Coldcard descriptor export: `coldcard.com/docs/descriptor_export/`
- Passport Core: `foundation.xyz/2025/03/passport-is-now-passport-core/`
- Jade multisig backup: `help.blockstream.com/hc/en-us/articles/20389615544089-Backup-a-multisig-configuration-on-Jade`

## HWI
- HWI 3.2.0: `github.com/bitcoin-core/HWI/releases`
- rust-hwi archived: `github.com/bitcoindevkit/rust-hwi`
- async-hwi (Wizardsardine): `github.com/wizardsardine/async-hwi`
- ur-rs Rust UR codec: `github.com/dspicher/ur-rs`
- BBQr Rust: `github.com/satoshiportal/bbqr-rust`
- Tauri sidecar pattern: `v2.tauri.app/develop/sidecar/`

## Detector
- BIP39 wordlists: `github.com/bitcoin/bips/tree/master/bip-0039`
- SLIP-39: `github.com/satoshilabs/slips/blob/master/slip-0039.md`
- BIP-93 codex32: `github.com/bitcoin/bips/blob/master/bip-0093.mediawiki`
- zeroize: `docs.rs/zeroize`
- secrecy: `docs.rs/secrecy`
- Tauri memory limitations: `github.com/orgs/tauri-apps/discussions/10852`
- cargo-fuzz: `rust-fuzz.github.io/book/cargo-fuzz.html`

## Distribution & Signing
- Sigstore cosign: `docs.sigstore.dev/cosign/`
- Minisign: `jedisct1.github.io/minisign/`
- 460-day code signing mandate (2026): `appviewx.com/blogs/460-day-code-signing-certificate-2026/`
- Wasabi reproducible build (informational): `docs.wasabiwallet.io/using-wasabi/DeterministicBuild.html`
- Bitcoin Core Guix builds: `github.com/bitcoin/bitcoin/blob/master/contrib/guix/README.md`

---

# Document History

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | 2026-05-21 | (initial) | First production-ready PRD |
| 2.0 | 2026-05-28 | (this) | All 600+ open questions resolved; pinned library versions; concrete acceptance criteria; appendix mapping question→section |

---

# End of PRD v2.0
