/**
 * Typed client for the Rust core (PRD §21.3 Tauri commands).
 *
 * This is the SINGLE seam between the React UI and the Bitcoin logic: the
 * frontend never parses descriptors, detects secrets, or does crypto — it calls
 * a `#[tauri::command]` here and gets back a leak-free, crate-owned serde type
 * (§13.5.8 / §20). Future stories extend this module (US-050 `generate_report`,
 * US-051 `save_export`, …); component tests `vi.mock("../tauri/commands")` so the
 * jsdom suite never touches the real IPC bridge.
 *
 * `withGlobalTauri` is false (tauri.conf.json), so `invoke` is imported from the
 * `@tauri-apps/api` package — there is no `window.__TAURI__` global.
 */
import { invoke } from "@tauri-apps/api/core";

/**
 * What the caller must do with screened input (mirrors the Rust
 * `sensitive_input_detector::DetectorAction`, serialized snake_case). Ordered by
 * severity: `allow < warn < block`.
 */
export type DetectorAction = "allow" | "warn" | "block";

/** Network a key encodes, to the resolution its version bytes allow (§17.4). */
export type DetectorNetwork = "mainnet" | "testnet";

/**
 * The kind of secret recognized, with only NON-secret metadata (§13.5). Mirrors
 * the externally-tagged Rust `DetectedSecret` enum: data-carrying variants
 * serialize as `{ "<tag>": { …fields } }`, unit variants as the bare tag string.
 * The detected secret's own characters are NEVER present here.
 */
export type DetectedSecret =
  | { bip39: { language: string; word_count: number; checksum_valid: boolean } }
  | { wif: { network: DetectorNetwork; compressed: boolean } }
  | { xprv: { kind: string; network: DetectorNetwork } }
  | "raw_hex_priv_key"
  | { slip39: { share_count_in_input: number } }
  | { codex32: { threshold: number } }
  | "none";

/** A half-open `[start, end)` byte range into the screened input (indices only). */
export interface ByteRange {
  start: number;
  end: number;
}

/** One recognized secret: its discriminant plus where it sat in the input. */
export type Finding = [DetectedSecret, ByteRange];

/**
 * The detector's verdict (§13.5.8). The only value derived from screened input
 * that crosses back to JS — it carries discriminants and byte ranges, never the
 * secret content.
 */
export interface DetectorReport {
  findings: Finding[];
  action: DetectorAction;
}

/**
 * §21.3 `detect_sensitive_input`: screen pasted/loaded text for Bitcoin secret
 * material BEFORE the app processes it. The input is wrapped in a Rust
 * `SecretString` and zeroized inside the core call; only the leak-free
 * {@link DetectorReport} comes back.
 */
export function detectSensitiveInput(input: string): Promise<DetectorReport> {
  return invoke<DetectorReport>("detect_sensitive_input", { input });
}

// --- §19.1 ReadinessReport (audit_descriptor / US-050 report viewer) ---------

/**
 * The §16.2 qualitative readiness status (snake_case; mirrors the Rust
 * `readiness_score::ReadinessStatus`). Identical to the union the `StatusBadge`
 * component accepts, so `report.score.status` passes straight to it.
 */
export type ReadinessStatus =
  | "ready"
  | "mostly_ready"
  | "needs_attention"
  | "not_ready"
  | "cannot_determine";

/** The verdict of a single §9.1 analysis check. */
export type CheckResult = "pass" | "warn" | "fail" | "na" | "unknown";

/** §19.1 `wallet_summary` — the shape of the audited wallet. `threshold` /
 *  `key_count` are `null` for a single-signature wallet. */
export interface WalletSummary {
  wallet_type: string;
  script_type: string;
  threshold: number | null;
  key_count: number | null;
  has_receive_descriptor: boolean;
  has_change_descriptor: boolean;
  uses_multipath: boolean;
  uses_taproot: boolean;
  uses_miniscript: boolean;
  uses_timelock: boolean;
  passphrase_documented: boolean;
}

/** §19.1 one descriptor (receive or change), with redacted + canonical forms. */
export interface ReportDescriptor {
  raw: string;
  raw_redacted: string;
  canonical: string;
  checksum_present: boolean;
  checksum_valid: boolean;
  parse_status: string;
}

export interface ReportDescriptors {
  receive: ReportDescriptor | null;
  change: ReportDescriptor | null;
}

/** §19.1 per-key provenance. `xpub` is omitted from a public-safe report; the
 *  `xpub_redacted` form is always present. */
export interface ReportKey {
  index: number;
  fingerprint: string | null;
  derivation_path: string | null;
  xpub?: string;
  xpub_redacted: string;
  key_origin_present: boolean;
}

export interface ReportDerivedAddress {
  index: number;
  address: string;
  chain: string;
}

export interface KnownAddressMatch {
  provided: string;
  matched: boolean;
  matched_at: { index: number; chain: string } | null;
}

export interface ReportAddresses {
  receive_derived: ReportDerivedAddress[];
  change_derived: ReportDerivedAddress[];
  known_address_match: KnownAddressMatch | null;
}

/** §19.1 numeric score + qualitative status + headline. */
export interface Score {
  numeric: number;
  status: ReadinessStatus;
  headline: string;
}

export interface ReportCheck {
  code: string;
  category: string;
  result: CheckResult;
  title: string;
}

/** §16.3 critical failure (forces "Not Ready"). */
export interface CriticalIssue {
  code: string;
  title: string;
  description: string;
}

/** §16.4 warning with user-facing text + an action-oriented fix (§22.5). */
export interface WarningDetail {
  code: string;
  title: string;
  description: string;
  recommended_fix: string;
}

export interface PassItem {
  code: string;
  title: string;
}

export interface ScoringAuditEntry {
  code: string;
  impact: number;
  running_score: number;
}

/** §16.6 multisig survivability, or `null` for singlesig wallets. */
export interface Survivability {
  tested: boolean;
  lose_1_signer: string;
  lose_2_signers: string;
  lose_descriptor_only: string;
}

/** §15.10 item 6 — a prioritized "what to do next" action with an effort hint. */
export interface NextStep {
  priority: number;
  action: string;
  effort: string;
}

/**
 * The §19.1 `ReadinessReport` — the deterministic, leak-free report the Rust core
 * returns from `audit_descriptor`. Field order mirrors §19.1; every field name is
 * the core's snake_case serde name. Confidential (carries the descriptor / xpubs
 * in `private` mode) — never persist it to web storage (§22.11).
 */
export interface ReadinessReport {
  schema_version: string;
  app_version: string;
  scoring_engine_version: string;
  created_at: string;
  mode: string;
  input_hash: string;
  report_hash: string;
  network: string | null;
  wallet_summary: WalletSummary;
  descriptors: ReportDescriptors;
  keys: ReportKey[];
  addresses: ReportAddresses;
  score: Score;
  checks: ReportCheck[];
  critical_issues: CriticalIssue[];
  warnings: WarningDetail[];
  passes: PassItem[];
  scoring_audit: ScoringAuditEntry[];
  survivability: Survivability | null;
  next_steps: NextStep[];
  anti_actions: string[];
  next_drill_recommendation: string | null;
  disclaimer_short: string;
  disclaimer_long: string;
}

/**
 * Input for {@link auditDescriptor} (§21.3 `DescriptorAuditInput`). All fields but
 * `descriptor` are optional — the core infers the network and skips the
 * known-address match when they are absent (serde maps a missing `Option` to
 * `None`).
 */
export interface DescriptorAuditInput {
  descriptor: string;
  network?: string | null;
  known_address?: string | null;
  derive_count?: number | null;
}

/**
 * §21.3 `audit_descriptor`: screen the descriptor for secrets, parse it, and build
 * the deterministic §19.1 {@link ReadinessReport} the report viewer (US-050)
 * renders. The descriptor is public wallet metadata; the core still screens it and
 * never echoes secret material back. (The export-rendering `generate_report`
 * command, which returns a formatted string rather than the structured report,
 * lands with the export UI in US-051.)
 */
export function auditDescriptor(input: DescriptorAuditInput): Promise<ReadinessReport> {
  return invoke<ReadinessReport>("audit_descriptor", { input });
}

/**
 * US-088 `render_miniscript_policy_dot`: ask the Rust core to parse the
 * descriptor, lift its Miniscript policy, and return redacted GraphViz DOT. React
 * only renders this public-safe DOT; it does not parse descriptors or Miniscript.
 */
export function renderMiniscriptPolicyDot(descriptor: string): Promise<string> {
  return invoke<string>("render_miniscript_policy_dot", { descriptor });
}

export type LianaRecoveryPathKind = "primary" | "recovery";
export type RelativeTimelockUnit = "blocks" | "time";
export type AbsoluteTimelockUnit = "height" | "timestamp";

export interface RelativeTimelock {
  unit: RelativeTimelockUnit;
  value: number;
  estimated_minutes: number;
  estimated_days: number;
}

export interface AbsoluteTimelock {
  unit: AbsoluteTimelockUnit;
  value: number;
}

export interface LianaRecoveryCountdown {
  current_block_height: number;
  active_in_blocks: number;
  active_at_block: number;
}

export interface LianaRecoveryPath {
  index: number;
  label: string;
  kind: LianaRecoveryPathKind;
  key_count: number;
  relative_timelocks: RelativeTimelock[];
  absolute_timelocks: AbsoluteTimelock[];
  countdown?: LianaRecoveryCountdown | null;
}

export interface LianaRecoveryTree {
  dot: string;
  paths: LianaRecoveryPath[];
}

/**
 * US-091 `render_liana_recovery_tree`: ask the Rust Miniscript visualizer to
 * extract Liana recovery paths and return a public-safe DOT tree plus path
 * timelocks. When `currentBlockHeight` is supplied, Rust also computes block
 * countdowns. React renders only this redacted structure.
 */
export function renderLianaRecoveryTree(
  descriptor: string,
  currentBlockHeight?: number | null,
): Promise<LianaRecoveryTree> {
  return invoke<LianaRecoveryTree>("render_liana_recovery_tree", {
    descriptor,
    currentBlockHeight: currentBlockHeight ?? null,
  });
}

// --- §21.3 generate_report / save_export (export UI, US-051) ------------------

/**
 * The export serialization format (§21.3 `ReportFormat`, snake_case). A *report*
 * renders to JSON / pretty JSON / Markdown — there is no backend PDF for a report
 * (true PDF generation is the *runbook* engine's job, §17.8). The export UI offers
 * PDF through the §17.7.4 "Print to PDF via OS print dialog" path: it prints the
 * in-app report view (print-optimized HTML), so PDF never goes through this command.
 */
export type ReportFormat = "json" | "json_pretty" | "markdown";

/**
 * The §17.7 / §9.5 export redaction mode (kebab-case; mirrors the Rust
 * `report_engine::RedactionMode`). `public-safe` (the default) redacts xpubs to
 * `xpub6…XXXX` and shows only the first derived address; `private` reveals the full
 * key material and requires the §9.5 confirmation before it can be selected.
 */
export type RedactionMode = "public-safe" | "private";

/**
 * Input for {@link generateReport} (§21.3 `ReportGenerationInput`). Mirrors
 * {@link DescriptorAuditInput} plus the export `redaction` mode (the Rust side
 * defaults it to `public-safe` when omitted; the UI always sends it explicitly).
 */
export interface ReportGenerationInput {
  descriptor: string;
  network?: string | null;
  known_address?: string | null;
  derive_count?: number | null;
  redaction: RedactionMode;
}

/**
 * The result of {@link generateReport} (§21.3 `ReportArtifact`): the rendered,
 * redaction-applied document plus the metadata the save flow needs. `content` is
 * the document TEXT — encode it to UTF-8 bytes for {@link saveExport}.
 */
export interface ReportArtifact {
  format: ReportFormat;
  redaction: RedactionMode;
  mime_type: string;
  suggested_filename: string;
  content: string;
}

/**
 * §21.3 `generate_report`: audit the descriptor and render the §19.1 report to the
 * requested `format` with `input.redaction` applied (§17.7). Unlike the raw machine
 * `audit_descriptor` output, this is the *export* path, so it honors the public-safe
 * / private redaction modes (private Markdown also prepends the §14.3 xpub warning).
 * The core screens the descriptor for secrets first and never echoes them back.
 */
export function generateReport(
  input: ReportGenerationInput,
  format: ReportFormat,
): Promise<ReportArtifact> {
  return invoke<ReportArtifact>("generate_report", { input, format });
}

/**
 * §21.3 `save_export`: write `content` (the artifact text encoded to UTF-8 bytes)
 * to a `path` the user chose via the OS save dialog ({@link showSaveDialog}). The
 * Rust side maps an IO failure to `E-FS-002`.
 */
export function saveExport(path: string, content: number[]): Promise<void> {
  return invoke<void>("save_export", { path, content });
}

/** One named extension group for the OS save dialog (e.g. Markdown → `["md"]`). */
export interface SaveDialogFilter {
  name: string;
  extensions: string[];
}

/** Options for {@link showSaveDialog}; all optional (the dialog supplies its own
 *  defaults when a field is omitted). */
export interface SaveDialogOptions {
  title?: string;
  defaultPath?: string;
  filters?: SaveDialogFilter[];
}

/**
 * Open the OS "Save As" dialog and resolve to the chosen path, or `null` if the
 * user cancels.
 *
 * This calls `tauri-plugin-dialog`'s `save` command through the core IPC bridge
 * (`plugin:dialog|save`) rather than the `@tauri-apps/plugin-dialog` JS wrapper:
 * the plugin is already registered in the Rust app and permitted by the
 * `dialog:allow-save` capability (§13.7), so routing through the existing
 * `@tauri-apps/api/core` keeps both the dependency surface and the capability set
 * unchanged. The dialog only *chooses* a path; {@link saveExport} does the write.
 */
export function showSaveDialog(options: SaveDialogOptions): Promise<string | null> {
  return invoke<string | null>("plugin:dialog|save", { options });
}

/** Options for {@link showOpenDialog}; defaults to a single file chooser. */
export interface OpenDialogOptions {
  title?: string;
  multiple?: boolean;
  directory?: boolean;
  filters?: SaveDialogFilter[];
}

/**
 * Open the OS file picker and resolve to the chosen path, or `null` if the user
 * cancels. File-based PSBT import keeps the capability scope at `$DIALOG_PATH`.
 */
export function showOpenDialog(
  options: OpenDialogOptions,
): Promise<string | string[] | null> {
  return invoke<string | string[] | null>("plugin:dialog|open", { options });
}

// --- §21.3 generate_runbook (runbook generator UI, US-052) --------------------

/**
 * The runbook output format (§21.3 `RunbookFormat`, snake_case; mirrors the Rust
 * `desktop_commands::RunbookFormat`). Unlike a *report*, a runbook DOES have a
 * backend PDF: the runbook engine renders a real PDF with its pure-Rust backend
 * (§17.8), so there is no print-to-PDF detour here — both formats come back as
 * bytes from {@link generateRunbook}.
 */
export type RunbookFormat = "pdf" | "markdown";

/**
 * Input for {@link generateRunbook} (§21.3 `RunbookGenerationInput`): the bundled
 * template id, an optional watch-only descriptor to pre-fill the wallet details
 * from, and the export `redaction` + `format`. The descriptor is screened for
 * secrets inside the core before it is parsed (§13.5); a `null`/omitted descriptor
 * leaves the template's blanks for hand-completion (§9.5).
 */
export interface RunbookGenerationInput {
  template: string;
  descriptor?: string | null;
  redaction: RedactionMode;
  format: RunbookFormat;
}

/**
 * The result of {@link generateRunbook} (§21.3 `RunbookArtifact`): the rendered
 * runbook BYTES plus the metadata the save flow needs. `content` is a UTF-8 byte
 * array (a serialized Rust `Vec<u8>`) — a PDF for `pdf`, or UTF-8 Markdown for
 * `markdown`; pass it straight to {@link saveExport}, or decode it with
 * `TextDecoder` to show the Markdown preview.
 */
export interface RunbookArtifact {
  template: string;
  format: RunbookFormat;
  redaction: RedactionMode;
  mime_type: string;
  suggested_filename: string;
  content: number[];
}

/**
 * §21.3 `generate_runbook`: render a recovery / inheritance runbook from a bundled
 * template — optionally pre-filled from a watch-only descriptor — in the requested
 * redaction mode and format. The frontend runs NO Bitcoin logic: it picks a
 * template and (optionally) hands over a descriptor, and the Rust core screens it,
 * parses it, and renders the deterministic runbook (§19 / §27). An unknown template
 * is `E-INPUT-003`; a secret-bearing descriptor is refused with `E-SECRET-*`.
 */
export function generateRunbook(input: RunbookGenerationInput): Promise<RunbookArtifact> {
  return invoke<RunbookArtifact>("generate_runbook", { input });
}

// --- §21.3 get_app_info / open_external_link (Settings -> About, US-054) ------

/**
 * §21.3 `AppInfo`: the app name, version, license, and repository / homepage URLs
 * (the latter two come from `project.config.toml`). Mirrors the Rust
 * `desktop_commands::AppInfo`.
 */
export interface AppInfo {
  name: string;
  version: string;
  license: string;
  repository: string;
  homepage: string;
}

/** §21.3 `get_app_info`: read the metadata shown in the Settings -> About panel. */
export function getAppInfo(): Promise<AppInfo> {
  return invoke<AppInfo>("get_app_info");
}

/**
 * §21.3 `open_external_link`: open a URL in the user's default OS browser. The
 * Rust core vets the URL against the build-time allowlist first (a non-allowlisted
 * URL is `E-LINK-001` and the browser is never launched), so only known project
 * links open. The app makes no network request itself (§13.10).
 */
export function openExternalLink(url: string): Promise<void> {
  return invoke<void>("open_external_link", { url });
}

// --- US-071 Practice Mode receive/send drill --------------------------------

/** The disposable practice networks supported by the receive/send drill. */
export type PracticeDrillNetwork = "regtest" | "signet";

/** File PSBT networks that can be inspected locally. */
export type FilePsbtNetwork = PracticeDrillNetwork | "mainnet";

/** Initial receive step returned by `start_practice_drill`. */
export interface PracticeDrillStart {
  network: PracticeDrillNetwork;
  receive_address: string;
  receive_index: number;
  faucet_url: string | null;
  funding_hint_sat: number;
  send_amount_sat: number;
  fee_rate_sat_vb: number;
}

/** Request for the local create/sign/finalize drill step. */
export interface PracticeSendDrillInput {
  network: PracticeDrillNetwork;
  funding_amount_sat: number;
  amount_sat: number;
  fee_rate_sat_vb: number;
}

/** Local receive/send drill result. Signet can be broadcast only by a separate command. */
export interface PracticeSendDrillResult {
  network: PracticeDrillNetwork;
  receive_address: string;
  receive_index: number;
  funding_amount_sat: number;
  recipient_address: string;
  amount_sat: number;
  fee_rate_sat_vb: number;
  unsigned_psbt_base64: string;
  signed_psbt_base64: string;
  finalized_txid: string;
  transaction_hex: string;
  input_total_sat: number;
  output_total_sat: number;
  fee_sat: number;
  finalized: boolean;
  broadcast_available: boolean;
}

/** Per-input public PSBT inspection returned by the Rust drill layer. */
export interface PsbtInputInspection {
  index: number;
  previous_output: string;
  sequence: number;
  amount_sat: number;
  has_witness_utxo: boolean;
  has_non_witness_utxo: boolean;
  finalized: boolean;
}

/** Per-output public PSBT inspection returned by the Rust drill layer. */
export interface PsbtOutputInspection {
  index: number;
  amount_sat: number;
  script_pubkey: string;
  address: string | null;
}

/** Local-only PSBT validation/finalization summary from `psbt-drill`. */
export interface PsbtInspection {
  version: number;
  network: FilePsbtNetwork;
  input_count: number;
  output_count: number;
  input_total_sat: number;
  output_total_sat: number;
  fee_sat: number;
  fee_rate_sat_vb: number;
  txid: string;
  finalized: boolean;
  inputs: PsbtInputInspection[];
  outputs: PsbtOutputInspection[];
}

/** Request for validating and finalizing a signed file PSBT. */
export interface FilePsbtFinalizeInput {
  network: PracticeDrillNetwork;
  psbt_base64: string;
}

/** Result of signed `.psbt` import through the Rust drill layer. */
export interface FilePsbtFinalizeResult {
  network: PracticeDrillNetwork;
  txid: string;
  transaction_hex: string;
  inspection: PsbtInspection;
}

/** Request for the acknowledged mainnet file-only PSBT validation path. */
export interface MainnetFilePsbtValidateInput {
  psbt_base64: string;
}

/** Result of local mainnet PSBT validation. No broadcast path is exposed. */
export interface MainnetFilePsbtValidateResult {
  network: "mainnet";
  txid: string;
  finalized: boolean;
  broadcast_available: false;
  inspection: PsbtInspection;
}

/** Request for generating a portable owner-created heir drill packet. */
export interface HeirDrillPacketInput {
  network?: PracticeDrillNetwork;
}

/** One file entry listed by the heir drill packet manifest. */
export interface HeirDrillPacketManifestFile {
  role: string;
  relative_path: string;
  mime_type: string;
  sha256: string;
}

/** Public manifest for an exported heir drill packet. */
export interface HeirDrillPacketManifest {
  schema_version: "0.1.0";
  packet_id: string;
  packet_type: "heir_drill_packet";
  created_at: string;
  network: PracticeDrillNetwork;
  wallet_kind: "disposable_heir_drill";
  instructions_file: string;
  wallet_file: string;
  first_receive_address: string;
  first_change_address: string;
  faucet_url: string | null;
  contains_real_funds: false;
  contains_real_user_material: false;
  includes_disposable_private_material: true;
  files: HeirDrillPacketManifestFile[];
}

/** One file written for an exported heir drill packet. */
export interface HeirDrillPacketWrittenFile {
  role: string;
  relative_path: string;
  path: string;
  mime_type: string;
  sha256: string;
}

/** Result of writing a heir drill packet to a dialog-chosen directory. */
export interface HeirDrillPacketExport {
  packet_dir: string;
  manifest: HeirDrillPacketManifest;
  files: HeirDrillPacketWrittenFile[];
}

/** Walkthrough steps recorded on a public-safe family drill receipt. */
export type FamilyDrillReceiptStep = "start" | "packet" | "wallet" | "send" | "result";

/** Confidence checks recorded on a public-safe family drill receipt. */
export type FamilyDrillConfidenceCheck = "packet" | "fake_bitcoin" | "real_seeds" | "contact";

/** Public-safe input for generating a family drill receipt PDF. */
export interface FamilyDrillReceiptInput {
  packet_id?: string | null;
  network?: PracticeDrillNetwork | null;
  completed_steps: FamilyDrillReceiptStep[];
  confidence_checks: FamilyDrillConfidenceCheck[];
  user_stopped?: boolean;
}

/** Rendered family drill receipt. Content is a PDF byte array. */
export interface FamilyDrillReceiptArtifact {
  schema_version: "0.1.0";
  format: "pdf";
  redaction: "public-safe";
  mime_type: "application/pdf";
  suggested_filename: string;
  receipt_hash: string;
  content: number[];
}

/** QR PSBT transport supported by the Rust `qr-psbt` crate. */
export type PsbtQrFormat = "ur" | "bbqr";

/** Request for rendering an unsigned PSBT as animated QR frames. */
export interface PsbtQrEncodeInput {
  psbt_base64: string;
  format: PsbtQrFormat;
}

/** One renderable QR payload frame. `svg` is displayed as a data-url image. */
export interface PsbtQrFrame {
  index: number;
  total: number;
  payload: string;
  svg: string;
}

/** Renderable QR frame set returned by Rust. */
export interface PsbtQrFrameSet {
  format: PsbtQrFormat;
  frame_count: number;
  frames: PsbtQrFrame[];
}

/** Request for decoding scanned QR payloads into a signed PSBT. */
export interface PsbtQrDecodeInput {
  format: PsbtQrFormat;
  payloads: string[];
}

/** Decode progress from the Rust QR transport layer. */
export interface PsbtQrDecodeResult {
  status: "incomplete" | "complete";
  received_count: number;
  parts_left: number | null;
  psbt_base64: string | null;
}

/** Public Signet Esplora endpoints exposed by the Rust drill layer. */
export type SignetBroadcastEndpoint = "mutinynet" | "sprovoost";

/** Request for the user-confirmed Signet broadcast command. */
export interface SignetBroadcastInput {
  network: PracticeDrillNetwork;
  transaction_hex: string;
  endpoint: SignetBroadcastEndpoint;
}

/** Result returned after the Signet Esplora endpoint accepts the transaction. */
export interface SignetBroadcastResult {
  network: "signet";
  endpoint: SignetBroadcastEndpoint;
  endpoint_url: string;
  txid: string;
}

/** Pass/fail values used in signed local DrillResult records. */
export type DrillStepResult = "pass" | "fail";

/** A §19.5 DrillResult step. */
export interface DrillResultStep {
  step: string;
  result: DrillStepResult;
}

/** Signature envelope attached by the Rust drill-history layer. */
export interface DrillResultSignature {
  algorithm: "ed25519-v1";
  public_key: string;
  payload_sha256: string;
  signature: string;
}

/** Signed §19.5 DrillResult record returned after an explicit save. */
export interface DrillResultRecord {
  schema_version: "0.1.0";
  drill_id: string;
  scenario: string;
  scenario_title: string;
  started_at: string;
  completed_at: string;
  result: DrillStepResult;
  wallet_type: string;
  steps: DrillResultStep[];
  report_hash: string;
  signature: DrillResultSignature;
}

/** Result returned after writing a local signed drill result. */
export interface DrillResultSaveOutcome {
  path: string;
  record: DrillResultRecord;
}

// --- US-076/US-082 Disaster Drill flows -------------------------------------

/** Questionnaire-only disaster scenarios from PRD §9.3. */
export type DisasterQuestionnaireScenario = "DS-1" | "DS-2" | "DS-3" | "DS-4" | "DS-5" | "DS-6";

/** Signing disaster scenarios from PRD §9.3. */
export type DisasterSigningScenario = "DS-7" | "DS-8" | "DS-9" | "DS-10";

/** File, QR, or HWI PSBT transport for signing disaster drills. */
export type DisasterSigningTransport = "file" | "qr" | "hwi";

/** Built-in US-089 multisig survivability templates. */
export type MultisigDrillTemplate = "multisig-2of3" | "multisig-3of5";

/** Network selected for descriptor address derivation in a disaster drill. */
export type DisasterQuestionnaireNetwork = "mainnet" | "testnet" | "signet" | "regtest";

/** Public yes/no/unsure questionnaire answer. No secret values are ever captured. */
export type DisasterAnswer = "yes" | "no" | "unsure";

export interface DisasterQuestionnaireAnswers {
  descriptor_backup_available: DisasterAnswer;
  recovery_materials_available: DisasterAnswer;
  wallet_software_documented: DisasterAnswer;
  passphrase_documented: DisasterAnswer;
  gap_limit_or_birthdate_documented: DisasterAnswer;
  signer_locations_known: DisasterAnswer;
}

/** Input for DS-1..DS-6 no-signing questionnaire drills. */
export interface DisasterQuestionnaireInput {
  scenario: DisasterQuestionnaireScenario;
  descriptor: string;
  network: DisasterQuestionnaireNetwork;
  known_address: string | null;
  available_signers: number | null;
  user_stopped: boolean;
  answers: DisasterQuestionnaireAnswers;
}

/** Input for the US-089 multisig survivability simulation. */
export interface MultisigSurvivabilityDrillInput {
  template: MultisigDrillTemplate;
  descriptor: string;
  network: DisasterQuestionnaireNetwork;
  known_address: string | null;
  user_stopped: boolean;
}

/** Input for the US-090 missing-signer drill. */
export interface MissingSignerDrillInput {
  descriptor: string;
  network: PracticeDrillNetwork;
  lost_signer_index: number;
  user_stopped: boolean;
}

/** Unsaved DS-1..DS-6 drill result returned by the Rust drill layer. */
export interface DisasterQuestionnaireDrillResult {
  schema_version: "0.1.0";
  scenario: DisasterQuestionnaireScenario;
  scenario_title: string;
  started_at: string;
  result: DrillStepResult;
  wallet_type: string;
  steps: DrillResultStep[];
  report_hash: string;
}

/** Unsaved US-089 multisig survivability result returned by the Rust drill layer. */
export interface MultisigSurvivabilityDrillResult {
  schema_version: "0.1.0";
  template_id: MultisigDrillTemplate;
  scenario: string;
  scenario_title: string;
  started_at: string;
  result: DrillStepResult;
  wallet_type: string;
  readiness_status: ReadinessStatus | null;
  readiness_headline: string | null;
  readiness_score: number | null;
  survivability: Survivability | null;
  steps: DrillResultStep[];
  report_hash: string;
}

export type MissingSignerMaterialKind =
  | "descriptor_backup"
  | "coordinator_wallet"
  | "practice_funds"
  | "remaining_signer";

/** One public material category needed for a US-090 missing-signer drill. */
export interface MissingSignerRequiredMaterial {
  kind: MissingSignerMaterialKind;
  signer_index: number | null;
}

/** Unsaved US-090 missing-signer result returned by the Rust drill layer. */
export interface MissingSignerDrillResult {
  schema_version: "0.1.0";
  scenario: string;
  scenario_title: string;
  started_at: string;
  result: DrillStepResult;
  wallet_type: string;
  network: PracticeDrillNetwork;
  threshold: number;
  key_count: number;
  lost_signer_index: number;
  remaining_signer_indexes: number[];
  signatures_required: number;
  recovery_possible: boolean;
  required_materials: MissingSignerRequiredMaterial[];
  steps: DrillResultStep[];
  report_hash: string;
}

/** Input for starting a DS-7..DS-10 file/QR signing drill. */
export interface DisasterSigningStartInput {
  scenario: DisasterSigningScenario;
  network: PracticeDrillNetwork;
  transport: DisasterSigningTransport;
}

/** Unsigned PSBT package returned for file or QR signing. */
export interface DisasterSigningStartResult {
  schema_version: "0.1.0";
  scenario: DisasterSigningScenario;
  scenario_title: string;
  started_at: string;
  network: PracticeDrillNetwork;
  transport: DisasterSigningTransport;
  wallet_type: string;
  required_signatures: number;
  receive_address: string;
  destination_address: string;
  amount_sat: number;
  fee_rate_sat_vb: number;
  unsigned_psbt_base64: string;
}

/** Input for completing a DS-7..DS-10 signing drill from an imported signed PSBT. */
export interface DisasterSigningCompleteInput {
  scenario: DisasterSigningScenario;
  network: PracticeDrillNetwork;
  transport: DisasterSigningTransport;
  started_at: string;
  signed_psbt_base64: string;
  expected_destination_address: string;
  expected_amount_sat: number;
  destination_confirmed: boolean;
  user_stopped: boolean;
}

/** Unsaved DS-7..DS-10 signing drill result returned by the Rust drill layer. */
export interface DisasterSigningDrillResult {
  schema_version: "0.1.0";
  scenario: DisasterSigningScenario;
  scenario_title: string;
  started_at: string;
  result: DrillStepResult;
  wallet_type: string;
  network: PracticeDrillNetwork;
  transport: DisasterSigningTransport;
  required_signatures: number;
  finalized_txid: string;
  steps: DrillResultStep[];
  report_hash: string;
}

/**
 * US-071 `start_practice_drill`: derive the disposable receive address for the
 * selected practice network. For Signet, the faucet URL is instruction-only; the
 * app opens it in the OS browser through `openExternalLink` and never calls it.
 */
export function startPracticeDrill(
  network: PracticeDrillNetwork,
): Promise<PracticeDrillStart> {
  return invoke<PracticeDrillStart>("start_practice_drill", { network });
}

/**
 * US-071 `run_practice_send_drill`: create, sign, and finalize a local
 * receive/send drill transaction through the Rust drill layer. It never
 * broadcasts; US-072 adds the separately gated Signet broadcast path.
 */
export function runPracticeSendDrill(
  input: PracticeSendDrillInput,
): Promise<PracticeSendDrillResult> {
  return invoke<PracticeSendDrillResult>("run_practice_send_drill", { input });
}

/**
 * US-072 `broadcast_signet_transaction`: user-confirmed Signet-only Esplora
 * broadcast. The UI must show the endpoint before invoking this command.
 */
export function broadcastSignetTransaction(
  input: SignetBroadcastInput,
): Promise<SignetBroadcastResult> {
  return invoke<SignetBroadcastResult>("broadcast_signet_transaction", { input });
}

/**
 * US-075 `save_practice_drill_result`: explicit opt-in local save for a completed
 * Practice Mode drill. The Rust side writes and signs the record.
 */
export function savePracticeDrillResult(
  result: PracticeSendDrillResult,
): Promise<DrillResultSaveOutcome> {
  return invoke<DrillResultSaveOutcome>("save_practice_drill_result", { result });
}

/** Read a dialog-chosen `.psbt` file. Binary PSBTs are converted to base64 in Rust. */
export function readPsbtFile(path: string): Promise<string> {
  return invoke<string>("read_psbt_file", { path });
}

/** Validate, finalize, and extract a signed file PSBT through `psbt-drill`. */
export function finalizeFilePsbt(
  input: FilePsbtFinalizeInput,
): Promise<FilePsbtFinalizeResult> {
  return invoke<FilePsbtFinalizeResult>("finalize_file_psbt", { input });
}

/** Validate a mainnet PSBT file locally after the UI's per-session acknowledgement. */
export function validateMainnetFilePsbt(
  input: MainnetFilePsbtValidateInput,
): Promise<MainnetFilePsbtValidateResult> {
  return invoke<MainnetFilePsbtValidateResult>("validate_mainnet_file_psbt", { input });
}

/**
 * US-094 `write_heir_drill_packet`: generate a fresh disposable regtest/Signet
 * heir drill packet and write its files under a directory selected by the owner.
 */
export function writeHeirDrillPacket(
  outputDir: string,
  input: HeirDrillPacketInput,
): Promise<HeirDrillPacketExport> {
  return invoke<HeirDrillPacketExport>("write_heir_drill_packet", { outputDir, input });
}

/**
 * US-096 `generate_family_drill_receipt`: render a local public-safe PDF receipt
 * from the heir walkthrough checklist. The Rust side stamps the time.
 */
export function generateFamilyDrillReceipt(
  input: FamilyDrillReceiptInput,
): Promise<FamilyDrillReceiptArtifact> {
  return invoke<FamilyDrillReceiptArtifact>("generate_family_drill_receipt", { input });
}

/** Render one unsigned PSBT as UR or BBQr QR frames through `qr-psbt`. */
export function encodePsbtQrFrames(
  input: PsbtQrEncodeInput,
): Promise<PsbtQrFrameSet> {
  return invoke<PsbtQrFrameSet>("encode_psbt_qr_frames", { input });
}

/** Decode scanned QR payload strings back into a base64 PSBT when complete. */
export function decodePsbtQrPayloads(
  input: PsbtQrDecodeInput,
): Promise<PsbtQrDecodeResult> {
  return invoke<PsbtQrDecodeResult>("decode_psbt_qr_payloads", { input });
}

/** Capture one native camera frame and return QR payload strings found in it. */
export function capturePsbtQrPayloads(cameraIndex: number): Promise<string[]> {
  return invoke<string[]>("capture_psbt_qr_payloads", { cameraIndex });
}

/** Run a DS-1..DS-6 questionnaire drill. This performs Rust-side descriptor audit logic. */
export function runDisasterQuestionnaireDrill(
  input: DisasterQuestionnaireInput,
): Promise<DisasterQuestionnaireDrillResult> {
  return invoke<DisasterQuestionnaireDrillResult>("run_disaster_questionnaire_drill", { input });
}

/** Save a completed questionnaire drill only after explicit user opt-in. */
export function saveDisasterQuestionnaireDrillResult(
  result: DisasterQuestionnaireDrillResult,
): Promise<DrillResultSaveOutcome> {
  return invoke<DrillResultSaveOutcome>("save_disaster_questionnaire_drill_result", { result });
}

/** Run a US-089 2-of-3 / 3-of-5 multisig survivability template. */
export function runMultisigSurvivabilityDrill(
  input: MultisigSurvivabilityDrillInput,
): Promise<MultisigSurvivabilityDrillResult> {
  return invoke<MultisigSurvivabilityDrillResult>("run_multisig_survivability_drill", { input });
}

/** Save a completed multisig survivability drill after explicit user opt-in. */
export function saveMultisigSurvivabilityDrillResult(
  result: MultisigSurvivabilityDrillResult,
): Promise<DrillResultSaveOutcome> {
  return invoke<DrillResultSaveOutcome>("save_multisig_survivability_drill_result", { result });
}

/** Run a US-090 missing-signer recovery rehearsal. */
export function runMissingSignerDrill(
  input: MissingSignerDrillInput,
): Promise<MissingSignerDrillResult> {
  return invoke<MissingSignerDrillResult>("run_missing_signer_drill", { input });
}

/** Save a completed missing-signer drill after explicit user opt-in. */
export function saveMissingSignerDrillResult(
  result: MissingSignerDrillResult,
): Promise<DrillResultSaveOutcome> {
  return invoke<DrillResultSaveOutcome>("save_missing_signer_drill_result", { result });
}

/** Start a DS-7..DS-10 signing drill and return an unsigned PSBT package. */
export function startDisasterSigningDrill(
  input: DisasterSigningStartInput,
): Promise<DisasterSigningStartResult> {
  return invoke<DisasterSigningStartResult>("start_disaster_signing_drill", { input });
}

/** Complete a DS-7..DS-10 signing drill from a signed file or QR PSBT. */
export function completeDisasterSigningDrill(
  input: DisasterSigningCompleteInput,
): Promise<DisasterSigningDrillResult> {
  return invoke<DisasterSigningDrillResult>("complete_disaster_signing_drill", { input });
}

/** Save a completed signing disaster drill only after explicit user opt-in. */
export function saveDisasterSigningDrillResult(
  result: DisasterSigningDrillResult,
): Promise<DrillResultSaveOutcome> {
  return invoke<DrillResultSaveOutcome>("save_disaster_signing_drill_result", { result });
}

// --- US-085 HWI USB device support ------------------------------------------

/** Device families Lifeboat supports through HWI. */
export type HwiDeviceKind = "ledger" | "trezor" | "bitbox02" | "coldcard";

/** HWI network selector. */
export type HwiChain = "main" | "test" | "regtest" | "signet" | "testnet4";

/** Non-fatal HWI warning codes. */
export type HwiWarningCode = "W-DEVICE-FIRMWARE-UNSUPPORTED";

export interface HwiWarning {
  code: HwiWarningCode;
  title: string;
  description: string;
  recommended_action: string;
}

/** One row returned by `hwi enumerate`. */
export interface HwiDevice {
  device_type: string;
  supported_kind: HwiDeviceKind | null;
  model: string | null;
  path: string | null;
  fingerprint: string | null;
  needs_pin_sent: boolean;
  needs_passphrase_sent: boolean;
  status_message: string | null;
  warnings: HwiWarning[];
}

/** Request to read an xpub at a descriptor-origin path from one HWI device. */
export interface HwiXpubRequest {
  fingerprint: string;
  derivation_path: string;
  chain?: HwiChain | null;
  device_type?: HwiDeviceKind | null;
  device_path?: string | null;
}

/** Xpub returned by HWI. Confidential wallet metadata; do not persist in web storage. */
export interface HwiDerivedXpub {
  fingerprint: string;
  derivation_path: string;
  xpub: string;
}

/** Request to sign a PSBT through the subprocess-only HWI sidecar. */
export interface HwiSignPsbtRequest {
  fingerprint: string;
  psbt_base64: string;
  chain?: HwiChain | null;
  device_type?: HwiDeviceKind | null;
  device_path?: string | null;
}

/** Signed PSBT returned by HWI. Confidential wallet metadata; do not persist in web storage. */
export interface HwiSignedPsbt {
  fingerprint: string;
  psbt_base64: string;
}

/** Descriptor-side key expected from one hardware signer. */
export interface ExpectedHwiKey {
  label?: string | null;
  fingerprint: string;
  derivation_path: string;
  xpub?: string | null;
  chain?: HwiChain | null;
}

export type HwiVerificationStatus =
  | "matched"
  | "device_missing"
  | "fingerprint_mismatch"
  | "unsupported_device"
  | "firmware_unsupported"
  | "xpub_mismatch";

/** Result of comparing one descriptor key origin against connected HWI devices. */
export interface HwiVerificationResult {
  expected_label: string | null;
  expected_fingerprint: string;
  expected_derivation_path: string;
  status: HwiVerificationStatus;
  fingerprint_matches: boolean;
  xpub_matches: boolean | null;
  device: HwiDevice | null;
  observed_fingerprints: string[];
  warnings: HwiWarning[];
}

/** List hardware wallets visible through the bundled HWI sidecar. */
export function enumerateHwiDevices(): Promise<HwiDevice[]> {
  return invoke<HwiDevice[]>("enumerate_hwi_devices");
}

/** Read one descriptor-origin xpub through HWI. */
export function readHwiXpub(input: HwiXpubRequest): Promise<HwiDerivedXpub> {
  return invoke<HwiDerivedXpub>("read_hwi_xpub", { input });
}

/** Sign a PSBT through HWI's `signtx` command. */
export function signHwiPsbt(input: HwiSignPsbtRequest): Promise<HwiSignedPsbt> {
  return invoke<HwiSignedPsbt>("sign_hwi_psbt", { input });
}

/** Verify descriptor key origins and xpubs against connected HWI devices. */
export function verifyHwiXpubs(
  expectedKeys: ExpectedHwiKey[],
): Promise<HwiVerificationResult[]> {
  return invoke<HwiVerificationResult[]>("verify_hwi_xpubs", { expectedKeys });
}

// --- §22.11 settings (Public preferences; US-054) ----------------------------

/** The UI theme preference (mirrors the Rust `ThemeSetting`, snake_case). */
export type ThemeSetting = "system" | "light" | "dark";

/**
 * The §15.5 large-text accessibility preference (mirrors the Rust
 * `TextScaleSetting`, snake_case): `normal` (1x) / `large` (1.5x) / `larger` (2x).
 */
export type TextScaleSetting = "normal" | "large" | "larger";

/**
 * The §22.11 Public, non-confidential preferences persisted to the Tauri-managed
 * settings file (NEVER web storage). Mirrors the Rust `desktop_commands::Settings`
 * (snake_case keys). Every field is Public — there is no field that unlocks seed
 * entry or bypasses a safety warning, and no Confidential wallet data is stored.
 */
export interface Settings {
  version: number;
  theme: ThemeSetting;
  language: string;
  diagnostics_enabled: boolean;
  show_advanced_details: boolean;
  text_scale: TextScaleSetting;
}

/** §22.11 `load_settings`: read the Public preferences (defaults on first launch). */
export function loadSettings(): Promise<Settings> {
  return invoke<Settings>("load_settings");
}

/** §22.11 `save_settings`: persist the Public preferences. */
export function saveSettings(settings: Settings): Promise<void> {
  return invoke<void>("save_settings", { settings });
}

/** §22.11 `clear_all_data`: delete the local settings file. */
export function clearAllData(): Promise<void> {
  return invoke<void>("clear_all_data");
}
