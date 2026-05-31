import { afterEach, describe, it, vi } from "vitest";
import { act, render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import AppLayout from "./layout/AppLayout";
import Onboarding from "./onboarding/Onboarding";
import AuditMultisig from "./pages/AuditMultisig";
import DisasterDrill from "./pages/DisasterDrill";
import GenerateRunbook from "./pages/GenerateRunbook";
import HardwareWalletDrill from "./pages/HardwareWalletDrill";
import HeirWalkthrough from "./pages/HeirWalkthrough";
import HeirRunbook from "./pages/HeirRunbook";
import Home from "./pages/Home";
import Learn from "./pages/Learn";
import PracticeMode from "./pages/PracticeMode";
import ReadinessCheck from "./pages/ReadinessCheck";
import Settings from "./pages/Settings";
import { useSessionStore } from "./store/session";
import { expectNoAxeViolations } from "./test/axe";

// §15.5 / NFR-A11Y-1+4: every screen must report ZERO WCAG 2.2 AA violations.
// Screens are rendered inside the real <AppLayout> chrome (skip link + nav +
// main landmarks) exactly as App.tsx mounts them, so page-level checks
// (`bypass`, landmarks) reflect production. The IPC seam is mocked so the jsdom
// suite never touches the real Tauri bridge; only Settings calls a command on
// mount (`getAppInfo`), but all command functions are stubbed defensively.
vi.mock("./tauri/commands", () => ({
  detectSensitiveInput: vi.fn().mockResolvedValue({ findings: [], action: "allow" }),
  auditDescriptor: vi.fn().mockResolvedValue(undefined),
  renderMiniscriptPolicyDot: vi.fn().mockResolvedValue("digraph miniscript_policy {\n}\n"),
  renderLianaRecoveryTree: vi.fn().mockResolvedValue({
    dot: "digraph liana_recovery_tree {\n}\n",
    paths: [],
  }),
  generateReport: vi.fn().mockResolvedValue(undefined),
  saveExport: vi.fn().mockResolvedValue(undefined),
  showSaveDialog: vi.fn().mockResolvedValue(null),
  showOpenDialog: vi.fn().mockResolvedValue(null),
  readPsbtFile: vi.fn().mockResolvedValue("cHNidP8BAHECAAAAsigned"),
  finalizeFilePsbt: vi.fn().mockResolvedValue({
    network: "regtest",
    txid: "1".repeat(64),
    transaction_hex: "020000000001",
    inspection: {
      version: 0,
      network: "regtest",
      input_count: 1,
      output_count: 2,
      input_total_sat: 125000,
      output_total_sat: 123456,
      fee_sat: 1544,
      fee_rate_sat_vb: 2,
      txid: "1".repeat(64),
      finalized: true,
      inputs: [],
      outputs: [],
    },
  }),
  encodePsbtQrFrames: vi.fn().mockResolvedValue({
    format: "ur",
    frame_count: 1,
    frames: [
      {
        index: 1,
        total: 1,
        payload: "ur:psbt/oyadgdaemw",
        svg: "<svg width=\"320\" height=\"320\"></svg>",
      },
    ],
  }),
  decodePsbtQrPayloads: vi.fn().mockResolvedValue({
    status: "complete",
    received_count: 1,
    parts_left: 0,
    psbt_base64: "cHNidP8BAHECAAAAsigned",
  }),
  capturePsbtQrPayloads: vi.fn().mockResolvedValue(["ur:psbt/oyadgdaemw"]),
  generateRunbook: vi.fn().mockResolvedValue(undefined),
  startPracticeDrill: vi.fn().mockResolvedValue({
    network: "regtest",
    receive_address: "bcrt1qpracticeaddress0000000000000000000000000000000",
    receive_index: 0,
    faucet_url: null,
    funding_hint_sat: 125000,
    send_amount_sat: 60000,
    fee_rate_sat_vb: 2,
  }),
  runPracticeSendDrill: vi.fn().mockResolvedValue(undefined),
  broadcastSignetTransaction: vi.fn().mockResolvedValue({
    network: "signet",
    endpoint: "mutinynet",
    endpoint_url: "https://mutinynet.com/api/tx",
    txid: "1".repeat(64),
  }),
  savePracticeDrillResult: vi.fn().mockResolvedValue({
    path: "/tmp/lifeboat-drill.json",
    record: {
      schema_version: "0.1.0",
      drill_id: "11111111-1111-4111-8111-111111111111",
      scenario: "DS-9",
      scenario_title: "I want to test a PSBT signing workflow",
      started_at: "2026-05-30T20:00:00Z",
      completed_at: "2026-05-30T20:00:00Z",
      result: "pass",
      wallet_type: "practice_singlesig",
      steps: [{ step: "finalize_psbt", result: "pass" }],
      report_hash: `sha256:${"0".repeat(64)}`,
      signature: {
        algorithm: "ed25519-v1",
        public_key: "public",
        payload_sha256: `sha256:${"1".repeat(64)}`,
        signature: "signature",
      },
    },
  }),
  runDisasterQuestionnaireDrill: vi.fn().mockResolvedValue({
    schema_version: "0.1.0",
    scenario: "DS-5",
    scenario_title: "I have my descriptor but not all signers",
    started_at: "2026-05-30T20:10:00Z",
    result: "pass",
    wallet_type: "multisig_2of3",
    steps: [{ step: "available_signers_meet_quorum", result: "pass" }],
    report_hash: `sha256:${"0".repeat(64)}`,
  }),
  saveDisasterQuestionnaireDrillResult: vi.fn().mockResolvedValue({
    path: "/tmp/lifeboat-disaster-drill.json",
    record: {
      schema_version: "0.1.0",
      drill_id: "22222222-2222-4222-8222-222222222222",
      scenario: "DS-5",
      scenario_title: "I have my descriptor but not all signers",
      started_at: "2026-05-30T20:10:00Z",
      completed_at: "2026-05-30T20:12:00Z",
      result: "pass",
      wallet_type: "multisig_2of3",
      steps: [{ step: "available_signers_meet_quorum", result: "pass" }],
      report_hash: `sha256:${"0".repeat(64)}`,
      signature: {
        algorithm: "ed25519-v1",
        public_key: "public",
        payload_sha256: `sha256:${"1".repeat(64)}`,
        signature: "signature",
      },
    },
  }),
  runMultisigSurvivabilityDrill: vi.fn().mockResolvedValue({
    schema_version: "0.1.0",
    template_id: "multisig-2of3",
    scenario: "DS-11",
    scenario_title: "2-of-3 multisig survivability simulation",
    started_at: "2026-05-30T20:20:00Z",
    result: "fail",
    wallet_type: "multisig_2of3",
    readiness_status: "needs_attention",
    readiness_headline: "Needs Attention",
    readiness_score: 64,
    survivability: {
      tested: true,
      lose_1_signer: "ok",
      lose_2_signers: "fail_expected_for_2of3",
      lose_descriptor_only: "ok_if_xpubs_retained",
    },
    steps: [{ step: "lose_2_signers_survives", result: "fail" }],
    report_hash: `sha256:${"4".repeat(64)}`,
  }),
  saveMultisigSurvivabilityDrillResult: vi.fn().mockResolvedValue({
    path: "/tmp/lifeboat-multisig-drill.json",
    record: {
      schema_version: "0.1.0",
      drill_id: "44444444-4444-4444-8444-444444444444",
      scenario: "DS-11",
      scenario_title: "2-of-3 multisig survivability simulation",
      started_at: "2026-05-30T20:20:00Z",
      completed_at: "2026-05-30T20:22:00Z",
      result: "fail",
      wallet_type: "multisig_2of3",
      steps: [{ step: "lose_2_signers_survives", result: "fail" }],
      report_hash: `sha256:${"4".repeat(64)}`,
      signature: {
        algorithm: "ed25519-v1",
        public_key: "public",
        payload_sha256: `sha256:${"5".repeat(64)}`,
        signature: "signature",
      },
    },
  }),
  runMissingSignerDrill: vi.fn().mockResolvedValue({
    schema_version: "0.1.0",
    scenario: "DS-13",
    scenario_title: "Missing signer interactive drill",
    started_at: "2026-05-30T20:30:00Z",
    result: "pass",
    wallet_type: "multisig_2of3",
    network: "regtest",
    threshold: 2,
    key_count: 3,
    lost_signer_index: 2,
    remaining_signer_indexes: [1, 3],
    signatures_required: 2,
    recovery_possible: true,
    required_materials: [
      { kind: "descriptor_backup", signer_index: null },
      { kind: "remaining_signer", signer_index: 1 },
      { kind: "remaining_signer", signer_index: 3 },
    ],
    steps: [{ step: "remaining_quorum_available", result: "pass" }],
    report_hash: `sha256:${"6".repeat(64)}`,
  }),
  saveMissingSignerDrillResult: vi.fn().mockResolvedValue({
    path: "/tmp/lifeboat-missing-signer-drill.json",
    record: {
      schema_version: "0.1.0",
      drill_id: "66666666-6666-4666-8666-666666666666",
      scenario: "DS-13",
      scenario_title: "Missing signer interactive drill",
      started_at: "2026-05-30T20:30:00Z",
      completed_at: "2026-05-30T20:32:00Z",
      result: "pass",
      wallet_type: "multisig_2of3",
      steps: [{ step: "remaining_quorum_available", result: "pass" }],
      report_hash: `sha256:${"6".repeat(64)}`,
      signature: {
        algorithm: "ed25519-v1",
        public_key: "public",
        payload_sha256: `sha256:${"7".repeat(64)}`,
        signature: "signature",
      },
    },
  }),
  startDisasterSigningDrill: vi.fn().mockResolvedValue({
    schema_version: "0.1.0",
    scenario: "DS-8",
    scenario_title: "I need to verify my hardware wallet can still sign",
    started_at: "2026-05-30T21:30:00Z",
    network: "regtest",
    transport: "hwi",
    wallet_type: "practice_singlesig",
    required_signatures: 1,
    receive_address: "bcrt1qhardwaredrillreceive",
    destination_address: "bcrt1qhardwaredrilldestination",
    amount_sat: 60000,
    fee_rate_sat_vb: 2,
    unsigned_psbt_base64: "cHNidP8unsigned",
  }),
  completeDisasterSigningDrill: vi.fn().mockResolvedValue({
    schema_version: "0.1.0",
    scenario: "DS-8",
    scenario_title: "I need to verify my hardware wallet can still sign",
    started_at: "2026-05-30T21:30:00Z",
    result: "pass",
    wallet_type: "practice_singlesig",
    network: "regtest",
    transport: "hwi",
    required_signatures: 1,
    finalized_txid: "2".repeat(64),
    steps: [{ step: "required_quorum_signed", result: "pass" }],
    report_hash: `sha256:${"2".repeat(64)}`,
  }),
  saveDisasterSigningDrillResult: vi.fn().mockResolvedValue({
    path: "/tmp/lifeboat-hardware-drill.json",
    record: {
      schema_version: "0.1.0",
      drill_id: "33333333-3333-4333-8333-333333333333",
      scenario: "DS-8",
      scenario_title: "I need to verify my hardware wallet can still sign",
      started_at: "2026-05-30T21:30:00Z",
      completed_at: "2026-05-30T21:32:00Z",
      result: "pass",
      wallet_type: "practice_singlesig",
      steps: [{ step: "required_quorum_signed", result: "pass" }],
      report_hash: `sha256:${"2".repeat(64)}`,
      signature: {
        algorithm: "ed25519-v1",
        public_key: "public",
        payload_sha256: `sha256:${"3".repeat(64)}`,
        signature: "signature",
      },
    },
  }),
  enumerateHwiDevices: vi.fn().mockResolvedValue([]),
  readHwiXpub: vi.fn().mockResolvedValue({
    fingerprint: "a1b2c3d4",
    derivation_path: "m/84h/1h/0h",
    xpub: "tpub-device",
  }),
  signHwiPsbt: vi.fn().mockResolvedValue({
    fingerprint: "a1b2c3d4",
    psbt_base64: "cHNidP8signed",
  }),
  verifyHwiXpubs: vi.fn().mockResolvedValue([]),
  generateFamilyDrillReceipt: vi.fn().mockResolvedValue({
    schema_version: "0.1.0",
    format: "pdf",
    redaction: "public-safe",
    mime_type: "application/pdf",
    suggested_filename: "bitcoin-lifeboat-family-drill-receipt.pdf",
    receipt_hash: `sha256:${"8".repeat(64)}`,
    content: [37, 80, 68, 70],
  }),
  getAppInfo: vi.fn().mockResolvedValue({
    name: "Bitcoin Lifeboat",
    version: "0.1.0-test",
    license: "MIT",
    repository: "https://github.com/example-org/bitcoin-lifeboat",
    homepage: "https://bitcoinlifeboat.org",
  }),
  openExternalLink: vi.fn().mockResolvedValue(undefined),
  loadSettings: vi.fn().mockResolvedValue(undefined),
  saveSettings: vi.fn().mockResolvedValue(undefined),
  clearAllData: vi.fn().mockResolvedValue(undefined),
}));

// The routed screens, keyed by the §22.1 path App.tsx mounts them at.
const ROUTES: { name: string; path: string }[] = [
  { name: "Home", path: "/" },
  { name: "Readiness Check", path: "/readiness-check" },
  { name: "Audit Multisig", path: "/audit-multisig" },
  { name: "Heir Runbook", path: "/heir-runbook" },
  { name: "Heir Walkthrough", path: "/heir-walkthrough" },
  { name: "Generate Runbook", path: "/generate-runbook" },
  { name: "Disaster Drill", path: "/disaster-drill" },
  { name: "Hardware Wallet Drill", path: "/hardware-wallet-drill" },
  { name: "Practice Mode", path: "/practice-mode" },
  { name: "Learn", path: "/learn" },
  { name: "Settings", path: "/settings" },
];

async function auditRoute(path: string): Promise<void> {
  const { container } = render(
    <MemoryRouter
      initialEntries={[path]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Home />} />
          <Route path="readiness-check" element={<ReadinessCheck />} />
          <Route path="audit-multisig" element={<AuditMultisig />} />
          <Route path="heir-runbook" element={<HeirRunbook />} />
          <Route path="heir-walkthrough" element={<HeirWalkthrough />} />
          <Route path="generate-runbook" element={<GenerateRunbook />} />
          <Route path="disaster-drill" element={<DisasterDrill />} />
          <Route path="hardware-wallet-drill" element={<HardwareWalletDrill />} />
          <Route path="practice-mode" element={<PracticeMode />} />
          <Route path="learn" element={<Learn />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
  // Let mount effects (e.g. Settings -> getAppInfo) settle before the audit.
  await act(async () => {
    await Promise.resolve();
  });
  await expectNoAxeViolations(container);
}

describe("Accessibility — WCAG 2.2 AA (§15.5 / US-056)", () => {
  afterEach(() => {
    useSessionStore.getState().reset();
    vi.clearAllMocks();
  });

  for (const route of ROUTES) {
    it(`${route.name} has no AA violations`, async () => {
      await auditRoute(route.path);
    });
  }

  it("Onboarding flow has no AA violations", async () => {
    const { container } = render(<Onboarding />);
    await act(async () => {
      await Promise.resolve();
    });
    await expectNoAxeViolations(container);
  });
});
