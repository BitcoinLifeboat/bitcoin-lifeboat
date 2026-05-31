import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { AlertTriangleIcon, CheckCircleIcon, XCircleIcon } from "../components/icons";
import SensitiveInputDialog from "../components/SensitiveInputDialog";
import { StatusBadge } from "../components/StatusBadge";
import { PageScaffold } from "./PageScaffold";
import {
  capturePsbtQrPayloads,
  completeDisasterSigningDrill,
  detectSensitiveInput,
  decodePsbtQrPayloads,
  encodePsbtQrFrames,
  readPsbtFile,
  runDisasterQuestionnaireDrill,
  runMissingSignerDrill,
  runMultisigSurvivabilityDrill,
  saveDisasterSigningDrillResult,
  saveExport,
  saveDisasterQuestionnaireDrillResult,
  saveMissingSignerDrillResult,
  saveMultisigSurvivabilityDrillResult,
  showOpenDialog,
  showSaveDialog,
  startDisasterSigningDrill,
  validateMainnetFilePsbt,
  type DetectedSecret,
  type DisasterAnswer,
  type DisasterQuestionnaireAnswers,
  type DisasterQuestionnaireDrillResult,
  type DisasterQuestionnaireNetwork,
  type DisasterQuestionnaireScenario,
  type DisasterSigningDrillResult,
  type DisasterSigningScenario,
  type DisasterSigningStartResult,
  type DisasterSigningTransport,
  type DrillResultSaveOutcome,
  type MainnetFilePsbtValidateResult,
  type MissingSignerDrillResult,
  type MissingSignerRequiredMaterial,
  type MultisigDrillTemplate,
  type MultisigSurvivabilityDrillResult,
  type PracticeDrillNetwork,
  type PsbtQrDecodeResult,
  type PsbtQrFormat,
  type PsbtQrFrameSet,
} from "../tauri/commands";

interface ScenarioOption {
  id: DisasterScenario;
  titleKey: string;
  bodyKey: string;
}

type AnswerKey = keyof DisasterQuestionnaireAnswers;
type MultisigSurvivabilityScenario = "MS-2OF3" | "MS-3OF5";
type MissingSignerScenario = "MS-MISSING";
type DisasterScenario =
  | DisasterQuestionnaireScenario
  | DisasterSigningScenario
  | MultisigSurvivabilityScenario
  | MissingSignerScenario;
type DescriptorScenario =
  | DisasterQuestionnaireScenario
  | MultisigSurvivabilityScenario
  | MissingSignerScenario;
type SigningNetwork = PracticeDrillNetwork | "mainnet";

interface RequiredAnswer {
  id: AnswerKey;
  labelKey: string;
}

const SCENARIOS: ScenarioOption[] = [
  {
    id: "DS-1",
    titleKey: "pages.disasterDrill.scenarios.ds1.title",
    bodyKey: "pages.disasterDrill.scenarios.ds1.body",
  },
  {
    id: "DS-2",
    titleKey: "pages.disasterDrill.scenarios.ds2.title",
    bodyKey: "pages.disasterDrill.scenarios.ds2.body",
  },
  {
    id: "DS-3",
    titleKey: "pages.disasterDrill.scenarios.ds3.title",
    bodyKey: "pages.disasterDrill.scenarios.ds3.body",
  },
  {
    id: "DS-4",
    titleKey: "pages.disasterDrill.scenarios.ds4.title",
    bodyKey: "pages.disasterDrill.scenarios.ds4.body",
  },
  {
    id: "DS-5",
    titleKey: "pages.disasterDrill.scenarios.ds5.title",
    bodyKey: "pages.disasterDrill.scenarios.ds5.body",
  },
  {
    id: "DS-6",
    titleKey: "pages.disasterDrill.scenarios.ds6.title",
    bodyKey: "pages.disasterDrill.scenarios.ds6.body",
  },
  {
    id: "MS-2OF3",
    titleKey: "pages.disasterDrill.scenarios.ms2of3.title",
    bodyKey: "pages.disasterDrill.scenarios.ms2of3.body",
  },
  {
    id: "MS-3OF5",
    titleKey: "pages.disasterDrill.scenarios.ms3of5.title",
    bodyKey: "pages.disasterDrill.scenarios.ms3of5.body",
  },
  {
    id: "MS-MISSING",
    titleKey: "pages.disasterDrill.scenarios.missingSigner.title",
    bodyKey: "pages.disasterDrill.scenarios.missingSigner.body",
  },
  {
    id: "DS-7",
    titleKey: "pages.disasterDrill.scenarios.ds7.title",
    bodyKey: "pages.disasterDrill.scenarios.ds7.body",
  },
  {
    id: "DS-8",
    titleKey: "pages.disasterDrill.scenarios.ds8.title",
    bodyKey: "pages.disasterDrill.scenarios.ds8.body",
  },
  {
    id: "DS-9",
    titleKey: "pages.disasterDrill.scenarios.ds9.title",
    bodyKey: "pages.disasterDrill.scenarios.ds9.body",
  },
  {
    id: "DS-10",
    titleKey: "pages.disasterDrill.scenarios.ds10.title",
    bodyKey: "pages.disasterDrill.scenarios.ds10.body",
  },
];

const NETWORKS: DisasterQuestionnaireNetwork[] = ["mainnet", "testnet", "signet", "regtest"];
const SIGNING_NETWORKS: SigningNetwork[] = ["regtest", "signet", "mainnet"];
const MISSING_SIGNER_NETWORKS: PracticeDrillNetwork[] = ["regtest", "signet"];
const SIGNING_TRANSPORTS: DisasterSigningTransport[] = ["file", "qr"];
const QR_FORMATS: PsbtQrFormat[] = ["ur", "bbqr"];
const ANSWERS: DisasterAnswer[] = ["yes", "no", "unsure"];

const EMPTY_ANSWERS: DisasterQuestionnaireAnswers = {
  descriptor_backup_available: "unsure",
  recovery_materials_available: "unsure",
  wallet_software_documented: "unsure",
  passphrase_documented: "unsure",
  gap_limit_or_birthdate_documented: "unsure",
  signer_locations_known: "unsure",
};

const REQUIRED_BY_SCENARIO: Record<DisasterQuestionnaireScenario, RequiredAnswer[]> = {
  "DS-1": [
    {
      id: "recovery_materials_available",
      labelKey: "pages.disasterDrill.questions.recoveryMaterials",
    },
    { id: "passphrase_documented", labelKey: "pages.disasterDrill.questions.passphrase" },
    {
      id: "wallet_software_documented",
      labelKey: "pages.disasterDrill.questions.walletSoftware",
    },
  ],
  "DS-2": [
    {
      id: "descriptor_backup_available",
      labelKey: "pages.disasterDrill.questions.descriptorBackup",
    },
    {
      id: "recovery_materials_available",
      labelKey: "pages.disasterDrill.questions.recoveryMaterials",
    },
    {
      id: "wallet_software_documented",
      labelKey: "pages.disasterDrill.questions.walletSoftware",
    },
  ],
  "DS-3": [
    {
      id: "descriptor_backup_available",
      labelKey: "pages.disasterDrill.questions.descriptorBackup",
    },
    {
      id: "wallet_software_documented",
      labelKey: "pages.disasterDrill.questions.walletSoftware",
    },
    {
      id: "gap_limit_or_birthdate_documented",
      labelKey: "pages.disasterDrill.questions.gapOrBirth",
    },
  ],
  "DS-4": [
    {
      id: "recovery_materials_available",
      labelKey: "pages.disasterDrill.questions.recoveryMaterials",
    },
    { id: "passphrase_documented", labelKey: "pages.disasterDrill.questions.passphrase" },
    {
      id: "wallet_software_documented",
      labelKey: "pages.disasterDrill.questions.walletSoftware",
    },
    {
      id: "gap_limit_or_birthdate_documented",
      labelKey: "pages.disasterDrill.questions.gapOrBirth",
    },
  ],
  "DS-5": [
    {
      id: "descriptor_backup_available",
      labelKey: "pages.disasterDrill.questions.descriptorBackup",
    },
    {
      id: "signer_locations_known",
      labelKey: "pages.disasterDrill.questions.signerLocations",
    },
  ],
  "DS-6": [
    {
      id: "descriptor_backup_available",
      labelKey: "pages.disasterDrill.questions.descriptorBackup",
    },
    {
      id: "signer_locations_known",
      labelKey: "pages.disasterDrill.questions.signerLocations",
    },
  ],
};

const STEP_LABEL_KEYS: Record<string, string> = {
  descriptor_parse: "pages.disasterDrill.steps.descriptorParse",
  derive_expected_addresses: "pages.disasterDrill.steps.deriveExpected",
  known_address_match: "pages.disasterDrill.steps.knownAddress",
  multisig_quorum: "pages.disasterDrill.steps.multisigQuorum",
  available_signers_meet_quorum: "pages.disasterDrill.steps.availableSigners",
  survives_one_signer_loss: "pages.disasterDrill.steps.survivesOneSigner",
  template_matches_descriptor: "pages.disasterDrill.steps.templateMatchesDescriptor",
  readiness_status_available: "pages.disasterDrill.steps.readinessStatusAvailable",
  lose_1_signer_survives: "pages.disasterDrill.steps.loseOneSignerSurvives",
  lose_2_signers_survives: "pages.disasterDrill.steps.loseTwoSignersSurvives",
  lose_descriptor_backup_survives: "pages.disasterDrill.steps.loseDescriptorBackupSurvives",
  lost_signer_in_range: "pages.disasterDrill.steps.lostSignerInRange",
  remaining_quorum_available: "pages.disasterDrill.steps.remainingQuorumAvailable",
  practice_chain_selected: "pages.disasterDrill.steps.practiceChainSelected",
  descriptor_backup_available: "pages.disasterDrill.steps.descriptorBackup",
  recovery_materials_available: "pages.disasterDrill.steps.recoveryMaterials",
  wallet_software_documented: "pages.disasterDrill.steps.walletSoftware",
  passphrase_documented: "pages.disasterDrill.steps.passphrase",
  gap_limit_or_birthdate_documented: "pages.disasterDrill.steps.gapOrBirth",
  signer_locations_known: "pages.disasterDrill.steps.signerLocations",
  user_did_not_stop: "pages.disasterDrill.steps.userDidNotStop",
  psbt_created: "pages.disasterDrill.steps.psbtCreated",
  required_quorum_signed: "pages.disasterDrill.steps.requiredQuorumSigned",
  psbt_finalized: "pages.disasterDrill.steps.psbtFinalized",
  valid_transaction: "pages.disasterDrill.steps.validTransaction",
  destination_confirmed_on_device: "pages.disasterDrill.steps.destinationConfirmed",
  destination_output_matches: "pages.disasterDrill.steps.destinationOutputMatches",
};

const SAMPLE_SINGLESIG_DESCRIPTOR =
  "wpkh([71348c8a/84'/1'/0']tpubDCTb5JhwTc9S3pfEMNMajVPCEgCDxHTiBwmJgzLa2Znne2pPQ4dh1CjpS7ibiPBEXeJRJxddRaW1ZxxWyDvrndrQk8vqfco9Uvr7Eseo55L/0/*)#r6yctejg";
const SAMPLE_SINGLESIG_KNOWN_ADDRESS = "tb1qqtf24asxktn2chm9wytxfcgu2lfmkcyp9snc80";
const SAMPLE_MULTISIG_DESCRIPTOR =
  "wsh(sortedmulti(2,[4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/0/*,[6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/0/*,[8dfc9b34/48'/1'/0'/2']tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq/0/*))#c2yhzrq7";
const SAMPLE_MULTISIG_3OF5_DESCRIPTOR =
  "wsh(sortedmulti(3,[4ba43603/48'/1'/0'/2']tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz/0/*,[6e37edb9/48'/1'/0'/2']tpubDE4CYsWtymYFQ6vKa1aBYUDn8DQxNCMNBYRXN6LxbPiW2RuQfYsjHnYLeTBsYSsK7Z1LvpjGWPz3YmUL8nEcGpCf9NJcyUoDn7TFSvdUaZJ/0/*,[8dfc9b34/48'/1'/0'/2']tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq/0/*,[83bfab59/48'/1'/0'/2']tpubDEeDAFdob3LJDkTRZgpjYWBgUDN5DQTz5VgzrGW2bABWm3cu365PEqTZJfaeTJKvnnWfVqb1j7qcjzXgQ5y54BBcyyZfkTuPNREB3r4UeoD/0/*,[56c4fac3/48'/1'/0'/2']tpubDEg3kqr2jo5ergkJbFqRHvCpiob7wR7Hi44J7y987G1JZfbzBND77XKTyPZzGvh3uyDf8kexMJnFD9W8FuraJ4wLMsx6YuZVXRSRRcx6QdD/0/*))#t0rxkc9k";
const SAMPLE_MULTISIG_KNOWN_ADDRESS =
  "tb1q8ke5xqhsyqydxk9jkkrn83f6ltp7edst4xv2ar2xlqdry2g8588qpqjjdj";

function utf8Bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

function firstDialogPath(path: string | string[] | null): string | null {
  if (Array.isArray(path)) {
    return path[0] ?? null;
  }
  return path;
}

function svgDataUrl(svg: string): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function mergePayloads(existing: string[], incoming: string[]): string[] {
  const merged = [...existing];
  for (const payload of incoming) {
    const trimmed = payload.trim();
    if (trimmed.length > 0 && !merged.includes(trimmed)) {
      merged.push(trimmed);
    }
  }
  return merged;
}

function firstFinding(report: {
  findings: [DetectedSecret, { start: number; end: number }][];
}): DetectedSecret | null {
  const first = report.findings[0];
  return first === undefined ? null : first[0];
}

function isMultisigScenario(scenario: DisasterQuestionnaireScenario): boolean {
  return scenario === "DS-5" || scenario === "DS-6";
}

function isQuestionnaireScenario(scenario: DisasterScenario): scenario is DisasterQuestionnaireScenario {
  return ["DS-1", "DS-2", "DS-3", "DS-4", "DS-5", "DS-6"].includes(scenario);
}

function isMultisigSurvivabilityScenario(
  scenario: DisasterScenario,
): scenario is MultisigSurvivabilityScenario {
  return scenario === "MS-2OF3" || scenario === "MS-3OF5";
}

function isMissingSignerScenario(scenario: DisasterScenario): scenario is MissingSignerScenario {
  return scenario === "MS-MISSING";
}

function isSigningScenario(scenario: DisasterScenario): scenario is DisasterSigningScenario {
  return ["DS-7", "DS-8", "DS-9", "DS-10"].includes(scenario);
}

function usesDescriptorInput(scenario: DisasterScenario): scenario is DescriptorScenario {
  return (
    isQuestionnaireScenario(scenario) ||
    isMultisigSurvivabilityScenario(scenario) ||
    isMissingSignerScenario(scenario)
  );
}

function templateFromScenario(scenario: MultisigSurvivabilityScenario): MultisigDrillTemplate {
  return scenario === "MS-2OF3" ? "multisig-2of3" : "multisig-3of5";
}

function sampleDescriptorFor(scenario: DisasterQuestionnaireScenario): string {
  return isMultisigScenario(scenario) ? SAMPLE_MULTISIG_DESCRIPTOR : SAMPLE_SINGLESIG_DESCRIPTOR;
}

function sampleMultisigTemplateDescriptor(scenario: MultisigSurvivabilityScenario): string {
  return scenario === "MS-2OF3" ? SAMPLE_MULTISIG_DESCRIPTOR : SAMPLE_MULTISIG_3OF5_DESCRIPTOR;
}

function sampleKnownAddressFor(scenario: DisasterQuestionnaireScenario): string {
  return isMultisigScenario(scenario)
    ? SAMPLE_MULTISIG_KNOWN_ADDRESS
    : SAMPLE_SINGLESIG_KNOWN_ADDRESS;
}

function sampleKnownAddressForScenario(scenario: DisasterScenario): string {
  if (isQuestionnaireScenario(scenario)) {
    return sampleKnownAddressFor(scenario);
  }
  if (scenario === "MS-2OF3") {
    return SAMPLE_MULTISIG_KNOWN_ADDRESS;
  }
  return "";
}

function materialLabelKey(material: MissingSignerRequiredMaterial): string {
  switch (material.kind) {
    case "descriptor_backup":
      return "pages.disasterDrill.missingSigner.materials.descriptorBackup";
    case "coordinator_wallet":
      return "pages.disasterDrill.missingSigner.materials.coordinatorWallet";
    case "practice_funds":
      return "pages.disasterDrill.missingSigner.materials.practiceFunds";
    case "remaining_signer":
      return "pages.disasterDrill.missingSigner.materials.remainingSigner";
    default:
      return "pages.disasterDrill.missingSigner.materials.unknown";
  }
}

function survivabilityLabelKey(verdict: string, descriptorLoss: boolean): string {
  if (descriptorLoss && verdict === "ok_if_xpubs_retained") {
    return "pages.disasterDrill.multisig.survivability.descriptorOk";
  }
  return verdict === "ok"
    ? "pages.disasterDrill.multisig.survivability.ok"
    : "pages.disasterDrill.multisig.survivability.fail";
}

function networkFromValue(value: string): DisasterQuestionnaireNetwork {
  switch (value) {
    case "mainnet":
      return "mainnet";
    case "signet":
      return "signet";
    case "regtest":
      return "regtest";
    case "testnet":
    default:
      return "testnet";
  }
}

function fillRequiredAnswers(scenario: DisasterQuestionnaireScenario): DisasterQuestionnaireAnswers {
  const next = { ...EMPTY_ANSWERS };
  for (const question of REQUIRED_BY_SCENARIO[scenario]) {
    next[question.id] = "yes";
  }
  return next;
}

export default function DisasterDrill(): JSX.Element {
  const { t } = useTranslation();
  const [scenario, setScenario] = useState<DisasterScenario>("DS-5");
  const [descriptor, setDescriptor] = useState("");
  const [knownAddress, setKnownAddress] = useState("");
  const [network, setNetwork] = useState<DisasterQuestionnaireNetwork>("testnet");
  const [signingNetwork, setSigningNetwork] = useState<SigningNetwork>("regtest");
  const [missingSignerNetwork, setMissingSignerNetwork] = useState<PracticeDrillNetwork>("regtest");
  const [signingTransport, setSigningTransport] = useState<DisasterSigningTransport>("file");
  const [qrFormat, setQrFormat] = useState<PsbtQrFormat>("ur");
  const [availableSigners, setAvailableSigners] = useState("");
  const [lostSignerIndex, setLostSignerIndex] = useState("2");
  const [answers, setAnswers] = useState<DisasterQuestionnaireAnswers>(EMPTY_ANSWERS);
  const [userStopped, setUserStopped] = useState(false);
  const [destinationConfirmed, setDestinationConfirmed] = useState(false);
  const [blockedSecret, setBlockedSecret] = useState<DetectedSecret | null>(null);
  const [warnSecret, setWarnSecret] = useState<DetectedSecret | null>(null);
  const [warnConfirmed, setWarnConfirmed] = useState(false);
  const [status, setStatus] = useState<"idle" | "screening" | "running" | "error">("idle");
  const [result, setResult] = useState<DisasterQuestionnaireDrillResult | null>(null);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveOutcome, setSaveOutcome] = useState<DrillResultSaveOutcome | null>(null);
  const [multisigResult, setMultisigResult] =
    useState<MultisigSurvivabilityDrillResult | null>(null);
  const [multisigSaveStatus, setMultisigSaveStatus] =
    useState<"idle" | "saving" | "saved" | "error">("idle");
  const [multisigSaveOutcome, setMultisigSaveOutcome] = useState<DrillResultSaveOutcome | null>(
    null,
  );
  const [missingSignerResult, setMissingSignerResult] = useState<MissingSignerDrillResult | null>(
    null,
  );
  const [missingSignerSaveStatus, setMissingSignerSaveStatus] =
    useState<"idle" | "saving" | "saved" | "error">("idle");
  const [missingSignerSaveOutcome, setMissingSignerSaveOutcome] =
    useState<DrillResultSaveOutcome | null>(null);
  const [signingStartStatus, setSigningStartStatus] =
    useState<"idle" | "starting" | "ready" | "error">("idle");
  const [signingCompleteStatus, setSigningCompleteStatus] =
    useState<"idle" | "completing" | "complete" | "error">("idle");
  const [unsignedPsbtStatus, setUnsignedPsbtStatus] =
    useState<"idle" | "saving" | "saved" | "cancelled" | "error">("idle");
  const [signedPsbtStatus, setSignedPsbtStatus] =
    useState<"idle" | "importing" | "finalized" | "cancelled" | "error">("idle");
  const [qrEncodeStatus, setQrEncodeStatus] =
    useState<"idle" | "encoding" | "ready" | "error">("idle");
  const [qrScanStatus, setQrScanStatus] =
    useState<"idle" | "scanning" | "incomplete" | "finalized" | "no_payload" | "error">("idle");
  const [signingSaveStatus, setSigningSaveStatus] =
    useState<"idle" | "saving" | "saved" | "error">("idle");
  const [signingStart, setSigningStart] = useState<DisasterSigningStartResult | null>(null);
  const [signingResult, setSigningResult] = useState<DisasterSigningDrillResult | null>(null);
  const [signingSaveOutcome, setSigningSaveOutcome] = useState<DrillResultSaveOutcome | null>(null);
  const [unsignedPsbtPath, setUnsignedPsbtPath] = useState<string | null>(null);
  const [signedPsbtPath, setSignedPsbtPath] = useState<string | null>(null);
  const [qrFrameSet, setQrFrameSet] = useState<PsbtQrFrameSet | null>(null);
  const [qrFrameIndex, setQrFrameIndex] = useState(0);
  const [qrPayloads, setQrPayloads] = useState<string[]>([]);
  const [qrDecodeProgress, setQrDecodeProgress] = useState<PsbtQrDecodeResult | null>(null);
  const [mainnetPsbtAcknowledged, setMainnetPsbtAcknowledged] = useState(false);
  const [mainnetPsbtStatus, setMainnetPsbtStatus] =
    useState<"idle" | "importing" | "validated" | "cancelled" | "error">("idle");
  const [mainnetPsbtPath, setMainnetPsbtPath] = useState<string | null>(null);
  const [mainnetPsbtResult, setMainnetPsbtResult] =
    useState<MainnetFilePsbtValidateResult | null>(null);

  const requiredQuestions = useMemo(
    () => (isQuestionnaireScenario(scenario) ? REQUIRED_BY_SCENARIO[scenario] : []),
    [scenario],
  );
  const descriptorMode = usesDescriptorInput(scenario);
  const runDisabled =
    !descriptorMode ||
    descriptor.trim() === "" ||
    status === "screening" ||
    status === "running";
  const visibleQrFrame = qrFrameSet?.frames[qrFrameIndex] ?? null;
  const signingTransportOptions: DisasterSigningTransport[] =
    signingNetwork === "mainnet" ? ["file"] : SIGNING_TRANSPORTS;

  function resetQuestionnaireResult(): void {
    setResult(null);
    setSaveOutcome(null);
    setSaveStatus("idle");
    setMultisigResult(null);
    setMultisigSaveOutcome(null);
    setMultisigSaveStatus("idle");
    setMissingSignerResult(null);
    setMissingSignerSaveOutcome(null);
    setMissingSignerSaveStatus("idle");
  }

  function resetSigningResult(): void {
    setSigningStartStatus("idle");
    setSigningCompleteStatus("idle");
    setUnsignedPsbtStatus("idle");
    setSignedPsbtStatus("idle");
    setQrEncodeStatus("idle");
    setQrScanStatus("idle");
    setSigningSaveStatus("idle");
    setSigningStart(null);
    setSigningResult(null);
    setSigningSaveOutcome(null);
    setUnsignedPsbtPath(null);
    setSignedPsbtPath(null);
    setQrFrameSet(null);
    setQrFrameIndex(0);
    setQrPayloads([]);
    setQrDecodeProgress(null);
    setDestinationConfirmed(false);
    setUserStopped(false);
  }

  function resetMainnetFileResult(): void {
    setMainnetPsbtStatus("idle");
    setMainnetPsbtPath(null);
    setMainnetPsbtResult(null);
  }

  function selectScenario(next: DisasterScenario): void {
    setScenario(next);
    resetQuestionnaireResult();
    resetSigningResult();
    resetMainnetFileResult();
    setWarnSecret(null);
    setWarnConfirmed(false);
    if (isQuestionnaireScenario(next) && isMultisigScenario(next)) {
      setAvailableSigners((current) => (current === "" ? "2" : current));
    }
    if (isMissingSignerScenario(next)) {
      setLostSignerIndex((current) => (current === "" ? "2" : current));
    }
  }

  function loadSample(): void {
    if (!usesDescriptorInput(scenario)) {
      return;
    }
    setDescriptor(
      isQuestionnaireScenario(scenario)
        ? sampleDescriptorFor(scenario)
        : isMultisigSurvivabilityScenario(scenario)
          ? sampleMultisigTemplateDescriptor(scenario)
          : SAMPLE_MULTISIG_DESCRIPTOR,
    );
    setKnownAddress(sampleKnownAddressForScenario(scenario));
    setNetwork("testnet");
    setAvailableSigners(isQuestionnaireScenario(scenario) && isMultisigScenario(scenario) ? "2" : "");
    if (isMissingSignerScenario(scenario)) {
      setLostSignerIndex("2");
      setMissingSignerNetwork("regtest");
    }
    if (isQuestionnaireScenario(scenario)) {
      setAnswers(fillRequiredAnswers(scenario));
    }
    setUserStopped(false);
    setWarnSecret(null);
    setWarnConfirmed(false);
    resetQuestionnaireResult();
  }

  function updateAnswer(id: AnswerKey, answer: DisasterAnswer): void {
    setAnswers((current) => ({ ...current, [id]: answer }));
  }

  async function screenText(
    value: string,
    clearValue: () => void,
  ): Promise<boolean> {
    if (value.trim() === "") {
      return true;
    }
    const report = await detectSensitiveInput(value);
    if (report.action === "block") {
      const detected = firstFinding(report);
      if (detected !== null) {
        setBlockedSecret(detected);
      }
      clearValue();
      setWarnSecret(null);
      setWarnConfirmed(false);
      return false;
    }
    if (report.action === "warn" && !warnConfirmed) {
      const detected = firstFinding(report);
      if (detected !== null) {
        setWarnSecret(detected);
      }
      return false;
    }
    return true;
  }

  function parsedAvailableSigners(): number | null {
    const parsed = Number.parseInt(availableSigners, 10);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function parsedLostSignerIndex(): number {
    const parsed = Number.parseInt(lostSignerIndex, 10);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  async function handleRun(): Promise<void> {
    if (runDisabled || !usesDescriptorInput(scenario)) {
      return;
    }
    setStatus("screening");
    setResult(null);
    setSaveOutcome(null);
    setSaveStatus("idle");
    setMultisigResult(null);
    setMultisigSaveOutcome(null);
    setMultisigSaveStatus("idle");
    setMissingSignerResult(null);
    setMissingSignerSaveOutcome(null);
    setMissingSignerSaveStatus("idle");
    try {
      const descriptorOk = await screenText(descriptor, () => setDescriptor(""));
      const addressOk = await screenText(knownAddress, () => setKnownAddress(""));
      if (!descriptorOk || !addressOk) {
        setStatus("idle");
        return;
      }
      setStatus("running");
      if (isQuestionnaireScenario(scenario)) {
        const nextResult = await runDisasterQuestionnaireDrill({
          scenario,
          descriptor,
          network,
          known_address: knownAddress.trim() === "" ? null : knownAddress,
          available_signers: parsedAvailableSigners(),
          user_stopped: userStopped,
          answers,
        });
        setResult(nextResult);
      } else if (isMultisigSurvivabilityScenario(scenario)) {
        const nextResult = await runMultisigSurvivabilityDrill({
          template: templateFromScenario(scenario),
          descriptor,
          network,
          known_address: knownAddress.trim() === "" ? null : knownAddress,
          user_stopped: userStopped,
        });
        setMultisigResult(nextResult);
      } else {
        const nextResult = await runMissingSignerDrill({
          descriptor,
          network: missingSignerNetwork,
          lost_signer_index: parsedLostSignerIndex(),
          user_stopped: userStopped,
        });
        setMissingSignerResult(nextResult);
      }
      setStatus("idle");
    } catch {
      setStatus("error");
    }
  }

  async function handleSave(): Promise<void> {
    if (result === null) {
      return;
    }
    setSaveStatus("saving");
    try {
      const saved = await saveDisasterQuestionnaireDrillResult(result);
      setSaveOutcome(saved);
      setSaveStatus("saved");
    } catch {
      setSaveStatus("error");
    }
  }

  async function handleSaveMultisig(): Promise<void> {
    if (multisigResult === null) {
      return;
    }
    setMultisigSaveStatus("saving");
    try {
      const saved = await saveMultisigSurvivabilityDrillResult(multisigResult);
      setMultisigSaveOutcome(saved);
      setMultisigSaveStatus("saved");
    } catch {
      setMultisigSaveStatus("error");
    }
  }

  async function handleSaveMissingSigner(): Promise<void> {
    if (missingSignerResult === null) {
      return;
    }
    setMissingSignerSaveStatus("saving");
    try {
      const saved = await saveMissingSignerDrillResult(missingSignerResult);
      setMissingSignerSaveOutcome(saved);
      setMissingSignerSaveStatus("saved");
    } catch {
      setMissingSignerSaveStatus("error");
    }
  }

  function selectSigningNetwork(next: SigningNetwork): void {
    setSigningNetwork(next);
    if (next === "mainnet") {
      setSigningTransport("file");
    }
    resetSigningResult();
    resetMainnetFileResult();
  }

  function selectSigningTransport(next: DisasterSigningTransport): void {
    if (signingNetwork === "mainnet" && next !== "file") {
      return;
    }
    setSigningTransport(next);
    resetSigningResult();
    resetMainnetFileResult();
  }

  function selectQrFormat(next: PsbtQrFormat): void {
    setQrFormat(next);
    setQrEncodeStatus("idle");
    setQrScanStatus("idle");
    setQrFrameSet(null);
    setQrFrameIndex(0);
    setQrPayloads([]);
    setQrDecodeProgress(null);
    setSigningResult(null);
    setSigningCompleteStatus("idle");
  }

  async function handleStartSigningDrill(): Promise<void> {
    if (!isSigningScenario(scenario) || signingNetwork === "mainnet") {
      return;
    }
    resetSigningResult();
    setSigningStartStatus("starting");
    try {
      const started = await startDisasterSigningDrill({
        scenario,
        network: signingNetwork,
        transport: signingTransport,
      });
      setSigningStart(started);
      setSigningStartStatus("ready");
    } catch {
      setSigningStartStatus("error");
    }
  }

  async function handleImportMainnetPsbt(): Promise<void> {
    if (!mainnetPsbtAcknowledged || mainnetPsbtStatus === "importing") {
      return;
    }
    setMainnetPsbtStatus("importing");
    setMainnetPsbtPath(null);
    setMainnetPsbtResult(null);
    try {
      const selected = await showOpenDialog({
        title: t("pages.disasterDrill.signing.mainnet.openTitle"),
        multiple: false,
        directory: false,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      const path = firstDialogPath(selected);
      if (!path) {
        setMainnetPsbtStatus("cancelled");
        return;
      }
      const psbtBase64 = await readPsbtFile(path);
      const validated = await validateMainnetFilePsbt({ psbt_base64: psbtBase64 });
      setMainnetPsbtPath(path);
      setMainnetPsbtResult(validated);
      setMainnetPsbtStatus("validated");
    } catch {
      setMainnetPsbtStatus("error");
    }
  }

  async function completeSigningDrill(signedPsbtBase64: string): Promise<void> {
    const start = signingStart;
    if (start === null || !isSigningScenario(scenario)) {
      return;
    }
    setSigningCompleteStatus("completing");
    setSigningResult(null);
    setSigningSaveOutcome(null);
    setSigningSaveStatus("idle");
    try {
      const completed = await completeDisasterSigningDrill({
        scenario,
        network: start.network,
        transport: start.transport,
        started_at: start.started_at,
        signed_psbt_base64: signedPsbtBase64,
        expected_destination_address: start.destination_address,
        expected_amount_sat: start.amount_sat,
        destination_confirmed: destinationConfirmed,
        user_stopped: userStopped,
      });
      setSigningResult(completed);
      setSigningCompleteStatus("complete");
    } catch {
      setSigningCompleteStatus("error");
    }
  }

  async function handleSaveSigningUnsignedPsbt(): Promise<void> {
    const start = signingStart;
    if (start === null || unsignedPsbtStatus === "saving") {
      return;
    }
    setUnsignedPsbtStatus("saving");
    setUnsignedPsbtPath(null);
    try {
      const path = await showSaveDialog({
        title: t("pages.disasterDrill.signing.file.saveTitle"),
        defaultPath: `lifeboat-${start.scenario.toLowerCase()}-${start.network}-unsigned.psbt`,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      if (!path) {
        setUnsignedPsbtStatus("cancelled");
        return;
      }
      await saveExport(path, utf8Bytes(`${start.unsigned_psbt_base64}\n`));
      setUnsignedPsbtPath(path);
      setUnsignedPsbtStatus("saved");
    } catch {
      setUnsignedPsbtStatus("error");
    }
  }

  async function handleImportSigningSignedPsbt(): Promise<void> {
    if (signingStart === null || signedPsbtStatus === "importing") {
      return;
    }
    setSignedPsbtStatus("importing");
    setSignedPsbtPath(null);
    try {
      const selected = await showOpenDialog({
        title: t("pages.disasterDrill.signing.file.openTitle"),
        multiple: false,
        directory: false,
        filters: [{ name: "PSBT", extensions: ["psbt"] }],
      });
      const path = firstDialogPath(selected);
      if (!path) {
        setSignedPsbtStatus("cancelled");
        return;
      }
      const psbtBase64 = await readPsbtFile(path);
      setSignedPsbtPath(path);
      await completeSigningDrill(psbtBase64);
      setSignedPsbtStatus("finalized");
    } catch {
      setSignedPsbtStatus("error");
      setSigningCompleteStatus("error");
    }
  }

  async function handleGenerateSigningQrFrames(): Promise<void> {
    const start = signingStart;
    if (start === null) {
      return;
    }
    setQrEncodeStatus("encoding");
    setQrScanStatus("idle");
    setQrFrameSet(null);
    setQrFrameIndex(0);
    setQrPayloads([]);
    setQrDecodeProgress(null);
    try {
      const frames = await encodePsbtQrFrames({
        format: qrFormat,
        psbt_base64: start.unsigned_psbt_base64,
      });
      setQrFrameSet(frames);
      setQrEncodeStatus("ready");
    } catch {
      setQrEncodeStatus("error");
    }
  }

  async function decodeSigningQrPayloads(nextPayloads: string[]): Promise<void> {
    const decoded = await decodePsbtQrPayloads({ format: qrFormat, payloads: nextPayloads });
    setQrDecodeProgress(decoded);
    if (decoded.status !== "complete" || !decoded.psbt_base64) {
      setQrScanStatus("incomplete");
      return;
    }
    await completeSigningDrill(decoded.psbt_base64);
    setQrScanStatus("finalized");
  }

  async function handleScanSigningQrFrame(): Promise<void> {
    if (qrFrameSet === null) {
      return;
    }
    setQrScanStatus("scanning");
    try {
      const scanned = await capturePsbtQrPayloads(0);
      if (scanned.length === 0) {
        setQrScanStatus("no_payload");
        return;
      }
      const nextPayloads = mergePayloads(qrPayloads, scanned);
      setQrPayloads(nextPayloads);
      await decodeSigningQrPayloads(nextPayloads);
    } catch {
      setQrScanStatus("error");
      setSigningCompleteStatus("error");
    }
  }

  async function handleSaveSigningResult(): Promise<void> {
    if (signingResult === null) {
      return;
    }
    setSigningSaveStatus("saving");
    try {
      const saved = await saveDisasterSigningDrillResult(signingResult);
      setSigningSaveOutcome(saved);
      setSigningSaveStatus("saved");
    } catch {
      setSigningSaveStatus("error");
    }
  }

  return (
    <PageScaffold titleKey="pages.disasterDrill.title" bodyKey="pages.disasterDrill.body">
      <div className="mt-6 space-y-6">
        <fieldset>
          <legend className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {t("pages.disasterDrill.scenarioLabel")}
          </legend>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            {SCENARIOS.map((option) => (
              <label
                key={option.id}
                className="flex cursor-pointer items-start gap-3 rounded border border-slate-200 p-3 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
              >
                <input
                  type="radio"
                  name="scenario"
                  value={option.id}
                  checked={scenario === option.id}
                  onChange={() => selectScenario(option.id)}
                  className="mt-1 h-4 w-4 accent-brand"
                />
                <span>
                  <span className="block text-sm font-medium text-slate-900 dark:text-slate-100">
                    {option.id}: {t(option.titleKey)}
                  </span>
                  <span className="mt-1 block text-sm text-slate-600 dark:text-slate-300">
                    {t(option.bodyKey)}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        {descriptorMode && (
          <>
        <div className="rounded border border-slate-200 p-4 dark:border-slate-700">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                {t("pages.disasterDrill.descriptor.heading")}
              </h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                {t("pages.disasterDrill.descriptor.help")}
              </p>
            </div>
            <button
              type="button"
              onClick={loadSample}
              className="rounded border border-brand px-3 py-2 text-sm font-medium text-brand hover:bg-brand hover:text-white"
            >
              {t("pages.disasterDrill.descriptor.useSample")}
            </button>
          </div>
          <label
            htmlFor="disaster-descriptor"
            className="mt-4 block text-sm font-medium text-slate-700 dark:text-slate-200"
          >
            {t("pages.disasterDrill.descriptor.label")}
          </label>
          <textarea
            id="disaster-descriptor"
            value={descriptor}
            onChange={(event) => {
              setDescriptor(event.currentTarget.value);
              setResult(null);
              setSaveOutcome(null);
              setSaveStatus("idle");
              setMultisigResult(null);
              setMultisigSaveOutcome(null);
              setMultisigSaveStatus("idle");
              setMissingSignerResult(null);
              setMissingSignerSaveOutcome(null);
              setMissingSignerSaveStatus("idle");
              setWarnSecret(null);
              setWarnConfirmed(false);
            }}
            rows={6}
            className="mt-2 w-full rounded border border-slate-300 bg-white p-3 font-mono text-sm text-slate-900 shadow-sm focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
            placeholder={t("pages.disasterDrill.descriptor.placeholder")}
          />
          {!isMissingSignerScenario(scenario) && (
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-200">
                {t("pages.disasterDrill.network.label")}
                <select
                  value={network}
                  onChange={(event) => setNetwork(networkFromValue(event.currentTarget.value))}
                  className="mt-2 block w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
                >
                  {NETWORKS.map((item) => (
                    <option key={item} value={item}>
                      {t(`pages.disasterDrill.network.${item}`)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-200">
                {t("pages.disasterDrill.knownAddress.label")}
                <input
                  value={knownAddress}
                  onChange={(event) => {
                    setKnownAddress(event.currentTarget.value);
                    setResult(null);
                    setSaveOutcome(null);
                    setSaveStatus("idle");
                    setMultisigResult(null);
                    setMultisigSaveOutcome(null);
                    setMultisigSaveStatus("idle");
                    setMissingSignerResult(null);
                    setMissingSignerSaveOutcome(null);
                    setMissingSignerSaveStatus("idle");
                    setWarnSecret(null);
                    setWarnConfirmed(false);
                  }}
                  className="mt-2 block w-full rounded border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
                  placeholder={t("pages.disasterDrill.knownAddress.placeholder")}
                />
                <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">
                  {t("pages.disasterDrill.knownAddress.help")}
                </span>
              </label>
            </div>
          )}
        </div>

        {isQuestionnaireScenario(scenario) && (
        <div className="rounded border border-slate-200 p-4 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
            {t("pages.disasterDrill.questionnaire.heading")}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {t("pages.disasterDrill.questionnaire.help")}
          </p>
          <div className="mt-4 space-y-4">
            {requiredQuestions.map((question) => (
              <fieldset
                key={question.id}
                className="rounded border border-slate-200 p-3 dark:border-slate-700"
              >
                <legend className="px-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                  {t(question.labelKey)}
                </legend>
                <div className="mt-2 flex flex-wrap gap-2">
                  {ANSWERS.map((answer) => (
                    <label
                      key={answer}
                      className="inline-flex cursor-pointer items-center gap-2 rounded border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
                    >
                      <input
                        type="radio"
                        name={question.id}
                        checked={answers[question.id] === answer}
                        onChange={() => updateAnswer(question.id, answer)}
                        className="h-4 w-4 accent-brand"
                      />
                      {t(`pages.disasterDrill.answers.${answer}`)}
                    </label>
                  ))}
                </div>
              </fieldset>
            ))}
          </div>

          {scenario === "DS-5" && (
            <label className="mt-4 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {t("pages.disasterDrill.availableSigners.label")}
              <input
                type="number"
                min={0}
                max={15}
                value={availableSigners}
                onChange={(event) => setAvailableSigners(event.currentTarget.value)}
                className="mt-2 block w-32 rounded border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
              />
              <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">
                {t("pages.disasterDrill.availableSigners.help")}
              </span>
            </label>
          )}

          <label className="mt-4 flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
            <input
              type="checkbox"
              checked={userStopped}
              onChange={(event) => setUserStopped(event.currentTarget.checked)}
              className="mt-0.5 h-4 w-4 accent-brand"
            />
            <span>{t("pages.disasterDrill.userStopped")}</span>
          </label>
        </div>
        )}

        {isMultisigSurvivabilityScenario(scenario) && (
          <label className="flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
            <input
              type="checkbox"
              checked={userStopped}
              onChange={(event) => setUserStopped(event.currentTarget.checked)}
              className="mt-0.5 h-4 w-4 accent-brand"
            />
            <span>{t("pages.disasterDrill.userStopped")}</span>
          </label>
        )}

        {isMissingSignerScenario(scenario) && (
          <div className="rounded border border-slate-200 p-4 dark:border-slate-700">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              {t("pages.disasterDrill.missingSigner.heading")}
            </h2>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {t("pages.disasterDrill.missingSigner.help")}
            </p>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <fieldset>
                <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.missingSigner.network.label")}
                </legend>
                <div className="mt-2 flex flex-wrap gap-2">
                  {MISSING_SIGNER_NETWORKS.map((item) => (
                    <label
                      key={item}
                      className="inline-flex cursor-pointer items-center gap-2 rounded border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
                    >
                      <input
                        type="radio"
                        name="missing-signer-network"
                        value={item}
                        checked={missingSignerNetwork === item}
                        onChange={() => {
                          setMissingSignerNetwork(item);
                          setMissingSignerResult(null);
                          setMissingSignerSaveOutcome(null);
                          setMissingSignerSaveStatus("idle");
                        }}
                        className="h-4 w-4 accent-brand"
                      />
                      {t(`pages.disasterDrill.missingSigner.network.${item}`)}
                    </label>
                  ))}
                </div>
              </fieldset>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-200">
                {t("pages.disasterDrill.missingSigner.lostSigner.label")}
                <input
                  type="number"
                  min={1}
                  max={15}
                  value={lostSignerIndex}
                  onChange={(event) => {
                    setLostSignerIndex(event.currentTarget.value);
                    setMissingSignerResult(null);
                    setMissingSignerSaveOutcome(null);
                    setMissingSignerSaveStatus("idle");
                  }}
                  className="mt-2 block w-32 rounded border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
                />
                <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">
                  {t("pages.disasterDrill.missingSigner.lostSigner.help")}
                </span>
              </label>
            </div>
            <label className="mt-4 flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
              <input
                type="checkbox"
                checked={userStopped}
                onChange={(event) => setUserStopped(event.currentTarget.checked)}
                className="mt-0.5 h-4 w-4 accent-brand"
              />
              <span>{t("pages.disasterDrill.userStopped")}</span>
            </label>
          </div>
        )}

        {warnSecret !== null && (
          <div className="rounded border border-status-needs-attention/60 bg-status-needs-attention/10 p-4 text-sm text-slate-800 dark:text-slate-100">
            <div className="flex items-start gap-3">
              <AlertTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-status-needs-attention" />
              <div>
                <p className="font-medium">{t("pages.disasterDrill.warn.title")}</p>
                <p className="mt-1">{t("pages.disasterDrill.warn.body")}</p>
                <label className="mt-3 flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={warnConfirmed}
                    onChange={(event) => setWarnConfirmed(event.currentTarget.checked)}
                    className="h-4 w-4 accent-brand"
                  />
                  <span>{t("pages.disasterDrill.warn.confirm")}</span>
                </label>
              </div>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => void handleRun()}
            disabled={runDisabled}
            className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
          >
            {status === "screening" || status === "running"
              ? t("pages.disasterDrill.actions.running")
              : isMultisigSurvivabilityScenario(scenario)
                ? t("pages.disasterDrill.multisig.actions.run")
                : isMissingSignerScenario(scenario)
                  ? t("pages.disasterDrill.missingSigner.actions.run")
                  : t("pages.disasterDrill.actions.run")}
          </button>
          <p className="text-sm text-slate-600 dark:text-slate-300" aria-live="polite">
            {status === "error" && (
              <span className="text-status-not-ready">{t("pages.disasterDrill.actions.error")}</span>
            )}
          </p>
        </div>

        {result !== null && (
          <section
            aria-labelledby="disaster-result-heading"
            className={`rounded border p-4 ${
              result.result === "pass"
                ? "border-status-ready/50 bg-status-ready/10"
                : "border-status-not-ready/50 bg-status-not-ready/10"
            }`}
          >
            <div className="flex items-start gap-3">
              {result.result === "pass" ? (
                <CheckCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-ready" />
              ) : (
                <XCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-not-ready" />
              )}
              <div>
                <h2
                  id="disaster-result-heading"
                  className="text-lg font-semibold text-slate-900 dark:text-slate-100"
                >
                  {result.result === "pass"
                    ? t("pages.disasterDrill.results.pass")
                    : t("pages.disasterDrill.results.fail")}
                </h2>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                  {result.scenario}: {result.scenario_title} - {result.wallet_type}
                </p>
              </div>
            </div>

            <ul className="mt-4 space-y-2">
              {result.steps.map((item) => (
                <li
                  key={item.step}
                  className="flex items-center justify-between gap-3 rounded bg-white px-3 py-2 text-sm dark:bg-slate-900"
                >
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(STEP_LABEL_KEYS[item.step] ?? "pages.disasterDrill.steps.unknown")}
                  </span>
                  <span
                    className={`rounded px-2 py-1 text-xs font-semibold ${
                      item.result === "pass"
                        ? "bg-status-ready text-white"
                        : "bg-status-not-ready text-white"
                    }`}
                  >
                    {t(`pages.disasterDrill.results.step.${item.result}`)}
                  </span>
                </li>
              ))}
            </ul>

            <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-700">
              <button
                type="button"
                onClick={() => void handleSave()}
                disabled={saveStatus === "saving" || saveStatus === "saved"}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {saveStatus === "saving"
                  ? t("pages.disasterDrill.save.saving")
                  : t("pages.disasterDrill.save.button")}
              </button>
              <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                {saveStatus === "saved" && saveOutcome !== null && (
                  <span className="break-all">
                    {t("pages.disasterDrill.save.saved", { path: saveOutcome.path })}
                  </span>
                )}
                {saveStatus === "error" && (
                  <span className="text-status-not-ready">
                    {t("pages.disasterDrill.save.error")}
                  </span>
                )}
              </p>
            </div>
          </section>
        )}

        {multisigResult !== null && (
          <section
            aria-labelledby="multisig-result-heading"
            className={`rounded border p-4 ${
              multisigResult.result === "pass"
                ? "border-status-ready/50 bg-status-ready/10"
                : "border-status-needs-attention/50 bg-status-needs-attention/10"
            }`}
          >
            <div className="flex items-start gap-3">
              {multisigResult.result === "pass" ? (
                <CheckCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-ready" />
              ) : (
                <AlertTriangleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-needs-attention" />
              )}
              <div className="min-w-0 flex-1">
                <h2
                  id="multisig-result-heading"
                  className="text-lg font-semibold text-slate-900 dark:text-slate-100"
                >
                  {multisigResult.result === "pass"
                    ? t("pages.disasterDrill.multisig.results.pass")
                    : t("pages.disasterDrill.multisig.results.fail")}
                </h2>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                  {multisigResult.scenario}: {multisigResult.scenario_title} -{" "}
                  {multisigResult.wallet_type}
                </p>
                <div className="mt-3 flex flex-wrap items-center gap-3 text-sm text-slate-700 dark:text-slate-200">
                  {multisigResult.readiness_status !== null && (
                    <StatusBadge status={multisigResult.readiness_status} />
                  )}
                  {multisigResult.readiness_score !== null && (
                    <span>
                      {t("pages.disasterDrill.multisig.readinessScore", {
                        score: multisigResult.readiness_score,
                      })}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {multisigResult.survivability !== null && (
              <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
                <div className="rounded bg-white p-3 dark:bg-slate-900">
                  <dt className="font-medium text-slate-900 dark:text-slate-100">
                    {t("pages.disasterDrill.multisig.survivability.loseOne")}
                  </dt>
                  <dd className="mt-1 text-slate-700 dark:text-slate-200">
                    {t(survivabilityLabelKey(multisigResult.survivability.lose_1_signer, false))}
                  </dd>
                </div>
                <div className="rounded bg-white p-3 dark:bg-slate-900">
                  <dt className="font-medium text-slate-900 dark:text-slate-100">
                    {t("pages.disasterDrill.multisig.survivability.loseTwo")}
                  </dt>
                  <dd className="mt-1 text-slate-700 dark:text-slate-200">
                    {t(survivabilityLabelKey(multisigResult.survivability.lose_2_signers, false))}
                  </dd>
                </div>
                <div className="rounded bg-white p-3 dark:bg-slate-900">
                  <dt className="font-medium text-slate-900 dark:text-slate-100">
                    {t("pages.disasterDrill.multisig.survivability.loseDescriptor")}
                  </dt>
                  <dd className="mt-1 text-slate-700 dark:text-slate-200">
                    {t(
                      survivabilityLabelKey(
                        multisigResult.survivability.lose_descriptor_only,
                        true,
                      ),
                    )}
                  </dd>
                </div>
              </dl>
            )}

            <ul className="mt-4 space-y-2">
              {multisigResult.steps.map((item) => (
                <li
                  key={item.step}
                  className="flex items-center justify-between gap-3 rounded bg-white px-3 py-2 text-sm dark:bg-slate-900"
                >
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(STEP_LABEL_KEYS[item.step] ?? "pages.disasterDrill.steps.unknown")}
                  </span>
                  <span
                    className={`rounded px-2 py-1 text-xs font-semibold ${
                      item.result === "pass"
                        ? "bg-status-ready text-white"
                        : "bg-status-not-ready text-white"
                    }`}
                  >
                    {t(`pages.disasterDrill.results.step.${item.result}`)}
                  </span>
                </li>
              ))}
            </ul>

            <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-700">
              <button
                type="button"
                onClick={() => void handleSaveMultisig()}
                disabled={multisigSaveStatus === "saving" || multisigSaveStatus === "saved"}
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {multisigSaveStatus === "saving"
                  ? t("pages.disasterDrill.save.saving")
                  : t("pages.disasterDrill.save.button")}
              </button>
              <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                {multisigSaveStatus === "saved" && multisigSaveOutcome !== null && (
                  <span className="break-all">
                    {t("pages.disasterDrill.save.saved", { path: multisigSaveOutcome.path })}
                  </span>
                )}
                {multisigSaveStatus === "error" && (
                  <span className="text-status-not-ready">
                    {t("pages.disasterDrill.save.error")}
                  </span>
                )}
              </p>
            </div>
          </section>
        )}

        {missingSignerResult !== null && (
          <section
            aria-labelledby="missing-signer-result-heading"
            className={`rounded border p-4 ${
              missingSignerResult.result === "pass"
                ? "border-status-ready/50 bg-status-ready/10"
                : "border-status-needs-attention/50 bg-status-needs-attention/10"
            }`}
          >
            <div className="flex items-start gap-3">
              {missingSignerResult.result === "pass" ? (
                <CheckCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-ready" />
              ) : (
                <AlertTriangleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-needs-attention" />
              )}
              <div className="min-w-0 flex-1">
                <h2
                  id="missing-signer-result-heading"
                  className="text-lg font-semibold text-slate-900 dark:text-slate-100"
                >
                  {missingSignerResult.recovery_possible
                    ? t("pages.disasterDrill.missingSigner.results.pass")
                    : t("pages.disasterDrill.missingSigner.results.fail")}
                </h2>
                <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                  {t("pages.disasterDrill.missingSigner.results.summary", {
                    lost: missingSignerResult.lost_signer_index,
                    threshold: missingSignerResult.threshold,
                    total: missingSignerResult.key_count,
                    network: t(
                      `pages.disasterDrill.missingSigner.network.${missingSignerResult.network}`,
                    ),
                  })}
                </p>
              </div>
            </div>

            <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
              <div className="rounded bg-white p-3 dark:bg-slate-900">
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.missingSigner.results.remaining")}
                </dt>
                <dd className="mt-1 text-slate-700 dark:text-slate-200">
                  {missingSignerResult.remaining_signer_indexes.length > 0
                    ? missingSignerResult.remaining_signer_indexes
                        .map((index) =>
                          t("pages.disasterDrill.missingSigner.signerLabel", { index }),
                        )
                        .join(", ")
                    : t("pages.disasterDrill.missingSigner.results.none")}
                </dd>
              </div>
              <div className="rounded bg-white p-3 dark:bg-slate-900">
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.missingSigner.results.required")}
                </dt>
                <dd className="mt-1 text-slate-700 dark:text-slate-200">
                  {t("pages.disasterDrill.missingSigner.results.requiredValue", {
                    count: missingSignerResult.signatures_required,
                  })}
                </dd>
              </div>
              <div className="rounded bg-white p-3 dark:bg-slate-900">
                <dt className="font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.missingSigner.results.outcome")}
                </dt>
                <dd className="mt-1 text-slate-700 dark:text-slate-200">
                  {missingSignerResult.recovery_possible
                    ? t("pages.disasterDrill.missingSigner.results.quorumOk")
                    : t("pages.disasterDrill.missingSigner.results.quorumFail")}
                </dd>
              </div>
            </dl>

            <div className="mt-4 rounded bg-white p-3 text-sm dark:bg-slate-900">
              <h3 className="font-medium text-slate-900 dark:text-slate-100">
                {t("pages.disasterDrill.missingSigner.materials.heading")}
              </h3>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-slate-700 dark:text-slate-200">
                {missingSignerResult.required_materials.map((material) => (
                  <li key={`${material.kind}-${material.signer_index ?? "all"}`}>
                    {t(materialLabelKey(material), { index: material.signer_index ?? 0 })}
                  </li>
                ))}
              </ul>
            </div>

            <ul className="mt-4 space-y-2">
              {missingSignerResult.steps.map((item) => (
                <li
                  key={item.step}
                  className="flex items-center justify-between gap-3 rounded bg-white px-3 py-2 text-sm dark:bg-slate-900"
                >
                  <span className="text-slate-800 dark:text-slate-100">
                    {t(STEP_LABEL_KEYS[item.step] ?? "pages.disasterDrill.steps.unknown")}
                  </span>
                  <span
                    className={`rounded px-2 py-1 text-xs font-semibold ${
                      item.result === "pass"
                        ? "bg-status-ready text-white"
                        : "bg-status-not-ready text-white"
                    }`}
                  >
                    {t(`pages.disasterDrill.results.step.${item.result}`)}
                  </span>
                </li>
              ))}
            </ul>

            <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-700">
              <button
                type="button"
                onClick={() => void handleSaveMissingSigner()}
                disabled={
                  missingSignerSaveStatus === "saving" || missingSignerSaveStatus === "saved"
                }
                className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
              >
                {missingSignerSaveStatus === "saving"
                  ? t("pages.disasterDrill.save.saving")
                  : t("pages.disasterDrill.save.button")}
              </button>
              <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                {missingSignerSaveStatus === "saved" && missingSignerSaveOutcome !== null && (
                  <span className="break-all">
                    {t("pages.disasterDrill.save.saved", { path: missingSignerSaveOutcome.path })}
                  </span>
                )}
                {missingSignerSaveStatus === "error" && (
                  <span className="text-status-not-ready">
                    {t("pages.disasterDrill.save.error")}
                  </span>
                )}
              </p>
            </div>
          </section>
        )}
          </>
        )}

        {isSigningScenario(scenario) && (
          <section className="rounded border border-slate-200 p-4 dark:border-slate-700">
            <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.signing.heading")}
                </h2>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                  {t("pages.disasterDrill.signing.help")}
                </p>
              </div>
              <span className="inline-flex self-start rounded bg-status-needs-attention px-2 py-1 text-xs font-bold uppercase text-slate-950">
                {t("pages.disasterDrill.signing.practiceOnly")}
              </span>
            </div>

            <div className="mt-5 grid gap-5 md:grid-cols-2">
              <fieldset>
                <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.signing.network.label")}
                </legend>
                <div className="mt-2 space-y-2">
                  {SIGNING_NETWORKS.map((item) => (
                    <label
                      key={item}
                      className="flex cursor-pointer items-start gap-3 rounded border border-slate-200 p-3 text-sm hover:border-brand dark:border-slate-700"
                    >
                      <input
                        type="radio"
                        name="disaster-signing-network"
                        value={item}
                        checked={signingNetwork === item}
                        onChange={() => selectSigningNetwork(item)}
                        className="mt-1 h-4 w-4 accent-brand"
                      />
                      <span>
                        <span className="block font-semibold text-slate-900 dark:text-slate-100">
                          {t(`pages.disasterDrill.signing.network.${item}.title`)}
                        </span>
                        <span className="mt-1 block text-slate-600 dark:text-slate-300">
                          {t(`pages.disasterDrill.signing.network.${item}.body`)}
                        </span>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>

              <fieldset>
                <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {t("pages.disasterDrill.signing.transport.label")}
                </legend>
                <div className="mt-2 space-y-2">
                  {signingTransportOptions.map((item) => (
                    <label
                      key={item}
                      className="flex cursor-pointer items-start gap-3 rounded border border-slate-200 p-3 text-sm hover:border-brand dark:border-slate-700"
                    >
                      <input
                        type="radio"
                        name="disaster-signing-transport"
                        value={item}
                        checked={signingTransport === item}
                        onChange={() => selectSigningTransport(item)}
                        className="mt-1 h-4 w-4 accent-brand"
                      />
                      <span>
                        <span className="block font-semibold text-slate-900 dark:text-slate-100">
                          {t(`pages.disasterDrill.signing.transport.${item}.title`)}
                        </span>
                        <span className="mt-1 block text-slate-600 dark:text-slate-300">
                          {t(`pages.disasterDrill.signing.transport.${item}.body`)}
                        </span>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </div>

            {signingNetwork !== "mainnet" && (
              <div className="mt-5 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => void handleStartSigningDrill()}
                  disabled={signingStartStatus === "starting"}
                  className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {signingStartStatus === "starting"
                    ? t("pages.disasterDrill.signing.actions.starting")
                    : t("pages.disasterDrill.signing.actions.start")}
                </button>
                <p className="min-h-5 text-sm text-slate-600 dark:text-slate-300" aria-live="polite">
                  {signingStartStatus === "error" && (
                    <span className="text-status-not-ready">
                      {t("pages.disasterDrill.signing.actions.startError")}
                    </span>
                  )}
                </p>
              </div>
            )}

            {signingNetwork === "mainnet" && (
              <div className="mt-5 rounded border border-network-mainnet/60 bg-network-mainnet/10 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-network-mainnet px-2 py-1 text-xs font-bold uppercase text-white">
                    {t("pages.disasterDrill.signing.mainnet.badge")}
                  </span>
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {t("pages.disasterDrill.signing.mainnet.heading")}
                  </h3>
                </div>
                <p className="mt-2 text-sm text-slate-700 dark:text-slate-200">
                  {t("pages.disasterDrill.signing.mainnet.help")}
                </p>
                <label className="mt-4 flex items-start gap-3 text-sm text-slate-800 dark:text-slate-100">
                  <input
                    type="checkbox"
                    checked={mainnetPsbtAcknowledged}
                    onChange={(event) => {
                      setMainnetPsbtAcknowledged(event.currentTarget.checked);
                      resetMainnetFileResult();
                    }}
                    className="mt-0.5 h-4 w-4 accent-brand"
                  />
                  <span>{t("pages.disasterDrill.signing.mainnet.acknowledge")}</span>
                </label>
                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={() => void handleImportMainnetPsbt()}
                    disabled={!mainnetPsbtAcknowledged || mainnetPsbtStatus === "importing"}
                    className="rounded bg-network-mainnet px-4 py-2 text-sm font-semibold text-white hover:bg-network-mainnet/80 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {mainnetPsbtStatus === "importing"
                      ? t("pages.disasterDrill.signing.mainnet.importing")
                      : t("pages.disasterDrill.signing.mainnet.import")}
                  </button>
                  {!mainnetPsbtAcknowledged && (
                    <p className="text-sm text-slate-700 dark:text-slate-200">
                      {t("pages.disasterDrill.signing.mainnet.ackRequired")}
                    </p>
                  )}
                </div>
                <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                  {mainnetPsbtStatus === "cancelled" && (
                    <p>{t("pages.disasterDrill.signing.mainnet.importCancelled")}</p>
                  )}
                  {mainnetPsbtStatus === "error" && (
                    <p className="text-status-not-ready">
                      {t("pages.disasterDrill.signing.mainnet.importError")}
                    </p>
                  )}
                  {mainnetPsbtStatus === "validated" &&
                    mainnetPsbtResult !== null &&
                    mainnetPsbtPath !== null && (
                      <div>
                        <p className="break-all font-medium text-slate-900 dark:text-slate-100">
                          {t("pages.disasterDrill.signing.mainnet.imported", {
                            path: mainnetPsbtPath,
                          })}
                        </p>
                        <p className="mt-1 font-semibold text-network-mainnet">
                          {t("pages.disasterDrill.signing.mainnet.noBroadcast")}
                        </p>
                        <dl className="mt-3 grid gap-2 md:grid-cols-3">
                          <div>
                            <dt className="font-medium text-slate-900 dark:text-slate-100">
                              {t("pages.disasterDrill.signing.mainnet.txid")}
                            </dt>
                            <dd className="break-all font-mono text-xs">
                              {mainnetPsbtResult.txid}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-slate-900 dark:text-slate-100">
                              {t("pages.disasterDrill.signing.mainnet.fee")}
                            </dt>
                            <dd>
                              {t("pages.disasterDrill.signing.mainnet.feeValue", {
                                fee: mainnetPsbtResult.inspection.fee_sat,
                              })}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium text-slate-900 dark:text-slate-100">
                              {t("pages.disasterDrill.signing.mainnet.finalized")}
                            </dt>
                            <dd>
                              {mainnetPsbtResult.finalized
                                ? t("pages.disasterDrill.signing.mainnet.yes")
                                : t("pages.disasterDrill.signing.mainnet.no")}
                            </dd>
                          </div>
                        </dl>
                      </div>
                    )}
                </div>
              </div>
            )}

            {signingStart !== null && (
              <div className="mt-5 space-y-4">
                <div className="rounded border border-slate-200 bg-slate-50 p-4 text-sm dark:border-slate-700 dark:bg-slate-900">
                  <dl className="grid gap-3 md:grid-cols-2">
                    <div>
                      <dt className="font-medium text-slate-900 dark:text-slate-100">
                        {t("pages.disasterDrill.signing.package.receive")}
                      </dt>
                      <dd className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-200">
                        {signingStart.receive_address}
                      </dd>
                    </div>
                    <div>
                      <dt className="font-medium text-slate-900 dark:text-slate-100">
                        {t("pages.disasterDrill.signing.package.destination")}
                      </dt>
                      <dd className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-200">
                        {signingStart.destination_address}
                      </dd>
                    </div>
                    <div>
                      <dt className="font-medium text-slate-900 dark:text-slate-100">
                        {t("pages.disasterDrill.signing.package.amount")}
                      </dt>
                      <dd className="mt-1 text-slate-700 dark:text-slate-200">
                        {t("pages.disasterDrill.signing.package.amountValue", {
                          amount: signingStart.amount_sat,
                        })}
                      </dd>
                    </div>
                    <div>
                      <dt className="font-medium text-slate-900 dark:text-slate-100">
                        {t("pages.disasterDrill.signing.package.required")}
                      </dt>
                      <dd className="mt-1 text-slate-700 dark:text-slate-200">
                        {t("pages.disasterDrill.signing.package.requiredValue", {
                          count: signingStart.required_signatures,
                        })}
                      </dd>
                    </div>
                  </dl>
                  <label className="mt-4 flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
                    <input
                      type="checkbox"
                      checked={destinationConfirmed}
                      onChange={(event) => {
                        setDestinationConfirmed(event.currentTarget.checked);
                        setSigningResult(null);
                        setSigningCompleteStatus("idle");
                      }}
                      className="mt-0.5 h-4 w-4 accent-brand"
                    />
                    <span>{t("pages.disasterDrill.signing.confirmDestination")}</span>
                  </label>
                  <label className="mt-3 flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
                    <input
                      type="checkbox"
                      checked={userStopped}
                      onChange={(event) => setUserStopped(event.currentTarget.checked)}
                      className="mt-0.5 h-4 w-4 accent-brand"
                    />
                    <span>{t("pages.disasterDrill.userStopped")}</span>
                  </label>
                </div>

                {signingTransport === "file" && (
                  <div className="rounded border border-slate-200 p-4 dark:border-slate-700">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t("pages.disasterDrill.signing.file.heading")}
                    </h3>
                    <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                      {t("pages.disasterDrill.signing.file.help")}
                    </p>
                    <div className="mt-3 flex flex-wrap items-center gap-3">
                      <button
                        type="button"
                        onClick={() => void handleSaveSigningUnsignedPsbt()}
                        disabled={unsignedPsbtStatus === "saving"}
                        className="rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {unsignedPsbtStatus === "saving"
                          ? t("pages.disasterDrill.signing.file.saving")
                          : t("pages.disasterDrill.signing.file.saveUnsigned")}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleImportSigningSignedPsbt()}
                        disabled={signedPsbtStatus === "importing"}
                        className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {signedPsbtStatus === "importing"
                          ? t("pages.disasterDrill.signing.file.importing")
                          : t("pages.disasterDrill.signing.file.importSigned")}
                      </button>
                    </div>
                    <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                      {unsignedPsbtStatus === "saved" && unsignedPsbtPath !== null && (
                        <p className="break-all">
                          {t("pages.disasterDrill.signing.file.saved", {
                            path: unsignedPsbtPath,
                          })}
                        </p>
                      )}
                      {unsignedPsbtStatus === "cancelled" && (
                        <p>{t("pages.disasterDrill.signing.file.saveCancelled")}</p>
                      )}
                      {unsignedPsbtStatus === "error" && (
                        <p className="text-status-not-ready">
                          {t("pages.disasterDrill.signing.file.saveError")}
                        </p>
                      )}
                      {signedPsbtStatus === "cancelled" && (
                        <p>{t("pages.disasterDrill.signing.file.importCancelled")}</p>
                      )}
                      {signedPsbtStatus === "error" && (
                        <p className="text-status-not-ready">
                          {t("pages.disasterDrill.signing.file.importError")}
                        </p>
                      )}
                      {signedPsbtStatus === "finalized" && signedPsbtPath !== null && (
                        <p className="break-all">
                          {t("pages.disasterDrill.signing.file.imported", {
                            path: signedPsbtPath,
                          })}
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {signingTransport === "qr" && (
                  <div className="rounded border border-slate-200 p-4 dark:border-slate-700">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t("pages.disasterDrill.signing.qr.heading")}
                    </h3>
                    <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                      {t("pages.disasterDrill.signing.qr.help")}
                    </p>
                    <fieldset className="mt-3">
                      <legend className="text-sm font-medium text-slate-900 dark:text-slate-100">
                        {t("pages.disasterDrill.signing.qr.format.label")}
                      </legend>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {QR_FORMATS.map((item) => (
                          <label
                            key={item}
                            className="inline-flex cursor-pointer items-center gap-2 rounded border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:border-brand dark:border-slate-700 dark:text-slate-200"
                          >
                            <input
                              type="radio"
                              name="disaster-signing-qr-format"
                              value={item}
                              checked={qrFormat === item}
                              onChange={() => selectQrFormat(item)}
                              className="h-4 w-4 accent-brand"
                            />
                            {t(`pages.disasterDrill.signing.qr.format.${item}`)}
                          </label>
                        ))}
                      </div>
                    </fieldset>
                    <div className="mt-3 flex flex-wrap items-center gap-3">
                      <button
                        type="button"
                        onClick={() => void handleGenerateSigningQrFrames()}
                        disabled={qrEncodeStatus === "encoding"}
                        className="rounded border border-brand px-4 py-2 text-sm font-medium text-brand hover:bg-brand/10 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {qrEncodeStatus === "encoding"
                          ? t("pages.disasterDrill.signing.qr.generating")
                          : t("pages.disasterDrill.signing.qr.generate")}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleScanSigningQrFrame()}
                        disabled={qrFrameSet === null || qrScanStatus === "scanning"}
                        className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {qrScanStatus === "scanning"
                          ? t("pages.disasterDrill.signing.qr.scanning")
                          : t("pages.disasterDrill.signing.qr.scan")}
                      </button>
                    </div>

                    {visibleQrFrame !== null && (
                      <div className="mt-4 grid gap-4 md:grid-cols-[minmax(0,16rem)_1fr]">
                        <div>
                          <div className="flex aspect-square w-full max-w-64 items-center justify-center rounded border border-slate-200 bg-white p-3 dark:border-slate-700">
                            <img
                              src={svgDataUrl(visibleQrFrame.svg)}
                              alt={t("pages.disasterDrill.signing.qr.alt", {
                                index: visibleQrFrame.index,
                                total: visibleQrFrame.total,
                              })}
                              className="h-full w-full"
                            />
                          </div>
                          <div className="mt-3 flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              onClick={() =>
                                setQrFrameIndex((current) =>
                                  current === 0 ? visibleQrFrame.total - 1 : current - 1,
                                )
                              }
                              className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:border-brand hover:text-brand dark:border-slate-600 dark:text-slate-200"
                            >
                              {t("pages.disasterDrill.signing.qr.previous")}
                            </button>
                            <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                              {t("pages.disasterDrill.signing.qr.frame", {
                                index: visibleQrFrame.index,
                                total: visibleQrFrame.total,
                              })}
                            </p>
                            <button
                              type="button"
                              onClick={() =>
                                setQrFrameIndex((current) => (current + 1) % visibleQrFrame.total)
                              }
                              className="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:border-brand hover:text-brand dark:border-slate-600 dark:text-slate-200"
                            >
                              {t("pages.disasterDrill.signing.qr.next")}
                            </button>
                          </div>
                        </div>
                        <div className="min-w-0 text-sm text-slate-700 dark:text-slate-200">
                          <p>{t("pages.disasterDrill.signing.qr.instructions")}</p>
                          <code className="mt-2 block max-h-28 overflow-auto break-all rounded bg-slate-100 p-3 font-mono text-xs text-slate-900 dark:bg-slate-900 dark:text-slate-100">
                            {visibleQrFrame.payload}
                          </code>
                        </div>
                      </div>
                    )}

                    <div className="mt-3 min-h-5 space-y-2 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                      {qrEncodeStatus === "error" && (
                        <p className="text-status-not-ready">
                          {t("pages.disasterDrill.signing.qr.encodeError")}
                        </p>
                      )}
                      {qrScanStatus === "no_payload" && (
                        <p>{t("pages.disasterDrill.signing.qr.noPayload")}</p>
                      )}
                      {qrScanStatus === "incomplete" && qrDecodeProgress !== null && (
                        <p>
                          {t("pages.disasterDrill.signing.qr.incomplete", {
                            count: qrDecodeProgress.received_count,
                          })}
                        </p>
                      )}
                      {qrScanStatus === "error" && (
                        <p className="text-status-not-ready">
                          {t("pages.disasterDrill.signing.qr.scanError")}
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {signingCompleteStatus === "error" && (
                  <p className="text-sm text-status-not-ready">
                    {t("pages.disasterDrill.signing.actions.completeError")}
                  </p>
                )}

                {signingResult !== null && (
                  <section
                    aria-labelledby="disaster-signing-result-heading"
                    className={`rounded border p-4 ${
                      signingResult.result === "pass"
                        ? "border-status-ready/50 bg-status-ready/10"
                        : "border-status-not-ready/50 bg-status-not-ready/10"
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      {signingResult.result === "pass" ? (
                        <CheckCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-ready" />
                      ) : (
                        <XCircleIcon className="mt-0.5 h-6 w-6 shrink-0 text-status-not-ready" />
                      )}
                      <div>
                        <h2
                          id="disaster-signing-result-heading"
                          className="text-lg font-semibold text-slate-900 dark:text-slate-100"
                        >
                          {signingResult.result === "pass"
                            ? t("pages.disasterDrill.signing.results.pass")
                            : t("pages.disasterDrill.signing.results.fail")}
                        </h2>
                        <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">
                          {signingResult.scenario}: {signingResult.scenario_title} -{" "}
                          {signingResult.wallet_type}
                        </p>
                        {signingResult.finalized_txid !== "" && (
                          <p className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-200">
                            {signingResult.finalized_txid}
                          </p>
                        )}
                      </div>
                    </div>

                    <ul className="mt-4 space-y-2">
                      {signingResult.steps.map((item) => (
                        <li
                          key={item.step}
                          className="flex items-center justify-between gap-3 rounded bg-white px-3 py-2 text-sm dark:bg-slate-900"
                        >
                          <span className="text-slate-800 dark:text-slate-100">
                            {t(STEP_LABEL_KEYS[item.step] ?? "pages.disasterDrill.steps.unknown")}
                          </span>
                          <span
                            className={`rounded px-2 py-1 text-xs font-semibold ${
                              item.result === "pass"
                                ? "bg-status-ready text-white"
                                : "bg-status-not-ready text-white"
                            }`}
                          >
                            {t(`pages.disasterDrill.results.step.${item.result}`)}
                          </span>
                        </li>
                      ))}
                    </ul>

                    <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-700">
                      <button
                        type="button"
                        onClick={() => void handleSaveSigningResult()}
                        disabled={signingSaveStatus === "saving" || signingSaveStatus === "saved"}
                        className="rounded bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand-fg disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {signingSaveStatus === "saving"
                          ? t("pages.disasterDrill.save.saving")
                          : t("pages.disasterDrill.save.button")}
                      </button>
                      <p className="min-h-5 text-sm text-slate-700 dark:text-slate-200" aria-live="polite">
                        {signingSaveStatus === "saved" && signingSaveOutcome !== null && (
                          <span className="break-all">
                            {t("pages.disasterDrill.save.saved", {
                              path: signingSaveOutcome.path,
                            })}
                          </span>
                        )}
                        {signingSaveStatus === "error" && (
                          <span className="text-status-not-ready">
                            {t("pages.disasterDrill.save.error")}
                          </span>
                        )}
                      </p>
                    </div>
                  </section>
                )}
              </div>
            )}
          </section>
        )}
      </div>

      <SensitiveInputDialog
        detected={blockedSecret}
        onAcknowledge={() => setBlockedSecret(null)}
      />
    </PageScaffold>
  );
}
