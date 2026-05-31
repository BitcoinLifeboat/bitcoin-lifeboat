import { HashRouter, Navigate, Route, Routes } from "react-router-dom";

import Onboarding from "./onboarding/Onboarding";
import AppLayout from "./layout/AppLayout";
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
import { usePrefsStore } from "./store/prefs";

/**
 * App shell.
 *
 * On first launch the §15.2 onboarding flow shows until the user finishes (or
 * skips, after Screen 2) — its final screen (Screen 5) is this routed app's Home
 * dashboard. Routing uses a HashRouter because it is robust inside the Tauri
 * webview (which serves assets from a custom protocol, not a real history-API
 * origin). Pages are placeholders here — US-046..US-055 fill each screen. No
 * Bitcoin logic ever runs in the frontend; screens call Rust commands
 * (US-042/043).
 */
export default function App(): JSX.Element {
  const onboardingComplete = usePrefsStore((state) => state.onboardingComplete);

  if (!onboardingComplete) {
    return <Onboarding />;
  }

  return (
    <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
