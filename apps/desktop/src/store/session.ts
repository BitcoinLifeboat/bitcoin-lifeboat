import { create } from "zustand";

/**
 * A derived address row. Mirrors the Rust core `DerivedAddress`; the frontend
 * never derives addresses itself — it receives them from a Rust command.
 */
export interface DerivedAddress {
  index: number;
  address: string;
  chain: "receive" | "change";
}

/**
 * The Bitcoin network whose data the current screen is handling. The values
 * mirror the Rust core's `Network` serialization — note mainnet serializes as
 * "bitcoin". The §22.4 network banner is the single place that maps "bitcoin" to
 * the MAINNET label and the red color.
 */
export type WalletNetwork = "bitcoin" | "testnet" | "signet" | "regtest";

/**
 * Confidential, current-screen-only state.
 *
 * SAFETY INVARIANT (§13, §22.11): descriptors, xpubs, fingerprints, derived
 * addresses, and reports are Confidential. This is intentionally a plain
 * in-memory Zustand store — it is NEVER wrapped in the `persist` middleware and
 * never touches localStorage / sessionStorage / IndexedDB. Leaving a screen (or
 * calling `reset`) drops the data. Enforced by `store/session.test.ts`.
 */
export interface SessionState {
  /** The descriptor the user is currently auditing (Confidential). */
  descriptor: string | null;
  /** An optional known receive address for the §D8 match check (Confidential). */
  knownAddress: string | null;
  /** The readiness report returned by the Rust core (Confidential; typed in US-050). */
  report: unknown | null;
  /** Addresses derived for the current descriptor (Confidential). */
  derivedAddresses: DerivedAddress[];
  /** The network the §22.4 banner reflects (not secret, but session-scoped). */
  network: WalletNetwork;
  setDescriptor: (descriptor: string | null) => void;
  setKnownAddress: (knownAddress: string | null) => void;
  setReport: (report: unknown | null) => void;
  setDerivedAddresses: (derivedAddresses: DerivedAddress[]) => void;
  setNetwork: (network: WalletNetwork) => void;
  /** Clear all Confidential data (e.g. on "Save and quit" or screen exit). */
  reset: () => void;
}

type SessionData = Pick<
  SessionState,
  "descriptor" | "knownAddress" | "report" | "derivedAddresses" | "network"
>;

// Default to mainnet ("bitcoin") so the §22.4 banner shows the conservative red
// MAINNET state until a descriptor's network is inferred. Inference happens in
// US-049/US-050, once a pasted descriptor has cleared the sensitive-input
// detector and reached the Rust core (audit_descriptor reports the network) —
// the wizard shell (US-048) never parses descriptors itself. The banner then
// recolors instantly. Network is session-scoped and resets on exit.
const EMPTY: SessionData = {
  descriptor: null,
  knownAddress: null,
  report: null,
  derivedAddresses: [],
  network: "bitcoin",
};

export const useSessionStore = create<SessionState>((set) => ({
  ...EMPTY,
  setDescriptor: (descriptor) => set({ descriptor }),
  setKnownAddress: (knownAddress) => set({ knownAddress }),
  setReport: (report) => set({ report }),
  setDerivedAddresses: (derivedAddresses) => set({ derivedAddresses }),
  setNetwork: (network) => set({ network }),
  reset: () => set({ ...EMPTY }),
}));
