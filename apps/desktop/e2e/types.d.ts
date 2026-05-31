export {};

declare global {
  interface Window {
    __TAURI_INTERNALS__: {
      invoke: (cmd: string, args?: unknown, options?: unknown) => Promise<unknown>;
      transformCallback: (callback?: unknown, once?: boolean) => number;
      unregisterCallback: (id: number) => void;
      convertFileSrc: (path: string, protocol?: string) => string;
    };
    __lifeboatE2e: {
      invocations: Array<{ cmd: string; args: unknown }>;
      saves: unknown[];
    };
    isTauri: boolean;
  }
}
