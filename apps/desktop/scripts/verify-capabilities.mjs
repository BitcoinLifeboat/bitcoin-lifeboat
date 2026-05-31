#!/usr/bin/env node
// Verifies the Tauri desktop security posture against the PRD NORMATIVE specs:
//   §13.7  capabilities/default.json is EXACTLY the locked-down permission set
//   §13.8  tauri.conf.json app.security.csp is EXACTLY the strict CSP
//   §13.10 no auto-updater anywhere in config or Cargo deps
//
// This gate needs no webkit2gtk / system libs, so it runs in CI and in
// constrained sandboxes where `cargo build` of the Tauri crate cannot link.
// It is the runnable enforcement of NFR-SEC-7 / NFR-SEC-8. Run with:
//   node scripts/verify-capabilities.mjs   (or `npm run verify:security`)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const srcTauri = join(here, "..", "src-tauri");

const pass = [];
const fail = [];
const check = (cond, msg) => (cond ? pass.push(msg) : fail.push(msg));

// ── §13.7 capabilities/default.json ────────────────────────────────────────
const desktopCap = JSON.parse(
  readFileSync(join(srcTauri, "capabilities", "default.json"), "utf8"),
);
const mobileCap = JSON.parse(
  readFileSync(join(srcTauri, "capabilities", "mobile.json"), "utf8"),
);

const EXPECTED_STRING_PERMS = [
  "core:default",
  "dialog:allow-open",
  "dialog:allow-save",
  "os:allow-platform",
  "os:allow-version",
  "process:allow-exit",
];
// fs read/write are scoped to dialog paths; shell execute is scoped to HWI only.
const EXPECTED_SCOPED = {
  "fs:allow-read-file": "$DIALOG_PATH",
  "fs:allow-write-file": "$DIALOG_PATH",
  "shell:allow-execute": {
    name: "binaries/hwi-lifeboat",
    sidecar: true,
    args: true,
  },
};

const perms = Array.isArray(desktopCap.permissions) ? desktopCap.permissions : [];
const stringPerms = perms.filter((p) => typeof p === "string").sort();
const objectPerms = perms.filter((p) => p && typeof p === "object");

check(
  JSON.stringify(desktopCap.platforms ?? []) ===
    JSON.stringify(["linux", "macOS", "windows"]),
  `desktop capability targets exactly linux/macOS/windows`,
);
check(
  JSON.stringify(stringPerms) ===
    JSON.stringify([...EXPECTED_STRING_PERMS].sort()),
  `desktop string permissions are EXACTLY the §13.7 set (got ${JSON.stringify(stringPerms)})`,
);

const scopedById = Object.fromEntries(objectPerms.map((p) => [p.identifier, p]));
check(
  JSON.stringify(Object.keys(scopedById).sort()) ===
    JSON.stringify(Object.keys(EXPECTED_SCOPED).sort()),
  `scoped permissions are EXACTLY fs read/write + HWI sidecar execute (got ${JSON.stringify(Object.keys(scopedById))})`,
);
for (const [id, expected] of Object.entries(EXPECTED_SCOPED)) {
  const p = scopedById[id];
  if (typeof expected === "string") {
    check(
      !!p &&
        Array.isArray(p.allow) &&
        p.allow.length === 1 &&
        p.allow[0] &&
        p.allow[0].path === expected,
      `${id} is scoped to exactly [{ path: "${expected}" }]`,
    );
  } else {
    const actual = p?.allow?.[0] ?? {};
    check(
      !!p &&
        Array.isArray(p.allow) &&
        p.allow.length === 1 &&
        actual.name === expected.name &&
        actual.sidecar === expected.sidecar &&
        actual.args === expected.args &&
        JSON.stringify(Object.keys(actual).sort()) ===
          JSON.stringify(Object.keys(expected).sort()),
      `${id} is scoped to exactly ${JSON.stringify([expected])}`,
    );
  }
}

check(
  Array.isArray(desktopCap.windows) &&
    desktopCap.windows.length === 1 &&
    desktopCap.windows[0] === "main",
  `desktop capability targets exactly the "main" window`,
);

check(
  JSON.stringify(mobileCap.platforms ?? []) ===
    JSON.stringify(["iOS", "android"]),
  `mobile capability targets exactly iOS/android`,
);
check(
  Array.isArray(mobileCap.windows) &&
    mobileCap.windows.length === 1 &&
    mobileCap.windows[0] === "main",
  `mobile capability targets exactly the "main" window`,
);
check(
  JSON.stringify(mobileCap.permissions ?? []) ===
    JSON.stringify(["camera:allow-take-picture"]),
  `mobile capability contains only camera:allow-take-picture`,
);

// ── §13.7 "Explicitly NOT included" — forbidden permission namespaces ───────
const FORBIDDEN = [
  "http:",
  "shell:allow-open",
  "shell:allow-spawn",
  "shell:allow-kill",
  "shell:allow-stdin-write",
  "shell:default",
  "clipboard-manager:",
  "clipboard:",
  "notification:",
  "global-shortcut:",
  "window:allow-create",
  "process:allow-spawn",
  "path:allow-resolve",
  "webview:allow-create-webview",
  "updater:",
  "camera:allow-record-video",
];
const capText = JSON.stringify([desktopCap, mobileCap]);
for (const f of FORBIDDEN) {
  check(!capText.includes(f), `capability does NOT include forbidden "${f}"`);
}

// ── §13.8 CSP in tauri.conf.json ───────────────────────────────────────────
const conf = JSON.parse(readFileSync(join(srcTauri, "tauri.conf.json"), "utf8"));
const csp = conf?.app?.security?.csp ?? "";

// Compare directive-by-directive, order-independent, whitespace-normalized.
const norm = (s) =>
  s
    .split(";")
    .map((d) => d.trim().replace(/\s+/g, " "))
    .filter(Boolean)
    .sort();
const EXPECTED_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self' ipc: http://ipc.localhost",
  "img-src 'self' data: asset: tauri:",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "worker-src 'self' blob:",
];
check(
  JSON.stringify(norm(csp)) === JSON.stringify([...EXPECTED_CSP].sort()),
  `CSP is EXACTLY the §13.8 policy (got: ${JSON.stringify(csp)})`,
);
check(!csp.includes("unsafe-eval"), "CSP contains no 'unsafe-eval' (§13.8)");
check(
  !csp.includes("wasm-unsafe-eval"),
  "CSP contains no 'wasm-unsafe-eval' (§13.8)",
);

// ── §13.10 no auto-updater ─────────────────────────────────────────────────
check(
  !("updater" in (conf.plugins ?? {})),
  "tauri.conf.json has no plugins.updater (§13.10)",
);
check(
  !JSON.stringify(conf).includes("updater"),
  "tauri.conf.json mentions no updater anywhere (§13.10)",
);
check(
  JSON.stringify(conf?.plugins?.shell ?? {}) === JSON.stringify({ open: false }),
  "shell plugin open API is disabled; only scoped sidecar execute is exposed",
);
check(
  JSON.stringify(conf?.bundle?.externalBin ?? []) ===
    JSON.stringify(["binaries/hwi-lifeboat"]),
  "bundle.externalBin contains only the HWI sidecar path",
);
const cargoToml = readFileSync(join(srcTauri, "Cargo.toml"), "utf8");
check(
  !cargoToml.includes("tauri-plugin-updater"),
  "src-tauri/Cargo.toml has no tauri-plugin-updater dependency (§13.10)",
);

// ── config window labelled "main" (matches the capability target) ──────────
const wins = conf?.app?.windows ?? [];
check(
  wins.some((w) => w && w.label === "main"),
  `tauri.conf.json defines a window labelled "main"`,
);

// ── report ─────────────────────────────────────────────────────────────────
for (const m of pass) console.log(`  ok  ${m}`);
if (fail.length) {
  console.error(`\nFAILED ${fail.length} security check(s):`);
  for (const m of fail) console.error(`  XX  ${m}`);
  process.exit(1);
}
console.log(
  `\nAll ${pass.length} checks passed (§13.7 capabilities, §13.8 CSP, §13.10 no-updater).`,
);
