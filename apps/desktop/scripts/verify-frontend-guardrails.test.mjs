#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { formatViolations, runGuardrails } from "./verify-frontend-guardrails.mjs";

function writeSampleProject(files = {}, packagePatch = {}) {
  const root = mkdtempSync(join(tmpdir(), "lifeboat-guardrails-"));
  const packageJson = {
    name: "lifeboat-guardrail-sample",
    private: true,
    type: "module",
    dependencies: {
      react: "18.3.1",
      ...(packagePatch.dependencies ?? {}),
    },
    devDependencies: {
      vite: "5.4.11",
      ...(packagePatch.devDependencies ?? {}),
    },
    optionalDependencies: packagePatch.optionalDependencies ?? undefined,
    peerDependencies: packagePatch.peerDependencies ?? undefined,
  };

  writeFile(root, "package.json", `${JSON.stringify(packageJson, null, 2)}\n`);
  writeFile(root, "src/index.ts", "export const clean = true;\n");
  writeFile(
    root,
    "src-tauri/tauri.conf.json",
    `${JSON.stringify(
      {
        app: {
          security: { csp: "default-src 'self'; script-src 'self';" },
          windows: [{ label: "main" }],
        },
      },
      null,
      2,
    )}\n`,
  );
  writeFile(
    root,
    "src-tauri/Cargo.toml",
    '[package]\nname = "sample"\nversion = "0.1.0"\n',
  );

  for (const [path, content] of Object.entries(files)) {
    writeFile(root, path, content);
  }
  return root;
}

function writeFile(root, path, content) {
  const full = join(root, path);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

function expectGuardrail(root, guardrail) {
  const result = runGuardrails({ root });
  assert(
    result.violations.some((v) => v.guardrail === guardrail),
    `expected ${guardrail}, got:\n${formatViolations(result.violations)}`,
  );
}

function withProject(files, packagePatch, fn) {
  const root = writeSampleProject(files, packagePatch);
  try {
    fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("passes on the clean desktop tree", () => {
  const result = runGuardrails();
  assert.equal(result.violations.length, 0, formatViolations(result.violations));
});

test("passes on a clean minimal sample tree", () => {
  withProject({}, {}, (root) => {
    const result = runGuardrails({ root });
    assert.equal(result.violations.length, 0, formatViolations(result.violations));
  });
});

test("fails on forbidden Bitcoin or crypto imports", () => {
  withProject(
    { "src/bad.ts": 'import { Psbt } from "@scure/btc-signer";\nconsole.log(Psbt);\n' },
    {},
    (root) => expectGuardrail(root, "frontend-forbidden-crypto"),
  );
});

test("fails on forbidden Bitcoin or crypto dependencies", () => {
  withProject({}, { dependencies: { "bitcoinjs-lib": "6.1.7" } }, (root) =>
    expectGuardrail(root, "frontend-forbidden-crypto"),
  );
});

test("fails on every dynamic-code execution form", () => {
  const samples = [
    "eval('1 + 1');\n",
    "new Function('return 1')();\n",
    "Function('return 1')();\n",
    "setTimeout('alert(1)', 1);\n",
    "setInterval(`alert(1)`, 1);\n",
  ];

  for (const sample of samples) {
    withProject({ "src/bad.ts": sample }, {}, (root) =>
      expectGuardrail(root, "frontend-no-dynamic-code"),
    );
  }
});

test("fails on web-storage writes that could persist Confidential data", () => {
  withProject(
    {
      "src/bad.ts":
        'const descriptor = "wpkh([00000000/84h/0h/0h]xpubCONFIDENTIAL/0/*)";\nlocalStorage.setItem("descriptor", descriptor);\n',
    },
    {},
    (root) => expectGuardrail(root, "frontend-no-confidential-web-storage"),
  );
});

test("fails on copy claiming user funds are safe", () => {
  withProject(
    { "src/i18n/en.json": '{ "bad": "Your funds are safe." }\n' },
    {},
    (root) => expectGuardrail(root, "frontend-no-safe-funds-claim"),
  );
});

test("allows negated normative safety copy", () => {
  withProject(
    { "src/i18n/en.json": '{ "ok": "We never claim your funds are safe." }\n' },
    {},
    (root) => {
      const result = runGuardrails({ root });
      assert.equal(result.violations.length, 0, formatViolations(result.violations));
    },
  );
});

test("fails on analytics SDK dependencies, imports, and snippets", () => {
  withProject({}, { dependencies: { "posthog-js": "1.0.0" } }, (root) =>
    expectGuardrail(root, "frontend-no-analytics"),
  );
  withProject(
    { "src/bad.ts": 'import * as Sentry from "@sentry/browser";\nSentry.init({});\n' },
    {},
    (root) => expectGuardrail(root, "frontend-no-analytics"),
  );
  withProject({ "src/bad.ts": 'gtag("event", "screen_view");\n' }, {}, (root) =>
    expectGuardrail(root, "frontend-no-analytics"),
  );
});

test("fails on Tauri updater dependencies and config", () => {
  withProject({}, { dependencies: { "@tauri-apps/plugin-updater": "2.0.0" } }, (root) =>
    expectGuardrail(root, "tauri-no-updater"),
  );
  withProject(
    { "src-tauri/Cargo.toml": '[package]\nname = "sample"\nversion = "0.1.0"\n[dependencies]\ntauri-plugin-updater = "2"\n' },
    {},
    (root) => expectGuardrail(root, "tauri-no-updater"),
  );
  withProject(
    { "src-tauri/tauri.conf.json": '{ "plugins": { "updater": {} }, "app": { "windows": [{ "label": "main" }] } }\n' },
    {},
    (root) => expectGuardrail(root, "tauri-no-updater"),
  );
});
