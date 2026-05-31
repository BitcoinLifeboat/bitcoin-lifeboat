#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { formatViolations, runI18nChecks } from "./verify-i18n.mjs";

const baseLocale = {
  app: { name: "Bitcoin Lifeboat" },
  nav: { home: "Home" },
};

const baseFtl = `errors-E-INPUT-001 =
    .title = Empty input
    .description = No descriptor or file was provided.
    .action = Paste a descriptor or choose a file.
`;

function writeFile(root, path, content) {
  const full = join(root, path);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

function writeJson(root, path, value) {
  writeFile(root, path, `${JSON.stringify(value, null, 2)}\n`);
}

function writeSampleTree(patch = {}) {
  const root = mkdtempSync(join(tmpdir(), "lifeboat-i18n-"));
  const appRoot = join(root, "apps/desktop");
  const repoRoot = root;
  for (const locale of ["en", "es", "de", "fr"]) {
    const localeValue = patch.locales?.[locale] ?? baseLocale;
    writeJson(appRoot, `src/i18n/${locale}.json`, localeValue);
    const ftlValue = patch.ftl?.[locale] ?? baseFtl;
    writeFile(repoRoot, `crates/error-taxonomy/strings/${locale}.ftl`, ftlValue);
  }
  writeFile(
    appRoot,
    "src/App.tsx",
    'import { useTranslation } from "react-i18next";\nexport default function App() { const { t } = useTranslation(); return <button aria-label={t("nav.home")}>{t("nav.home")}</button>; }\n',
  );
  for (const [file, content] of Object.entries(patch.files ?? {})) {
    writeFile(appRoot, file, content);
  }
  return { root, appRoot, repoRoot };
}

function withSampleTree(patch, fn) {
  const tree = writeSampleTree(patch);
  try {
    fn(tree);
  } finally {
    rmSync(tree.root, { recursive: true, force: true });
  }
}

function expectGuardrail(patch, guardrail) {
  withSampleTree(patch, ({ appRoot, repoRoot }) => {
    const result = runI18nChecks({ appRoot, repoRoot });
    assert(
      result.violations.some((v) => v.guardrail === guardrail),
      `expected ${guardrail}, got:\n${formatViolations(result.violations)}`,
    );
  });
}

test("passes on the clean desktop tree", () => {
  const result = runI18nChecks();
  assert.equal(result.violations.length, 0, formatViolations(result.violations));
});

test("passes on a clean minimal sample tree", () => {
  withSampleTree({}, ({ appRoot, repoRoot }) => {
    const result = runI18nChecks({ appRoot, repoRoot });
    assert.equal(result.violations.length, 0, formatViolations(result.violations));
  });
});

test("fails when a locale is missing a key", () => {
  expectGuardrail({ locales: { es: { app: { name: "Bitcoin Lifeboat" } } } }, "i18n-missing-key");
});

test("fails when a locale has a dead key", () => {
  expectGuardrail(
    { locales: { fr: { ...baseLocale, stale: { key: "unused" } } } },
    "i18n-dead-key",
  );
});

test("fails when a Fluent locale is missing a key", () => {
  expectGuardrail(
    {
      ftl: {
        de: `errors-E-INPUT-001 =
    .title = Leere Eingabe
`,
      },
    },
    "i18n-fluent-missing-key",
  );
});

test("fails on hardcoded JSX text", () => {
  expectGuardrail(
    {
      files: {
        "src/Hardcoded.tsx": "export function Hardcoded() { return <p>Click this button</p>; }\n",
      },
    },
    "i18n-hardcoded-jsx-text",
  );
});

test("fails on hardcoded accessible labels", () => {
  expectGuardrail(
    {
      files: {
        "src/HardcodedLabel.tsx":
          'export function HardcodedLabel() { return <nav aria-label="Primary">x</nav>; }\n',
      },
    },
    "i18n-hardcoded-jsx-attribute",
  );
});

test("fails on overclaiming translation copy", () => {
  expectGuardrail(
    {
      locales: {
        en: { app: { name: "Bitcoin Lifeboat" }, nav: { home: "Your funds are safe." } },
      },
    },
    "i18n-no-safe-funds-claim",
  );
});
