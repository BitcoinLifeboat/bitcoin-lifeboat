#!/usr/bin/env node
// i18n guardrails for PRD §18.7 / Appendix D (US-097).
//
// Scope:
// - desktop i18next locale files must have identical key sets
// - Rust Fluent error catalogs must have identical message/attribute keys
// - translation strings are scanned for forbidden "funds are safe" style claims
// - obvious JSX text/label literals outside i18n files are rejected
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const here = dirname(fileURLToPath(import.meta.url));
const defaultAppRoot = join(here, "..");
const defaultRepoRoot = join(defaultAppRoot, "../..");

const LOCALES = ["en", "es", "de", "fr"];
const NON_ENGLISH_MINIMUM = 3;
const JSX_SOURCE_EXTENSIONS = new Set([".tsx"]);
const IGNORED_DIRS = new Set(["node_modules", "dist", "target", "test-results"]);
const USER_FACING_JSX_ATTRIBUTES = new Set([
  "aria-label",
  "aria-description",
  "title",
  "placeholder",
  "alt",
]);

const OVERCLAIM_PATTERNS = [
  {
    label: "en",
    regex:
      /\b(?:your\s+)?(?:funds|bitcoin|wallet|wallets)\s+(?:is|are|will be|remain|remains|stay|stays)\s+(?:safe|secure|protected|guaranteed)\b/i,
    allowed:
      /\b(?:never claim|does not mean|does not tell you|cannot guarantee|can't guarantee|no guarantee|not (?:a )?guarantee|not safe|not secure|not protected|not guaranteed)\b/i,
  },
  {
    label: "es",
    regex:
      /\b(?:fondos|bitcoin|billetera|billeteras|wallet|wallets|recuperaci[oó]n)\b.*\b(?:segur[oa]s?|protegidos?|garantizad[oa]s?)\b/i,
    allowed:
      /\b(?:nunca|no afirmamos|no garantiza|no puede garantizar|sin garant[ií]a|no es una garant[ií]a)\b/i,
  },
  {
    label: "de",
    regex:
      /\b(?:gelder|bitcoin|wallet|wallets|wiederherstellung)\b.*\b(?:sicher|gesch[uü]tzt|garantiert)\b/i,
    allowed: /\b(?:nie|nicht|keine garantie|nicht garantiert|kann nicht garantieren)\b/i,
  },
  {
    label: "fr",
    regex:
      /\b(?:fonds|bitcoin|portefeuille|portefeuilles|r[eé]cup[eé]ration)\b.*\b(?:en s[eé]curit[eé]|s[eé]curis[eé]s?|prot[eé]g[eé]s?|garantis?)\b/i,
    allowed:
      /\b(?:jamais|ne pr[eé]tendons|ne garantit pas|ne peut pas garantir|sans garantie|pas une garantie)\b/i,
  },
];

function readText(path) {
  return readFileSync(path, "utf8");
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function fileExtension(path) {
  const lastDot = path.lastIndexOf(".");
  return lastDot === -1 ? "" : path.slice(lastDot);
}

function rel(root, file) {
  return relative(root, file).replaceAll("\\", "/");
}

function addViolation(violations, guardrail, file, line, message) {
  violations.push({ guardrail, file, line, message });
}

function flattenJson(value, prefix = [], out = new Map()) {
  if (value == null || ["string", "number", "boolean"].includes(typeof value)) {
    out.set(prefix.join("."), value);
    return out;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => flattenJson(item, [...prefix, String(index)], out));
    return out;
  }
  for (const [key, child] of Object.entries(value)) {
    flattenJson(child, [...prefix, key], out);
  }
  return out;
}

function compareKeySets(baseKeys, candidateKeys) {
  const missing = [...baseKeys].filter((key) => !candidateKeys.has(key)).sort();
  const dead = [...candidateKeys].filter((key) => !baseKeys.has(key)).sort();
  return { missing, dead };
}

function checkDesktopLocaleParity(appRoot, violations) {
  const localeDir = join(appRoot, "src/i18n");
  const englishPath = join(localeDir, "en.json");
  if (!existsSync(englishPath)) {
    addViolation(violations, "i18n-locale", "src/i18n/en.json", null, "English locale is missing");
    return [];
  }

  const english = flattenJson(readJson(englishPath));
  const englishKeys = new Set(english.keys());
  const localeFiles = [];

  for (const locale of LOCALES) {
    const file = join(localeDir, `${locale}.json`);
    const fileRel = rel(appRoot, file);
    if (!existsSync(file)) {
      addViolation(violations, "i18n-locale", fileRel, null, `${locale}.json is missing`);
      continue;
    }
    localeFiles.push(file);
    const candidate = flattenJson(readJson(file));
    const { missing, dead } = compareKeySets(englishKeys, new Set(candidate.keys()));
    if (missing.length) {
      addViolation(
        violations,
        "i18n-missing-key",
        fileRel,
        null,
        `missing ${missing.length} key(s): ${missing.slice(0, 8).join(", ")}`,
      );
    }
    if (dead.length) {
      addViolation(
        violations,
        "i18n-dead-key",
        fileRel,
        null,
        `has ${dead.length} key(s) not present in en.json: ${dead.slice(0, 8).join(", ")}`,
      );
    }
  }

  if (LOCALES.filter((locale) => locale !== "en").length < NON_ENGLISH_MINIMUM) {
    addViolation(
      violations,
      "i18n-locale-count",
      "src/i18n",
      null,
      `at least ${NON_ENGLISH_MINIMUM} non-English locales are required`,
    );
  }

  return localeFiles;
}

function ftlKeys(source) {
  const keys = new Set();
  let currentMessage = null;
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const messageMatch = /^([A-Za-z][A-Za-z0-9_-]*)\s*=/.exec(line);
    if (messageMatch) {
      currentMessage = messageMatch[1];
      continue;
    }
    const attrMatch = /^\.([A-Za-z][A-Za-z0-9_-]*)\s*=/.exec(line);
    if (attrMatch && currentMessage) {
      keys.add(`${currentMessage}.${attrMatch[1]}`);
    }
  }
  return keys;
}

function ftlValues(source) {
  const values = [];
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    const attrMatch = /^\.([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.+)$/.exec(line);
    if (attrMatch) values.push(attrMatch[2]);
  }
  return values;
}

function checkRustFluentParity(repoRoot, violations) {
  const stringDir = join(repoRoot, "crates/error-taxonomy/strings");
  const englishPath = join(stringDir, "en.ftl");
  if (!existsSync(englishPath)) {
    addViolation(
      violations,
      "i18n-fluent",
      rel(repoRoot, englishPath),
      null,
      "English Fluent catalog is missing",
    );
    return [];
  }

  const englishKeys = ftlKeys(readText(englishPath));
  const files = [];
  for (const locale of LOCALES) {
    const file = join(stringDir, `${locale}.ftl`);
    const fileRel = rel(repoRoot, file);
    if (!existsSync(file)) {
      addViolation(violations, "i18n-fluent", fileRel, null, `${locale}.ftl is missing`);
      continue;
    }
    files.push(file);
    const keys = ftlKeys(readText(file));
    const { missing, dead } = compareKeySets(englishKeys, keys);
    if (missing.length) {
      addViolation(
        violations,
        "i18n-fluent-missing-key",
        fileRel,
        null,
        `missing ${missing.length} Fluent key(s): ${missing.slice(0, 8).join(", ")}`,
      );
    }
    if (dead.length) {
      addViolation(
        violations,
        "i18n-fluent-dead-key",
        fileRel,
        null,
        `has ${dead.length} Fluent key(s) not present in en.ftl: ${dead.slice(0, 8).join(", ")}`,
      );
    }
  }
  return files;
}

function collectJsonStrings(value, out = []) {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((item) => collectJsonStrings(item, out));
  } else if (value && typeof value === "object") {
    Object.values(value).forEach((child) => collectJsonStrings(child, out));
  }
  return out;
}

function checkOverclaims(appRoot, repoRoot, desktopLocaleFiles, rustFtlFiles, violations) {
  const candidates = [];
  for (const file of desktopLocaleFiles) {
    for (const value of collectJsonStrings(readJson(file))) {
      candidates.push({ file: rel(appRoot, file), value });
    }
  }
  for (const file of rustFtlFiles) {
    for (const value of ftlValues(readText(file))) {
      candidates.push({ file: rel(repoRoot, file), value });
    }
  }

  for (const { file, value } of candidates) {
    for (const pattern of OVERCLAIM_PATTERNS) {
      if (!pattern.regex.test(value)) continue;
      if (pattern.allowed.test(value)) continue;
      addViolation(
        violations,
        "i18n-no-safe-funds-claim",
        file,
        null,
        `translation copy (${pattern.label}) must not claim funds, wallets, or recovery are safe/secure/guaranteed: ${value}`,
      );
    }
  }
}

function collectTsxFiles(appRoot) {
  const sourceRoot = join(appRoot, "src");
  const files = [];
  const walk = (dir) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
      if (IGNORED_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (
        st.isFile() &&
        JSX_SOURCE_EXTENSIONS.has(fileExtension(full)) &&
        !full.endsWith(".test.tsx")
      ) {
        files.push(full);
      }
    }
  };
  walk(sourceRoot);
  return files.sort();
}

function hasHumanText(value) {
  return /[A-Za-zÀ-ÖØ-öø-ÿ]/.test(value);
}

function nodeLine(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function jsxAttributeLiteral(node) {
  if (!node.initializer) return null;
  if (ts.isStringLiteral(node.initializer)) return node.initializer.text;
  if (
    ts.isJsxExpression(node.initializer) &&
    node.initializer.expression &&
    ts.isStringLiteral(node.initializer.expression)
  ) {
    return node.initializer.expression.text;
  }
  return null;
}

function checkHardcodedJsx(appRoot, violations) {
  for (const file of collectTsxFiles(appRoot)) {
    const text = readText(file);
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const fileRel = rel(appRoot, file);

    const visit = (node) => {
      if (ts.isJsxText(node)) {
        const value = node.getText(source).replace(/\s+/g, " ").trim();
        if (hasHumanText(value)) {
          addViolation(
            violations,
            "i18n-hardcoded-jsx-text",
            fileRel,
            nodeLine(source, node),
            `JSX text must come from i18n: ${value}`,
          );
        }
      }

      if (ts.isJsxAttribute(node)) {
        const name = node.name.getText(source);
        const value = jsxAttributeLiteral(node);
        if (value && USER_FACING_JSX_ATTRIBUTES.has(name) && hasHumanText(value)) {
          addViolation(
            violations,
            "i18n-hardcoded-jsx-attribute",
            fileRel,
            nodeLine(source, node),
            `${name} must come from i18n: ${value}`,
          );
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(source);
  }
}

export function runI18nChecks({ appRoot = defaultAppRoot, repoRoot = defaultRepoRoot } = {}) {
  const violations = [];
  const desktopLocaleFiles = checkDesktopLocaleParity(appRoot, violations);
  const rustFtlFiles = checkRustFluentParity(repoRoot, violations);
  checkOverclaims(appRoot, repoRoot, desktopLocaleFiles, rustFtlFiles, violations);
  checkHardcodedJsx(appRoot, violations);
  return { appRoot, repoRoot, violations };
}

export function formatViolations(violations) {
  return violations
    .map((v) => {
      const loc = v.line == null ? v.file : `${v.file}:${v.line}`;
      return `  XX  [${v.guardrail}] ${loc} - ${v.message}`;
    })
    .join("\n");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = runI18nChecks();
  if (result.violations.length) {
    console.error(`FAILED ${result.violations.length} i18n guardrail check(s):`);
    console.error(formatViolations(result.violations));
    process.exit(1);
  }

  console.log(
    `All i18n guardrails passed (${LOCALES.length} desktop locales, ${LOCALES.length} Rust Fluent catalogs, hardcoded JSX text scan, and translation overclaim scan).`,
  );
}
