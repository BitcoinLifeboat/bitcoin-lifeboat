#!/usr/bin/env node
// Frontend guardrails for PRD §27 anti-acceptance items 41, 42, 44, 46, 47, 48.
// This scanner is intentionally dependency-free so it can run before install-time
// lint tooling exists and inside the Tauri beforeBuildCommand.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const defaultRoot = join(here, "..");

const SOURCE_DIRS = ["src", "e2e"];
const ROOT_SOURCE_FILES = [
  "index.html",
  "vite.config.ts",
  "playwright.config.ts",
  "tailwind.config.js",
  "postcss.config.js",
];
const SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".html",
  ".md",
  ".css",
]);
const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "target",
  "test-results",
  "playwright-report",
]);

const CRYPTO_MODULES = [
  /^bitcoinjs-lib(?:\/|$)/,
  /^@scure\/btc-signer(?:\/|$)/,
  /^@scure\//,
  /^@noble\//,
  /^crypto$/,
  /^node:crypto$/,
  /^crypto-js(?:\/|$)/,
  /^bip3[29](?:\/|$)/,
  /^bip39(?:\/|$)/,
  /^tiny-secp256k1(?:\/|$)/,
  /^secp256k1(?:\/|$)/,
  /^elliptic(?:\/|$)/,
  /^ecpair(?:\/|$)/,
  /^ethers(?:\/|$)/,
  /^viem(?:\/|$)/,
  /^web3(?:\/|$)/,
];

const ANALYTICS_MODULES = [
  /^analytics(?:\/|$)/,
  /^@segment\//,
  /^posthog-js(?:\/|$)/,
  /^mixpanel-browser(?:\/|$)/,
  /^amplitude-js(?:\/|$)/,
  /^@amplitude\//,
  /^plausible-tracker(?:\/|$)/,
  /^react-ga(?:\/|$)/,
  /^react-ga4(?:\/|$)/,
  /^gtag(?:\.js)?(?:\/|$)/,
  /^hotjar(?:\/|$)/,
  /^@hotjar\//,
  /^@sentry\//,
  /^firebase\/analytics(?:\/|$)/,
  /^@firebase\/analytics(?:\/|$)/,
  /^rudder-sdk-js(?:\/|$)/,
  /^@datadog\//,
  /^newrelic(?:\/|$)/,
  /^logrocket(?:\/|$)/,
  /^fullstory(?:\/|$)/,
];

const UPDATER_MODULES = [
  /^@tauri-apps\/plugin-updater(?:\/|$)/,
  /^tauri-plugin-updater(?:\/|$)/,
];

const IMPORT_PATTERNS = [
  /\bimport\s+(?:type\s+)?(?:[^'"]*?\s+from\s*)?["']([^"']+)["']/g,
  /\bexport\s+(?:type\s+)?[^'"]*?\s+from\s*["']([^"']+)["']/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
];

const DYNAMIC_CODE_PATTERNS = [
  { label: "eval()", regex: /\beval\s*\(/g },
  { label: "new Function()", regex: /\bnew\s+Function\s*\(/g },
  { label: "setTimeout(string)", regex: /(?:^|[^\w.$])(?:window\.|globalThis\.)?setTimeout\s*\(\s*["'`]/gm },
  { label: "setInterval(string)", regex: /(?:^|[^\w.$])(?:window\.|globalThis\.)?setInterval\s*\(\s*["'`]/gm },
];

const BARE_FUNCTION_REGEX = /(?:^|[^\w.$])Function\s*\(/gm;
const WEB_STORAGE_WRITE_REGEX =
  /\b(?:window\.|globalThis\.)?(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(/g;

const ANALYTICS_USAGE_PATTERNS = [
  { label: "gtag()", regex: /\bgtag\s*\(/g },
  { label: "dataLayer.push()", regex: /\bdataLayer\s*\.\s*push\s*\(/g },
  { label: "analytics.track()", regex: /\banalytics\s*\.\s*track\s*\(/g },
  { label: "posthog.capture()", regex: /\bposthog\s*\.\s*capture\s*\(/g },
  { label: "mixpanel.track()", regex: /\bmixpanel\s*\.\s*track\s*\(/g },
  { label: "amplitude.track()", regex: /\bamplitude\s*\.\s*track\s*\(/g },
  { label: "Sentry.init()", regex: /\bSentry\s*\.\s*init\s*\(/g },
  { label: "plausible()", regex: /\bplausible\s*\(/g },
];

const OVERCLAIM_PATTERNS = [
  /\b(?:your\s+)?(?:funds|bitcoin|wallet|wallets)\s+(?:is|are|will be|remain|remains|stay|stays)\s+(?:safe|secure|protected|guaranteed)\b/i,
  /\b(?:safe|secure|protected|guaranteed)\s+(?:funds|bitcoin|wallet|wallets)\b/i,
  /\b(?:recovery|recovery plan)\s+(?:is|will be)\s+guaranteed\b/i,
];

const ALLOWED_OVERCLAIM_CONTEXTS = [
  /\bnever claim\b/i,
  /\bdoes not mean\b/i,
  /\bdoes\s+\*\*not\*\*\s+tell you\b/i,
  /\bdoes not tell you\b/i,
  /\bnot\s+(?:safe|secure|protected|guaranteed)\b/i,
  /\bcannot guarantee\b/i,
  /\bcan't guarantee\b/i,
  /\bno guarantee\b/i,
  /\bnot (?:a )?guarantee\b/i,
];

const packageSections = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

function fileExtension(path) {
  const lastDot = path.lastIndexOf(".");
  return lastDot === -1 ? "" : path.slice(lastDot);
}

function readText(path) {
  return readFileSync(path, "utf8");
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function rel(root, file) {
  return relative(root, file).replaceAll("\\", "/");
}

function lineNumber(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function addViolation(violations, guardrail, file, line, message) {
  violations.push({ guardrail, file, line, message });
}

function collectFiles(root) {
  const out = [];
  const walk = (dir) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
      if (IGNORED_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (st.isFile() && SOURCE_EXTENSIONS.has(fileExtension(full))) {
        out.push(full);
      }
    }
  };

  for (const dir of SOURCE_DIRS) walk(join(root, dir));
  for (const file of ROOT_SOURCE_FILES) {
    const full = join(root, file);
    if (existsSync(full)) out.push(full);
  }
  return [...new Set(out)].sort();
}

function packageEntries(packageJson) {
  const entries = [];
  for (const section of packageSections) {
    const deps = packageJson[section];
    if (!deps || typeof deps !== "object") continue;
    for (const name of Object.keys(deps)) entries.push({ section, name });
  }
  return entries;
}

function matchesAny(value, patterns) {
  return patterns.some((pattern) => pattern.test(value));
}

function classifyForbiddenModule(moduleName) {
  if (matchesAny(moduleName, CRYPTO_MODULES)) {
    return {
      guardrail: "frontend-forbidden-crypto",
      message: `frontend imports forbidden crypto/Bitcoin module "${moduleName}"`,
    };
  }
  if (matchesAny(moduleName, ANALYTICS_MODULES)) {
    return {
      guardrail: "frontend-no-analytics",
      message: `frontend imports forbidden analytics SDK "${moduleName}"`,
    };
  }
  if (matchesAny(moduleName, UPDATER_MODULES)) {
    return {
      guardrail: "tauri-no-updater",
      message: `frontend imports forbidden Tauri updater module "${moduleName}"`,
    };
  }
  return null;
}

function checkPackageDependencies(root, violations) {
  const packagePath = join(root, "package.json");
  if (!existsSync(packagePath)) {
    addViolation(
      violations,
      "frontend-package",
      "package.json",
      null,
      "package.json is missing; guardrails cannot verify frontend dependencies",
    );
    return;
  }

  const packageJson = readJson(packagePath);
  for (const { section, name } of packageEntries(packageJson)) {
    const classification = classifyForbiddenModule(name);
    if (!classification) continue;
    addViolation(
      violations,
      classification.guardrail,
      "package.json",
      null,
      `${section} contains ${classification.message.replace("frontend imports ", "")}`,
    );
  }
}

function checkImports(root, files, violations) {
  for (const file of files) {
    const text = readText(file);
    const fileRel = rel(root, file);
    for (const pattern of IMPORT_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const moduleName = match[1];
        const classification = classifyForbiddenModule(moduleName);
        if (!classification) continue;
        addViolation(
          violations,
          classification.guardrail,
          fileRel,
          lineNumber(text, match.index),
          classification.message,
        );
      }
    }
  }
}

function checkDynamicCode(root, files, violations) {
  for (const file of files) {
    const text = readText(file);
    const fileRel = rel(root, file);
    for (const { label, regex } of DYNAMIC_CODE_PATTERNS) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(text)) !== null) {
        addViolation(
          violations,
          "frontend-no-dynamic-code",
          fileRel,
          lineNumber(text, match.index),
          `${label} is forbidden in the frontend`,
        );
      }
    }

    BARE_FUNCTION_REGEX.lastIndex = 0;
    let match;
    while ((match = BARE_FUNCTION_REGEX.exec(text)) !== null) {
      const index = match.index + match[0].indexOf("Function");
      const before = text.slice(Math.max(0, index - 8), index);
      if (/\bnew\s+$/.test(before)) continue;
      addViolation(
        violations,
        "frontend-no-dynamic-code",
        fileRel,
        lineNumber(text, index),
        "Function() is forbidden in the frontend",
      );
    }
  }
}

function checkWebStorage(root, files, violations) {
  for (const file of files) {
    const text = readText(file);
    const fileRel = rel(root, file);
    WEB_STORAGE_WRITE_REGEX.lastIndex = 0;
    let match;
    while ((match = WEB_STORAGE_WRITE_REGEX.exec(text)) !== null) {
      addViolation(
        violations,
        "frontend-no-confidential-web-storage",
        fileRel,
        lineNumber(text, match.index),
        "web storage writes are forbidden; Confidential data stays in memory and Public prefs use the Tauri settings file",
      );
    }
  }
}

function lineIsAllowedOverclaim(line) {
  return ALLOWED_OVERCLAIM_CONTEXTS.some((pattern) => pattern.test(line));
}

function checkOverclaims(root, files, violations) {
  for (const file of files) {
    const text = readText(file);
    const fileRel = rel(root, file);
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (!OVERCLAIM_PATTERNS.some((pattern) => pattern.test(line))) return;
      if (lineIsAllowedOverclaim(line)) return;
      addViolation(
        violations,
        "frontend-no-safe-funds-claim",
        fileRel,
        index + 1,
        'frontend copy must not claim user funds, wallets, or recovery are "safe", "secure", or guaranteed',
      );
    });
  }
}

function checkAnalyticsUsage(root, files, violations) {
  for (const file of files) {
    const text = readText(file);
    const fileRel = rel(root, file);
    for (const { label, regex } of ANALYTICS_USAGE_PATTERNS) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(text)) !== null) {
        addViolation(
          violations,
          "frontend-no-analytics",
          fileRel,
          lineNumber(text, match.index),
          `${label} is forbidden; the app ships with no analytics SDK or tracking snippet`,
        );
      }
    }
  }
}

function checkTauriUpdater(root, violations) {
  const confPath = join(root, "src-tauri", "tauri.conf.json");
  if (existsSync(confPath)) {
    const confText = readText(confPath);
    const conf = JSON.parse(confText);
    if (conf?.plugins && Object.prototype.hasOwnProperty.call(conf.plugins, "updater")) {
      addViolation(
        violations,
        "tauri-no-updater",
        "src-tauri/tauri.conf.json",
        null,
        "tauri.conf.json must not contain plugins.updater",
      );
    }
    if (/\bupdater\b/i.test(confText)) {
      addViolation(
        violations,
        "tauri-no-updater",
        "src-tauri/tauri.conf.json",
        null,
        "tauri.conf.json must not mention updater",
      );
    }
  } else {
    addViolation(
      violations,
      "tauri-no-updater",
      "src-tauri/tauri.conf.json",
      null,
      "tauri.conf.json is missing; guardrails cannot verify updater posture",
    );
  }

  const cargoPath = join(root, "src-tauri", "Cargo.toml");
  if (existsSync(cargoPath)) {
    const cargoText = readText(cargoPath);
    if (/tauri-plugin-updater/i.test(cargoText)) {
      addViolation(
        violations,
        "tauri-no-updater",
        "src-tauri/Cargo.toml",
        null,
        "src-tauri/Cargo.toml must not depend on tauri-plugin-updater",
      );
    }
  } else {
    addViolation(
      violations,
      "tauri-no-updater",
      "src-tauri/Cargo.toml",
      null,
      "src-tauri/Cargo.toml is missing; guardrails cannot verify updater dependencies",
    );
  }
}

export function runGuardrails({ root = defaultRoot } = {}) {
  const files = collectFiles(root);
  const violations = [];

  checkPackageDependencies(root, violations);
  checkImports(root, files, violations);
  checkDynamicCode(root, files, violations);
  checkWebStorage(root, files, violations);
  checkOverclaims(root, files, violations);
  checkAnalyticsUsage(root, files, violations);
  checkTauriUpdater(root, violations);

  return { root, files, violations };
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
  const result = runGuardrails();
  if (result.violations.length) {
    console.error(`FAILED ${result.violations.length} frontend guardrail check(s):`);
    console.error(formatViolations(result.violations));
    process.exit(1);
  }

  console.log(
    `All frontend guardrails passed (${result.files.length} files scanned; crypto imports, dynamic code, web storage writes, overclaim copy, analytics, and updater checks).`,
  );
}
