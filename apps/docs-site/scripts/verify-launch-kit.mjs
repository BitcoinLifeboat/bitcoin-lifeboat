import fs from 'node:fs/promises';
import path from 'node:path';

import { repoRoot } from '../src/project-config.mjs';

const docsSiteDir = path.join(repoRoot, 'apps/docs-site');
const docsDir = path.join(repoRoot, 'docs');
const generatedDocsDir = path.join(docsSiteDir, 'src/content/docs');
const distDir = path.join(docsSiteDir, 'dist');

const canonicalNotWallet =
  'Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase manager, not an inheritance legal service, and not a recovery company. It is a free, open-source diagnostic tool that helps you test whether your recovery plan works.';

const kitDocs = [
  {
    source: 'recovery-day.md',
    route: 'recovery-day',
    required: ['Workshop slide deck', 'Meetup organizer guide', 'Press kit'],
  },
  {
    source: 'recovery-day-workshop-slide-deck.md',
    route: 'recovery-day-workshop-slide-deck',
    required: ['Once a year, run a recovery drill.', canonicalNotWallet],
  },
  {
    source: 'recovery-day-organizer-guide.md',
    route: 'recovery-day-organizer-guide',
    required: ['Room Setup', 'If Someone Pastes A Real Secret'],
  },
  {
    source: 'recovery-day-live-demo-descriptors.md',
    route: 'recovery-day-live-demo-descriptors',
    required: ['wpkh([71348c8a', 'wsh(sortedmulti(2', 'liana_basic.txt'],
  },
  {
    source: 'recovery-day-heir-drill-packet-template.md',
    route: 'recovery-day-heir-drill-packet-template',
    required: ['contains_real_user_material', 'includes_disposable_private_material'],
  },
  {
    source: 'recovery-day-press-kit.md',
    route: 'recovery-day-press-kit',
    required: ['One-Sentence Description', canonicalNotWallet, 'project.config.toml'],
  },
];

const failures = [];

for (const doc of kitDocs) {
  const sourcePath = path.join(docsDir, doc.source);
  const generatedPath = path.join(generatedDocsDir, doc.source);
  const routePath = path.join(distDir, doc.route, 'index.html');

  await assertFile(sourcePath, `docs/${doc.source}`);
  await assertFile(generatedPath, `generated docs page ${doc.source}`);
  await assertFile(routePath, `built route /${doc.route}/`);

  const source = await readOptional(sourcePath);
  for (const expected of doc.required) {
    if (!includesText(source, expected)) {
      failures.push(`docs/${doc.source} is missing required launch-kit text: ${expected}`);
    }
  }
}

const recoveryDay = await readOptional(path.join(docsDir, 'recovery-day.md'));
for (const doc of kitDocs.slice(1)) {
  const link = `](${doc.source})`;
  if (!recoveryDay.includes(link)) {
    failures.push(`docs/recovery-day.md does not link to ${doc.source}`);
  }
}

const homeHtml = await readOptional(path.join(distDir, 'index.html'));
for (const expected of [canonicalNotWallet, '/download-verify-signature/', '/recovery-day/']) {
  if (!includesText(homeHtml, expected)) {
    failures.push(`built homepage is missing ${expected}`);
  }
}

const releaseGate = await readOptional(path.join(repoRoot, 'scripts/verify-release-gates.sh'));
if (!releaseGate.includes('verify_no_placeholders')) {
  failures.push('scripts/verify-release-gates.sh no longer exposes the placeholder-token release gate');
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`Verified ${kitDocs.length} Recovery Day launch-kit pages and homepage launch links.`);

async function assertFile(file, label) {
  try {
    const stat = await fs.stat(file);
    if (!stat.isFile()) {
      failures.push(`${label} exists but is not a file`);
    }
  } catch {
    failures.push(`${label} is missing`);
  }
}

async function readOptional(file) {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return '';
  }
}

function includesText(haystack, needle) {
  return normalizeWhitespace(haystack).includes(normalizeWhitespace(needle));
}

function normalizeWhitespace(value) {
  return value.replace(/\s+/g, ' ').trim();
}
