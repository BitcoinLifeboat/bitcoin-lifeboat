import fs from 'node:fs/promises';
import path from 'node:path';

import {
  getCname,
  getGithubRepoUrl,
  loadProjectConfig,
  repoRoot,
} from '../src/project-config.mjs';

const canonicalNotWallet =
  'Bitcoin Lifeboat is not a wallet, not a custody service, not a seed phrase manager, not an inheritance legal service, and not a recovery company. It is a free, open-source diagnostic tool that helps you test whether your recovery plan works.';

const docs = [
  {
    source: 'README.md',
    output: 'index.md',
    title: 'Bitcoin Lifeboat Documentation',
    description: 'Read the Bitcoin Lifeboat mission, safety model, user guide, and developer reference.',
    home: true,
  },
  {
    source: 'mission.md',
    output: 'mission.md',
    title: 'Mission',
    description: 'What Bitcoin Lifeboat is, what it is not, and the four public promises.',
  },
  {
    source: 'safety-model.md',
    output: 'safety-model.md',
    title: 'Safety Model',
    description: 'What Lifeboat accepts, what it refuses, and what to do after accidental secret entry.',
  },
  {
    source: 'user-guide.md',
    output: 'user-guide.md',
    title: 'User Guide',
    description: 'Run a readiness check, create a runbook, and export public-safe reports.',
  },
  {
    source: 'download-verify-signature.md',
    output: 'download-verify-signature.md',
    title: 'Download and Verify Signatures',
    description: 'Download releases from official channels and verify signatures before running them.',
  },
  {
    source: 'wallet-compatibility.md',
    output: 'wallet-compatibility.md',
    title: 'Wallet Compatibility',
    description: 'Supported wallet exports, tier definitions, and contributor notes.',
  },
  {
    source: 'descriptor-audit.md',
    output: 'descriptor-audit.md',
    title: 'Descriptor Audit',
    description: 'How descriptors, xpubs, checksums, and known-address matching are analyzed.',
  },
  {
    source: 'scoring.md',
    output: 'scoring.md',
    title: 'Scoring',
    description: 'Readiness statuses, score weights, critical failures, and warnings.',
  },
  {
    source: 'heir-mode.md',
    output: 'heir-mode.md',
    title: 'Heir Mode',
    description: 'Owner-created runbooks for family, executors, and trusted helpers.',
  },
  {
    source: 'practice-seeds.md',
    output: 'practice-seeds.md',
    title: 'Practice Seeds',
    description: 'The documented test mnemonic accepted by Practice Mode.',
  },
  {
    source: 'psbt-drills.md',
    output: 'psbt-drills.md',
    title: 'PSBT Drills',
    description: 'Inspect, validate, and rehearse PSBT flows without handling real seed material.',
  },
  {
    source: 'hardware-wallet-drill.md',
    output: 'hardware-wallet-drill.md',
    title: 'Hardware Wallet Drill',
    description: 'Rehearse file, QR, and HWI hardware-wallet signing paths with fake funds.',
  },
  {
    source: 'signet-practice.md',
    output: 'signet-practice.md',
    title: 'Signet Practice',
    description: 'Use Signet practice flows with explicit network boundaries and local PSBT checks.',
  },
  {
    source: 'multisig-liana-drills.md',
    output: 'multisig-liana-drills.md',
    title: 'Multisig and Liana Drills',
    description: 'Survivability drills, missing-signer rehearsals, Liana recovery trees, and timelock runbooks.',
  },
  {
    source: 'recovery-day.md',
    output: 'recovery-day.md',
    title: 'Bitcoin Recovery Day',
    description: 'Community materials and workshop guidance for recovery-readiness education.',
  },
  {
    source: 'recovery-day-workshop-slide-deck.md',
    output: 'recovery-day-workshop-slide-deck.md',
    title: 'Recovery Day Workshop Slide Deck',
    description: 'A facilitator-ready slide outline for a Bitcoin Recovery Day meetup or workshop.',
  },
  {
    source: 'recovery-day-organizer-guide.md',
    output: 'recovery-day-organizer-guide.md',
    title: 'Recovery Day Organizer Guide',
    description: 'Room setup, volunteer roles, privacy boundaries, and event follow-up for organizers.',
  },
  {
    source: 'recovery-day-live-demo-descriptors.md',
    output: 'recovery-day-live-demo-descriptors.md',
    title: 'Recovery Day Live Demo Descriptors',
    description: 'Testnet-only descriptors and addresses for public demos.',
  },
  {
    source: 'recovery-day-heir-drill-packet-template.md',
    output: 'recovery-day-heir-drill-packet-template.md',
    title: 'Recovery Day Heir Drill Packet Template',
    description: 'A disposable test-wallet packet outline for heir and family practice drills.',
  },
  {
    source: 'recovery-day-press-kit.md',
    output: 'recovery-day-press-kit.md',
    title: 'Recovery Day Press Kit',
    description: 'Short descriptions, event copy, official-link guidance, and publishing boundaries.',
  },
  {
    source: 'developer-guide.md',
    output: 'developer-guide.md',
    title: 'Developer Guide',
    description: 'Build from source, add fixtures, add wallet compatibility, and contribute changes.',
  },
  {
    source: 'architecture.md',
    output: 'architecture.md',
    title: 'Architecture',
    description: 'The local-first architecture, crate boundaries, and desktop command surface.',
  },
  {
    source: 'cli-reference.md',
    output: 'cli-reference.md',
    title: 'CLI Reference',
    description: 'Command-line usage for parsing descriptors, scoring readiness, and exporting artifacts.',
  },
  {
    source: 'json-schemas.md',
    output: 'json-schemas.md',
    title: 'JSON Schemas',
    description: 'Stable JSON shapes used by reports, runbooks, and drill records.',
  },
  {
    source: 'error-codes.md',
    output: 'error-codes.md',
    title: 'Error Codes',
    description: 'The stable error vocabulary returned by Lifeboat commands.',
  },
  {
    source: 'threat-model.md',
    output: 'threat-model.md',
    title: 'Threat Model',
    description: 'Threats Lifeboat handles, reduces, or explicitly does not cover.',
  },
  {
    source: 'reproducible-builds.md',
    output: 'reproducible-builds.md',
    title: 'Reproducible Builds',
    description: 'The roadmap and verification model for reproducible release artifacts.',
  },
  {
    source: 'security-audit.md',
    output: 'security-audit.md',
    title: 'Security Audit',
    description: 'The external audit scope, sign-off requirements, and stable release gate.',
  },
  {
    source: 'acceptance-v0.1.md',
    output: 'acceptance-v01.md',
    title: 'v0.1 MVP Acceptance Verification',
    description: 'Evidence mapping for the v0.1 MVP functional, documentation, release, and anti-acceptance gates.',
  },
  {
    source: 'CONFIGURATION.md',
    output: 'configuration.md',
    title: 'Configuration',
    description: 'Project configuration values, placeholders, and the replacement procedure.',
  },
];

const config = loadProjectConfig();
if (config.docs.framework !== 'astro-starlight') {
  throw new Error(
    `US-060 docs site expects project.config.toml docs.framework = "astro-starlight", got "${config.docs.framework}"`,
  );
}
if (config.docs.host !== 'github-pages') {
  throw new Error(
    `US-060 docs workflow expects project.config.toml docs.host = "github-pages", got "${config.docs.host}"`,
  );
}
const releaseChannel = getReleaseChannel(config);
const releaseBanner = releaseBannerContent(releaseChannel);

const docsDir = path.join(repoRoot, 'docs');
const outputDir = path.join(repoRoot, 'apps/docs-site/src/content/docs');
const publicDir = path.join(repoRoot, 'apps/docs-site/public');
const bySource = new Map(docs.map((doc) => [doc.source, doc]));

await fs.rm(outputDir, { recursive: true, force: true });
await fs.mkdir(outputDir, { recursive: true });
await fs.mkdir(publicDir, { recursive: true });
await fs.writeFile(path.join(publicDir, 'CNAME'), `${getCname(config)}\n`);

for (const doc of docs) {
  const sourcePath = path.join(docsDir, doc.source);
  const source = await fs.readFile(sourcePath, 'utf8');
  const body = transformMarkdownLinks(stripFirstHeading(source), doc.source);
  const generated = `${renderFrontmatter(doc)}\n<!-- Generated from docs/${doc.source} by apps/docs-site/scripts/sync-docs.mjs. Do not edit. -->\n\n${body.trim()}\n`;
  await fs.writeFile(path.join(outputDir, doc.output), generated);
}

function renderFrontmatter(doc) {
  const lines = ['---', `title: ${yamlString(doc.title)}`, `description: ${yamlString(doc.description)}`];

  if (releaseBanner) {
    lines.push('banner:');
    lines.push(`  content: ${yamlString(releaseBanner)}`);
  }

  if (doc.home) {
    lines.push('template: splash');
    lines.push('hero:');
    lines.push('  title: Bitcoin Lifeboat');
    lines.push(`  tagline: ${yamlString(canonicalNotWallet)}`);
    lines.push('  image:');
    lines.push('    file: ../../assets/recovery-readiness-map.png');
    lines.push('    alt: A local recovery-readiness map with a lifeboat route, checklist markers, and offline documents.');
    lines.push('  actions:');
    lines.push('    - text: Start with the safety model');
    lines.push('      link: /safety-model/');
    lines.push('      icon: right-arrow');
    lines.push('    - text: Verify a download');
    lines.push('      link: /download-verify-signature/');
    lines.push('      icon: external');
    lines.push('      variant: minimal');
    lines.push('    - text: Recovery Day kit');
    lines.push('      link: /recovery-day/');
    lines.push('      icon: right-arrow');
    lines.push('      variant: minimal');
  }

  lines.push('---');
  return lines.join('\n');
}

function getReleaseChannel(config) {
  const channel = (process.env.LIFEBOAT_RELEASE_CHANNEL || config.release.channelDefault).trim().toLowerCase();
  if (!['alpha', 'beta', 'stable'].includes(channel)) {
    throw new Error(`release channel must be alpha, beta, or stable; got "${channel}"`);
  }
  return channel;
}

function releaseBannerContent(channel) {
  if (channel === 'alpha') {
    return 'Alpha build: for testing only. Verify the download before running it, and do not rely on this build for emergency recovery.';
  }
  if (channel === 'beta') {
    return 'Beta build: for community testing. Verify the download before running it, and rehearse recovery before depending on the release.';
  }
  return null;
}

function stripFirstHeading(markdown) {
  return markdown.replace(/^# .*(?:\r?\n){1,2}/, '');
}

function transformMarkdownLinks(markdown, sourceName) {
  return markdown.replace(/\]\(([^)]+)\)/g, (match, target) => {
    if (!isRelativeMarkdownLink(target)) {
      return match;
    }

    const [targetPath, anchor = ''] = target.split('#');
    const normalized = targetPath.replace(/^docs\//, '');
    const mapped = bySource.get(normalized);

    if (mapped) {
      const route = mapped.output === 'index.md' ? '/' : `/${mapped.output.replace(/\.md$/, '')}/`;
      return `](${route}${anchor ? `#${anchor}` : ''})`;
    }

    if (normalized === 'PRD-v2.md') {
      return `](${getGithubRepoUrl(config)}/blob/main/docs/PRD-v2.md${anchor ? `#${anchor}` : ''})`;
    }

    throw new Error(`docs/${sourceName} links to docs/${normalized}, but that file is not published by the docs site`);
  });
}

function isRelativeMarkdownLink(target) {
  const [targetPath] = target.split('#');
  return (
    targetPath.endsWith('.md') &&
    !targetPath.startsWith('http://') &&
    !targetPath.startsWith('https://') &&
    !targetPath.startsWith('mailto:')
  );
}

function yamlString(value) {
  return JSON.stringify(value);
}
