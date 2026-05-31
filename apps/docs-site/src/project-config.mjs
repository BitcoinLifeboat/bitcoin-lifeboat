import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const docsSiteDir = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
export const repoRoot = path.resolve(docsSiteDir, '../..');
export const projectConfigPath = path.join(repoRoot, 'project.config.toml');

export function loadProjectConfig() {
  const toml = fs.readFileSync(projectConfigPath, 'utf8');

  return {
    github: {
      org: readTomlString(toml, 'github', 'org'),
      repo: readTomlString(toml, 'github', 'repo'),
      urlBase: readTomlString(toml, 'github', 'url_base'),
    },
    site: {
      domain: readTomlString(toml, 'site', 'domain'),
    },
    docs: {
      framework: readTomlString(toml, 'docs', 'framework'),
      host: readTomlString(toml, 'docs', 'host'),
    },
    release: {
      channelDefault: readTomlString(toml, 'release', 'channel_default'),
    },
  };
}

export function getSiteUrl(config) {
  const domain = config.site.domain.trim();
  if (!domain) {
    throw new Error('project.config.toml site.domain must not be empty');
  }
  return domain.startsWith('http://') || domain.startsWith('https://')
    ? domain
    : `https://${domain}`;
}

export function getCname(config) {
  return getSiteUrl(config).replace(/^https?:\/\//, '').replace(/\/$/, '');
}

export function getGithubRepoUrl(config) {
  if (!config.github.urlBase.startsWith('https://')) {
    throw new Error('project.config.toml github.url_base must be an https URL');
  }
  return config.github.urlBase;
}

function readTomlString(toml, section, key) {
  const sectionPattern = new RegExp(`(?:^|\\n)\\[${escapeRegExp(section)}\\]\\n([\\s\\S]*?)(?=\\n\\[|$)`);
  const sectionMatch = toml.match(sectionPattern);
  if (!sectionMatch) {
    throw new Error(`project.config.toml is missing [${section}]`);
  }

  const keyPattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*=\\s*"([^"]*)"\\s*$`, 'm');
  const keyMatch = sectionMatch[1].match(keyPattern);
  if (!keyMatch) {
    throw new Error(`project.config.toml is missing ${section}.${key}`);
  }

  return keyMatch[1];
}

function escapeRegExp(input) {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
