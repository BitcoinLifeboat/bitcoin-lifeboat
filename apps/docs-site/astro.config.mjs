import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

import { getGithubRepoUrl, getSiteUrl, loadProjectConfig } from './src/project-config.mjs';

const projectConfig = loadProjectConfig();

export default defineConfig({
  output: 'static',
  site: getSiteUrl(projectConfig),
  integrations: [
    starlight({
      title: 'Bitcoin Lifeboat',
      description:
        'Local-first documentation for checking Bitcoin recovery readiness without seed entry or automatic network calls.',
      customCss: ['./src/styles/starlight.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub repository',
          href: getGithubRepoUrl(projectConfig),
        },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { slug: 'mission' },
            { slug: 'safety-model' },
            { slug: 'user-guide' },
            { slug: 'download-verify-signature' },
            { slug: 'wallet-compatibility' },
          ],
        },
        {
          label: 'Recovery readiness',
          items: [
            { slug: 'descriptor-audit' },
            { slug: 'scoring' },
            { slug: 'heir-mode' },
            { slug: 'multisig-liana-drills' },
            { slug: 'recovery-day' },
            { slug: 'recovery-day-workshop-slide-deck' },
            { slug: 'recovery-day-organizer-guide' },
            { slug: 'recovery-day-live-demo-descriptors' },
            { slug: 'recovery-day-heir-drill-packet-template' },
            { slug: 'recovery-day-press-kit' },
          ],
        },
        {
          label: 'Developer guide',
          items: [
            { slug: 'developer-guide' },
            { slug: 'architecture' },
            { slug: 'cli-reference' },
            { slug: 'json-schemas' },
            { slug: 'error-codes' },
            { slug: 'threat-model' },
            { slug: 'reproducible-builds' },
            { slug: 'security-audit' },
            { slug: 'configuration' },
          ],
        },
      ],
    }),
  ],
});
