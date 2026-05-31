# docs-site agent notes

This package is a static Astro Starlight site. The source of truth for page prose is the
root `docs/` directory. Run `npm run sync` to regenerate Starlight content into
`src/content/docs/`; never edit generated files directly.

`astro.config.mjs` and the sync script read `../../project.config.toml`. Keep the site URL,
GitHub repository URL, CNAME, docs framework, and docs host config-driven. Do not hardcode
the public domain or GitHub org in site code.

The Alpha/Beta release banner is generated during `npm run sync` from
`project.config.toml release.channel_default`, with `LIFEBOAT_RELEASE_CHANNEL`
as the release-workflow override. Keep the banner in generated frontmatter; do
not hand-edit files under `src/content/docs/`.

Quality gates for this package:

```sh
npm run typecheck
npm run build
```

`npm run build` includes an internal-link check over `dist/**/*.html`. Root Markdown links
to other published docs are rewritten to site routes during sync; links to `PRD-v2.md` are
rewritten to the configured GitHub source URL because the full PRD is not published as a
Starlight page.

Starlight normalizes dots out of generated page slugs. If a root doc filename includes a
version like `acceptance-v0.1.md`, keep the source filename in `docs/` but choose a
dot-free generated output filename in `scripts/sync-docs.mjs` (for example
`acceptance-v01.md`) so rewritten links match the built route.

Recovery Day launch-kit pages are root `docs/recovery-day-*.md` files. When adding or
renaming one, update `scripts/sync-docs.mjs`, `astro.config.mjs`, and
`scripts/verify-launch-kit.mjs` together; `npm run build` asserts that every kit page
is generated, linked from `/recovery-day/`, and present in the built static site.
