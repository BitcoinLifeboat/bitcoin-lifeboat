import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const docsSiteDir = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const distDir = path.join(docsSiteDir, 'dist');
const htmlFiles = await walk(distDir, (file) => file.endsWith('.html'));
const routes = new Set(htmlFiles.map((file) => routeForHtml(file)));
const failures = [];

for (const file of htmlFiles) {
  const html = await fs.readFile(file, 'utf8');
  const currentRoute = routeForHtml(file);

  for (const href of anchorHrefs(html)) {
    if (shouldSkip(href)) {
      continue;
    }

    const url = new URL(href, `https://docs.local${currentRoute}`);
    if (url.origin !== 'https://docs.local') {
      continue;
    }

    if (href.includes('.md')) {
      failures.push(`${currentRoute} links to Markdown source path ${href}`);
      continue;
    }

    const pathname = decodeURIComponent(url.pathname);
    if (path.extname(pathname)) {
      const assetPath = path.join(distDir, pathname);
      if (!(await exists(assetPath))) {
        failures.push(`${currentRoute} links to missing asset ${href}`);
      }
      continue;
    }

    const route = pathname.endsWith('/') ? pathname : `${pathname}/`;
    if (!routes.has(route)) {
      failures.push(`${currentRoute} links to missing page ${href}`);
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`Checked ${htmlFiles.length} HTML files for internal links.`);

async function walk(dir, predicate) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(fullPath, predicate)));
    } else if (predicate(fullPath)) {
      files.push(fullPath);
    }
  }

  return files;
}

function routeForHtml(file) {
  const relative = path.relative(distDir, file).replaceAll(path.sep, '/');
  if (relative === 'index.html') {
    return '/';
  }
  if (relative.endsWith('/index.html')) {
    return `/${relative.slice(0, -'index.html'.length)}`;
  }
  return `/${relative.replace(/\.html$/, '/')}`;
}

function anchorHrefs(html) {
  const matches = html.matchAll(/<a\b[^>]*\shref=(["'])(.*?)\1/gi);
  return [...matches].map((match) => match[2].replaceAll('&amp;', '&'));
}

function shouldSkip(href) {
  return (
    href === '' ||
    href.startsWith('#') ||
    href.startsWith('mailto:') ||
    href.startsWith('tel:') ||
    href.startsWith('javascript:')
  );
}

async function exists(file) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}
