import { useMemo } from "react";
import type { MouseEvent } from "react";
import MarkdownIt from "markdown-it";

import { openExternalLink } from "../tauri/commands";

/**
 * The strict Markdown renderer for the in-app docs (§28.4 / US-055).
 *
 * `html: false` is the critical setting: raw HTML in the source is NOT parsed,
 * it is escaped and rendered as literal text, so a `<script>` (or any other tag)
 * embedded in a doc can never become a live DOM node. `linkify: false` means only
 * explicit `[text](url)` / `<url>` Markdown links become anchors (no surprise
 * auto-linking), and the `image` rule is disabled so a Markdown image can never
 * trigger a remote fetch — the app makes no network requests on its own (§13.10).
 *
 * One shared instance is enough: rendering is a pure function of the input string.
 */
const md = new MarkdownIt({ html: false, linkify: false, typographer: false });
md.disable("image", true);

/** True for an absolute web URL we route to the OS browser. */
function isExternalUrl(href: string): boolean {
  return /^https?:\/\//i.test(href);
}

/** Reduce an intra-doc link href (`glossary`, `./glossary`, `glossary.md`) to a
 *  bare page id. */
function toDocId(href: string): string {
  return href.replace(/^\.?\//, "").replace(/\.md$/, "");
}

export interface MarkdownViewProps {
  /** The Markdown document body to render. */
  content: string;
  /** Called when an intra-doc link (a bare page id) is activated, so the viewer
   *  can switch pages. External links are not routed here. */
  onNavigate?: (docId: string) => void;
}

/**
 * Render a trusted, bundled Markdown document.
 *
 * Every link is intercepted: the webview never navigates away. An absolute
 * `http(s)` link is opened in the user's browser via the allowlisted
 * {@link openExternalLink} command (the Rust core vets it against the §21.3
 * allowlist and refuses anything off-list); a relative link that names another
 * doc page is handled in-app via {@link MarkdownViewProps.onNavigate}; anything
 * else is ignored. This is the only way a docs link can reach the network, which
 * is exactly the §22.11 "does not link to external content other than the
 * allowlist" rule.
 */
export function MarkdownView({ content, onNavigate }: MarkdownViewProps): JSX.Element {
  const html = useMemo(() => md.render(content), [content]);

  function handleClick(event: MouseEvent<HTMLDivElement>): void {
    const anchor = (event.target as HTMLElement).closest("a");
    if (!anchor) {
      return;
    }
    // Never let the webview follow a link itself — we decide what happens.
    event.preventDefault();
    const href = anchor.getAttribute("href")?.trim() ?? "";
    if (!href) {
      return;
    }
    if (isExternalUrl(href)) {
      void openExternalLink(href).catch(() => {
        /* off-allowlist (E-LINK-001) or no browser: leave the UI unchanged */
      });
      return;
    }
    const id = toDocId(href);
    if (id && onNavigate) {
      onNavigate(id);
    }
  }

  return (
    <div
      className="markdown-body"
      // Safe: `md` is configured with `html: false`, so this string contains only
      // the tags markdown-it itself emits (headings, paragraphs, lists, links,
      // code, …) over trusted bundled content — never raw HTML from the source.
      dangerouslySetInnerHTML={{ __html: html }}
      onClick={handleClick}
    />
  );
}
