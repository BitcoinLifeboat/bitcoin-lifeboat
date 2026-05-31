/**
 * The bundled in-app documentation set (§28.1 / §28.3 / US-055).
 *
 * Each page is a plain Markdown file imported at build time as a raw string
 * (Vite's `?raw` query). The Markdown is the SAME content the docs site renders
 * (§28.4 / §28.5) — nothing here is fetched over the network, so the Learn viewer
 * works fully offline. Page titles live in i18n (`pages.learn.docs.*`); the body
 * is the Markdown itself. To add a page: drop a `<id>.md` file beside this one and
 * add a `{ id, titleKey, content }` row (keep `id` a single lowercase token so it
 * can be used as an intra-doc link target, e.g. `[glossary](glossary)`).
 */
import overview from "./overview.md?raw";
import descriptors from "./descriptors.md?raw";
import xpub from "./xpub.md?raw";
import glossary from "./glossary.md?raw";
import safety from "./safety.md?raw";
import practiceSeeds from "./practice-seeds.md?raw";

/** One embedded documentation page. */
export interface DocPage {
  /** Stable id; also the intra-doc link target (`[text](<id>)`). */
  id: string;
  /** i18n key for the page's nav/heading label. */
  titleKey: string;
  /** The page body as raw Markdown. */
  content: string;
}

/**
 * The documentation pages, in display order. The set includes the glossary and
 * the safety-education page required by US-055, plus the core descriptor and xpub
 * explainers (§28.1).
 */
export const DOC_PAGES: readonly DocPage[] = [
  { id: "overview", titleKey: "pages.learn.docs.overview", content: overview },
  { id: "descriptors", titleKey: "pages.learn.docs.descriptors", content: descriptors },
  { id: "xpub", titleKey: "pages.learn.docs.xpub", content: xpub },
  { id: "glossary", titleKey: "pages.learn.docs.glossary", content: glossary },
  { id: "safety", titleKey: "pages.learn.docs.safety", content: safety },
  { id: "practice-seeds", titleKey: "pages.learn.docs.practiceSeeds", content: practiceSeeds },
];

/** The id of the page shown first when the Learn viewer opens. */
export const DEFAULT_DOC_ID = DOC_PAGES[0].id;

/** Look up a page by id, or `undefined` if no page has that id. */
export function findDocPage(id: string): DocPage | undefined {
  return DOC_PAGES.find((page) => page.id === id);
}
