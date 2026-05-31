import { useState } from "react";
import { useTranslation } from "react-i18next";

import { MarkdownView } from "../components/MarkdownView";
import { DEFAULT_DOC_ID, DOC_PAGES, findDocPage } from "../content/docs";

/**
 * Learn — the in-app docs viewer (§28 / US-055).
 *
 * Renders the bundled Markdown set (glossary, safety education, descriptor and
 * xpub explainers) through the strict {@link MarkdownView}. Everything is local:
 * no doc is fetched over the network, and the only links that leave the app are
 * the allowlisted ones {@link MarkdownView} routes to the OS browser (§22.11).
 * The frontend runs no Bitcoin logic here — it just selects and displays text.
 */
export default function Learn(): JSX.Element {
  const { t } = useTranslation();
  const [activeId, setActiveId] = useState<string>(DEFAULT_DOC_ID);
  const active = findDocPage(activeId) ?? DOC_PAGES[0];

  return (
    <section className="mx-auto max-w-5xl">
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">
        {t("pages.learn.title")}
      </h1>
      <p className="mt-2 text-slate-600 dark:text-slate-300">{t("pages.learn.intro")}</p>

      <div className="mt-6 flex flex-col gap-8 md:flex-row">
        <nav aria-label={t("pages.learn.navLabel")} className="shrink-0 md:w-56">
          <ul className="space-y-1">
            {DOC_PAGES.map((page) => {
              const isActive = page.id === active.id;
              return (
                <li key={page.id}>
                  <button
                    type="button"
                    aria-current={isActive ? "page" : undefined}
                    onClick={() => setActiveId(page.id)}
                    className={[
                      "block w-full rounded px-3 py-2 text-left text-sm",
                      isActive
                        ? "bg-brand text-white"
                        : "text-slate-700 hover:bg-slate-200 dark:text-slate-200 dark:hover:bg-slate-800",
                    ].join(" ")}
                  >
                    {t(page.titleKey)}
                  </button>
                </li>
              );
            })}
          </ul>
          <p className="mt-4 px-3 text-xs text-slate-500 dark:text-slate-400">
            {t("pages.learn.externalNote")}
          </p>
        </nav>

        <article className="min-w-0 flex-1">
          <MarkdownView
            key={active.id}
            content={active.content}
            onNavigate={(id) => {
              if (findDocPage(id)) {
                setActiveId(id);
              }
            }}
          />
        </article>
      </div>
    </section>
  );
}
