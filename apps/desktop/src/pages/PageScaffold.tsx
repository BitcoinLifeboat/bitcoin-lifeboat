import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

interface PageScaffoldProps {
  titleKey: string;
  bodyKey: string;
  children?: ReactNode;
}

/**
 * Shared chrome for a routed screen: a localized title and intro, then any
 * screen-specific content. US-045..US-055 replace the placeholder bodies with
 * real UI; the title/intro pattern keeps every screen consistent.
 */
export function PageScaffold({ titleKey, bodyKey, children }: PageScaffoldProps): JSX.Element {
  const { t } = useTranslation();
  return (
    <section className="mx-auto max-w-3xl">
      <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">{t(titleKey)}</h1>
      <p className="mt-2 text-slate-600 dark:text-slate-300">{t(bodyKey)}</p>
      {children}
    </section>
  );
}
