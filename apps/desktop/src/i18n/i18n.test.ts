import { afterEach, describe, expect, it } from "vitest";

import i18n, { SUPPORTED_LOCALES, normalizeLocale } from ".";

describe("desktop i18n resources (US-097)", () => {
  afterEach(async () => {
    await i18n.changeLanguage("en");
    document.documentElement.lang = "en";
  });

  it("loads every supported locale synchronously", async () => {
    for (const locale of SUPPORTED_LOCALES) {
      await i18n.changeLanguage(locale.code);
      expect(i18n.exists("app.name")).toBe(true);
      expect(i18n.t("pages.settings.language.label")).not.toContain(
        "pages.settings.language.label",
      );
    }
  });

  it("normalizes unsupported or region-specific language tags", () => {
    expect(normalizeLocale("es-MX")).toBe("es");
    expect(normalizeLocale("de-DE")).toBe("de");
    expect(normalizeLocale("fr-CA")).toBe("fr");
    expect(normalizeLocale("pt-BR")).toBe("en");
    expect(normalizeLocale(null)).toBe("en");
  });
});
