import type { ThemePreference, TextScale } from "../store/prefs";

/** Resolve a preference to a concrete mode, honoring the OS for "system". */
export function resolveTheme(preference: ThemePreference): "light" | "dark" {
  if (preference === "system") {
    const prefersDark =
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches;
    return prefersDark ? "dark" : "light";
  }
  return preference;
}

/**
 * Toggle the `dark` class on <html> so Tailwind's class-based dark mode (§22.10)
 * applies. Safe to call when no DOM is present (returns early).
 */
export function applyTheme(preference: ThemePreference): void {
  if (typeof document === "undefined") {
    return;
  }
  const mode = resolveTheme(preference);
  document.documentElement.classList.toggle("dark", mode === "dark");
}

/** Root font-size percentages for the §15.5 large-text scales. */
const TEXT_SCALE_PERCENT: Record<TextScale, string> = {
  normal: "100%",
  large: "150%",
  larger: "200%",
};

/**
 * Apply the §15.5 large-text mode by setting the root (`<html>`) font size, so
 * all rem-based Tailwind sizing (text, spacing, controls) scales proportionally
 * at 1x / 1.5x / 2x. Safe to call when no DOM is present (returns early).
 */
export function applyTextScale(scale: TextScale): void {
  if (typeof document === "undefined") {
    return;
  }
  document.documentElement.style.fontSize = TEXT_SCALE_PERCENT[scale];
}
