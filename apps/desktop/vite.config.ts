/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Tauri serves the built assets from ../dist (tauri.conf.json -> build.frontendDist)
// and the dev server from a fixed port (build.devUrl). Tailwind/PostCSS are wired
// via postcss.config.js, so no extra Vite CSS config is needed here.
export default defineConfig({
  plugins: [react()],
  // Tauri controls the terminal; don't let Vite clear it.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    target: "es2020",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
