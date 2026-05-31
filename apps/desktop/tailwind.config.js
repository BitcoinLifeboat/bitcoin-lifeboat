/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // Class-based dark mode so Settings (US-054) can override the OS preference.
  darkMode: "class",
  theme: {
    extend: {
      // All app colors are centralized here so no component hardcodes a hex
      // value and dark/light parity (§22.10) stays in one place.
      colors: {
        // Calm, local-first brand surface.
        brand: {
          DEFAULT: "#1d4ed8",
          fg: "#0b1f33",
        },
        // §22.3 readiness status badge colors (verified WCAG AA on white).
        // Used by the badges in US-047; declared here as the single source.
        status: {
          ready: "#0f7a3f",
          "mostly-ready": "#5aa36b",
          "needs-attention": "#c87a00",
          "not-ready": "#b91c1c",
          "cannot-determine": "#6b7280",
        },
        // §22.4 network banner colors (mainnet red, testnet/signet yellow,
        // regtest gray). Used by the network banner in US-047.
        network: {
          mainnet: "#b91c1c",
          testnet: "#c87a00",
          signet: "#c87a00",
          regtest: "#6b7280",
        },
      },
    },
  },
  plugins: [],
};
