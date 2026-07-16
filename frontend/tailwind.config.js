/** @type {import('tailwindcss').Config} */

// Semantic design tokens resolve from CSS variables (see src/index.css), so every
// colour is one source of truth and Tailwind's opacity modifiers (bg-accent/10)
// keep working. GuardRail ships a single refined dark theme.
const token = (v) => `rgb(var(${v}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: token("--bg"),
        surface: token("--surface"),
        "surface-2": token("--surface-2"),
        "surface-3": token("--surface-3"),
        line: token("--line"),
        "line-strong": token("--line-strong"),
        fg: token("--fg"),
        muted: token("--muted"),
        faint: token("--faint"),
        accent: token("--accent"),
        "accent-fg": token("--accent-fg"),
        "accent-soft": token("--accent-soft"),
        success: token("--success"),
        warn: token("--warn"),
        danger: token("--danger"),
        info: token("--info"),
        // Retained so any un-migrated markup keeps rendering.
        brand: { 50: "#f0fdfa", 100: "#ccfbf1", 200: "#99f6e4", 500: "#14b8a6", 600: "#0d9488", 700: "#0f766e" },
      },
      borderRadius: { lg: "0.625rem", xl: "0.875rem", "2xl": "1.125rem" },
      // Type scale with intentional line-height + tracking per step. Display
      // sizes tighten as they grow (the Space Grotesk display face wants it);
      // body sizes stay comfortable for dense data.
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.01em" }],
        xs: ["0.75rem", { lineHeight: "1.05rem" }],
        sm: ["0.875rem", { lineHeight: "1.3rem" }],
        base: ["1rem", { lineHeight: "1.55rem" }],
        lg: ["1.125rem", { lineHeight: "1.6rem", letterSpacing: "-0.006em" }],
        xl: ["1.25rem", { lineHeight: "1.6rem", letterSpacing: "-0.012em" }],
        "2xl": ["1.5rem", { lineHeight: "1.85rem", letterSpacing: "-0.018em" }],
        "3xl": ["1.875rem", { lineHeight: "2.15rem", letterSpacing: "-0.022em" }],
        "4xl": ["2.25rem", { lineHeight: "2.4rem", letterSpacing: "-0.026em" }],
        "5xl": ["3rem", { lineHeight: "1.05", letterSpacing: "-0.03em" }],
      },
      boxShadow: {
        xs: "0 1px 2px 0 rgb(0 0 0 / 0.30)",
        sm: "0 1px 3px 0 rgb(0 0 0 / 0.35), 0 1px 2px -1px rgb(0 0 0 / 0.35)",
        md: "0 8px 24px -12px rgb(0 0 0 / 0.55)",
        focus: "0 0 0 3px rgb(var(--accent) / 0.30)",
        // Accent-tinted glow for icon tiles / active elements — a premium cue
        // (a colored glow reads richer than a grey drop shadow).
        glow: "0 6px 20px -8px rgb(var(--accent) / 0.55)",
        "glow-sm": "0 4px 12px -6px rgb(var(--accent) / 0.45)",
        // Deepest tier — modals/drawers floating above everything.
        overlay: "0 24px 60px -18px rgb(0 0 0 / 0.65)",
      },
      keyframes: {
        fadein: { from: { opacity: "0" }, to: { opacity: "1" } },
        slideup: { from: { opacity: "0", transform: "translateY(8px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
        spin: { to: { transform: "rotate(360deg)" } },
      },
      animation: {
        fadein: "fadein 0.35s ease both",
        slideup: "slideup 0.4s cubic-bezier(0.22, 1, 0.36, 1) both",
      },
      fontFamily: {
        sans: ["Inter var", "Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        // Space Grotesk — the display/brand voice, used with restraint on titles.
        display: ["Space Grotesk", "Inter var", "ui-sans-serif", "system-ui", "sans-serif"],
        // JetBrains Mono — the machine-data voice: IPs, session IDs, permission
        // keys, hosts, hashes. In a PAM these are literally machine data.
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      transitionTimingFunction: {
        // One easing for panels/reveals — a soft settle used everywhere.
        smooth: "cubic-bezier(0.16, 1, 0.3, 1)",
      },
    },
  },
  plugins: [],
};
