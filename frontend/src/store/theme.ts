import { create } from "zustand";

export type Theme = "dark" | "light";

const STORAGE_KEY = "guardrail-theme";

function readStored(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    /* ignore */
  }
  return "dark"; // dark is the primary theme
}

function apply(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* ignore */
  }
}

interface ThemeState {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggle: () => void;
}

export const useTheme = create<ThemeState>((set, get) => ({
  theme: readStored(),
  setTheme: (t) => {
    apply(t);
    set({ theme: t });
  },
  toggle: () => get().setTheme(get().theme === "dark" ? "light" : "dark"),
}));

// Apply the stored theme immediately at module load so first paint matches (the
// index.html ships with class="dark" so dark users never flash light).
apply(useTheme.getState().theme);
