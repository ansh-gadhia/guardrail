import { useMemo } from "react";
import { cn } from "./ui";

/* The strength meter the console shows must agree with what the server enforces
   (backend/internal/domain/iam/password.go) — a meter that says "Good" about a
   password the API then rejects is worse than no meter at all. This mirrors that
   rubric exactly: a point each for 8 characters, the minimum length, and
   passphrase length; a point for mixing lower/upper/digit; a point for a symbol.
   A password built on a common word is TooWeak regardless. */

export const MIN_PASSWORD_LEN = 12;
const LONG_PASSWORD_LEN = 20;
const MIN_ACCEPTABLE = 3; // "Good" — the server's floor.

// Kept in step with commonPasswords in the Go policy.
const COMMON = [
  "password", "letmein", "welcome", "admin", "administrator",
  "qwerty", "iloveyou", "monkey", "dragon", "sunshine", "princess",
  "guardrail", "changeme", "secret", "master",
];

// Each letter matches itself or its usual leet substitutions, so "P@ssw0rd" is
// still recognised as "password". Mirrors leetClass in the Go policy.
const LEET: Record<string, string> = {
  a: "[a4@]", b: "[b8]", e: "[e3]", g: "[g9]", i: "[i1!|]",
  l: "[l1|]", o: "[o0]", s: "[s5$]", t: "[t7+]", z: "[z2]",
};
const COMMON_PATTERNS = COMMON.map(
  (w) => new RegExp([...w].map((ch) => LEET[ch] ?? ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(""), "i"),
);

export interface Strength {
  score: number; // 0-4
  label: string;
  tone: "danger" | "warn" | "info" | "success";
  acceptable: boolean;
}

export function scorePassword(pw: string): Strength {
  const meta = [
    { label: "Too weak", tone: "danger" as const },
    { label: "Weak", tone: "danger" as const },
    { label: "Fair", tone: "warn" as const },
    { label: "Good", tone: "info" as const },
    { label: "Strong", tone: "success" as const },
  ];
  const build = (score: number): Strength => ({
    score,
    ...meta[score],
    acceptable: score >= MIN_ACCEPTABLE && pw.length >= MIN_PASSWORD_LEN,
  });

  if (!pw) return build(0);
  if (COMMON_PATTERNS.some((re) => re.test(pw))) return build(0);

  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= MIN_PASSWORD_LEN) score++;
  if (pw.length >= LONG_PASSWORD_LEN) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return build(Math.min(score, 4));
}

// hintFor names the one thing that would most improve this password, so the
// meter tells the user what to do rather than only how they scored.
export function hintFor(pw: string): string {
  if (!pw) return "";
  if (COMMON_PATTERNS.some((re) => re.test(pw))) return "Built on a commonly guessed word — pick something unrelated.";
  if (pw.length < MIN_PASSWORD_LEN) return `Use at least ${MIN_PASSWORD_LEN} characters.`;
  const s = scorePassword(pw);
  if (s.acceptable) return "";
  if (pw.length < LONG_PASSWORD_LEN) return "Mix upper and lower case, a digit, and a symbol — or make it longer.";
  return "";
}

const TONE_BAR = {
  danger: "bg-danger",
  warn: "bg-warn",
  info: "bg-info",
  success: "bg-success",
} as const;

/* PasswordStrength renders the meter. It stays out of the way until there is
   something to say — an empty field gets no bars and no verdict. */
export function PasswordStrength({ value, className }: { value: string; className?: string }) {
  const s = useMemo(() => scorePassword(value), [value]);
  const hint = useMemo(() => hintFor(value), [value]);
  if (!value) return null;
  return (
    <div className={cn("mb-4 -mt-1", className)} aria-live="polite">
      <div className="flex gap-1.5">
        {Array.from({ length: 4 }).map((_, i) => (
          <span
            key={i}
            className={cn(
              "h-1.5 flex-1 rounded-full transition-colors duration-200",
              i < s.score ? TONE_BAR[s.tone] : "bg-surface-3",
            )}
          />
        ))}
      </div>
      <div className="mt-1.5 flex items-baseline justify-between gap-3">
        <span className="text-2xs text-muted">
          Strength: <span className={cn(s.acceptable ? "text-success" : "text-muted")}>{s.label}</span>
        </span>
        {hint && <span className="text-2xs text-faint">{hint}</span>}
      </div>
    </div>
  );
}
