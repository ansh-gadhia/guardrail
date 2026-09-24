import { FormEvent, KeyboardEvent, PointerEvent, useCallback, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, problemDetail, takeSignOutReason } from "@/lib/api";
import { useAuth } from "@/store/auth";
import { isMFAChallenge } from "@/lib/types";
import type { AuthProviders } from "@/lib/types";
import { useVersion } from "@/hooks/useVersion";
import { useMediaQuery } from "@/hooks/useMediaQuery";
import { ErrorNote, cn } from "@/components/ui";
import { BrandMark, CompanyLogo } from "@/components/brand";
import { IconCheck } from "@/components/icons";
import { RailScene, type RailSignal } from "@/components/RailScene";

/**
 * The sign-in page.
 *
 * The form is on the left, and the schematic on the right is GuardRail at work
 * (see RailScene). The two are one piece: submitting the form sends this
 * person's own request across the rail to the vault's gate, and the answer
 * comes back there as well as here — the vault opens, the gate turns red, or it
 * holds on amber for a second factor. On success the page waits the half second
 * it takes the vault to open, then goes in; with reduced motion it goes at once.
 */
export function LoginPage() {
  const { principal, login, verifyMFA, ldapLogin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: { pathname: string } } };
  const version = useVersion();
  const wide = useMediaQuery("(min-width: 1024px)");
  const reduced = useMediaQuery("(prefers-reduced-motion: reduce)");

  const [mode, setMode] = useState<"local" | "ldap">("local");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Why the console signed this person out, when it was policy rather than them.
  // Read once on arrival; it is not an error, and is not styled as one.
  const [signedOut] = useState<string | null>(() => takeSignOutReason());
  const [busy, setBusy] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [focused, setFocused] = useState(false);
  const [providers, setProviders] = useState<AuthProviders>({ local: true, ldap: false, oidc: false });

  const [signal, setSignal] = useState<RailSignal>({ attempt: 0, verdict: "pending" });
  const [unlocking, setUnlocking] = useState(false);
  const [shakes, setShakes] = useState(0);
  const signedInHere = useRef(false);
  const left = useRef(false);
  const formRef = useRef<HTMLDivElement>(null);

  const dest = location.state?.from?.pathname ?? "/";
  const enter = useCallback(() => {
    if (left.current) return;
    left.current = true;
    navigate(dest, { replace: true });
  }, [navigate, dest]);

  // Somebody already signed in goes straight through. Somebody who has just
  // signed in here sees the vault open first — unless they asked for less
  // motion, or the scene is not on screen and a phone's emblem stands in for it.
  useEffect(() => {
    if (!principal) return;
    if (!signedInHere.current || reduced) {
      enter();
      return;
    }
    setUnlocking(true);
    setSignal((s) => ({ ...s, verdict: "granted" }));
    const t = window.setTimeout(enter, wide ? 1600 : 700); // the scene calls back sooner
    return () => window.clearTimeout(t);
  }, [principal, reduced, wide, enter]);

  useEffect(() => {
    api.get<AuthProviders>("/auth/providers").then((r) => setProviders(r.data)).catch(() => undefined);
  }, []);

  // A wrong answer shakes the form once. Restarted by hand so the inputs keep
  // their focus, which remounting them would lose.
  useEffect(() => {
    const el = formRef.current;
    if (!shakes || !el || reduced) return;
    el.classList.remove("signin-shake");
    void el.offsetWidth;
    el.classList.add("signin-shake");
  }, [shakes, reduced]);

  const refused = () => {
    signedInHere.current = false;
    setSignal((s) => ({ ...s, verdict: "denied" }));
    setShakes((n) => n + 1);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    signedInHere.current = true;
    setSignal((s) => ({ attempt: s.attempt + 1, verdict: "pending" }));
    try {
      if (mode === "ldap") {
        await ldapLogin(email, password);
        return;
      }
      const res = await login(email, password);
      if (isMFAChallenge(res)) {
        setMfaToken(res.mfa_token);
        setSignal((s) => ({ ...s, verdict: "mfa" }));
      }
    } catch (err) {
      setError(problemDetail(err, "Sign-in failed"));
      refused();
    } finally {
      setBusy(false);
    }
  };

  const submitMFA = async (e: FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setBusy(true);
    signedInHere.current = true;
    // Still waiting at the gate from the password step: carry on from there.
    // After a wrong code the request starts over.
    setSignal((s) => (s.verdict === "mfa" ? { ...s, verdict: "pending" } : { attempt: s.attempt + 1, verdict: "pending" }));
    try {
      await verifyMFA(mfaToken, code.trim());
    } catch (err) {
      setError(problemDetail(err, "Invalid code"));
      refused();
    } finally {
      setBusy(false);
    }
  };

  const capsFrom = (e: KeyboardEvent<HTMLInputElement>) => setCapsLock(e.getModifierState("CapsLock"));

  const vaultState = unlocking
    ? "unlock"
    : signal.attempt === 0
      ? "idle"
      : busy
        ? "wait"
        : signal.verdict === "mfa"
          ? "mfa"
          : signal.verdict === "denied"
            ? "deny"
            : "idle";

  return (
    <div className="min-h-screen bg-bg lg:grid lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
      <main className="relative flex min-h-screen flex-col px-6 py-8 sm:px-10 lg:px-14 lg:py-10 xl:px-20">
        <div className="app-aura pointer-events-none absolute inset-0 lg:hidden" />

        <header className="relative hidden items-center gap-3 lg:flex">
          <BrandMark className="h-10 w-10" />
          <div className="leading-tight">
            <div className="font-display text-base font-semibold tracking-tight text-fg">GuardRail</div>
            <div className="text-xs text-faint">Privileged access management</div>
          </div>
        </header>

        <div className="relative flex flex-1 items-center py-10">
          <div className="mx-auto w-full max-w-sm lg:mx-0">
            {/* On a phone the schematic has no room; its vault stands in. */}
            <div className="mb-8 flex flex-col items-center gap-4 text-center lg:hidden">
              <CompactVault state={vaultState} />
              <div>
                <div className="font-display text-xl font-semibold tracking-tight text-fg">GuardRail</div>
                <div className="text-xs text-faint">Privileged access management</div>
              </div>
            </div>

            <h1 className="text-center font-display text-[28px] font-semibold leading-tight tracking-tight text-fg lg:text-left lg:text-[34px]">
              {unlocking ? "Signed in" : mfaToken ? "Verify it's you" : "Sign in"}
            </h1>
            <p className="mt-2 text-center text-sm text-muted lg:text-left">
              {unlocking
                ? "Opening the console."
                : mfaToken
                  ? "Enter the 6-digit code from your authenticator app, or a recovery code."
                  : "Request, approve and watch privileged sessions."}
            </p>

            <div
              ref={formRef}
              className="mt-8"
              onFocus={() => setFocused(true)}
              onBlur={(e) => {
                if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocused(false);
              }}
            >
              {signedOut && !error && (
                <div
                  role="status"
                  className="mb-5 flex items-start gap-2.5 rounded-lg border border-line bg-surface-2/60 px-3 py-2.5 text-sm text-muted"
                >
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />
                  <span>
                    {signedOut.charAt(0).toUpperCase() + signedOut.slice(1)}. Sign in to continue.
                  </span>
                </div>
              )}
              {error && (
                <div className="mb-5">
                  <ErrorNote message={error} />
                </div>
              )}

              {!mfaToken ? (
                <form onSubmit={submit} className="space-y-4">
                  {providers.ldap && (
                    <div className="flex gap-1 rounded-lg border border-line bg-surface-2/60 p-1 text-sm">
                      {(["local", "ldap"] as const).map((m) => (
                        <button
                          key={m}
                          type="button"
                          onClick={() => setMode(m)}
                          className={cn(
                            "flex-1 rounded-md px-3 py-1.5 font-medium transition",
                            mode === m ? "bg-surface text-accent shadow-xs ring-1 ring-line" : "text-muted hover:text-fg",
                          )}
                        >
                          {m === "local" ? "Local" : "Directory"}
                        </button>
                      ))}
                    </div>
                  )}

                  <div>
                    <label className="label" htmlFor="signin-user">
                      {mode === "ldap" ? "Username" : "Email"}
                    </label>
                    <input
                      id="signin-user"
                      className="input h-11"
                      type={mode === "ldap" ? "text" : "email"}
                      autoComplete="username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      disabled={unlocking}
                      required
                    />
                  </div>
                  <div>
                    <label className="label" htmlFor="signin-password">
                      Password
                    </label>
                    <input
                      id="signin-password"
                      className="input h-11"
                      type="password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={capsFrom}
                      onKeyUp={capsFrom}
                      onBlur={() => setCapsLock(false)}
                      disabled={unlocking}
                      aria-describedby={capsLock ? "signin-caps" : undefined}
                      required
                    />
                    {capsLock && (
                      <p id="signin-caps" className="mt-1.5 text-xs font-medium text-warn">
                        Caps Lock is on.
                      </p>
                    )}
                  </div>
                  <SubmitButton busy={busy} done={unlocking} idle="Sign in" working="Signing in…" />

                  {providers.oidc && (
                    <>
                      <div className="flex items-center gap-3 py-0.5 text-xs text-faint">
                        <span className="h-px flex-1 bg-line" />
                        or
                        <span className="h-px flex-1 bg-line" />
                      </div>
                      <a href="/api/v1/auth/oidc/start" className="btn-ghost h-11 w-full">
                        Continue with SSO
                      </a>
                    </>
                  )}

                  {/* No button, because there is nothing here to click: the SIEM
                      handoff starts at the SIEM and lands on /auth/sso. Saying so
                      is the whole point — an analyst who has never been issued a
                      GuardRail password would otherwise stand at this form with no
                      idea that it is not the door they are meant to use. */}
                  {providers.siem_sso && (
                    <p className="pt-1 text-center text-xs text-faint">
                      Analysts signed in to the SIEM can open GuardRail from there — no separate password.
                    </p>
                  )}
                </form>
              ) : (
                <form onSubmit={submitMFA} className="space-y-4">
                  <label className="label" htmlFor="signin-code">
                    Code
                  </label>
                  <input
                    id="signin-code"
                    className="input h-12 text-center text-lg tracking-[0.3em]"
                    inputMode="text"
                    autoComplete="one-time-code"
                    autoFocus
                    placeholder="123456"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    disabled={unlocking}
                    required
                  />
                  <SubmitButton busy={busy} done={unlocking} idle="Verify" working="Verifying…" />
                  <button
                    type="button"
                    className="w-full text-center text-xs text-faint hover:text-muted"
                    onClick={() => {
                      setMfaToken(null);
                      setCode("");
                      setError(null);
                      setSignal((s) => ({ ...s, verdict: "cancel" }));
                    }}
                  >
                    Back to sign in
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>

        <footer className="relative flex flex-col items-center gap-3 text-center lg:items-start lg:text-left">
          <CompanyLogo className="h-8 w-auto lg:hidden" />
          <p className="text-xs text-faint">Every sign-in, successful or not, is recorded in the audit log.</p>
          <span className="font-mono text-2xs text-faint lg:hidden">GuardRail v{version.data?.version ?? "…"}</span>
        </footer>
      </main>

      <RailPanel
        version={version.data?.version}
        scene={wide}
        reduced={reduced}
        signal={signal}
        present={focused || email !== "" || password !== ""}
        onUnlocked={enter}
      />
    </div>
  );
}

function SubmitButton({ busy, done, idle, working }: { busy: boolean; done: boolean; idle: string; working: string }) {
  return (
    <button className={cn("btn-primary h-11 w-full", busy && "signin-busy")} disabled={busy || done}>
      {done ? (
        <>
          <IconCheck size={16} /> Signed in
        </>
      ) : busy ? (
        working
      ) : (
        idle
      )}
    </button>
  );
}

/* ---- The dark panel ------------------------------------------------------------
   Always dark, whatever the theme: it is the product's signature. The schematic
   is only mounted where it is shown, so a phone does not run an animation loop
   for a panel it hides. */
function RailPanel({
  version,
  scene,
  reduced,
  signal,
  present,
  onUnlocked,
}: {
  version?: string;
  scene: boolean;
  reduced: boolean;
  signal: RailSignal;
  present: boolean;
  onUnlocked: () => void;
}) {
  const ref = useRef<HTMLElement>(null);
  const lamp = (e: PointerEvent<HTMLElement>) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  };

  return (
    <aside
      ref={ref}
      onPointerMove={reduced ? undefined : lamp}
      className="relative hidden overflow-hidden bg-[#070b12] text-slate-200 lg:flex lg:flex-col lg:px-12 lg:py-8 xl:px-16"
    >
      <div className="rail-grid pointer-events-none absolute inset-0" aria-hidden />
      <div className="rail-grid-lit pointer-events-none absolute inset-0" aria-hidden />

      <div className="relative flex flex-1 flex-col justify-center gap-8 py-4">
        <h2 className="rail-headline max-w-xl font-display text-[34px] font-semibold leading-[1.1] tracking-tight text-white xl:text-[40px]">
          Every privileged session runs on a rail.
        </h2>
        {scene && <RailScene signal={signal} present={present} onUnlocked={onUnlocked} reduced={reduced} />}
      </div>

      <div className="relative flex items-end justify-between gap-6">
        <CompanyLogo onDark className="h-9 w-auto" />
        <div className="text-right text-xs leading-5 text-slate-500">
          <div>Secrets stay in the vault. People never touch them.</div>
          <div className="font-mono tabular-nums">v{version ?? "…"}</div>
        </div>
      </div>
    </aside>
  );
}

/* The emblem in its dial, above the form on a phone. It answers the way the
   vault does: turning while the server decides, amber for a second factor, red
   for a refusal, opening on success. */
function CompactVault({ state }: { state: string }) {
  return (
    <div className="compact-vault relative h-24 w-24" data-state={state}>
      <svg viewBox="0 0 96 96" className="absolute inset-0 overflow-visible" aria-hidden>
        <g className="cv-dial">
          <circle cx={48} cy={48} r={46} fill="none" stroke="rgb(var(--line-strong))" strokeWidth={4} strokeDasharray="1.2 6.03" />
        </g>
        <circle className="cv-ring" cx={48} cy={48} r={38} fill="none" stroke="rgb(var(--accent) / 0.55)" strokeWidth={1.5} />
      </svg>
      <BrandMark className="absolute inset-0 m-auto h-[56%] w-[56%]" />
    </div>
  );
}
