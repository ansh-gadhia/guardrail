import { FormEvent, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import { useAuth } from "@/store/auth";
import { isMFAChallenge } from "@/lib/types";
import type { AuthProviders } from "@/lib/types";
import { useVersion } from "@/hooks/useVersion";
import { ErrorNote, Hairline, cn } from "@/components/ui";
import { BrandMark, CompanyLogo } from "@/components/brand";
import { IconKey, IconCheck, IconShield, IconAudit } from "@/components/icons";

export function LoginPage() {
  const { principal, login, verifyMFA, ldapLogin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: { pathname: string } } };
  const version = useVersion();

  const [mode, setMode] = useState<"local" | "ldap">("local");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<AuthProviders>({ local: true, ldap: false, oidc: false });

  const dest = location.state?.from?.pathname ?? "/";

  useEffect(() => {
    if (principal) navigate(dest, { replace: true });
  }, [principal, dest, navigate]);

  useEffect(() => {
    api.get<AuthProviders>("/auth/providers").then((r) => setProviders(r.data)).catch(() => undefined);
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "ldap") {
        await ldapLogin(email, password);
        return;
      }
      const res = await login(email, password);
      if (isMFAChallenge(res)) setMfaToken(res.mfa_token);
    } catch (err) {
      setError(problemDetail(err, "Sign-in failed"));
    } finally {
      setBusy(false);
    }
  };

  const submitMFA = async (e: FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setBusy(true);
    try {
      await verifyMFA(mfaToken, code.trim());
    } catch (err) {
      setError(problemDetail(err, "Invalid code"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[1.05fr_minmax(0,1fr)]">
      <BrandRail version={version.data?.version} />

      <main className="relative flex min-h-screen items-center justify-center px-5 py-10">
        <div className="app-aura pointer-events-none absolute inset-0 lg:hidden" />
        <div className="relative w-full max-w-sm">
          {/* Compact mark — only when the rail panel is hidden */}
          <div className="mb-8 flex flex-col items-center gap-3 text-center lg:hidden">
            <BrandMark className="h-16 w-16 drop-shadow-md" />
            <div>
              <div className="font-display text-xl font-semibold tracking-tight">GuardRail</div>
              <div className="text-2xs uppercase tracking-[0.14em] text-faint">Privileged Access Management</div>
            </div>
          </div>

          <div className="mb-6 hidden lg:block">
            <h1 className="font-display text-2xl font-semibold tracking-tight text-fg">
              {mfaToken ? "Verify it's you" : "Sign in"}
            </h1>
            <p className="mt-1 text-sm text-muted">
              {mfaToken ? "One more step to reach the console." : "Access the GuardRail console to broker privileged sessions."}
            </p>
          </div>

          <div className="relative overflow-hidden rounded-2xl border border-line bg-surface p-6 shadow-md animate-slideup">
            <Hairline />
            {error && (
              <div className="mb-4">
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
                  <label className="label">{mode === "ldap" ? "Username" : "Email"}</label>
                  <input
                    className="input"
                    type={mode === "ldap" ? "text" : "email"}
                    autoComplete="username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="label">Password</label>
                  <input
                    className="input"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                <button className="btn-primary w-full" disabled={busy}>
                  {busy ? "Signing in…" : "Sign in"}
                </button>

                {providers.oidc && (
                  <>
                    <div className="flex items-center gap-3 py-0.5 text-2xs uppercase tracking-wider text-faint">
                      <span className="h-px flex-1 bg-line" />
                      or
                      <span className="h-px flex-1 bg-line" />
                    </div>
                    <a href="/api/v1/auth/oidc/start" className="btn-ghost w-full">
                      Continue with SSO
                    </a>
                  </>
                )}
              </form>
            ) : (
              <form onSubmit={submitMFA} className="space-y-4">
                <p className="text-sm text-muted">Enter the 6-digit code from your authenticator app, or a recovery code.</p>
                <input
                  className="input text-center text-lg tracking-[0.3em]"
                  inputMode="text"
                  autoFocus
                  placeholder="123456"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  required
                />
                <button className="btn-primary w-full" disabled={busy}>
                  {busy ? "Verifying…" : "Verify"}
                </button>
                <button
                  type="button"
                  className="w-full text-center text-xs text-faint hover:text-muted"
                  onClick={() => {
                    setMfaToken(null);
                    setCode("");
                  }}
                >
                  Back to sign in
                </button>
              </form>
            )}
          </div>

          {/* Company mark — shown here on small screens (the brand rail carries it
              on desktop). Theme-aware: dark ink on light, light ink on dark. */}
          <div className="mt-8 flex flex-col items-center gap-2 lg:hidden">
            <CompanyLogo className="h-9 w-auto" />
            <span className="text-2xs text-faint">GuardRail v{version.data?.version ?? "…"}</span>
          </div>
        </div>
      </main>
    </div>
  );
}

/* ---- Brand rail — the signature ------------------------------------------------
   Always dark. It states what the product does: it puts a rail between a person
   and a privileged system, so every session is requested, approved, brokered
   without exposing the secret, and recorded end to end. The four nodes are that
   lifecycle, not decoration. */
const LIFECYCLE: { label: string; desc: string; icon: typeof IconKey }[] = [
  { label: "Request", desc: "A person asks for access to a system they don't hold keys to.", icon: IconKey },
  { label: "Approve", desc: "An operator authorizes it — or policy does, on their behalf.", icon: IconCheck },
  { label: "Broker", desc: "GuardRail injects the credential. The secret is never shown.", icon: IconShield },
  { label: "Record", desc: "The whole session is captured, timestamped, and auditable.", icon: IconAudit },
];

function BrandRail({ version }: { version?: string }) {
  return (
    <aside className="relative hidden overflow-hidden bg-[#070b12] text-slate-200 lg:flex lg:flex-col lg:justify-between lg:p-12 xl:p-14">
      {/* atmosphere */}
      <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-teal-500/15 blur-[120px]" />
      <div className="pointer-events-none absolute -bottom-40 -right-24 h-96 w-96 rounded-full bg-cyan-500/10 blur-[120px]" />
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(148,163,184,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.06) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
        }}
      />

      {/* wordmark */}
      <div className="relative flex items-center gap-3">
        <BrandMark className="h-12 w-12 drop-shadow-lg" />
        <div>
          <div className="font-display text-lg font-semibold tracking-tight text-white">GuardRail</div>
          <div className="font-mono text-2xs uppercase tracking-[0.18em] text-teal-300/80">Privileged Access Management</div>
        </div>
      </div>

      {/* the rail */}
      <div className="relative my-10 max-w-md">
        <p className="mb-8 font-display text-[26px] font-semibold leading-[1.2] tracking-tight text-white">
          Every privileged session runs on a rail.
        </p>
        <ol className="relative space-y-7">
          <span
            className="absolute bottom-2 left-[19px] top-2 w-px bg-gradient-to-b from-teal-400/70 via-teal-400/30 to-transparent"
            aria-hidden
          />
          {LIFECYCLE.map((step, i) => (
            <li key={step.label} className="relative flex gap-4">
              <span className="relative z-10 grid h-10 w-10 shrink-0 place-items-center rounded-full border border-teal-400/30 bg-teal-400/10 text-teal-300 shadow-[0_0_0_4px_rgba(7,11,18,1)]">
                <step.icon size={17} />
              </span>
              <div className="pt-1">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-2xs tabular-nums text-teal-400/70">0{i + 1}</span>
                  <span className="font-display text-sm font-semibold tracking-tight text-white">{step.label}</span>
                </div>
                <p className="mt-1 text-[13px] leading-relaxed text-slate-400">{step.desc}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>

      {/* footer — the company mark sits here on desktop, always on the dark rail */}
      <div className="relative space-y-4">
        <CompanyLogo onDark className="h-10 w-auto" />
        <div className="flex items-center justify-between font-mono text-2xs text-slate-500">
          <span>Secrets stay in the vault. People never touch them.</span>
          <span className="tabular-nums">v{version ?? "…"}</span>
        </div>
      </div>
    </aside>
  );
}
