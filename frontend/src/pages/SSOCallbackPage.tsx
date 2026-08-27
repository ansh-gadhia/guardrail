import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import { useAuth } from "@/store/auth";
import { isMFAChallenge } from "@/lib/types";
import type { LoginResult } from "@/lib/types";
import { ErrorNote, Hairline } from "@/components/ui";
import { BrandMark } from "@/components/brand";

// readExchangeToken pulls the SIEM's exchange token off the URL and scrubs it
// from the address bar in the same breath.
//
// FRAGMENT FIRST, and this is the part worth copying rather than the part worth
// skimming. A URL fragment is never transmitted to a server. A query string is —
// so `?token=…` is written verbatim into the reverse proxy's access log, which
// is rotated, shipped somewhere, and kept for far longer than the thirty seconds
// the credential is alive. It also lands in browser history and in the Referer
// header of the next thing the page loads. The query string is accepted anyway
// so that a SIEM already redirecting that way keeps working, and has a strictly
// better option to move to.
//
// The scrub uses replaceState rather than pushState so the token-bearing URL
// does not become a back-button destination. The token is single-use by the time
// this returns, so what is left is only useful to somebody reading over a
// shoulder — but that is a real threat in a SOC.
function readExchangeToken(): string | null {
  const fromFragment = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token");
  const fromQuery = new URLSearchParams(window.location.search).get("token");
  const token = fromFragment ?? fromQuery;
  if (token) {
    window.history.replaceState(null, "", window.location.pathname);
  }
  return token;
}

/**
 * SSOCallbackPage lands the browser handoff from the SIEM.
 *
 * The SIEM mints a short-lived signed assertion and redirects here; this page
 * trades it for a GuardRail session and moves on. There is nothing to click,
 * because there is nothing to decide.
 */
export function SSOCallbackPage() {
  const navigate = useNavigate();
  const { setSession, verifyMFA } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  // The exchange runs once. React's development StrictMode mounts every effect
  // twice, and the token is single-use — without this guard the second run
  // reliably reports "already used" and the sign-in appears to fail on every
  // developer's machine but nobody else's.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const token = readExchangeToken();
    if (!token) {
      setError(
        "This link carries no sign-in token. Open the GuardRail console from the SIEM rather than " +
          "bookmarking this page.",
      );
      return;
    }
    api
      .post<LoginResult>("/auth/sso/exchange", { token })
      .then(({ data }) => {
        if (isMFAChallenge(data)) {
          setMfaToken(data.mfa_token);
          return;
        }
        setSession(data);
        // replace, not push: the handoff URL should not be somewhere the back
        // button can return to.
        navigate("/", { replace: true });
      })
      .catch((err) => {
        // The server's own detail string, verbatim. Every rejection message on
        // that endpoint is written to be read by a person — usually whoever is
        // wiring the SIEM up — and replacing them with "Sign-in failed" throws
        // away the only diagnosis they get.
        setError(problemDetail(err, "The SIEM sign-in could not be completed."));
      });
  }, [navigate, setSession]);

  const submitMFA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setBusy(true);
    try {
      await verifyMFA(mfaToken, code.trim());
      navigate("/", { replace: true });
    } catch (err) {
      setError(problemDetail(err, "Invalid code"));
    } finally {
      setBusy(false);
    }
  };

  return (
    // The same backdrop the sign-in page uses. A differently-styled interstitial
    // makes signing in look like a flash through some third product, which is
    // exactly the impression an integration should not leave.
    <main className="relative flex min-h-screen items-center justify-center px-5 py-10">
      <div className="app-aura pointer-events-none absolute inset-0" />
      <div className="relative w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <BrandMark className="h-16 w-16 drop-shadow-md" />
          <div>
            <div className="font-display text-xl font-semibold tracking-tight">GuardRail</div>
            <div className="text-2xs uppercase tracking-[0.14em] text-faint">Privileged Access Management</div>
          </div>
        </div>

        <div className="relative overflow-hidden rounded-2xl border border-line bg-surface p-6 shadow-md animate-slideup">
          <Hairline />

          {error ? (
            <div className="space-y-4">
              <ErrorNote message={error} />
              <button className="btn btn-subtle w-full" onClick={() => navigate("/login", { replace: true })}>
                Sign in with a GuardRail account
              </button>
            </div>
          ) : mfaToken ? (
            <form onSubmit={submitMFA} className="space-y-4">
              <div>
                <h1 className="font-display text-lg font-semibold tracking-tight text-fg">Verify it&apos;s you</h1>
                {/* Said plainly, because otherwise being asked for a code after
                    already signing in at the SIEM reads as something going wrong. */}
                <p className="mt-1 text-sm text-muted">
                  The SIEM confirmed who you are. GuardRail still asks for the second factor you enrolled here.
                </p>
              </div>
              <div>
                <label className="label">Authentication code</label>
                <input
                  className="input tracking-[0.3em]"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  required
                />
              </div>
              <button className="btn-primary w-full" disabled={busy}>
                {busy ? "Verifying…" : "Verify"}
              </button>
            </form>
          ) : (
            <div className="flex flex-col items-center gap-4 py-6 text-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-line-strong border-t-accent" />
              <div className="text-sm text-muted">Signing you in from the SIEM…</div>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
