import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { Enrollment, MFAStatus } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, Spinner, ErrorNote, StatusBadge, Panel, Field, Badge, Tabs, Switch, Modal } from "@/components/ui";
import { IconShield, IconLock, IconKey } from "@/components/icons";
import { PasswordStrength, scorePassword, MIN_PASSWORD_LEN as MIN_LEN } from "@/components/PasswordStrength";
import { QRCode } from "@/components/QRCode";
import { toast } from "@/components/Toast";

export function SecurityPage() {
  const principal = useAuth((s) => s.principal);
  const [tab, setTab] = useState("password");

  return (
    <div>
      <PageHero
        icon={IconShield}
        eyebrow="Governance"
        title="Account"
        subtitle={principal?.email}
        actions={<Badge tone={principal?.is_super_admin ? "accent" : "neutral"}>{principal?.is_super_admin ? "Super Admin" : principal?.roles.join(", ") || "Member"}</Badge>}
      />
      <div className="mb-5">
        <Tabs
          tabs={[
            { id: "password", label: "Password", icon: IconLock },
            { id: "mfa", label: "Two-factor", icon: IconKey },
          ]}
          active={tab}
          onChange={setTab}
        />
      </div>
      {tab === "password" ? <PasswordTab /> : <MfaTab />}
    </div>
  );
}

function PasswordTab() {
  const changePassword = useAuth((s) => s.changePassword);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);

  const strength = useMemo(() => scorePassword(next), [next]);
  const mismatch = !!next && !!confirm && next !== confirm;
  const tooWeak = !!next && !strength.acceptable;
  const canSubmit = current.length > 0 && strength.acceptable && next === confirm && next !== current;

  const mutate = useMutation({
    mutationFn: async () => changePassword(current, next),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setConfirm("");
      setDone(true);
    },
  });


  return (
    <div className="max-w-xl space-y-4">
      <Panel title="Change password" subtitle="Rotating your password signs out all your other sessions." icon={IconLock}>
        {mutate.isError && (
          <div className="mb-4">
            <ErrorNote message={problemDetail(mutate.error, "Could not change password")} />
          </div>
        )}
        {done && !mutate.isError && (
          <div className="mb-4 rounded-lg border border-success/25 bg-success/10 px-4 py-3 text-sm text-success">
            Password updated. Your other sessions have been signed out.
          </div>
        )}

        <Field label="Current password">
          <input className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => { setCurrent(e.target.value); setDone(false); }} />
        </Field>
        <Field label="New password" hint={`At least ${MIN_LEN} characters.`}>
          <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => { setNext(e.target.value); setDone(false); }} />
        </Field>

        <PasswordStrength value={next} />

        <Field label="Confirm new password">
          <input className="input" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>

        {(mismatch || tooWeak) && (
          <div className="mb-4 rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-xs text-danger">
            {mismatch ? "Passwords do not match." : `Pick a stronger password — at least ${MIN_LEN} characters, and not a common word.`}
          </div>
        )}

        <div className="flex justify-end">
          <button className="btn-primary" disabled={!canSubmit || mutate.isPending} onClick={() => mutate.mutate()}>
            {mutate.isPending ? "Updating…" : "Update password"}
          </button>
        </div>
      </Panel>
    </div>
  );
}

/* ---- MFA -------------------------------------------------------------------- */
function MfaTab() {
  const qc = useQueryClient();
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [code, setCode] = useState("");
  const [nextCode, setNextCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);
  const [disableCode, setDisableCode] = useState("");

  // clean is for enrolment only, where the input really is a 6-digit TOTP.
  const clean = (v: string) => v.replace(/\D/g, "").slice(0, 6);
  const codesReady = code.length === 6 && nextCode.length === 6 && code !== nextCode;

  // Turning MFA off accepts either factor the server accepts: a 6-digit TOTP, or
  // a recovery code. Recovery codes are hex with a dash ("a1b2c-3d4e5"), so the
  // enrolment cleaner must not be reused here — stripping non-digits turns a
  // recovery code into a few stray numbers and the button never enables. That
  // silently produced the exact lockout recovery codes exist to prevent: lose
  // the authenticator, and MFA could never be turned off.
  //
  // The server normalises case, dashes and spaces before hashing, so accept the
  // code however the user pastes it.
  const isTotpCode = (v: string) => /^\d{6}$/.test(v.trim());
  const isRecoveryCode = (v: string) => /^[0-9a-f]{10}$/i.test(v.trim().replace(/[-\s]/g, ""));
  const disableReady = isTotpCode(disableCode) || isRecoveryCode(disableCode);

  const resetEnrollment = () => {
    setEnrollment(null);
    setCode("");
    setNextCode("");
  };

  const status = useQuery<MFAStatus>({
    queryKey: ["mfa"],
    queryFn: async () => (await api.get<MFAStatus>("/mfa")).data,
    // Always reflect the true state: the badge must flip the moment enrollment
    // begins/completes or MFA is disabled, never serve a stale snapshot.
    staleTime: 0,
  });

  const begin = useMutation({
    mutationFn: async () => (await api.post<Enrollment>("/mfa/totp/enroll", {})).data,
    // Enrollment creates the (unconfirmed) method server-side, so refresh status
    // too — otherwise the header badge stays "disabled" during setup.
    onSuccess: (d) => { setEnrollment(d); setError(null); void qc.invalidateQueries({ queryKey: ["mfa"] }); },
    onError: (e) => setError(problemDetail(e, "Could not start enrollment")),
  });
  const confirm = useMutation({
    mutationFn: async () =>
      (await api.post<{ recovery_codes: string[] }>("/mfa/totp/confirm", { code, next_code: nextCode })).data,
    onSuccess: (d) => { setRecoveryCodes(d.recovery_codes); resetEnrollment(); setError(null); void qc.invalidateQueries({ queryKey: ["mfa"] }); },
    onError: (e) => setError(problemDetail(e, "Those codes didn't match. Wait for a fresh code and try again.")),
  });
  const disable = useMutation({
    mutationFn: async () => api.post("/mfa/disable", { code: disableCode }),
    onSuccess: () => {
      setRecoveryCodes(null);
      setDisabling(false);
      setDisableCode("");
      setError(null);
      toast.warn("Two-factor authentication disabled");
      void qc.invalidateQueries({ queryKey: ["mfa"] });
    },
  });
  const regen = useMutation({
    mutationFn: async () => (await api.post<{ recovery_codes: string[] }>("/mfa/recovery-codes", {})).data,
    onSuccess: (d) => setRecoveryCodes(d.recovery_codes),
  });

  return (
    <div className="max-w-xl space-y-4">
      {status.isLoading && <Spinner />}
      {error && <ErrorNote message={error} />}

      {status.data && (
        <Panel
          title="Two-factor authentication"
          subtitle="Authenticator app · time-based one-time passwords"
          icon={IconKey}
          actions={<StatusBadge value={status.data.confirmed ? "active" : status.data.enabled ? "pending" : "disabled"} />}
        >
          {!status.data.confirmed && !enrollment && (
            <button className="btn-primary" disabled={begin.isPending} onClick={() => begin.mutate()}>
              {begin.isPending ? "Preparing…" : "Set up authenticator"}
            </button>
          )}

          {enrollment && (
            <div className="rounded-lg border border-line bg-surface-2/40 p-4">
              <div className="flex flex-col gap-5 sm:flex-row">
                {/* Scan target */}
                <div className="flex flex-col items-center gap-3">
                  <QRCode value={enrollment.provisioning_uri} size={168} />
                  <div className="text-center">
                    <div className="text-2xs uppercase tracking-wider text-faint">Can't scan? Setup key</div>
                    <div className="mt-1 select-all break-all font-mono text-xs text-accent">{enrollment.secret}</div>
                  </div>
                </div>

                {/* Confirm with two consecutive codes */}
                <div className="min-w-0 flex-1 space-y-3">
                  <div>
                    <p className="text-sm font-medium text-fg">Scan the QR with your authenticator</p>
                    <p className="mt-1 text-sm text-muted">
                      Google Authenticator, 1Password, Authy — any TOTP app. Then, to prove your device's clock is in
                      step, enter <span className="text-fg">two codes in a row</span>: the one showing now, then the next
                      one after it refreshes.
                    </p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Current code">
                      <input
                        className="input text-center tracking-[0.3em]"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="123456"
                        value={code}
                        onChange={(e) => setCode(clean(e.target.value))}
                      />
                    </Field>
                    <Field label="Next code">
                      <input
                        className="input text-center tracking-[0.3em]"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="654321"
                        value={nextCode}
                        onChange={(e) => setNextCode(clean(e.target.value))}
                      />
                    </Field>
                  </div>
                  {code.length === 6 && nextCode.length === 6 && code === nextCode && (
                    <p className="text-xs text-warn">Enter the next code after it changes — the two must differ.</p>
                  )}
                  <div className="flex items-center gap-2">
                    <button className="btn-primary" disabled={!codesReady || confirm.isPending} onClick={() => confirm.mutate()}>
                      {confirm.isPending ? "Verifying…" : "Activate two-factor"}
                    </button>
                    <button className="btn-ghost" disabled={confirm.isPending} onClick={resetEnrollment}>
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {status.data.confirmed && (
            <div className="flex items-center gap-3">
              <span className="text-sm text-muted">{status.data.recovery_codes_left} recovery codes remaining</span>
              <div className="flex-1" />
              <button
                className="btn-ghost"
                disabled={regen.isPending}
                onClick={() => {
                  if (window.confirm("Regenerate recovery codes? Your existing codes will stop working immediately.")) regen.mutate();
                }}
              >
                Regenerate codes
              </button>
              <div className="flex items-center gap-2">
                <span className="text-sm text-fg">Enabled</span>
                <Switch
                  checked
                  disabled={disable.isPending}
                  label="Disable two-factor authentication"
                  onChange={() => { setDisableCode(""); setDisabling(true); }}
                />
              </div>
            </div>
          )}

          {disabling && (
            <Modal
              title="Disable two-factor"
              icon={IconKey}
              onClose={() => { setDisabling(false); setDisableCode(""); }}
              footer={
                <>
                  <button className="btn-ghost" disabled={disable.isPending} onClick={() => { setDisabling(false); setDisableCode(""); }}>
                    Cancel
                  </button>
                  <button className="btn-danger" disabled={!disableReady || disable.isPending} onClick={() => disable.mutate()}>
                    {disable.isPending ? "Disabling…" : "Disable two-factor"}
                  </button>
                </>
              }
            >
              <p className="mb-3 text-sm text-muted">
                Turning off two-factor lowers your account security. Confirm with a code from your authenticator app — or
                a recovery code, if you no longer have the app.
              </p>
              <Field label="Authenticator or recovery code">
                <input
                  className="input text-center tracking-[0.2em]"
                  inputMode="text"
                  autoComplete="one-time-code"
                  placeholder="123456 or a1b2c-3d4e5"
                  autoFocus
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value)}
                />
              </Field>
              {disable.isError && (
                <div className="mt-3">
                  <ErrorNote message={problemDetail(disable.error, "That code didn't work. Try a fresh one.")} />
                </div>
              )}
            </Modal>
          )}

          {recoveryCodes && (
            <div className="mt-4 rounded-lg border border-warn/30 bg-warn/10 p-4">
              <p className="mb-2 text-sm text-warn">Save these recovery codes now — they are shown only once.</p>
              {/* Say what they are for. A list of codes with no explanation is a
                  list of codes people lose: the one moment you need them is the
                  one moment you cannot come back here to find out. */}
              <p className="mb-3 text-xs text-muted">
                Each code works once, anywhere a code from your authenticator app is asked for: signing in, and turning
                two-factor off. They are how you get back in if you lose the app — keep them somewhere other than the
                phone the app is on.
              </p>
              <div className="grid grid-cols-2 gap-2 font-mono text-sm text-fg">
                {recoveryCodes.map((c) => (
                  <div key={c} className="rounded bg-surface px-2 py-1">{c}</div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
