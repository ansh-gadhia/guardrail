import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { Enrollment, MFAStatus } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { ErrorNote, Field, Spinner, cn } from "@/components/ui";
import { IconShield, IconLock, IconKey, IconCheck } from "@/components/icons";
import { PasswordStrength, scorePassword, MIN_PASSWORD_LEN } from "@/components/PasswordStrength";
import { QRCode } from "@/components/QRCode";

/* The first-run flow. A person whose password was typed by someone else has one
   job before anything else: replace it. Two-factor is offered right after —
   this is the moment someone is already thinking about their credentials — but
   it is genuinely optional, because a nag that cannot be dismissed just teaches
   people to click past security prompts.

   This deliberately renders instead of the app rather than as a modal over it:
   there is nothing useful to do behind it, and a dismissible-looking overlay
   would misrepresent that. */
export function FirstRunPage() {
  const principal = useAuth((s) => s.principal);
  const [step, setStep] = useState<"password" | "mfa">(
    principal?.must_change_password ? "password" : "mfa",
  );

  return (
    <div className="min-h-screen bg-surface-2/40 px-4 py-10">
      <div className="mx-auto w-full max-w-lg">
        <header className="mb-7 flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-xl accent-grad text-white shadow-sm ring-1 ring-white/20">
            <IconShield size={19} />
          </span>
          <div>
            <div className="text-sm font-semibold text-fg">GuardRail</div>
            <div className="text-2xs uppercase tracking-widest text-faint">Privileged Access</div>
          </div>
        </header>

        <Stepper step={step} />

        {step === "password" ? (
          <SetPasswordStep onDone={() => setStep("mfa")} />
        ) : (
          <AddMfaStep />
        )}
      </div>
    </div>
  );
}

function Stepper({ step }: { step: "password" | "mfa" }) {
  const items = [
    { id: "password", label: "New password" },
    { id: "mfa", label: "Two-factor" },
  ];
  return (
    <ol className="mb-5 flex items-center gap-2">
      {items.map((it, i) => {
        const done = step === "mfa" && it.id === "password";
        const active = step === it.id;
        return (
          <li key={it.id} className="flex flex-1 items-center gap-2">
            <span
              className={cn(
                "grid h-6 w-6 shrink-0 place-items-center rounded-full text-2xs font-semibold ring-1 ring-inset transition",
                done
                  ? "bg-success/15 text-success ring-success/30"
                  : active
                    ? "bg-accent-soft text-accent ring-accent/30"
                    : "bg-surface-3 text-faint ring-line",
              )}
            >
              {done ? <IconCheck size={12} /> : i + 1}
            </span>
            <span className={cn("text-xs", active || done ? "text-fg" : "text-faint")}>{it.label}</span>
            {i === 0 && <span className="h-px flex-1 bg-line" />}
          </li>
        );
      })}
    </ol>
  );
}

function Card({ title, subtitle, icon: Icon, children }: {
  title: string;
  subtitle: string;
  icon: typeof IconLock;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-2xl border border-line bg-surface shadow-md">
      <div className="border-b border-line px-5 py-4">
        <div className="flex items-center gap-3">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
            <Icon size={16} />
          </span>
          <div>
            <h1 className="text-base font-semibold text-fg">{title}</h1>
            <p className="text-xs text-muted">{subtitle}</p>
          </div>
        </div>
      </div>
      <div className="px-5 py-4">{children}</div>
    </div>
  );
}

function SetPasswordStep({ onDone }: { onDone: () => void }) {
  const changePassword = useAuth((s) => s.changePassword);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");

  const strength = scorePassword(next);
  const mismatch = !!confirm && next !== confirm;
  const canSubmit = current.length > 0 && strength.acceptable && next === confirm && next !== current;

  const save = useMutation({
    mutationFn: async () => changePassword(current, next),
    onSuccess: onDone,
  });

  return (
    <Card
      title="Choose your password"
      subtitle="Your account was created with a temporary password. Replace it to continue."
      icon={IconLock}
    >
      {save.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(save.error, "Could not set your password")} />
        </div>
      )}
      <Field label="Temporary password" hint="The one you were given.">
        <input
          className="input"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
      </Field>
      <Field label="New password" hint={`At least ${MIN_PASSWORD_LEN} characters.`}>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
      </Field>
      <PasswordStrength value={next} />
      <Field label="Confirm new password">
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && canSubmit && save.mutate()}
        />
      </Field>
      {mismatch && (
        <div className="mb-4 rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-xs text-danger">
          Passwords do not match.
        </div>
      )}
      {!!next && next === current && (
        <div className="mb-4 rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-xs text-danger">
          Pick something different from your temporary password.
        </div>
      )}
      <button className="btn-primary w-full" disabled={!canSubmit || save.isPending} onClick={() => save.mutate()}>
        {save.isPending ? "Saving…" : "Set password and continue"}
      </button>
    </Card>
  );
}

function AddMfaStep() {
  const skipFirstRun = useAuth((s) => s.skipFirstRun);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [code, setCode] = useState("");
  const [nextCode, setNextCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const clean = (v: string) => v.replace(/\D/g, "").slice(0, 6);
  const codesReady = code.length === 6 && nextCode.length === 6 && code !== nextCode;

  // If the account already has MFA (rare here, but possible), don't pretend to
  // offer it.
  const status = useQuery<MFAStatus>({
    queryKey: ["mfa"],
    queryFn: async () => (await api.get<MFAStatus>("/mfa")).data,
    staleTime: 0,
  });

  const begin = useMutation({
    mutationFn: async () => (await api.post<Enrollment>("/mfa/totp/enroll", {})).data,
    onSuccess: (d) => { setEnrollment(d); setError(null); },
    onError: (e) => setError(problemDetail(e, "Could not start enrollment")),
  });
  const confirm = useMutation({
    mutationFn: async () =>
      (await api.post<{ recovery_codes: string[] }>("/mfa/totp/confirm", { code, next_code: nextCode })).data,
    onSuccess: (d) => { setRecoveryCodes(d.recovery_codes); setError(null); },
    onError: (e) => setError(problemDetail(e, "Those codes didn't match. Wait for a fresh code and try again.")),
  });

  if (status.isLoading) {
    return (
      <Card title="Two-factor authentication" subtitle="Checking your account…" icon={IconKey}>
        <div className="flex items-center gap-2 py-4 text-sm text-muted"><Spinner /> Loading…</div>
      </Card>
    );
  }

  if (recoveryCodes) {
    return (
      <Card
        title="Save your recovery codes"
        subtitle="Each code works once if you lose your authenticator. This is the only time they're shown."
        icon={IconKey}
      >
        <ul className="mb-4 grid grid-cols-2 gap-2">
          {recoveryCodes.map((c) => (
            <li key={c} className="rounded-lg bg-surface-2 px-3 py-2 text-center font-mono text-sm text-fg">{c}</li>
          ))}
        </ul>
        <button className="btn-primary w-full" onClick={skipFirstRun}>
          I've saved them — take me in
        </button>
      </Card>
    );
  }

  if (status.data?.confirmed) {
    return (
      <Card title="You're all set" subtitle="Two-factor is already active on this account." icon={IconCheck}>
        <button className="btn-primary w-full" onClick={skipFirstRun}>Continue to GuardRail</button>
      </Card>
    );
  }

  return (
    <Card
      title="Add two-factor authentication"
      subtitle="A password alone protects every device this console reaches. A second factor is the difference between a stolen password and a breach."
      icon={IconKey}
    >
      {error && <div className="mb-4"><ErrorNote message={error} /></div>}

      {!enrollment ? (
        <div className="space-y-3">
          <button className="btn-primary w-full" disabled={begin.isPending} onClick={() => begin.mutate()}>
            {begin.isPending ? "Starting…" : "Set up two-factor now"}
          </button>
          <button className="btn-ghost w-full" onClick={skipFirstRun}>
            I'll do this later
          </button>
          <p className="text-center text-2xs text-faint">
            You can turn it on any time from Account → Two-factor.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex justify-center rounded-xl border border-line bg-white p-3">
            <QRCode value={enrollment.provisioning_uri} size={168} />
          </div>
          <p className="text-xs text-muted">
            Scan with your authenticator app, then enter two codes in a row so we know the clock is in sync.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Current code">
              <input className="input font-mono" inputMode="numeric" value={code} onChange={(e) => setCode(clean(e.target.value))} placeholder="123456" />
            </Field>
            <Field label="Next code" hint="Wait for it to change.">
              <input className="input font-mono" inputMode="numeric" value={nextCode} onChange={(e) => setNextCode(clean(e.target.value))} placeholder="654321" />
            </Field>
          </div>
          <button className="btn-primary w-full" disabled={!codesReady || confirm.isPending} onClick={() => confirm.mutate()}>
            {confirm.isPending ? "Verifying…" : "Turn on two-factor"}
          </button>
          <button className="btn-ghost w-full" onClick={skipFirstRun}>I'll do this later</button>
        </div>
      )}
    </Card>
  );
}
