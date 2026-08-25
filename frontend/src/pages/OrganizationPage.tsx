import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import { absLocal } from "@/lib/dates";
import { isValidEntry, verdictFor } from "@/lib/net";
import type { NetworkRule, OrgSettings } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { BrandSeal } from "@/components/brand";
import { IntegrityPanel } from "@/components/AuditIntegrity";
import { toast } from "@/components/Toast";
import {
  PageHero, HeroStat, Panel, Field, Badge, Button, Input, Switch, Skeleton, ErrorNote, cn,
} from "@/components/ui";
import {
  IconSettings, IconBrush, IconNetwork, IconArchive, IconUpload,
  IconTrash, IconPlus, IconCheck, IconAlert, IconShield, IconGlobe,
} from "@/components/icons";

/* ---------------------------------------------------------------------------
   Organization — the policies that apply to everybody in the tenant rather than
   to one person: how the console is branded, who may reach it, how long the
   evidence is kept, and whether the ledger holding that evidence is intact.

   Each panel saves on its own. A single page-level "Save" would mean changing a
   logo also applied whatever half-finished firewall rules were on screen, and
   these four things are not one decision.
--------------------------------------------------------------------------- */

export function OrganizationPage() {
  const has = useAuth((s) => s.has);
  const isSuper = useAuth((s) => s.principal?.is_super_admin ?? false);
  const canWrite = isSuper || has("org:write");

  const settings = useQuery<OrgSettings>({
    queryKey: ["org-settings"],
    queryFn: async () => (await api.get<OrgSettings>("/settings")).data,
  });

  const s = settings.data;

  return (
    <div className="space-y-5">
      <PageHero
        icon={IconSettings}
        eyebrow="Policy"
        title="Organization"
        subtitle="How this console presents itself, who may reach it, and how long it keeps what it records."
        stats={
          s && (
            <>
              <HeroStat
                icon={IconBrush}
                label="Branding"
                value={s.branding.configured ? s.branding.client_name || "Client logo" : "GuardRail default"}
                tone={s.branding.configured ? "accent" : "neutral"}
              />
              <HeroStat
                icon={IconNetwork}
                label="Address policy"
                value={policySummary(s)}
                tone={s.network_policy.allowlist_enabled || s.network_policy.blocklist_enabled ? "success" : "neutral"}
              />
              <HeroStat
                icon={IconArchive}
                label="Recordings kept"
                value={s.recording_retention_days === 0 ? "Indefinitely" : `${s.recording_retention_days} days`}
                tone={s.recording_retention_days === 0 ? "warn" : "neutral"}
              />
            </>
          )
        }
      />

      {settings.isError && <ErrorNote message="Couldn't load organization settings. Try reloading." />}
      {settings.isLoading && <Skeleton className="h-64 rounded-xl" />}

      {s && (
        <>
          <BrandingPanel settings={s} canWrite={canWrite} />
          <NetworkPanel settings={s} canWrite={canWrite} />
          <RetentionPanel settings={s} canWrite={canWrite} />
          {(isSuper || has("log:read")) && <IntegrityPanel />}
          {s.updated_at && (
            <p className="px-1 text-2xs text-faint">
              Last changed {absLocal(s.updated_at)}
              {s.updated_by ? ` by ${s.updated_by}` : ""}.
            </p>
          )}
        </>
      )}
    </div>
  );
}

function policySummary(s: OrgSettings): string {
  const on: string[] = [];
  if (s.network_policy.allowlist_enabled) on.push(`${s.network_policy.allowlist.length} allowed`);
  if (s.network_policy.blocklist_enabled) on.push(`${s.network_policy.blocklist.length} blocked`);
  return on.length ? on.join(" · ") : "Open to any address";
}

/* ---- Branding -------------------------------------------------------------- */

const MAX_LOGO_BYTES = 280 * 1024;

function BrandingPanel({ settings, canWrite }: { settings: OrgSettings; canWrite: boolean }) {
  const qc = useQueryClient();
  const [name, setName] = useState(settings.branding.client_name);
  const [logo, setLogo] = useState(settings.branding.client_logo);
  const [enabled, setEnabled] = useState(settings.branding.enabled);
  const [fileError, setFileError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const dirty =
    name !== settings.branding.client_name ||
    logo !== settings.branding.client_logo ||
    enabled !== settings.branding.enabled;

  // What the rail will look like once this is saved — the real component the
  // sidebar renders, not a drawing of it.
  const preview = {
    client_name: name.trim(),
    client_logo: logo,
    configured: enabled && (name.trim() !== "" || logo !== ""),
  };

  const save = useMutation({
    mutationFn: async () =>
      (await api.put<OrgSettings>("/settings/branding", {
        client_name: name.trim(),
        client_logo: logo,
        enabled,
      })).data,
    onSuccess: (next) => {
      qc.setQueryData(["org-settings"], next);
      qc.invalidateQueries({ queryKey: ["branding"] });
      toast.success("Branding saved");
    },
    onError: (e) => toast.error(problemDetail(e, "The branding could not be saved.")),
  });

  const takeFile = (file: File | undefined) => {
    setFileError(null);
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setFileError("That file isn't an image. Use a PNG, JPEG or SVG.");
      return;
    }
    if (file.size > MAX_LOGO_BYTES) {
      setFileError(`That image is ${Math.round(file.size / 1024)} KB. Use one under 280 KB.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setLogo(String(reader.result ?? ""));
    reader.onerror = () => setFileError("That file couldn't be read. Try another one.");
    reader.readAsDataURL(file);
  };

  return (
    <Panel
      icon={IconBrush}
      title="Console branding"
      subtitle="Put the client's identity under the GuardRail wordmark, in the sidebar and the footer. Give a logo, a name, or both — whatever you set is what shows."
      actions={
        <div className="flex items-center gap-3">
          <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
            <Switch checked={enabled} onChange={setEnabled} disabled={!canWrite} label="Show client branding" />
            <span>Show client branding</span>
          </label>
        </div>
      }
    >
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_240px]">
        <div className="space-y-4">
          <Field
            label="Client name"
            hint="On its own it becomes the wordmark. Alongside a logo it sits beneath it."
          >
            <Input
              value={name}
              maxLength={120}
              disabled={!canWrite}
              placeholder="e.g. Acme Bank"
              onChange={(e) => setName(e.target.value)}
            />
          </Field>

          <Field label="Client logo" hint="PNG, JPEG or SVG, under 280 KB. Stored with this organization, not fetched from anywhere.">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                if (canWrite) setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                if (canWrite) takeFile(e.dataTransfer.files?.[0]);
              }}
              className={cn(
                "flex items-center gap-4 rounded-xl border border-dashed px-4 py-4 transition-colors",
                dragging ? "border-accent/60 bg-accent/5" : "border-line bg-surface-2/40",
              )}
            >
              {logo ? (
                <img
                  src={logo}
                  alt="Client logo"
                  className="h-10 w-auto max-w-[140px] shrink-0 object-contain"
                />
              ) : (
                <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-surface-3 text-faint">
                  <IconUpload size={18} />
                </span>
              )}
              <div className="min-w-0 flex-1">
                <p className="text-xs text-muted">
                  {logo ? "Logo ready to save." : "Drop an image here, or choose a file."}
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <Button variant="ghost" size="sm" disabled={!canWrite} onClick={() => fileInput.current?.click()}>
                    <IconUpload size={14} /> Choose file
                  </Button>
                  {logo && (
                    <Button variant="ghost" size="sm" disabled={!canWrite} onClick={() => setLogo("")}>
                      <IconTrash size={14} /> Remove logo
                    </Button>
                  )}
                </div>
              </div>
              <input
                ref={fileInput}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => takeFile(e.target.files?.[0])}
              />
            </div>
          </Field>
          {fileError && <p className="text-xs text-danger">{fileError}</p>}

          <div className="flex items-center gap-2 pt-1">
            <Button
              variant="primary"
              disabled={!canWrite || !dirty || save.isPending}
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Saving…" : "Save branding"}
            </Button>
            {dirty && (
              <Button
                variant="ghost"
                disabled={save.isPending}
                onClick={() => {
                  setName(settings.branding.client_name);
                  setLogo(settings.branding.client_logo);
                  setEnabled(settings.branding.enabled);
                  setFileError(null);
                }}
              >
                Discard changes
              </Button>
            )}
          </div>
        </div>

        {/* The signature of this page: the sidebar rail itself, live. */}
        <div className="lg:sticky lg:top-2">
          <div className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-faint">Sidebar preview</div>
          <div className="overflow-hidden rounded-xl border border-line bg-surface-2/50 pb-2 pt-4">
            <div className="flex items-center gap-2.5 px-5 pb-3">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl accent-grad text-white shadow-glow-sm ring-1 ring-white/20">
                <IconShield size={18} />
              </span>
              <div>
                <div className="font-display text-[15px] font-semibold leading-none tracking-tight text-fg">GuardRail</div>
                <div className="mt-1 text-2xs uppercase tracking-wider text-faint">Privileged Access Management</div>
              </div>
            </div>
            <BrandSeal branding={preview} compact />
          </div>
          <p className="mt-2 text-2xs leading-relaxed text-faint">
            {preview.configured
              ? "Everyone signing in to this organization sees this rail."
              : "With neither a logo nor a name set, the console keeps its default: engineered by Virtual Galaxy."}
          </p>
        </div>
      </div>
    </Panel>
  );
}

/* ---- Network policy -------------------------------------------------------- */

function NetworkPanel({ settings, canWrite }: { settings: OrgSettings; canWrite: boolean }) {
  const qc = useQueryClient();
  const original = settings.network_policy;
  const [allowOn, setAllowOn] = useState(original.allowlist_enabled);
  const [allow, setAllow] = useState<NetworkRule[]>(original.allowlist);
  const [blockOn, setBlockOn] = useState(original.blocklist_enabled);
  const [block, setBlock] = useState<NetworkRule[]>(original.blocklist);
  const [probe, setProbe] = useState("");

  const draft = {
    allowlist_enabled: allowOn,
    allowlist: allow,
    blocklist_enabled: blockOn,
    blocklist: block,
  };

  const dirty = JSON.stringify(draft) !== JSON.stringify(original);
  const yourIP = settings.your_ip ?? "";
  const self = useMemo(() => verdictFor(draft, yourIP), [draft, yourIP]);
  const emptyAllowlist = allowOn && allow.filter((r) => r.cidr.trim()).length === 0;
  const malformed = [...allow, ...block].some((r) => r.cidr.trim() !== "" && !isValidEntry(r.cidr));
  const blocked = !self.allowed || emptyAllowlist || malformed;

  const save = useMutation({
    mutationFn: async () =>
      (await api.put<OrgSettings>("/settings/network-policy", {
        allowlist_enabled: allowOn,
        allowlist: allow.filter((r) => r.cidr.trim()),
        blocklist_enabled: blockOn,
        blocklist: block.filter((r) => r.cidr.trim()),
      })).data,
    onSuccess: (next) => {
      qc.setQueryData(["org-settings"], next);
      setAllow(next.network_policy.allowlist);
      setBlock(next.network_policy.blocklist);
      toast.success("Address policy saved");
    },
    onError: (e) => toast.error(problemDetail(e, "The address policy could not be saved.")),
  });

  const probeVerdict = probe.trim() ? verdictFor(draft, probe.trim()) : null;

  return (
    <Panel
      icon={IconNetwork}
      title="Source address policy"
      subtitle="Which addresses may reach this console. The two lists work independently — switch on only what you need."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        <RuleList
          tone="allow"
          title="Allowlist"
          caption="Only these addresses may sign in."
          emptyMessage="No addresses yet. While the allowlist is on, an empty list refuses everybody."
          enabled={allowOn}
          onToggle={setAllowOn}
          rules={allow}
          onChange={setAllow}
          canWrite={canWrite}
        />
        <RuleList
          tone="block"
          title="Blocklist"
          caption="These addresses are refused, even if the allowlist permits them."
          emptyMessage="No addresses yet. Add the ones you never want to hear from."
          enabled={blockOn}
          onToggle={setBlockOn}
          rules={block}
          onChange={setBlock}
          canWrite={canWrite}
        />
      </div>

      {/* Your own address, judged against the DRAFT. Guessing your public
          address is exactly the thing people get wrong, and the mistake costs
          you the console. */}
      <div
        className={cn(
          "mt-4 flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-xl border px-4 py-3 text-xs transition-colors",
          self.allowed
            ? "border-line bg-surface-2/50 text-muted"
            : "border-danger/35 bg-danger/10 text-danger",
        )}
      >
        <span className={cn("grid h-6 w-6 shrink-0 place-items-center rounded-lg", self.allowed ? "bg-success/12 text-success" : "bg-danger/15 text-danger")}>
          {self.allowed ? <IconCheck size={13} /> : <IconAlert size={13} />}
        </span>
        <span>
          You are connected from <span className="font-mono text-fg">{yourIP || "an unknown address"}</span>.
        </span>
        <span className="font-medium">
          {self.allowed
            ? "This policy keeps you signed in."
            : self.reason === "blocklisted"
              ? "Your own address is on the blocklist — saving is refused."
              : "Your own address is not on the allowlist — saving is refused."}
        </span>
      </div>

      {malformed && (
        <p className="mt-2 text-xs text-danger">
          One of the entries isn't a valid address or range. Use a form like <span className="font-mono">10.0.0.0/8</span> or{" "}
          <span className="font-mono">203.0.113.9</span>.
        </p>
      )}

      <div className="mt-4 flex flex-wrap items-end gap-3 border-t border-line pt-4">
        <div className="min-w-[200px] flex-1">
          <Field label="Try an address" hint="Checks it against the lists above before you save.">
            <Input
              value={probe}
              placeholder="203.0.113.9"
              className="font-mono"
              onChange={(e) => setProbe(e.target.value)}
            />
          </Field>
        </div>
        <div className="pb-1">
          {probeVerdict ? (
            <Badge tone={probeVerdict.allowed ? "success" : "danger"}>
              <IconGlobe size={12} />
              {probeVerdict.allowed
                ? "Allowed in"
                : probeVerdict.reason === "blocklisted"
                  ? "Refused — on the blocklist"
                  : "Refused — not on the allowlist"}
            </Badge>
          ) : (
            <span className="text-2xs text-faint">Nothing to check yet.</span>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2 pb-1">
          {dirty && (
            <Button
              variant="ghost"
              disabled={save.isPending}
              onClick={() => {
                setAllowOn(original.allowlist_enabled);
                setAllow(original.allowlist);
                setBlockOn(original.blocklist_enabled);
                setBlock(original.blocklist);
              }}
            >
              Discard changes
            </Button>
          )}
          <Button variant="primary" disabled={!canWrite || !dirty || blocked || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save address policy"}
          </Button>
        </div>
      </div>
    </Panel>
  );
}

const TONE_STYLES = {
  allow: {
    rail: "border-l-success/70",
    chip: "bg-success/12 text-success ring-success/25",
    header: "text-success",
  },
  block: {
    rail: "border-l-danger/70",
    chip: "bg-danger/12 text-danger ring-danger/25",
    header: "text-danger",
  },
} as const;

function RuleList({
  tone,
  title,
  caption,
  emptyMessage,
  enabled,
  onToggle,
  rules,
  onChange,
  canWrite,
}: {
  tone: "allow" | "block";
  title: string;
  caption: string;
  emptyMessage: string;
  enabled: boolean;
  onToggle: (next: boolean) => void;
  rules: NetworkRule[];
  onChange: (next: NetworkRule[]) => void;
  canWrite: boolean;
}) {
  const styles = TONE_STYLES[tone];
  const set = (i: number, patch: Partial<NetworkRule>) =>
    onChange(rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));

  return (
    <div
      className={cn(
        "rounded-xl border border-line bg-surface-2/40 transition-opacity",
        !enabled && "opacity-65",
      )}
    >
      <header className="flex items-start justify-between gap-3 border-b border-line px-3.5 py-2.5">
        <div className="min-w-0">
          <h3 className={cn("font-display text-xs font-semibold uppercase tracking-[0.14em]", styles.header)}>{title}</h3>
          <p className="mt-0.5 text-2xs text-faint">{caption}</p>
        </div>
        <Switch checked={enabled} onChange={onToggle} disabled={!canWrite} label={`${title} enabled`} />
      </header>

      <div className="space-y-1.5 p-3">
        {rules.length === 0 ? (
          <p className="px-1 py-3 text-2xs text-faint">{emptyMessage}</p>
        ) : (
          rules.map((rule, i) => {
            const bad = rule.cidr.trim() !== "" && !isValidEntry(rule.cidr);
            return (
              <div key={i} className={cn("flex items-center gap-2 border-l-2 pl-2.5", styles.rail)}>
                <Input
                  value={rule.cidr}
                  invalid={bad}
                  disabled={!canWrite}
                  placeholder="10.0.0.0/8"
                  className="w-[46%] font-mono text-xs"
                  onChange={(e) => set(i, { cidr: e.target.value })}
                />
                <Input
                  value={rule.note ?? ""}
                  disabled={!canWrite}
                  placeholder="what this is"
                  className="flex-1 text-xs"
                  onChange={(e) => set(i, { note: e.target.value })}
                />
                <button
                  type="button"
                  disabled={!canWrite}
                  aria-label="Remove this entry"
                  className="rounded-lg p-1.5 text-faint transition-colors hover:bg-danger/10 hover:text-danger disabled:opacity-40"
                  onClick={() => onChange(rules.filter((_, idx) => idx !== i))}
                >
                  <IconTrash size={14} />
                </button>
              </div>
            );
          })
        )}
        <Button
          variant="ghost"
          size="sm"
          disabled={!canWrite}
          onClick={() => onChange([...rules, { cidr: "", note: "" }])}
        >
          <IconPlus size={14} /> Add address
        </Button>
      </div>
    </div>
  );
}

/* ---- Retention ------------------------------------------------------------- */

function RetentionPanel({ settings, canWrite }: { settings: OrgSettings; canWrite: boolean }) {
  const qc = useQueryClient();
  const [days, setDays] = useState(String(settings.recording_retention_days));
  const parsed = Number(days);
  const valid = /^\d+$/.test(days.trim()) && parsed >= 0 && parsed <= 3650;
  const dirty = valid && parsed !== settings.recording_retention_days;
  const shortening = valid && parsed > 0 && (settings.recording_retention_days === 0 || parsed < settings.recording_retention_days);

  const save = useMutation({
    mutationFn: async () => (await api.put<OrgSettings>("/settings/recording-retention", { days: parsed })).data,
    onSuccess: (next) => {
      qc.setQueryData(["org-settings"], next);
      toast.success(next.recording_retention_days === 0 ? "Recordings will be kept indefinitely" : `Recordings kept for ${next.recording_retention_days} days`);
    },
    onError: (e) => toast.error(problemDetail(e, "The retention policy could not be saved.")),
  });

  return (
    <Panel
      icon={IconArchive}
      title="Recording retention"
      subtitle="How long session recordings are kept before they are deleted for good."
    >
      <div className="flex flex-wrap items-end gap-4">
        <div className="w-40">
          <Field label="Days" hint="0 keeps recordings indefinitely.">
            <Input
              value={days}
              inputMode="numeric"
              disabled={!canWrite}
              invalid={!valid}
              className="font-mono"
              onChange={(e) => setDays(e.target.value)}
            />
          </Field>
        </div>
        <div className="pb-1 text-xs text-muted">
          <div>
            This deployment's <span className="font-mono text-2xs">.env</span> asks for{" "}
            <span className="font-medium text-fg">{settings.configured_default_days} days</span>.
          </div>
          <div className="mt-0.5 text-2xs text-faint">
            {settings.configured_default_days === settings.recording_retention_days
              ? "The stored policy matches it."
              : "The stored policy above is what is in force — the file only seeds organizations that have never set one."}
          </div>
        </div>
        <div className="ml-auto pb-1">
          <Button variant="primary" disabled={!canWrite || !dirty || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save retention"}
          </Button>
        </div>
      </div>

      {shortening && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2">
          <IconAlert size={15} className="mt-0.5 shrink-0 text-warn" />
          <p className="text-xs text-fg">
            Shortening retention applies to recordings you already hold. The next sweep deletes anything older than{" "}
            {parsed} days, and deleted recordings do not come back.
          </p>
        </div>
      )}
      {!valid && <p className="mt-2 text-xs text-danger">Enter a whole number of days between 0 and 3650.</p>}
    </Panel>
  );
}
