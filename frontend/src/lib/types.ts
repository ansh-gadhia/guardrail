// API response types mirroring the Go delivery layer.

export interface Principal {
  user_id: string;
  organization_id: string;
  email: string;
  username: string;
  is_super_admin: boolean;
  roles: string[];
  permissions: string[];
  // True while this account still has the temporary password an admin set for
  // it. The console forces a change before letting the person do anything else.
  must_change_password: boolean;
  // Rank in the approval hierarchy: the highest of this person's roles. They
  // can decide requests from anybody strictly below it.
  approval_level: number;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_at: string;
  principal: Principal;
}

export interface MFAChallenge {
  mfa_required: true;
  mfa_token: string;
}

export type LoginResult = TokenResponse | MFAChallenge;

export function isMFAChallenge(r: LoginResult): r is MFAChallenge {
  return (r as MFAChallenge).mfa_required === true;
}

// RecordingKind is what a recorded session captures. These match the backend's
// assets.Record* constants and the recording_artifacts.kind column, so a policy
// and the evidence it produces are named the same thing throughout.
export type RecordingKind = "transcript" | "video" | "desktop";

// Labels and rationale for each capture, so the console explains the choice
// rather than showing three bare words.
export const RECORDING_KIND_INFO: Record<RecordingKind, { label: string; detail: string }> = {
  transcript: {
    label: "Transcript",
    detail: "The text the device printed, with the original timing. Small, searchable, and exact.",
  },
  video: {
    label: "Video",
    detail: "The session as the operator saw it, replayable frame by frame. Much larger than a transcript.",
  },
  desktop: {
    label: "Desktop replay",
    detail: "The desktop session as a Guacamole stream, replayed in the console.",
  },
};

export interface Device {
  id: string;
  name: string;
  description: string;
  vendor: string;
  device_type: string;
  host: string;
  port: number;
  scheme: string;
  verify_tls: boolean;
  tags: string[];
  status: string;
  url: string;
  // Whether a credential is bound to this device (server-injected on connect).
  has_credential: boolean;
  // Break-glass: allow connecting with no bound credential (no injection).
  allow_unmanaged: boolean;
  // "shared" — one vaulted login for everyone entitled. "per_user" — each
  // person is injected with their own named account ON THE DEVICE, so the
  // device's own logs record who was actually there.
  credential_mode: CredentialMode;
  // Connecting needs a decision from somebody who outranks the requester.
  requires_approval: boolean;
  // How many distinct approvals a gated connect needs (the two-person rule).
  min_approvals: number;
  // Whether sessions to this device are recorded at all.
  record_sessions: boolean;
  // What a recorded session captures, already resolved against the protocol:
  // "transcript" (terminal output), "video" (screencast frames), "desktop" (a
  // Guacamole dump). Empty when record_sessions is false.
  recording_kinds: RecordingKind[];
  // The kinds this device's protocol could capture. A terminal offers a real
  // choice; a desktop or a web device has exactly one.
  supported_recording_kinds: RecordingKind[];
  // How a session to this device is delivered: "proxy" re-serves the device's
  // own UI through GuardRail, "isolated" renders it in a browser on the server
  // and streams pixels. Recording only exists under "isolated".
  delivery_mode: string;
  // Minutes of inactivity after which a session to this device is ended.
  // 0 means sessions are never ended for being idle.
  idle_timeout_minutes: number;
  // Whether the current viewer may change record_sessions. The server decides
  // this (creator or super admin only) and tells us, so the console can't
  // disagree with what the API will accept.
  can_set_recording: boolean;
  // When the device was registered (UTC RFC3339).
  created_at?: string;
  // Liveness, maintained by the background health poller.
  health?: DeviceHealth;
  // The credential the device owns (metadata only, never the secret). Present on
  // device detail responses; absent on list responses to avoid N+1 lookups.
  credential?: DeviceCredential;
  // Asset groups the device belongs to. Present on device detail responses only,
  // for the same reason as `credential`.
  group_ids?: string[];
}

// DeviceHealth is the reachability state of a device's management endpoint.
export interface DeviceHealth {
  status: "online" | "offline" | "unknown";
  checked_at?: string;
  latency_ms?: number;
}

// DeviceCredential is the non-secret projection of a device's owned credential.
export interface DeviceCredential {
  username: string;
  injection: string; // basic | header | form | none
  has_secret: boolean;
}

// Injection methods a device credential can use. "No auth" isn't a method here —
// a device with no credential (or break-glass) covers that case.
// How a device's secret is presented to it. This mirrors the server's
// injectionsByScheme: a method that cannot authenticate a protocol is not a
// preference, and the API refuses it (422).
//
// Offering the web methods for every device is how a real SSH server was
// registered with HTTP Basic auth — the console accepted it, the vault stored it,
// and the failure waited until someone pressed Connect.
export interface InjectionMethod {
  value: string;
  label: string;
  hint: string;
}

const WEB_INJECTION: InjectionMethod[] = [
  { value: "basic", label: "HTTP Basic auth", hint: "username + password sent as an Authorization: Basic header" },
  { value: "header", label: "Authorization header", hint: 'the secret is the full header value, e.g. "Bearer <token>"' },
  {
    value: "form",
    label: "Login form fill",
    // Form fill needs a browser to type into the page, and the only browser that
    // may ever see the secret is the one on the server. That is isolated
    // delivery — under the reverse proxy the device is refused rather than
    // connected to without its credential.
    hint: "a browser on the server types the credential into the device's login page — requires isolated delivery",
  },
];

const SSH_INJECTION: InjectionMethod[] = [
  { value: "ssh-password", label: "Password", hint: "the account's password, used for the SSH login" },
  {
    value: "ssh-key",
    label: "Private key",
    hint: "the secret is the PEM private key itself; encrypted (passphrase-protected) keys are not supported",
  },
];

const DESKTOP_INJECTION: InjectionMethod[] = [
  {
    value: "password",
    label: "Password",
    // The username format is the usual cause of "it logged in as the wrong user":
    // a bare name makes Windows NLA try the wrong domain, authentication silently
    // fails, and RDP drops to the interactive login showing the last user. A local
    // account needs .\ , a domain account needs DOMAIN\ .
    hint: "username + password, sent to the desktop by the server. For a local Windows account use .\\Administrator; for a domain account use DOMAIN\\user",
  },
];

const TELNET_INJECTION: InjectionMethod[] = [
  {
    value: "password",
    label: "Password",
    hint: "username + password, typed at the device's login prompt by the server",
  },
];

// This mirrors the server's vault.injectionsByScheme. The two are checked by
// nothing, so they are the pair to keep in step when a protocol is added.
const INJECTION_BY_SCHEME: Record<string, InjectionMethod[]> = {
  https: WEB_INJECTION,
  http: WEB_INJECTION,
  ssh: SSH_INJECTION,
  rdp: DESKTOP_INJECTION,
  vnc: DESKTOP_INJECTION,
  // Telnet authenticates with a password and nothing else. It was missing here
  // while being offered in the protocol picker, so it fell to the fallback below
  // and was given the WEB methods: choosing Telnet showed HTTP Basic / header /
  // form fill, the form defaulted to "basic", and the API — which does know
  // better — refused the whole device with an injection mismatch. Adding a telnet
  // device with a credential could not succeed.
  telnet: TELNET_INJECTION,
};

// injectionMethodsFor returns the methods that can authenticate a protocol, in
// the order to offer them.
//
// An unknown scheme gets NOTHING, exactly as the server's InjectionsFor does.
// The previous fallback handed back the web set because the console "must render
// something" — but rendering something is not the same as rendering the truth. It
// meant any protocol not listed above silently offered methods the API rejects,
// which is the bug telnet hit, and the same one vault.go's comment records
// against SSH before it. An empty list renders no picker, which is honest and
// visible; a wrong list renders a form that cannot be submitted and blames the
// operator for it.
export function injectionMethodsFor(scheme: string): InjectionMethod[] {
  return INJECTION_BY_SCHEME[scheme] ?? [];
}

// defaultInjectionFor is what a form lands on for a protocol. "none" for a
// protocol with no methods, mirroring the server's DefaultInjectionFor — it means
// "there is no secret to inject", which is coherent for anything.
export function defaultInjectionFor(scheme: string): string {
  return injectionMethodsFor(scheme)[0]?.value ?? "none";
}

// INJECTION_METHODS is the web set, kept for surfaces that are web-only.
export const INJECTION_METHODS = WEB_INJECTION;

// MIXED_INJECTION is what to offer when the protocol genuinely is not known at
// bind time — an asset group holds devices of several schemes, so the method is
// taken as given here and checked per device when it is actually used.
//
// Written out rather than derived from the per-scheme lists, because two entries
// share a value: SSH's password is "ssh-password" and a desktop's is "password",
// and a de-duplicated union would offer "Password" twice with no way to tell
// which was which. The labels name the protocol for the same reason. Where the
// scheme IS known, use injectionMethodsFor — offering a method the device cannot
// accept produces a binding that looks configured and refuses every connection.
export const MIXED_INJECTION: InjectionMethod[] = [
  { value: "ssh-password", label: "SSH password", hint: "the account's password, used for the SSH login" },
  { value: "ssh-key", label: "SSH private key", hint: "the secret is the PEM private key itself; passphrase-protected keys are not supported" },
  { value: "password", label: "Desktop or telnet password", hint: "RDP, VNC and telnet. For a local Windows account use .\\Administrator; for a domain account use DOMAIN\\user" },
  { value: "basic", label: "HTTP Basic auth", hint: "username + password sent as an Authorization: Basic header" },
  { value: "header", label: "Authorization header", hint: 'the secret is the full header value, e.g. "Bearer <token>"' },
  { value: "form", label: "Login form fill", hint: "a browser on the server types the credential into the device's login page — requires isolated delivery" },
];

export interface UserRow {
  user_id: string;
  organization_id: string;
  email: string;
  username: string;
  is_super_admin: boolean;
  // The account this GuardRail was installed with. Its roles cannot be changed
  // and its password cannot be reset — by anyone, including other super admins —
  // because it is the way back in if every other administrator is lost. It CAN
  // be removed: that frees the email address, so `guardrail seed-admin` on the
  // server puts it back, which is what makes removal the one recoverable change.
  is_bootstrap_admin: boolean;
  roles: string[];
  permissions: string[];
  approval_level: number;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
  // Which devices this role's device:connect permission reaches. 'all' is the
  // default (every device in the org); 'scoped' narrows it to the types and
  // groups in RoleDeviceAccess.
  device_scope: "all" | "scoped";
  // Rank in the approval hierarchy. An approver must outrank the requester
  // STRICTLY — which is also what makes self-approval impossible, since nobody
  // outranks themselves.
  approval_level: number;
}

// AssetGroup is a folder of devices (GET /asset-groups) — the unit a role can be
// granted access to alongside device types.
export interface AssetGroup {
  id: string;
  name: string;
  type: string;
  parent_id?: string | null;
}

export interface ConnectResult {
  status: string; // active
  session_id?: string;
  proxy_url?: string;
  // Present when the session is delivered on its own hostname
  // (<session-id>.<tunnel-domain>) rather than under /proxy/<sid>/. It carries a
  // short-lived one-time grant, so it is not reusable — the session view mints a
  // fresh one from GET /sessions/:id/tunnel each time it opens the tab.
  tunnel_url?: string;
  granted_until?: string;
}

export interface Session {
  id: string;
  device_id: string;
  // The device as it was when this session ran, snapshotted at connect. Present
  // even when the device has since been deleted — that is why it is stored on the
  // session rather than looked up from the device.
  device_name?: string;
  device_type?: string;
  device_address?: string;
  user_id?: string;
  user_email?: string;
  status: string;
  protocol: string;
  // Source IP the session was opened from (who is connected, from where).
  client_ip?: string;
  user_agent?: string;
  gateway_node?: string;
  started_at?: string;
  ended_at?: string;
  created_at?: string;
  granted_from?: string;
  granted_until?: string;
  // The last time anything happened on the session. It is the only field that
  // separates a session somebody worked in from one that was left open: a record
  // closed long after this was not that long of access.
  last_activity_at?: string;
  end_reason?: string;
}

// Paged is a listing that reports how many rows exist beyond the page returned.
// `total` is the count for the whole filter, so a pager and a counter built from
// it describe the table rather than the slab that happened to be fetched.
export interface Paged<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

// SessionStats are the live counters behind the Recordings header
// (GET /sessions/stats), computed across every session in the tenant.
export interface SessionStats {
  total: number;
  active: number;
  ended: number;
  devices: number;
}

// SessionEvent is one entry in a session's recorded activity timeline
// (GET /sessions/:id/events) — e.g. a URL the operator navigated to through the
// proxy. `data` shape varies by `kind` (url_change carries { path, method }).
export interface SessionEvent {
  ts: string;
  kind: string;
  data: Record<string, unknown>;
}

// RecordingMeta is a session's recording (GET /sessions/:id/recording). A 404
// means the session wasn't recorded — the device has recording switched off —
// which is a normal answer, not a failure.
export interface RecordingMeta {
  id: string;
  session_id: string;
  status: string; // recording | finalized | failed
  started_at: string;
  ended_at?: string;
  duration_ms?: number;
  // Whether there are frames to replay. A session still running, or one that
  // ended before anything was painted, has a recording but no video.
  has_video: boolean;
  // Whether an SSH session's terminal output was stored. A recording is exactly
  // one of these three kinds, never more: the device's protocol decides which,
  // and by playback time the device may have been changed or removed — so the
  // recording says.
  has_transcript: boolean;
  // Whether an RDP/VNC session's Guacamole dump was stored. A desktop is not
  // frames and answers has_video false, so a console that asked only about video
  // and transcripts called a perfectly good desktop recording "nothing captured".
  has_desktop: boolean;
}

// LoginSession is one live console sign-in (GET /auth/sessions) — a person
// authenticated to GuardRail itself, as opposed to a brokered device Session.
// All timestamps are UTC RFC3339; render them in the viewer's local zone.
export interface LoginSession {
  id: string; // refresh-token family id — the stable identifier of the sign-in
  user_id: string;
  email: string;
  ip: string;
  user_agent: string;
  signed_in_at: string; // when the session was first established
  last_seen_at: string; // last time it was refreshed (last activity)
  expires_at: string;
  current: boolean; // the session making this very request
  self: boolean; // belongs to the viewer
}

// A permission from the catalogue (GET /permissions): a resource:action key
// and a human description.
export interface Permission {
  key: string;
  description: string;
}

// RoleDeviceAccess is a role's resource-level device entitlement
// (GET /roles/:id/device-access). scope 'all' reaches every device in the org;
// 'scoped' restricts access to the listed device types and/or asset groups.
export interface RoleDeviceAccess {
  device_scope: "all" | "scoped";
  device_types: string[];
  group_ids: string[];
}

export interface DashboardSummary {
  devices: number;
  active_sessions: number;
  users: number;
  failed_logins_24h: number;
  top_devices: { device_id: string; name: string; sessions: number }[];
  recent_activity: { ts: string; actor: string; action: string; result: string }[];
}

export interface AuditRow {
  ts: string;
  actor: string;
  action: string;
  category: string;
  target_type: string;
  target_id: string;
  /**
   * The target resolved to a name a person recognises — a device name, a user's
   * email, a credential name. Empty when the target has been purged since, or
   * when the action has no separate target; the console falls back to the id.
   */
  target_label?: string;
  /**
   * The session this event happened inside, when it happened inside one. It is
   * what lets the console offer the recording, the timeline and the approval
   * behind an entry instead of leaving the reader to go and search for them.
   */
  session_id?: string;
  ip: string;
  user_agent?: string;
  result: string;
  // Structured payload recorded with the event; shape varies by action.
  detail?: Record<string, unknown> | null;
}

export interface SearchResults {
  users: { id: string; label: string }[];
  devices: { id: string; label: string }[];
  sessions: { id: string; label: string }[];
}

export interface AuthProviders {
  local: boolean;
  ldap: boolean;
  oidc: boolean;
  // Whether SIEM single sign-on is wired up. There is no button for it — the
  // flow starts at the SIEM — so the console uses this only to explain where to
  // sign in, rather than leaving somebody staring at a form they have no
  // password for.
  siem_sso?: boolean;
}

export interface MFAStatus {
  enabled: boolean;
  confirmed: boolean;
  recovery_codes_left: number;
}

export interface VersionInfo {
  name: string;
  version: string;
}

// Capabilities describes what the server can deliver, as opposed to what a
// tenant is allowed to do.
export interface Capabilities {
  // Both are false when no Chromium resolved on the server. They are separate
  // because they fail differently: an isolated device degrades to a proxy
  // session, a recorded device is refused.
  session_recording: boolean;
  browser_isolation: boolean;
}

/** What POST /mfa/totp/enroll returns.
 *
 * Shared rather than redeclared per page: this was duplicated in FirstRunPage and
 * SecurityPage, one of them named the URI field `otpauth_url`, and nothing caught
 * it — a hand-written interface describes what a page HOPES the API returns, so a
 * wrong name reads as `undefined` at runtime with tsc perfectly happy. */
export interface Enrollment {
  secret: string;
  provisioning_uri: string;
}

/* ---- API tokens -------------------------------------------------------------
 *
 * Machine credentials: they authenticate directly, with no login and no refresh,
 * so a monitoring board polling the status feed does not mint a session and an
 * audit event every thirty seconds.
 */

/** A token's metadata. The value itself is never in this shape — the server
 * stores only a SHA-256 of it and has nothing to return. */
export interface APIToken {
  id: string;
  name: string;
  /** Leading characters of the value, kept in clear so a person can tell which
   * row is which when deciding what to revoke. */
  prefix: string;
  scopes: string[];
  revoked: boolean;
  created_at: string;
  created_by?: string;
  expires_at?: string;
  last_used_at?: string;
  revoked_at?: string;
}

/** What POST /api-tokens returns: the metadata plus the one and only look at the
 * value. Nothing else, ever, carries `token`. */
export interface NewAPIToken extends APIToken {
  token: string;
  warning: string;
}

/** Scopes a machine token may carry.
 *
 * Mirrors iam.AllowedTokenScopes on the server, which is the authority — the
 * server rejects anything outside it, so a drift here shows up as a failed
 * create rather than as a token with powers it should not have.
 *
 * Reads only, and that is deliberate: access_sessions.user_id is a foreign key
 * to users, so a token cannot be the actor on a brokered session even if we
 * wanted it to be. */
export const TOKEN_SCOPES: { key: string; label: string; blurb: string }[] = [
  { key: "device:read", label: "Devices", blurb: "Names, addresses, types and online status" },
  { key: "session:read", label: "Sessions", blurb: "Session history — who connected to what, and when" },
  { key: "recording:read", label: "Recordings", blurb: "Recorded sessions, transcripts and their metadata" },
  { key: "group:read", label: "Groups", blurb: "Device and user group membership" },
  { key: "log:read", label: "Access log", blurb: "Access decisions and their reasons" },
  { key: "report:read", label: "Reports", blurb: "Aggregates behind the dashboard" },
  { key: "user:read", label: "Users", blurb: "Accounts, emails and role assignments" },
  { key: "role:read", label: "Roles", blurb: "Roles and the permissions they carry" },
  { key: "org:read", label: "Organization", blurb: "Organization name and settings" },
];

// ---- per-user accounts ----------------------------------------------------

export type CredentialMode = "shared" | "per_user";

// Account is a named login that exists ON THE TARGET DEVICE — `jsmith-admin`.
// It is never the person's own password: GuardRail must not hold one.
export interface Account {
  credential_id: string;
  name: string;
  username: string;
  injection: string;
  user_id?: string;
  user?: string;
  // "device" — bound to this device. "group" — inherited from an asset group,
  // covering everything in its subtree.
  scope: "device" | "group";
  group_id?: string;
  group_name?: string;
  // How long the secret has gone unchanged, from the rotation if there was one
  // and from creation otherwise.
  age_days: number;
  rotated_at?: string;
}

// WhoAmI is which account the current user would connect as, answered before
// they press Connect rather than after.
export interface WhoAmI {
  credential_mode: CredentialMode;
  allow_unmanaged: boolean;
  has_credential: boolean;
  username?: string;
  per_user?: boolean;
  inherited?: boolean;
  age_days?: number;
}

// ---- approvals ------------------------------------------------------------

export type RequestStatus = "pending" | "approved" | "denied" | "expired" | "cancelled";
export type GrantScope = "once" | "always";

export interface AccessDecision {
  by: string;
  decision: "approve" | "deny";
  note?: string;
  decided_at: string;
}

export interface AccessRequest {
  id: string;
  user_id: string;
  device_id: string;
  requester: string;
  device: string;
  status: RequestStatus;
  reason: string;
  requested_minutes: number;
  granted_minutes?: number;
  grant_scope?: GrantScope;
  approvals: number;
  min_approvals: number;
  requester_level: number;
  is_emergency: boolean;
  reviewed: boolean;
  review_note?: string;
  escalated_level?: number;
  session_id?: string;
  // session_active tells a live session from one that has already ended.
  // session_id is never cleared, so it alone cannot answer that. Optional
  // because a server older than the field simply omits it, and reading a
  // missing answer as "not live" is the direction that does not invent access.
  session_active?: boolean;
  expires_at: string;
  created_at: string;
  decisions: AccessDecision[];
}

// Grant is standing permission for one person on one device — the "allow all
// time" button. It gets its own list and its own revoke path, because access
// that only accumulates and can never be enumerated is how a deployment rots.
export interface AccessGrant {
  id: string;
  user_id: string;
  user: string;
  device_id: string;
  device: string;
  granted_by?: string;
  expires_at?: string;
  revoked_at?: string;
  live: boolean;
  created_at: string;
}

// Windows a requester can ask for. Capped well below a working day: an access
// request is for a task, and "I need it until tomorrow" is a standing grant
// wearing a disguise.
export const REQUEST_WINDOWS: { minutes: number; label: string }[] = [
  { minutes: 15, label: "15 minutes" },
  { minutes: 30, label: "30 minutes" },
  { minutes: 60, label: "1 hour" },
  { minutes: 120, label: "2 hours" },
  { minutes: 240, label: "4 hours" },
  { minutes: 480, label: "8 hours" },
];

/* ---- Organization settings ------------------------------------------------ */

/** How an organization's console presents itself. */
export interface Branding {
  client_name: string;
  /** A data: URI, or "" when no artwork is set. */
  client_logo: string;
  enabled: boolean;
  /** Whether there is anything to show — the server's own reading of the rule. */
  configured: boolean;
}

/** One entry in a source-address list. */
export interface NetworkRule {
  cidr: string;
  note?: string;
}

export interface NetworkPolicy {
  allowlist_enabled: boolean;
  allowlist: NetworkRule[];
  blocklist_enabled: boolean;
  blocklist: NetworkRule[];
}

export interface OrgSettings {
  recording_retention_days: number;
  /** What this deployment's .env asked for, shown beside the live value. */
  configured_default_days: number;
  branding: Branding;
  network_policy: NetworkPolicy;
  updated_at?: string;
  updated_by?: string;
  /** The address this console reached the API from. */
  your_ip?: string;
}

/** The result of walking the audit log's hash chain. */
export interface ChainReport {
  ok: boolean;
  checked: number;
  /** True when the walk stopped at its row cap rather than at the end of the chain. */
  truncated?: boolean;
  /** Entries whose hash predates the current scheme and cannot be recomputed. */
  unverifiable?: number;
  from?: string;
  to?: string;
  broken_at?: string;
  broken_at_ts?: string;
  reason?: string;
}
