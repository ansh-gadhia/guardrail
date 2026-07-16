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
  // Whether sessions to this device are screen-recorded.
  record_sessions: boolean;
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

export interface UserRow {
  user_id: string;
  organization_id: string;
  email: string;
  username: string;
  is_super_admin: boolean;
  roles: string[];
  permissions: string[];
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
  granted_until?: string;
}

export interface Session {
  id: string;
  device_id: string;
  device_name?: string;
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
  granted_until?: string;
  end_reason?: string;
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
