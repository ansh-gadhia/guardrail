/**
 * Address matching for the network-policy editor.
 *
 * This exists so the console can answer "would this policy still let me in?"
 * while the administrator is still typing, before anything is saved. It is a
 * preview, not the enforcement: the server evaluates the same question in Go and
 * refuses a policy that would lock its author out. Where the two could disagree
 * — an exotic IPv6 form — this errs towards saying nothing rather than towards
 * a confident wrong answer.
 */

/** Parses a dotted-quad into a 32-bit number, or null. */
function v4(addr: string): number | null {
  const parts = addr.trim().split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

/** Strips the ::ffff: prefix a v4 address wears on a dual-stack listener. */
export function normalizeAddress(addr: string): string {
  const trimmed = addr.trim().toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(trimmed);
  return mapped ? mapped[1] : trimmed;
}

/** Reports whether `entry` (an address or CIDR) is well-formed. */
export function isValidEntry(entry: string): boolean {
  const value = entry.trim();
  if (!value) return false;
  const [addr, bits] = value.split("/");
  if (bits !== undefined) {
    if (!/^\d{1,3}$/.test(bits)) return false;
    const width = v4(addr) !== null ? 32 : 128;
    if (Number(bits) > width) return false;
  }
  if (v4(addr) !== null) return true;
  // Loose IPv6: hex groups and colons, optionally with a trailing v4 tail.
  return /^[0-9a-f:]+(\.\d{1,3}){0,3}$/i.test(addr) && addr.includes(":");
}

/** Reports whether an address falls inside an address-or-CIDR entry. */
export function entryContains(entry: string, address: string): boolean {
  const value = entry.trim();
  const addr = normalizeAddress(address);
  if (!value || !addr) return false;

  const slash = value.indexOf("/");
  if (slash === -1) return normalizeAddress(value) === addr;

  const network = normalizeAddress(value.slice(0, slash));
  const bits = Number(value.slice(slash + 1));
  const netNum = v4(network);
  const addrNum = v4(addr);
  if (netNum !== null && addrNum !== null) {
    if (!Number.isFinite(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
    return (netNum & mask) === (addrNum & mask);
  }
  // Outside IPv4 the console does not guess. An exact match is still an answer
  // it can give honestly; a prefix comparison it has not implemented is not.
  return network === addr;
}

export type Verdict = { allowed: boolean; reason: "blocklisted" | "not_allowlisted" | "" };

/** The same decision the server makes, for a policy that has not been saved yet. */
export function verdictFor(
  policy: {
    allowlist_enabled: boolean;
    allowlist: { cidr: string }[];
    blocklist_enabled: boolean;
    blocklist: { cidr: string }[];
  },
  address: string,
): Verdict {
  const hits = (rules: { cidr: string }[]) => rules.some((r) => entryContains(r.cidr, address));
  // The blocklist is consulted first and wins: an address on both lists is being
  // argued about, and refusing is the answer that fails safe.
  if (policy.blocklist_enabled && hits(policy.blocklist)) return { allowed: false, reason: "blocklisted" };
  if (policy.allowlist_enabled && !hits(policy.allowlist)) return { allowed: false, reason: "not_allowlisted" };
  return { allowed: true, reason: "" };
}
