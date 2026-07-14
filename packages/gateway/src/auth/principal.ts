/**
 * The resolved identity of a request. A session id never carries privilege:
 * every request re-authenticates and must resolve to the same principal key
 * the session was created with (mcp-itglue's binding model, generalized).
 */

import { createHash } from "node:crypto";

export interface Principal {
  kind: "static" | "oidc" | "dev";
  /** Stable identity: static → token label; oidc → `${iss}|${sub}`; dev → "dev". */
  subject: string;
  /** Human-readable, for logs (never a secret). */
  label: string;
  roleId: number;
  roleName: string;
  isAdmin: boolean;
}

export const principalKey = (p: Principal): string => `${p.kind}:${p.subject}:${p.roleId}`;

/**
 * Identity key for personal state (prefs, registered credentials) —
 * deliberately WITHOUT roleId: a role change must not orphan a user's own
 * narrowing or credentials.
 */
export const prefsIdentity = (p: Principal): string => `${p.kind}:${p.subject}`;

/**
 * Deterministic Key-Vault-safe slug for per-user secret names
 * (gw-user-<slug>-<upstreamId>-<field>). Entra OIDs are GUIDs and pass
 * through recognizably; anything else (issuer URLs, emails) is hashed so the
 * slug never leaks structure into secret names and always fits the KV charset.
 */
export function principalSlug(p: Principal): string {
  const subjectPart = p.subject.split("|").pop() ?? p.subject;
  if (/^[0-9A-Za-z-]{1,36}$/.test(subjectPart)) return subjectPart.toLowerCase();
  return createHash("sha256").update(prefsIdentity(p)).digest("hex").slice(0, 16);
}
