/**
 * Interactive OIDC login: cookie session + PKCE via openid-client (v6).
 *
 * The gateway reuses the MSPStack Entra login app as a CONFIDENTIAL client:
 *   - discovery of the configured OIDC issuer
 *   - authorization-code + PKCE (code_verifier/code_challenge) + state + nonce
 *   - code→token exchange at the callback, with the library validating
 *     iss/aud/nonce/exp of the id-token (aud MUST equal the client id)
 *
 * This is DISTINCT from src/auth/oidc.ts, which validates inbound *access
 * tokens* as an OAuth 2.1 resource server. Here we consume an *id-token* to
 * establish our own signed cookie session.
 *
 * Session invariant: the session cookie carries ONLY identity ({iss, sub} +
 * issued-at), signed with SESSION_SECRET. It NEVER carries a role/privilege —
 * the role is re-resolved server-side on every request (see createAuthResolver).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import * as client from "openid-client";
import type { JWTPayload } from "jose";
import { identityFromPayload, type OidcIdentity } from "./oidc.js";
import type { PendingAuthorization } from "./authz-server.js";
import type { LoginConfig, OidcConfig } from "../config.js";

/** Scopes requested at the authorization endpoint. */
const SCOPE = "openid profile email";

/** Cookie names. */
export const SESSION_COOKIE = "mspstack_session";
export const TRANSIENT_COOKIE = "mspstack_login";

/** Lifetimes. */
export const SESSION_MAX_AGE_MS = 8 * 60 * 60 * 1000; // 8h
export const TRANSIENT_MAX_AGE_MS = 10 * 60 * 1000; // 10 min

/** Transient per-attempt PKCE state, stored in a short-lived signed cookie. */
export interface TransientState {
  codeVerifier: string;
  nonce: string;
  state: string;
  returnTo: string;
  /**
   * Pending /oauth/authorize request when this login attempt is brokering
   * user authentication for an MCP client (the OAuth AS facade). The callback
   * then mints a single-use authorization code and redirects to the client's
   * registered redirect_uri instead of returnTo.
   */
  oauth?: PendingAuthorization;
}

/** What the session cookie carries — identity only, never privilege. */
export interface SessionClaims {
  iss: string;
  sub: string;
}

/**
 * The openid-client-backed flow, behind a small interface so tests can inject
 * a fake (no live IdP). Discovery is lazy so construction never hits the
 * network — mirrors createOidcVerifier in oidc.ts.
 */
export interface LoginService {
  /** Build the authorization redirect URL + the transient PKCE state to persist. */
  startAuth(returnTo: string): Promise<{ redirectUrl: string; transient: TransientState }>;
  /** Validate the callback: exchange code, validate the id-token, return identity. */
  completeAuth(callbackUrl: URL, transient: TransientState): Promise<OidcIdentity>;
}

export function createLoginService(
  oidc: OidcConfig,
  login: LoginConfig,
  /** Injectable for tests — a pre-built Configuration skips network discovery. */
  configOverride?: client.Configuration
): LoginService {
  let cfg: client.Configuration | null = configOverride ?? null;
  let discovering: Promise<client.Configuration> | null = null;

  const getConfig = async (): Promise<client.Configuration> => {
    if (cfg) return cfg;
    if (!discovering) {
      discovering = client
        .discovery(new URL(oidc.issuer), login.clientId, login.clientSecret)
        .then((c) => {
          cfg = c;
          return c;
        })
        .finally(() => {
          discovering = null;
        });
    }
    return discovering;
  };

  return {
    async startAuth(returnTo: string) {
      const c = await getConfig();
      const codeVerifier = client.randomPKCECodeVerifier();
      const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
      const state = client.randomState();
      const nonce = client.randomNonce();
      const url = client.buildAuthorizationUrl(c, {
        redirect_uri: login.redirectUri,
        scope: SCOPE,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce,
      });
      return { redirectUrl: url.href, transient: { codeVerifier, nonce, state, returnTo } };
    },

    async completeAuth(callbackUrl: URL, transient: TransientState): Promise<OidcIdentity> {
      const c = await getConfig();
      // The library validates state (expectedState), nonce, PKCE, and the
      // id-token's iss/aud/exp — aud must equal the client id.
      const tokens = await client.authorizationCodeGrant(c, callbackUrl, {
        pkceCodeVerifier: transient.codeVerifier,
        expectedNonce: transient.nonce,
        expectedState: transient.state,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (!claims) throw new Error("token response carried no id-token claims");
      // Reuse the resource-server identity mapping (email/displayName/groups),
      // but key the subject on the stable Entra object id when present: id-token
      // `sub` is pairwise per client, `oid` is stable across apps in the tenant.
      const base = identityFromPayload(claims as unknown as JWTPayload, oidc.groupsClaim);
      const oid = (claims as Record<string, unknown>).oid;
      return { ...base, sub: typeof oid === "string" && oid ? oid : base.sub };
    },
  };
}

// ── Signed cookie helpers (pure; exported for direct unit tests) ────────────

const hmac = (payload: string, secret: string): string =>
  createHmac("sha256", secret).update(payload).digest("base64url");

/** Sign an object into a `<base64url(json)>.<base64url(hmac)>` token with an issued-at. */
export function signCookiePayload(obj: Record<string, unknown>, secret: string): string {
  const body = Buffer.from(JSON.stringify({ ...obj, iat: Date.now() })).toString("base64url");
  return `${body}.${hmac(body, secret)}`;
}

/** Verify signature + freshness; returns the parsed payload or null. */
export function verifyCookiePayload(
  token: string | undefined,
  secret: string,
  maxAgeMs: number
): Record<string, unknown> | null {
  if (!token) return null;
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(body, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
  const iat = typeof parsed.iat === "number" ? parsed.iat : 0;
  if (!iat || Date.now() - iat > maxAgeMs) return null;
  return parsed;
}

export function mintSessionCookieValue(claims: SessionClaims, secret: string): string {
  return signCookiePayload({ iss: claims.iss, sub: claims.sub }, secret);
}

export function readSessionClaims(
  cookieValue: string | undefined,
  secret: string
): SessionClaims | null {
  const p = verifyCookiePayload(cookieValue, secret, SESSION_MAX_AGE_MS);
  if (!p || typeof p.iss !== "string" || typeof p.sub !== "string") return null;
  return { iss: p.iss, sub: p.sub };
}

export function mintTransientCookieValue(t: TransientState, secret: string): string {
  return signCookiePayload({ ...t }, secret);
}

export function readTransientState(
  cookieValue: string | undefined,
  secret: string
): TransientState | null {
  const p = verifyCookiePayload(cookieValue, secret, TRANSIENT_MAX_AGE_MS);
  if (
    !p ||
    typeof p.codeVerifier !== "string" ||
    typeof p.nonce !== "string" ||
    typeof p.state !== "string" ||
    typeof p.returnTo !== "string"
  ) {
    return null;
  }
  const oauth = readPendingAuthorization(p.oauth);
  if (p.oauth !== undefined && !oauth) return null; // present but malformed → reject the attempt
  return {
    codeVerifier: p.codeVerifier,
    nonce: p.nonce,
    state: p.state,
    returnTo: p.returnTo,
    ...(oauth ? { oauth } : {}),
  };
}

function readPendingAuthorization(raw: unknown): PendingAuthorization | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (
    typeof o.clientId !== "string" ||
    typeof o.redirectUri !== "string" ||
    typeof o.codeChallenge !== "string" ||
    (o.state !== null && typeof o.state !== "string") ||
    (o.resource !== null && typeof o.resource !== "string")
  ) {
    return null;
  }
  return {
    clientId: o.clientId,
    redirectUri: o.redirectUri,
    codeChallenge: o.codeChallenge,
    state: o.state,
    resource: o.resource,
  };
}

/** Minimal Cookie-header parser (avoids a cookie-parser dependency). */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[key] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

/**
 * Validate a `returnTo` target: only local absolute paths are allowed (no
 * protocol-relative "//host", no absolute URLs, no backslashes) so login can
 * never be used as an open redirect.
 */
export function safeReturnTo(raw: unknown, fallback: string): string {
  const v = Array.isArray(raw) ? raw[0] : raw;
  if (typeof v !== "string" || v.length === 0) return fallback;
  if (!v.startsWith("/") || v.startsWith("//") || v.includes("\\")) return fallback;
  return v;
}
