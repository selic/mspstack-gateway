/**
 * OAuth Authorization Server facade (RFC 8414 metadata + RFC 7591 dynamic
 * client registration + authorization-code/PKCE grant) so standard MCP
 * clients can connect with nothing but the gateway URL.
 *
 * Entra has no anonymous DCR, so the gateway itself is the authorization
 * server the MCP client talks to; the user-authentication leg is brokered to
 * Entra through the existing interactive-login confidential client
 * (src/auth/login.ts). Design: docs/plans/oauth-authorization-server.md.
 *
 * Invariants:
 *  - PKCE S256 is mandatory; exact redirect_uri match; codes are single-use
 *    with a 60s TTL and stored hashed (sha256) — plaintext never persisted.
 *  - Gateway-issued access tokens are HS256 JWTs carrying IDENTITY ONLY
 *    (iss/aud/sub/exp/jti). The role is re-resolved on every request by the
 *    auth resolver — a token never carries privilege.
 *  - Token/code values are never logged (labels + sha256 prefixes only).
 */

import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import type { Repo, OauthCodeRow } from "../db/repo.js";

/** Authorization-code lifetime (MCP/OAuth 2.1 guidance: short and single-use). */
export const CODE_TTL_MS = 60_000;
/** Gateway-issued access-token lifetime. */
export const ACCESS_TOKEN_TTL_S = 3600;
/** Refresh-token lifetime — sliding: each rotation issues a fresh 30-day token. */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const sha256hex = (value: string): string => createHash("sha256").update(value).digest("hex");

/** The canonical resource identifier tokens are bound to (RFC 8707). */
export const canonicalResource = (publicUrl: string): string => `${publicUrl}/mcp`;

// ── RFC 8414 metadata ────────────────────────────────────────────────────────

export function authorizationServerMetadata(publicUrl: string): Record<string, unknown> {
  return {
    issuer: publicUrl,
    authorization_endpoint: `${publicUrl}/oauth/authorize`,
    token_endpoint: `${publicUrl}/oauth/token`,
    registration_endpoint: `${publicUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  };
}

// ── RFC 7591 dynamic client registration ────────────────────────────────────

/**
 * Redirect URIs are the only place an authorization response can be sent, so
 * they are the open-redirect surface: allow https:// anywhere, and plain
 * http:// only for loopback interfaces (native-app pattern, RFC 8252).
 */
export function redirectUriAllowed(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:") return false;
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "::1";
}

export interface RegistrationResult {
  ok: true;
  clientId: string;
  clientName: string | null;
  redirectUris: string[];
}

export interface RegistrationError {
  ok: false;
  error: "invalid_redirect_uri" | "invalid_client_metadata";
  description: string;
}

/** Validate an RFC 7591 registration request and persist the client. */
export function registerClient(repo: Repo, body: unknown): RegistrationResult | RegistrationError {
  const req = (body ?? {}) as Record<string, unknown>;
  const redirectUris = req.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every((u) => typeof u === "string")) {
    return { ok: false, error: "invalid_redirect_uri", description: "redirect_uris must be a non-empty array of strings" };
  }
  for (const uri of redirectUris as string[]) {
    if (!redirectUriAllowed(uri)) {
      return {
        ok: false,
        error: "invalid_redirect_uri",
        description: `redirect_uri "${uri}" is not allowed — use https:// or an http:// loopback address`,
      };
    }
  }
  if (req.token_endpoint_auth_method !== undefined && req.token_endpoint_auth_method !== "none") {
    return {
      ok: false,
      error: "invalid_client_metadata",
      description: 'only public clients are supported — token_endpoint_auth_method must be "none"',
    };
  }
  const clientName = typeof req.client_name === "string" ? req.client_name.slice(0, 200) : null;
  const clientId = randomUUID();
  repo.createOauthClient({ clientId, clientName, redirectUris: redirectUris as string[] });
  console.error(`[oauth] registered client ${clientId} ("${clientName ?? "unnamed"}")`);
  return { ok: true, clientId, clientName, redirectUris: redirectUris as string[] };
}

// ── Authorization codes (single-use, hashed at rest) ────────────────────────

export interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
  resource: string | null;
}

/** Mint a single-use code bound to the pending request + authenticated principal. */
export function mintAuthorizationCode(
  repo: Repo,
  pending: PendingAuthorization,
  principal: { iss: string; sub: string },
  now = Date.now()
): string {
  const code = randomBytes(32).toString("base64url");
  repo.insertOauthCode({
    codeHash: sha256hex(code),
    clientId: pending.clientId,
    principalIss: principal.iss,
    principalSub: principal.sub,
    codeChallenge: pending.codeChallenge,
    resource: pending.resource,
    expiresAt: now + CODE_TTL_MS,
  });
  console.error(`[oauth] code minted for client ${pending.clientId} (sha256 ${sha256hex(code).slice(0, 12)}…)`);
  return code;
}

/** RFC 7636: BASE64URL(SHA256(verifier)) must equal the stored challenge. */
export function pkceChallengeMatches(codeVerifier: string, codeChallenge: string): boolean {
  const computed = createHash("sha256").update(codeVerifier).digest("base64url");
  const a = Buffer.from(computed);
  const b = Buffer.from(codeChallenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

export interface RedemptionResult {
  ok: true;
  principal: { iss: string; sub: string };
}

export interface RedemptionError {
  ok: false;
  error: "invalid_grant" | "invalid_request";
  description: string;
}

/**
 * Redeem an authorization code: single-use (atomic), client binding, PKCE.
 * Every failure is the same opaque invalid_grant — no oracle for which check
 * tripped.
 */
export function redeemAuthorizationCode(
  repo: Repo,
  params: { code: string; clientId: string; codeVerifier: string }
): RedemptionResult | RedemptionError {
  const invalid: RedemptionError = {
    ok: false,
    error: "invalid_grant",
    description: "authorization code is invalid, expired, already used, or does not match this client",
  };
  const row: OauthCodeRow | null = repo.consumeOauthCode(sha256hex(params.code));
  if (!row) return invalid;
  if (row.clientId !== params.clientId) return invalid;
  if (!pkceChallengeMatches(params.codeVerifier, row.codeChallenge)) return invalid;
  return { ok: true, principal: { iss: row.principalIss, sub: row.principalSub } };
}

// ── Refresh tokens (rotating; reuse revokes the family) ─────────────────────

/**
 * Issue a refresh token. For the grant's first token omit `rotatedFrom` —
 * the token becomes its own family root; rotations pass the predecessor's
 * hash and stay in the same family.
 */
export function issueRefreshToken(
  repo: Repo,
  params: {
    clientId: string;
    principal: { iss: string; sub: string };
    familyId?: string;
    rotatedFrom?: string;
  },
  now = Date.now()
): string {
  const token = randomBytes(48).toString("base64url");
  const tokenHash = sha256hex(token);
  repo.insertOauthRefreshToken({
    tokenHash,
    clientId: params.clientId,
    principalIss: params.principal.iss,
    principalSub: params.principal.sub,
    familyId: params.familyId ?? tokenHash,
    rotatedFrom: params.rotatedFrom ?? null,
    expiresAt: now + REFRESH_TOKEN_TTL_MS,
  });
  return token;
}

export interface RefreshResult {
  ok: true;
  principal: { iss: string; sub: string };
  /** The rotated successor — the old token is now dead. */
  refreshToken: string;
}

/**
 * Redeem a refresh token: single rotation, client binding, and OAuth 2.1
 * reuse detection — a replayed (already-rotated) token revokes its entire
 * family, cutting off whoever holds the live descendant. Failures are the
 * same opaque invalid_grant.
 */
export function redeemRefreshToken(
  repo: Repo,
  params: { token: string; clientId: string }
): RefreshResult | RedemptionError {
  const invalid: RedemptionError = {
    ok: false,
    error: "invalid_grant",
    description: "refresh token is invalid, expired, revoked, or does not match this client",
  };
  const tokenHash = sha256hex(params.token);
  const result = repo.consumeOauthRefreshToken(tokenHash, params.clientId);
  if (result.status === "reuse") {
    const revoked = repo.revokeOauthRefreshFamily(result.familyId);
    console.error(
      `[oauth] refresh-token REUSE detected for client ${params.clientId} (sha256 ${tokenHash.slice(0, 12)}…) — revoked ${revoked} token(s) in the family`
    );
    return invalid;
  }
  if (result.status === "invalid") return invalid;
  const principal = { iss: result.row.principalIss, sub: result.row.principalSub };
  const refreshToken = issueRefreshToken(repo, {
    clientId: params.clientId,
    principal,
    familyId: result.row.familyId,
    rotatedFrom: tokenHash,
  });
  return { ok: true, principal, refreshToken };
}

// ── Gateway-issued access tokens (HS256 JWT, identity only) ─────────────────

export interface GatewayTokenClaims {
  /** Entra issuer of the authenticated user. */
  iss: string;
  /** Entra subject (stable oid) of the authenticated user. */
  sub: string;
}

export async function mintAccessToken(
  claims: GatewayTokenClaims,
  publicUrl: string,
  jwtSecret: string
): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(publicUrl)
    .setAudience(canonicalResource(publicUrl))
    .setSubject(`${claims.iss}|${claims.sub}`)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_S}s`)
    .sign(new TextEncoder().encode(jwtSecret));
}

/**
 * Verify a gateway-issued token: signature, iss = PUBLIC_URL, aud = the
 * canonical /mcp resource, exp. Returns the embedded Entra identity — the
 * caller re-resolves the role per request (a token never carries privilege).
 */
export async function verifyAccessToken(
  token: string,
  publicUrl: string,
  jwtSecret: string
): Promise<GatewayTokenClaims> {
  const { payload } = await jwtVerify(token, new TextEncoder().encode(jwtSecret), {
    algorithms: ["HS256"],
    issuer: publicUrl,
    audience: canonicalResource(publicUrl),
  });
  const sub = payload.sub ?? "";
  const sep = sub.indexOf("|");
  if (sep <= 0 || sep === sub.length - 1) throw new Error("token sub is not an <iss>|<sub> principal");
  return { iss: sub.slice(0, sep), sub: sub.slice(sep + 1) };
}

// ── Rate limiting (the register endpoint is anonymous by design) ────────────

/** Fixed-window in-memory limiter; single-process, matching the SQLite posture. */
export class RateLimiter {
  private readonly hits = new Map<string, { windowStart: number; count: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number
  ) {}

  allow(key: string, now = Date.now()): boolean {
    const entry = this.hits.get(key);
    if (!entry || now - entry.windowStart >= this.windowMs) {
      this.hits.set(key, { windowStart: now, count: 1 });
      if (this.hits.size > 10_000) this.prune(now);
      return true;
    }
    entry.count += 1;
    return entry.count <= this.limit;
  }

  private prune(now: number): void {
    for (const [key, entry] of this.hits) {
      if (now - entry.windowStart >= this.windowMs) this.hits.delete(key);
    }
  }
}
