/**
 * HTTP transport: Express app exposing
 *
 *   POST/GET/DELETE /mcp                        federated MCP endpoint (auth + policy)
 *   GET /.well-known/oauth-protected-resource   RFC 9728 metadata (when OIDC configured)
 *   /api/*                                      admin JSON API (admin role required)
 *   /admin                                      admin UI (static)
 *   GET /health                                 liveness probe
 *
 * Authentication model:
 *  - Static role tokens (Authorization: Bearer …, MCP_TOKENS_<ROLE>) — the
 *    mcp-itglue pattern, generalized to DB-backed roles.
 *  - OIDC JWTs from the configured IdP (Entra ID / generic OIDC), validated
 *    as an OAuth 2.1 resource server: issuer, expiry, audience (RFC 8707).
 *    401 responses carry WWW-Authenticate pointing at the PRM document.
 *  - DEV_ALLOW_UNAUTHENTICATED=true is the only unauthenticated mode and is
 *    an explicit opt-in; there is no silent "no config → admin" fallback.
 *  - A session id never carries privilege: every request re-authenticates
 *    and must resolve to the same principal the session was created with.
 */

import { createHash, randomUUID } from "node:crypto";
import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { GatewayConfig } from "../config.js";
import type { Repo, RoleRow, UserRow } from "../db/repo.js";
import type { PolicyService } from "../domain/policy.js";
import type { UpstreamManager } from "../upstream/manager.js";
import type { SecretStore } from "../secrets/store.js";
import type { OidcVerifier, OidcIdentity } from "../auth/oidc.js";
import { authenticateStaticToken, bearerToken } from "../auth/static-tokens.js";
import { prefsIdentity, principalKey, type Principal } from "../auth/principal.js";
import {
  SESSION_COOKIE,
  TRANSIENT_COOKIE,
  SESSION_MAX_AGE_MS,
  TRANSIENT_MAX_AGE_MS,
  parseCookies,
  readSessionClaims,
  readTransientState,
  mintSessionCookieValue,
  mintTransientCookieValue,
  safeReturnTo,
  type LoginService,
} from "../auth/login.js";
import { PRM_PATH, prmDocument, wwwAuthenticate } from "../auth/prm.js";
import {
  ACCESS_TOKEN_TTL_S,
  authorizationServerMetadata,
  canonicalResource,
  mintAccessToken,
  mintAuthorizationCode,
  RateLimiter,
  redeemAuthorizationCode,
  registerClient,
} from "../auth/authz-server.js";
import { createGatewayServer, SERVER_NAME, SERVER_VERSION } from "../mcp/gateway-server.js";
import { createAdminRouter } from "./admin-api.js";
import { createMeRouter } from "./me-api.js";

export interface AppDeps {
  config: GatewayConfig;
  repo: Repo;
  manager: UpstreamManager;
  policy: PolicyService;
  secretStore: SecretStore | null;
  oidcVerifier: OidcVerifier | null;
  /** Interactive-login flow (openid-client), or null when login is unconfigured. */
  loginService?: LoginService | null;
  /** Directory with the static admin UI, or null to skip mounting. */
  adminUiDir?: string | null;
}

export type AuthOutcome =
  | { ok: true; principal: Principal }
  | { ok: false; status: number; code: number; message: string };

interface SessionRecord {
  transport: StreamableHTTPServerTransport;
  server: Server;
  principal: Principal;
  visibleFingerprint: string;
}

function rpcError(res: Response, status: number, code: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code, message }, id: null });
}

function headerValue(req: Request, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

/**
 * DNS-rebinding / cross-site protection for /mcp (MCP spec: servers SHOULD
 * validate Origin). Non-browser clients send no Origin header and always
 * pass; browser pages only pass from localhost or an explicitly allowed
 * origin. Exported for tests.
 */
export function originAllowed(origin: string | undefined, allowedOrigins: string[]): boolean {
  if (origin === undefined) return true;
  let hostname: string;
  try {
    hostname = new URL(origin).hostname;
  } catch {
    return false; // malformed Origin (including the literal "null") → reject
  }
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]") return true;
  return allowedOrigins.includes(origin.replace(/\/+$/, ""));
}

/** Shared 403 message for authenticated-but-unmapped principals (bearer + cookie). */
const NO_ROLE_MESSAGE =
  "Authenticated, but no role is assigned — ask an administrator to map your user or group to a role.";

/**
 * The identical login side effects shared by the OIDC bearer path and the
 * interactive-login callback: upsert the user, apply the admin bootstrap, then
 * resolve the role. Factored out so the two paths can never drift.
 */
export function loginUpsert(
  repo: Repo,
  config: GatewayConfig,
  identity: OidcIdentity
): { user: UserRow; role: RoleRow | null } {
  const user = repo.upsertUserOnLogin({
    iss: identity.iss,
    sub: identity.sub,
    ...(identity.email ? { email: identity.email } : {}),
    ...(identity.displayName ? { displayName: identity.displayName } : {}),
  });
  // Bootstrap: configured subjects become admin on first login (persisted as an
  // explicit user-role override so it is visible in the UI).
  if (user.roleId == null && config.adminBootstrapSubjects.length > 0) {
    const candidates = [identity.email?.toLowerCase(), identity.sub.toLowerCase()];
    if (candidates.some((c) => c && config.adminBootstrapSubjects.includes(c))) {
      const admin = repo.roleByName("admin");
      if (admin) {
        repo.setUserRole(user.id, admin.id);
        console.error(`[auth] bootstrap: granted admin to ${identity.email ?? identity.sub}`);
      }
    }
  }
  const role = repo.resolveOidcRole(identity.iss, identity.sub, identity.groups);
  return { user, role };
}

/** Resolve the principal for a request. Exported for tests and the admin API. */
export function createAuthResolver(deps: AppDeps) {
  const { config, repo, oidcVerifier } = deps;
  // Cache verified principals briefly so per-request JWT validation and user
  // upserts don't dominate; keyed by token hash, never by session id.
  const cache = new Map<string, { principal: Principal; expiresAt: number }>();
  const CACHE_TTL_MS = 60_000;

  const unauthorized = (message: string): AuthOutcome => ({
    ok: false,
    status: 401,
    code: -32001,
    message,
  });

  return async function resolveAuth(req: Request): Promise<AuthOutcome> {
    const header = req.headers.authorization;

    // 1. Static role tokens (timing-safe).
    const staticEntry = authenticateStaticToken(header, config.staticTokens);
    if (staticEntry) {
      const role = repo.roleByName(staticEntry.roleName);
      if (!role) {
        return unauthorized(
          `Token "${staticEntry.label}" references role "${staticEntry.roleName}" which does not exist`
        );
      }
      return {
        ok: true,
        principal: {
          kind: "static",
          subject: staticEntry.label,
          label: staticEntry.label,
          roleId: role.id,
          roleName: role.name,
          isAdmin: role.isAdmin,
        },
      };
    }

    // 2. OIDC JWT.
    const token = bearerToken(header);
    if (token && oidcVerifier) {
      const cacheKey = sha256(token);
      const cached = cache.get(cacheKey);
      if (cached && Date.now() < cached.expiresAt) {
        return { ok: true, principal: cached.principal };
      }
      let identity;
      try {
        identity = await oidcVerifier.verify(token);
      } catch (err) {
        return unauthorized(`Invalid token: ${err instanceof Error ? err.message : String(err)}`);
      }
      const { role } = loginUpsert(repo, config, identity);
      if (!role) {
        return { ok: false, status: 403, code: -32003, message: NO_ROLE_MESSAGE };
      }
      const principal: Principal = {
        kind: "oidc",
        subject: `${identity.iss}|${identity.sub}`,
        label: identity.email ?? identity.sub,
        roleId: role.id,
        roleName: role.name,
        isAdmin: role.isAdmin,
      };
      cache.set(cacheKey, { principal, expiresAt: Date.now() + CACHE_TTL_MS });
      return { ok: true, principal };
    }

    // 3. Interactive-login cookie session. Only when there is no Authorization
    // bearer (bearer paths above stay the sole path for MCP clients / CI). The
    // cookie carries ONLY identity — the role is re-resolved here every request
    // from the stored user row (persisted at callback time), so a session id
    // still never carries privilege.
    if (!token && config.login) {
      const cookies = parseCookies(req.headers.cookie);
      const session = readSessionClaims(cookies[SESSION_COOKIE], config.login.sessionSecret);
      if (session) {
        const role = repo.resolveOidcRole(session.iss, session.sub, []);
        if (!role) {
          return { ok: false, status: 403, code: -32003, message: NO_ROLE_MESSAGE };
        }
        const user = repo.userBySubject(session.iss, session.sub);
        return {
          ok: true,
          principal: {
            kind: "oidc",
            subject: `${session.iss}|${session.sub}`,
            label: user?.email ?? user?.displayName ?? session.sub,
            roleId: role.id,
            roleName: role.name,
            isAdmin: role.isAdmin,
          },
        };
      }
    }

    // 4. Explicit dev escape hatch.
    if (!token && config.devAllowUnauthenticated) {
      const admin = repo.roleByName("admin");
      if (admin) {
        return {
          ok: true,
          principal: {
            kind: "dev",
            subject: "dev",
            label: "dev-unauthenticated",
            roleId: admin.id,
            roleName: admin.name,
            isAdmin: true,
          },
        };
      }
    }

    if (config.staticTokens.length === 0 && !oidcVerifier) {
      return unauthorized(
        "No authentication is configured on this gateway — set MCP_TOKENS_<ROLE> or OIDC_ISSUER (or DEV_ALLOW_UNAUTHENTICATED=true for local development)."
      );
    }
    return unauthorized("Unauthorized: invalid or missing bearer token.");
  };
}

export function createApp(deps: AppDeps): express.Express {
  const { config, manager, policy } = deps;
  const app = express();
  app.use(express.json({ limit: "5mb", type: ["application/json", "application/*+json"] }));

  const resolveAuth = createAuthResolver(deps);
  const sessions = new Map<string, SessionRecord>();

  const visibleFingerprint = (roleId: number): string =>
    policy
      .visibleEntries(roleId, manager.catalogEntries())
      .map((entry) => entry.exposedName)
      .sort()
      .join("\n");

  /** Re-check every live session's visible tools; notify only those that changed. */
  const broadcastVisibility = (): void => {
    for (const [id, session] of sessions) {
      const fingerprint = visibleFingerprint(session.principal.roleId);
      if (fingerprint === session.visibleFingerprint) continue;
      session.visibleFingerprint = fingerprint;
      session.server.sendToolListChanged().catch((err) => {
        console.error(`[http] list_changed notify failed for session ${id}: ${String(err)}`);
      });
    }
  };
  manager.onCatalogChanged = broadcastVisibility;

  const attachWwwAuthenticate = (res: Response): void => {
    if (deps.oidcVerifier) res.set("WWW-Authenticate", wwwAuthenticate(config.publicUrl));
  };

  app.get("/health", (_req: Request, res: Response) => {
    res.json({ status: "ok", name: SERVER_NAME, version: SERVER_VERSION });
  });

  // ── RFC 9728 Protected Resource Metadata ─────────────────────
  const servePrm = (_req: Request, res: Response): void => {
    if (!config.oidc) {
      res.status(404).json({ error: "OAuth is not configured on this gateway" });
      return;
    }
    res.json(prmDocument(config.publicUrl, config.oidc));
  };
  app.get(PRM_PATH, servePrm);
  app.get(`${PRM_PATH}/mcp`, servePrm); // path-scoped variant some clients probe

  // ── MCP endpoint ─────────────────────────────────────────────

  app.use("/mcp", (req: Request, res: Response, next) => {
    const origin = headerValue(req, "origin");
    if (!originAllowed(origin, config.allowedOrigins)) {
      return rpcError(
        res,
        403,
        -32003,
        `Forbidden: origin "${origin}" is not allowed. Add it to ALLOWED_ORIGINS to permit browser access.`
      );
    }
    next();
  });

  app.post("/mcp", (req: Request, res: Response) => {
    void (async () => {
      const auth = await resolveAuth(req);
      if (!auth.ok) {
        if (auth.status === 401) attachWwwAuthenticate(res);
        return rpcError(res, auth.status, auth.code, auth.message);
      }

      const sessionId = headerValue(req, "mcp-session-id");
      if (sessionId) {
        const session = sessions.get(sessionId);
        if (!session) return rpcError(res, 404, -32000, "Session not found");
        if (principalKey(session.principal) !== principalKey(auth.principal)) {
          return rpcError(res, 403, -32003, "Forbidden: credentials do not match this session");
        }
        await session.transport.handleRequest(req, res, req.body);
        return;
      }

      if (!isInitializeRequest(req.body)) {
        return rpcError(res, 400, -32600, "Bad request: expected an initialize request");
      }

      const principal = auth.principal;
      const server = createGatewayServer(manager, policy, principal, (upstreamId) =>
        Object.fromEntries(
          deps.repo
            .listUserCredentials(prefsIdentity(principal))
            .filter((row) => row.upstreamId === upstreamId)
            .map((row) => [row.field, row.secretRef])
        )
      );
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          sessions.set(newSessionId, {
            transport,
            server,
            principal: auth.principal,
            visibleFingerprint: visibleFingerprint(auth.principal.roleId),
          });
          console.error(
            `[http] session ${newSessionId} created for ${auth.principal.label} (${auth.principal.roleName})`
          );
        },
      });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    })().catch((err) => {
      console.error(`[http] POST /mcp failed: ${String(err)}`);
      if (!res.headersSent) rpcError(res, 500, -32603, "Internal server error");
    });
  });

  const handleSessionRequest = (req: Request, res: Response): void => {
    void (async () => {
      const auth = await resolveAuth(req);
      if (!auth.ok) {
        if (auth.status === 401) attachWwwAuthenticate(res);
        return rpcError(res, auth.status, auth.code, auth.message);
      }
      const sessionId = headerValue(req, "mcp-session-id");
      const session = sessionId ? sessions.get(sessionId) : undefined;
      if (!session) return rpcError(res, 404, -32000, "Session not found");
      if (principalKey(session.principal) !== principalKey(auth.principal)) {
        return rpcError(res, 403, -32003, "Forbidden: credentials do not match this session");
      }
      await session.transport.handleRequest(req, res);
    })().catch((err) => {
      console.error(`[http] ${req.method} /mcp failed: ${String(err)}`);
      if (!res.headersSent) rpcError(res, 500, -32603, "Internal server error");
    });
  };

  app.get("/mcp", handleSessionRequest);
  app.delete("/mcp", handleSessionRequest);

  // ── User self-service API (any principal) ───────────────────
  // Mounted BEFORE /api so the admin router's admin-only middleware never
  // sees /api/me requests.

  app.use(
    "/api/me",
    createMeRouter(deps, { resolveAuth, onPolicyChanged: broadcastVisibility })
  );

  // ── Admin API + UI ───────────────────────────────────────────

  app.use(
    "/api",
    createAdminRouter(deps, { resolveAuth, onPolicyChanged: broadcastVisibility })
  );

  // ── Interactive login (cookie + PKCE) ───────────────────────
  // Only mounted when login is configured. Bearer paths are untouched.
  const login = config.login;
  const loginService = deps.loginService ?? null;
  if (login && loginService) {
    const sessionCookieOpts = {
      httpOnly: true,
      secure: true,
      sameSite: "lax" as const,
      path: "/",
      maxAge: SESSION_MAX_AGE_MS,
    };
    const transientCookieOpts = {
      httpOnly: true,
      secure: true,
      sameSite: "lax" as const,
      path: "/",
      maxAge: TRANSIENT_MAX_AGE_MS,
    };

    // GET /auth/login — build PKCE + auth URL, stash transient state in a
    // short-lived signed cookie, 302 to the IdP.
    app.get("/auth/login", (req: Request, res: Response) => {
      void (async () => {
        const returnTo = safeReturnTo(req.query.returnTo, "/me");
        const { redirectUrl, transient } = await loginService.startAuth(returnTo);
        res.cookie(TRANSIENT_COOKIE, mintTransientCookieValue(transient, login.sessionSecret), transientCookieOpts);
        res.redirect(302, redirectUrl);
      })().catch((err) => {
        console.error(`[auth] /auth/login failed: ${String(err)}`);
        if (!res.headersSent) res.status(500).send("Login initialization failed");
      });
    });

    // GET /auth/callback — verify state (in the library), exchange code,
    // validate the id-token, run the shared upsert/bootstrap/resolve, persist
    // the resolved role so later cookie requests need no groups, set the
    // session cookie, 302 to returnTo.
    app.get("/auth/callback", (req: Request, res: Response) => {
      void (async () => {
        const cookies = parseCookies(req.headers.cookie);
        const transient = readTransientState(cookies[TRANSIENT_COOKIE], login.sessionSecret);
        res.clearCookie(TRANSIENT_COOKIE, { path: "/" });
        if (!transient) {
          res.status(400).send("Login session expired or was tampered with — please try again.");
          return;
        }
        const callbackUrl = new URL(req.originalUrl, config.publicUrl);
        let identity: OidcIdentity;
        try {
          identity = await loginService.completeAuth(callbackUrl, transient);
        } catch (err) {
          console.error(`[auth] /auth/callback exchange failed: ${String(err)}`);
          res.status(401).send("Sign-in failed. Please try again.");
          return;
        }
        const { user, role } = loginUpsert(deps.repo, config, identity);
        // Persist the resolved role so the cookie path resolves it from the
        // stored user row (approach b) — no privilege ever rides in the cookie.
        if (role) deps.repo.setUserRole(user.id, role.id);
        // OAuth AS facade: this login was brokering user authentication for an
        // MCP client — mint a single-use code bound to the pending request and
        // bounce to the client's registered redirect_uri (validated at
        // /oauth/authorize; the transient cookie is HMAC-signed, so the
        // pending request cannot have been tampered with).
        if (transient.oauth) {
          const code = mintAuthorizationCode(deps.repo, transient.oauth, {
            iss: identity.iss,
            sub: identity.sub,
          });
          const target = new URL(transient.oauth.redirectUri);
          target.searchParams.set("code", code);
          if (transient.oauth.state !== null) target.searchParams.set("state", transient.oauth.state);
          console.error(
            `[oauth] authorization granted to client ${transient.oauth.clientId} for ${identity.email ?? identity.sub}`
          );
          res.redirect(302, target.href);
          return;
        }
        res.cookie(
          SESSION_COOKIE,
          mintSessionCookieValue({ iss: identity.iss, sub: identity.sub }, login.sessionSecret),
          sessionCookieOpts
        );
        console.error(`[auth] session established for ${identity.email ?? identity.sub}`);
        res.redirect(302, safeReturnTo(transient.returnTo, "/me"));
      })().catch((err) => {
        console.error(`[auth] /auth/callback failed: ${String(err)}`);
        if (!res.headersSent) res.status(500).send("Sign-in failed");
      });
    });

    // Logout — clear the session cookie, bounce to /me (which re-gates to login).
    const logout = (_req: Request, res: Response): void => {
      res.clearCookie(SESSION_COOKIE, { path: "/" });
      res.redirect(302, "/me");
    };
    app.post("/auth/logout", logout);
    app.get("/auth/logout", logout);

    // ── OAuth Authorization Server facade (DCR) ──────────────
    // The gateway is the authorization server standard MCP clients talk to
    // (Entra has no anonymous DCR); the user-authentication leg reuses the
    // Entra confidential-client login above. Mounted only when login is
    // configured — otherwise these endpoints 404 and PRM keeps pointing at
    // the raw IdP (today's behavior).
    const jwtSecret = config.gatewayJwtSecret!; // set whenever login is configured
    const queryParam = (value: unknown): string | undefined => {
      const v = Array.isArray(value) ? value[0] : value;
      return typeof v === "string" && v.length > 0 ? v : undefined;
    };

    // RFC 8414 metadata (+ the path-suffix variant some clients probe).
    const serveAsMetadata = (_req: Request, res: Response): void => {
      res.json(authorizationServerMetadata(config.publicUrl));
    };
    app.get("/.well-known/oauth-authorization-server", serveAsMetadata);
    app.get("/.well-known/oauth-authorization-server/mcp", serveAsMetadata);

    // RFC 7591 dynamic client registration: anonymous + auto-approve, so it
    // is rate-limited per IP. Public clients only (PKCE carries the proof).
    const registerLimiter = new RateLimiter(10, 60_000);
    app.post("/oauth/register", (req: Request, res: Response) => {
      if (!registerLimiter.allow(req.ip ?? "unknown")) {
        res.status(429).json({ error: "too_many_requests", error_description: "registration rate limit exceeded — retry later" });
        return;
      }
      const result = registerClient(deps.repo, req.body);
      if (!result.ok) {
        res.status(400).json({ error: result.error, error_description: result.description });
        return;
      }
      res.status(201).json({
        client_id: result.clientId,
        ...(result.clientName ? { client_name: result.clientName } : {}),
        redirect_uris: result.redirectUris,
        token_endpoint_auth_method: "none",
        client_id_issued_at: Math.floor(Date.now() / 1000),
      });
    });

    // Authorization endpoint: validate the request, then broker the user-
    // authentication leg to Entra by piggybacking on the interactive login —
    // the pending request rides in the signed transient cookie and the
    // callback above mints the code.
    app.get("/oauth/authorize", (req: Request, res: Response) => {
      void (async () => {
        const clientId = queryParam(req.query.client_id);
        const redirectUri = queryParam(req.query.redirect_uri);
        const client = clientId ? deps.repo.oauthClient(clientId) : null;
        // Per RFC 6749 §4.1.2.1: an invalid client or redirect_uri must NOT
        // redirect — that would be an open redirect.
        if (!client || !redirectUri || !client.redirectUris.includes(redirectUri)) {
          res.status(400).send("Invalid client_id or redirect_uri. Clients register via POST /oauth/register (RFC 7591).");
          return;
        }
        const state = queryParam(req.query.state) ?? null;
        const fail = (error: string, description: string): void => {
          const target = new URL(redirectUri);
          target.searchParams.set("error", error);
          target.searchParams.set("error_description", description);
          if (state !== null) target.searchParams.set("state", state);
          res.redirect(302, target.href);
        };
        if (queryParam(req.query.response_type) !== "code") {
          return fail("unsupported_response_type", 'only response_type "code" is supported');
        }
        const codeChallenge = queryParam(req.query.code_challenge);
        if (!codeChallenge || queryParam(req.query.code_challenge_method) !== "S256") {
          return fail("invalid_request", "PKCE is required: code_challenge + code_challenge_method=S256");
        }
        const resource = queryParam(req.query.resource) ?? null;
        if (resource !== null && resource !== canonicalResource(config.publicUrl)) {
          return fail("invalid_target", `unknown resource — this server protects ${canonicalResource(config.publicUrl)}`);
        }
        const { redirectUrl, transient } = await loginService.startAuth("/me");
        transient.oauth = { clientId: client.clientId, redirectUri, codeChallenge, state, resource };
        res.cookie(TRANSIENT_COOKIE, mintTransientCookieValue(transient, login.sessionSecret), transientCookieOpts);
        res.redirect(302, redirectUrl);
      })().catch((err) => {
        console.error(`[oauth] /oauth/authorize failed: ${String(err)}`);
        if (!res.headersSent) res.status(500).send("Authorization initialization failed");
      });
    });

    // Token endpoint: authorization_code + PKCE → gateway-issued JWT. The
    // token carries identity only; the role is re-resolved on every request.
    app.post("/oauth/token", express.urlencoded({ extended: false }), (req: Request, res: Response) => {
      void (async () => {
        res.set("Cache-Control", "no-store");
        const body = (req.body ?? {}) as Record<string, unknown>;
        const param = (name: string): string | undefined => queryParam(body[name]);
        if (param("grant_type") !== "authorization_code") {
          res.status(400).json({ error: "unsupported_grant_type", error_description: 'only "authorization_code" is supported' });
          return;
        }
        const code = param("code");
        const tokenClientId = param("client_id");
        const codeVerifier = param("code_verifier");
        if (!code || !tokenClientId || !codeVerifier) {
          res.status(400).json({ error: "invalid_request", error_description: "code, client_id, and code_verifier are required" });
          return;
        }
        const result = redeemAuthorizationCode(deps.repo, { code, clientId: tokenClientId, codeVerifier });
        if (!result.ok) {
          res.status(400).json({ error: result.error, error_description: result.description });
          return;
        }
        const accessToken = await mintAccessToken(result.principal, config.publicUrl, jwtSecret);
        console.error(`[oauth] access token issued to client ${tokenClientId} (sha256 ${sha256(accessToken).slice(0, 12)}…)`);
        res.json({ access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TOKEN_TTL_S });
      })().catch((err) => {
        console.error(`[oauth] /oauth/token failed: ${String(err)}`);
        if (!res.headersSent) res.status(500).json({ error: "server_error" });
      });
    });

    // Light browser-navigation gate for the user-facing pages. Only redirects
    // HTML GETs with no session; /api/* is NOT gated (server-side auth is the
    // real boundary). /admin is intentionally NOT gated: admin.html renders its
    // own sign-in (Microsoft button + break-glass token box).
    const wantsHtml = (req: Request): boolean => (req.headers.accept ?? "").includes("text/html");
    const hasSession = (req: Request): boolean =>
      readSessionClaims(parseCookies(req.headers.cookie)[SESSION_COOKIE], login.sessionSecret) !== null;
    const toLogin = (res: Response, path: string): void => {
      res.redirect(302, `/auth/login?returnTo=${encodeURIComponent(path)}`);
    };

    app.get("/", (req: Request, res: Response) => {
      if (wantsHtml(req) && !hasSession(req)) return toLogin(res, "/me");
      res.redirect(302, "/me");
    });
    app.get("/me", (req: Request, res: Response, next) => {
      if (wantsHtml(req) && !hasSession(req)) return toLogin(res, "/me");
      next();
    });
  }

  // ── Static pages ─────────────────────────────────────────────
  if (deps.adminUiDir) {
    app.use("/me", express.static(deps.adminUiDir, { index: "me.html" }));
    app.use("/admin", express.static(deps.adminUiDir, { index: "admin.html" }));
  }

  return app;
}
