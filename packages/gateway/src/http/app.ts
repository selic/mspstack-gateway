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
import type { Repo } from "../db/repo.js";
import type { PolicyService } from "../domain/policy.js";
import type { UpstreamManager } from "../upstream/manager.js";
import type { SecretStore } from "../secrets/store.js";
import type { OidcVerifier } from "../auth/oidc.js";
import { authenticateStaticToken, bearerToken } from "../auth/static-tokens.js";
import { principalKey, type Principal } from "../auth/principal.js";
import { PRM_PATH, prmDocument, wwwAuthenticate } from "../auth/prm.js";
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
      const user = repo.upsertUserOnLogin({
        iss: identity.iss,
        sub: identity.sub,
        ...(identity.email ? { email: identity.email } : {}),
        ...(identity.displayName ? { displayName: identity.displayName } : {}),
      });
      // Bootstrap: configured subjects become admin on first login (persisted
      // as an explicit user-role override so it is visible in the UI).
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
      if (!role) {
        return {
          ok: false,
          status: 403,
          code: -32003,
          message:
            "Authenticated, but no role is assigned — ask an administrator to map your user or group to a role.",
        };
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

    // 3. Explicit dev escape hatch.
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

      const server = createGatewayServer(manager, policy, auth.principal);
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

  if (deps.adminUiDir) {
    app.use("/admin", express.static(deps.adminUiDir, { index: "admin.html" }));
  }

  return app;
}
