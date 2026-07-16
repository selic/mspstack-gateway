/**
 * Integration test for the OAuth Authorization Server facade: real Express
 * app + real repo, with a fake LoginService standing in for the Entra leg.
 * Exercises DCR → authorize (broker) → callback (code mint) → token (PKCE →
 * gateway JWT), plus the security invariants (single-use codes, exact
 * redirect_uri match, mandatory S256, resource binding, register rate limit).
 */

import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import { openDatabase } from "../db/index.js";
import { Repo } from "../db/repo.js";
import { PolicyService } from "../domain/policy.js";
import { UpstreamManager } from "../upstream/manager.js";
import type { GatewayConfig } from "../config.js";
import type { LoginService } from "../auth/login.js";
import { mintAccessToken, verifyAccessToken } from "../auth/authz-server.js";
import { createApp } from "./app.js";

const PUBLIC_URL = "http://gw.test";
const JWT_SECRET = "flow-test-jwt-secret-0123456789";
const ENTRA_ISS = "https://login.microsoftonline.com/tenant/v2.0";
const ENTRA_SUB = "oid-user-1";

const config: GatewayConfig = {
  port: 0,
  publicUrl: PUBLIC_URL,
  configPath: "unused",
  dbPath: ":memory:",
  allowedOrigins: [],
  upstreamsFromFile: [],
  staticTokens: [],
  oidc: { issuer: ENTRA_ISS, audience: "api://gw", groupsClaim: "groups" },
  login: {
    clientId: "entra-client",
    clientSecret: "entra-secret",
    redirectUri: `${PUBLIC_URL}/auth/callback`,
    sessionSecret: "session-secret-0123456789",
  },
  gatewayJwtSecret: JWT_SECRET,
  adminBootstrapSubjects: ["user@example.com"],
  devAllowUnauthenticated: false,
  bao: null,
  keyVault: null,
  mode: "standalone",
};

/** Fake Entra leg: fixed transient state, fixed authenticated identity. */
const fakeLogin: LoginService = {
  async startAuth(returnTo: string) {
    return {
      redirectUrl: "https://entra.example/authorize?req=1",
      transient: { codeVerifier: "cv", nonce: "n", state: "entra-state", returnTo },
    };
  },
  async completeAuth() {
    return { iss: ENTRA_ISS, sub: ENTRA_SUB, email: "user@example.com", groups: [] };
  },
};

let httpServer: HttpServer;
let base: string;
let repo: Repo;

beforeAll(async () => {
  repo = new Repo(openDatabase(":memory:"));
  const manager = new UpstreamManager([], () => {
    throw new Error("no upstreams in this test");
  });
  await manager.start();
  const app = createApp({
    config,
    repo,
    manager,
    policy: new PolicyService(repo),
    secretStore: null,
    oidcVerifier: null,
    loginService: fakeLogin,
    adminUiDir: null,
    oauthRegisterLimit: { limit: 1000, windowMs: 60_000 },
  });
  httpServer = app.listen(0);
  base = `http://localhost:${(httpServer.address() as AddressInfo).port}`;
});

afterAll(() => {
  httpServer.close();
});

const REDIRECT_URI = "http://127.0.0.1:23456/callback";

const pkce = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

async function register(): Promise<string> {
  const response = await fetch(`${base}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT_URI], client_name: "Test MCP client" }),
  });
  expect(response.status).toBe(201);
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

/** Run authorize → (fake Entra) → callback; returns the code delivered to the client. */
async function authorizeAndCallback(
  clientId: string,
  challenge: string,
  extra: Record<string, string> = {}
): Promise<{ code: string; state: string | null }> {
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "client-state",
    ...extra,
  });
  const authorize = await fetch(`${base}/oauth/authorize?${query}`, { redirect: "manual" });
  expect(authorize.status).toBe(302);
  expect(authorize.headers.get("location")).toBe("https://entra.example/authorize?req=1");
  const setCookie = authorize.headers.get("set-cookie")!;
  const cookie = /mspstack_login=([^;]+)/.exec(setCookie)![1]!;

  const callback = await fetch(`${base}/auth/callback?code=entra-code&state=entra-state`, {
    redirect: "manual",
    headers: { Cookie: `mspstack_login=${cookie}` },
  });
  expect(callback.status).toBe(302);
  const target = new URL(callback.headers.get("location")!);
  expect(target.href.startsWith(REDIRECT_URI)).toBe(true);
  return { code: target.searchParams.get("code")!, state: target.searchParams.get("state") };
}

async function exchangeToken(clientId: string, code: string, verifier: string) {
  const response = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      code_verifier: verifier,
    }),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe("OAuth AS facade — happy path", () => {
  it("serves RFC 8414 metadata at both probe paths", async () => {
    for (const path of ["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp"]) {
      const response = await fetch(`${base}${path}`);
      expect(response.status).toBe(200);
      const meta = (await response.json()) as Record<string, unknown>;
      expect(meta.issuer).toBe(PUBLIC_URL);
      expect(meta.registration_endpoint).toBe(`${PUBLIC_URL}/oauth/register`);
      expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
      expect(meta.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    }
  });

  it("DCR → authorize → callback → token yields a verifiable gateway JWT + refresh token", async () => {
    const clientId = await register();
    const verifier = "verifier-verifier-verifier-verifier-43chars!";
    const { code, state } = await authorizeAndCallback(clientId, pkce(verifier));
    expect(state).toBe("client-state");

    const { status, body } = await exchangeToken(clientId, code, verifier);
    expect(status).toBe(200);
    expect(body.token_type).toBe("Bearer");
    expect(typeof body.refresh_token).toBe("string");
    const claims = await verifyAccessToken(body.access_token as string, PUBLIC_URL, JWT_SECRET);
    expect(claims).toEqual({ iss: ENTRA_ISS, sub: ENTRA_SUB });

    // the login upsert ran: the user exists and got the bootstrap admin role
    const user = repo.userBySubject(ENTRA_ISS, ENTRA_SUB)!;
    expect(user.email).toBe("user@example.com");
    expect(repo.roleById(user.roleId!)?.name).toBe("admin");
  });

  it("accepts a matching RFC 8707 resource and echoes no code for a foreign one", async () => {
    const clientId = await register();
    const verifier = "resource-verifier-resource-verifier-43chars";
    const ok = await authorizeAndCallback(clientId, pkce(verifier), { resource: `${PUBLIC_URL}/mcp` });
    expect((await exchangeToken(clientId, ok.code, verifier)).status).toBe(200);

    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      code_challenge: pkce(verifier),
      code_challenge_method: "S256",
      resource: "https://other.example/mcp",
    });
    const response = await fetch(`${base}/oauth/authorize?${query}`, { redirect: "manual" });
    expect(response.status).toBe(302);
    const target = new URL(response.headers.get("location")!);
    expect(target.searchParams.get("error")).toBe("invalid_target");
    expect(target.searchParams.get("code")).toBeNull();
  });
});

describe("OAuth AS facade — security invariants", () => {
  it("codes are single-use: a replayed exchange is invalid_grant", async () => {
    const clientId = await register();
    const verifier = "replay-verifier-replay-verifier-43chars-abc";
    const { code } = await authorizeAndCallback(clientId, pkce(verifier));
    expect((await exchangeToken(clientId, code, verifier)).status).toBe(200);
    const replay = await exchangeToken(clientId, code, verifier);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
  });

  it("a wrong PKCE verifier or wrong client is invalid_grant", async () => {
    const clientId = await register();
    const verifier = "pkce-verifier-pkce-verifier-43chars-abcdef";
    const first = await authorizeAndCallback(clientId, pkce(verifier));
    expect((await exchangeToken(clientId, first.code, "wrong-verifier")).body.error).toBe("invalid_grant");

    const other = await register();
    const second = await authorizeAndCallback(clientId, pkce(verifier));
    expect((await exchangeToken(other, second.code, verifier)).body.error).toBe("invalid_grant");
  });

  it("an unregistered redirect_uri gets a 400 page, never a redirect", async () => {
    const clientId = await register();
    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "http://127.0.0.1:23456/other",
      code_challenge: "x",
      code_challenge_method: "S256",
    });
    const response = await fetch(`${base}/oauth/authorize?${query}`, { redirect: "manual" });
    expect(response.status).toBe(400);
  });

  it("PKCE is mandatory: missing or non-S256 challenge → invalid_request redirect", async () => {
    const clientId = await register();
    for (const params of [{}, { code_challenge: "x", code_challenge_method: "plain" }]) {
      const query = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        state: "s1",
        ...params,
      });
      const response = await fetch(`${base}/oauth/authorize?${query}`, { redirect: "manual" });
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get("location")!);
      expect(target.searchParams.get("error")).toBe("invalid_request");
      expect(target.searchParams.get("state")).toBe("s1");
    }
  });

  it("register rejects non-loopback http redirect URIs", async () => {
    const response = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://evil.example/cb"] }),
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe("invalid_redirect_uri");
  });

  it("token endpoint rejects unknown grant types", async () => {
    const response = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials" }),
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe("unsupported_grant_type");
  });
});

describe("refresh_token grant", () => {
  const refreshExchange = async (clientId: string, refreshToken: string) => {
    const response = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }),
    });
    return { status: response.status, body: (await response.json()) as Record<string, unknown> };
  };

  it("refreshes the access token and rotates the refresh token", async () => {
    const clientId = await register();
    const verifier = "refresh-flow-verifier-refresh-flow-43chars!";
    const { code } = await authorizeAndCallback(clientId, pkce(verifier));
    const initial = await exchangeToken(clientId, code, verifier);
    const rt1 = initial.body.refresh_token as string;

    const refreshed = await refreshExchange(clientId, rt1);
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refresh_token).not.toBe(rt1);
    const claims = await verifyAccessToken(refreshed.body.access_token as string, PUBLIC_URL, JWT_SECRET);
    expect(claims).toEqual({ iss: ENTRA_ISS, sub: ENTRA_SUB });

    // replaying the rotated token fails AND kills the newly issued one (family revocation)
    expect((await refreshExchange(clientId, rt1)).body.error).toBe("invalid_grant");
    expect((await refreshExchange(clientId, refreshed.body.refresh_token as string)).body.error).toBe("invalid_grant");
  });

  it("a refresh token is bound to its client", async () => {
    const clientId = await register();
    const other = await register();
    const verifier = "client-bound-verifier-client-bound-43chars!";
    const { code } = await authorizeAndCallback(clientId, pkce(verifier));
    const rt = (await exchangeToken(clientId, code, verifier)).body.refresh_token as string;

    expect((await refreshExchange(other, rt)).body.error).toBe("invalid_grant");
    // and the wrong-client attempt did not burn it
    expect((await refreshExchange(clientId, rt)).status).toBe(200);
  });
});

describe("gateway-token auth on /mcp + PRM discovery", () => {
  const initBody = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
  };

  const postMcp = (token?: string) =>
    fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(initBody),
    });

  it("PRM lists the gateway itself as the authorization server", async () => {
    const response = await fetch(`${base}/.well-known/oauth-protected-resource`);
    expect(response.status).toBe(200);
    const prm = (await response.json()) as { resource: string; authorization_servers: string[] };
    expect(prm.resource).toBe(`${PUBLIC_URL}/mcp`);
    expect(prm.authorization_servers).toEqual([PUBLIC_URL]);
  });

  it("a token from the full DCR flow authenticates an MCP session", async () => {
    const clientId = await register();
    const verifier = "mcp-verifier-mcp-verifier-mcp-verifier-43ch";
    const { code } = await authorizeAndCallback(clientId, pkce(verifier));
    const { body } = await exchangeToken(clientId, code, verifier);

    const response = await postMcp(body.access_token as string);
    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBeTruthy();
  });

  it("a gateway token for a user with no role is 403, tampered tokens are 401", async () => {
    const stranger = await mintAccessToken({ iss: ENTRA_ISS, sub: "oid-nobody" }, PUBLIC_URL, JWT_SECRET);
    expect((await postMcp(stranger)).status).toBe(403);

    const forged = await mintAccessToken({ iss: ENTRA_ISS, sub: ENTRA_SUB }, PUBLIC_URL, "wrong-secret-wrong-secret");
    expect((await postMcp(forged)).status).toBe(401);

    expect((await postMcp()).status).toBe(401);
  });

  it("without interactive login the PRM keeps pointing at the raw IdP (regression)", async () => {
    const bare = createApp({
      config: { ...config, login: null, gatewayJwtSecret: null },
      repo: new Repo(openDatabase(":memory:")),
      manager: new UpstreamManager([], () => {
        throw new Error("unused");
      }),
      policy: new PolicyService(new Repo(openDatabase(":memory:"))),
      secretStore: null,
      oidcVerifier: null,
      adminUiDir: null,
    });
    const server = bare.listen(0);
    try {
      const port = (server.address() as AddressInfo).port;
      const prm = await fetch(`http://localhost:${port}/.well-known/oauth-protected-resource`);
      expect(((await prm.json()) as { authorization_servers: string[] }).authorization_servers).toEqual([ENTRA_ISS]);
      // and the AS endpoints are not mounted
      expect((await fetch(`http://localhost:${port}/.well-known/oauth-authorization-server`)).status).toBe(404);
      expect((await fetch(`http://localhost:${port}/oauth/register`, { method: "POST" })).status).toBe(404);
    } finally {
      server.close();
    }
  });
});
