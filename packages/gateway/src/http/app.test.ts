/**
 * Integration test: real Express app + real repo/policy + fake upstream.
 * Exercises the auth wiring, role-filtered tools/list, call-time policy
 * re-check, principal-bound sessions, and the admin API guard.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { openDatabase } from "../db/index.js";
import { Repo } from "../db/repo.js";
import { PolicyService } from "../domain/policy.js";
import { UpstreamManager, type UpstreamLink } from "../upstream/manager.js";
import type { GatewayConfig, UpstreamSpec } from "../config.js";
import { createApp, originAllowed } from "./app.js";

const upstreamSpec: UpstreamSpec = {
  id: "fake",
  namespace: "fake",
  transport: "http",
  url: "http://unused/mcp",
  headers: {},
  enabled: true,
};

const tools: Tool[] = [
  { name: "read_thing", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
  { name: "write_thing", inputSchema: { type: "object" } },
];

const fakeLink: UpstreamLink = {
  spec: upstreamSpec,
  onToolListChanged: null,
  onRecovered: null,
  async connect() {},
  async listTools() {
    return tools;
  },
  async callTool(name): Promise<CallToolResult> {
    return { content: [{ type: "text", text: `ok:${name}` }] };
  },
  async close() {},
};

const config: GatewayConfig = {
  port: 0,
  publicUrl: "http://localhost:0",
  configPath: "unused",
  dbPath: ":memory:",
  allowedOrigins: [],
  upstreamsFromFile: [],
  staticTokens: [
    { token: "tok-viewer", roleName: "viewer", label: "alice" },
    { token: "tok-admin", roleName: "admin", label: "root" },
  ],
  oidc: null,
  login: null,
  gatewayJwtSecret: null,
  adminBootstrapSubjects: [],
  devAllowUnauthenticated: false,
  bao: null,
  keyVault: null,
  mode: "standalone",
};

let httpServer: HttpServer;
let base: string;
let repo: Repo;

beforeAll(async () => {
  repo = new Repo(openDatabase(":memory:"));
  const manager = new UpstreamManager([upstreamSpec], () => fakeLink);
  await manager.start();
  const app = createApp({
    config,
    repo,
    manager,
    policy: new PolicyService(repo),
    secretStore: null,
    oidcVerifier: null,
    adminUiDir: null,
  });
  httpServer = app.listen(0);
  base = `http://localhost:${(httpServer.address() as AddressInfo).port}`;
});

afterAll(() => {
  httpServer.close();
});

interface RpcReply {
  status: number;
  sessionId?: string;
  json?: { result?: Record<string, never> & { tools?: Tool[]; content?: Array<{ text: string }>; isError?: boolean } };
}

async function rpc(body: unknown, token?: string, sessionId?: string): Promise<RpcReply> {
  const response = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const dataLine = text.split("\n").find((line) => line.startsWith("data:"));
  const raw = dataLine ? dataLine.slice(5).trim() : text;
  return {
    status: response.status,
    ...(response.headers.get("mcp-session-id")
      ? { sessionId: response.headers.get("mcp-session-id")! }
      : {}),
    ...(raw ? { json: JSON.parse(raw) } : {}),
  };
}

const initBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
};

async function initSession(token: string): Promise<string> {
  const reply = await rpc(initBody, token);
  expect(reply.status).toBe(200);
  await fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
      "mcp-session-id": reply.sessionId!,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });
  return reply.sessionId!;
}

const listTools = async (token: string, sid: string) =>
  (await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }, token, sid)).json!.result!.tools!.map(
    (t) => t.name
  );

describe("gateway HTTP app", () => {
  it("serves /health without auth", async () => {
    const response = await fetch(`${base}/health`);
    expect(response.status).toBe(200);
  });

  it("rejects unauthenticated /mcp requests", async () => {
    const reply = await rpc(initBody);
    expect(reply.status).toBe(401);
  });

  it("PRM endpoint 404s when OIDC is not configured", async () => {
    const response = await fetch(`${base}/.well-known/oauth-protected-resource`);
    expect(response.status).toBe(404);
  });

  it("filters tools/list by role and re-checks at call time", async () => {
    const viewerSid = await initSession("tok-viewer");
    expect(await listTools("tok-viewer", viewerSid)).toEqual(["fake_read_thing"]);

    const adminSid = await initSession("tok-admin");
    expect((await listTools("tok-admin", adminSid)).sort()).toEqual([
      "fake_read_thing",
      "fake_write_thing",
    ]);

    // viewer calling a write tool → policy stops it before the upstream
    const denied = await rpc(
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "fake_write_thing", arguments: {} } },
      "tok-viewer",
      viewerSid
    );
    expect(denied.json?.result?.isError).toBe(true);
    expect(denied.json?.result?.content?.[0]?.text).toContain("not available");

    // and an allowed call flows through to the upstream
    const allowed = await rpc(
      { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "fake_read_thing", arguments: {} } },
      "tok-viewer",
      viewerSid
    );
    expect(allowed.json?.result?.content?.[0]?.text).toBe("ok:read_thing");
  });

  it("binds sessions to principals — a different token on the same session is 403", async () => {
    const sid = await initSession("tok-viewer");
    const hijack = await rpc({ jsonrpc: "2.0", id: 5, method: "tools/list" }, "tok-admin", sid);
    expect(hijack.status).toBe(403);
  });

  it("disabling a tool removes it for everyone", async () => {
    repo.upsertToolSetting({ upstreamId: "fake", toolName: "read_thing", enabled: false });
    try {
      const sid = await initSession("tok-admin");
      expect(await listTools("tok-admin", sid)).toEqual(["fake_write_thing"]);
    } finally {
      repo.upsertToolSetting({ upstreamId: "fake", toolName: "read_thing", enabled: true });
    }
  });

  it("guards the admin API by role", async () => {
    const asViewer = await fetch(`${base}/api/status`, {
      headers: { Authorization: "Bearer tok-viewer" },
    });
    expect(asViewer.status).toBe(403);

    const asAdmin = await fetch(`${base}/api/status`, {
      headers: { Authorization: "Bearer tok-admin" },
    });
    expect(asAdmin.status).toBe(200);
    const body = (await asAdmin.json()) as { upstreams: Array<{ id: string }> };
    expect(body.upstreams.map((u) => u.id)).toEqual(["fake"]);
  });
});

describe("admin directory search endpoint", () => {
  it("reports configured:false when no directory search is wired", async () => {
    const response = await fetch(`${base}/api/directory/search?q=ndr`, {
      headers: { Authorization: "Bearer tok-admin" },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ configured: false, results: [] });
  });

  it("is admin-only and proxies to the injected search", async () => {
    const fakeSearch = {
      async search(query: string, type: string) {
        return [{ kind: "group" as const, id: "g1", displayName: `hit:${query}:${type}`, secondary: "" }];
      },
      async namesByIds(ids: string[]) {
        return Object.fromEntries(ids.filter((id) => id === "known-guid").map((id) => [id, "Known Group"]));
      },
    };
    const app = createApp({
      config,
      repo,
      manager: new UpstreamManager([upstreamSpec], () => fakeLink),
      policy: new PolicyService(repo),
      secretStore: null,
      oidcVerifier: null,
      directorySearch: fakeSearch,
      adminUiDir: null,
    });
    const server = app.listen(0);
    try {
      const port = (server.address() as AddressInfo).port;
      const asViewer = await fetch(`http://localhost:${port}/api/directory/search?q=ndr`, {
        headers: { Authorization: "Bearer tok-viewer" },
      });
      expect(asViewer.status).toBe(403);

      const asAdmin = await fetch(`http://localhost:${port}/api/directory/search?q=ndr&type=group`, {
        headers: { Authorization: "Bearer tok-admin" },
      });
      const body = (await asAdmin.json()) as { configured: boolean; results: Array<{ displayName: string }> };
      expect(body.configured).toBe(true);
      expect(body.results[0]?.displayName).toBe("hit:ndr:group");

      // sub-2-char query returns empty without touching the search
      const short = await fetch(`http://localhost:${port}/api/directory/search?q=n`, {
        headers: { Authorization: "Bearer tok-admin" },
      });
      expect(await short.json()).toEqual({ configured: true, results: [] });

      // group-mappings are enriched with directory display names when resolvable
      const editor = repo.roleByName("editor")!;
      repo.setGroupMapping("https://idp", "known-guid", editor.id);
      repo.setGroupMapping("https://idp", "unknown-guid", editor.id);
      try {
        const mappings = (await (
          await fetch(`http://localhost:${port}/api/group-mappings`, {
            headers: { Authorization: "Bearer tok-admin" },
          })
        ).json()) as Array<{ claimValue: string; claimLabel: string | null }>;
        expect(mappings.find((m) => m.claimValue === "known-guid")?.claimLabel).toBe("Known Group");
        expect(mappings.find((m) => m.claimValue === "unknown-guid")?.claimLabel).toBeNull();
      } finally {
        for (const m of repo.listGroupMappings()) repo.deleteGroupMapping(m.id);
      }
    } finally {
      server.close();
    }
  });
});

describe("originAllowed", () => {
  it("passes absent Origin and localhost; rejects malformed and unlisted", () => {
    expect(originAllowed(undefined, [])).toBe(true);
    expect(originAllowed("http://localhost:5173", [])).toBe(true);
    expect(originAllowed("null", [])).toBe(false);
    expect(originAllowed("https://evil.com", [])).toBe(false);
    expect(originAllowed("https://ok.com", ["https://ok.com"])).toBe(true);
  });
});
