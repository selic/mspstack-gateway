/**
 * Integration test for /api/me — user self-service: effective access,
 * narrow-only prefs (rejected outside the envelope), credential registration
 * (value → secret store, ref only in SQLite and the response).
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { openDatabase } from "../db/index.js";
import { Repo } from "../db/repo.js";
import { PolicyService } from "../domain/policy.js";
import { UpstreamManager, type UpstreamLink } from "../upstream/manager.js";
import { MemorySecretStore } from "../secrets/memory.js";
import type { GatewayConfig, UpstreamSpec } from "../config.js";
import { createApp } from "./app.js";

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
    { token: "tok-editor", roleName: "editor", label: "bob" },
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
let secretStore: MemorySecretStore;

beforeAll(async () => {
  repo = new Repo(openDatabase(":memory:"));
  repo.upsertUpstream(upstreamSpec, "api");
  secretStore = new MemorySecretStore();
  const manager = new UpstreamManager([upstreamSpec], () => fakeLink);
  await manager.start();
  const app = createApp({
    config,
    repo,
    manager,
    policy: new PolicyService(repo),
    secretStore,
    oidcVerifier: null,
    adminUiDir: null,
  });
  httpServer = app.listen(0);
  base = `http://localhost:${(httpServer.address() as AddressInfo).port}`;
});

afterAll(() => {
  httpServer.close();
});

async function me(
  method: string,
  path: string,
  token: string,
  body?: unknown
): Promise<{ status: number; json: Record<string, unknown> }> {
  const response = await fetch(`${base}/api/me${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: response.status, json: (await response.json()) as Record<string, unknown> };
}

describe("/api/me", () => {
  it("rejects unauthenticated requests", async () => {
    const response = await fetch(`${base}/api/me/access`);
    expect(response.status).toBe(401);
  });

  it("is reachable by NON-admin principals (unlike /api/*)", async () => {
    const { status } = await me("GET", "/access", "tok-viewer");
    expect(status).toBe(200);
    const admin = await fetch(`${base}/api/status`, {
      headers: { Authorization: "Bearer tok-viewer" },
    });
    expect(admin.status).toBe(403); // the admin API still requires admin
  });

  it("GET /access shows only the envelope, with personal enabled flags", async () => {
    const { json } = await me("GET", "/access", "tok-viewer");
    const servers = json.servers as Array<{ upstreamId: string; enabled: boolean; tools: Array<{ name: string; enabled: boolean }> }>;
    expect(servers).toHaveLength(1);
    // viewer's envelope: read_thing only — write_thing must not even be listed.
    expect(servers[0]!.tools.map((t) => t.name)).toEqual(["read_thing"]);
    expect(servers[0]!.tools[0]!.enabled).toBe(true);
  });

  it("PUT /prefs narrows and GET /access reflects it; MCP tools/list agrees", async () => {
    const put = await me("PUT", "/prefs", "tok-editor", {
      upstreamId: "fake",
      toolName: "write_thing",
      enabled: false,
    });
    expect(put.status).toBe(200);

    const { json } = await me("GET", "/access", "tok-editor");
    const servers = json.servers as Array<{ tools: Array<{ name: string; enabled: boolean }> }>;
    const writeTool = servers[0]!.tools.find((t) => t.name === "write_thing")!;
    expect(writeTool.enabled).toBe(false);

    // The MCP surface (the actual boundary) honors the same narrowing.
    const rpc = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer tok-editor",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } },
      }),
    });
    expect(rpc.status).toBe(200);

    // restore
    await me("PUT", "/prefs", "tok-editor", { upstreamId: "fake", toolName: "write_thing", enabled: true });
  });

  it("rejects prefs for tools outside the envelope (no widening, no junk)", async () => {
    // viewer never sees write_thing — targeting it is a 404, not a stored row.
    const denied = await me("PUT", "/prefs", "tok-viewer", {
      upstreamId: "fake",
      toolName: "write_thing",
      enabled: true,
    });
    expect(denied.status).toBe(404);
    const unknown = await me("PUT", "/prefs", "tok-viewer", { upstreamId: "nope", enabled: false });
    expect(unknown.status).toBe(404);
  });

  it("PUT /credentials stores the value in the secret store and returns only a ref", async () => {
    const put = await me("PUT", "/credentials/fake", "tok-editor", {
      field: "token",
      value: "super-secret-value",
    });
    expect(put.status).toBe(200);
    const ref = put.json.ref as string;
    expect(ref).toMatch(/^bao:gw-user-/); // memory store renders bao-style refs
    expect(JSON.stringify(put.json)).not.toContain("super-secret-value");

    const list = await me("GET", "/credentials", "tok-editor");
    const rows = list.json as unknown as Array<{ upstreamId: string; field: string; secretRef: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.secretRef).toBe(ref);
    expect(JSON.stringify(rows)).not.toContain("super-secret-value");

    // Another principal sees nothing.
    const other = await me("GET", "/credentials", "tok-viewer");
    expect(other.json).toEqual([]);
  });

  it("DELETE /credentials removes the registration", async () => {
    const del = await me("DELETE", "/credentials/fake/token", "tok-editor");
    expect(del.status).toBe(200);
    expect(del.json.ok).toBe(true);
    const list = await me("GET", "/credentials", "tok-editor");
    expect(list.json).toEqual([]);
  });

  it("404s credentials for unknown upstreams", async () => {
    const put = await me("PUT", "/credentials/ghost", "tok-editor", { field: "token", value: "x" });
    expect(put.status).toBe(404);
  });
});
