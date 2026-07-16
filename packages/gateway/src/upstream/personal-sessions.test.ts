/**
 * sessionMode:"per-user" — per-principal upstream sessions (slice 5).
 *
 * End-to-end over the real HTTP app: two principals register different
 * credentials for a per-user upstream; each call runs over a link whose spec
 * carries THAT caller's credential ref. Fallback and require-personal paths
 * covered, plus pool lifecycle on upstream removal.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { openDatabase } from "../db/index.js";
import { Repo } from "../db/repo.js";
import { PolicyService } from "../domain/policy.js";
import { UpstreamManager, type UpstreamLink } from "./manager.js";
import { MemorySecretStore } from "../secrets/memory.js";
import type { GatewayConfig, UpstreamSpec } from "../config.js";
import { createApp } from "../http/app.js";

const perUserSpec: UpstreamSpec = {
  id: "peruser",
  namespace: "peruser",
  transport: "http",
  url: "http://unused/mcp",
  headers: { Authorization: "Bearer bao:upstreams/peruser#token" },
  enabled: true,
  sessionMode: "per-user",
  requirePersonalCredentials: false,
};

const strictSpec: UpstreamSpec = {
  id: "strict",
  namespace: "strict",
  transport: "http",
  url: "http://unused/mcp",
  headers: {},
  enabled: true,
  sessionMode: "per-user",
  requirePersonalCredentials: true,
};

const tools: Tool[] = [
  { name: "who", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
];

/** Fake link that echoes back which Authorization ref its spec carries. */
const linksCreated: UpstreamSpec[] = [];
function fakeLink(spec: UpstreamSpec): UpstreamLink {
  linksCreated.push(spec);
  return {
    spec,
    onToolListChanged: null,
    onRecovered: null,
    async connect() {},
    async listTools() {
      return tools;
    },
    async callTool(name): Promise<CallToolResult> {
      const auth = spec.transport === "http" ? (spec.headers.Authorization ?? "none") : "none";
      return { content: [{ type: "text", text: `${name} via ${auth}` }] };
    },
    async close() {},
  };
}

const config: GatewayConfig = {
  port: 0,
  publicUrl: "http://localhost:0",
  configPath: "unused",
  dbPath: ":memory:",
  allowedOrigins: [],
  upstreamsFromFile: [],
  staticTokens: [
    { token: "tok-alice", roleName: "viewer", label: "alice" },
    { token: "tok-bob", roleName: "viewer", label: "bob" },
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
let manager: UpstreamManager;

beforeAll(async () => {
  const repo = new Repo(openDatabase(":memory:"));
  repo.upsertUpstream(perUserSpec, "api");
  repo.upsertUpstream(strictSpec, "api");
  manager = new UpstreamManager([perUserSpec, strictSpec], fakeLink);
  await manager.start();
  const app = createApp({
    config,
    repo,
    manager,
    policy: new PolicyService(repo),
    secretStore: new MemorySecretStore(),
    oidcVerifier: null,
    adminUiDir: null,
  });
  httpServer = app.listen(0);
  base = `http://localhost:${(httpServer.address() as AddressInfo).port}`;
});

afterAll(() => {
  httpServer.close();
});

async function rpc(token: string, body: unknown, sessionId?: string): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    body: JSON.stringify(body),
  });
}

async function callTool(token: string, name: string): Promise<string> {
  // initialize → initialized → call (minimal streamable-HTTP dance).
  const init = await rpc(token, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
  });
  const sessionId = init.headers.get("mcp-session-id")!;
  await rpc(token, { jsonrpc: "2.0", method: "notifications/initialized" }, sessionId);
  const response = await rpc(
    token,
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: {} } },
    sessionId
  );
  const text = await response.text();
  // SSE or JSON — extract the result line either way.
  const jsonLine = text.split("\n").find((line) => line.startsWith("data:"))?.slice(5) ?? text;
  const parsed = JSON.parse(jsonLine) as { result?: { content?: Array<{ text: string }>; isError?: boolean } };
  return parsed.result?.content?.[0]?.text ?? "";
}

async function putCredential(token: string, upstreamId: string, value: string): Promise<string> {
  const response = await fetch(`${base}/api/me/credentials/${upstreamId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ field: "Authorization", value }),
  });
  const json = (await response.json()) as { ref: string };
  return json.ref;
}

describe("per-user upstream sessions", () => {
  it("falls back to the shared connection when the caller has no creds", async () => {
    const text = await callTool("tok-alice", "peruser_who");
    expect(text).toBe("who via Bearer bao:upstreams/peruser#token");
  });

  it("routes each principal over a link carrying THEIR credential ref", async () => {
    const aliceRef = await putCredential("tok-alice", "peruser", "alice-secret");
    const bobRef = await putCredential("tok-bob", "peruser", "bob-secret");
    expect(aliceRef).not.toBe(bobRef);

    const aliceText = await callTool("tok-alice", "peruser_who");
    const bobText = await callTool("tok-bob", "peruser_who");
    expect(aliceText).toBe(`who via ${aliceRef}`);
    expect(bobText).toBe(`who via ${bobRef}`);
    // Distinct pooled links were created for the two principals.
    const personal = linksCreated.filter(
      (s) => s.id === "peruser" && s.transport === "http" && s.headers.Authorization !== perUserSpec.headers!.Authorization
    );
    expect(personal).toHaveLength(2);
  });

  it("reuses the caller's personal link across calls (pooled, not per-call)", async () => {
    const before = linksCreated.length;
    await callTool("tok-alice", "peruser_who");
    await callTool("tok-alice", "peruser_who");
    expect(linksCreated.length).toBe(before);
  });

  it("requirePersonalCredentials refuses the shared fallback", async () => {
    const text = await callTool("tok-bob", "strict_who");
    expect(text).toMatch(/requires personal credentials/);
    await putCredential("tok-bob", "strict", "bob-strict-secret");
    const after = await callTool("tok-bob", "strict_who");
    expect(after).toMatch(/^who via bao:gw-user-/);
  });

  it("upstream removal closes and forgets personal links", async () => {
    const before = linksCreated.length;
    await manager.upsertUpstream(perUserSpec); // upsert = remove + re-register
    await callTool("tok-alice", "peruser_who");
    // A fresh personal link had to be created after the pool was flushed.
    expect(linksCreated.length).toBeGreaterThan(before);
  });
});
