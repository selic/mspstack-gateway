import { describe, expect, it, vi } from "vitest";
import type { LoginConfig, OidcConfig } from "../config.js";
import { createDirectorySearch, tenantFromIssuer } from "./directory.js";

const oidc: OidcConfig = {
  issuer: "https://login.microsoftonline.com/tenant-guid/v2.0",
  audience: "api://gw",
  groupsClaim: "groups",
};
const login: LoginConfig = {
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "https://gw/auth/callback",
  sessionSecret: "session-secret-0123456789",
};

describe("tenantFromIssuer", () => {
  it("extracts the tenant from an Entra v2 issuer and rejects others", () => {
    expect(tenantFromIssuer("https://login.microsoftonline.com/abc-123/v2.0")).toBe("abc-123");
    expect(tenantFromIssuer("https://login.microsoftonline.com/abc-123/v2.0/")).toBe("abc-123");
    expect(tenantFromIssuer("https://idp.example.com/realms/main")).toBeNull();
    expect(tenantFromIssuer("https://login.microsoftonline.com/")).toBeNull();
  });
});

/** fetch fake: token endpoint + graph endpoints, recording calls. */
function fakeGraph() {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    if (url.includes("/oauth2/v2.0/token")) {
      return new Response(JSON.stringify({ access_token: "app-token", expires_in: 3600 }), { status: 200 });
    }
    if (url.includes("/groups?")) {
      return new Response(
        JSON.stringify({ value: [{ id: "g1", displayName: "NDR-Security", mail: "sec@ndr" }] }),
        { status: 200 }
      );
    }
    if (url.includes("/users?")) {
      return new Response(
        JSON.stringify({ value: [{ id: "u1", displayName: "Eugene", mail: "e@ndr", userPrincipalName: "e@ndr" }] }),
        { status: 200 }
      );
    }
    return new Response("not found", { status: 404 });
  });
  return { calls, fetchImpl: fetchImpl as unknown as typeof fetch };
}

describe("createDirectorySearch", () => {
  it("is null for non-Entra issuers", () => {
    expect(
      createDirectorySearch({ ...oidc, issuer: "https://idp.example.com" }, login)
    ).toBeNull();
  });

  it("searches groups and users, groups first", async () => {
    const { fetchImpl } = fakeGraph();
    const search = createDirectorySearch(oidc, login, fetchImpl)!;
    const results = await search.search("ndr", "all");
    expect(results.map((r) => `${r.kind}:${r.id}`)).toEqual(["group:g1", "user:u1"]);
    expect(results[0]!.displayName).toBe("NDR-Security");
  });

  it("type=group hits only the groups endpoint and caches the app token", async () => {
    const { calls, fetchImpl } = fakeGraph();
    const search = createDirectorySearch(oidc, login, fetchImpl)!;
    await search.search("ndr", "group");
    await search.search("security", "group");
    expect(calls.filter((u) => u.includes("/token")).length).toBe(1); // cached
    expect(calls.some((u) => u.includes("/users?"))).toBe(false);
    expect(calls.filter((u) => u.includes("/groups?")).length).toBe(2);
  });

  it("short or quote-only queries return [] without any network call", async () => {
    const { calls, fetchImpl } = fakeGraph();
    const search = createDirectorySearch(oidc, login, fetchImpl)!;
    expect(await search.search("a", "all")).toEqual([]);
    expect(await search.search('""', "all")).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("namesByIds resolves via getByIds, caches, and swallows failures", async () => {
    const calls: string[] = [];
    let fail = false;
    const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      calls.push(url);
      if (url.includes("/oauth2/v2.0/token")) {
        return new Response(JSON.stringify({ access_token: "t", expires_in: 3600 }), { status: 200 });
      }
      if (fail) return new Response("boom", { status: 500 });
      const body = JSON.parse(String(init?.body)) as { ids: string[] };
      return new Response(
        JSON.stringify({ value: body.ids.filter((id) => id !== "ghost").map((id) => ({ id, displayName: `Name-${id}` })) }),
        { status: 200 }
      );
    }) as unknown as typeof fetch;

    const search = createDirectorySearch(oidc, login, fetchImpl)!;
    expect(await search.namesByIds(["g1", "ghost"])).toEqual({ g1: "Name-g1" });
    // cached: no second getByIds for g1
    expect(await search.namesByIds(["g1"])).toEqual({ g1: "Name-g1" });
    expect(calls.filter((u) => u.includes("getByIds")).length).toBe(1);
    // failures degrade to {} (labels are cosmetic)
    fail = true;
    expect(await search.namesByIds(["g2"])).toEqual({});
  });

  it("surfaces Graph failures as thrown errors (the API maps them to 502)", async () => {
    const failing = (async () => new Response("nope", { status: 403 })) as unknown as typeof fetch;
    const search = createDirectorySearch(oidc, login, failing)!;
    await expect(search.search("ndr", "group")).rejects.toThrow();
  });
});
