import { describe, expect, it } from "vitest";
import { openDatabase } from "./index.js";
import { Repo } from "./repo.js";
import type { UpstreamSpec } from "../config.js";

const spec = (id: string, namespace: string): UpstreamSpec => ({
  id,
  namespace,
  transport: "http",
  url: `http://localhost/${id}/mcp`,
  headers: {},
  enabled: true,
});

const fresh = () => new Repo(openDatabase(":memory:"));

describe("Repo", () => {
  it("seeds protected viewer/editor/admin roles", () => {
    const repo = fresh();
    const names = repo.listRoles().map((r) => r.name);
    expect(names).toEqual(["viewer", "editor", "admin"]);
    expect(repo.roleByName("admin")?.isAdmin).toBe(true);
    expect(repo.roleByName("viewer")?.defaultMaxTier).toBe("read");
    // protected roles cannot be deleted
    expect(repo.deleteRole(repo.roleByName("admin")!.id)).toBe(false);
  });

  it("creates and deletes custom roles", () => {
    const repo = fresh();
    const role = repo.createRole("dispatch", "write");
    expect(repo.roleByName("dispatch")?.id).toBe(role.id);
    expect(repo.deleteRole(role.id)).toBe(true);
    expect(repo.roleByName("dispatch")).toBeNull();
  });

  it("upserts upstreams and rejects namespace collisions", () => {
    const repo = fresh();
    repo.upsertUpstream(spec("a", "one"), "file");
    repo.upsertUpstream({ ...spec("a", "one"), enabled: false }, "file"); // update ok
    expect(repo.getUpstream("a")?.spec.enabled).toBe(false);
    expect(() => repo.upsertUpstream(spec("b", "one"), "api")).toThrow(/namespace "one"/);
  });

  it("deleting an upstream removes its settings, overrides, and grants", () => {
    const repo = fresh();
    const viewer = repo.roleByName("viewer")!;
    repo.upsertUpstream(spec("a", "one"), "api");
    repo.upsertToolSetting({ upstreamId: "a", toolName: "t", enabled: false });
    repo.setOverride(viewer.id, "a", "t", "allow");
    repo.setGrant(viewer.id, "a", "write");
    repo.deleteUpstream("a");
    expect(repo.toolSetting("a", "t")).toBeNull();
    expect(repo.overrideFor(viewer.id, "a", "t")).toBeNull();
    expect(repo.grantFor(viewer.id, "a")).toBeNull();
  });

  it("tool setting upsert merges partial updates", () => {
    const repo = fresh();
    repo.upsertToolSetting({ upstreamId: "a", toolName: "t", tierOverride: "read" });
    repo.upsertToolSetting({ upstreamId: "a", toolName: "t", enabled: false });
    const setting = repo.toolSetting("a", "t")!;
    expect(setting.enabled).toBe(false);
    expect(setting.tierOverride).toBe("read"); // preserved
  });

  it("upserts users on login and keeps known fields", () => {
    const repo = fresh();
    const user = repo.upsertUserOnLogin({ iss: "https://idp", sub: "u1", email: "a@b.c" });
    const again = repo.upsertUserOnLogin({ iss: "https://idp", sub: "u1" });
    expect(again.id).toBe(user.id);
    expect(again.email).toBe("a@b.c"); // COALESCE keeps the earlier email
  });

  it("resolveOidcRole: explicit user role beats group mappings; highest tier mapping wins", () => {
    const repo = fresh();
    const viewer = repo.roleByName("viewer")!;
    const editor = repo.roleByName("editor")!;
    const admin = repo.roleByName("admin")!;
    const user = repo.upsertUserOnLogin({ iss: "https://idp", sub: "u1" });

    expect(repo.resolveOidcRole("https://idp", "u1", ["g1"])).toBeNull();

    repo.setGroupMapping("https://idp", "g1", viewer.id);
    repo.setGroupMapping("https://idp", "g2", editor.id);
    expect(repo.resolveOidcRole("https://idp", "u1", ["g1", "g2"])?.name).toBe("editor");

    repo.setUserRole(user.id, admin.id);
    expect(repo.resolveOidcRole("https://idp", "u1", ["g1"])?.name).toBe("admin");
  });

  it("stores and reads back OAuth clients", () => {
    const repo = fresh();
    repo.createOauthClient({
      clientId: "c1",
      clientName: "Claude",
      redirectUris: ["http://127.0.0.1:9000/cb", "https://client.example/cb"],
    });
    const client = repo.oauthClient("c1")!;
    expect(client.clientName).toBe("Claude");
    expect(client.redirectUris).toEqual(["http://127.0.0.1:9000/cb", "https://client.example/cb"]);
    expect(repo.oauthClient("nope")).toBeNull();
  });

  it("OAuth codes are single-use and expire", () => {
    const repo = fresh();
    const base = {
      clientId: "c1",
      principalIss: "https://idp",
      principalSub: "u1",
      codeChallenge: "chal",
      resource: "https://gw/mcp",
    };
    repo.insertOauthCode({ ...base, codeHash: "h1", expiresAt: Date.now() + 60_000 });

    const first = repo.consumeOauthCode("h1");
    expect(first?.principalSub).toBe("u1");
    expect(first?.usedAt).not.toBeNull();
    // replay → rejected
    expect(repo.consumeOauthCode("h1")).toBeNull();
    // unknown → rejected
    expect(repo.consumeOauthCode("h2")).toBeNull();

    // expired → rejected
    repo.insertOauthCode({ ...base, codeHash: "h3", expiresAt: Date.now() - 1 });
    expect(repo.consumeOauthCode("h3")).toBeNull();
  });

  it("lists and deletes OAuth clients with their codes and refresh tokens", () => {
    const repo = fresh();
    repo.createOauthClient({ clientId: "c1", clientName: "One", redirectUris: ["https://a/cb"] });
    repo.createOauthClient({ clientId: "c2", clientName: "Two", redirectUris: ["https://b/cb"] });
    repo.insertOauthCode({
      codeHash: "code1", clientId: "c1", principalIss: "https://idp", principalSub: "u1",
      codeChallenge: "ch", resource: null, expiresAt: Date.now() + 60_000,
    });
    repo.insertOauthRefreshToken({
      tokenHash: "rt1", clientId: "c1", principalIss: "https://idp", principalSub: "u1",
      familyId: "rt1", rotatedFrom: null, expiresAt: Date.now() + 60_000,
    });

    expect(repo.listOauthClients().map((c) => c.clientId).sort()).toEqual(["c1", "c2"]);
    expect(repo.deleteOauthClient("c1")).toBe(true);
    expect(repo.deleteOauthClient("c1")).toBe(false); // gone
    expect(repo.listOauthClients().map((c) => c.clientId)).toEqual(["c2"]);
    expect(repo.consumeOauthCode("code1")).toBeNull(); // cascaded
    expect(repo.consumeOauthRefreshToken("rt1", "c1").status).toBe("invalid"); // cascaded
  });

  it("refresh tokens rotate once; replay is classified as reuse; family revocation kills the chain", () => {
    const repo = fresh();
    const base = { clientId: "c1", principalIss: "https://idp", principalSub: "u1", familyId: "root" };
    repo.insertOauthRefreshToken({ ...base, tokenHash: "root", rotatedFrom: null, expiresAt: Date.now() + 60_000 });

    // wrong client must NOT burn the token
    expect(repo.consumeOauthRefreshToken("root", "other").status).toBe("invalid");

    const first = repo.consumeOauthRefreshToken("root", "c1");
    expect(first.status).toBe("ok");
    if (first.status === "ok") expect(first.row.principalSub).toBe("u1");

    // successor in the same family
    repo.insertOauthRefreshToken({ ...base, tokenHash: "gen2", rotatedFrom: "root", expiresAt: Date.now() + 60_000 });

    // replaying the rotated root → reuse signal with the family id
    const replay = repo.consumeOauthRefreshToken("root", "c1");
    expect(replay).toEqual({ status: "reuse", familyId: "root" });

    // revoking the family kills the live successor (and stamps the rotated root)
    expect(repo.revokeOauthRefreshFamily("root")).toBe(2);
    expect(repo.consumeOauthRefreshToken("gen2", "c1").status).toBe("reuse");

    // expired tokens are plain invalid
    repo.insertOauthRefreshToken({ ...base, tokenHash: "old", rotatedFrom: null, expiresAt: Date.now() - 1 });
    expect(repo.consumeOauthRefreshToken("old", "c1").status).toBe("invalid");
  });

  it("inserting a code sweeps expired ones", () => {
    const repo = fresh();
    const base = {
      clientId: "c1",
      principalIss: "https://idp",
      principalSub: "u1",
      codeChallenge: "chal",
      resource: null,
    };
    repo.insertOauthCode({ ...base, codeHash: "old", expiresAt: Date.now() - 1 });
    repo.insertOauthCode({ ...base, codeHash: "new", expiresAt: Date.now() + 60_000 });
    // the sweep removed "old" entirely (not just unredeemable)
    expect(repo.consumeOauthCode("old")).toBeNull();
    expect(repo.consumeOauthCode("new")).not.toBeNull();
  });
});
