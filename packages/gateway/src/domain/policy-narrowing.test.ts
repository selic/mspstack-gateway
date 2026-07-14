import { describe, expect, it } from "vitest";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { openDatabase } from "../db/index.js";
import { Repo } from "../db/repo.js";
import type { Principal } from "../auth/principal.js";
import { prefsIdentity, principalSlug } from "../auth/principal.js";
import type { CatalogEntry } from "./catalog.js";
import { PolicyService } from "./policy.js";

const tool = (name: string): Tool => ({ name, inputSchema: { type: "object" } });
const entry = (upstreamToolName: string, tier: "read" | "write" | "destructive", upstreamId = "up1"): CatalogEntry => ({
  upstreamId,
  namespace: upstreamId,
  upstreamToolName,
  exposedName: `${upstreamId}_${upstreamToolName}`,
  tier,
  tool: tool(upstreamToolName),
});

function setup() {
  const repo = new Repo(openDatabase(":memory:"));
  const policy = new PolicyService(repo);
  const editorRole = repo.roleByName("editor")!;
  const editor: Principal = {
    kind: "oidc",
    subject: "https://login.example|ab428be9-1111-2222-3333-444455556666",
    label: "alice",
    roleId: editorRole.id,
    roleName: "editor",
    isAdmin: false,
  };
  return { repo, policy, editor };
}

describe("personal narrowing (allowsFor = envelope ∧ prefs)", () => {
  it("defaults to the envelope when no prefs exist", () => {
    const { policy, editor } = setup();
    expect(policy.allowsFor(editor, entry("update_doc", "write"))).toBe(true);
    expect(policy.allowsFor(editor, entry("delete_doc", "destructive"))).toBe(false);
  });

  it("a per-tool deny pref removes an envelope-allowed tool (deny wins)", () => {
    const { repo, policy, editor } = setup();
    const e = entry("update_doc", "write");
    repo.setUserPref(prefsIdentity(editor), "up1", "update_doc", false);
    expect(policy.allows(editor.roleId, e)).toBe(true); // envelope unchanged
    expect(policy.allowsFor(editor, e)).toBe(false); // personal narrowing applied
  });

  it("an upstream-wide deny pref ('' row) removes every tool on that upstream", () => {
    const { repo, policy, editor } = setup();
    repo.setUserPref(prefsIdentity(editor), "up1", "", false);
    expect(policy.allowsFor(editor, entry("get_doc", "read"))).toBe(false);
    expect(policy.allowsFor(editor, entry("update_doc", "write"))).toBe(false);
    expect(policy.allowsFor(editor, entry("other_tool", "read", "up2"))).toBe(true); // other upstreams untouched
  });

  it("prefs can NEVER widen: enabling an envelope-denied tool stays denied", () => {
    const { repo, policy, editor } = setup();
    const destroy = entry("delete_doc", "destructive"); // above editor's tier
    // "enable" is delete-the-deny-row semantics — there is nothing to widen with.
    repo.setUserPref(prefsIdentity(editor), "up1", "delete_doc", true);
    expect(policy.allowsFor(editor, destroy)).toBe(false);
  });

  it("re-enabling clears the personal deny and restores the envelope", () => {
    const { repo, policy, editor } = setup();
    const e = entry("update_doc", "write");
    const who = prefsIdentity(editor);
    repo.setUserPref(who, "up1", "update_doc", false);
    expect(policy.allowsFor(editor, e)).toBe(false);
    repo.setUserPref(who, "up1", "update_doc", true);
    expect(policy.allowsFor(editor, e)).toBe(true);
    expect(repo.listUserPrefs(who)).toHaveLength(0); // enable = row removed, not stored
  });

  it("list filtering and call-time gating agree (same function)", () => {
    const { repo, policy, editor } = setup();
    const entries = [entry("get_doc", "read"), entry("update_doc", "write")];
    repo.setUserPref(prefsIdentity(editor), "up1", "update_doc", false);
    const visible = policy.visibleEntriesFor(editor, entries);
    expect(visible.map((e) => e.upstreamToolName)).toEqual(["get_doc"]);
    for (const e of entries) {
      expect(policy.allowsFor(editor, e)).toBe(visible.includes(e));
    }
  });

  it("prefs are keyed by kind:subject — they survive a role change", () => {
    const { repo, policy, editor } = setup();
    repo.setUserPref(prefsIdentity(editor), "up1", "get_doc", false);
    const viewerRole = repo.roleByName("viewer")!;
    const sameUserNewRole: Principal = { ...editor, roleId: viewerRole.id, roleName: "viewer" };
    expect(policy.allowsFor(sameUserNewRole, entry("get_doc", "read"))).toBe(false);
  });
});

describe("principalSlug", () => {
  it("passes Entra OIDs through recognizably", () => {
    const p: Principal = {
      kind: "oidc",
      subject: "https://login.example|AB428BE9-1111-2222-3333-444455556666",
      label: "x",
      roleId: 1,
      roleName: "viewer",
      isAdmin: false,
    };
    expect(principalSlug(p)).toBe("ab428be9-1111-2222-3333-444455556666");
  });

  it("hashes non-KV-safe subjects deterministically", () => {
    const p: Principal = {
      kind: "oidc",
      subject: "user@example.com",
      label: "x",
      roleId: 1,
      roleName: "viewer",
      isAdmin: false,
    };
    const slug = principalSlug(p);
    expect(slug).toMatch(/^[0-9a-f]{16}$/);
    expect(principalSlug({ ...p, roleId: 99 })).toBe(slug); // role-independent
  });
});
