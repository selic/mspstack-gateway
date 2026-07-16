/**
 * Typed data access over node:sqlite. All methods are synchronous
 * (DatabaseSync); callers treat this as the single source of truth for
 * upstream definitions, roles, grants, tool settings, users, and mappings.
 */

import type { DatabaseSync } from "node:sqlite";
import { parseUpstreamSpec, type UpstreamSpec } from "../config.js";
import type { MaxTier, Tier } from "../domain/policy.js";

export interface RoleRow {
  id: number;
  name: string;
  defaultMaxTier: MaxTier;
  isAdmin: boolean;
  protected: boolean;
}

export interface UpstreamRow {
  spec: UpstreamSpec;
  source: "file" | "api";
}

export interface ToolSettingRow {
  upstreamId: string;
  toolName: string;
  enabled: boolean;
  tierOverride: Tier | null;
  groupLabel: string | null;
}

export interface UserRow {
  id: number;
  iss: string;
  sub: string;
  email: string | null;
  displayName: string | null;
  roleId: number | null;
  lastLoginAt: string | null;
}

export interface GroupMappingRow {
  id: number;
  iss: string;
  claimValue: string;
  roleId: number;
}

export interface UserPrefRow {
  principal: string;
  upstreamId: string;
  /** '' = the whole upstream. */
  toolName: string;
  enabled: boolean;
}

export interface OauthClientRow {
  clientId: string;
  clientName: string | null;
  redirectUris: string[];
  createdAt: string;
}

export interface OauthCodeRow {
  codeHash: string;
  clientId: string;
  principalIss: string;
  principalSub: string;
  codeChallenge: string;
  resource: string | null;
  /** unix epoch millis */
  expiresAt: number;
  usedAt: string | null;
}

export interface OauthRefreshTokenRow {
  tokenHash: string;
  clientId: string;
  principalIss: string;
  principalSub: string;
  /** Rotation-chain id (the root token's hash) — one revocation hits the chain. */
  familyId: string;
  rotatedFrom: string | null;
  /** unix epoch millis */
  expiresAt: number;
  createdAt: string;
  rotatedAt: string | null;
  revokedAt: string | null;
}

export type RefreshConsumeResult =
  | { status: "ok"; row: OauthRefreshTokenRow }
  /** The token existed but was already rotated/revoked — replay; revoke the family. */
  | { status: "reuse"; familyId: string }
  | { status: "invalid" };

export interface UserCredentialRow {
  principal: string;
  upstreamId: string;
  field: string;
  secretRef: string;
  updatedAt: string;
}

export class Repo {
  constructor(private readonly db: DatabaseSync) {}

  // ── roles ──

  listRoles(): RoleRow[] {
    return (
      this.db
        .prepare("SELECT id, name, default_max_tier, is_admin, protected FROM roles ORDER BY id")
        .all() as Array<Record<string, unknown>>
    ).map(mapRole);
  }

  roleById(id: number): RoleRow | null {
    const row = this.db
      .prepare("SELECT id, name, default_max_tier, is_admin, protected FROM roles WHERE id = ?")
      .get(id) as Record<string, unknown> | undefined;
    return row ? mapRole(row) : null;
  }

  roleByName(name: string): RoleRow | null {
    const row = this.db
      .prepare("SELECT id, name, default_max_tier, is_admin, protected FROM roles WHERE name = ?")
      .get(name) as Record<string, unknown> | undefined;
    return row ? mapRole(row) : null;
  }

  createRole(name: string, defaultMaxTier: MaxTier, isAdmin = false): RoleRow {
    this.db
      .prepare("INSERT INTO roles (name, default_max_tier, is_admin) VALUES (?, ?, ?)")
      .run(name, defaultMaxTier, isAdmin ? 1 : 0);
    return this.roleByName(name)!;
  }

  deleteRole(id: number): boolean {
    const result = this.db.prepare("DELETE FROM roles WHERE id = ? AND protected = 0").run(id);
    return result.changes > 0;
  }

  // ── upstreams ──

  listUpstreams(): UpstreamRow[] {
    return (
      this.db.prepare("SELECT spec_json, enabled, source FROM upstreams ORDER BY id").all() as Array<{
        spec_json: string;
        enabled: number;
        source: "file" | "api";
      }>
    ).map((row) => ({
      spec: { ...(JSON.parse(row.spec_json) as UpstreamSpec), enabled: row.enabled === 1 },
      source: row.source,
    }));
  }

  getUpstream(id: string): UpstreamRow | null {
    const row = this.db
      .prepare("SELECT spec_json, enabled, source FROM upstreams WHERE id = ?")
      .get(id) as { spec_json: string; enabled: number; source: "file" | "api" } | undefined;
    if (!row) return null;
    return {
      spec: { ...(JSON.parse(row.spec_json) as UpstreamSpec), enabled: row.enabled === 1 },
      source: row.source,
    };
  }

  upsertUpstream(spec: UpstreamSpec, source: "file" | "api"): void {
    parseUpstreamSpec(spec); // defense in depth — never persist an invalid spec
    const existingNamespace = this.db
      .prepare("SELECT id FROM upstreams WHERE namespace = ? AND id != ?")
      .get(spec.namespace, spec.id) as { id: string } | undefined;
    if (existingNamespace) {
      throw new Error(
        `namespace "${spec.namespace}" is already used by upstream "${existingNamespace.id}"`
      );
    }
    this.db
      .prepare(
        `INSERT INTO upstreams (id, namespace, transport, spec_json, enabled, source)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           namespace = excluded.namespace,
           transport = excluded.transport,
           spec_json = excluded.spec_json,
           enabled = excluded.enabled,
           source = excluded.source`
      )
      .run(spec.id, spec.namespace, spec.transport, JSON.stringify(spec), spec.enabled ? 1 : 0, source);
  }

  setUpstreamEnabled(id: string, enabled: boolean): boolean {
    const result = this.db
      .prepare("UPDATE upstreams SET enabled = ? WHERE id = ?")
      .run(enabled ? 1 : 0, id);
    return result.changes > 0;
  }

  deleteUpstream(id: string): boolean {
    const result = this.db.prepare("DELETE FROM upstreams WHERE id = ?").run(id);
    this.db.prepare("DELETE FROM tool_settings WHERE upstream_id = ?").run(id);
    this.db.prepare("DELETE FROM tool_overrides WHERE upstream_id = ?").run(id);
    this.db.prepare("DELETE FROM grants WHERE upstream_id = ?").run(id);
    return result.changes > 0;
  }

  // ── grants ──

  grantFor(roleId: number, upstreamId: string): MaxTier | null {
    const row = this.db
      .prepare("SELECT max_tier FROM grants WHERE role_id = ? AND upstream_id = ?")
      .get(roleId, upstreamId) as { max_tier: MaxTier } | undefined;
    return row?.max_tier ?? null;
  }

  listGrants(): Array<{ roleId: number; upstreamId: string; maxTier: MaxTier }> {
    return (
      this.db.prepare("SELECT role_id, upstream_id, max_tier FROM grants").all() as Array<{
        role_id: number;
        upstream_id: string;
        max_tier: MaxTier;
      }>
    ).map((row) => ({ roleId: row.role_id, upstreamId: row.upstream_id, maxTier: row.max_tier }));
  }

  setGrant(roleId: number, upstreamId: string, maxTier: MaxTier): void {
    this.db
      .prepare(
        `INSERT INTO grants (role_id, upstream_id, max_tier) VALUES (?, ?, ?)
         ON CONFLICT(role_id, upstream_id) DO UPDATE SET max_tier = excluded.max_tier`
      )
      .run(roleId, upstreamId, maxTier);
  }

  clearGrant(roleId: number, upstreamId: string): void {
    this.db.prepare("DELETE FROM grants WHERE role_id = ? AND upstream_id = ?").run(roleId, upstreamId);
  }

  // ── tool overrides ──

  overrideFor(roleId: number, upstreamId: string, toolName: string): "allow" | "deny" | null {
    const row = this.db
      .prepare(
        "SELECT effect FROM tool_overrides WHERE role_id = ? AND upstream_id = ? AND tool_name = ?"
      )
      .get(roleId, upstreamId, toolName) as { effect: "allow" | "deny" } | undefined;
    return row?.effect ?? null;
  }

  listOverrides(): Array<{ roleId: number; upstreamId: string; toolName: string; effect: "allow" | "deny" }> {
    return (
      this.db
        .prepare("SELECT role_id, upstream_id, tool_name, effect FROM tool_overrides")
        .all() as Array<{ role_id: number; upstream_id: string; tool_name: string; effect: "allow" | "deny" }>
    ).map((row) => ({
      roleId: row.role_id,
      upstreamId: row.upstream_id,
      toolName: row.tool_name,
      effect: row.effect,
    }));
  }

  setOverride(roleId: number, upstreamId: string, toolName: string, effect: "allow" | "deny"): void {
    this.db
      .prepare(
        `INSERT INTO tool_overrides (role_id, upstream_id, tool_name, effect) VALUES (?, ?, ?, ?)
         ON CONFLICT(role_id, upstream_id, tool_name) DO UPDATE SET effect = excluded.effect`
      )
      .run(roleId, upstreamId, toolName, effect);
  }

  clearOverride(roleId: number, upstreamId: string, toolName: string): void {
    this.db
      .prepare("DELETE FROM tool_overrides WHERE role_id = ? AND upstream_id = ? AND tool_name = ?")
      .run(roleId, upstreamId, toolName);
  }

  // ── tool settings ──

  toolSetting(upstreamId: string, toolName: string): ToolSettingRow | null {
    const row = this.db
      .prepare(
        "SELECT upstream_id, tool_name, enabled, tier_override, group_label FROM tool_settings WHERE upstream_id = ? AND tool_name = ?"
      )
      .get(upstreamId, toolName) as Record<string, unknown> | undefined;
    return row ? mapToolSetting(row) : null;
  }

  listToolSettings(): ToolSettingRow[] {
    return (
      this.db
        .prepare("SELECT upstream_id, tool_name, enabled, tier_override, group_label FROM tool_settings")
        .all() as Array<Record<string, unknown>>
    ).map(mapToolSetting);
  }

  upsertToolSetting(setting: {
    upstreamId: string;
    toolName: string;
    enabled?: boolean;
    tierOverride?: Tier | null;
    groupLabel?: string | null;
  }): void {
    const current = this.toolSetting(setting.upstreamId, setting.toolName);
    const enabled = setting.enabled ?? current?.enabled ?? true;
    const tierOverride =
      setting.tierOverride !== undefined ? setting.tierOverride : (current?.tierOverride ?? null);
    const groupLabel =
      setting.groupLabel !== undefined ? setting.groupLabel : (current?.groupLabel ?? null);
    this.db
      .prepare(
        `INSERT INTO tool_settings (upstream_id, tool_name, enabled, tier_override, group_label)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(upstream_id, tool_name) DO UPDATE SET
           enabled = excluded.enabled,
           tier_override = excluded.tier_override,
           group_label = excluded.group_label`
      )
      .run(setting.upstreamId, setting.toolName, enabled ? 1 : 0, tierOverride, groupLabel);
  }

  // ── users ──

  upsertUserOnLogin(user: {
    iss: string;
    sub: string;
    email?: string;
    displayName?: string;
  }): UserRow {
    this.db
      .prepare(
        `INSERT INTO users (iss, sub, email, display_name, last_login_at)
         VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT(iss, sub) DO UPDATE SET
           email = COALESCE(excluded.email, users.email),
           display_name = COALESCE(excluded.display_name, users.display_name),
           last_login_at = excluded.last_login_at`
      )
      .run(user.iss, user.sub, user.email ?? null, user.displayName ?? null);
    return this.userBySubject(user.iss, user.sub)!;
  }

  userBySubject(iss: string, sub: string): UserRow | null {
    const row = this.db
      .prepare(
        "SELECT id, iss, sub, email, display_name, role_id, last_login_at FROM users WHERE iss = ? AND sub = ?"
      )
      .get(iss, sub) as Record<string, unknown> | undefined;
    return row ? mapUser(row) : null;
  }

  listUsers(): UserRow[] {
    return (
      this.db
        .prepare("SELECT id, iss, sub, email, display_name, role_id, last_login_at FROM users ORDER BY id")
        .all() as Array<Record<string, unknown>>
    ).map(mapUser);
  }

  setUserRole(userId: number, roleId: number | null): boolean {
    const result = this.db.prepare("UPDATE users SET role_id = ? WHERE id = ?").run(roleId, userId);
    return result.changes > 0;
  }

  // ── group mappings ──

  listGroupMappings(): GroupMappingRow[] {
    return (
      this.db.prepare("SELECT id, iss, claim_value, role_id FROM group_mappings ORDER BY id").all() as Array<{
        id: number;
        iss: string;
        claim_value: string;
        role_id: number;
      }>
    ).map((row) => ({ id: row.id, iss: row.iss, claimValue: row.claim_value, roleId: row.role_id }));
  }

  setGroupMapping(iss: string, claimValue: string, roleId: number): void {
    this.db
      .prepare(
        `INSERT INTO group_mappings (iss, claim_value, role_id) VALUES (?, ?, ?)
         ON CONFLICT(iss, claim_value) DO UPDATE SET role_id = excluded.role_id`
      )
      .run(iss, claimValue, roleId);
  }

  deleteGroupMapping(id: number): boolean {
    return this.db.prepare("DELETE FROM group_mappings WHERE id = ?").run(id).changes > 0;
  }

  /** Resolve the role for an OIDC login: user override > group mapping (highest tier wins). */
  resolveOidcRole(iss: string, sub: string, groups: string[]): RoleRow | null {
    const user = this.userBySubject(iss, sub);
    if (user?.roleId != null) return this.roleById(user.roleId);
    if (groups.length === 0) return null;
    const placeholders = groups.map(() => "?").join(",");
    const row = this.db
      .prepare(
        `SELECT r.id, r.name, r.default_max_tier, r.is_admin, r.protected
         FROM group_mappings gm JOIN roles r ON r.id = gm.role_id
         WHERE gm.iss = ? AND gm.claim_value IN (${placeholders})
         ORDER BY r.is_admin DESC,
           CASE r.default_max_tier
             WHEN 'destructive' THEN 3 WHEN 'write' THEN 2 WHEN 'read' THEN 1 ELSE 0
           END DESC
         LIMIT 1`
      )
      .get(iss, ...groups) as Record<string, unknown> | undefined;
    return row ? mapRole(row) : null;
  }

  // ── user prefs (personal narrowing — slice 3) ──

  /** All narrowing rows for a principal. tool_name '' = the whole upstream. */
  listUserPrefs(principal: string): UserPrefRow[] {
    return (
      this.db
        .prepare("SELECT * FROM user_prefs WHERE principal = ? ORDER BY upstream_id, tool_name")
        .all(principal) as Record<string, unknown>[]
    ).map(mapUserPref);
  }

  userPrefFor(principal: string, upstreamId: string, toolName: string): boolean | null {
    const row = this.db
      .prepare(
        "SELECT enabled FROM user_prefs WHERE principal = ? AND upstream_id = ? AND tool_name = ?"
      )
      .get(principal, upstreamId, toolName) as { enabled: number } | undefined;
    return row === undefined ? null : row.enabled === 1;
  }

  /**
   * enabled=false stores a personal deny; enabled=true DELETES the row —
   * "enable" only ever removes personal narrowing, it can never widen the
   * admin envelope (the policy AND takes care of the rest).
   */
  setUserPref(principal: string, upstreamId: string, toolName: string, enabled: boolean): void {
    if (enabled) {
      this.db
        .prepare(
          "DELETE FROM user_prefs WHERE principal = ? AND upstream_id = ? AND tool_name = ?"
        )
        .run(principal, upstreamId, toolName);
      return;
    }
    this.db
      .prepare(
        `INSERT INTO user_prefs (principal, upstream_id, tool_name, enabled) VALUES (?, ?, ?, 0)
         ON CONFLICT (principal, upstream_id, tool_name) DO UPDATE SET enabled = 0`
      )
      .run(principal, upstreamId, toolName);
  }

  // ── user credentials (registered refs only — never values) ──

  listUserCredentials(principal: string): UserCredentialRow[] {
    return (
      this.db
        .prepare(
          "SELECT * FROM user_credentials WHERE principal = ? ORDER BY upstream_id, field"
        )
        .all(principal) as Record<string, unknown>[]
    ).map(mapUserCredential);
  }

  upsertUserCredential(principal: string, upstreamId: string, field: string, secretRef: string): void {
    this.db
      .prepare(
        `INSERT INTO user_credentials (principal, upstream_id, field, secret_ref, updated_at)
         VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT (principal, upstream_id, field)
         DO UPDATE SET secret_ref = excluded.secret_ref, updated_at = datetime('now')`
      )
      .run(principal, upstreamId, field, secretRef);
  }

  // ── OAuth AS facade (DCR clients + single-use authorization codes) ──

  createOauthClient(client: { clientId: string; clientName: string | null; redirectUris: string[] }): void {
    this.db
      .prepare("INSERT INTO oauth_clients (client_id, client_name, redirect_uris_json) VALUES (?, ?, ?)")
      .run(client.clientId, client.clientName, JSON.stringify(client.redirectUris));
  }

  oauthClient(clientId: string): OauthClientRow | null {
    const row = this.db
      .prepare("SELECT client_id, client_name, redirect_uris_json, created_at FROM oauth_clients WHERE client_id = ?")
      .get(clientId) as Record<string, unknown> | undefined;
    return row ? mapOauthClient(row) : null;
  }

  /**
   * Persist a new authorization code by its HASH (plaintext codes never touch
   * the DB) and opportunistically sweep codes past their TTL.
   */
  insertOauthCode(code: {
    codeHash: string;
    clientId: string;
    principalIss: string;
    principalSub: string;
    codeChallenge: string;
    resource: string | null;
    expiresAt: number;
  }): void {
    this.db.prepare("DELETE FROM oauth_codes WHERE expires_at < ?").run(Date.now());
    this.db
      .prepare(
        `INSERT INTO oauth_codes
           (code_hash, client_id, principal_iss, principal_sub, code_challenge, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        code.codeHash,
        code.clientId,
        code.principalIss,
        code.principalSub,
        code.codeChallenge,
        code.resource,
        code.expiresAt
      );
  }

  /**
   * Single-use redemption: atomically marks the code used and returns it only
   * if it existed, was unused, and is unexpired. A replay (or an expired /
   * unknown code) returns null.
   */
  consumeOauthCode(codeHash: string): OauthCodeRow | null {
    const row = this.db
      .prepare(
        `UPDATE oauth_codes SET used_at = datetime('now')
         WHERE code_hash = ? AND used_at IS NULL AND expires_at >= ?
         RETURNING code_hash, client_id, principal_iss, principal_sub, code_challenge, resource, expires_at, used_at`
      )
      .get(codeHash, Date.now()) as Record<string, unknown> | undefined;
    return row ? mapOauthCode(row) : null;
  }

  listOauthClients(): OauthClientRow[] {
    return (
      this.db
        .prepare("SELECT client_id, client_name, redirect_uris_json, created_at FROM oauth_clients ORDER BY created_at DESC, client_id")
        .all() as Array<Record<string, unknown>>
    ).map(mapOauthClient);
  }

  /** Remove a registered client and everything minted for it (codes + refresh tokens). */
  deleteOauthClient(clientId: string): boolean {
    this.db.prepare("DELETE FROM oauth_codes WHERE client_id = ?").run(clientId);
    this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE client_id = ?").run(clientId);
    return this.db.prepare("DELETE FROM oauth_clients WHERE client_id = ?").run(clientId).changes > 0;
  }

  // ── OAuth refresh tokens (rotating; phase 2) ──

  insertOauthRefreshToken(token: {
    tokenHash: string;
    clientId: string;
    principalIss: string;
    principalSub: string;
    familyId: string;
    rotatedFrom: string | null;
    expiresAt: number;
  }): void {
    this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE expires_at < ?").run(Date.now());
    this.db
      .prepare(
        `INSERT INTO oauth_refresh_tokens
           (token_hash, client_id, principal_iss, principal_sub, family_id, rotated_from, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        token.tokenHash,
        token.clientId,
        token.principalIss,
        token.principalSub,
        token.familyId,
        token.rotatedFrom,
        token.expiresAt
      );
  }

  /**
   * Rotation step: atomically mark the token rotated and return it, but only
   * if it is live (unrotated, unrevoked, unexpired) AND belongs to clientId —
   * the client check happens BEFORE consumption so a wrong-client request
   * cannot burn a legitimate token. A live-miss is then classified: an
   * existing rotated/revoked row for the same client is a REPLAY (the caller
   * must revoke the family); anything else is plain invalid.
   */
  consumeOauthRefreshToken(tokenHash: string, clientId: string): RefreshConsumeResult {
    const row = this.db
      .prepare(
        `UPDATE oauth_refresh_tokens SET rotated_at = datetime('now')
         WHERE token_hash = ? AND client_id = ? AND rotated_at IS NULL AND revoked_at IS NULL AND expires_at >= ?
         RETURNING token_hash, client_id, principal_iss, principal_sub, family_id, rotated_from,
                   expires_at, created_at, rotated_at, revoked_at`
      )
      .get(tokenHash, clientId, Date.now()) as Record<string, unknown> | undefined;
    if (row) return { status: "ok", row: mapOauthRefreshToken(row) };

    const stale = this.db
      .prepare(
        `SELECT family_id FROM oauth_refresh_tokens
         WHERE token_hash = ? AND client_id = ? AND (rotated_at IS NOT NULL OR revoked_at IS NOT NULL)`
      )
      .get(tokenHash, clientId) as { family_id: string } | undefined;
    if (stale) return { status: "reuse", familyId: stale.family_id };
    return { status: "invalid" };
  }

  /** Reuse detected (or admin action): kill every live token in the chain. */
  revokeOauthRefreshFamily(familyId: string): number {
    return this.db
      .prepare("UPDATE oauth_refresh_tokens SET revoked_at = datetime('now') WHERE family_id = ? AND revoked_at IS NULL")
      .run(familyId).changes;
  }

  deleteUserCredential(principal: string, upstreamId: string, field: string): boolean {
    const result = this.db
      .prepare(
        "DELETE FROM user_credentials WHERE principal = ? AND upstream_id = ? AND field = ?"
      )
      .run(principal, upstreamId, field);
    return result.changes > 0;
  }
}

const mapRole = (row: Record<string, unknown>): RoleRow => ({
  id: row.id as number,
  name: row.name as string,
  defaultMaxTier: row.default_max_tier as MaxTier,
  isAdmin: row.is_admin === 1,
  protected: row.protected === 1,
});

const mapToolSetting = (row: Record<string, unknown>): ToolSettingRow => ({
  upstreamId: row.upstream_id as string,
  toolName: row.tool_name as string,
  enabled: row.enabled === 1,
  tierOverride: (row.tier_override as Tier | null) ?? null,
  groupLabel: (row.group_label as string | null) ?? null,
});

const mapUser = (row: Record<string, unknown>): UserRow => ({
  id: row.id as number,
  iss: row.iss as string,
  sub: row.sub as string,
  email: (row.email as string | null) ?? null,
  displayName: (row.display_name as string | null) ?? null,
  roleId: (row.role_id as number | null) ?? null,
  lastLoginAt: (row.last_login_at as string | null) ?? null,
});

const mapUserPref = (row: Record<string, unknown>): UserPrefRow => ({
  principal: row.principal as string,
  upstreamId: row.upstream_id as string,
  toolName: row.tool_name as string,
  enabled: row.enabled === 1,
});

const mapOauthClient = (row: Record<string, unknown>): OauthClientRow => ({
  clientId: row.client_id as string,
  clientName: (row.client_name as string | null) ?? null,
  redirectUris: JSON.parse(row.redirect_uris_json as string) as string[],
  createdAt: row.created_at as string,
});

const mapOauthCode = (row: Record<string, unknown>): OauthCodeRow => ({
  codeHash: row.code_hash as string,
  clientId: row.client_id as string,
  principalIss: row.principal_iss as string,
  principalSub: row.principal_sub as string,
  codeChallenge: row.code_challenge as string,
  resource: (row.resource as string | null) ?? null,
  expiresAt: row.expires_at as number,
  usedAt: (row.used_at as string | null) ?? null,
});

const mapOauthRefreshToken = (row: Record<string, unknown>): OauthRefreshTokenRow => ({
  tokenHash: row.token_hash as string,
  clientId: row.client_id as string,
  principalIss: row.principal_iss as string,
  principalSub: row.principal_sub as string,
  familyId: row.family_id as string,
  rotatedFrom: (row.rotated_from as string | null) ?? null,
  expiresAt: row.expires_at as number,
  createdAt: row.created_at as string,
  rotatedAt: (row.rotated_at as string | null) ?? null,
  revokedAt: (row.revoked_at as string | null) ?? null,
});

const mapUserCredential = (row: Record<string, unknown>): UserCredentialRow => ({
  principal: row.principal as string,
  upstreamId: row.upstream_id as string,
  field: row.field as string,
  secretRef: row.secret_ref as string,
  updatedAt: row.updated_at as string,
});
