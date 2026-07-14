/**
 * Policy engine: which tools a role can see and call.
 *
 * Two-layer enforcement (mcp-itglue's model, generalized): tools/list
 * filtering is UX, the call-time check is the security boundary — both go
 * through the same PolicyService so they can never disagree.
 *
 * Effective visibility of a tool for a role:
 *   toolEnabled ∧ (override(allow) ∨ (tier ≤ maxTier ∧ ¬override(deny)))
 * where tier = admin tierOverride ?? annotation-derived tier, and
 * maxTier = per-upstream grant ?? the role's default.
 */

import type { CatalogEntry, Tier } from "./catalog.js";
import type { Repo, RoleRow } from "../db/repo.js";
import type { Principal } from "../auth/principal.js";
import { prefsIdentity } from "../auth/principal.js";

export type { Tier };
export type MaxTier = Tier | "none";

const TIER_RANK: Record<MaxTier, number> = { none: 0, read: 1, write: 2, destructive: 3 };

export const isMaxTier = (value: unknown): value is MaxTier =>
  value === "none" || value === "read" || value === "write" || value === "destructive";

export function tierAllowed(maxTier: MaxTier, tier: Tier): boolean {
  return TIER_RANK[maxTier] >= TIER_RANK[tier];
}

/** Pure decision function — heavily unit-tested. */
export function toolAllowed(input: {
  toolEnabled: boolean;
  effectiveTier: Tier;
  maxTier: MaxTier;
  override: "allow" | "deny" | null;
}): boolean {
  if (!input.toolEnabled) return false;
  if (input.override === "deny") return false;
  if (input.override === "allow") return true;
  return tierAllowed(input.maxTier, input.effectiveTier);
}

export class PolicyService {
  constructor(private readonly repo: Repo) {}

  roleFor(roleId: number): RoleRow | null {
    return this.repo.roleById(roleId);
  }

  /** The single authorization decision, used by list filtering AND call-time checks. */
  allows(roleId: number, entry: CatalogEntry): boolean {
    const role = this.repo.roleById(roleId);
    if (!role) return false;
    const setting = this.repo.toolSetting(entry.upstreamId, entry.upstreamToolName);
    return toolAllowed({
      toolEnabled: setting?.enabled ?? true,
      effectiveTier: setting?.tierOverride ?? entry.tier,
      maxTier: this.repo.grantFor(roleId, entry.upstreamId) ?? role.defaultMaxTier,
      override: this.repo.overrideFor(roleId, entry.upstreamId, entry.upstreamToolName),
    });
  }

  visibleEntries(roleId: number, entries: Iterable<CatalogEntry>): CatalogEntry[] {
    return [...entries].filter((entry) => this.allows(roleId, entry));
  }

  /**
   * Personal narrowing (slice 3): effective = admin envelope ∧ user prefs.
   * Prefs are deny-only rows (an upstream-wide '' row or a per-tool row), so
   * this can only ever REMOVE access relative to allows() — never widen it.
   * Same function gates tools/list and tools/call, like the envelope itself.
   */
  allowsFor(principal: Principal, entry: CatalogEntry): boolean {
    if (!this.allows(principal.roleId, entry)) return false;
    const who = prefsIdentity(principal);
    if (this.repo.userPrefFor(who, entry.upstreamId, "") === false) return false;
    if (this.repo.userPrefFor(who, entry.upstreamId, entry.upstreamToolName) === false) return false;
    return true;
  }

  visibleEntriesFor(principal: Principal, entries: Iterable<CatalogEntry>): CatalogEntry[] {
    return [...entries].filter((entry) => this.allowsFor(principal, entry));
  }
}
