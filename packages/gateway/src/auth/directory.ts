/**
 * Entra directory search (app-only Microsoft Graph) for the admin UI: look up
 * groups and users by name so group→role mappings don't require pasting
 * object ids blind.
 *
 * Uses the interactive-login app's confidential credentials (client
 * credentials grant) — the NDR deployment granted that app the app-only
 * directory-read roles (User.ReadBasic.All + Group.Read.All, admin-consented,
 * 2026-07-17). No inbound token is ever forwarded (anti-passthrough intact);
 * this is the gateway's own credential talking to Graph.
 *
 * Feature-gated: only available when interactive login is configured AND the
 * issuer is an Entra tenant (login.microsoftonline.com) — for generic OIDC
 * issuers there is no Graph, and createDirectorySearch returns null so the
 * admin API reports `configured: false` and the UI keeps paste-an-id behavior.
 * Tokens/secrets are never logged.
 */

import type { LoginConfig, OidcConfig } from "../config.js";

const GRAPH = "https://graph.microsoft.com/v1.0";

export interface DirectoryResult {
  kind: "user" | "group";
  id: string;
  displayName: string;
  /** email / UPN for users, mail for groups — may be empty. */
  secondary: string;
}

export interface DirectorySearch {
  search(query: string, type: "user" | "group" | "all"): Promise<DirectoryResult[]>;
  /**
   * Resolve object ids → display names (users and groups), for showing
   * friendly labels next to stored GUIDs. Unknown/deleted ids are simply
   * absent from the result; failures resolve to {} so callers degrade to
   * showing the raw id.
   */
  namesByIds(ids: string[]): Promise<Record<string, string>>;
}

/** Extract the tenant id from an Entra v2 issuer URL; null for non-Entra issuers. */
export function tenantFromIssuer(issuer: string): string | null {
  const match = /^https:\/\/login\.microsoftonline\.com\/([^/]+)\/v2\.0\/?$/.exec(issuer.trim());
  return match ? match[1]! : null;
}

/** Sanitize a term for a Graph $search phrase (quotes/backslashes would break it). */
const sanitize = (term: string): string => term.replace(/["\\]/g, "").trim();

export function createDirectorySearch(
  oidc: OidcConfig,
  login: LoginConfig,
  /** Injectable for tests. */
  fetchImpl: typeof fetch = fetch
): DirectorySearch | null {
  const tenant = tenantFromIssuer(oidc.issuer);
  if (!tenant) return null;

  let tokenCache: { token: string; expiresAt: number } | null = null;

  const getAppToken = async (): Promise<string> => {
    if (tokenCache && Date.now() < tokenCache.expiresAt) return tokenCache.token;
    const response = await fetchImpl(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: login.clientId,
          client_secret: login.clientSecret,
          scope: "https://graph.microsoft.com/.default",
          grant_type: "client_credentials",
        }),
      }
    );
    if (!response.ok) {
      // Never echo the response body — it may reflect request details.
      console.error(`[directory] Graph token request failed: ${response.status}`);
      throw new Error("graph token request failed");
    }
    const json = (await response.json()) as { access_token?: string; expires_in?: number };
    if (!json.access_token) throw new Error("graph token response had no access_token");
    tokenCache = {
      token: json.access_token,
      expiresAt: Date.now() + ((json.expires_in ?? 3600) * 1000 - 60_000),
    };
    return json.access_token;
  };

  const graphSearch = async (path: string): Promise<Record<string, unknown>[]> => {
    const token = await getAppToken();
    const response = await fetchImpl(`${GRAPH}${path}`, {
      headers: {
        authorization: `Bearer ${token}`,
        // $search on directory objects requires advanced query capabilities.
        ConsistencyLevel: "eventual",
      },
    });
    if (!response.ok) {
      console.error(`[directory] Graph search failed: ${response.status} ${path.split("?")[0]}`);
      throw new Error(`graph search failed: ${response.status}`);
    }
    const json = (await response.json()) as { value?: Record<string, unknown>[] };
    return json.value ?? [];
  };

  // id → display name, cached (renames surface within the TTL).
  const nameCache = new Map<string, { name: string; expiresAt: number }>();
  const NAME_TTL_MS = 60 * 60 * 1000;

  return {
    async namesByIds(ids) {
      const out: Record<string, string> = {};
      const now = Date.now();
      const missing: string[] = [];
      for (const id of new Set(ids)) {
        const cached = nameCache.get(id);
        if (cached && now < cached.expiresAt) out[id] = cached.name;
        else missing.push(id);
      }
      if (missing.length === 0) return out;
      try {
        const token = await getAppToken();
        const response = await fetchImpl(`${GRAPH}/directoryObjects/getByIds`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ ids: missing, types: ["group", "user"] }),
        });
        if (!response.ok) throw new Error(`getByIds failed: ${response.status}`);
        const json = (await response.json()) as { value?: Array<{ id?: string; displayName?: string }> };
        for (const obj of json.value ?? []) {
          if (!obj.id || typeof obj.displayName !== "string") continue;
          out[obj.id] = obj.displayName;
          nameCache.set(obj.id, { name: obj.displayName, expiresAt: now + NAME_TTL_MS });
        }
      } catch (err) {
        // Labels are cosmetic — never fail the caller over them.
        console.error(`[directory] name lookup failed: ${err instanceof Error ? err.message : String(err)}`);
      }
      return out;
    },

    async search(query, type) {
      const term = sanitize(query);
      if (term.length < 2) return [];
      const enc = encodeURIComponent;
      const top = 8;

      const [users, groups] = await Promise.all([
        type === "user" || type === "all"
          ? graphSearch(
              `/users?$search=${enc(`"displayName:${term}" OR "mail:${term}" OR "userPrincipalName:${term}"`)}` +
                `&$select=id,displayName,mail,userPrincipalName&$top=${top}`
            )
          : Promise.resolve([]),
        type === "group" || type === "all"
          ? graphSearch(
              `/groups?$search=${enc(`"displayName:${term}" OR "mail:${term}"`)}` +
                `&$select=id,displayName,mail&$top=${top}`
            )
          : Promise.resolve([]),
      ]);

      return [
        ...groups.map((g) => ({
          kind: "group" as const,
          id: String(g.id),
          displayName: String(g.displayName ?? g.id),
          secondary: String(g.mail ?? ""),
        })),
        ...users.map((u) => ({
          kind: "user" as const,
          id: String(u.id),
          displayName: String(u.displayName ?? u.userPrincipalName ?? u.id),
          secondary: String(u.mail ?? u.userPrincipalName ?? ""),
        })),
      ];
    },
  };
}
