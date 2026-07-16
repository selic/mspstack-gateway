# mcp-gateway

Self-hosted MCP manager/gateway: one streamable-HTTP `/mcp` endpoint federating many upstream MCP servers, with OAuth/token auth, DB-backed roles, per-tool toggles, OpenBao secret injection, and an admin UI. TypeScript, ESM, **Node ≥24** (uses built-in `node:sqlite`), npm workspaces. Founding piece of the MSPStack umbrella; siblings: mcp-itglue, mcp-connectwise-psa, mcp-planner (same author, same conventions).

## Commands

- `npm run build` — tsc across workspaces (tests excluded from builds)
- `npm test` — vitest, test files live beside sources (`src/**/*.test.ts`)
- `npm run dev` — run from source via tsx (needs auth env vars or `DEV_ALLOW_UNAUTHENTICATED=true`)

## Architecture (packages/gateway/src)

- `index.ts` — CLI entry: refuses to start with no auth configured; boots DB → secrets → OIDC → upstreams → HTTP
- `config.ts` — flags/env + `mspstack.config.json` (`ConfigError`); parses `MCP_TOKENS_<ROLE>` lists, OIDC (`OIDC_ISSUER`/`ENTRA_TENANT_ID` + required `OIDC_AUDIENCE`), `BAO_*`
- `db/` — `node:sqlite` schema (roles/upstreams/grants/tool_overrides/tool_settings/users/group_mappings, seeded viewer/editor/admin) + typed `Repo`
- `domain/catalog.ts` — namespacing (`${namespace}_${tool}`, no double-prefix), routing map (no string-splitting), annotation-derived tiers (port of mcp-itglue `tierOf`)
- `domain/policy.ts` — `PolicyService`: toolEnabled ∧ (override(allow) ∨ (tier ≤ maxTier ∧ ¬deny)); maxTier = per-upstream grant ?? role default. Same function gates tools/list AND tools/call. `allowsFor(principal, entry)` = envelope ∧ personal prefs (deny-only rows in `user_prefs`; "enable" deletes the row — narrowing can never widen)
- `auth/` — `static-tokens.ts` (timing-safe bearer match), `oidc.ts` (jose JWKS resource-server verifier for inbound *access* tokens), `login.ts` (interactive login: openid-client cookie+PKCE confidential-client flow consuming an *id-token*; signed identity-only session cookie, HMAC + freshness; `safeReturnTo`), `authz-server.ts` (OAuth AS facade: RFC 8414 metadata, RFC 7591 DCR for public clients, single-use hashed 60s codes + PKCE S256, HS256 gateway JWTs keyed by `GATEWAY_JWT_SECRET` (default derived from `SESSION_SECRET`), register rate limit), `prm.ts` (RFC 9728 doc + WWW-Authenticate; lists the gateway itself as AS when login is configured, else the raw IdP), `principal.ts` (session binding key). Four inbound auth paths in `createAuthResolver`: static token, gateway-issued JWT (routed by unverified `iss == PUBLIC_URL`, then fully verified), OIDC bearer, and the cookie session — the cookie/JWT carry only identity and the role is re-resolved every request (persisted at callback via `setUserRole`), so a session id never carries privilege. `loginUpsert()` is shared by the bearer + callback paths so they can't drift. `/oauth/authorize` brokers user auth to Entra by piggybacking the interactive login: the pending request rides in the signed transient cookie and `/auth/callback` mints the code.
- `secrets/` — `SecretStore` interface (scheme-tagged: `bao` | `kv`), `openbao.ts` (KV v2, AppRole or token, 5-min cache), `keyvault.ts` (Azure Key Vault, `DefaultAzureCredential`, lazy SDK import, same 5-min cache; `put(path, field)` writes `path-field`), `memory.ts` (tests). Refs: `bao:path#field` / `kv:secret-name`; env refs: `${VAR}` — all resolved only at upstream connect time. One store at a time (`BAO_ADDR` xor `KEY_VAULT_URI`)
- `upstream/connection.ts` — one pooled SDK `Client` per upstream; header/env injection; backoff reconnect (1s→60s) + `onRecovered`; retry-once on dropped transport
- `upstream/manager.ts` also pools **per-principal links** for `sessionMode:"per-user"` upstreams: spec clone with the caller's credential REFS layered over headers/env (still resolved via the secret store at connect — anti-passthrough intact); catalog discovery stays on the shared link; personal pool flushed on upstream upsert/remove. `requirePersonalCredentials` refuses the shared fallback
- `upstream/manager.ts` — policy-free catalog owner; hot `upsertUpstream`/`removeUpstream`; `summaries()` for the UI
- `mcp/gateway-server.ts` — low-level SDK `Server` per session, closes over the Principal; unknown and forbidden tools get the same error (no existence oracle)
- `http/app.ts` — `/mcp` (origin check → resolveAuth → principal-bound sessions), PRM endpoints, per-session fingerprint-diffed `list_changed`, mounts `/api` + `/admin`
- `http/admin-api.ts` — admin-only JSON API (upstream CRUD, preflight, registry search, catalog toggles, roles/grants/overrides, users, mappings, secret writes)
- `http/me-api.ts` — `/api/me/*` for ANY principal (mounted before `/api`): effective access (envelope ∧ prefs), narrow-only prefs (404 outside the envelope), personal credential registration → secret store under `gw-user-<principalSlug>-<upstreamId>-<field>`, SQLite keeps only refs. Consumed by per-principal sessions later (`sessionMode`)
- `public/admin.html` — dependency-free single-file admin UI ("Sign in with Microsoft" cookie flow + token paste as break-glass), served at `/admin`
- `public/me.html` — dependency-free user page ("My MCP Access") served at `/me`: my servers/tools (narrow-only), my personal upstream credentials (ref only), connect snippet. Calls `/api/me/*` over the cookie session. Browser GETs to `/` and `/me` redirect to `/auth/login` when unauthenticated; `/api/*` stays server-side-gated (the real boundary)

## Security invariants

- **Anti-passthrough (MCP auth spec):** the inbound client's token must NEVER be forwarded to an upstream. Upstream credentials come only from the secret store / env.
- **No silent admin:** no auth configured → the gateway refuses to start; `DEV_ALLOW_UNAUTHENTICATED=true` is the only (loudly logged) escape hatch.
- OIDC tokens must be audience-bound to this gateway (`OIDC_AUDIENCE` is mandatory with an issuer).
- Never log secret values — labels and sha256 prefixes only; all logs to `console.error` (stdout untouched).
- Authorization is two-layer: list filtering is UX, the call-time `PolicyService.allows` check is the boundary.
- A session id never carries privilege: every request re-authenticates; principal mismatch → 403.

## Deployment

`docker/` — multi-stage Dockerfile (node:24-alpine, no native deps) + compose (gateway + OpenBao dev + commented family-server examples on an internal network). `.env.example` documents all knobs. Behind the gateway, family servers must have their own tokens set (kills mcp-itglue's dev-unauthenticated mode) and `CLIENT_ITGLUE_KEYS=disabled`.

## Roadmap (post-v1)

**OAuth Authorization Server facade (DCR) — SHIPPED** (plan:
`docs/plans/oauth-authorization-server.md`): the gateway hosts RFC 8414
metadata + RFC 7591 DCR + `/oauth/authorize|token`, brokering user auth to
Entra, so `claude mcp add <url>` connects with zero pre-provisioned client
config. Remaining phases: refresh-token grant (phase 2), CIMD `https://`
client ids (phase 3).

Also: resources/prompts federation · npm pre-install pool.

**MSPStack integrated mode** — the gateway runs as a native MSPStack app. SHIPPED: `secrets/keyvault.ts` (`kv:<name>` refs), `GATEWAY_MODE=standalone|integrated` (integrated demands KEY_VAULT_URI + OIDC; standalone is byte-for-byte the old behavior), `/api/me/*` self-service (narrow-only prefs enforced in PolicyService at list AND call; personal creds → secret store, refs only), and `sessionMode:"per-user"` upstream sessions consuming those creds. REMAINING: the Toolbox "My MCP Access" app (MSPStack repo; gated on an Entra app registration for the gateway audience). Design plan: hub repo (private, github.com/mspstack/hub) `docs/plans/gateway-integrated-mode.md`.
