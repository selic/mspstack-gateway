# OAuth Authorization Server facade (DCR) — make the gateway connectable by standard MCP clients

> **Status: IMPLEMENTED (phase 1, 2026-07-16)** — commits 1–5 of §4 are done:
> DCR + authorize/token + gateway JWTs + resolver/PRM wiring + docs. Phase 2
> (refresh tokens) and phase 3 (CIMD) remain. This document is self-contained:
> a fresh session in this repo can execute the remaining phases without prior
> conversation context.

## 1. Problem — verified in production 2026-07-16

`claude mcp add --transport http mspstack https://mcp-gateway.mspstack.networkdr.tech/mcp`
→ **"Failed to connect"**. Reproduced at protocol level against the live deployment
(`ndr-mcp-gateway`, v0.2.0, OAuth mode with Entra tenant `b85077ce-…`):

| MCP auth spec step | Result |
|---|---|
| `POST /mcp` unauth → `401` + `WWW-Authenticate: Bearer resource_metadata=…` | ✅ works (`src/auth/prm.ts`) |
| PRM lists the protecting authorization server | ✅ points at Entra (`login.microsoftonline.com/<tenant>/v2.0`) |
| Client fetches AS metadata, looks for `registration_endpoint` | ❌ Entra advertises **none** (no anonymous DCR, by design) |
| Client registers via RFC 7591 DCR to obtain a `client_id` | ❌ **flow dies here** |
| Gateway hosts its own `/.well-known/oauth-authorization-server` | ❌ 404 (never built) |

Clients that "just work" in Claude (Linear, Notion, …) all run authorization servers
that support DCR. Entra cannot; therefore **the gateway itself must become the
authorization server** the client talks to, brokering user authentication to Entra.
This is the roadmap item previously listed as "CIMD client registration".

Note the role inversion: the existing interactive login (`src/auth/login.ts`) makes the
gateway an OAuth **client** of Entra (confidential app "MSP-Stack Control Plane",
`AUTH_CLIENT_ID=79ef11c8-701e-4505-bc60-810188b474de`, redirect
`https://mcp-gateway.mspstack.networkdr.tech/auth/callback` already registered). What is
missing is the gateway acting as an OAuth **server** toward unknown MCP clients.

## 2. Design

Gateway-hosted AS endpoints; the user-authentication leg reuses the existing Entra
confidential-client flow. No change to Entra app registration is required.

```
MCP client                gateway (new AS)                    Entra
   |  POST /mcp (no token)     |                                |
   |<-- 401 + PRM ------------ |                                |
   |  GET /.well-known/oauth-protected-resource                 |
   |<-- authorization_servers: [ PUBLIC_URL ]  (self, not Entra)|
   |  GET /.well-known/oauth-authorization-server               |
   |<-- {authorize, token, registration endpoints}              |
   |  POST /oauth/register  (RFC 7591) --> client_id            |
   |  browser: GET /oauth/authorize?client_id&code_challenge…   |
   |                           | --302--> Entra authorize ----->|
   |                           |<-- callback (code) ------------|
   |                           | token exchange (existing leg)  |
   |<-- 302 redirect_uri?code=<gateway code>                    |
   |  POST /oauth/token (code + PKCE verifier)                  |
   |<-- gateway-issued access token                             |
   |  POST /mcp  Authorization: Bearer <gateway token>          |
```

### 2.1 Endpoints (new module `src/auth/authz-server.ts` + routes in `src/http/app.ts`)

- **`GET /.well-known/oauth-authorization-server`** (RFC 8414; also serve the
  path-suffix variant `…/oauth-authorization-server/mcp` — some clients probe it).
  Issuer = `PUBLIC_URL`. Advertise `code` response type, `S256` only,
  `token_endpoint_auth_methods_supported: ["none"]` (public clients + PKCE).
- **PRM change** (`src/auth/prm.ts`): `authorization_servers: [PUBLIC_URL]` instead of
  the Entra issuer. Direct Entra bearers must STILL validate (see 2.4) — PRM only
  affects discovery, not acceptance.
- **`POST /oauth/register`** (RFC 7591): anonymous, auto-approve. Accept
  `redirect_uris` (allow only `http://localhost:*` / `http://127.0.0.1:*` loopback and
  `https://…`), `client_name`, `token_endpoint_auth_method: "none"`. Return generated
  `client_id`. Persist in SQLite. Rate-limit (e.g. 10/min/IP) — it is an open endpoint.
- **`GET /oauth/authorize`**: validate `client_id` exists, `redirect_uri` exact-matches
  a registered one, `code_challenge` + `method=S256` present, `state` echoed,
  `resource` (RFC 8707) if present must equal the canonical `<PUBLIC_URL>/mcp`.
  Then run the Entra leg: reuse the openid-client machinery from
  `createLoginService` (`src/auth/login.ts`) — same confidential client, same
  `/auth/callback`, but carry the pending authorize-request in the transient state
  (extend the existing `TRANSIENT_COOKIE` payload or a server-side pending table).
  On successful Entra callback: mint a **single-use, short-TTL (60s) authorization
  code** bound to `{client_id, code_challenge, principal(iss,sub), resource}` and 302
  to the client's `redirect_uri`.
- **`POST /oauth/token`**: `grant_type=authorization_code` — verify code unused/unexpired,
  client_id matches, PKCE verifier hashes to the stored challenge. Mint the access token.
  Phase 2 (recommended, small): `grant_type=refresh_token` with rotating refresh tokens.

### 2.2 Gateway-issued access tokens

Signed JWT (HS256), dedicated secret `GATEWAY_JWT_SECRET` (fallback: derive from
`SESSION_SECRET`, but a separate knob keeps rotation independent). Claims:
`iss=PUBLIC_URL`, `aud=<PUBLIC_URL>/mcp`, `sub=<entra iss>|<entra sub>` (the same
principal key shape as `src/auth/principal.ts`), `exp` ≈ 1h, `jti`.
**Do NOT embed the role** — the resolver re-resolves role per request from the users
table, preserving the "a session id never carries privilege" invariant.

### 2.3 Persistence (`src/db/`)

SQLite is correct here: the integrated-mode design (MSPStack repo,
`docs/plans/gateway-integrated-mode.md`) fixes "gateway SQLite is the single writer
for its own state" — Postgres belongs to the hub, and SQLite→Postgres convergence is
an open item gated on a multi-instance gateway. Note for that future item: AS state
(single-use codes, client registrations) must move too — single-use enforcement
breaks across instances otherwise. If the DB is ever wiped, registered clients just
re-register via DCR (clients handle `invalid_client` by re-registering).

New tables (follow the existing `Repo` pattern in `src/db/repo.ts`):
- `oauth_clients(client_id PK, client_name, redirect_uris_json, created_at)`
- `oauth_codes(code_hash PK, client_id, principal_iss, principal_sub, code_challenge,
  resource, expires_at, used_at)` — store the **hash** of the code, never plaintext.
- (phase 2) `oauth_refresh_tokens(token_hash PK, client_id, principal…, expires_at, rotated_from)`

### 2.4 Inbound auth resolver (`createAuthResolver`)

Add a **fourth** path alongside static tokens, Entra OIDC bearers, and the cookie
session: verify gateway-issued JWTs (iss/aud/exp/signature) → principal `{iss, sub}`
(the embedded Entra identity) → role re-resolved exactly like the OIDC path
(`loginUpsert`/`setUserRole` data). Existing paths keep working — static tokens and
direct Entra bearers must not regress (`OIDC_AUDIENCE` validation unchanged).

### 2.5 Enablement

AS mode requires the interactive-login config (`AUTH_CLIENT_ID`/`AUTH_CLIENT_SECRET`/
`SESSION_SECRET`) + `PUBLIC_URL` + OIDC issuer — all already present on the NDR
deployment. When absent, the AS endpoints 404 and PRM falls back to today's behavior.
No new mandatory env for existing deployments except (optionally) `GATEWAY_JWT_SECRET`.

### 2.6 Explicitly out of scope / later

- **CIMD** (client-id metadata documents): accept `https://` client_id URLs per the
  draft the MCP spec is moving toward — additive on top of DCR; do after DCR ships.
- Consent screen (auto-approve is acceptable: the resource is ours, users authenticate
  via Entra; revisit if third-party clients matter).
- Upstream anything: this is purely inbound auth. Anti-passthrough is untouched —
  gateway tokens are never forwarded upstream (structurally impossible already).

## 3. Security invariants (must hold; add tests)

- PKCE S256 mandatory; exact `redirect_uri` match; single-use codes (mark `used_at`,
  reject replays); 60s code TTL.
- `resource`/`aud` binding: tokens minted for other resources rejected (mirrors the
  existing audience rule).
- Tokens/codes never logged — labels + sha256 prefixes only (repo convention).
- Unknown vs forbidden stays indistinguishable on `/mcp` (no existence oracle).
- Register endpoint rate-limited; no open redirect (only registered URIs).
- Role resolved per request; JWT carries identity only.

## 4. Commit plan (small, verified)

1. `db`: `oauth_clients` + `oauth_codes` tables + Repo methods + tests.
2. `auth/authz-server.ts`: AS metadata endpoint + `/oauth/register` (+ rate limit) + tests.
3. `/oauth/authorize` — pending-request handling + Entra broker leg (reuse login.ts) +
   code minting; `/oauth/token` + PKCE + JWT mint + tests.
4. Resolver branch for gateway JWTs + PRM switch to self + `WWW-Authenticate` unchanged;
   regression tests: static tokens, Entra bearers, cookie session all still pass.
5. README (Features + Security model) + CLAUDE.md roadmap update.
6. (phase 2) refresh tokens; (phase 3) CIMD.

## 5. Verification

- Unit: vitest suites per commit (`npm test`).
- Local e2e: `npm run dev` with dev Entra config (or `DEV_ALLOW_UNAUTHENTICATED` for
  non-auth surfaces), then `npx @modelcontextprotocol/inspector` OAuth connect, and
  `claude mcp add --transport http gw http://localhost:3100/mcp` → browser sign-in →
  `tools/list` shows federated upstreams → a read-tier `tools/call` succeeds → a
  destructive-tier call is denied for a viewer.
- Prod (after release via the release-mcp-server skill → `ndr-mcp-gateway`):
  repeat `claude mcp add` against `https://mcp-gateway.mspstack.networkdr.tech/mcp`,
  sign in as `eugene.samotija@networkdr.com` (ADMIN_BOOTSTRAP_SUBJECTS) → admin role.
- Success criterion: a stock Claude Code/Desktop connects with **zero** pre-provisioned
  client config — URL only.

## 6. Deployment facts (NDR, for the e2e leg)

- App Service `ndr-mcp-gateway`, RG `NDR-RG-MSPCopilot`, sub `18405009-ab39-4220-9c8e-32c7a502606f`.
- `PUBLIC_URL=https://mcp-gateway.mspstack.networkdr.tech`, `GATEWAY_MODE=integrated`,
  `ENTRA_TENANT_ID=b85077ce-59ca-4a5c-a0be-a7a610623572`,
  `OIDC_AUDIENCE=api://79ef11c8-701e-4505-bc60-810188b474de`.
- Entra app "MSP-Stack Control Plane" (`79ef11c8-…`): scope `gateway.access`, gateway
  callback already in web redirects. **No Entra changes needed for this plan.**
- Image: `ghcr.io/mspstack/mcp-gateway` (org namespace as of v0.3.0); deploy runbook =
  user-level `release-mcp-server` skill.
