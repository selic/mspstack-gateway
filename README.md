# MSPStack Gateway

A self-hosted **MCP manager**: one Model Context Protocol endpoint that federates all your MCP servers — with OAuth/token authentication, role-based tool access, per-tool enable/disable, OpenBao-backed secret storage, and an admin UI to install and manage servers.

Point Claude (Code, Desktop, or any MCP client) at a single URL; the gateway connects to your MCP servers — IT Glue, ConnectWise, Planner, or anything else — and exposes their tools under one roof. Credentials for upstream services live in the gateway's secret store (never in client config files), and what each user can see and call is centrally controlled.

## Features

- **One endpoint, many servers** — aggregates HTTP and stdio MCP servers with namespaced tools (`itglue_*`, `cw_*`, …) and live `tools/list_changed` propagation
- **OAuth 2.1 + static tokens** — resource-server auth per the MCP spec (Entra ID or any OIDC provider; RFC 9728 discovery, audience-bound tokens) plus `MCP_TOKENS_<ROLE>` bearer tokens for non-OAuth clients
- **Roles & policy** — viewer/editor/admin (plus custom roles) gate tools by annotation-derived tiers (read/write/destructive), with per-upstream grants and per-tool allow/deny overrides; enforcement is re-checked at call time
- **Secrets stay server-side** — upstream API keys live in OpenBao (`bao:path#field` refs) or env vars, injected at connect time; the inbound client token is never passed through to upstreams
- **Install from the UI** — add MCP servers by URL, npm package (npx), or Docker image; search the official MCP registry; preflight-test before saving; crashed stdio servers restart with backoff
- **Admin UI** at `/admin` — status, server management, tool toggles, role matrix, users & group mappings, secret writes

## Quick start

```bash
npm install && npm run build

export MCP_TOKENS_ADMIN="me:$(openssl rand -hex 24)"
npm run dev            # gateway on http://localhost:3100
```

Open `http://localhost:3100/admin`, sign in with the admin token, and add your first MCP server. Then connect Claude Code:

```bash
claude mcp add --transport http mspstack http://localhost:3100/mcp \
  --header "Authorization: Bearer <your token>"
```

Or with Docker (gateway + OpenBao):

```bash
cp .env.example docker/.env   # set MCP_TOKENS_ADMIN
docker compose -f docker/docker-compose.yml up -d
```

## Configuration

| Env | Purpose |
| --- | --- |
| `MCP_TOKENS_ADMIN` / `_EDITOR` / `_VIEWER` / `_<ROLE>` | static bearer tokens, `label:token,…` |
| `ENTRA_TENANT_ID` or `OIDC_ISSUER` + `OIDC_AUDIENCE` | OAuth 2.1 resource-server mode |
| `ADMIN_BOOTSTRAP_SUBJECTS` | emails/subs that get admin on first OIDC login |
| `BAO_ADDR` + `BAO_TOKEN` or `BAO_ROLE_ID`/`BAO_SECRET_ID` | OpenBao secret store (`bao:path#field` refs) |
| `KEY_VAULT_URI` | Azure Key Vault secret store via `DefaultAzureCredential` (`kv:secret-name` refs; one store at a time) |
| `GATEWAY_MODE` | `standalone` (default) or `integrated` — integrated (running as a native MSPStack app) requires `KEY_VAULT_URI` + OIDC |
| `PORT`, `PUBLIC_URL`, `DB_PATH`, `ALLOWED_ORIGINS` | plumbing |
| `DEV_ALLOW_UNAUTHENTICATED=true` | localhost-dev only; without any auth configured the gateway refuses to start |

Upstreams are managed in the admin UI (stored in SQLite) and/or declared in `mspstack.config.json` (upserted at boot; see `mspstack.config.example.json`). Header/env values accept `${ENV_VAR}` and `bao:path#field` references — resolved at connect time, never stored:

```json
{
  "upstreams": [
    {
      "id": "itglue", "namespace": "itglue", "transport": "http",
      "url": "http://mcp-itglue:3000/mcp",
      "headers": { "Authorization": "Bearer bao:upstreams/itglue#token" }
    },
    {
      "id": "everything", "namespace": "demo", "transport": "stdio",
      "command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything"]
    }
  ]
}
```

## Security model

- The gateway is an **OAuth 2.1 resource server** (MCP authorization spec 2025-11-25): RFC 9728 metadata at `/.well-known/oauth-protected-resource`, `WWW-Authenticate` discovery on 401, and strict audience validation — tokens minted for other resources are rejected.
- **Anti-passthrough:** inbound client tokens are used only to resolve identity; upstream credentials come exclusively from the secret store / env and are injected server-side.
- Tool authorization is two-layer: `tools/list` filtering is UX; the call-time policy check is the boundary. Sessions are principal-bound — a session id alone grants nothing.

Requires **Node ≥ 24** (built-in `node:sqlite` — no native dependencies).

Part of **MSPStack** — a family of MCP tooling for MSPs: [mcp-itglue](https://github.com/selic/mcp-itglue), [mcp-connectwise-psa](https://github.com/selic/mcp-connectwise-psa), [mcp-planner](https://github.com/selic/mcp-planner).

## Roadmap

Admin-UI OIDC login (today the UI signs in with an admin token) · resources/prompts federation · CIMD client registration.

Shipped from the MSPStack integrated-mode plan (`docs/plans/gateway-integrated-mode.md` in the MSPStack repo): Azure Key Vault secret store (`kv:` refs), `GATEWAY_MODE`, `/api/me` self-service (narrow-only tool prefs + personal upstream credentials), and `sessionMode: "per-user"` — per-principal upstream sessions running each caller's calls over their own registered credentials (PSA write attribution).

## Author

Built by **Eugene Samotija** ([@selic](https://github.com/selic)) — [defency.net](https://defency.net).
More projects: [github.com/selic](https://github.com/selic) · [LinkedIn](https://www.linkedin.com/in/evghenii-samotiia)

## License

MIT
