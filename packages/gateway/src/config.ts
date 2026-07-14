/**
 * Configuration: CLI flags + environment + a declarative upstreams file.
 *
 *   --port / PORT                    HTTP listen port (default 3100)
 *   --config / MSPSTACK_CONFIG       path to mspstack.config.json (default ./mspstack.config.json)
 *   --db / DB_PATH                   SQLite database path (default data/gateway.db, ":memory:" allowed)
 *   PUBLIC_URL                       externally visible base URL (default http://localhost:<port>)
 *   ALLOWED_ORIGINS                  comma-separated browser origins allowed on /mcp
 *
 * Authentication (at least one of these must be configured, or the explicit
 * dev override — there is no silent "no config → full admin" mode):
 *   MCP_TOKENS_<ROLE>                static bearer tokens per role, "label:token,…" lists
 *   OIDC_ISSUER / ENTRA_TENANT_ID    OAuth 2.1 resource-server mode (+ OIDC_AUDIENCE required)
 *   OIDC_GROUPS_CLAIM                claim holding group ids (default "groups")
 *   ADMIN_BOOTSTRAP_SUBJECTS         comma list of emails/subs granted admin on first OIDC login
 *   DEV_ALLOW_UNAUTHENTICATED=true   explicit localhost-dev escape hatch (admin role)
 *
 *   GATEWAY_MODE                     standalone (default) | integrated — integrated
 *                                    requires KEY_VAULT_URI + OIDC (refuses to start otherwise)
 *
 * Secrets (one store at a time, optional):
 *   BAO_ADDR, BAO_MOUNT (default "mspstack"), BAO_TOKEN or BAO_ROLE_ID+BAO_SECRET_ID
 *     — OpenBao / Vault KV v2, enables "bao:path#field" refs
 *   KEY_VAULT_URI (https://<vault>.vault.azure.net)
 *     — Azure Key Vault via DefaultAzureCredential, enables "kv:secret-name" refs
 *
 * Upstream header/env values support `${VAR}` env substitution and
 * `bao:`/`kv:` secret refs — all resolved at connect time, never stored.
 */

import { readFileSync } from "node:fs";
import { z } from "zod";

export class ConfigError extends Error {}

/** Namespaces exclude "_" so exposed tool names stay unambiguous. */
const NAMESPACE_RE = /^[a-z0-9]+$/;

const upstreamBase = {
  id: z.string().min(1),
  namespace: z
    .string()
    .regex(NAMESPACE_RE, "namespace must match [a-z0-9]+ (no underscores)"),
  enabled: z.boolean().default(true),
  /**
   * shared (default) — one pooled connection with the spec's credentials.
   * per-user — calls run over a per-principal connection whose header/env
   * values are overridden by the caller's registered credentials
   * (/api/me/credentials); catalog discovery still uses the shared link.
   */
  sessionMode: z.enum(["shared", "per-user"]).default("shared"),
  /** per-user only: refuse shared-credential fallback for callers without personal creds. */
  requirePersonalCredentials: z.boolean().default(false),
};

const httpUpstreamSchema = z.object({
  ...upstreamBase,
  transport: z.literal("http"),
  url: z.string().min(1),
  headers: z.record(z.string(), z.string()).default({}),
});

const stdioUpstreamSchema = z.object({
  ...upstreamBase,
  transport: z.literal("stdio"),
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
});

export const upstreamSpecSchema = z.discriminatedUnion("transport", [
  httpUpstreamSchema,
  stdioUpstreamSchema,
]);

const configFileSchema = z.object({
  upstreams: z.array(upstreamSpecSchema).default([]),
});

export type HttpUpstreamSpec = z.infer<typeof httpUpstreamSchema>;
export type StdioUpstreamSpec = z.infer<typeof stdioUpstreamSchema>;
export type UpstreamSpec = HttpUpstreamSpec | StdioUpstreamSpec;

export interface StaticTokenEntry {
  token: string;
  roleName: string;
  label: string;
}

export interface OidcConfig {
  issuer: string;
  audience: string;
  groupsClaim: string;
}

export interface BaoConfig {
  addr: string;
  mount: string;
  token?: string;
  roleId?: string;
  secretId?: string;
}

export interface KeyVaultConfig {
  vaultUrl: string;
}

export type GatewayMode = "standalone" | "integrated";

export interface GatewayConfig {
  /**
   * standalone (default) — today's behavior, byte for byte.
   * integrated — running as a native MSPStack app: requires the platform
   * Key Vault (KEY_VAULT_URI) and OIDC (Entra) so user self-service has a
   * real principal and a real secret store. Same "no silent misconfig"
   * posture as auth: refuse to start rather than run half-integrated.
   */
  mode: GatewayMode;
  port: number;
  publicUrl: string;
  configPath: string;
  dbPath: string;
  allowedOrigins: string[];
  upstreamsFromFile: UpstreamSpec[];
  staticTokens: StaticTokenEntry[];
  oidc: OidcConfig | null;
  adminBootstrapSubjects: string[];
  devAllowUnauthenticated: boolean;
  bao: BaoConfig | null;
  keyVault: KeyVaultConfig | null;
}

/** Substitute `${VAR}` references from env; unset variables are a hard error. */
export function substituteEnv(
  value: string,
  env: NodeJS.ProcessEnv,
  context: string
): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_match, name: string) => {
    const resolved = env[name];
    if (resolved === undefined || resolved === "") {
      throw new ConfigError(
        `Environment variable "${name}" referenced by ${context} is not set`
      );
    }
    return resolved;
  });
}

function flagValue(argv: string[], flag: string): string | undefined {
  const index = argv.indexOf(flag);
  if (index === -1) return undefined;
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new ConfigError(`Missing value for ${flag}`);
  }
  return value;
}

/** Validate a single upstream spec object (also used by the admin API). */
export function parseUpstreamSpec(json: unknown): UpstreamSpec {
  const parsed = upstreamSpecSchema.safeParse(json);
  if (!parsed.success) throw new ConfigError(`Invalid upstream: ${parsed.error.message}`);
  const spec = parsed.data;
  // URLs may contain ${VAR}/bao: refs resolved at connect time — only
  // validate the shape when the value is already concrete.
  if (spec.transport === "http" && !spec.url.includes("${") && !spec.url.startsWith("bao:")) {
    try {
      const url = new URL(spec.url);
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new ConfigError(`upstream "${spec.id}": url must be http(s)`);
      }
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      throw new ConfigError(`upstream "${spec.id}": invalid url "${spec.url}"`);
    }
  }
  return spec;
}

/** Parse the upstreams file content. Exported for tests. */
export function parseConfigFile(raw: string): UpstreamSpec[] {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw new ConfigError(`Config file is not valid JSON: ${String(err)}`);
  }
  const parsed = configFileSchema.safeParse(json);
  if (!parsed.success) {
    throw new ConfigError(`Invalid config file: ${parsed.error.message}`);
  }

  const ids = new Set<string>();
  const namespaces = new Set<string>();
  for (const upstream of parsed.data.upstreams) {
    if (ids.has(upstream.id)) {
      throw new ConfigError(`Duplicate upstream id "${upstream.id}"`);
    }
    if (namespaces.has(upstream.namespace)) {
      throw new ConfigError(`Duplicate upstream namespace "${upstream.namespace}"`);
    }
    ids.add(upstream.id);
    namespaces.add(upstream.namespace);
  }

  return parsed.data.upstreams.map((upstream) => parseUpstreamSpec(upstream));
}

/**
 * Parse MCP_TOKENS_<ROLE> env vars into token entries (generalized port of
 * mcp-itglue's tokens.ts: "label:token,…" lists, auto labels, cross-role
 * duplicate tokens dropped with a warning).
 */
export function parseStaticTokens(env: NodeJS.ProcessEnv): StaticTokenEntry[] {
  const entries: StaticTokenEntry[] = [];
  const seen = new Set<string>();

  for (const [key, value] of Object.entries(env)) {
    const match = /^MCP_TOKENS_([A-Z0-9_]+)$/.exec(key);
    if (!match || !value) continue;
    const roleName = match[1]!.toLowerCase();

    let autoIndex = 0;
    for (const piece of value.split(",")) {
      const trimmed = piece.trim();
      if (!trimmed) continue;
      const sep = trimmed.indexOf(":");
      let label: string;
      let token: string;
      if (sep > 0 && sep < trimmed.length - 1) {
        label = trimmed.slice(0, sep);
        token = trimmed.slice(sep + 1);
      } else {
        autoIndex += 1;
        label = `${roleName}-${autoIndex}`;
        token = trimmed.replace(/^:|:$/g, "");
      }
      if (!token) continue;
      if (seen.has(token)) {
        console.error(
          `[auth] duplicate token value for label "${label}" (${roleName}) ignored — first definition wins`
        );
        continue;
      }
      seen.add(token);
      entries.push({ token, roleName, label });
    }
  }
  return entries;
}

const cleanEnv = (value: string | undefined): string | undefined => {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed || /^\$\{.*\}$/.test(trimmed)) return undefined; // unsubstituted template
  return trimmed;
};

export function loadConfig(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env
): GatewayConfig {
  const portRaw = flagValue(argv, "--port") ?? env.PORT ?? "3100";
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigError(`Invalid port "${portRaw}"`);
  }

  const configPath = flagValue(argv, "--config") ?? env.MSPSTACK_CONFIG ?? "mspstack.config.json";
  const dbPath = flagValue(argv, "--db") ?? cleanEnv(env.DB_PATH) ?? "data/gateway.db";
  const publicUrl = (cleanEnv(env.PUBLIC_URL) ?? `http://localhost:${port}`).replace(/\/+$/, "");

  let raw: string;
  try {
    raw = readFileSync(configPath, "utf-8");
  } catch {
    raw = '{"upstreams":[]}'; // config file is optional — upstreams can live in the DB
  }

  const allowedOrigins = (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/+$/, ""))
    .filter((origin) => origin.length > 0);

  // ── OIDC ──
  const entraTenant = cleanEnv(env.ENTRA_TENANT_ID);
  const issuer =
    cleanEnv(env.OIDC_ISSUER) ??
    (entraTenant ? `https://login.microsoftonline.com/${entraTenant}/v2.0` : undefined);
  const audience = cleanEnv(env.OIDC_AUDIENCE);
  let oidc: OidcConfig | null = null;
  if (issuer) {
    if (!audience) {
      throw new ConfigError(
        "OIDC_AUDIENCE is required when OIDC_ISSUER/ENTRA_TENANT_ID is set — tokens must be audience-bound to this gateway (RFC 8707)"
      );
    }
    oidc = { issuer, audience, groupsClaim: cleanEnv(env.OIDC_GROUPS_CLAIM) ?? "groups" };
  }

  // ── OpenBao ──
  const baoAddr = cleanEnv(env.BAO_ADDR);
  let bao: BaoConfig | null = null;
  if (baoAddr) {
    const token = cleanEnv(env.BAO_TOKEN);
    const roleId = cleanEnv(env.BAO_ROLE_ID);
    const secretId = cleanEnv(env.BAO_SECRET_ID);
    if (!token && !(roleId && secretId)) {
      throw new ConfigError(
        "BAO_ADDR is set but no auth — provide BAO_TOKEN or BAO_ROLE_ID + BAO_SECRET_ID"
      );
    }
    bao = {
      addr: baoAddr.replace(/\/+$/, ""),
      mount: cleanEnv(env.BAO_MOUNT) ?? "mspstack",
      ...(token ? { token } : {}),
      ...(roleId ? { roleId } : {}),
      ...(secretId ? { secretId } : {}),
    };
  }

  // ── mode ──
  const modeRaw = cleanEnv(env.GATEWAY_MODE) ?? "standalone";
  if (modeRaw !== "standalone" && modeRaw !== "integrated") {
    throw new ConfigError(`GATEWAY_MODE must be "standalone" or "integrated", got "${modeRaw}"`);
  }
  const mode: GatewayMode = modeRaw;

  // ── Azure Key Vault ──
  const keyVaultUri = cleanEnv(env.KEY_VAULT_URI);
  let keyVault: KeyVaultConfig | null = null;
  if (keyVaultUri) {
    if (bao) {
      throw new ConfigError(
        "Both BAO_ADDR and KEY_VAULT_URI are set — the gateway serves one ref scheme at a time; unset one"
      );
    }
    if (!/^https:\/\//i.test(keyVaultUri)) {
      throw new ConfigError(`KEY_VAULT_URI must be an https:// vault URL, got "${keyVaultUri}"`);
    }
    keyVault = { vaultUrl: keyVaultUri.replace(/\/+$/, "") };
  }

  if (mode === "integrated") {
    if (!keyVault) {
      throw new ConfigError("GATEWAY_MODE=integrated requires KEY_VAULT_URI (the platform Key Vault)");
    }
    if (!oidc) {
      throw new ConfigError(
        "GATEWAY_MODE=integrated requires OIDC (ENTRA_TENANT_ID/OIDC_ISSUER + OIDC_AUDIENCE) — user self-service needs real principals"
      );
    }
  }

  return {
    mode,
    port,
    publicUrl,
    configPath,
    dbPath,
    allowedOrigins,
    upstreamsFromFile: parseConfigFile(raw),
    staticTokens: parseStaticTokens(env),
    oidc,
    adminBootstrapSubjects: (env.ADMIN_BOOTSTRAP_SUBJECTS ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    devAllowUnauthenticated: env.DEV_ALLOW_UNAUTHENTICATED === "true",
    bao,
    keyVault,
  };
}
