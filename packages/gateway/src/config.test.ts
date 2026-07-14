import { describe, expect, it } from "vitest";
import {
  ConfigError,
  loadConfig,
  parseConfigFile,
  parseStaticTokens,
  substituteEnv,
} from "./config.js";

const env = { ITGLUE_TOKEN: "secret-token" } as NodeJS.ProcessEnv;

describe("substituteEnv", () => {
  it("substitutes ${VAR} references", () => {
    expect(substituteEnv("Bearer ${ITGLUE_TOKEN}", env, "test")).toBe("Bearer secret-token");
  });

  it("passes through values without references", () => {
    expect(substituteEnv("plain", env, "test")).toBe("plain");
  });

  it("throws ConfigError on unset variables", () => {
    expect(() => substituteEnv("${MISSING_VAR}", env, "upstream x")).toThrow(ConfigError);
    expect(() => substituteEnv("${MISSING_VAR}", env, "upstream x")).toThrow(/MISSING_VAR/);
  });
});

describe("parseConfigFile", () => {
  const wrap = (upstreams: unknown[]): string => JSON.stringify({ upstreams });

  it("parses upstreams, keeping ${VAR}/bao: refs raw for connect-time resolution", () => {
    const specs = parseConfigFile(
      wrap([
        {
          id: "itglue",
          namespace: "itglue",
          transport: "http",
          url: "http://localhost:3000/mcp",
          headers: { Authorization: "Bearer ${ITGLUE_TOKEN}", "x-key": "bao:upstreams/itglue#key" },
        },
      ])
    );
    const spec = specs[0]!;
    expect(spec.transport).toBe("http");
    if (spec.transport === "http") {
      expect(spec.headers.Authorization).toBe("Bearer ${ITGLUE_TOKEN}");
      expect(spec.headers["x-key"]).toBe("bao:upstreams/itglue#key");
    }
    expect(spec.enabled).toBe(true);
  });

  it("parses a stdio upstream with defaulted args/env", () => {
    const specs = parseConfigFile(
      wrap([{ id: "demo", namespace: "demo", transport: "stdio", command: "npx" }])
    );
    const spec = specs[0]!;
    if (spec.transport === "stdio") {
      expect(spec.args).toEqual([]);
      expect(spec.env).toEqual({});
    }
  });

  it("rejects invalid JSON", () => {
    expect(() => parseConfigFile("{nope")).toThrow(ConfigError);
  });

  it("rejects namespaces with underscores or uppercase", () => {
    for (const namespace of ["it_glue", "ItGlue", ""]) {
      expect(() =>
        parseConfigFile(
          wrap([{ id: "x", namespace, transport: "http", url: "http://localhost/mcp" }])
        )
      ).toThrow(ConfigError);
    }
  });

  it("rejects duplicate ids and namespaces", () => {
    const base = { transport: "http", url: "http://localhost/mcp" };
    expect(() =>
      parseConfigFile(wrap([{ id: "a", namespace: "one", ...base }, { id: "a", namespace: "two", ...base }]))
    ).toThrow(/Duplicate upstream id/);
    expect(() =>
      parseConfigFile(wrap([{ id: "a", namespace: "one", ...base }, { id: "b", namespace: "one", ...base }]))
    ).toThrow(/Duplicate upstream namespace/);
  });

  it("rejects concrete non-http(s) urls but tolerates templated ones", () => {
    expect(() =>
      parseConfigFile(wrap([{ id: "a", namespace: "a", transport: "http", url: "ftp://x" }]))
    ).toThrow(ConfigError);
    expect(() =>
      parseConfigFile(wrap([{ id: "a", namespace: "a", transport: "http", url: "${UPSTREAM_URL}" }]))
    ).not.toThrow();
  });
});

describe("parseStaticTokens", () => {
  it("parses label:token lists per role from MCP_TOKENS_<ROLE>", () => {
    const entries = parseStaticTokens({
      MCP_TOKENS_VIEWER: "alice:tok-a, bob:tok-b",
      MCP_TOKENS_ADMIN: "root:tok-r",
    } as NodeJS.ProcessEnv);
    expect(entries).toContainEqual({ token: "tok-a", roleName: "viewer", label: "alice" });
    expect(entries).toContainEqual({ token: "tok-b", roleName: "viewer", label: "bob" });
    expect(entries).toContainEqual({ token: "tok-r", roleName: "admin", label: "root" });
  });

  it("supports custom role names and auto labels", () => {
    const entries = parseStaticTokens({
      MCP_TOKENS_DISPATCH: "raw-token-1,raw-token-2",
    } as NodeJS.ProcessEnv);
    expect(entries).toEqual([
      { token: "raw-token-1", roleName: "dispatch", label: "dispatch-1" },
      { token: "raw-token-2", roleName: "dispatch", label: "dispatch-2" },
    ]);
  });

  it("keeps colons inside tokens after the first separator", () => {
    const entries = parseStaticTokens({ MCP_TOKENS_ADMIN: "svc:a:b:c" } as NodeJS.ProcessEnv);
    expect(entries).toEqual([{ token: "a:b:c", roleName: "admin", label: "svc" }]);
  });

  it("drops duplicate token values across roles (first wins)", () => {
    const entries = parseStaticTokens({
      MCP_TOKENS_ADMIN: "root:same",
      MCP_TOKENS_VIEWER: "alice:same",
    } as NodeJS.ProcessEnv);
    expect(entries).toHaveLength(1);
  });

  it("ignores empty entries and unrelated env vars", () => {
    const entries = parseStaticTokens({
      MCP_TOKENS_VIEWER: " , ,",
      SOMETHING_ELSE: "x:y",
    } as NodeJS.ProcessEnv);
    expect(entries).toEqual([]);
  });
});

describe("loadConfig — KEY_VAULT_URI", () => {
  const load = (env: Record<string, string>) => loadConfig([], env as NodeJS.ProcessEnv);

  it("parses KEY_VAULT_URI into keyVault config, trimming trailing slashes", () => {
    const config = load({ KEY_VAULT_URI: "https://example-kv.vault.azure.net/" });
    expect(config.keyVault).toEqual({ vaultUrl: "https://example-kv.vault.azure.net" });
    expect(config.bao).toBeNull();
  });

  it("leaves keyVault null when unset", () => {
    expect(load({}).keyVault).toBeNull();
  });

  it("rejects non-https vault URLs", () => {
    expect(() => load({ KEY_VAULT_URI: "http://example-kv.vault.azure.net" })).toThrow(ConfigError);
  });

  it("refuses BAO_ADDR and KEY_VAULT_URI together — one ref scheme at a time", () => {
    expect(() =>
      load({
        KEY_VAULT_URI: "https://example-kv.vault.azure.net",
        BAO_ADDR: "http://127.0.0.1:8200",
        BAO_TOKEN: "dev",
      })
    ).toThrow(/one ref scheme at a time/);
  });
});

describe("loadConfig — GATEWAY_MODE", () => {
  const load = (env: Record<string, string>) => loadConfig([], env as NodeJS.ProcessEnv);
  const integratedEnv = {
    GATEWAY_MODE: "integrated",
    KEY_VAULT_URI: "https://example-kv.vault.azure.net",
    ENTRA_TENANT_ID: "tenant-guid",
    OIDC_AUDIENCE: "api://gateway",
  };

  it("defaults to standalone", () => {
    expect(load({}).mode).toBe("standalone");
  });

  it("rejects unknown modes", () => {
    expect(() => load({ GATEWAY_MODE: "hybrid" })).toThrow(ConfigError);
  });

  it("integrated with Key Vault + OIDC starts", () => {
    const config = load(integratedEnv);
    expect(config.mode).toBe("integrated");
    expect(config.keyVault).not.toBeNull();
    expect(config.oidc).not.toBeNull();
  });

  it("integrated refuses to start without the platform Key Vault", () => {
    const { KEY_VAULT_URI: _omit, ...env } = integratedEnv;
    expect(() => load(env)).toThrow(/requires KEY_VAULT_URI/);
  });

  it("integrated refuses to start without OIDC (self-service needs real principals)", () => {
    const env = { GATEWAY_MODE: "integrated", KEY_VAULT_URI: "https://example-kv.vault.azure.net" };
    expect(() => load(env)).toThrow(/requires OIDC/);
  });
});
