/**
 * SQLite persistence via node:sqlite (built-in, zero native deps; Node ≥24).
 * Schema is created idempotently; PRAGMA user_version tracks migrations.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export function openDatabase(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  migrate(db);
  return db;
}

function migrate(db: DatabaseSync): void {
  const version = (db.prepare("PRAGMA user_version").get() as { user_version: number })
    .user_version;

  if (version < 1) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        default_max_tier TEXT NOT NULL DEFAULT 'none'
          CHECK (default_max_tier IN ('none','read','write','destructive')),
        is_admin INTEGER NOT NULL DEFAULT 0,
        protected INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS upstreams (
        id TEXT PRIMARY KEY,
        namespace TEXT NOT NULL UNIQUE,
        transport TEXT NOT NULL CHECK (transport IN ('http','stdio')),
        spec_json TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        source TEXT NOT NULL DEFAULT 'api' CHECK (source IN ('file','api'))
      );

      CREATE TABLE IF NOT EXISTS grants (
        role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        upstream_id TEXT NOT NULL,
        max_tier TEXT NOT NULL CHECK (max_tier IN ('none','read','write','destructive')),
        PRIMARY KEY (role_id, upstream_id)
      );

      CREATE TABLE IF NOT EXISTS tool_overrides (
        role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        upstream_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        effect TEXT NOT NULL CHECK (effect IN ('allow','deny')),
        PRIMARY KEY (role_id, upstream_id, tool_name)
      );

      CREATE TABLE IF NOT EXISTS tool_settings (
        upstream_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        tier_override TEXT CHECK (tier_override IN ('read','write','destructive')),
        group_label TEXT,
        PRIMARY KEY (upstream_id, tool_name)
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        iss TEXT NOT NULL,
        sub TEXT NOT NULL,
        email TEXT,
        display_name TEXT,
        role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL,
        last_login_at TEXT,
        UNIQUE (iss, sub)
      );

      CREATE TABLE IF NOT EXISTS group_mappings (
        id INTEGER PRIMARY KEY,
        iss TEXT NOT NULL,
        claim_value TEXT NOT NULL,
        role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        UNIQUE (iss, claim_value)
      );
    `);

    const seed = db.prepare(
      "INSERT OR IGNORE INTO roles (name, default_max_tier, is_admin, protected) VALUES (?, ?, ?, 1)"
    );
    seed.run("viewer", "read", 0);
    seed.run("editor", "write", 0);
    seed.run("admin", "destructive", 1);

    db.exec("PRAGMA user_version = 1");
  }

  if (version < 2) {
    // Per-principal self-service (integrated-mode slice 3): personal narrowing
    // prefs and registered upstream credentials. `principal` is the stable
    // identity `${kind}:${subject}` — deliberately NOT the role-qualified
    // session key, so prefs survive role changes.
    db.exec(`
      CREATE TABLE IF NOT EXISTS user_prefs (
        principal TEXT NOT NULL,
        upstream_id TEXT NOT NULL,
        tool_name TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL,
        PRIMARY KEY (principal, upstream_id, tool_name)
      );

      CREATE TABLE IF NOT EXISTS user_credentials (
        principal TEXT NOT NULL,
        upstream_id TEXT NOT NULL,
        field TEXT NOT NULL,
        secret_ref TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (principal, upstream_id, field)
      );
    `);

    db.exec("PRAGMA user_version = 2");
  }

  if (version < 3) {
    // OAuth Authorization Server facade (DCR): dynamically registered MCP
    // clients and single-use authorization codes. Codes are stored HASHED
    // (sha256 hex) — the plaintext never touches the database. expires_at is
    // unix epoch millis for cheap comparison.
    db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT,
        redirect_uris_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS oauth_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        principal_iss TEXT NOT NULL,
        principal_sub TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        resource TEXT,
        expires_at INTEGER NOT NULL,
        used_at TEXT
      );
    `);

    db.exec("PRAGMA user_version = 3");
  }
}
