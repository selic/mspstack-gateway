/**
 * User self-service API (integrated-mode slice 3), mounted at /api/me for ANY
 * authenticated principal — this is the backend the Toolbox "My MCP Access"
 * app talks to with the operator's own Entra token.
 *
 * - GET  /api/me/access                    effective servers+tools (envelope ∧ prefs)
 * - PUT  /api/me/prefs                     narrow-only toggles (enable = remove narrowing)
 * - GET  /api/me/credentials               registered credential REFS (never values)
 * - PUT  /api/me/credentials/:upstreamId   store a personal credential; ref only comes back
 * - DELETE /api/me/credentials/:upstreamId/:field
 *
 * Credentials registered here are consumed by per-principal upstream sessions
 * (sessionMode — slice 5); until then they are stored + rotatable but unused.
 * The value goes straight to the secret store under
 * gw-user-<principalSlug>-<upstreamId>[-<field>]; SQLite keeps only the ref.
 */

import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { prefsIdentity, principalSlug, type Principal } from "../auth/principal.js";
import type { AppDeps, AuthOutcome } from "./app.js";

interface MeDeps {
  resolveAuth: (req: Request) => Promise<AuthOutcome>;
  onPolicyChanged: () => void;
}

export function createMeRouter(deps: AppDeps, me: MeDeps): Router {
  const { repo, manager, policy, secretStore } = deps;
  const router = Router();

  // Any authenticated principal — no admin requirement here.
  router.use((req: Request & { principal?: Principal }, res: Response, next) => {
    me.resolveAuth(req)
      .then((auth) => {
        if (!auth.ok) return res.status(auth.status).json({ error: auth.message });
        req.principal = auth.principal;
        next();
      })
      .catch((err) => res.status(500).json({ error: String(err) }));
  });

  const h =
    (fn: (req: Request & { principal?: Principal }, res: Response) => Promise<void> | void) =>
    (req: Request, res: Response): void => {
      Promise.resolve(fn(req, res)).catch((err) => {
        const status = err instanceof z.ZodError ? 400 : 500;
        if (!res.headersSent) res.status(status).json({ error: String(err?.message ?? err) });
      });
    };

  router.get(
    "/access",
    h((req, res) => {
      const principal = req.principal!;
      const who = prefsIdentity(principal);
      const prefs = repo.listUserPrefs(who);
      const serverOff = new Set(prefs.filter((p) => !p.enabled && p.toolName === "").map((p) => p.upstreamId));
      const toolOff = new Set(prefs.filter((p) => !p.enabled && p.toolName !== "").map((p) => `${p.upstreamId} ${p.toolName}`));

      // Only entries inside the admin envelope are listed at all — personal
      // narrowing is shown on top of them; envelope-denied tools stay invisible.
      const byUpstream = new Map<string, Array<{ name: string; exposedName: string; tier: string; enabled: boolean }>>();
      for (const entry of policy.visibleEntries(principal.roleId, manager.catalogEntries())) {
        const list = byUpstream.get(entry.upstreamId) ?? [];
        list.push({
          name: entry.upstreamToolName,
          exposedName: entry.exposedName,
          tier: entry.tier,
          enabled: !serverOff.has(entry.upstreamId) && !toolOff.has(`${entry.upstreamId} ${entry.upstreamToolName}`),
        });
        byUpstream.set(entry.upstreamId, list);
      }
      res.json({
        principal: { label: principal.label, role: principal.roleName },
        servers: [...byUpstream.entries()].map(([upstreamId, tools]) => ({
          upstreamId,
          enabled: !serverOff.has(upstreamId),
          tools,
        })),
      });
    })
  );

  router.put(
    "/prefs",
    h((req, res) => {
      const principal = req.principal!;
      const body = z
        .object({
          upstreamId: z.string().min(1),
          toolName: z.string().default(""),
          enabled: z.boolean(),
        })
        .parse(req.body);

      // Prefs only make sense inside the envelope; reject junk targets so the
      // table can't fill with garbage (and enabling can never widen anyway —
      // "enable" just deletes the personal deny row).
      const envelope = policy.visibleEntries(principal.roleId, manager.catalogEntries());
      const upstreamKnown = envelope.some((e) => e.upstreamId === body.upstreamId);
      const toolKnown =
        body.toolName === "" ||
        envelope.some((e) => e.upstreamId === body.upstreamId && e.upstreamToolName === body.toolName);
      if (!upstreamKnown || !toolKnown) {
        res.status(404).json({ error: "Unknown upstream or tool (or outside your access)" });
        return;
      }

      repo.setUserPref(prefsIdentity(principal), body.upstreamId, body.toolName, body.enabled);
      me.onPolicyChanged();
      res.json({ ok: true });
    })
  );

  router.get(
    "/credentials",
    h((req, res) => {
      const rows = repo.listUserCredentials(prefsIdentity(req.principal!));
      res.json(rows.map(({ upstreamId, field, secretRef, updatedAt }) => ({ upstreamId, field, secretRef, updatedAt })));
    })
  );

  router.put(
    "/credentials/:upstreamId",
    h(async (req, res) => {
      const principal = req.principal!;
      if (!secretStore) {
        res.status(503).json({ error: "No secret store configured — set BAO_ADDR or KEY_VAULT_URI" });
        return;
      }
      const upstreamId = String(req.params.upstreamId ?? "");
      if (!repo.getUpstream(upstreamId)) {
        res.status(404).json({ error: `Unknown upstream "${upstreamId}"` });
        return;
      }
      const body = z
        .object({
          field: z.string().min(1).regex(/^[A-Za-z0-9_-]+$/),
          value: z.string().min(1),
        })
        .parse(req.body);

      const path = `gw-user-${principalSlug(principal)}-${upstreamId}`;
      await secretStore.put(path, body.field, body.value);
      const ref = secretStore.refFor(path, body.field);
      repo.upsertUserCredential(prefsIdentity(principal), upstreamId, body.field, ref);
      // Never echo the value.
      res.json({ ok: true, ref });
    })
  );

  router.delete(
    "/credentials/:upstreamId/:field",
    h((req, res) => {
      const removed = repo.deleteUserCredential(
        prefsIdentity(req.principal!),
        String(req.params.upstreamId ?? ""),
        String(req.params.field ?? "")
      );
      // The secret store copy is left for rotation-history; re-registering
      // overwrites it. (Store-side cleanup can come with sessionMode.)
      res.json({ ok: removed });
    })
  );

  return router;
}
