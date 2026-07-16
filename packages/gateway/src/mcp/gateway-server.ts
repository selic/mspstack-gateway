/**
 * The MCP server gateway clients talk to. Uses the SDK's low-level Server
 * (not McpServer) because the tool list is dynamic: it changes with admin
 * toggles, upstream availability, and the caller's role.
 *
 * Two-layer enforcement: tools/list filtering is UX; the call-time policy
 * re-check is the security boundary. Both use the same PolicyService.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { prefsIdentity, type Principal } from "../auth/principal.js";
import type { PolicyService } from "../domain/policy.js";
import type { UpstreamManager } from "../upstream/manager.js";

export const SERVER_NAME = "mspstack-gateway";
export const SERVER_VERSION = "0.4.0";

/** Field→secretRef map of the principal's registered creds for an upstream. */
export type PersonalCredsLookup = (upstreamId: string) => Record<string, string>;

export function createGatewayServer(
  manager: UpstreamManager,
  policy: PolicyService,
  principal: Principal,
  personalCredsFor?: PersonalCredsLookup
): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: { listChanged: true } } }
  );

  // Envelope ∧ personal prefs — the same allowsFor gates list AND call, so
  // a user's own narrowing is enforced at the boundary, not just hidden in UX.
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: policy
      .visibleEntriesFor(principal, manager.catalogEntries())
      .map((entry) => ({ ...entry.tool, name: entry.exposedName })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const entry = manager.entryFor(request.params.name);
    if (!entry || !policy.allowsFor(principal, entry)) {
      // Same response for unknown and forbidden — no tool-existence oracle.
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text: `Tool "${request.params.name}" is not available to this session — it may not exist, be disabled, or require a higher role than "${principal.roleName}".`,
          },
        ],
      };
    }
    const args = request.params.arguments ?? {};

    // sessionMode:"per-user" — route the call over the caller's own
    // connection, with their registered credential refs layered onto the
    // spec (resolved server-side; the inbound token is never forwarded).
    const spec = manager.specFor(entry.upstreamId);
    if (spec?.sessionMode === "per-user") {
      const credentialRefs = personalCredsFor?.(entry.upstreamId) ?? {};
      if (Object.keys(credentialRefs).length > 0) {
        return manager.callTool(entry, args, {
          sessionKey: prefsIdentity(principal),
          credentialRefs,
        });
      }
      if (spec.requirePersonalCredentials) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: `Upstream "${entry.upstreamId}" requires personal credentials — register yours via the gateway's self-service (PUT /api/me/credentials/${entry.upstreamId}) and retry.`,
            },
          ],
        };
      }
      // No personal creds and fallback allowed → shared connection.
    }

    return manager.callTool(entry, args);
  });

  return server;
}
