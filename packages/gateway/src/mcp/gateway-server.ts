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
import type { Principal } from "../auth/principal.js";
import type { PolicyService } from "../domain/policy.js";
import type { UpstreamManager } from "../upstream/manager.js";

export const SERVER_NAME = "mspstack-gateway";
export const SERVER_VERSION = "0.1.0";

export function createGatewayServer(
  manager: UpstreamManager,
  policy: PolicyService,
  principal: Principal
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
    return manager.callTool(entry, request.params.arguments ?? {});
  });

  return server;
}
