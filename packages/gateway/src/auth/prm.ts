/**
 * RFC 9728 Protected Resource Metadata + WWW-Authenticate discovery, per the
 * MCP authorization spec: clients hitting 401 read the WWW-Authenticate
 * header, fetch the PRM document, and run the OAuth flow against the listed
 * authorization server.
 *
 * When the gateway hosts its own authorization server (the DCR facade —
 * enabled with interactive login), the PRM lists the gateway itself so
 * standard MCP clients can dynamically register; otherwise it lists the raw
 * IdP (which works only for clients with a pre-provisioned client id). PRM
 * affects DISCOVERY only — direct IdP bearers stay accepted either way.
 */

export const PRM_PATH = "/.well-known/oauth-protected-resource";

export interface PrmDocument {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
  scopes_supported?: string[];
}

export function prmDocument(publicUrl: string, authorizationServers: string[]): PrmDocument {
  return {
    resource: `${publicUrl}/mcp`,
    authorization_servers: authorizationServers,
    bearer_methods_supported: ["header"],
  };
}

/** Value for the WWW-Authenticate header on 401 responses. */
export function wwwAuthenticate(publicUrl: string): string {
  return `Bearer resource_metadata="${publicUrl}${PRM_PATH}"`;
}
