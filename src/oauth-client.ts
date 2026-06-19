import { constantTimeEqual, fromUtf8 } from "./encoding";
import type { McpOAuthClient, McpOAuthConfig, McpOAuthTokenConfig } from "./oauth-config";

export interface OAuthClientCredentials {
  clientId: string;
  clientSecret?: string;
}

export function parseClientCredentials(request: Request, form: URLSearchParams): OAuthClientCredentials | null {
  const basicCredentials = parseBasicClientCredentials(request.headers.get("Authorization"));
  if (basicCredentials) {
    return basicCredentials;
  }

  const clientId = form.get("client_id");
  const clientSecret = form.get("client_secret");
  return clientId ? { clientId, ...(clientSecret ? { clientSecret } : {}) } : null;
}

export function configuredOAuthClient(
  clientId: string,
  config: Pick<McpOAuthConfig, "clients">,
): McpOAuthClient | null {
  return config.clients.find((client) => constantTimeEqual(client.clientId, clientId)) ?? null;
}

export function isValidOAuthClient(
  client: OAuthClientCredentials,
  config: Pick<McpOAuthConfig, "clients">,
): boolean {
  const configured = configuredOAuthClient(client.clientId, config);
  if (!configured) {
    return false;
  }

  if (configured.kind === "public") {
    return client.clientSecret === undefined;
  }

  return client.clientSecret !== undefined && constantTimeEqual(client.clientSecret, configured.clientSecret);
}

export function isValidOAuthClientId(clientId: string, config: Pick<McpOAuthConfig, "clients">): boolean {
  return configuredOAuthClient(clientId, config) !== null;
}

export function isValidAccessTokenClientId(clientId: string, config: Pick<McpOAuthTokenConfig, "clientIds">): boolean {
  return config.clientIds.some((configuredClientId) => constantTimeEqual(clientId, configuredClientId));
}

function parseBasicClientCredentials(authorization: string | null): OAuthClientCredentials | null {
  if (!authorization?.startsWith("Basic ")) {
    return null;
  }

  try {
    const decoded = fromUtf8(base64ToBytes(authorization.slice("Basic ".length)));
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex === -1) {
      return null;
    }

    return {
      clientId: decodeClientCredential(decoded.slice(0, separatorIndex)),
      clientSecret: decodeClientCredential(decoded.slice(separatorIndex + 1)),
    };
  } catch {
    return null;
  }
}

function decodeClientCredential(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}
