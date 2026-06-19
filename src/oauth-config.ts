import { HttpError } from "./http";
import { isLocalDevelopmentRequest } from "./origin-policy";

export interface McpOAuthEnv {
  MCP_BASE_URL?: string;
  MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS?: string;
  MCP_OAUTH_ACCESS_AUD?: string;
  MCP_OAUTH_ACCESS_TEAM_DOMAIN?: string;
  MCP_OAUTH_ALLOWED_REDIRECT_URIS?: string;
  MCP_OAUTH_ALLOWED_EMAIL_DOMAIN?: string;
  MCP_OAUTH_CLIENT_ID?: string;
  MCP_OAUTH_CLIENT_SECRET?: string;
  MCP_OAUTH_LOCAL_BYPASS_EMAIL?: string;
  MCP_OAUTH_PUBLIC_CLIENT_IDS?: string;
  MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS?: string;
  MCP_OAUTH_REQUIRE_USER_AUTH?: string;
  MCP_OAUTH_SCOPES?: string;
  MCP_OAUTH_TOKEN_SECRET?: string;
  PUBLISH_ACCESS_AUD?: string;
  PUBLISH_ACCESS_TEAM_DOMAIN?: string;
  PUBLISHER_EMAIL_DOMAIN?: string;
}

export type McpOAuthClient =
  | {
      clientId: string;
      kind: "confidential";
      clientSecret: string;
    }
  | {
      clientId: string;
      kind: "public";
    };

export interface McpOAuthPublicConfig {
  defaultScope: string;
  issuer: string;
  resource: string;
  scopes: string[];
}

export interface McpOAuthConfig extends McpOAuthPublicConfig {
  accessTokenTtlSeconds: number;
  allowedRedirectUris: string[];
  clients: McpOAuthClient[];
  refreshTokenTtlSeconds: number;
  tokenSecret: string;
}

export interface McpOAuthTokenConfig extends McpOAuthPublicConfig {
  clientIds: string[];
  tokenSecret: string;
}

const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const DEFAULT_SCOPE = "mcp:tools";
const MAX_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;
const MAX_REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60;
const CURSOR_MCP_REDIRECT_URI = "cursor://anysphere.cursor-mcp/oauth/callback";

export function mcpOAuthPublicConfig(request: Request, env: McpOAuthEnv): McpOAuthPublicConfig {
  const issuer = oauthIssuer(request, env);
  const scopes = configuredScopes(env);
  return {
    defaultScope: scopes[0],
    issuer,
    resource: new URL("/mcp", issuer).toString(),
    scopes,
  };
}

export function mcpOAuthConfig(request: Request, env: McpOAuthEnv): McpOAuthConfig {
  return {
    ...mcpOAuthTokenConfig(request, env),
    accessTokenTtlSeconds: accessTokenTtlSeconds(env),
    allowedRedirectUris: allowedRedirectUris(env),
    clients: configuredClients(env),
    refreshTokenTtlSeconds: refreshTokenTtlSeconds(env),
  };
}

export function mcpOAuthTokenConfig(request: Request, env: McpOAuthEnv): McpOAuthTokenConfig {
  const clients = configuredClients(env);
  return {
    ...mcpOAuthPublicConfig(request, env),
    clientIds: clients.map((client) => client.clientId),
    tokenSecret: requiredEnv(env.MCP_OAUTH_TOKEN_SECRET, "MCP_OAUTH_TOKEN_SECRET"),
  };
}

export function requestedScope(value: string | null, config: McpOAuthPublicConfig): string | null {
  if (!value || value.trim() === "") {
    return config.defaultScope;
  }

  const requestedScopes = uniqueList(value.trim().split(/\s+/));
  return requestedScopes.every((scope) => config.scopes.includes(scope)) ? requestedScopes.join(" ") : null;
}

export function scopeErrorDescription(config: McpOAuthPublicConfig): string {
  return `Supported OAuth scopes: ${config.scopes.join(" ")}`;
}

export function accessTokenHasSupportedScope(scope: string, config: McpOAuthPublicConfig): boolean {
  const tokenScopes = new Set(scope.trim().split(/\s+/).filter(Boolean));
  return config.scopes.some((supportedScope) => tokenScopes.has(supportedScope));
}

export function validatedRedirectUri(value: string | null, config: McpOAuthConfig): string | null {
  if (!value) {
    return null;
  }

  let redirectUri: URL;
  try {
    redirectUri = new URL(value);
  } catch {
    throw new HttpError(400, "invalid_request", "redirect_uri must be a valid URL");
  }

  if (!isAllowedRedirectProtocol(redirectUri)) {
    throw new HttpError(
      400,
      "invalid_request",
      "redirect_uri must be HTTPS, loopback HTTP, or Cursor's MCP callback URI",
    );
  }

  if (!isAllowedRedirectUri(redirectUri, config.allowedRedirectUris)) {
    throw new HttpError(400, "invalid_request", "redirect_uri is not allowed");
  }

  return redirectUri.toString();
}

function oauthIssuer(request: Request, env: McpOAuthEnv): string {
  return baseUrl(request, env).origin;
}

function baseUrl(request: Request, env: McpOAuthEnv): URL {
  const requestUrl = new URL(request.url);
  if (isLocalDevelopmentRequest(request, requestUrl)) {
    return new URL(requestUrl.origin);
  }

  if (!env.MCP_BASE_URL) {
    throw new HttpError(500, "missing_mcp_base_url", "MCP_BASE_URL is not configured");
  }

  try {
    return new URL(env.MCP_BASE_URL);
  } catch {
    throw new HttpError(500, "invalid_mcp_base_url", "MCP_BASE_URL is not a valid URL");
  }
}

function configuredScopes(env: Pick<McpOAuthEnv, "MCP_OAUTH_SCOPES">): string[] {
  if (!env.MCP_OAUTH_SCOPES) {
    return [DEFAULT_SCOPE];
  }

  const scopes = uniqueList(env.MCP_OAUTH_SCOPES.trim().split(/[\s,]+/).filter(Boolean));
  if (scopes.length === 0) {
    throw new HttpError(500, "invalid_mcp_oauth_scopes", "MCP_OAUTH_SCOPES must include at least one scope");
  }

  for (const scope of scopes) {
    if (!/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) {
      throw new HttpError(500, "invalid_mcp_oauth_scopes", "MCP_OAUTH_SCOPES contains an invalid scope value");
    }
  }

  return scopes;
}

function configuredClients(
  env: Pick<McpOAuthEnv, "MCP_OAUTH_CLIENT_ID" | "MCP_OAUTH_CLIENT_SECRET" | "MCP_OAUTH_PUBLIC_CLIENT_IDS">,
): McpOAuthClient[] {
  const clients: McpOAuthClient[] = [];
  if (env.MCP_OAUTH_CLIENT_ID || env.MCP_OAUTH_CLIENT_SECRET) {
    clients.push({
      clientId: requiredEnv(env.MCP_OAUTH_CLIENT_ID, "MCP_OAUTH_CLIENT_ID"),
      kind: "confidential",
      clientSecret: requiredEnv(env.MCP_OAUTH_CLIENT_SECRET, "MCP_OAUTH_CLIENT_SECRET"),
    });
  }

  for (const clientId of parseConfiguredList(env.MCP_OAUTH_PUBLIC_CLIENT_IDS, "MCP_OAUTH_PUBLIC_CLIENT_IDS")) {
    clients.push({
      clientId,
      kind: "public",
    });
  }

  const clientIds = uniqueList(clients.map((client) => client.clientId));
  if (clients.length === 0) {
    throw new HttpError(500, "missing_mcp_oauth_clients", "At least one MCP OAuth client is required");
  }

  if (clientIds.length !== clients.length) {
    throw new HttpError(500, "duplicate_mcp_oauth_client_id", "MCP OAuth client IDs must be unique");
  }

  return clients;
}

function allowedRedirectUris(env: Pick<McpOAuthEnv, "MCP_OAUTH_ALLOWED_REDIRECT_URIS">): string[] {
  const values = parseConfiguredList(env.MCP_OAUTH_ALLOWED_REDIRECT_URIS, "MCP_OAUTH_ALLOWED_REDIRECT_URIS");
  const uris = uniqueList(values.map((value) => normalizeRedirectUri(value)));
  if (uris.length === 0) {
    throw new HttpError(
      500,
      "missing_mcp_oauth_allowed_redirect_uris",
      "MCP_OAUTH_ALLOWED_REDIRECT_URIS is not configured",
    );
  }

  return uris;
}

function parseConfiguredList(value: string | undefined, name: string): string[] {
  if (!value || value.trim() === "") {
    return [];
  }

  const trimmed = value.trim();
  if (trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
        throw new Error("Expected a string array");
      }

      return parsed;
    } catch {
      throw new HttpError(500, `invalid_${name.toLowerCase()}`, `${name} must be a JSON string array`);
    }
  }

  return trimmed.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

function normalizeRedirectUri(value: string): string {
  let redirectUri: URL;
  try {
    redirectUri = new URL(value);
  } catch {
    throw new HttpError(500, "invalid_mcp_oauth_allowed_redirect_uris", "Configured redirect URI is not valid");
  }

  if (!isAllowedRedirectProtocol(redirectUri)) {
    throw new HttpError(
      500,
      "invalid_mcp_oauth_allowed_redirect_uris",
      "Configured redirect URI must be HTTPS unless it uses loopback HTTP or Cursor's MCP callback URI",
    );
  }

  return redirectUri.toString();
}

function accessTokenTtlSeconds(env: Pick<McpOAuthEnv, "MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS">): number {
  if (!env.MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS) {
    return DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
  }

  const value = Number(env.MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS);
  if (!Number.isInteger(value) || value < 60 || value > MAX_ACCESS_TOKEN_TTL_SECONDS) {
    throw new HttpError(
      500,
      "invalid_mcp_oauth_access_token_ttl_seconds",
      "MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS must be between 60 and 86400",
    );
  }

  return value;
}

function refreshTokenTtlSeconds(env: Pick<McpOAuthEnv, "MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS">): number {
  if (!env.MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS) {
    return DEFAULT_REFRESH_TOKEN_TTL_SECONDS;
  }

  const value = Number(env.MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS);
  if (!Number.isInteger(value) || value < 3600 || value > MAX_REFRESH_TOKEN_TTL_SECONDS) {
    throw new HttpError(
      500,
      "invalid_mcp_oauth_refresh_token_ttl_seconds",
      "MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS must be between 3600 and 7776000",
    );
  }

  return value;
}

function requiredEnv(value: string | undefined, name: string): string {
  if (!value) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, `${name} is not configured`);
  }

  return value;
}

function uniqueList(values: string[]): string[] {
  return [...new Set(values)];
}

function isAllowedRedirectProtocol(redirectUri: URL): boolean {
  return (
    redirectUri.protocol === "https:" ||
    isLoopbackHost(redirectUri.hostname) ||
    isCursorMcpRedirectUri(redirectUri)
  );
}

function isCursorMcpRedirectUri(redirectUri: URL): boolean {
  return redirectUri.toString() === CURSOR_MCP_REDIRECT_URI;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

function isAllowedRedirectUri(redirectUri: URL, allowedRedirectUris: string[]): boolean {
  return allowedRedirectUris.some((allowedValue) => {
    if (redirectUri.toString() === allowedValue) {
      return true;
    }

    const allowedUrl = new URL(allowedValue);
    if (!isLoopbackHost(redirectUri.hostname) || !isLoopbackHost(allowedUrl.hostname)) {
      return false;
    }

    if (redirectUri.protocol !== allowedUrl.protocol || redirectUri.host !== allowedUrl.host) {
      return false;
    }

    if (allowedUrl.search || allowedUrl.hash) {
      return false;
    }

    const allowedPathPrefix = allowedUrl.pathname.endsWith("/") ? allowedUrl.pathname : `${allowedUrl.pathname}/`;
    return redirectUri.pathname.startsWith(allowedPathPrefix);
  });
}
