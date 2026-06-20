import { expect } from "vitest";

import worker from "./index";
import { createTestPreviewDb, testOrigins } from "./test-fixtures";

export const oauthClientId = "dev-oauth-client";
export const oauthClientSecret = "dev-oauth-secret";
export const codexClientId = "codex-html-sharing-mcp";
export const claudeCodeClientId = "claude-code-html-sharing-mcp";
export const cursorClientId = "cursor-html-sharing-mcp";
export const oauthRedirectUri = "https://oauth-client.example.test/tools/oauth/callback";
export const codexAllowedRedirectUri = "http://127.0.0.1:5555/callback";
export const codexRedirectUri = "http://127.0.0.1:5555/callback/UnEALRF1ZB92";
export const claudeCodeRedirectUri = "http://localhost:5555/callback";
export const cursorRedirectUri = "cursor://anysphere.cursor-mcp/oauth/callback";
export const oauthScope = "html-preview:publish";
export const oauthActorEmail = "publisher@example.com";

export function createMcpTestEnv(envOverrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    MCP_OAUTH_ALLOWED_REDIRECT_URIS: [
      oauthRedirectUri,
      "https://oauth-client.example.test/tools/oauth/alternate-callback",
      codexAllowedRedirectUri,
      claudeCodeRedirectUri,
      cursorRedirectUri,
    ].join("\n"),
    MCP_OAUTH_CLIENT_ID: oauthClientId,
    MCP_OAUTH_CLIENT_SECRET: oauthClientSecret,
    MCP_OAUTH_ALLOWED_EMAIL_DOMAIN: "example.com",
    MCP_OAUTH_LOCAL_BYPASS_EMAIL: "Publisher@Example.com",
    MCP_OAUTH_PUBLIC_CLIENT_IDS: `${codexClientId}\n${claudeCodeClientId}\n${cursorClientId}`,
    MCP_OAUTH_REQUIRE_USER_AUTH: "true",
    MCP_OAUTH_SCOPES: oauthScope,
    MCP_OAUTH_TOKEN_SECRET: "dev-token-signing-secret",
    MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS: "3600",
    PREVIEW_DB: createTestPreviewDb(),
    API_BASE_URL: testOrigins.apiBaseUrl,
    PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
    PUBLISH_API_TOKEN: "dev-publish-token",
    PUBLISH_INTERNAL_SERVICE_TOKEN: "internal-service-token",
    ...envOverrides,
  };
}

export function authorizedRpc(method: string, params?: unknown): unknown {
  return {
    jsonrpc: "2.0",
    id: 1,
    method,
    ...(params === undefined ? {} : { params }),
  };
}

export async function postMcp(
  body: unknown,
  headers?: Record<string, string>,
  envOverrides: Record<string, unknown> = {},
) {
  const env = createMcpTestEnv(envOverrides);
  const requestHeaders = headers === undefined ? await oauthHeaders(env) : headers;

  return worker.fetch(
    new Request("http://localhost:8787/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...requestHeaders,
      },
      body: JSON.stringify(body),
    }),
    env as never,
  );
}

export async function oauthHeaders(env: Record<string, unknown>): Promise<Record<string, string>> {
  return {
    Authorization: `Bearer ${await requestAccessToken(env)}`,
  };
}

export async function requestAccessToken(envOverrides: Record<string, unknown> = {}): Promise<string> {
  const response = await requestAccessTokenResponse(undefined, envOverrides);
  expect(response.status).toBe(200);
  const body = (await response.json()) as { access_token?: string };
  expect(body.access_token).toBeTypeOf("string");
  return body.access_token as string;
}

export async function requestAccessTokenResponse(
  credentials: { clientId: string; clientSecret: string } = {
    clientId: oauthClientId,
    clientSecret: oauthClientSecret,
  },
  envOverrides: Record<string, unknown> = {},
  form: Record<string, string> = {
    grant_type: "client_credentials",
    scope: oauthScope,
  },
): Promise<Response> {
  return worker.fetch(
    new Request("http://localhost:8787/oauth/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${btoa(`${credentials.clientId}:${credentials.clientSecret}`)}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(form),
    }),
    createMcpTestEnv(envOverrides) as never,
  );
}

export async function requestPublicAuthorizationCodeAccessToken(clientId: string, redirectUri: string): Promise<string> {
  const body = await requestPublicAuthorizationCodeToken(clientId, redirectUri);
  expect(body.access_token).toBeTypeOf("string");
  return body.access_token as string;
}

export async function requestPublicAuthorizationCodeToken(
  clientId: string,
  redirectUri: string,
  env: Record<string, unknown> = createMcpTestEnv(),
): Promise<{ access_token?: string; refresh_token?: string; scope?: string }> {
  const codeVerifier = `verifier-${clientId}`;
  const codeChallenge = await s256CodeChallenge(codeVerifier);
  const authorizeUrl = new URL("http://localhost:8787/oauth/authorize");
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", oauthScope);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  const authorize = await worker.fetch(new Request(authorizeUrl), env as never);
  expect(authorize.status).toBe(302);

  const redirect = new URL(authorize.headers.get("Location") ?? "");
  expect(redirect.toString().replace(/[?#].*$/, "")).toBe(redirectUri);
  expect(redirect.searchParams.get("error")).toBeNull();

  const token = await worker.fetch(
    new Request("http://localhost:8787/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        code: redirect.searchParams.get("code") ?? "",
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        resource: "http://localhost:8787/mcp",
      }),
    }),
    env as never,
  );
  expect(token.status).toBe(200);
  const body = (await token.json()) as { access_token?: string; refresh_token?: string; scope?: string };
  expect(body.scope).toBe(oauthScope);
  expect(body.access_token).toBeTypeOf("string");
  expect(body.refresh_token).toBeTypeOf("string");
  return body;
}

export function jwtPayload(token: string): Record<string, unknown> {
  const [, encodedPayload] = token.split(".");
  expect(encodedPayload).toBeTypeOf("string");
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(encodedPayload ?? ""))) as Record<string, unknown>;
}

export async function s256CodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const bytes = new Uint8Array(digest);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}
