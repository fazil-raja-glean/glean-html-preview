import { describe, expect, it, vi } from "vitest";

import worker from "./index";
import { testOrigins } from "./test-fixtures";

const oauthClientId = "dev-oauth-client";
const oauthClientSecret = "dev-oauth-secret";
const codexClientId = "codex-html-sharing-mcp";
const claudeCodeClientId = "claude-code-html-sharing-mcp";
const oauthRedirectUri = "https://oauth-client.example.test/tools/oauth/callback";
const codexRedirectUri = "http://127.0.0.1:5555/callback";
const claudeCodeRedirectUri = "http://localhost:5555/callback";
const oauthScope = "html-preview:publish";

const mcpEnv = {
  MCP_OAUTH_ALLOWED_REDIRECT_URIS: [
    oauthRedirectUri,
    "https://oauth-client.example.test/tools/oauth/alternate-callback",
    codexRedirectUri,
    claudeCodeRedirectUri,
  ].join("\n"),
  MCP_OAUTH_CLIENT_ID: oauthClientId,
  MCP_OAUTH_CLIENT_SECRET: oauthClientSecret,
  MCP_OAUTH_PUBLIC_CLIENT_IDS: `${codexClientId}\n${claudeCodeClientId}`,
  MCP_OAUTH_SCOPES: oauthScope,
  MCP_OAUTH_TOKEN_SECRET: "dev-token-signing-secret",
  MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS: "3600",
  API_BASE_URL: testOrigins.apiBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
  PUBLISH_API_TOKEN: "dev-publish-token",
  PUBLISH_INTERNAL_SERVICE_TOKEN: "internal-service-token",
};

describe("MCP endpoint", () => {
  it("exposes OAuth metadata and issues client-credentials access tokens", async () => {
    const authorizationMetadata = await worker.fetch(
      new Request("http://localhost:8787/.well-known/oauth-authorization-server"),
      mcpEnv as never,
    );
    const resourceMetadata = await worker.fetch(
      new Request("http://localhost:8787/.well-known/oauth-protected-resource"),
      mcpEnv as never,
    );
    const token = await requestAccessToken();

    expect(authorizationMetadata.status).toBe(200);
    await expect(authorizationMetadata.json()).resolves.toMatchObject({
      issuer: "http://localhost:8787",
      authorization_endpoint: "http://localhost:8787/oauth/authorize",
      token_endpoint: "http://localhost:8787/oauth/token",
      grant_types_supported: ["authorization_code", "client_credentials"],
      scopes_supported: [oauthScope],
    });

    expect(resourceMetadata.status).toBe(200);
    await expect(resourceMetadata.json()).resolves.toMatchObject({
      resource: "http://localhost:8787/mcp",
      authorization_servers: ["http://localhost:8787"],
      scopes_supported: [oauthScope],
    });

    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("supports OAuth authorization-code exchange for the Glean admin UI", async () => {
    const authorizeUrl = new URL("http://localhost:8787/oauth/authorize");
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", oauthClientId);
    authorizeUrl.searchParams.set("redirect_uri", oauthRedirectUri);
    authorizeUrl.searchParams.set("scope", oauthScope);
    authorizeUrl.searchParams.set("state", "state-123");

    const authorize = await worker.fetch(new Request(authorizeUrl), mcpEnv as never);
    expect(authorize.status).toBe(302);

    const redirect = new URL(authorize.headers.get("Location") ?? "");
    expect(redirect.origin + redirect.pathname).toBe(oauthRedirectUri);
    expect(redirect.searchParams.get("state")).toBe("state-123");
    expect(redirect.searchParams.get("code")).toBeTypeOf("string");

    const token = await requestAccessTokenResponse(undefined, {}, {
      grant_type: "authorization_code",
      code: redirect.searchParams.get("code") ?? "",
      redirect_uri: oauthRedirectUri,
    });
    expect(token.status).toBe(200);
    await expect(token.json()).resolves.toMatchObject({
      token_type: "Bearer",
      expires_in: 3600,
      scope: oauthScope,
    });
  });

  it("rejects wrong OAuth client credentials", async () => {
    const response = await requestAccessTokenResponse({
      clientId: "wrong",
      clientSecret: "wrong",
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: "invalid_client",
    });
  });

  it("accepts OAuth client_secret_post token requests for Glean setup", async () => {
    const response = await worker.fetch(
      new Request("http://localhost:8787/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: oauthClientId,
          client_secret: oauthClientSecret,
          scope: oauthScope,
        }),
      }),
      mcpEnv as never,
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      token_type: "Bearer",
      expires_in: 3600,
      scope: oauthScope,
    });
  });

  it("supports public PKCE OAuth clients for Codex and Claude Code", async () => {
    const codexToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    const claudeCodeToken = await requestPublicAuthorizationCodeAccessToken(claudeCodeClientId, claudeCodeRedirectUri);
    const initialized = await postMcp(authorizedRpc("initialize"), {
      Authorization: `Bearer ${codexToken}`,
    });

    expect(codexToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(claudeCodeToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(initialized.status).toBe(200);
  });

  it("does not let public OAuth clients use client credentials", async () => {
    const response = await worker.fetch(
      new Request("http://localhost:8787/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: codexClientId,
          scope: oauthScope,
        }),
      }),
      mcpEnv as never,
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: "unauthorized_client",
    });
  });

  it("requires S256 PKCE for public OAuth clients", async () => {
    const authorizeUrl = new URL("http://localhost:8787/oauth/authorize");
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", codexClientId);
    authorizeUrl.searchParams.set("redirect_uri", codexRedirectUri);
    authorizeUrl.searchParams.set("scope", oauthScope);

    const response = await worker.fetch(new Request(authorizeUrl), mcpEnv as never);
    expect(response.status).toBe(302);

    const redirect = new URL(response.headers.get("Location") ?? "");
    expect(redirect.searchParams.get("error")).toBe("invalid_request");
    expect(redirect.searchParams.get("error_description")).toBe("code_challenge is required");
  });

  it("fails closed when configured OAuth redirect URIs are not HTTPS", async () => {
    const response = await worker.fetch(
      new Request("http://localhost:8787/oauth/authorize?response_type=code&client_id=dev-oauth-client"),
      {
        ...mcpEnv,
        MCP_OAUTH_ALLOWED_REDIRECT_URIS: "http://oauth-client.example.test/tools/oauth/callback",
      } as never,
    );

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_mcp_oauth_allowed_redirect_uris",
      },
    });
  });

  it("requires an OAuth bearer token", async () => {
    const missing = await postMcp({ jsonrpc: "2.0", id: 1, method: "initialize" }, {});
    const invalid = await postMcp(
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      {
        Authorization: "Bearer wrong-token",
      },
    );

    expect(missing.status).toBe(401);
    expect(missing.headers.get("WWW-Authenticate")).toContain("/.well-known/oauth-protected-resource");
    await expect(missing.json()).resolves.toMatchObject({
      error: {
        code: "unauthorized",
      },
    });

    expect(invalid.status).toBe(401);
    expect(invalid.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
    await expect(invalid.json()).resolves.toMatchObject({
      error: {
        code: "invalid_token",
      },
    });
  });

  it("responds to initialize and lists the publish tool", async () => {
    const initialized = await postMcp(authorizedRpc("initialize"));
    const listed = await postMcp(authorizedRpc("tools/list"));

    expect(initialized.status).toBe(200);
    await expect(initialized.json()).resolves.toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: {
          tools: {
            listChanged: false,
          },
        },
        serverInfo: {
          name: "html-sharing",
        },
      },
    });

    expect(listed.status).toBe(200);
    await expect(listed.json()).resolves.toMatchObject({
      result: {
        tools: [
          {
            name: "publish_html_preview",
            inputSchema: {
              required: ["title", "html", "password"],
              properties: {
                password: {
                  minLength: 12,
                },
              },
            },
          },
        ],
      },
    });
  });

  it("publishes HTML by forwarding through the API Worker service binding with an internal token", async () => {
    let capturedRequest:
      | {
          url: string;
          method: string;
          headers: Headers;
          body: unknown;
        }
      | undefined;
    const upstreamFetch = vi.fn(async (request: Request) => {
      capturedRequest = {
        url: request.url,
        method: request.method,
        headers: request.headers,
        body: await request.clone().json(),
      };
      return new Response(
        JSON.stringify({
          url: `${mcpEnv.PUBLIC_BASE_URL}/p/abc123`,
          slug: "abc123",
          expiresAt: "2026-08-18T12:00:00.000Z",
          status: "active",
        }),
        {
          status: 201,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    });

    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
          sourceUrl: "https://source.example.test/artifacts/test",
        },
      }),
      undefined,
      {
        PUBLISH_API: {
          fetch: upstreamFetch,
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        content: [
          {
            type: "text",
            text: `Published HTML preview: ${mcpEnv.PUBLIC_BASE_URL}/p/abc123`,
          },
        ],
        structuredContent: {
          url: `${mcpEnv.PUBLIC_BASE_URL}/p/abc123`,
          slug: "abc123",
          status: "active",
        },
      },
    });

    expect(upstreamFetch).toHaveBeenCalledOnce();
    expect(capturedRequest?.url).toBe(`${mcpEnv.API_BASE_URL}/v1/html-previews`);
    expect(capturedRequest?.method).toBe("POST");
    expect(capturedRequest?.headers.get("Authorization")).toBe("Bearer dev-publish-token");
    expect(capturedRequest?.headers.get("X-Publish-Internal-Service-Token")).toBe("internal-service-token");
    expect(capturedRequest?.headers.get("CF-Access-Client-Id")).toBeNull();
    expect(capturedRequest?.headers.get("CF-Access-Client-Secret")).toBeNull();
    expect(capturedRequest?.body).toEqual({
      title: "Smoke Test",
      html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
      password: "correct horse battery",
      sourceUrl: "https://source.example.test/artifacts/test",
    });
  });

  it("returns tool errors without exposing internal credentials when the API rejects a publish", async () => {
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
        },
      }),
      undefined,
      {
        PUBLISH_API: {
          fetch: vi.fn(async () => {
            return new Response(
              JSON.stringify({
                error: {
                  code: "invalid_html",
                  message: "HTML must be a complete document with an html element",
                },
              }),
              {
                status: 400,
                headers: {
                  "Content-Type": "application/json",
                },
              },
            );
          }),
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      result: {
        isError: true,
        content: [
          {
            type: "text",
            text: "Publish failed: HTML must be a complete document with an html element",
          },
        ],
        structuredContent: {
          status: 400,
          error: "invalid_html",
        },
      },
    });
  });

  it("fails closed when the API Worker service binding is missing", async () => {
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
        },
      }),
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: -32603,
        message: "PUBLISH_API service binding is not configured",
      },
    });
  });
});

function authorizedRpc(method: string, params?: unknown): unknown {
  return {
    jsonrpc: "2.0",
    id: 1,
    method,
    ...(params === undefined ? {} : { params }),
  };
}

async function postMcp(
  body: unknown,
  headers?: Record<string, string>,
  envOverrides: Record<string, unknown> = {},
) {
  const env = {
    ...mcpEnv,
    ...envOverrides,
  };
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

async function oauthHeaders(env: Record<string, unknown>): Promise<Record<string, string>> {
  return {
    Authorization: `Bearer ${await requestAccessToken(env)}`,
  };
}

async function requestAccessToken(envOverrides: Record<string, unknown> = {}): Promise<string> {
  const response = await requestAccessTokenResponse(undefined, envOverrides);
  expect(response.status).toBe(200);
  const body = (await response.json()) as { access_token?: string };
  expect(body.access_token).toBeTypeOf("string");
  return body.access_token as string;
}

async function requestAccessTokenResponse(
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
    {
      ...mcpEnv,
      ...envOverrides,
    } as never,
  );
}

async function requestPublicAuthorizationCodeAccessToken(clientId: string, redirectUri: string): Promise<string> {
  const codeVerifier = `verifier-${clientId}`;
  const codeChallenge = await s256CodeChallenge(codeVerifier);
  const authorizeUrl = new URL("http://localhost:8787/oauth/authorize");
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", oauthScope);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  const authorize = await worker.fetch(new Request(authorizeUrl), mcpEnv as never);
  expect(authorize.status).toBe(302);

  const redirect = new URL(authorize.headers.get("Location") ?? "");
  expect(redirect.origin + redirect.pathname).toBe(redirectUri);
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
    mcpEnv as never,
  );
  expect(token.status).toBe(200);
  const body = (await token.json()) as { access_token?: string; scope?: string };
  expect(body.scope).toBe(oauthScope);
  expect(body.access_token).toBeTypeOf("string");
  return body.access_token as string;
}

async function s256CodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const bytes = new Uint8Array(digest);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
