import { describe, expect, it } from "vitest";

import worker from "./index";
import {
  claudeCodeClientId,
  claudeCodeRedirectUri,
  codexClientId,
  codexRedirectUri,
  createMcpTestEnv,
  cursorClientId,
  cursorRedirectUri,
  jwtPayload,
  oauthActorEmail,
  oauthClientId,
  oauthClientSecret,
  oauthRedirectUri,
  oauthScope,
  requestAccessToken,
  requestAccessTokenResponse,
  requestPublicAuthorizationCodeAccessToken,
  requestPublicAuthorizationCodeToken,
  s256CodeChallenge,
} from "./mcp-test-helpers";

describe("MCP OAuth", () => {
  it("exposes OAuth metadata and issues client-credentials access tokens", async () => {
    const env = createMcpTestEnv();
    const authorizationMetadata = await worker.fetch(
      new Request("http://localhost:8787/.well-known/oauth-authorization-server"),
      env as never,
    );
    const resourceMetadata = await worker.fetch(
      new Request("http://localhost:8787/.well-known/oauth-protected-resource"),
      env as never,
    );
    const token = await requestAccessToken(env);

    expect(authorizationMetadata.status).toBe(200);
    await expect(authorizationMetadata.json()).resolves.toMatchObject({
      issuer: "http://localhost:8787",
      authorization_endpoint: "http://localhost:8787/oauth/authorize",
      token_endpoint: "http://localhost:8787/oauth/token",
      grant_types_supported: ["authorization_code", "client_credentials", "refresh_token"],
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

  it("supports one-time authorization-code exchange and refresh-token rotation", async () => {
    const env = createMcpTestEnv();
    const authorizeUrl = new URL("http://localhost:8787/oauth/authorize");
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", oauthClientId);
    authorizeUrl.searchParams.set("redirect_uri", oauthRedirectUri);
    authorizeUrl.searchParams.set("scope", oauthScope);
    authorizeUrl.searchParams.set("state", "state-123");

    const authorize = await worker.fetch(new Request(authorizeUrl), env as never);
    expect(authorize.status).toBe(302);

    const redirect = new URL(authorize.headers.get("Location") ?? "");
    expect(redirect.origin + redirect.pathname).toBe(oauthRedirectUri);
    expect(redirect.searchParams.get("state")).toBe("state-123");
    expect(redirect.searchParams.get("code")).toBeTypeOf("string");

    const token = await requestAccessTokenResponse(undefined, env, {
      grant_type: "authorization_code",
      code: redirect.searchParams.get("code") ?? "",
      redirect_uri: oauthRedirectUri,
    });
    expect(token.status).toBe(200);
    const body = (await token.json()) as { access_token?: string; refresh_token?: string };
    expect(body.access_token).toBeTypeOf("string");
    expect(body.refresh_token).toBeTypeOf("string");
    expect(jwtPayload(body.access_token as string)).toMatchObject({
      email: oauthActorEmail,
      sub: oauthClientId,
    });

    const replayedCode = await requestAccessTokenResponse(undefined, env, {
      grant_type: "authorization_code",
      code: redirect.searchParams.get("code") ?? "",
      redirect_uri: oauthRedirectUri,
    });
    expect(replayedCode.status).toBe(400);
    await expect(replayedCode.json()).resolves.toMatchObject({
      error: "invalid_grant",
    });

    const refreshed = await requestAccessTokenResponse(undefined, env, {
      grant_type: "refresh_token",
      refresh_token: body.refresh_token as string,
      resource: "http://localhost:8787/mcp",
    });
    expect(refreshed.status).toBe(200);
    const refreshedBody = (await refreshed.json()) as { access_token?: string; refresh_token?: string };
    expect(refreshedBody.access_token).toBeTypeOf("string");
    expect(refreshedBody.refresh_token).toBeTypeOf("string");
    expect(jwtPayload(refreshedBody.access_token as string)).toMatchObject({
      email: oauthActorEmail,
      sub: oauthClientId,
    });

    const replayedRefresh = await requestAccessTokenResponse(undefined, env, {
      grant_type: "refresh_token",
      refresh_token: body.refresh_token as string,
      resource: "http://localhost:8787/mcp",
    });
    expect(replayedRefresh.status).toBe(400);
    await expect(replayedRefresh.json()).resolves.toMatchObject({
      error: "invalid_grant",
    });
  });

  it("fails closed when user-bound OAuth is enabled without Glean OAuth or local identity", async () => {
    const authorizeUrl = new URL("http://localhost:8787/oauth/authorize");
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", codexClientId);
    authorizeUrl.searchParams.set("redirect_uri", codexRedirectUri);
    authorizeUrl.searchParams.set("scope", oauthScope);
    authorizeUrl.searchParams.set("code_challenge", await s256CodeChallenge("verifier"));
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    const response = await worker.fetch(
      new Request(authorizeUrl),
      createMcpTestEnv({
        MCP_OAUTH_LOCAL_BYPASS_EMAIL: undefined,
      }) as never,
    );

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "missing_glean_oauth",
      },
    });
  });

  it("redirects MCP authorization through Glean OAuth when no identity session exists", async () => {
    const authorizeUrl = new URL("https://mcp.example.test/oauth/authorize");
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", codexClientId);
    authorizeUrl.searchParams.set("redirect_uri", codexRedirectUri);
    authorizeUrl.searchParams.set("scope", oauthScope);
    authorizeUrl.searchParams.set("code_challenge", await s256CodeChallenge("verifier"));
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    const response = await worker.fetch(
      new Request(authorizeUrl),
      createMcpTestEnv({
        WORKER_ROLE: "mcp",
        MCP_BASE_URL: "https://mcp.example.test",
        MCP_OAUTH_LOCAL_BYPASS_EMAIL: undefined,
        ADMIN_SESSION_SECRET: "dev-admin-session-secret",
        GLEAN_OAUTH_AUTHORIZATION_URL: "https://glean.example.test/oauth/authorize",
        GLEAN_OAUTH_TOKEN_URL: "https://glean.example.test/oauth/token",
        GLEAN_OAUTH_USERINFO_URL: "https://glean.example.test/oauth/userinfo",
        GLEAN_OAUTH_CLIENT_ID: "html-sharing",
        GLEAN_OAUTH_CLIENT_SECRET: "secret",
      }) as never,
    );

    expect(response.status).toBe(302);
    const redirect = new URL(response.headers.get("Location") ?? "");
    expect(redirect.origin + redirect.pathname).toBe("https://glean.example.test/oauth/authorize");
    expect(redirect.searchParams.get("redirect_uri")).toBe("https://mcp.example.test/oauth/callback");
    expect(redirect.searchParams.get("code_challenge_method")).toBe("S256");
    expect(response.headers.get("Set-Cookie")).toContain("html_oauth_state=");
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
      createMcpTestEnv() as never,
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      token_type: "Bearer",
      expires_in: 3600,
      scope: oauthScope,
    });
  });

  it("supports public PKCE OAuth clients for Codex, Claude Code, and Cursor", async () => {
    const codexToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    const claudeCodeToken = await requestPublicAuthorizationCodeAccessToken(claudeCodeClientId, claudeCodeRedirectUri);
    const cursorToken = await requestPublicAuthorizationCodeAccessToken(cursorClientId, cursorRedirectUri);

    expect(codexToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(claudeCodeToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(cursorToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(jwtPayload(codexToken)).toMatchObject({
      email: oauthActorEmail,
      sub: codexClientId,
    });
    expect(jwtPayload(claudeCodeToken)).toMatchObject({
      email: oauthActorEmail,
      sub: claudeCodeClientId,
    });
    expect(jwtPayload(cursorToken)).toMatchObject({
      email: oauthActorEmail,
      sub: cursorClientId,
    });
  });

  it("refreshes public PKCE OAuth clients without a client secret", async () => {
    const env = createMcpTestEnv();
    const codexToken = await requestPublicAuthorizationCodeToken(codexClientId, codexRedirectUri, env);
    expect(codexToken.refresh_token).toBeTypeOf("string");

    const refreshed = await worker.fetch(
      new Request("http://localhost:8787/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          client_id: codexClientId,
          refresh_token: codexToken.refresh_token as string,
          resource: "http://localhost:8787/mcp",
        }),
      }),
      env as never,
    );
    expect(refreshed.status).toBe(200);
    const refreshedBody = (await refreshed.json()) as { access_token?: string; refresh_token?: string };
    expect(refreshedBody.access_token).toBeTypeOf("string");
    expect(refreshedBody.refresh_token).toBeTypeOf("string");
    expect(jwtPayload(refreshedBody.access_token as string)).toMatchObject({
      email: oauthActorEmail,
      sub: codexClientId,
    });
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
      createMcpTestEnv() as never,
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

    const response = await worker.fetch(new Request(authorizeUrl), createMcpTestEnv() as never);
    expect(response.status).toBe(302);

    const redirect = new URL(response.headers.get("Location") ?? "");
    expect(redirect.searchParams.get("error")).toBe("invalid_request");
    expect(redirect.searchParams.get("error_description")).toBe("code_challenge is required");
  });

  it("fails closed when configured OAuth redirect URIs are not HTTPS", async () => {
    const response = await worker.fetch(
      new Request("http://localhost:8787/oauth/authorize?response_type=code&client_id=dev-oauth-client"),
      createMcpTestEnv({
        MCP_OAUTH_ALLOWED_REDIRECT_URIS: "http://oauth-client.example.test/tools/oauth/callback",
      }) as never,
    );

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_mcp_oauth_allowed_redirect_uris",
      },
    });
  });
});
