import { MCP_GLEAN_OAUTH_FLOW, completeGleanOAuthLogin, startGleanOAuthLogin } from "./auth/glean-oauth";
import { readIdentitySession, requireAllowedOAuthUser } from "./auth/session";
import { HttpError, jsonResponse } from "./http";
import { d1OAuthGrantStore, type OAuthGrantStore } from "./oauth-grants";
import {
  configuredOAuthClient,
  isValidOAuthClient,
  isValidOAuthClientId,
  parseClientCredentials,
} from "./oauth-client";
import {
  mcpOAuthConfig,
  mcpOAuthPublicConfig,
  mcpOAuthTokenConfig,
  requestedScope,
  scopeErrorDescription,
  validatedRedirectUri,
  type McpOAuthConfig,
  type McpOAuthEnv,
  type McpOAuthPublicConfig,
} from "./oauth-config";
import {
  exchangeRefreshTokenGrant,
  exchangeAuthorizationCodeGrant,
  issueAccessToken,
  issueAuthorizationCode,
  issueRefreshToken,
  parseCodeChallengeMethod,
  verifyAccessToken,
} from "./oauth-token";
import { isLocalDevelopmentRequest } from "./origin-policy";

export type { McpOAuthEnv } from "./oauth-config";

export interface McpOAuthAccessContext {
  actorEmail?: string;
  clientId: string;
}

type OAuthGrantType = "authorization_code" | "client_credentials" | "refresh_token";

type AuthorizeActorResult =
  | {
      actorEmail?: string;
    }
  | {
      response: Response;
    };

type TokenGrant =
  | {
      valid: true;
      actorEmail?: string;
      issueRefreshToken: boolean;
      refreshToken?: string;
      scope: string;
    }
  | {
      valid: false;
      description: string;
      error: string;
      headers?: HeadersInit;
      status: number;
    };

export function handleOAuthAuthorizationServerMetadata(request: Request, env: McpOAuthEnv): Response {
  const config = mcpOAuthPublicConfig(request, env);

  return jsonResponse({
    issuer: config.issuer,
    authorization_endpoint: new URL("/oauth/authorize", config.issuer).toString(),
    token_endpoint: new URL("/oauth/token", config.issuer).toString(),
    grant_types_supported: ["authorization_code", "client_credentials", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    scopes_supported: config.scopes,
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
  });
}

export function handleOAuthProtectedResourceMetadata(request: Request, env: McpOAuthEnv): Response {
  const config = mcpOAuthPublicConfig(request, env);

  return jsonResponse({
    resource: config.resource,
    authorization_servers: [config.issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: config.scopes,
  });
}

export async function handleOAuthAuthorizeRequest(request: Request, env: McpOAuthEnv): Promise<Response> {
  const config = mcpOAuthConfig(request, env);
  const grantStore = d1OAuthGrantStore(env);
  const requestUrl = new URL(request.url);
  const responseType = requestUrl.searchParams.get("response_type");
  if (responseType !== "code") {
    return oauthErrorResponse(400, "unsupported_response_type", "Only code response_type is supported");
  }

  const clientId = requestUrl.searchParams.get("client_id");
  if (!clientId || !isValidOAuthClientId(clientId, config)) {
    return oauthErrorResponse(400, "invalid_client", "Invalid OAuth client_id");
  }
  const oauthClient = configuredOAuthClient(clientId, config);

  const redirectUri = validatedRedirectUri(requestUrl.searchParams.get("redirect_uri"), config);
  if (!redirectUri) {
    return oauthErrorResponse(400, "invalid_request", "redirect_uri is required");
  }

  const scope = requestedScope(requestUrl.searchParams.get("scope"), config);
  if (!scope) {
    return redirectWithOAuthError(redirectUri, "invalid_scope", scopeErrorDescription(config), requestUrl);
  }

  const codeChallenge = optionalQueryString(requestUrl.searchParams.get("code_challenge"));
  const codeChallengeMethod = parseCodeChallengeMethod(requestUrl.searchParams.get("code_challenge_method"));
  if (!codeChallenge && oauthClient?.kind === "public") {
    return redirectWithOAuthError(redirectUri, "invalid_request", "code_challenge is required", requestUrl);
  }

  if (codeChallengeMethod !== "S256" && oauthClient?.kind === "public") {
    return redirectWithOAuthError(redirectUri, "invalid_request", "code_challenge_method must be S256", requestUrl);
  }

  if ((codeChallenge || requestUrl.searchParams.has("code_challenge_method")) && !codeChallengeMethod) {
    return redirectWithOAuthError(
      redirectUri,
      "invalid_request",
      "code_challenge_method must be S256",
      requestUrl,
    );
  }

  const actor = await authorizeActorEmail(request, env);
  if ("response" in actor) {
    return actor.response;
  }

  const code = await issueAuthorizationCode(config, grantStore, {
    clientId,
    redirectUri,
    scope,
    ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
    ...(codeChallenge ? { codeChallenge, codeChallengeMethod: codeChallengeMethod ?? "plain" } : {}),
  });

  return redirectWithCode(redirectUri, code, requestUrl);
}

export function handleOAuthCallbackRequest(request: Request, env: McpOAuthEnv): Promise<Response> {
  return completeGleanOAuthLogin(request, env, MCP_GLEAN_OAUTH_FLOW);
}

export async function handleOAuthTokenRequest(request: Request, env: McpOAuthEnv): Promise<Response> {
  const config = mcpOAuthConfig(request, env);
  const grantStore = d1OAuthGrantStore(env);
  const form = await readFormBody(request);
  const grantType = parseGrantType(form.get("grant_type"));
  if (!grantType) {
    return oauthErrorResponse(
      400,
      "unsupported_grant_type",
      "Only authorization_code, client_credentials, and refresh_token are supported",
    );
  }

  const client = parseClientCredentials(request, form);
  if (!client) {
    return oauthErrorResponse(401, "invalid_client", "Missing OAuth client credentials", {
      "WWW-Authenticate": 'Basic realm="html-sharing-oauth"',
    });
  }

  if (!isValidOAuthClient(client, config)) {
    return oauthErrorResponse(401, "invalid_client", "Invalid OAuth client credentials", {
      "WWW-Authenticate": 'Basic realm="html-sharing-oauth", error="invalid_client"',
    });
  }

  const grant = await resolveTokenGrant(config, grantStore, form, grantType, client.clientId);
  if (!grant.valid) {
    return oauthErrorResponse(grant.status, grant.error, grant.description, grant.headers);
  }

  return jsonResponse({
    access_token: await issueAccessToken(config, client.clientId, grant.scope, grant.actorEmail),
    token_type: "Bearer",
    expires_in: config.accessTokenTtlSeconds,
    scope: grant.scope,
    ...(grant.issueRefreshToken && grant.refreshToken ? { refresh_token: grant.refreshToken } : {}),
  });
}

export async function requireMcpOAuthAccessToken(request: Request, env: McpOAuthEnv): Promise<McpOAuthAccessContext> {
  const config = mcpOAuthTokenConfig(request, env);
  const authorization = request.headers.get("Authorization");
  const prefix = "Bearer ";
  if (!authorization?.startsWith(prefix)) {
    throw new HttpError(401, "unauthorized", "Missing OAuth bearer token", {
      headers: mcpBearerChallenge(config),
    });
  }

  const token = authorization.slice(prefix.length).trim();
  const result = await verifyAccessToken(token, config);
  if (!result.valid) {
    throw new HttpError(401, "invalid_token", result.message, {
      headers: mcpBearerChallenge(config, "invalid_token"),
    });
  }

  return {
    clientId: result.clientId,
    ...(result.actorEmail ? { actorEmail: result.actorEmail } : {}),
  };
}

async function readFormBody(request: Request): Promise<URLSearchParams> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
    throw new HttpError(400, "invalid_request", "OAuth token requests must be form encoded");
  }

  return new URLSearchParams(await request.text());
}

async function resolveTokenGrant(
  config: McpOAuthConfig,
  grantStore: OAuthGrantStore,
  form: URLSearchParams,
  grantType: OAuthGrantType,
  clientId: string,
): Promise<TokenGrant> {
  const requestedResource = form.get("resource");
  if (requestedResource && requestedResource !== config.resource) {
    return invalidTokenGrant(400, "invalid_target", "Requested resource is not this MCP server");
  }

  switch (grantType) {
    case "client_credentials": {
      const oauthClient = configuredOAuthClient(clientId, config);
      if (oauthClient?.kind === "public") {
        return invalidTokenGrant(400, "unauthorized_client", "Public clients cannot use client_credentials");
      }

      const scope = requestedScope(form.get("scope"), config);
      return scope
        ? { valid: true, issueRefreshToken: false, scope }
        : invalidTokenGrant(400, "invalid_scope", scopeErrorDescription(config));
    }
    case "authorization_code": {
      const codeGrant = await exchangeAuthorizationCodeGrant(config, grantStore, form, clientId);
      if (!codeGrant.valid) {
        return invalidTokenGrant(400, codeGrant.error, codeGrant.description);
      }

      const refreshToken = await issueRefreshToken(
        config,
        grantStore,
        clientId,
        codeGrant.scope,
        codeGrant.actorEmail,
      );
      return {
        valid: true,
        issueRefreshToken: true,
        scope: codeGrant.scope,
        refreshToken: refreshToken.token,
        ...(codeGrant.actorEmail ? { actorEmail: codeGrant.actorEmail } : {}),
      };
    }
    case "refresh_token": {
      const refreshGrant = await exchangeRefreshTokenGrant(config, grantStore, form, clientId);
      return refreshGrant.valid
        ? {
            valid: true,
            issueRefreshToken: true,
            scope: refreshGrant.scope,
            refreshToken: refreshGrant.refreshToken,
            ...(refreshGrant.actorEmail ? { actorEmail: refreshGrant.actorEmail } : {}),
          }
        : invalidTokenGrant(400, refreshGrant.error, refreshGrant.description);
    }
  }
}

function parseGrantType(value: string | null): OAuthGrantType | null {
  return value === "client_credentials" || value === "authorization_code" || value === "refresh_token" ? value : null;
}

function invalidTokenGrant(
  status: number,
  error: string,
  description: string,
  headers?: HeadersInit,
): TokenGrant {
  return {
    valid: false,
    status,
    error,
    description,
    ...(headers ? { headers } : {}),
  };
}

function optionalQueryString(value: string | null): string | undefined {
  return value && value.trim() !== "" ? value : undefined;
}

function mcpBearerChallenge(config: McpOAuthPublicConfig, error?: string): HeadersInit {
  const metadataUrl = new URL("/.well-known/oauth-protected-resource", config.issuer).toString();
  const params = [`resource_metadata="${metadataUrl}"`];
  if (error) {
    params.push(`error="${error}"`);
  }

  return {
    "WWW-Authenticate": `Bearer ${params.join(", ")}`,
  };
}

async function authorizeActorEmail(request: Request, env: McpOAuthEnv): Promise<AuthorizeActorResult> {
  if (!booleanEnv(env.MCP_OAUTH_REQUIRE_USER_AUTH)) {
    return {};
  }

  const requestUrl = new URL(request.url);
  if (isLocalDevelopmentRequest(request, requestUrl) && env.MCP_OAUTH_LOCAL_BYPASS_EMAIL) {
    return {
      actorEmail: requireAllowedOAuthUser(
        {
          email: normalizedEmail(env.MCP_OAUTH_LOCAL_BYPASS_EMAIL, "MCP_OAUTH_LOCAL_BYPASS_EMAIL"),
        },
        env,
      ).email,
    };
  }

  const session = await readIdentitySession(request, env, "oauth");
  if (session) {
    return {
      actorEmail: requireAllowedOAuthUser(session, env).email,
    };
  }

  if (!hasGleanOAuthConfig(env)) {
    throw new HttpError(500, "missing_glean_oauth", "Glean OAuth is not configured");
  }

  return {
    response: await startGleanOAuthLogin(
      request,
      env,
      MCP_GLEAN_OAUTH_FLOW,
      `${requestUrl.pathname}${requestUrl.search}`,
    ),
  };
}

function normalizedEmail(value: string, field: string): string {
  const email = value.trim().toLowerCase();
  if (!email.includes("@")) {
    throw new HttpError(403, `invalid_${field.toLowerCase()}`, `${field} must be an email address`);
  }

  return email;
}

function hasGleanOAuthConfig(env: McpOAuthEnv): boolean {
  return !!(
    hasText(env.GLEAN_OAUTH_CLIENT_ID) &&
    hasText(env.GLEAN_OAUTH_CLIENT_SECRET) &&
    (hasText(env.GLEAN_OAUTH_DISCOVERY_URL) ||
      hasText(env.GLEAN_OAUTH_ISSUER) ||
      (hasText(env.GLEAN_OAUTH_AUTHORIZATION_URL) && hasText(env.GLEAN_OAUTH_TOKEN_URL)))
  );
}

function hasText(value: string | undefined): boolean {
  return !!value?.trim();
}

function booleanEnv(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "true";
}

function oauthErrorResponse(
  status: number,
  error: string,
  errorDescription: string,
  headers: HeadersInit = {},
): Response {
  return jsonResponse(
    {
      error,
      error_description: errorDescription,
    },
    status,
    headers,
  );
}

function redirectWithCode(redirectUri: string, code: string, requestUrl: URL): Response {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  const state = requestUrl.searchParams.get("state");
  if (state) {
    redirect.searchParams.set("state", state);
  }

  return noStoreRedirect(redirect);
}

function redirectWithOAuthError(
  redirectUri: string,
  error: string,
  errorDescription: string,
  requestUrl: URL,
): Response {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set("error", error);
  redirect.searchParams.set("error_description", errorDescription);
  const state = requestUrl.searchParams.get("state");
  if (state) {
    redirect.searchParams.set("state", state);
  }

  return noStoreRedirect(redirect);
}

function noStoreRedirect(location: URL): Response {
  return new Response(null, {
    status: 302,
    headers: {
      Location: location.toString(),
      "Cache-Control": "no-store",
    },
  });
}
