import { requireCloudflareAccessUserEmail, type CloudflareAccessJwtConfig } from "./admin-auth";
import { HttpError, jsonResponse } from "./http";
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

  const code = await issueAuthorizationCode(config, {
    clientId,
    redirectUri,
    scope,
    actorEmail: await authorizeActorEmail(request, env),
    ...(codeChallenge ? { codeChallenge, codeChallengeMethod: codeChallengeMethod ?? "plain" } : {}),
  });

  return redirectWithCode(redirectUri, code, requestUrl);
}

export async function handleOAuthTokenRequest(request: Request, env: McpOAuthEnv): Promise<Response> {
  const config = mcpOAuthConfig(request, env);
  const form = await readFormBody(request);
  const grantType = form.get("grant_type");
  if (grantType !== "client_credentials" && grantType !== "authorization_code" && grantType !== "refresh_token") {
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
  const oauthClient = configuredOAuthClient(client.clientId, config);
  if (grantType === "client_credentials" && oauthClient?.kind === "public") {
    return oauthErrorResponse(400, "unauthorized_client", "Public clients cannot use client_credentials");
  }

  const codeResult =
    grantType === "authorization_code" ? await exchangeAuthorizationCodeGrant(config, form, client.clientId) : null;
  if (codeResult && !codeResult.valid) {
    return oauthErrorResponse(400, codeResult.error, codeResult.description);
  }

  const refreshResult =
    grantType === "refresh_token" ? await exchangeRefreshTokenGrant(config, form, client.clientId) : null;
  if (refreshResult && !refreshResult.valid) {
    return oauthErrorResponse(400, refreshResult.error, refreshResult.description);
  }

  const requestedResource = form.get("resource");
  if (requestedResource && requestedResource !== config.resource) {
    return oauthErrorResponse(400, "invalid_target", "Requested resource is not this MCP server");
  }

  const scope = codeResult?.scope ?? refreshResult?.scope ?? requestedScope(form.get("scope"), config);
  if (!scope) {
    return oauthErrorResponse(400, "invalid_scope", scopeErrorDescription(config));
  }

  const actorEmail = codeResult?.actorEmail ?? refreshResult?.actorEmail;
  return jsonResponse({
    access_token: await issueAccessToken(config, client.clientId, scope, actorEmail),
    token_type: "Bearer",
    expires_in: config.accessTokenTtlSeconds,
    scope,
    ...(grantType === "authorization_code" || grantType === "refresh_token"
      ? { refresh_token: await issueRefreshToken(config, client.clientId, scope, actorEmail) }
      : {}),
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

async function authorizeActorEmail(request: Request, env: McpOAuthEnv): Promise<string | undefined> {
  if (!booleanEnv(env.MCP_OAUTH_REQUIRE_USER_AUTH)) {
    return undefined;
  }

  const requestUrl = new URL(request.url);
  if (isLocalDevelopmentRequest(request, requestUrl) && env.MCP_OAUTH_LOCAL_BYPASS_EMAIL) {
    return normalizedAllowedEmail(env.MCP_OAUTH_LOCAL_BYPASS_EMAIL, env);
  }

  const email = await requireCloudflareAccessUserEmail(request, oauthAccessConfig(env));
  return normalizedAllowedEmail(email, env);
}

function oauthAccessConfig(env: McpOAuthEnv): CloudflareAccessJwtConfig {
  const teamDomain = env.MCP_OAUTH_ACCESS_TEAM_DOMAIN ?? env.PUBLISH_ACCESS_TEAM_DOMAIN;
  const audience = env.MCP_OAUTH_ACCESS_AUD ?? env.PUBLISH_ACCESS_AUD;
  if (!teamDomain || !audience) {
    throw new HttpError(
      500,
      "missing_mcp_oauth_user_auth",
      "MCP OAuth user authentication is not configured",
    );
  }

  return {
    teamDomain,
    audience,
  };
}

function normalizedAllowedEmail(value: string, env: McpOAuthEnv): string {
  const email = value.trim().toLowerCase();
  if (!email.includes("@")) {
    throw new HttpError(403, "invalid_access_email", "Cloudflare Access user email is invalid");
  }

  const domain = (env.MCP_OAUTH_ALLOWED_EMAIL_DOMAIN ?? env.PUBLISHER_EMAIL_DOMAIN)?.trim().toLowerCase();
  if (!domain) {
    throw new HttpError(500, "missing_mcp_oauth_email_domain", "MCP OAuth allowed email domain is not configured");
  }

  const suffix = `@${domain}`;
  if (!email.endsWith(suffix) || email.length <= suffix.length) {
    throw new HttpError(403, "access_email_forbidden", `Cloudflare Access user must be a ${suffix} user`);
  }

  return email;
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
