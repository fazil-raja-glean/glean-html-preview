import { randomBase64Url, toBase64Url, utf8 } from "../encoding";
import { getCookie } from "../cookies";
import { HttpError, safeRelativePath } from "../http";
import {
  decodeJwt,
  jwtClaimsAreValid,
  parseRsaPublicJwks,
  verifyRs256JwtSignature,
  type RsaPublicJwk,
} from "../jwt";
import { isLocalDevelopmentRequest } from "../origin-policy";
import { ADMIN_OAUTH_CALLBACK_PATH, MCP_OAUTH_CALLBACK_PATH } from "../oauth-paths";
import { signToken, verifyToken } from "../signed-token";
import {
  ADMIN_GLEAN_OAUTH_SCOPES,
  getAdminDynamicOAuthClient,
  type GleanAdminDynamicOAuthEnv,
  type GleanOAuthProviderMetadata,
  type GleanTokenEndpointAuthMethod,
} from "./glean-admin-dcr";
import {
  type AuthenticatedGleanUser,
  type IdentitySessionEnv,
  type IdentitySessionKind,
  createIdentitySession,
  requireAllowedAdminUser,
  requireAllowedOAuthUser,
} from "./session";

export interface GleanOAuthEnv extends IdentitySessionEnv, GleanAdminDynamicOAuthEnv {
  API_BASE_URL?: string;
  GLEAN_OAUTH_AUTHORIZATION_URL?: string;
  GLEAN_OAUTH_CLIENT_ID?: string;
  GLEAN_OAUTH_CLIENT_SECRET?: string;
  GLEAN_OAUTH_DISCOVERY_URL?: string;
  GLEAN_OAUTH_ISSUER?: string;
  GLEAN_OAUTH_JWKS_URL?: string;
  GLEAN_OAUTH_REGISTRATION_URL?: string;
  GLEAN_OAUTH_SCOPES?: string;
  GLEAN_OAUTH_TOKEN_URL?: string;
  GLEAN_OAUTH_USERINFO_URL?: string;
  MCP_BASE_URL?: string;
}

export type GleanOAuthFlowKind = "admin" | "oauth";

export interface GleanOAuthFlow {
  callbackPath: string;
  kind: GleanOAuthFlowKind;
  sessionKind: IdentitySessionKind;
  stateCookieName: string;
  stateCookiePath: string;
}

interface GleanOAuthConfig {
  authorizationUrl: string;
  clientId: string;
  clientSecret?: string;
  issuer?: string;
  jwksUrl?: string;
  scopes: string;
  tokenEndpointAuthMethod: GleanTokenEndpointAuthMethod;
  tokenUrl: string;
  userinfoUrl?: string;
}

interface OAuthStatePayload {
  codeVerifier: string;
  exp: number;
  returnTo: string;
  state: string;
}

interface CachedGleanJwks {
  expiresAt: number;
  keys: RsaPublicJwk[];
}

const DEFAULT_GLEAN_OAUTH_SCOPES = ADMIN_GLEAN_OAUTH_SCOPES;
const GLEAN_JWKS_CACHE_MS = 10 * 60 * 1000;
const JWT_CLOCK_SKEW_SECONDS = 60;
const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const OAUTH_STATE_PURPOSE = "glean-oauth-state:v1";
const gleanJwksCache = new Map<string, CachedGleanJwks>();

export const ADMIN_GLEAN_OAUTH_FLOW: GleanOAuthFlow = {
  kind: "admin",
  sessionKind: "admin",
  callbackPath: ADMIN_OAUTH_CALLBACK_PATH,
  stateCookieName: "html_admin_oauth_state",
  stateCookiePath: stateCookiePathForCallback(ADMIN_OAUTH_CALLBACK_PATH),
};

export const MCP_GLEAN_OAUTH_FLOW: GleanOAuthFlow = {
  kind: "oauth",
  sessionKind: "oauth",
  callbackPath: MCP_OAUTH_CALLBACK_PATH,
  stateCookieName: "html_oauth_state",
  stateCookiePath: stateCookiePathForCallback(MCP_OAUTH_CALLBACK_PATH),
};

// The OAuth state cookie must be scoped so the browser sends it back to the callback.
// Deriving it from the callback's parent path keeps the two from drifting apart.
function stateCookiePathForCallback(callbackPath: string): string {
  return callbackPath.slice(0, callbackPath.lastIndexOf("/")) || "/";
}

export async function startGleanOAuthLogin(
  request: Request,
  env: GleanOAuthEnv,
  flow: GleanOAuthFlow,
  returnTo: string,
): Promise<Response> {
  const callbackUrl = callbackUrlForFlow(request, env, flow);
  const config = await gleanOAuthConfig(env, flow, callbackUrl);
  const state = randomBase64Url(24);
  const codeVerifier = randomBase64Url(48);
  const codeChallenge = await s256CodeChallenge(codeVerifier);
  const authorizationUrl = new URL(config.authorizationUrl);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("redirect_uri", callbackUrl);
  authorizationUrl.searchParams.set("scope", config.scopes);
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");

  const stateCookie = await signToken(
    {
      state,
      codeVerifier,
      returnTo: safeRelativePath(returnTo, "/"),
      exp: Math.floor(Date.now() / 1000) + OAUTH_STATE_TTL_SECONDS,
    } satisfies OAuthStatePayload,
    oauthStateSecret(env),
    statePurpose(flow),
  );

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizationUrl.toString(),
      "Set-Cookie": [
        `${flow.stateCookieName}=${stateCookie}`,
        `Path=${flow.stateCookiePath}`,
        `Max-Age=${OAUTH_STATE_TTL_SECONDS}`,
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
      ].join("; "),
      "Cache-Control": "no-store",
    },
  });
}

export async function completeGleanOAuthLogin(
  request: Request,
  env: GleanOAuthEnv,
  flow: GleanOAuthFlow,
): Promise<Response> {
  const requestUrl = new URL(request.url);
  const state = requestUrl.searchParams.get("state");
  const code = requestUrl.searchParams.get("code");
  const oauthError = requestUrl.searchParams.get("error");
  if (oauthError) {
    throw new HttpError(401, "glean_oauth_denied", "Glean OAuth login was denied");
  }
  if (!state || !code) {
    throw new HttpError(400, "invalid_oauth_callback", "Glean OAuth callback is missing state or code");
  }

  const storedState = await readOAuthState(request, env, flow);
  if (!storedState || storedState.state !== state || storedState.exp <= Math.floor(Date.now() / 1000)) {
    throw new HttpError(403, "invalid_oauth_state", "Glean OAuth state is invalid");
  }

  const callbackUrl = callbackUrlForFlow(request, env, flow);
  const config = await gleanOAuthConfig(env, flow, callbackUrl);
  const user = authorizeUserForFlow(await exchangeCodeForGleanUser(config, code, storedState.codeVerifier, request, env, flow), env, flow);
  const session = await createIdentitySession(user, env, flow.sessionKind);

  const headers = new Headers({
    Location: storedState.returnTo,
    "Cache-Control": "no-store",
  });
  headers.append("Set-Cookie", session.cookie);
  headers.append("Set-Cookie", clearStateCookie(flow));

  return new Response(null, {
    status: 302,
    headers,
  });
}

async function exchangeCodeForGleanUser(
  config: GleanOAuthConfig,
  code: string,
  codeVerifier: string,
  request: Request,
  env: GleanOAuthEnv,
  flow: GleanOAuthFlow,
): Promise<AuthenticatedGleanUser> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    code,
    code_verifier: codeVerifier,
    redirect_uri: callbackUrlForFlow(request, env, flow),
  });
  if (config.tokenEndpointAuthMethod === "client_secret_post") {
    if (!config.clientSecret) {
      throw new HttpError(500, "missing_glean_oauth_client_secret", "Glean OAuth client secret is not configured");
    }
    body.set("client_secret", config.clientSecret);
  }

  const tokenResponse = await fetch(config.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!tokenResponse.ok) {
    throw new HttpError(401, "glean_token_exchange_failed", "Glean OAuth token exchange failed");
  }

  const tokenBody = await readJsonResponse(
    tokenResponse,
    "glean_token_response_not_json",
    "Glean OAuth token response was not valid JSON",
  );
  const accessToken = isRecord(tokenBody) && typeof tokenBody.access_token === "string" ? tokenBody.access_token : null;
  const idToken = isRecord(tokenBody) ? tokenBody.id_token : null;
  const userFromIdToken = await verifiedIdTokenUser(idToken, config);
  if (userFromIdToken) {
    return userFromIdToken;
  }

  if (typeof idToken === "string" && !config.userinfoUrl) {
    throw new HttpError(
      401,
      idTokenVerificationConfigured(config) ? "invalid_glean_id_token" : "missing_glean_id_token_verification",
      idTokenVerificationConfigured(config)
        ? "Glean identity token could not be verified"
        : "Glean identity token verification is not configured",
    );
  }

  if (!accessToken) {
    throw new HttpError(401, "missing_glean_access_token", "Glean OAuth response did not include an access token");
  }
  if (!config.userinfoUrl) {
    throw new HttpError(401, "missing_glean_user", "Glean OAuth response did not include an identity token");
  }

  const userinfoResponse = await fetch(config.userinfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  if (!userinfoResponse.ok) {
    throw new HttpError(401, "glean_userinfo_failed", "Glean userinfo lookup failed");
  }

  const user = parseGleanUser(
    await readJsonResponse(userinfoResponse, "glean_userinfo_not_json", "Glean userinfo response was not valid JSON"),
  );
  if (!user) {
    throw new HttpError(401, "missing_glean_user", "Glean userinfo did not include an email address");
  }

  return user;
}

async function gleanOAuthConfig(env: GleanOAuthEnv, flow: GleanOAuthFlow, callbackUrl: string): Promise<GleanOAuthConfig> {
  const provider = await gleanOAuthProviderMetadata(env);
  if (flow.kind === "admin") {
    const client = await getAdminDynamicOAuthClient(env, provider, {
      callbackUrl,
    });
    return {
      ...provider,
      clientId: client.clientId,
      ...(client.clientSecret ? { clientSecret: client.clientSecret } : {}),
      scopes: ADMIN_GLEAN_OAUTH_SCOPES,
      tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    };
  }

  const scopes = optionalString(env.GLEAN_OAUTH_SCOPES) ?? DEFAULT_GLEAN_OAUTH_SCOPES;
  return {
    ...provider,
    clientId: requiredEnv(env.GLEAN_OAUTH_CLIENT_ID, "GLEAN_OAUTH_CLIENT_ID"),
    clientSecret: requiredEnv(env.GLEAN_OAUTH_CLIENT_SECRET, "GLEAN_OAUTH_CLIENT_SECRET"),
    scopes,
    tokenEndpointAuthMethod: "client_secret_post",
  };
}

async function gleanOAuthProviderMetadata(env: GleanOAuthEnv): Promise<GleanOAuthProviderMetadata> {
  const discovered = await discoveredOAuthConfig(env);
  return {
    authorizationUrl: configuredUrl(
      optionalString(env.GLEAN_OAUTH_AUTHORIZATION_URL) ?? optionalString(discovered?.authorization_endpoint),
      "GLEAN_OAUTH_AUTHORIZATION_URL",
    ),
    tokenUrl: configuredUrl(
      optionalString(env.GLEAN_OAUTH_TOKEN_URL) ?? optionalString(discovered?.token_endpoint),
      "GLEAN_OAUTH_TOKEN_URL",
    ),
    userinfoUrl: optionalConfiguredUrl(
      optionalString(env.GLEAN_OAUTH_USERINFO_URL) ?? optionalString(discovered?.userinfo_endpoint),
      "GLEAN_OAUTH_USERINFO_URL",
    ),
    issuer: optionalConfiguredIssuer(
      optionalString(discovered?.issuer) ?? optionalString(env.GLEAN_OAUTH_ISSUER),
      "GLEAN_OAUTH_ISSUER",
    ),
    jwksUrl: optionalConfiguredUrl(
      optionalString(env.GLEAN_OAUTH_JWKS_URL) ?? optionalString(discovered?.jwks_uri),
      "GLEAN_OAUTH_JWKS_URL",
    ),
    registrationUrl: optionalConfiguredUrl(
      optionalString(env.GLEAN_OAUTH_REGISTRATION_URL) ?? optionalString(discovered?.registration_endpoint),
      "GLEAN_OAUTH_REGISTRATION_URL",
    ),
  };
}

async function discoveredOAuthConfig(env: GleanOAuthEnv): Promise<Record<string, unknown> | null> {
  const discoveryUrl = optionalString(env.GLEAN_OAUTH_DISCOVERY_URL) ?? implicitDiscoveryUrlFromIssuer(env);
  if (!discoveryUrl) {
    return null;
  }

  const response = await fetch(discoveryUrl, {
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new HttpError(500, "glean_oauth_discovery_failed", "Glean OAuth discovery failed");
  }

  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new HttpError(500, "glean_oauth_discovery_not_json", "Glean OAuth discovery response was not valid JSON");
  }

  if (!isRecord(value)) {
    throw new HttpError(500, "glean_oauth_discovery_not_json", "Glean OAuth discovery response was not a JSON object");
  }

  return value;
}

function implicitDiscoveryUrlFromIssuer(env: GleanOAuthEnv): string | null {
  const issuer = optionalString(env.GLEAN_OAUTH_ISSUER);
  if (!issuer) {
    return null;
  }

  const hasManualEndpoints = optionalString(env.GLEAN_OAUTH_AUTHORIZATION_URL) && optionalString(env.GLEAN_OAUTH_TOKEN_URL);
  const hasManualIdentitySource = optionalString(env.GLEAN_OAUTH_USERINFO_URL) || optionalString(env.GLEAN_OAUTH_JWKS_URL);
  return hasManualEndpoints && hasManualIdentitySource ? null : discoveryUrlFromIssuer(issuer);
}

function discoveryUrlFromIssuer(issuer: string | undefined): string | null {
  if (!issuer) {
    return null;
  }

  return new URL("/.well-known/oauth-authorization-server", issuer).toString();
}

function callbackUrlForFlow(request: Request, env: GleanOAuthEnv, flow: GleanOAuthFlow): string {
  const requestUrl = new URL(request.url);
  if (isLocalDevelopmentRequest(request, requestUrl)) {
    return new URL(flow.callbackPath, requestUrl.origin).toString();
  }

  const base = flow.kind === "admin" ? env.API_BASE_URL : env.MCP_BASE_URL;
  return new URL(flow.callbackPath, configuredUrl(base, flow.kind === "admin" ? "API_BASE_URL" : "MCP_BASE_URL")).toString();
}

async function readOAuthState(
  request: Request,
  env: GleanOAuthEnv,
  flow: GleanOAuthFlow,
): Promise<OAuthStatePayload | null> {
  const token = getCookie(request, flow.stateCookieName);
  if (!token) {
    return null;
  }

  return verifyToken(token, oauthStateSecret(env), statePurpose(flow), parseOAuthStatePayload);
}

function parseOAuthStatePayload(value: unknown): OAuthStatePayload | null {
  if (!isRecord(value)) {
    return null;
  }

  return typeof value.state === "string" &&
    typeof value.codeVerifier === "string" &&
    typeof value.returnTo === "string" &&
    typeof value.exp === "number"
    ? {
        state: value.state,
        codeVerifier: value.codeVerifier,
        returnTo: value.returnTo,
        exp: value.exp,
      }
    : null;
}

function authorizeUserForFlow(
  user: AuthenticatedGleanUser,
  env: GleanOAuthEnv,
  flow: GleanOAuthFlow,
): AuthenticatedGleanUser {
  return flow.kind === "admin" ? requireAllowedAdminUser(user, env) : requireAllowedOAuthUser(user, env);
}

function parseGleanUser(value: unknown): AuthenticatedGleanUser | null {
  if (!isRecord(value)) {
    return null;
  }

  const email = normalizedEmailClaim(value.email ?? value.mail ?? value.preferred_username);
  if (!email) {
    return null;
  }

  return {
    email,
    ...(typeof value.name === "string" ? { name: value.name } : {}),
    ...(typeof value.picture === "string" ? { picture: value.picture } : {}),
    ...(typeof value.tenant === "string" ? { tenant: value.tenant } : {}),
  };
}

async function verifiedIdTokenUser(value: unknown, config: GleanOAuthConfig): Promise<AuthenticatedGleanUser | null> {
  if (typeof value !== "string") {
    return null;
  }

  if (!idTokenVerificationConfigured(config)) {
    return null;
  }

  const decoded = decodeJwt(value);
  const kid = decoded?.header.kid;
  if (!decoded || decoded.header.alg !== "RS256" || typeof kid !== "string") {
    return null;
  }

  if (
    !jwtClaimsAreValid(decoded, {
      clockSkewSeconds: JWT_CLOCK_SKEW_SECONDS,
      expectedAudience: config.clientId,
      expectedIssuer: config.issuer,
    })
  ) {
    return null;
  }

  const keys = await gleanJwks(config.jwksUrl);
  let jwk = keys.find((candidate) => candidate.kid === kid);
  if (!jwk) {
    const refreshedKeys = await gleanJwks(config.jwksUrl, true);
    jwk = refreshedKeys.find((candidate) => candidate.kid === kid);
  }

  if (!jwk || !(await verifyRs256JwtSignature(decoded, jwk))) {
    return null;
  }

  return parseGleanUser(decoded.payload);
}

function idTokenVerificationConfigured(config: GleanOAuthConfig): config is GleanOAuthConfig & {
  issuer: string;
  jwksUrl: string;
} {
  return !!config.issuer && !!config.jwksUrl;
}

async function gleanJwks(jwksUrl: string, forceRefresh = false, now = Date.now()): Promise<RsaPublicJwk[]> {
  const cached = gleanJwksCache.get(jwksUrl);
  if (!forceRefresh && cached && cached.expiresAt > now) {
    return cached.keys;
  }

  const response = await fetch(jwksUrl, {
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new HttpError(401, "glean_jwks_failed", "Glean signing keys lookup failed");
  }

  const keys = parseRsaPublicJwks(
    await readJsonResponse(response, "glean_jwks_not_json", "Glean signing keys response was not valid JSON"),
  );
  gleanJwksCache.set(jwksUrl, {
    keys,
    expiresAt: now + GLEAN_JWKS_CACHE_MS,
  });

  return keys;
}

async function readJsonResponse(response: Response, errorCode: string, errorMessage: string): Promise<unknown> {
  try {
    return await response.json() as unknown;
  } catch {
    throw new HttpError(401, errorCode, errorMessage);
  }
}

function normalizedEmailClaim(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const email = value.trim().toLowerCase();
  return email.includes("@") ? email : null;
}

function clearStateCookie(flow: GleanOAuthFlow): string {
  return [
    `${flow.stateCookieName}=`,
    `Path=${flow.stateCookiePath}`,
    "Max-Age=0",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

function oauthStateSecret(env: GleanOAuthEnv): string {
  const secret = env.ADMIN_SESSION_SECRET ?? env.COOKIE_SIGNING_SECRET;
  if (!secret) {
    throw new HttpError(500, "missing_oauth_state_secret", "ADMIN_SESSION_SECRET is not configured");
  }

  return secret;
}

function statePurpose(flow: GleanOAuthFlow): string {
  return `${OAUTH_STATE_PURPOSE}:${flow.kind}`;
}

function requiredEnv(value: string | undefined, name: string): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, `${name} is not configured`);
  }

  return trimmed;
}

function configuredUrl(value: string | undefined, name: string): string {
  if (!value) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, `${name} is not configured`);
  }

  try {
    return new URL(value).toString();
  } catch {
    throw new HttpError(500, `invalid_${name.toLowerCase()}`, `${name} is not a valid URL`);
  }
}

function optionalConfiguredUrl(value: string | undefined, name: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? configuredUrl(trimmed, name) : undefined;
}

function optionalConfiguredIssuer(value: string | undefined, name: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) {
    return undefined;
  }

  try {
    new URL(trimmed);
    return trimmed;
  } catch {
    throw new HttpError(500, `invalid_${name.toLowerCase()}`, `${name} is not a valid URL`);
  }
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

async function s256CodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8(codeVerifier));
  return toBase64Url(new Uint8Array(digest));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
