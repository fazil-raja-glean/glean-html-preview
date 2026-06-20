import { randomBase64Url, toBase64Url, utf8 } from "../encoding";
import { getCookie } from "../cookies";
import { HttpError } from "../http";
import { isLocalDevelopmentRequest } from "../origin-policy";
import { signToken, verifyToken } from "../signed-token";
import {
  type AuthenticatedGleanUser,
  type IdentitySessionEnv,
  type IdentitySessionKind,
  createIdentitySession,
  requireAllowedAdminUser,
  requireAllowedOAuthUser,
} from "./session";

export interface GleanOAuthEnv extends IdentitySessionEnv {
  API_BASE_URL?: string;
  GLEAN_OAUTH_AUTHORIZATION_URL?: string;
  GLEAN_OAUTH_CLIENT_ID?: string;
  GLEAN_OAUTH_CLIENT_SECRET?: string;
  GLEAN_OAUTH_DISCOVERY_URL?: string;
  GLEAN_OAUTH_ISSUER?: string;
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
  clientSecret: string;
  scopes: string;
  tokenUrl: string;
  userinfoUrl: string;
}

interface OAuthStatePayload {
  codeVerifier: string;
  exp: number;
  returnTo: string;
  state: string;
}

const DEFAULT_GLEAN_OAUTH_SCOPES = "openid email profile";
const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const OAUTH_STATE_PURPOSE = "glean-oauth-state:v1";

export const ADMIN_GLEAN_OAUTH_FLOW: GleanOAuthFlow = {
  kind: "admin",
  sessionKind: "admin",
  callbackPath: "/admin/oauth/callback",
  stateCookieName: "html_admin_oauth_state",
  stateCookiePath: "/admin",
};

export const MCP_GLEAN_OAUTH_FLOW: GleanOAuthFlow = {
  kind: "oauth",
  sessionKind: "oauth",
  callbackPath: "/oauth/callback",
  stateCookieName: "html_oauth_state",
  stateCookiePath: "/oauth",
};

export async function startGleanOAuthLogin(
  request: Request,
  env: GleanOAuthEnv,
  flow: GleanOAuthFlow,
  returnTo: string,
): Promise<Response> {
  const config = await gleanOAuthConfig(env);
  const state = randomBase64Url(24);
  const codeVerifier = randomBase64Url(48);
  const codeChallenge = await s256CodeChallenge(codeVerifier);
  const callbackUrl = callbackUrlForFlow(request, env, flow);
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
      returnTo: safeReturnTo(returnTo),
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

  const config = await gleanOAuthConfig(env);
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
  const tokenResponse = await fetch(config.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      code_verifier: codeVerifier,
      redirect_uri: callbackUrlForFlow(request, env, flow),
    }),
  });
  if (!tokenResponse.ok) {
    throw new HttpError(401, "glean_token_exchange_failed", "Glean OAuth token exchange failed");
  }

  const tokenBody = await tokenResponse.json() as unknown;
  const accessToken = isRecord(tokenBody) && typeof tokenBody.access_token === "string" ? tokenBody.access_token : null;
  if (!accessToken) {
    throw new HttpError(401, "missing_glean_access_token", "Glean OAuth response did not include an access token");
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

  const user = parseGleanUser(await userinfoResponse.json() as unknown);
  if (!user) {
    throw new HttpError(401, "missing_glean_user", "Glean userinfo did not include an email address");
  }

  return user;
}

async function gleanOAuthConfig(env: GleanOAuthEnv): Promise<GleanOAuthConfig> {
  const discovered = await discoveredOAuthConfig(env);
  return {
    authorizationUrl: configuredUrl(
      env.GLEAN_OAUTH_AUTHORIZATION_URL ?? optionalString(discovered?.authorization_endpoint),
      "GLEAN_OAUTH_AUTHORIZATION_URL",
    ),
    tokenUrl: configuredUrl(
      env.GLEAN_OAUTH_TOKEN_URL ?? optionalString(discovered?.token_endpoint),
      "GLEAN_OAUTH_TOKEN_URL",
    ),
    userinfoUrl: configuredUrl(
      env.GLEAN_OAUTH_USERINFO_URL ?? optionalString(discovered?.userinfo_endpoint),
      "GLEAN_OAUTH_USERINFO_URL",
    ),
    clientId: requiredEnv(env.GLEAN_OAUTH_CLIENT_ID, "GLEAN_OAUTH_CLIENT_ID"),
    clientSecret: requiredEnv(env.GLEAN_OAUTH_CLIENT_SECRET, "GLEAN_OAUTH_CLIENT_SECRET"),
    scopes: env.GLEAN_OAUTH_SCOPES?.trim() || DEFAULT_GLEAN_OAUTH_SCOPES,
  };
}

async function discoveredOAuthConfig(env: GleanOAuthEnv): Promise<Record<string, unknown> | null> {
  const discoveryUrl = env.GLEAN_OAUTH_DISCOVERY_URL ?? discoveryUrlFromIssuer(env.GLEAN_OAUTH_ISSUER);
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

  const value = await response.json() as unknown;
  return isRecord(value) ? value : null;
}

function discoveryUrlFromIssuer(issuer: string | undefined): string | null {
  if (!issuer) {
    return null;
  }

  return new URL("/.well-known/openid-configuration", issuer).toString();
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

function safeReturnTo(value: string): string {
  return value.startsWith("/") && !value.startsWith("//") ? value : "/admin";
}

function requiredEnv(value: string | undefined, name: string): string {
  if (!value) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, `${name} is not configured`);
  }

  return value;
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
