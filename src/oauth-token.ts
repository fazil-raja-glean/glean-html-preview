import { constantTimeEqual, randomBase64Url, toBase64Url, utf8 } from "./encoding";
import { isValidAccessTokenClientId } from "./oauth-client";
import type { OAuthGrantStore } from "./oauth-grants";
import {
  accessTokenHasSupportedScope,
  type McpOAuthConfig,
  type McpOAuthTokenConfig,
  validatedRedirectUri,
} from "./oauth-config";
import { signJwt, verifySignedJwt } from "./oauth-jwt";

interface AccessTokenPayload {
  typ?: "access";
  iss: string;
  sub: string;
  aud: string;
  scope: string;
  iat: number;
  exp: number;
  jti: string;
  email?: string;
}

interface AuthorizationCodePayload {
  iss: string;
  sub: string;
  redirectUri: string;
  scope: string;
  iat: number;
  exp: number;
  jti: string;
  email?: string;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
}

interface RefreshTokenPayload {
  typ: "refresh";
  iss: string;
  sub: string;
  aud: string;
  scope: string;
  iat: number;
  exp: number;
  jti: string;
  email?: string;
}

export type CodeChallengeMethod = "plain" | "S256";

export type AuthorizationCodeGrantResult =
  | { valid: true; scope: string; actorEmail?: string }
  | { valid: false; error: string; description: string };

export type RefreshTokenGrantResult =
  | { valid: true; scope: string; actorEmail?: string; refreshToken: string }
  | { valid: false; error: string; description: string };

export type AccessTokenVerificationResult =
  | { valid: true; actorEmail?: string; clientId: string }
  | { valid: false; message: string };

const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;

export async function issueAuthorizationCode(
  config: McpOAuthConfig,
  grantStore: OAuthGrantStore,
  input: {
    clientId: string;
    redirectUri: string;
    scope: string;
    actorEmail?: string;
    codeChallenge?: string;
    codeChallengeMethod?: CodeChallengeMethod;
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + AUTHORIZATION_CODE_TTL_SECONDS;
  const jti = randomBase64Url(16);
  const token = await signJwt(
    authorizationCodePayload({
      ...input,
      issuer: config.issuer,
      issuedAt: now,
      expiresAt,
      jti,
    }),
    config.tokenSecret,
  );
  await grantStore.create({
    jti,
    kind: "authorization_code",
    clientId: input.clientId,
    scope: input.scope,
    issuedAt: now,
    expiresAt,
    ...(input.actorEmail ? { actorEmail: input.actorEmail } : {}),
  });
  return token;
}

export async function exchangeAuthorizationCodeGrant(
  config: McpOAuthConfig,
  grantStore: OAuthGrantStore,
  form: URLSearchParams,
  clientId: string,
): Promise<AuthorizationCodeGrantResult> {
  const code = form.get("code");
  if (!code) {
    return { valid: false, error: "invalid_request", description: "code is required" };
  }

  const redirectUri = validatedRedirectUri(form.get("redirect_uri"), config);
  if (!redirectUri) {
    return { valid: false, error: "invalid_request", description: "redirect_uri is required" };
  }

  const payload = await verifyAuthorizationCode(code, config);
  if (!payload) {
    return { valid: false, error: "invalid_grant", description: "Invalid authorization code" };
  }

  if (!constantTimeEqual(payload.sub, clientId)) {
    return { valid: false, error: "invalid_grant", description: "Authorization code client is invalid" };
  }

  if (payload.redirectUri !== redirectUri) {
    return { valid: false, error: "invalid_grant", description: "Authorization code redirect_uri is invalid" };
  }

  const codeVerifier = form.get("code_verifier");
  if (payload.codeChallenge && !(await isValidPkceVerifier(payload, codeVerifier))) {
    return { valid: false, error: "invalid_grant", description: "Authorization code verifier is invalid" };
  }

  const consumed = await grantStore.consume({
    jti: payload.jti,
    kind: "authorization_code",
    clientId,
    scope: payload.scope,
    now: new Date(),
    ...(payload.email ? { actorEmail: payload.email } : {}),
  });
  if (!consumed) {
    return { valid: false, error: "invalid_grant", description: "Authorization code has already been used" };
  }

  return {
    valid: true,
    scope: payload.scope,
    ...(payload.email ? { actorEmail: payload.email } : {}),
  };
}

export async function exchangeRefreshTokenGrant(
  config: McpOAuthConfig,
  grantStore: OAuthGrantStore,
  form: URLSearchParams,
  clientId: string,
): Promise<RefreshTokenGrantResult> {
  const refreshToken = form.get("refresh_token");
  if (!refreshToken) {
    return { valid: false, error: "invalid_request", description: "refresh_token is required" };
  }

  const payload = await verifyRefreshToken(refreshToken, config);
  if (!payload) {
    return { valid: false, error: "invalid_grant", description: "Invalid refresh token" };
  }

  if (!constantTimeEqual(payload.sub, clientId)) {
    return { valid: false, error: "invalid_grant", description: "Refresh token client is invalid" };
  }

  const now = new Date();
  const nextRefreshToken = await issueRefreshToken(config, grantStore, clientId, payload.scope, payload.email);
  const consumed = await grantStore.consume({
    jti: payload.jti,
    kind: "refresh_token",
    clientId,
    scope: payload.scope,
    consumedByJti: nextRefreshToken.jti,
    now,
    ...(payload.email ? { actorEmail: payload.email } : {}),
  });
  if (!consumed) {
    await grantStore.revoke({
      jti: nextRefreshToken.jti,
      now,
    });
    return { valid: false, error: "invalid_grant", description: "Refresh token has already been used" };
  }

  return {
    valid: true,
    scope: payload.scope,
    refreshToken: nextRefreshToken.token,
    ...(payload.email ? { actorEmail: payload.email } : {}),
  };
}

export async function issueAccessToken(
  config: McpOAuthConfig,
  clientId: string,
  scope: string,
  actorEmail?: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
      typ: "access",
      iss: config.issuer,
      sub: clientId,
      client_id: clientId,
      aud: config.resource,
      scope,
      iat: now,
      exp: now + config.accessTokenTtlSeconds,
      jti: randomBase64Url(16),
      ...(actorEmail ? { email: actorEmail } : {}),
    },
    config.tokenSecret,
  );
}

export async function issueRefreshToken(
  config: McpOAuthConfig,
  grantStore: OAuthGrantStore,
  clientId: string,
  scope: string,
  actorEmail?: string,
): Promise<{ token: string; jti: string }> {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + config.refreshTokenTtlSeconds;
  const jti = randomBase64Url(16);
  const token = await signJwt(
    refreshTokenPayload({
      actorEmail,
      clientId,
      config,
      expiresAt,
      issuedAt: now,
      jti,
      scope,
    }),
    config.tokenSecret,
  );
  await grantStore.create({
    jti,
    kind: "refresh_token",
    clientId,
    scope,
    issuedAt: now,
    expiresAt,
    ...(actorEmail ? { actorEmail } : {}),
  });
  return { token, jti };
}

export async function verifyAccessToken(
  token: string,
  config: McpOAuthTokenConfig,
): Promise<AccessTokenVerificationResult> {
  const payload = await verifySignedJwt(token, config.tokenSecret, parseAccessTokenPayload);
  if (!payload) {
    return { valid: false, message: "Invalid OAuth bearer token" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    return { valid: false, message: "Expired OAuth bearer token" };
  }

  if (payload.iss !== config.issuer) {
    return { valid: false, message: "OAuth bearer token issuer is invalid" };
  }

  if (payload.aud !== config.resource) {
    return { valid: false, message: "OAuth bearer token audience is invalid" };
  }

  if (payload.typ !== undefined && payload.typ !== "access") {
    return { valid: false, message: "OAuth bearer token type is invalid" };
  }

  if (!isValidAccessTokenClientId(payload.sub, config)) {
    return { valid: false, message: "OAuth bearer token subject is invalid" };
  }

  if (!accessTokenHasSupportedScope(payload.scope, config)) {
    return { valid: false, message: "OAuth bearer token scope is invalid" };
  }

  return {
    valid: true,
    clientId: payload.sub,
    ...(payload.email ? { actorEmail: payload.email } : {}),
  };
}

export function parseCodeChallengeMethod(value: string | null): CodeChallengeMethod | null {
  if (!value) {
    return "plain";
  }

  return value === "plain" || value === "S256" ? value : null;
}

async function verifyAuthorizationCode(code: string, config: McpOAuthConfig): Promise<AuthorizationCodePayload | null> {
  const payload = await verifySignedJwt(code, config.tokenSecret, parseAuthorizationCodePayload);
  if (!payload) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  return payload.exp > now && payload.iss === config.issuer ? payload : null;
}

async function verifyRefreshToken(token: string, config: McpOAuthConfig): Promise<RefreshTokenPayload | null> {
  const payload = await verifySignedJwt(token, config.tokenSecret, parseRefreshTokenPayload);
  if (!payload) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now || payload.iss !== config.issuer || payload.aud !== config.resource) {
    return null;
  }

  return accessTokenHasSupportedScope(payload.scope, config) ? payload : null;
}

function parseAccessTokenPayload(value: Record<string, unknown>): AccessTokenPayload | null {
  const base = parseBaseTokenPayload(value);
  if (!base || typeof value.aud !== "string") {
    return null;
  }

  if (value.typ !== undefined && value.typ !== "access") {
    return null;
  }

  if (value.email !== undefined && typeof value.email !== "string") {
    return null;
  }

  return {
    ...(value.typ ? { typ: value.typ } : {}),
    iss: base.iss,
    sub: base.sub,
    aud: value.aud,
    scope: base.scope,
    iat: base.iat,
    exp: base.exp,
    jti: base.jti,
    ...(base.email ? { email: base.email } : {}),
  };
}

function parseRefreshTokenPayload(value: Record<string, unknown>): RefreshTokenPayload | null {
  const base = parseBaseTokenPayload(value);
  if (!base || value.typ !== "refresh" || typeof value.aud !== "string") {
    return null;
  }

  return {
    typ: value.typ,
    iss: base.iss,
    sub: base.sub,
    aud: value.aud,
    scope: base.scope,
    iat: base.iat,
    exp: base.exp,
    jti: base.jti,
    ...(base.email ? { email: base.email } : {}),
  };
}

function parseAuthorizationCodePayload(value: Record<string, unknown>): AuthorizationCodePayload | null {
  const base = parseBaseTokenPayload(value);
  if (!base || typeof value.redirectUri !== "string") {
    return null;
  }

  if (value.codeChallenge !== undefined && typeof value.codeChallenge !== "string") {
    return null;
  }

  if (
    value.codeChallengeMethod !== undefined &&
    value.codeChallengeMethod !== "plain" &&
    value.codeChallengeMethod !== "S256"
  ) {
    return null;
  }

  return {
    iss: base.iss,
    sub: base.sub,
    redirectUri: value.redirectUri,
    scope: base.scope,
    iat: base.iat,
    exp: base.exp,
    jti: base.jti,
    ...(base.email ? { email: base.email } : {}),
    ...(value.codeChallenge ? { codeChallenge: value.codeChallenge } : {}),
    ...(value.codeChallengeMethod ? { codeChallengeMethod: value.codeChallengeMethod } : {}),
  };
}

function parseBaseTokenPayload(value: Record<string, unknown>): Omit<AccessTokenPayload, "aud" | "typ"> | null {
  if (
    typeof value.iss !== "string" ||
    typeof value.sub !== "string" ||
    typeof value.scope !== "string" ||
    typeof value.iat !== "number" ||
    typeof value.exp !== "number" ||
    typeof value.jti !== "string" ||
    !Number.isInteger(value.iat) ||
    !Number.isInteger(value.exp)
  ) {
    return null;
  }

  if (value.email !== undefined && typeof value.email !== "string") {
    return null;
  }

  return {
    iss: value.iss,
    sub: value.sub,
    scope: value.scope,
    iat: value.iat,
    exp: value.exp,
    jti: value.jti,
    ...(value.email ? { email: value.email } : {}),
  };
}

function authorizationCodePayload(input: {
  actorEmail?: string;
  clientId: string;
  codeChallenge?: string;
  codeChallengeMethod?: CodeChallengeMethod;
  expiresAt: number;
  issuedAt: number;
  issuer: string;
  jti: string;
  redirectUri: string;
  scope: string;
}): AuthorizationCodePayload {
  return {
    iss: input.issuer,
    sub: input.clientId,
    redirectUri: input.redirectUri,
    scope: input.scope,
    iat: input.issuedAt,
    exp: input.expiresAt,
    jti: input.jti,
    ...(input.actorEmail ? { email: input.actorEmail } : {}),
    ...(input.codeChallenge
      ? { codeChallenge: input.codeChallenge, codeChallengeMethod: input.codeChallengeMethod ?? "plain" }
      : {}),
  };
}

function refreshTokenPayload(input: {
  actorEmail?: string;
  clientId: string;
  config: McpOAuthConfig;
  expiresAt: number;
  issuedAt: number;
  jti: string;
  scope: string;
}): RefreshTokenPayload {
  return {
    typ: "refresh",
    iss: input.config.issuer,
    sub: input.clientId,
    aud: input.config.resource,
    scope: input.scope,
    iat: input.issuedAt,
    exp: input.expiresAt,
    jti: input.jti,
    ...(input.actorEmail ? { email: input.actorEmail } : {}),
  };
}

async function isValidPkceVerifier(payload: AuthorizationCodePayload, verifier: string | null): Promise<boolean> {
  if (!verifier) {
    return false;
  }

  if (payload.codeChallengeMethod === "S256") {
    const digest = await crypto.subtle.digest("SHA-256", utf8(verifier));
    return constantTimeEqual(toBase64Url(new Uint8Array(digest)), payload.codeChallenge ?? "");
  }

  return constantTimeEqual(verifier, payload.codeChallenge ?? "");
}
