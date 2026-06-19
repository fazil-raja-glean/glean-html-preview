import { constantTimeEqual, randomBase64Url, toBase64Url, utf8 } from "./encoding";
import { isValidAccessTokenClientId } from "./oauth-client";
import {
  accessTokenHasSupportedScope,
  type McpOAuthConfig,
  type McpOAuthTokenConfig,
  validatedRedirectUri,
} from "./oauth-config";
import { signJwt, verifySignedJwt } from "./oauth-jwt";

interface AccessTokenPayload {
  iss: string;
  sub: string;
  aud: string;
  scope: string;
  iat: number;
  exp: number;
  jti: string;
}

interface AuthorizationCodePayload {
  iss: string;
  sub: string;
  redirectUri: string;
  scope: string;
  iat: number;
  exp: number;
  jti: string;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
}

export type CodeChallengeMethod = "plain" | "S256";

export type AuthorizationCodeGrantResult =
  | { valid: true; scope: string }
  | { valid: false; error: string; description: string };

const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;

export async function issueAuthorizationCode(
  config: McpOAuthConfig,
  input: {
    clientId: string;
    redirectUri: string;
    scope: string;
    codeChallenge?: string;
    codeChallengeMethod?: CodeChallengeMethod;
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
      iss: config.issuer,
      sub: input.clientId,
      redirectUri: input.redirectUri,
      scope: input.scope,
      iat: now,
      exp: now + AUTHORIZATION_CODE_TTL_SECONDS,
      jti: randomBase64Url(16),
      ...(input.codeChallenge
        ? { codeChallenge: input.codeChallenge, codeChallengeMethod: input.codeChallengeMethod ?? "plain" }
        : {}),
    },
    config.tokenSecret,
  );
}

export async function exchangeAuthorizationCodeGrant(
  config: McpOAuthConfig,
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

  return { valid: true, scope: payload.scope };
}

export async function issueAccessToken(config: McpOAuthConfig, clientId: string, scope: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
      iss: config.issuer,
      sub: clientId,
      aud: config.resource,
      scope,
      iat: now,
      exp: now + config.accessTokenTtlSeconds,
      jti: randomBase64Url(16),
    },
    config.tokenSecret,
  );
}

export async function verifyAccessToken(
  token: string,
  config: McpOAuthTokenConfig,
): Promise<{ valid: true } | { valid: false; message: string }> {
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

  if (!isValidAccessTokenClientId(payload.sub, config)) {
    return { valid: false, message: "OAuth bearer token subject is invalid" };
  }

  if (!accessTokenHasSupportedScope(payload.scope, config)) {
    return { valid: false, message: "OAuth bearer token scope is invalid" };
  }

  return { valid: true };
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

function parseAccessTokenPayload(value: Record<string, unknown>): AccessTokenPayload | null {
  if (
    typeof value.iss !== "string" ||
    typeof value.sub !== "string" ||
    typeof value.aud !== "string" ||
    typeof value.scope !== "string" ||
    typeof value.iat !== "number" ||
    typeof value.exp !== "number" ||
    typeof value.jti !== "string" ||
    !Number.isInteger(value.iat) ||
    !Number.isInteger(value.exp)
  ) {
    return null;
  }

  return {
    iss: value.iss,
    sub: value.sub,
    aud: value.aud,
    scope: value.scope,
    iat: value.iat,
    exp: value.exp,
    jti: value.jti,
  };
}

function parseAuthorizationCodePayload(value: Record<string, unknown>): AuthorizationCodePayload | null {
  if (
    typeof value.iss !== "string" ||
    typeof value.sub !== "string" ||
    typeof value.redirectUri !== "string" ||
    typeof value.scope !== "string" ||
    typeof value.iat !== "number" ||
    typeof value.exp !== "number" ||
    typeof value.jti !== "string" ||
    !Number.isInteger(value.iat) ||
    !Number.isInteger(value.exp)
  ) {
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
    iss: value.iss,
    sub: value.sub,
    redirectUri: value.redirectUri,
    scope: value.scope,
    iat: value.iat,
    exp: value.exp,
    jti: value.jti,
    ...(value.codeChallenge ? { codeChallenge: value.codeChallenge } : {}),
    ...(value.codeChallengeMethod ? { codeChallengeMethod: value.codeChallengeMethod } : {}),
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
