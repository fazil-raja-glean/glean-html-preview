import { getCookie } from "../cookies";
import { HttpError } from "../http";
import { isLocalDevelopmentRequest } from "../origin-policy";
import { signToken, verifyToken } from "../signed-token";
import { createCsrfToken } from "./csrf";

export interface AuthenticatedGleanUser {
  email: string;
  name?: string;
  picture?: string;
  tenant?: string;
}

export interface AdminSessionPayload extends AuthenticatedGleanUser {
  csrf: string;
  exp: number;
  iat: number;
}

export interface IdentitySessionEnv {
  ADMIN_ALLOWED_EMAIL_DOMAIN?: string;
  ADMIN_ALLOWED_EMAILS?: string;
  ADMIN_LOCAL_BYPASS_EMAIL?: string;
  ADMIN_SESSION_SECRET?: string;
  ADMIN_SESSION_TTL_SECONDS?: string;
  COOKIE_SIGNING_SECRET?: string;
  MCP_OAUTH_ALLOWED_EMAIL_DOMAIN?: string;
  PUBLISHER_EMAIL_DOMAIN?: string;
}

export type IdentitySessionKind = "admin" | "oauth";

const ADMIN_SESSION_COOKIE = "html_admin_session";
const OAUTH_SESSION_COOKIE = "html_oauth_identity";
const DEFAULT_ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_ADMIN_SESSION_TTL_SECONDS = 24 * 60 * 60;

export function sessionCookieName(kind: IdentitySessionKind): string {
  return kind === "admin" ? ADMIN_SESSION_COOKIE : OAUTH_SESSION_COOKIE;
}

export function sessionCookiePath(kind: IdentitySessionKind): string {
  return kind === "admin" ? "/admin" : "/oauth";
}

export async function createIdentitySession(
  user: AuthenticatedGleanUser,
  env: IdentitySessionEnv,
  kind: IdentitySessionKind,
  now = Date.now(),
): Promise<{
  cookie: string;
  session: AdminSessionPayload;
}> {
  const ttlSeconds = adminSessionTtlSeconds(env);
  const session: AdminSessionPayload = {
    email: user.email,
    ...(user.name ? { name: user.name } : {}),
    ...(user.picture ? { picture: user.picture } : {}),
    ...(user.tenant ? { tenant: user.tenant } : {}),
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + ttlSeconds,
    csrf: createCsrfToken(),
  };
  const token = await signToken(session, sessionSecret(env), sessionPurpose(kind));

  return {
    session,
    cookie: [
      `${sessionCookieName(kind)}=${token}`,
      `Path=${sessionCookiePath(kind)}`,
      `Max-Age=${ttlSeconds}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
    ].join("; "),
  };
}

export async function readIdentitySession(
  request: Request,
  env: IdentitySessionEnv,
  kind: IdentitySessionKind,
  now = Date.now(),
): Promise<AdminSessionPayload | null> {
  const token = getCookie(request, sessionCookieName(kind));
  if (!token) {
    return null;
  }

  const session = await verifyToken(token, sessionSecret(env), sessionPurpose(kind), parseAdminSessionPayload);
  if (!session || session.exp <= Math.floor(now / 1000)) {
    return null;
  }

  return session;
}

export async function requireIdentitySession(
  request: Request,
  env: IdentitySessionEnv,
  kind: IdentitySessionKind,
): Promise<AdminSessionPayload> {
  const session = await readIdentitySession(request, env, kind);
  if (!session) {
    throw new HttpError(401, "missing_admin_session", "Admin login is required");
  }

  return session;
}

export function clearIdentitySessionCookie(kind: IdentitySessionKind): string {
  return [
    `${sessionCookieName(kind)}=`,
    `Path=${sessionCookiePath(kind)}`,
    "Max-Age=0",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

export function localBypassUser(request: Request, env: IdentitySessionEnv): AuthenticatedGleanUser | null {
  const requestUrl = new URL(request.url);
  if (!isLocalDevelopmentRequest(request, requestUrl) || !env.ADMIN_LOCAL_BYPASS_EMAIL) {
    return null;
  }

  return {
    email: normalizeEmail(env.ADMIN_LOCAL_BYPASS_EMAIL, "ADMIN_LOCAL_BYPASS_EMAIL"),
    name: "Local Admin",
  };
}

export function requireAllowedAdminUser(user: AuthenticatedGleanUser, env: IdentitySessionEnv): AuthenticatedGleanUser {
  const allowedEmails = parseConfiguredList(env.ADMIN_ALLOWED_EMAILS).map((email) =>
    normalizeEmail(email, "ADMIN_ALLOWED_EMAILS"),
  );
  if (allowedEmails.length > 0) {
    if (!allowedEmails.includes(user.email)) {
      throw new HttpError(403, "admin_email_forbidden", "This Glean user is not an allowed admin");
    }

    return user;
  }

  const domain = allowedEmailDomain(env.ADMIN_ALLOWED_EMAIL_DOMAIN ?? env.PUBLISHER_EMAIL_DOMAIN);
  requireEmailDomain(user.email, domain, "admin_email_forbidden", "Glean user is not in the allowed admin domain");
  return user;
}

export function requireAllowedOAuthUser(user: AuthenticatedGleanUser, env: IdentitySessionEnv): AuthenticatedGleanUser {
  const domain = allowedEmailDomain(
    env.MCP_OAUTH_ALLOWED_EMAIL_DOMAIN ?? env.ADMIN_ALLOWED_EMAIL_DOMAIN ?? env.PUBLISHER_EMAIL_DOMAIN,
  );
  requireEmailDomain(user.email, domain, "access_email_forbidden", "Glean user is not in the allowed OAuth domain");
  return user;
}

export function normalizeEmail(value: string, field: string): string {
  const email = value.trim().toLowerCase();
  if (!email.includes("@")) {
    throw new HttpError(403, `invalid_${field.toLowerCase()}`, `${field} must be an email address`);
  }

  return email;
}

function sessionSecret(env: IdentitySessionEnv): string {
  const secret = env.ADMIN_SESSION_SECRET ?? env.COOKIE_SIGNING_SECRET;
  if (!secret) {
    throw new HttpError(500, "missing_admin_session_secret", "ADMIN_SESSION_SECRET is not configured");
  }

  return secret;
}

function sessionPurpose(kind: IdentitySessionKind): string {
  return `identity-session:${kind}:v1`;
}

function adminSessionTtlSeconds(env: Pick<IdentitySessionEnv, "ADMIN_SESSION_TTL_SECONDS">): number {
  if (!env.ADMIN_SESSION_TTL_SECONDS) {
    return DEFAULT_ADMIN_SESSION_TTL_SECONDS;
  }

  const value = Number(env.ADMIN_SESSION_TTL_SECONDS);
  if (!Number.isInteger(value) || value < 300 || value > MAX_ADMIN_SESSION_TTL_SECONDS) {
    throw new HttpError(
      500,
      "invalid_admin_session_ttl_seconds",
      "ADMIN_SESSION_TTL_SECONDS must be between 300 and 86400",
    );
  }

  return value;
}

function parseAdminSessionPayload(value: unknown): AdminSessionPayload | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const record = value as Record<string, unknown>;
  if (
    typeof record.email !== "string" ||
    typeof record.iat !== "number" ||
    typeof record.exp !== "number" ||
    typeof record.csrf !== "string"
  ) {
    return null;
  }

  return {
    email: record.email,
    ...(typeof record.name === "string" ? { name: record.name } : {}),
    ...(typeof record.picture === "string" ? { picture: record.picture } : {}),
    ...(typeof record.tenant === "string" ? { tenant: record.tenant } : {}),
    iat: record.iat,
    exp: record.exp,
    csrf: record.csrf,
  };
}

function allowedEmailDomain(value: string | undefined): string {
  const domain = value?.trim().toLowerCase();
  if (!domain) {
    throw new HttpError(500, "missing_allowed_email_domain", "Allowed Glean email domain is not configured");
  }

  return domain;
}

function requireEmailDomain(email: string, domain: string, code: string, message: string): void {
  const suffix = `@${domain}`;
  if (!email.endsWith(suffix) || email.length <= suffix.length) {
    throw new HttpError(403, code, message);
  }
}

function parseConfiguredList(value: string | undefined): string[] {
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
      throw new HttpError(500, "invalid_admin_allowed_emails", "ADMIN_ALLOWED_EMAILS must be a JSON string array");
    }
  }

  return trimmed.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}
