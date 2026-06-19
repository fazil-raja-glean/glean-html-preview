import { constantTimeEqual, fromBase64Url, fromUtf8, randomBase64Url, toBase64Url, utf8 } from "./encoding";

const PASSWORD_ALGORITHM = "PBKDF2-SHA256";
const PASSWORD_ITERATIONS = 100_000;
const SIGNING_ALGORITHM = { name: "HMAC", hash: "SHA-256" };

export interface PasswordHash {
  algorithm: typeof PASSWORD_ALGORITHM;
  hash: string;
  salt: string;
  iterations: number;
}

export interface AccessCookiePayload {
  slug: string;
  passwordVersion: number;
  expiresAt: number;
}

export function createSlug(): string {
  return randomBase64Url(16);
}

export async function hashPassword(
  password: string,
  pepper: string,
  salt = randomBase64Url(16),
  iterations = PASSWORD_ITERATIONS,
): Promise<PasswordHash> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    utf8(`${password}\0${pepper}`),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: fromBase64Url(salt),
      iterations,
    },
    passwordKey,
    256,
  );

  return {
    algorithm: PASSWORD_ALGORITHM,
    hash: toBase64Url(new Uint8Array(bits)),
    salt,
    iterations,
  };
}

export async function verifyPassword(
  password: string,
  pepper: string,
  storedHash: string,
  salt: string,
  iterations: number,
): Promise<boolean> {
  const candidate = await hashPassword(password, pepper, salt, iterations);
  return constantTimeEqual(candidate.hash, storedHash);
}

export async function signAccessCookie(payload: AccessCookiePayload, secret: string): Promise<string> {
  const encodedPayload = toBase64Url(utf8(JSON.stringify(payload)));
  const signature = await sign(encodedPayload, secret);
  return `${encodedPayload}.${signature}`;
}

export async function verifyAccessCookie(
  token: string,
  secret: string,
  expectedSlug: string,
  expectedPasswordVersion: number,
  now = Date.now(),
): Promise<boolean> {
  const [encodedPayload, signature, extra] = token.split(".");
  if (!encodedPayload || !signature || extra !== undefined) {
    return false;
  }

  const expectedSignature = await sign(encodedPayload, secret);
  if (!constantTimeEqual(signature, expectedSignature)) {
    return false;
  }

  const payload = parseAccessCookiePayload(encodedPayload);
  if (!payload) {
    return false;
  }

  return (
    payload.slug === expectedSlug &&
    payload.passwordVersion === expectedPasswordVersion &&
    payload.expiresAt > now
  );
}

export async function hashViewerIp(ipAddress: string | null, secret: string): Promise<string | null> {
  if (!ipAddress) {
    return null;
  }

  const signature = await sign(ipAddress, secret);
  return signature.slice(0, 24);
}

async function sign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8(secret), SIGNING_ALGORITHM, false, ["sign"]);
  const signature = await crypto.subtle.sign(SIGNING_ALGORITHM, key, utf8(payload));
  return toBase64Url(new Uint8Array(signature));
}

function parseAccessCookiePayload(encodedPayload: string): AccessCookiePayload | null {
  try {
    const decoded = fromUtf8(fromBase64Url(encodedPayload));
    const value: unknown = JSON.parse(decoded);
    if (!isAccessCookiePayload(value)) {
      return null;
    }

    return value;
  } catch {
    return null;
  }
}

function isAccessCookiePayload(value: unknown): value is AccessCookiePayload {
  if (!value || typeof value !== "object") {
    return false;
  }

  const record = value as Record<string, unknown>;
  return (
    typeof record.slug === "string" &&
    typeof record.passwordVersion === "number" &&
    Number.isInteger(record.passwordVersion) &&
    typeof record.expiresAt === "number" &&
    Number.isFinite(record.expiresAt)
  );
}
