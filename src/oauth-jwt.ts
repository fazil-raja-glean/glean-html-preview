import { constantTimeEqual, fromBase64Url, fromUtf8, toBase64Url, utf8 } from "./encoding";

const JWT_HEADER = {
  alg: "HS256",
  typ: "JWT",
};
const SIGNING_ALGORITHM = { name: "HMAC", hash: "SHA-256" };

export async function signJwt(payload: object, secret: string): Promise<string> {
  const encodedHeader = toBase64Url(utf8(JSON.stringify(JWT_HEADER)));
  const encodedPayload = toBase64Url(utf8(JSON.stringify(payload)));
  const signature = await sign(`${encodedHeader}.${encodedPayload}`, secret);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export async function verifySignedJwt<T>(
  token: string,
  secret: string,
  parsePayload: (value: Record<string, unknown>) => T | null,
): Promise<T | null> {
  const [encodedHeader, encodedPayload, signature, extra] = token.split(".");
  if (!encodedHeader || !encodedPayload || !signature || extra !== undefined) {
    return null;
  }

  const expectedSignature = await sign(`${encodedHeader}.${encodedPayload}`, secret);
  if (!constantTimeEqual(signature, expectedSignature)) {
    return null;
  }

  const header = parseJsonRecord(encodedHeader);
  if (header?.alg !== JWT_HEADER.alg || header.typ !== JWT_HEADER.typ) {
    return null;
  }

  const payload = parseJsonRecord(encodedPayload);
  return payload ? parsePayload(payload) : null;
}

async function sign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8(secret), SIGNING_ALGORITHM, false, ["sign"]);
  const signature = await crypto.subtle.sign(SIGNING_ALGORITHM, key, utf8(payload));
  return toBase64Url(new Uint8Array(signature));
}

function parseJsonRecord(encodedValue: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(fromUtf8(fromBase64Url(encodedValue)));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
