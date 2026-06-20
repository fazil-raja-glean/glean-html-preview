import { constantTimeEqual, fromBase64Url, fromUtf8, toBase64Url, utf8 } from "./encoding";

const SIGNING_ALGORITHM = { name: "HMAC", hash: "SHA-256" };

export async function signToken(payload: unknown, secret: string, purpose: string): Promise<string> {
  const encodedPayload = toBase64Url(utf8(JSON.stringify(payload)));
  const signature = await sign(`${purpose}.${encodedPayload}`, secret);
  return `${encodedPayload}.${signature}`;
}

export function signText(value: string, secret: string, purpose: string): Promise<string> {
  return sign(`${purpose}.${value}`, secret);
}

export async function verifyToken<T>(
  token: string,
  secret: string,
  purpose: string,
  parser: (value: unknown) => T | null,
): Promise<T | null> {
  const [encodedPayload, signature, extra] = token.split(".");
  if (!encodedPayload || !signature || extra !== undefined) {
    return null;
  }

  const expectedSignature = await sign(`${purpose}.${encodedPayload}`, secret);
  if (!constantTimeEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    return parser(JSON.parse(fromUtf8(fromBase64Url(encodedPayload))) as unknown);
  } catch {
    return null;
  }
}

async function sign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8(secret), SIGNING_ALGORITHM, false, ["sign"]);
  const signature = await crypto.subtle.sign(SIGNING_ALGORITHM, key, utf8(payload));
  return toBase64Url(new Uint8Array(signature));
}
