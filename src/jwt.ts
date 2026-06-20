import { fromBase64Url, fromUtf8, utf8 } from "./encoding";

const RS256_ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

export interface DecodedJwt {
  signingInput: string;
  signature: Uint8Array;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

export interface RsaPublicJwk {
  kid: string;
  kty: "RSA";
  n: string;
  e: string;
  alg?: string;
  use?: string;
}

export interface JwtClaimsValidationInput {
  clockSkewSeconds: number;
  expectedAudience: string;
  expectedIssuer: string;
  now?: number;
}

export function decodeJwt(token: string): DecodedJwt | null {
  const [encodedHeader, encodedPayload, encodedSignature, extra] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature || extra !== undefined) {
    return null;
  }

  try {
    const header = JSON.parse(fromUtf8(fromBase64Url(encodedHeader))) as unknown;
    const payload = JSON.parse(fromUtf8(fromBase64Url(encodedPayload))) as unknown;
    if (!isRecord(header) || !isRecord(payload)) {
      return null;
    }

    return {
      signingInput: `${encodedHeader}.${encodedPayload}`,
      signature: fromBase64Url(encodedSignature),
      header,
      payload,
    };
  } catch {
    return null;
  }
}

export function jwtClaimsAreValid(
  decoded: DecodedJwt,
  {
    clockSkewSeconds,
    expectedAudience,
    expectedIssuer,
    now = Date.now(),
  }: JwtClaimsValidationInput,
): boolean {
  const nowSeconds = Math.floor(now / 1000);
  const { payload } = decoded;

  if (payload.iss !== expectedIssuer || !audienceIncludes(payload.aud, expectedAudience)) {
    return false;
  }

  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds - clockSkewSeconds) {
    return false;
  }

  if (typeof payload.nbf === "number" && payload.nbf > nowSeconds + clockSkewSeconds) {
    return false;
  }

  if (typeof payload.iat === "number" && payload.iat > nowSeconds + clockSkewSeconds) {
    return false;
  }

  return true;
}

export function audienceIncludes(value: unknown, expectedAudience: string): boolean {
  if (typeof value === "string") {
    return value === expectedAudience;
  }

  return Array.isArray(value) && value.some((item) => item === expectedAudience);
}

export function parseRsaPublicJwks(value: unknown): RsaPublicJwk[] {
  if (!isRecord(value) || !Array.isArray(value.keys)) {
    return [];
  }

  return value.keys.filter(isRsaPublicJwk);
}

export async function verifyRs256JwtSignature(decoded: DecodedJwt, jwk: RsaPublicJwk): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: "RS256",
        ext: true,
      },
      RS256_ALGORITHM,
      false,
      ["verify"],
    );

    return crypto.subtle.verify(RS256_ALGORITHM, key, decoded.signature, utf8(decoded.signingInput));
  } catch {
    return false;
  }
}

function isRsaPublicJwk(value: unknown): value is RsaPublicJwk {
  if (!isRecord(value)) {
    return false;
  }

  return (
    value.kty === "RSA" &&
    typeof value.kid === "string" &&
    typeof value.n === "string" &&
    typeof value.e === "string" &&
    (value.alg === undefined || value.alg === "RS256") &&
    (value.use === undefined || value.use === "sig")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
