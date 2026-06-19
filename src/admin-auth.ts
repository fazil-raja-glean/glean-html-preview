import { constantTimeEqual, fromBase64Url, fromUtf8, utf8 } from "./encoding";
import { HttpError } from "./http";

export const CLOUDFLARE_ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion";
export const LOCAL_PUBLISH_ADMIN_SECRET_HEADER = "X-Publish-Admin-Secret";

const ACCESS_CERTS_CACHE_MS = 10 * 60 * 1000;
const JWT_CLOCK_SKEW_SECONDS = 60;
const RS256_ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const PLACEHOLDER_PATTERN = /<|>|YOUR_|REPLACE_/i;

type AccessCertsFetcher = typeof fetch;

interface AccessJwk {
  kid: string;
  kty: "RSA";
  n: string;
  e: string;
  alg?: string;
}

interface CachedAccessKeys {
  keys: AccessJwk[];
  expiresAt: number;
}

interface DecodedJwt {
  signingInput: string;
  signature: Uint8Array;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

export interface PublishAdminAccessEnv {
  PUBLISH_ACCESS_TEAM_DOMAIN?: string;
  PUBLISH_ACCESS_AUD?: string;
  PUBLISH_ADMIN_LOCAL_BYPASS_SECRET?: string;
}

export interface CloudflareAccessJwtConfig {
  teamDomain: string;
  audience: string;
}

export interface CloudflareAccessIdentity {
  email: string | null;
}

export interface CloudflareAccessJwtVerifyOptions {
  fetcher?: AccessCertsFetcher;
  now?: number;
}

const accessJwksCache = new Map<string, CachedAccessKeys>();

export async function requirePublishAdminAccess(
  request: Request,
  env: PublishAdminAccessEnv,
  options: {
    isLocalDevelopment: boolean;
    fetcher?: AccessCertsFetcher;
    now?: number;
  },
): Promise<CloudflareAccessIdentity> {
  if (options.isLocalDevelopment && env.PUBLISH_ADMIN_LOCAL_BYPASS_SECRET) {
    requireLocalPublishAdminSecret(request, env.PUBLISH_ADMIN_LOCAL_BYPASS_SECRET);
    return { email: null };
  }

  const config = cloudflareAccessConfig(env);
  if (!config) {
    throw new HttpError(
      500,
      "missing_publish_admin_access",
      "Publish/admin Cloudflare Access JWT validation is not configured",
    );
  }

  const token = request.headers.get(CLOUDFLARE_ACCESS_JWT_HEADER);
  if (!token) {
    throw new HttpError(401, "missing_access_jwt", "Missing Cloudflare Access JWT");
  }

  const identity = await verifyCloudflareAccessJwtIdentity(token, config, {
    fetcher: options.fetcher,
    now: options.now,
  });
  if (!identity) {
    throw new HttpError(403, "invalid_access_jwt", "Invalid Cloudflare Access JWT");
  }

  return identity;
}

export async function requireCloudflareAccessUserEmail(
  request: Request,
  config: CloudflareAccessJwtConfig,
  options: CloudflareAccessJwtVerifyOptions = {},
): Promise<string> {
  const token = request.headers.get(CLOUDFLARE_ACCESS_JWT_HEADER);
  if (!token) {
    throw new HttpError(401, "missing_access_jwt", "Missing Cloudflare Access JWT");
  }

  const identity = await verifyCloudflareAccessJwtIdentity(token, config, options);
  if (!identity) {
    throw new HttpError(403, "invalid_access_jwt", "Invalid Cloudflare Access JWT");
  }

  if (!identity.email) {
    throw new HttpError(403, "missing_access_email", "Cloudflare Access JWT is missing a user email");
  }

  return identity.email;
}

export async function verifyCloudflareAccessJwt(
  token: string,
  config: CloudflareAccessJwtConfig,
  options: CloudflareAccessJwtVerifyOptions = {},
): Promise<boolean> {
  return (await verifyCloudflareAccessJwtIdentity(token, config, options)) !== null;
}

export async function verifyCloudflareAccessJwtIdentity(
  token: string,
  config: CloudflareAccessJwtConfig,
  options: CloudflareAccessJwtVerifyOptions = {},
): Promise<CloudflareAccessIdentity | null> {
  const decoded = decodeJwt(token);
  if (!decoded) {
    return null;
  }

  const expectedTeamDomain = normalizeAccessTeamDomain(config.teamDomain);
  if (!expectedTeamDomain || !tokenClaimsAreValid(decoded, expectedTeamDomain, config.audience, options.now)) {
    return null;
  }

  const kid = decoded.header.kid;
  if (decoded.header.alg !== "RS256" || typeof kid !== "string") {
    return null;
  }

  const fetcher = options.fetcher ?? fetch;
  const keys = await accessKeysForTeamDomain(expectedTeamDomain, fetcher, options.now);
  let jwk = keys.find((candidate) => candidate.kid === kid);
  if (!jwk) {
    const refreshedKeys = await accessKeysForTeamDomain(expectedTeamDomain, fetcher, options.now, true);
    jwk = refreshedKeys.find((candidate) => candidate.kid === kid);
  }

  if (!jwk) {
    return null;
  }

  const verified = await verifyRs256Signature(decoded, jwk);
  if (!verified) {
    return null;
  }

  return {
    email: normalizedEmailClaim(decoded.payload.email),
  };
}

function requireLocalPublishAdminSecret(request: Request, expectedSecret: string): void {
  const actualSecret = request.headers.get(LOCAL_PUBLISH_ADMIN_SECRET_HEADER);
  if (!actualSecret) {
    throw new HttpError(401, "missing_publish_admin_secret", "Missing local publish/admin secret");
  }

  if (!constantTimeEqual(actualSecret, expectedSecret)) {
    throw new HttpError(403, "invalid_publish_admin_secret", "Invalid local publish/admin secret");
  }
}

function cloudflareAccessConfig(env: PublishAdminAccessEnv): CloudflareAccessJwtConfig | null {
  const teamDomain = normalizeAccessTeamDomain(env.PUBLISH_ACCESS_TEAM_DOMAIN);
  const audience = env.PUBLISH_ACCESS_AUD?.trim();
  if (!teamDomain || !audience || isPlaceholder(audience)) {
    return null;
  }

  return {
    teamDomain,
    audience,
  };
}

function normalizeAccessTeamDomain(value: string | undefined): string | null {
  const trimmed = value?.trim().replace(/\/+$/, "");
  if (!trimmed || isPlaceholder(trimmed)) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }

  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash) {
    return null;
  }

  return url.origin;
}

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERN.test(value);
}

function decodeJwt(token: string): DecodedJwt | null {
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

function tokenClaimsAreValid(
  decoded: DecodedJwt,
  expectedIssuer: string,
  expectedAudience: string,
  now = Date.now(),
): boolean {
  const nowSeconds = Math.floor(now / 1000);
  const { payload } = decoded;

  if (payload.iss !== expectedIssuer || !audienceIncludes(payload.aud, expectedAudience)) {
    return false;
  }

  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds - JWT_CLOCK_SKEW_SECONDS) {
    return false;
  }

  if (typeof payload.nbf === "number" && payload.nbf > nowSeconds + JWT_CLOCK_SKEW_SECONDS) {
    return false;
  }

  return true;
}

function audienceIncludes(value: unknown, expectedAudience: string): boolean {
  if (typeof value === "string") {
    return value === expectedAudience;
  }

  return Array.isArray(value) && value.some((item) => item === expectedAudience);
}

function normalizedEmailClaim(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const email = value.trim().toLowerCase();
  return email.includes("@") ? email : null;
}

async function accessKeysForTeamDomain(
  teamDomain: string,
  fetcher: AccessCertsFetcher,
  now = Date.now(),
  forceRefresh = false,
): Promise<AccessJwk[]> {
  const cached = accessJwksCache.get(teamDomain);
  if (!forceRefresh && cached && cached.expiresAt > now) {
    return cached.keys;
  }

  const response = await fetcher(`${teamDomain}/cdn-cgi/access/certs`);
  if (!response.ok) {
    throw new Error(`Unable to fetch Cloudflare Access certs: ${response.status}`);
  }

  const body = (await response.json()) as unknown;
  const keys = parseAccessKeys(body);
  accessJwksCache.set(teamDomain, {
    keys,
    expiresAt: now + ACCESS_CERTS_CACHE_MS,
  });

  return keys;
}

function parseAccessKeys(value: unknown): AccessJwk[] {
  if (!isRecord(value) || !Array.isArray(value.keys)) {
    return [];
  }

  return value.keys.filter(isAccessJwk);
}

function isAccessJwk(value: unknown): value is AccessJwk {
  if (!isRecord(value)) {
    return false;
  }

  return (
    value.kty === "RSA" &&
    typeof value.kid === "string" &&
    typeof value.n === "string" &&
    typeof value.e === "string" &&
    (value.alg === undefined || value.alg === "RS256")
  );
}

async function verifyRs256Signature(decoded: DecodedJwt, jwk: AccessJwk): Promise<boolean> {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
