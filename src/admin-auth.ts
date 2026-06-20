import { constantTimeEqual } from "./encoding";
import { HttpError } from "./http";
import {
  decodeJwt,
  jwtClaimsAreValid,
  parseRsaPublicJwks,
  verifyRs256JwtSignature,
  type RsaPublicJwk,
} from "./jwt";

export const CLOUDFLARE_ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion";
export const LOCAL_PUBLISH_ADMIN_SECRET_HEADER = "X-Publish-Admin-Secret";

const ACCESS_CERTS_CACHE_MS = 10 * 60 * 1000;
const JWT_CLOCK_SKEW_SECONDS = 60;
const PLACEHOLDER_PATTERN = /<|>|YOUR_|REPLACE_/i;

type AccessCertsFetcher = typeof fetch;

interface CachedAccessKeys {
  keys: RsaPublicJwk[];
  expiresAt: number;
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
  if (
    !expectedTeamDomain ||
    !jwtClaimsAreValid(decoded, {
      clockSkewSeconds: JWT_CLOCK_SKEW_SECONDS,
      expectedAudience: config.audience,
      expectedIssuer: expectedTeamDomain,
      now: options.now,
    })
  ) {
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

  const verified = await verifyRs256JwtSignature(decoded, jwk);
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
): Promise<RsaPublicJwk[]> {
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

function parseAccessKeys(value: unknown): RsaPublicJwk[] {
  return parseRsaPublicJwks(value);
}
