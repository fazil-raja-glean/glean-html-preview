import { fromBase64Url, toBase64Url, utf8 } from "../encoding";
import { HttpError } from "../http";

export interface GleanAdminDynamicOAuthEnv {
  ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET?: string;
}

export interface GleanOAuthProviderMetadata {
  authorizationUrl: string;
  issuer?: string;
  jwksUrl?: string;
  registrationUrl?: string;
  tokenUrl: string;
  userinfoUrl?: string;
}

export type GleanTokenEndpointAuthMethod = "client_secret_post" | "none";

export interface GleanAdminOAuthClient {
  clientId: string;
  clientSecret?: string;
  tokenEndpointAuthMethod: GleanTokenEndpointAuthMethod;
}

interface AdminOAuthClientRow {
  api_base_url: string;
  client_id: string;
  client_secret_ciphertext: string | null;
  client_secret_iv: string | null;
  created_at: string;
  expires_at: string | null;
  id: string;
  issuer: string;
  metadata_json: string;
  redirect_uri: string;
  scopes: string;
  token_endpoint_auth_method: string;
  updated_at: string;
}

const ADMIN_CLIENT_NAME = "Glean HTML Preview Admin";
const ADMIN_DCR_SECRET_PURPOSE = "admin-dynamic-oauth-client-secret:v1";
export const ADMIN_GLEAN_OAUTH_SCOPES = "openid email";

export async function getAdminDynamicOAuthClient(
  env: GleanAdminDynamicOAuthEnv & { PREVIEW_DB?: D1Database },
  provider: GleanOAuthProviderMetadata,
  input: {
    callbackUrl: string;
  },
): Promise<GleanAdminOAuthClient> {
  const db = requiredDb(env);
  const secret = encryptionSecret(env);
  const issuer = requiredIssuer(provider);
  const callbackUrl = normalizedUrl(input.callbackUrl, "admin OAuth callback URL");
  const apiBaseUrl = new URL(callbackUrl).origin;
  const scopes = ADMIN_GLEAN_OAUTH_SCOPES;
  const registration = await readStoredClient(db, secret, {
    apiBaseUrl,
    callbackUrl,
    issuer,
    scopes,
  });
  if (registration) {
    return registration;
  }

  const created = await registerClient(provider, {
    callbackUrl,
    scopes,
  });
  await storeClient(db, secret, {
    apiBaseUrl,
    callbackUrl,
    issuer,
    scopes,
    client: created,
  });

  return publicClient(created);
}

async function readStoredClient(
  db: D1Database,
  encryptionKeyText: string,
  key: {
    apiBaseUrl: string;
    callbackUrl: string;
    issuer: string;
    scopes: string;
  },
): Promise<GleanAdminOAuthClient | null> {
  const row = await db.prepare("SELECT * FROM admin_oauth_clients WHERE issuer = ? AND api_base_url = ?")
    .bind(key.issuer, key.apiBaseUrl)
    .first<AdminOAuthClientRow>();
  if (!row || row.redirect_uri !== key.callbackUrl || row.scopes !== key.scopes || isExpired(row.expires_at)) {
    return null;
  }

  const tokenEndpointAuthMethod = parseTokenEndpointAuthMethod(row.token_endpoint_auth_method, !!row.client_secret_ciphertext);
  return {
    clientId: row.client_id,
    tokenEndpointAuthMethod,
    ...(row.client_secret_ciphertext
      ? {
          clientSecret: await decryptClientSecret(encryptionKeyText, {
            ciphertext: row.client_secret_ciphertext,
            iv: requiredStoredIv(row),
          }),
        }
      : {}),
  };
}

async function registerClient(
  provider: GleanOAuthProviderMetadata,
  input: {
    callbackUrl: string;
    scopes: string;
  },
): Promise<GleanAdminOAuthClient & { expiresAt: string | null; metadata: Record<string, unknown> }> {
  const response = await fetch(registrationUrl(provider), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_name: ADMIN_CLIENT_NAME,
      grant_types: ["authorization_code"],
      redirect_uris: [input.callbackUrl],
      response_types: ["code"],
      scope: input.scopes,
      token_endpoint_auth_method: "client_secret_post",
    }),
  });
  if (!response.ok) {
    throw new HttpError(500, "glean_admin_oauth_registration_failed", "Glean dynamic OAuth registration failed");
  }

  const metadata = await readRegistrationMetadata(response);
  const clientId = stringField(metadata, "client_id");
  if (!clientId) {
    throw new HttpError(500, "invalid_glean_admin_oauth_registration", "Glean dynamic OAuth registration did not return a client_id");
  }

  validateRedirectUris(metadata, input.callbackUrl);
  const clientSecret = stringField(metadata, "client_secret");
  const tokenEndpointAuthMethod = parseTokenEndpointAuthMethod(
    stringField(metadata, "token_endpoint_auth_method"),
    !!clientSecret,
  );
  if (tokenEndpointAuthMethod === "client_secret_post" && !clientSecret) {
    throw new HttpError(
      500,
      "invalid_glean_admin_oauth_registration",
      "Glean dynamic OAuth registration requires client_secret_post but did not return a client_secret",
    );
  }

  return {
    clientId,
    tokenEndpointAuthMethod,
    metadata: sanitizedMetadata(metadata),
    expiresAt: clientSecretExpiresAt(metadata),
    ...(clientSecret ? { clientSecret } : {}),
  };
}

async function storeClient(
  db: D1Database,
  encryptionKeyText: string,
  input: {
    apiBaseUrl: string;
    callbackUrl: string;
    client: GleanAdminOAuthClient & { expiresAt: string | null; metadata: Record<string, unknown> };
    issuer: string;
    scopes: string;
  },
): Promise<void> {
  const encryptedSecret = input.client.clientSecret
    ? await encryptClientSecret(encryptionKeyText, input.client.clientSecret)
    : null;
  const now = new Date().toISOString();

  await db.prepare(
    `INSERT OR REPLACE INTO admin_oauth_clients (
      id,
      issuer,
      api_base_url,
      redirect_uri,
      client_id,
      client_secret_ciphertext,
      client_secret_iv,
      token_endpoint_auth_method,
      scopes,
      metadata_json,
      created_at,
      updated_at,
      expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM admin_oauth_clients WHERE id = ?), ?), ?, ?)`,
  )
    .bind(
      registrationId(input.issuer, input.apiBaseUrl),
      input.issuer,
      input.apiBaseUrl,
      input.callbackUrl,
      input.client.clientId,
      encryptedSecret?.ciphertext ?? null,
      encryptedSecret?.iv ?? null,
      input.client.tokenEndpointAuthMethod,
      input.scopes,
      JSON.stringify(input.client.metadata),
      registrationId(input.issuer, input.apiBaseUrl),
      now,
      now,
      input.client.expiresAt,
    )
    .run();
}

function registrationUrl(provider: GleanOAuthProviderMetadata): string {
  if (provider.registrationUrl) {
    return normalizedUrl(provider.registrationUrl, "Glean OAuth registration URL");
  }

  const issuer = requiredIssuer(provider);
  return new URL("/oauth/register", issuer).toString();
}

function publicClient(client: GleanAdminOAuthClient): GleanAdminOAuthClient {
  return {
    clientId: client.clientId,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    ...(client.clientSecret ? { clientSecret: client.clientSecret } : {}),
  };
}

function validateRedirectUris(metadata: Record<string, unknown>, callbackUrl: string): void {
  const redirectUris = metadata.redirect_uris;
  if (redirectUris === undefined) {
    return;
  }

  if (!Array.isArray(redirectUris) || !redirectUris.includes(callbackUrl)) {
    throw new HttpError(
      500,
      "invalid_glean_admin_oauth_registration",
      "Glean dynamic OAuth registration returned unexpected redirect_uris",
    );
  }
}

function parseTokenEndpointAuthMethod(value: string | null, hasClientSecret: boolean): GleanTokenEndpointAuthMethod {
  if (!value) {
    return hasClientSecret ? "client_secret_post" : "none";
  }

  if (value === "client_secret_post" || value === "none") {
    return value;
  }

  throw new HttpError(
    500,
    "unsupported_glean_admin_oauth_client_auth",
    "Glean dynamic OAuth registration returned an unsupported token endpoint auth method",
  );
}

async function readRegistrationMetadata(response: Response): Promise<Record<string, unknown>> {
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new HttpError(500, "glean_admin_oauth_registration_not_json", "Glean dynamic OAuth registration response was not valid JSON");
  }

  if (!isRecord(value)) {
    throw new HttpError(500, "glean_admin_oauth_registration_not_json", "Glean dynamic OAuth registration response was not a JSON object");
  }

  return value;
}

function sanitizedMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...metadata };
  delete copy.client_secret;
  return copy;
}

function clientSecretExpiresAt(metadata: Record<string, unknown>): string | null {
  const value = metadata.client_secret_expires_at;
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? new Date(value * 1000).toISOString()
    : null;
}

async function encryptClientSecret(secret: string, plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(ADMIN_DCR_SECRET_PURPOSE) },
    await aesKey(secret),
    utf8(plaintext),
  );

  return {
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
    iv: toBase64Url(iv),
  };
}

async function decryptClientSecret(
  secret: string,
  input: {
    ciphertext: string;
    iv: string;
  },
): Promise<string> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(input.iv), additionalData: utf8(ADMIN_DCR_SECRET_PURPOSE) },
      await aesKey(secret),
      fromBase64Url(input.ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new HttpError(500, "invalid_admin_oauth_client_secret", "Stored admin OAuth client secret could not be decrypted");
  }
}

async function aesKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", utf8(secret));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function registrationId(issuer: string, apiBaseUrl: string): string {
  return `${issuer}|${apiBaseUrl}`;
}

function requiredDb(env: GleanAdminDynamicOAuthEnv & { PREVIEW_DB?: D1Database }): D1Database {
  if (!env.PREVIEW_DB) {
    throw new HttpError(500, "missing_admin_oauth_client_store", "PREVIEW_DB is required for admin dynamic OAuth");
  }

  return env.PREVIEW_DB;
}

function encryptionSecret(env: GleanAdminDynamicOAuthEnv): string {
  const value = env.ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET?.trim();
  if (!value) {
    throw new HttpError(
      500,
      "missing_admin_dynamic_oauth_encryption_secret",
      "ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET is not configured",
    );
  }

  return value;
}

function requiredIssuer(provider: GleanOAuthProviderMetadata): string {
  if (!provider.issuer) {
    throw new HttpError(500, "missing_glean_oauth_issuer", "GLEAN_OAUTH_ISSUER or discovery issuer is required");
  }

  return provider.issuer;
}

function requiredStoredIv(row: AdminOAuthClientRow): string {
  if (!row.client_secret_iv) {
    throw new HttpError(500, "invalid_admin_oauth_client_secret", "Stored admin OAuth client secret is missing its IV");
  }

  return row.client_secret_iv;
}

function normalizedUrl(value: string, label: string): string {
  try {
    return new URL(value).toString();
  } catch {
    throw new HttpError(500, "invalid_admin_oauth_url", `${label} is not a valid URL`);
  }
}

function stringField(value: Record<string, unknown>, key: string): string | null {
  const field = value[key];
  return typeof field === "string" && field.trim() !== "" ? field : null;
}

function isExpired(expiresAt: string | null): boolean {
  if (!expiresAt) {
    return false;
  }

  const expiry = Date.parse(expiresAt);
  return !Number.isFinite(expiry) || expiry <= Date.now();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
