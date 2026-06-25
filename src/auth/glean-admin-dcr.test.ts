import { afterEach, describe, expect, it, vi } from "vitest";

import { createTestPreviewDb } from "../test-fixtures";
import { ADMIN_GLEAN_OAUTH_SCOPES, getAdminDynamicOAuthClient, type GleanOAuthProviderMetadata } from "./glean-admin-dcr";

const provider: GleanOAuthProviderMetadata = {
  issuer: "https://glean.example.test/oauth",
  authorizationUrl: "https://glean.example.test/oauth/authorize",
  tokenUrl: "https://glean.example.test/oauth/token",
  registrationUrl: "https://glean.example.test/oauth/register",
  userinfoUrl: "https://glean.example.test/oauth/userinfo",
};

const baseEnv = {
  ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET: "dynamic-oauth-encryption-secret",
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("admin dynamic Glean OAuth client registration", () => {
  it("registers once, encrypts returned client secrets, and reuses the stored client", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    const fetchMock = mockRegistration({
      client_id: "dynamic-admin-client",
      client_secret: "dynamic-admin-secret",
      redirect_uris: ["https://api.example.test/auth/callback"],
      scope: ADMIN_GLEAN_OAUTH_SCOPES,
      token_endpoint_auth_method: "client_secret_post",
    });

    const first = await getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    });
    const second = await getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    });

    expect(first).toEqual({
      clientId: "dynamic-admin-client",
      clientSecret: "dynamic-admin-secret",
      tokenEndpointAuthMethod: "client_secret_post",
    });
    expect(second).toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fails closed when a stored client secret cannot be decrypted", async () => {
    const db = createTestPreviewDb();
    const fetchMock = mockRegistration({
      client_id: "dynamic-admin-client",
      client_secret: "dynamic-admin-secret",
      redirect_uris: ["https://api.example.test/auth/callback"],
      scope: ADMIN_GLEAN_OAUTH_SCOPES,
      token_endpoint_auth_method: "client_secret_post",
    });

    await getAdminDynamicOAuthClient({ ...baseEnv, PREVIEW_DB: db }, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    });

    await expect(getAdminDynamicOAuthClient(
      {
        ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET: "wrong-dynamic-oauth-encryption-secret",
        PREVIEW_DB: db,
      },
      provider,
      {
        callbackUrl: "https://api.example.test/auth/callback",
      },
    )).rejects.toThrow("could not be decrypted");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("supports public PKCE registrations without a client secret", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    mockRegistration({
      client_id: "public-admin-client",
      redirect_uris: ["https://api.example.test/auth/callback"],
      scope: ADMIN_GLEAN_OAUTH_SCOPES,
      token_endpoint_auth_method: "none",
    });

    await expect(getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    })).resolves.toEqual({
      clientId: "public-admin-client",
      tokenEndpointAuthMethod: "none",
    });
  });

  it("fails closed when dynamic OAuth encryption is not configured", async () => {
    const fetchMock = mockRegistration({
      client_id: "unused-client",
      redirect_uris: ["https://api.example.test/auth/callback"],
    });

    await expect(getAdminDynamicOAuthClient(
      { PREVIEW_DB: createTestPreviewDb() },
      provider,
      {
        callbackUrl: "https://api.example.test/auth/callback",
      },
    )).rejects.toThrow("ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET is not configured");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails closed when Glean returns mismatched redirect URIs", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    mockRegistration({
      client_id: "bad-redirect-client",
      redirect_uris: ["https://evil.example.test/auth/callback"],
    });

    await expect(getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    })).rejects.toThrow("unexpected redirect_uris");
  });

  it("accepts broader returned DCR scopes but reuses the requested admin scope registration", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    const fetchMock = mockRegistration({
      client_id: "broad-scope-client",
      client_secret: "dynamic-admin-secret",
      redirect_uris: ["https://api.example.test/auth/callback"],
      scope: `${ADMIN_GLEAN_OAUTH_SCOPES} chat documents search`,
      token_endpoint_auth_method: "client_secret_post",
    });

    const first = await getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    });
    const second = await getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    });

    expect(first).toEqual({
      clientId: "broad-scope-client",
      clientSecret: "dynamic-admin-secret",
      tokenEndpointAuthMethod: "client_secret_post",
    });
    expect(second).toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("accepts registrations when Glean omits returned scopes", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    mockRegistration({
      client_id: "missing-scope-client",
      client_secret: "dynamic-admin-secret",
      redirect_uris: ["https://api.example.test/auth/callback"],
      token_endpoint_auth_method: "client_secret_post",
    });

    await expect(getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    })).resolves.toEqual({
      clientId: "missing-scope-client",
      clientSecret: "dynamic-admin-secret",
      tokenEndpointAuthMethod: "client_secret_post",
    });
  });

  it("fails closed when Glean rejects dynamic client registration", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    mockRegistration({ error: "invalid_redirect_uri" }, 400);

    await expect(getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    })).rejects.toThrow("Glean dynamic OAuth registration failed");
  });

  it("fails closed when Glean returns invalid registration metadata", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("not-json", {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    })).rejects.toThrow("response was not valid JSON");
  });

  it("fails closed when the registration response omits client_id", async () => {
    const env = { ...baseEnv, PREVIEW_DB: createTestPreviewDb() };
    mockRegistration({
      redirect_uris: ["https://api.example.test/auth/callback"],
    });

    await expect(getAdminDynamicOAuthClient(env, provider, {
      callbackUrl: "https://api.example.test/auth/callback",
    })).rejects.toThrow("did not return a client_id");
  });
});

function mockRegistration(body: Record<string, unknown>, status = 201) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}
