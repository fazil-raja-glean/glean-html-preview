import { describe, expect, it } from "vitest";

import {
  CLOUDFLARE_ACCESS_JWT_HEADER,
  LOCAL_PUBLISH_ADMIN_SECRET_HEADER,
  requirePublishAdminAccess,
  verifyCloudflareAccessJwt,
} from "./admin-auth";
import { toBase64Url, utf8 } from "./encoding";
import worker from "./index";
import { INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER } from "./mcp";
import { requestOn, testApiOriginEnv } from "./test-fixtures";

const apiWorkerEnv = {
  ...testApiOriginEnv,
  PUBLISH_API_TOKEN: "dev-publish-token",
  PUBLISH_INTERNAL_SERVICE_TOKEN: "internal-service-token",
} as const;

describe("publish/admin access gate", () => {
  it.each([
    "/v1/html-previews",
    "/v1/html-previews/abc123/unpublish",
    "/v1/html-previews/abc123/password",
  ])("rejects %s before mutation when the second lock is missing", async (pathname) => {
    const response = await worker.fetch(
      new Request(`http://localhost:8787${pathname}`, {
        method: "POST",
        headers: {
          Authorization: "Bearer dev-publish-token",
          "Content-Type": "application/json",
        },
        body: "{}",
      }),
      {
        PUBLISH_API_TOKEN: "dev-publish-token",
        PUBLISH_ADMIN_LOCAL_BYPASS_SECRET: "dev-second-lock",
      } as never,
    );

    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "missing_publish_admin_secret",
      },
    });
    expect(response.status).toBe(401);
  });

  it("requires the localhost-only admin secret when configured for local development", async () => {
    const env = {
      PUBLISH_ADMIN_LOCAL_BYPASS_SECRET: "dev-second-lock",
    };

    await expect(
      requirePublishAdminAccess(new Request("http://localhost:8787/v1/html-previews"), env, {
        isLocalDevelopment: true,
      }),
    ).rejects.toThrow("Missing local publish/admin secret");

    await expect(
      requirePublishAdminAccess(
        new Request("http://localhost:8787/v1/html-previews", {
          headers: {
            [LOCAL_PUBLISH_ADMIN_SECRET_HEADER]: "wrong",
          },
        }),
        env,
        {
          isLocalDevelopment: true,
        },
      ),
    ).rejects.toThrow("Invalid local publish/admin secret");

    await expect(
      requirePublishAdminAccess(
        new Request("http://localhost:8787/v1/html-previews", {
          headers: {
            [LOCAL_PUBLISH_ADMIN_SECRET_HEADER]: "dev-second-lock",
          },
        }),
        env,
        {
          isLocalDevelopment: true,
        },
      ),
    ).resolves.toEqual({ email: null });
  });

  it("does not accept the local bypass secret for non-local publish/admin requests", async () => {
    await expect(
      requirePublishAdminAccess(
        requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews", {
          headers: {
            [LOCAL_PUBLISH_ADMIN_SECRET_HEADER]: "dev-second-lock",
          },
        }),
        {
          PUBLISH_ADMIN_LOCAL_BYPASS_SECRET: "dev-second-lock",
        },
        {
          isLocalDevelopment: false,
        },
      ),
    ).rejects.toThrow("Publish/admin Cloudflare Access JWT validation is not configured");
  });

  it("accepts the internal service token for MCP-to-API service binding requests", async () => {
    const response = await worker.fetch(
      requestOn(apiWorkerEnv.API_BASE_URL, "/v1/html-previews", {
        method: "POST",
        headers: {
          Authorization: "Bearer dev-publish-token",
          [INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER]: "internal-service-token",
          "Content-Type": "application/json",
        },
        body: "{}",
      }),
      apiWorkerEnv as never,
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_request",
        message: "title must be a string",
      },
    });
  });

  it("rejects incorrect internal service tokens before publish/admin mutation", async () => {
    const response = await worker.fetch(
      requestOn(apiWorkerEnv.API_BASE_URL, "/v1/html-previews", {
        method: "POST",
        headers: {
          Authorization: "Bearer dev-publish-token",
          [INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER]: "wrong",
          "Content-Type": "application/json",
        },
        body: "{}",
      }),
      apiWorkerEnv as never,
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_internal_service_token",
      },
    });
  });

  it("verifies Cloudflare Access JWTs against the configured issuer and audience", async () => {
    const now = Date.parse("2026-06-18T12:00:00.000Z");
    const key = await createTestRsaKey("access-key");
    const token = await signTestAccessJwt(key.privateKey, "access-key", {
      iss: "https://team.cloudflareaccess.com",
      aud: "expected-aud",
      exp: Math.floor(now / 1000) + 300,
    });
    const fetcher = accessCertsFetcher(key.publicJwk);

    await expect(
      verifyCloudflareAccessJwt(
        token,
        {
          teamDomain: "https://team.cloudflareaccess.com",
          audience: "expected-aud",
        },
        {
          fetcher,
          now,
        },
      ),
    ).resolves.toBe(true);

    await expect(
      verifyCloudflareAccessJwt(
        token,
        {
          teamDomain: "https://team.cloudflareaccess.com",
          audience: "wrong-aud",
        },
        {
          fetcher,
          now,
        },
      ),
    ).resolves.toBe(false);
  });

  it("rejects tampered or expired Cloudflare Access JWTs", async () => {
    const now = Date.parse("2026-06-18T12:00:00.000Z");
    const key = await createTestRsaKey("access-key-tampered");
    const fetcher = accessCertsFetcher(key.publicJwk);
    const expiredToken = await signTestAccessJwt(key.privateKey, "access-key-tampered", {
      iss: "https://tampered.cloudflareaccess.com",
      aud: "expected-aud",
      exp: Math.floor(now / 1000) - 120,
    });
    const validToken = await signTestAccessJwt(key.privateKey, "access-key-tampered", {
      iss: "https://tampered.cloudflareaccess.com",
      aud: "expected-aud",
      exp: Math.floor(now / 1000) + 300,
    });
    const [header, , signature] = validToken.split(".");
    const tamperedPayload = toBase64Url(
      utf8(
        JSON.stringify({
          iss: "https://tampered.cloudflareaccess.com",
          aud: "expected-aud",
          exp: Math.floor(now / 1000) + 300,
          email: "attacker@example.com",
        }),
      ),
    );

    await expect(
      verifyCloudflareAccessJwt(
        expiredToken,
        {
          teamDomain: "https://tampered.cloudflareaccess.com",
          audience: "expected-aud",
        },
        {
          fetcher,
          now,
        },
      ),
    ).resolves.toBe(false);

    await expect(
      verifyCloudflareAccessJwt(
        `${header}.${tamperedPayload}.${signature}`,
        {
          teamDomain: "https://tampered.cloudflareaccess.com",
          audience: "expected-aud",
        },
        {
          fetcher,
          now,
        },
      ),
    ).resolves.toBe(false);
  });

  it("accepts the Access JWT header on publish/admin requests", async () => {
    const now = Date.parse("2026-06-18T12:00:00.000Z");
    const key = await createTestRsaKey("access-key-header");
    const token = await signTestAccessJwt(key.privateKey, "access-key-header", {
      iss: "https://header.cloudflareaccess.com",
      aud: "expected-aud",
      exp: Math.floor(now / 1000) + 300,
    });

    await expect(
      requirePublishAdminAccess(
        requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews", {
          headers: {
            [CLOUDFLARE_ACCESS_JWT_HEADER]: token,
          },
        }),
        {
          PUBLISH_ACCESS_TEAM_DOMAIN: "https://header.cloudflareaccess.com",
          PUBLISH_ACCESS_AUD: "expected-aud",
        },
        {
          fetcher: accessCertsFetcher(key.publicJwk),
          isLocalDevelopment: false,
          now,
        },
      ),
    ).resolves.toEqual({ email: null });
  });

  it("extracts the verified Cloudflare Access email when present", async () => {
    const now = Date.parse("2026-06-18T12:00:00.000Z");
    const key = await createTestRsaKey("access-key-email");
    const token = await signTestAccessJwt(key.privateKey, "access-key-email", {
      iss: "https://email.cloudflareaccess.com",
      aud: "expected-aud",
      exp: Math.floor(now / 1000) + 300,
      email: "Publisher@Example.com",
    });

    await expect(
      requirePublishAdminAccess(
        requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews", {
          headers: {
            [CLOUDFLARE_ACCESS_JWT_HEADER]: token,
          },
        }),
        {
          PUBLISH_ACCESS_TEAM_DOMAIN: "https://email.cloudflareaccess.com",
          PUBLISH_ACCESS_AUD: "expected-aud",
        },
        {
          fetcher: accessCertsFetcher(key.publicJwk),
          isLocalDevelopment: false,
          now,
        },
      ),
    ).resolves.toEqual({ email: "publisher@example.com" });
  });
});

async function createTestRsaKey(kid: string): Promise<{
  privateKey: CryptoKey;
  publicJwk: JsonWebKey & { kid: string };
}> {
  const keyPair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey & { kid: string };
  publicJwk.kid = kid;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";

  return {
    privateKey: keyPair.privateKey,
    publicJwk,
  };
}

async function signTestAccessJwt(
  privateKey: CryptoKey,
  kid: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const encodedHeader = toBase64Url(
    utf8(
      JSON.stringify({
        alg: "RS256",
        kid,
        typ: "JWT",
      }),
    ),
  );
  const encodedPayload = toBase64Url(utf8(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    privateKey,
    utf8(signingInput),
  );

  return `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
}

function accessCertsFetcher(publicJwk: JsonWebKey): typeof fetch {
  return async () =>
    new Response(
      JSON.stringify({
        keys: [publicJwk],
      }),
      {
        headers: {
          "Content-Type": "application/json",
        },
      },
    );
}
