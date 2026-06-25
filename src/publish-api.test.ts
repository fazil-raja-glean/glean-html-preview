import { describe, expect, it } from "vitest";

import worker from "./index";
import { INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER } from "./mcp";
import { hardDeletePreview, type PreviewRow } from "./preview-store";
import type { PreviewAssetRow } from "./preview-assets";
import { createTestPreviewDb, createTestR2Bucket, requestOn, testApiOriginEnv, testOrigins } from "./test-fixtures";

const customSlug = "hello-world-test";
const completeHtml = "<!doctype html><html><body><h1>Hello</h1></body></html>";
const existingHtml = "<!doctype html><html><body><h1>Existing</h1></body></html>";
const existingAssetBody = "existing asset bytes";
const tinyPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";

interface ApiPublishTestEnv {
  API_BASE_URL: string;
  COOKIE_SIGNING_SECRET: string;
  HTML_PREVIEWS: R2Bucket;
  MCP_BASE_URL: string;
  PASSWORD_PEPPER: string;
  PREVIEW_DB: D1Database;
  PUBLIC_BASE_URL: string;
  PUBLISHER_EMAIL_DOMAIN: string;
  PUBLISH_API_TOKEN: string;
  PUBLISH_INTERNAL_SERVICE_TOKEN: string;
  TRUSTED_PUBLISHER_EMAIL: string;
  WORKER_ROLE: string;
}

describe("publish API custom slugs", () => {
  it("keeps random slug publishing when slug is omitted", async () => {
    const response = await publishPreview(basePayload(), createApiPublishEnv());
    const body = (await response.json()) as { slug: string; url: string };

    expect(response.status).toBe(201);
    expect(body.slug).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(body.url).toBe(`${testOrigins.previewBaseUrl}/p/${body.slug}`);
  });

  it("publishes at the requested custom slug when it is available", async () => {
    const response = await publishPreview(basePayload({ slug: customSlug }), createApiPublishEnv());
    const body = (await response.json()) as { slug: string; url: string };

    expect(response.status).toBe(201);
    expect(body).toMatchObject({
      slug: customSlug,
      url: `${testOrigins.previewBaseUrl}/p/${customSlug}`,
    });
  });

  it("rejects invalid custom slugs with invalid_slug", async () => {
    const response = await publishPreview(basePayload({ slug: "Hello_World" }), createApiPublishEnv());

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_slug",
      },
    });
  });

  it("returns slug_taken without overwriting existing HTML or asset objects", async () => {
    const existingPreview = previewRow({
      slug: customSlug,
      object_key: `previews/${customSlug}/index.html`,
    });
    const existingAsset = previewAssetRow({
      slug: customSlug,
      object_key: `previews/${customSlug}/assets/existing-asset`,
    });
    const { bucket, putKeys } = trackedR2Bucket({
      [existingPreview.object_key]: existingHtml,
      [existingAsset.object_key]: existingAssetBody,
    });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      assets: [existingAsset],
      bucket,
    });

    const response = await publishPreview(
      basePayload({
        slug: customSlug,
        html: "<!doctype html><html><body><h1>New</h1><img src=\"cid:proof.png\"></body></html>",
        images: [
          {
            name: "proof.png",
            mimeType: "image/png",
            dataBase64: tinyPngBase64,
          },
        ],
      }),
      env,
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "slug_taken",
        message: "Slug is already in use",
      },
    });
    expect(await r2Text(bucket, existingPreview.object_key)).toBe(existingHtml);
    expect(await r2Text(bucket, existingAsset.object_key)).toBe(existingAssetBody);
    expect(putKeys).toHaveLength(2);
    expect(putKeys.every((key) => key.startsWith("previews/objects/"))).toBe(true);
    expect(putKeys).not.toContain(existingPreview.object_key);
    expect(putKeys).not.toContain(existingAsset.object_key);
    expect(await r2Text(bucket, putKeys[0])).toBeNull();
    expect(await r2Text(bucket, putKeys[1])).toBeNull();
  });

  it.each([
    {
      label: "soft-deleted",
      row: previewRow({ slug: customSlug, deleted_at: "2026-06-22T12:00:00.000Z" }),
    },
    {
      label: "expired",
      row: previewRow({ slug: customSlug, expires_at: "2000-01-01T00:00:00.000Z" }),
    },
  ])("keeps $label preview slugs reserved", async ({ row }) => {
    const response = await publishPreview(basePayload({ slug: customSlug }), createApiPublishEnv({ previews: [row] }));

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "slug_taken",
      },
    });
  });

  it("allows a hard-deleted preview slug to be reused", async () => {
    const existingPreview = previewRow({
      slug: customSlug,
      object_key: `previews/${customSlug}/index.html`,
    });
    const bucket = createTestR2Bucket({
      [existingPreview.object_key]: existingHtml,
    });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      bucket,
    });

    await hardDeletePreview(env, customSlug);
    const response = await publishPreview(basePayload({ slug: customSlug }), env);
    const body = (await response.json()) as { slug: string; url: string };

    expect(response.status).toBe(201);
    expect(body.slug).toBe(customSlug);
    expect(body.url).toBe(`${testOrigins.previewBaseUrl}/p/${customSlug}`);
  });
});

async function publishPreview(payload: Record<string, unknown>, env: ApiPublishTestEnv): Promise<Response> {
  return worker.fetch(
    requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews", {
      method: "POST",
      headers: {
        Authorization: "Bearer dev-publish-token",
        [INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER]: "internal-service-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }),
    env as never,
  );
}

function createApiPublishEnv(
  options: {
    assets?: PreviewAssetRow[];
    bucket?: R2Bucket;
    previews?: PreviewRow[];
  } = {},
): ApiPublishTestEnv {
  return {
    ...testApiOriginEnv,
    COOKIE_SIGNING_SECRET: "test-cookie-secret",
    HTML_PREVIEWS: options.bucket ?? createTestR2Bucket(),
    PASSWORD_PEPPER: "pepper",
    PREVIEW_DB: createTestPreviewDb(options.previews ?? [], options.assets ?? []),
    PUBLISH_API_TOKEN: "dev-publish-token",
    PUBLISH_INTERNAL_SERVICE_TOKEN: "internal-service-token",
    PUBLISHER_EMAIL_DOMAIN: "example.com",
    TRUSTED_PUBLISHER_EMAIL: "service@example.com",
  };
}

function basePayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    title: "Published Page",
    html: completeHtml,
    password: "correct horse",
    ...overrides,
  };
}

function previewRow(overrides: Partial<PreviewRow> = {}): PreviewRow {
  return {
    slug: "abc123",
    title: "Existing Preview",
    object_key: "previews/abc123/index.html",
    password_hash: "hash",
    password_salt: "salt",
    password_iterations: 100_000,
    password_version: 1,
    publisher_email: "service@example.com",
    source_url: null,
    created_at: "2026-06-20T12:00:00.000Z",
    expires_at: "2099-06-20T12:00:00.000Z",
    deleted_at: null,
    ...overrides,
  };
}

function previewAssetRow(overrides: Partial<PreviewAssetRow> = {}): PreviewAssetRow {
  return {
    slug: "abc123",
    asset_id: "asset123",
    object_key: "previews/abc123/assets/asset123",
    content_type: "image/png",
    byte_size: existingAssetBody.length,
    original_name: "proof.png",
    created_at: "2026-06-20T12:00:00.000Z",
    ...overrides,
  };
}

function trackedR2Bucket(initialObjects: Record<string, string | Uint8Array>): {
  bucket: R2Bucket;
  putKeys: string[];
} {
  const bucket = createTestR2Bucket(initialObjects);
  const putKeys: string[] = [];
  return {
    bucket: {
      get: bucket.get.bind(bucket),
      put: async (
        key: string,
        value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
        options?: R2PutOptions,
      ) => {
        putKeys.push(key);
        return bucket.put(key, value, options);
      },
      delete: bucket.delete.bind(bucket),
    } as R2Bucket,
    putKeys,
  };
}

async function r2Text(bucket: R2Bucket, key: string): Promise<string | null> {
  const object = await bucket.get(key);
  return object ? object.text() : null;
}
