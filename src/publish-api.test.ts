import { describe, expect, it, vi } from "vitest";

import worker from "./index";
import { INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER } from "./mcp";
import { hardDeletePreview, type PreviewRow } from "./preview-store";
import type { PreviewAssetRow } from "./preview-assets";
import { signAccessCookie } from "./security";
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
  it("requires a slug", async () => {
    const response = await publishPreview(without(basePayload(), "slug"), createApiPublishEnv());

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "missing_slug",
      },
    });
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

  it("rejects removed allowScripts input", async () => {
    const response = await publishPreview(basePayload({ allowScripts: true }), createApiPublishEnv());

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_request",
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

  it("updates HTML and replaces image attachments without rotating viewer cookies", async () => {
    const existingPreview = previewRow({
      slug: customSlug,
      object_key: "previews/objects/old/index.html",
    });
    const existingAsset = previewAssetRow({
      slug: customSlug,
      asset_id: "oldasset",
      object_key: "previews/objects/old/assets/oldasset",
    });
    const bucket = createTestR2Bucket({
      [existingPreview.object_key]: '<!doctype html><html><body><img src="cid:old.png">Old</body></html>',
      [existingAsset.object_key]: existingAssetBody,
    });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      assets: [existingAsset],
      bucket,
    });
    const viewerCookie = await accessCookie(customSlug, existingPreview.password_version);

    const updated = await apiRequest(
      "PUT",
      `/v1/html-previews/${customSlug}`,
      {
        html: '<!doctype html><html><body><h1>Updated</h1><img src="cid:proof.png"></body></html>',
        title: "Updated Page",
        images: [
          {
            name: "proof.png",
            mimeType: "image/png",
            dataBase64: tinyPngBase64,
          },
        ],
      },
      env,
    );
    const updatedBody = (await updated.json()) as { slug: string; url: string };

    expect(updated.status).toBe(200);
    expect(updatedBody).toMatchObject({
      slug: customSlug,
      url: `${testOrigins.previewBaseUrl}/p/${customSlug}`,
    });
    expect(await r2Text(bucket, existingPreview.object_key)).toBeNull();
    expect(await r2Text(bucket, existingAsset.object_key)).toBeNull();

    const preview = await worker.fetch(
      requestOn("http://localhost:8787", `/p/${customSlug}`, {
        headers: { Cookie: `html_preview_access=${viewerCookie}` },
      }),
      env as never,
    );
    const html = await preview.text();
    const assetPath = html.match(/\/p\/hello-world-test\/assets\/[A-Za-z0-9_-]+/)?.[0];
    expect(preview.status).toBe(200);
    expect(html).toContain("<h1>Updated</h1>");
    expect(html).not.toContain("cid:proof.png");
    expect(assetPath).toBeTruthy();
  });

  it("rejects updates from a different OAuth actor", async () => {
    const existingPreview = previewRow({ slug: customSlug });
    const bucket = createTestR2Bucket({
      [existingPreview.object_key]: existingHtml,
    });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      bucket,
    });

    const response = await apiRequest(
      "PUT",
      `/v1/html-previews/${customSlug}`,
      {
        html: "<!doctype html><html><body>owned by someone else</body></html>",
      },
      env,
      "other@example.com",
    );

    expect(response.status).toBe(404);
    expect(await r2Text(bucket, existingPreview.object_key)).toBe(existingHtml);
  });

  it("rotates passwords and invalidates old viewer cookies through the direct API", async () => {
    const existingPreview = previewRow({ slug: customSlug, password_version: 1 });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      bucket: createTestR2Bucket({
        [existingPreview.object_key]: existingHtml,
      }),
    });
    const oldViewerCookie = await accessCookie(customSlug, 1);

    const rotated = await apiRequest(
      "POST",
      `/v1/html-previews/${customSlug}/password`,
      { password: "new correct horse" },
      env,
    );
    const preview = await worker.fetch(
      requestOn("http://localhost:8787", `/p/${customSlug}`, {
        headers: { Cookie: `html_preview_access=${oldViewerCookie}` },
      }),
      env as never,
    );

    expect(rotated.status).toBe(200);
    expect(preview.status).toBe(200);
    expect(await preview.text()).toContain("password protected");
  });

  it("hard deletes through the direct API and frees the slug", async () => {
    const existingPreview = previewRow({ slug: customSlug });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      bucket: createTestR2Bucket({
        [existingPreview.object_key]: existingHtml,
      }),
    });

    const deleted = await apiRequest("DELETE", `/v1/html-previews/${customSlug}`, null, env);
    const republished = await publishPreview(basePayload({ slug: customSlug }), env);

    expect(deleted.status).toBe(200);
    await expect(deleted.json()).resolves.toMatchObject({ slug: customSlug, status: "deleted" });
    expect(republished.status).toBe(201);
  });

  it("frees the slug on hard delete even when private object cleanup fails", async () => {
    const existingPreview = previewRow({ slug: customSlug });
    const bucket = createDeleteFailingBucket({
      [existingPreview.object_key]: existingHtml,
    });
    const env = createApiPublishEnv({
      previews: [existingPreview],
      bucket,
    });
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      const deleted = await apiRequest("DELETE", `/v1/html-previews/${customSlug}`, null, env);
      const republished = await publishPreview(basePayload({ slug: customSlug }), env);

      expect(deleted.status).toBe(200);
      expect(republished.status).toBe(201);
      expect(await r2Text(bucket, existingPreview.object_key)).toBe(existingHtml);
    } finally {
      consoleError.mockRestore();
    }
  });
});

async function publishPreview(payload: Record<string, unknown>, env: ApiPublishTestEnv): Promise<Response> {
  return apiRequest("POST", "/v1/html-previews", payload, env);
}

async function apiRequest(
  method: string,
  path: string,
  payload: Record<string, unknown> | null,
  env: ApiPublishTestEnv,
  actorEmail = "service@example.com",
): Promise<Response> {
  return worker.fetch(
    requestOn(testApiOriginEnv.API_BASE_URL, path, {
      method,
      headers: {
        Authorization: "Bearer dev-publish-token",
        [INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER]: "internal-service-token",
        "X-Publish-Actor-Email": actorEmail,
        "Content-Type": "application/json",
      },
      ...(payload === null ? {} : { body: JSON.stringify(payload) }),
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
    slug: "published-page",
    password: "correct horse",
    ...overrides,
  };
}

function without(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

async function accessCookie(slug: string, passwordVersion: number): Promise<string> {
  return signAccessCookie(
    {
      slug,
      passwordVersion,
      expiresAt: Date.now() + 60_000,
    },
    "test-cookie-secret",
  );
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

function createDeleteFailingBucket(initialObjects: Record<string, string | Uint8Array>): R2Bucket {
  const bucket = createTestR2Bucket(initialObjects);
  bucket.delete = async () => {
    throw new Error("delete failed");
  };
  return bucket;
}

async function r2Text(bucket: R2Bucket, key: string): Promise<string | null> {
  const object = await bucket.get(key);
  return object ? object.text() : null;
}
