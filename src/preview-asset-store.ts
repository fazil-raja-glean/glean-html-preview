import { HttpError } from "./http";
import type { PreviewAssetRow, PreviewAssetUpload, StoredPreviewAsset } from "./preview-assets";

export interface PreviewAssetStoreEnv {
  HTML_PREVIEWS: R2Bucket;
  PREVIEW_DB: D1Database;
}

export interface PreviewAssetObject {
  body: ReadableStream;
  contentType: string;
}

export interface PreviewObjectRef {
  objectKey: string;
  slug: string;
}

export async function putPreviewObjects(
  env: PreviewAssetStoreEnv,
  input: {
    createdAt: string;
    html: string;
    assets: PreviewAssetUpload[];
    objectKey: string;
    publisherEmail: string;
    slug: string;
    title: string;
  },
): Promise<void> {
  await Promise.all([
    env.HTML_PREVIEWS.put(input.objectKey, input.html, {
      httpMetadata: {
        contentType: "text/html; charset=utf-8",
      },
      customMetadata: {
        slug: input.slug,
        title: input.title,
        publisherEmail: input.publisherEmail,
        createdAt: input.createdAt,
      },
    }),
    ...input.assets.map((asset) =>
      env.HTML_PREVIEWS.put(asset.objectKey, asset.bytes, {
        httpMetadata: {
          contentType: asset.contentType,
        },
        customMetadata: {
          slug: input.slug,
          assetId: asset.assetId,
          originalName: asset.originalName,
          publisherEmail: input.publisherEmail,
          createdAt: input.createdAt,
        },
      }),
    ),
  ]);
}

export function previewAssetInsertStatements(
  env: PreviewAssetStoreEnv,
  assets: StoredPreviewAsset[],
  createdAt: string,
): D1PreparedStatement[] {
  return assets.map((asset) =>
    env.PREVIEW_DB.prepare(
      `INSERT INTO preview_assets (
        slug,
        asset_id,
        object_key,
        content_type,
        byte_size,
        original_name,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      asset.slug,
      asset.assetId,
      asset.objectKey,
      asset.contentType,
      asset.byteSize,
      asset.originalName,
      createdAt,
    ),
  );
}

export async function readPreviewAsset(
  env: PreviewAssetStoreEnv,
  slug: string,
  assetId: string,
): Promise<PreviewAssetObject> {
  const asset = await getPreviewAssetRow(env, slug, assetId);
  const object = await env.HTML_PREVIEWS.get(asset.object_key);
  if (!object?.body) {
    throw new HttpError(404, "preview_asset_missing", "Preview asset is missing");
  }

  return {
    body: object.body,
    contentType: asset.content_type,
  };
}

export async function deletePreviewObjects(env: PreviewAssetStoreEnv, preview: PreviewObjectRef): Promise<void> {
  const assets = await listPreviewAssets(env, preview.slug);
  await Promise.all(
    [preview.objectKey, ...assets.map((asset) => asset.object_key)].map((key) => env.HTML_PREVIEWS.delete(key)),
  );
}

export async function deletePreviewAssetRows(env: PreviewAssetStoreEnv, slug: string): Promise<void> {
  await env.PREVIEW_DB.prepare("DELETE FROM preview_assets WHERE slug = ?").bind(slug).run();
}

export async function listPreviewAssets(env: PreviewAssetStoreEnv, slug: string): Promise<PreviewAssetRow[]> {
  const result = await env.PREVIEW_DB.prepare("SELECT * FROM preview_assets WHERE slug = ?")
    .bind(slug)
    .all<PreviewAssetRow>();
  return result.results;
}

async function getPreviewAssetRow(env: PreviewAssetStoreEnv, slug: string, assetId: string): Promise<PreviewAssetRow> {
  const asset = await env.PREVIEW_DB.prepare("SELECT * FROM preview_assets WHERE slug = ? AND asset_id = ?")
    .bind(slug, assetId)
    .first<PreviewAssetRow>();
  if (!asset) {
    throw new HttpError(404, "preview_asset_not_found", "Preview asset not found");
  }
  return asset;
}
