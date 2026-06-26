import { HttpError } from "./http";
import {
  previewAssetInsertStatements,
  putPreviewObjects,
} from "./preview-asset-store";
import {
  previewAssetUploads,
  type PreviewAssetUpload,
  type PreviewAssetRow,
  type PreviewImageInput,
} from "./preview-assets";
import { createStorageId, hashPassword, type PasswordHash } from "./security";

export interface PreviewStoreEnv {
  HTML_PREVIEWS: R2Bucket;
  PASSWORD_PEPPER: string;
  PREVIEW_DB: D1Database;
}

export interface PreviewRow {
  created_at: string;
  deleted_at: string | null;
  expires_at: string;
  object_key: string;
  password_hash: string;
  password_iterations: number;
  password_salt: string;
  password_version: number;
  publisher_email: string;
  slug: string;
  source_url: string | null;
  title: string;
}

export interface CreatePreviewInput {
  expiresAt: string | null;
  html: string;
  images: PreviewImageInput[];
  password: string;
  publisherEmail: string;
  slug: string;
  sourceUrl: string | null;
  title: string;
}

export interface UpdatePreviewHtmlInput {
  expiresAt?: string | null;
  html: string;
  images: PreviewImageInput[];
  sourceUrl?: string | null;
  title?: string;
}

export async function createPreview(env: PreviewStoreEnv, input: CreatePreviewInput): Promise<PreviewRow> {
  const slug = input.slug;
  const storagePrefix = previewStoragePrefix(createStorageId());
  const objectKey = `${storagePrefix}/index.html`;
  const assets = previewAssetUploads({
    slug,
    storagePrefix,
    images: input.images,
  });
  const now = new Date().toISOString();
  const password = await hashPassword(input.password, env.PASSWORD_PEPPER);
  const objectKeys = [objectKey, ...assets.map((asset) => asset.objectKey)];

  try {
    await putPreviewObjects(env, {
      slug,
      title: input.title,
      publisherEmail: input.publisherEmail,
      html: input.html,
      objectKey,
      assets,
      createdAt: now,
    });
    await insertPreviewRows(env, input, {
      slug,
      objectKey,
      password,
      assets,
      createdAt: now,
    });
  } catch (error) {
    await deletePreviewObjectKeys(env, objectKeys);
    if (isPreviewSlugConflict(error)) {
      throw new HttpError(409, "slug_taken", "Slug is already in use");
    }
    throw error;
  }

  return {
    slug,
    title: input.title,
    object_key: objectKey,
    password_hash: password.hash,
    password_salt: password.salt,
    password_iterations: password.iterations,
    password_version: 1,
    publisher_email: input.publisherEmail,
    source_url: input.sourceUrl,
    created_at: now,
    expires_at: previewExpiresAtStorageValue(input.expiresAt),
    deleted_at: null,
  };
}

export async function listPreviews(env: PreviewStoreEnv, limit = 100): Promise<PreviewRow[]> {
  const result = await env.PREVIEW_DB.prepare(
    `SELECT *
      FROM previews
      ORDER BY datetime(created_at) DESC
      LIMIT ?`,
  )
    .bind(limit)
    .all<PreviewRow>();

  return result.results;
}

export async function listPreviewsForPublisher(
  env: PreviewStoreEnv,
  publisherEmail: string,
  limit = 100,
): Promise<PreviewRow[]> {
  const result = await env.PREVIEW_DB.prepare(
    `SELECT *
      FROM previews
      WHERE lower(publisher_email) = ?
      ORDER BY datetime(created_at) DESC
      LIMIT ?`,
  )
    .bind(publisherEmail.trim().toLowerCase(), limit)
    .all<PreviewRow>();

  return result.results;
}

export async function getPreview(env: PreviewStoreEnv, slug: string): Promise<PreviewRow> {
  const preview = await env.PREVIEW_DB.prepare("SELECT * FROM previews WHERE slug = ?").bind(slug).first<PreviewRow>();
  if (!preview) {
    throw new HttpError(404, "preview_not_found", "Preview not found");
  }

  return preview;
}

export async function getPreviewForPublisher(
  env: PreviewStoreEnv,
  slug: string,
  publisherEmail: string,
): Promise<PreviewRow> {
  const preview = await env.PREVIEW_DB.prepare(
    "SELECT * FROM previews WHERE slug = ? AND lower(publisher_email) = ?",
  )
    .bind(slug, publisherEmail.trim().toLowerCase())
    .first<PreviewRow>();
  if (!preview) {
    throw new HttpError(404, "preview_not_found", "Preview not found");
  }

  return preview;
}

export async function updatePreviewHtml(
  env: PreviewStoreEnv,
  slug: string,
  publisherEmail: string,
  input: UpdatePreviewHtmlInput,
): Promise<PreviewRow> {
  const existing = await getPreviewForPublisher(env, slug, publisherEmail);
  ensurePreviewCanUpdate(existing);

  const oldAssets = await listPreviewAssetRows(env, slug);
  const oldObjectKeys = [existing.object_key, ...oldAssets.map((asset) => asset.object_key)];
  const storagePrefix = previewStoragePrefix(createStorageId());
  const objectKey = `${storagePrefix}/index.html`;
  const assets = previewAssetUploads({
    slug,
    storagePrefix,
    images: input.images,
  });
  const now = new Date().toISOString();
  const objectKeys = [objectKey, ...assets.map((asset) => asset.objectKey)];
  const nextPreview = previewRowWithHtmlUpdate(existing, input, objectKey);

  try {
    await putPreviewObjects(env, {
      slug,
      title: nextPreview.title,
      publisherEmail,
      html: input.html,
      objectKey,
      assets,
      createdAt: now,
    });
    await replacePreviewHtmlRows(env, slug, publisherEmail, nextPreview, assets, now);
  } catch (error) {
    await deletePreviewObjectKeys(env, objectKeys);
    throw error;
  }

  await deletePreviewObjectKeys(env, oldObjectKeys);
  return nextPreview;
}

export async function getActivePreview(env: PreviewStoreEnv, slug: string): Promise<PreviewRow> {
  const preview = await getPreview(env, slug);

  if (preview.deleted_at) {
    throw new HttpError(410, "preview_unpublished", "Preview has been unpublished");
  }

  if (isPreviewExpired(preview)) {
    throw new HttpError(410, "preview_expired", "Preview has expired");
  }

  return preview;
}

export async function rotatePreviewPassword(env: PreviewStoreEnv, slug: string, passwordText: string): Promise<void> {
  ensurePreviewIsNotDeleted(await getPreview(env, slug));
  const password = await hashPassword(passwordText, env.PASSWORD_PEPPER);

  await env.PREVIEW_DB.prepare(
    `UPDATE previews
      SET password_hash = ?,
          password_salt = ?,
          password_iterations = ?,
          password_version = password_version + 1
      WHERE slug = ? AND deleted_at IS NULL`,
  )
    .bind(password.hash, password.salt, password.iterations, slug)
    .run();
}

export async function softDeletePreview(env: PreviewStoreEnv, slug: string, deletedAt = new Date().toISOString()): Promise<string> {
  ensurePreviewIsNotDeleted(await getPreview(env, slug));
  await env.PREVIEW_DB.prepare("UPDATE previews SET deleted_at = ? WHERE slug = ? AND deleted_at IS NULL")
    .bind(deletedAt, slug)
    .run();

  return deletedAt;
}

export async function hardDeletePreview(env: PreviewStoreEnv, slug: string): Promise<void> {
  const preview = await getPreview(env, slug);
  const assets = await listPreviewAssetRows(env, slug);
  await env.PREVIEW_DB.batch([
    env.PREVIEW_DB.prepare("DELETE FROM preview_assets WHERE slug = ?").bind(slug),
    env.PREVIEW_DB.prepare("DELETE FROM previews WHERE slug = ?").bind(slug),
  ]);
  await deletePreviewObjectKeys(env, [preview.object_key, ...assets.map((asset) => asset.object_key)]);
}

export async function readPreviewHtml(env: PreviewStoreEnv, slug: string): Promise<string> {
  const preview = await getPreview(env, slug);
  const object = await env.HTML_PREVIEWS.get(preview.object_key);
  if (!object?.body) {
    throw new HttpError(404, "preview_object_missing", "Preview content is missing");
  }

  return object.text();
}

async function insertPreviewRows(
  env: PreviewStoreEnv,
  input: CreatePreviewInput,
  values: {
    assets: PreviewAssetUpload[];
    createdAt: string;
    objectKey: string;
    password: PasswordHash;
    slug: string;
  },
): Promise<void> {
  const statements = [
    env.PREVIEW_DB.prepare(
      `INSERT INTO previews (
        slug,
        title,
        object_key,
        password_hash,
        password_salt,
        password_iterations,
        password_version,
        publisher_email,
        source_url,
        created_at,
        expires_at,
        deleted_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, NULL)`,
    ).bind(
      values.slug,
      input.title,
      values.objectKey,
      values.password.hash,
      values.password.salt,
      values.password.iterations,
      input.publisherEmail,
      input.sourceUrl,
      values.createdAt,
      previewExpiresAtStorageValue(input.expiresAt),
    ),
    ...previewAssetInsertStatements(env, values.assets, values.createdAt),
  ];

  await env.PREVIEW_DB.batch(statements);
}

async function replacePreviewHtmlRows(
  env: PreviewStoreEnv,
  slug: string,
  publisherEmail: string,
  preview: PreviewRow,
  assets: PreviewAssetUpload[],
  updatedAt: string,
): Promise<void> {
  const ownerEmail = publisherEmail.trim().toLowerCase();
  const results = await env.PREVIEW_DB.batch([
    env.PREVIEW_DB.prepare(
      `UPDATE previews
        SET object_key = ?,
            title = ?,
            source_url = ?,
            expires_at = ?
        WHERE slug = ? AND lower(publisher_email) = ? AND deleted_at IS NULL`,
    ).bind(
      preview.object_key,
      preview.title,
      preview.source_url,
      preview.expires_at,
      slug,
      ownerEmail,
    ),
    env.PREVIEW_DB.prepare(
      `DELETE FROM preview_assets
        WHERE slug = ?
          AND EXISTS (
            SELECT 1 FROM previews
            WHERE slug = ? AND lower(publisher_email) = ? AND deleted_at IS NULL
          )`,
    ).bind(slug, slug, ownerEmail),
    ...previewAssetReplacementStatements(env, assets, updatedAt, ownerEmail),
  ]);

  if (results[0]?.meta.changes !== 1) {
    throw new HttpError(404, "preview_not_found", "Preview not found");
  }
}

function previewAssetReplacementStatements(
  env: PreviewStoreEnv,
  assets: PreviewAssetUpload[],
  createdAt: string,
  ownerEmail: string,
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
      )
      SELECT ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1 FROM previews
        WHERE slug = ? AND lower(publisher_email) = ? AND deleted_at IS NULL
      )`,
    ).bind(
      asset.slug,
      asset.assetId,
      asset.objectKey,
      asset.contentType,
      asset.byteSize,
      asset.originalName,
      createdAt,
      asset.slug,
      ownerEmail,
    ),
  );
}

function previewRowWithHtmlUpdate(
  existing: PreviewRow,
  input: UpdatePreviewHtmlInput,
  objectKey: string,
): PreviewRow {
  return {
    ...existing,
    title: input.title ?? existing.title,
    object_key: objectKey,
    source_url: input.sourceUrl === undefined ? existing.source_url : input.sourceUrl,
    expires_at: input.expiresAt === undefined ? existing.expires_at : previewExpiresAtStorageValue(input.expiresAt),
  };
}

function ensurePreviewIsNotDeleted(preview: PreviewRow): void {
  if (preview.deleted_at) {
    throw new HttpError(410, "preview_unpublished", "Preview has been unpublished");
  }
}

function ensurePreviewCanUpdate(preview: PreviewRow): void {
  ensurePreviewIsNotDeleted(preview);
  if (isPreviewExpired(preview)) {
    throw new HttpError(410, "preview_expired", "Preview has expired");
  }
}

async function listPreviewAssetRows(env: PreviewStoreEnv, slug: string): Promise<PreviewAssetRow[]> {
  const result = await env.PREVIEW_DB.prepare("SELECT * FROM preview_assets WHERE slug = ?")
    .bind(slug)
    .all<PreviewAssetRow>();
  return result.results;
}

async function deletePreviewObjectKeys(env: PreviewStoreEnv, objectKeys: string[]): Promise<void> {
  try {
    await Promise.all(objectKeys.map((key) => env.HTML_PREVIEWS.delete(key)));
  } catch (error) {
    console.error("preview_object_cleanup_failed", error);
  }
}

function isPreviewSlugConflict(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /(?:UNIQUE|PRIMARY KEY) constraint failed: previews\.slug/i.test(message);
}

function previewStoragePrefix(storageId: string): string {
  return `previews/objects/${storageId}`;
}

export function normalizePreviewExpiresAt(value: string | null): string | null {
  const text = value?.trim() ?? "";
  return text ? text : null;
}

export function previewExpiresAtStorageValue(value: string | null): string {
  return normalizePreviewExpiresAt(value) ?? "";
}

function isPreviewExpired(preview: PreviewRow, now = Date.now()): boolean {
  const expiresAt = normalizePreviewExpiresAt(preview.expires_at);
  return expiresAt !== null && Date.parse(expiresAt) <= now;
}
