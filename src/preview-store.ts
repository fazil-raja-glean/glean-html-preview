import { HttpError } from "./http";
import {
  deletePreviewAssetRows,
  deletePreviewObjects,
  previewAssetInsertStatements,
  putPreviewObjects,
} from "./preview-asset-store";
import {
  previewAssetUploads,
  type PreviewAssetUpload,
  type PreviewImageInput,
} from "./preview-assets";
import { createSlug, hashPassword, type PasswordHash } from "./security";

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

export interface PreviewSettingsRow {
  allow_scripts: number;
  created_at: string;
  slug: string;
}

export interface PreviewRenderOptions {
  allowScripts: boolean;
}

export interface CreatePreviewInput {
  allowScripts: boolean;
  expiresAt: string | null;
  html: string;
  images: PreviewImageInput[];
  password: string;
  publisherEmail: string;
  sourceUrl: string | null;
  title: string;
}

export async function createPreview(env: PreviewStoreEnv, input: CreatePreviewInput): Promise<PreviewRow> {
  const slug = createSlug();
  const objectKey = `previews/${slug}/index.html`;
  const assets = previewAssetUploads(slug, input.images);
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
    await Promise.all(objectKeys.map((key) => env.HTML_PREVIEWS.delete(key)));
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

export async function getPreviewRenderOptions(env: PreviewStoreEnv, slug: string): Promise<PreviewRenderOptions> {
  const settings = await env.PREVIEW_DB.prepare("SELECT * FROM preview_settings WHERE slug = ?")
    .bind(slug)
    .first<PreviewSettingsRow>();

  return {
    allowScripts: settings?.allow_scripts === 1,
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
  await deletePreviewObjects(env, { slug: preview.slug, objectKey: preview.object_key });
  await deletePreviewAssetRows(env, slug);
  await env.PREVIEW_DB.prepare("DELETE FROM previews WHERE slug = ?").bind(slug).run();
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
    env.PREVIEW_DB.prepare(
      `INSERT INTO preview_settings (
        slug,
        allow_scripts,
        created_at
      ) VALUES (?, ?, ?)`,
    ).bind(values.slug, input.allowScripts ? 1 : 0, values.createdAt),
    ...previewAssetInsertStatements(env, values.assets, values.createdAt),
  ];

  await env.PREVIEW_DB.batch(statements);
}

function ensurePreviewIsNotDeleted(preview: PreviewRow): void {
  if (preview.deleted_at) {
    throw new HttpError(410, "preview_unpublished", "Preview has been unpublished");
  }
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
