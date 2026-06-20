import { HttpError } from "./http";
import { createSlug, hashPassword } from "./security";

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
  expiresAt: string;
  html: string;
  password: string;
  publisherEmail: string;
  sourceUrl: string | null;
  title: string;
}

export async function createPreview(env: PreviewStoreEnv, input: CreatePreviewInput): Promise<PreviewRow> {
  const slug = createSlug();
  const objectKey = `previews/${slug}/index.html`;
  const now = new Date().toISOString();
  const password = await hashPassword(input.password, env.PASSWORD_PEPPER);

  await env.HTML_PREVIEWS.put(objectKey, input.html, {
    httpMetadata: {
      contentType: "text/html; charset=utf-8",
    },
    customMetadata: {
      slug,
      title: input.title,
      publisherEmail: input.publisherEmail,
      createdAt: now,
    },
  });

  try {
    await env.PREVIEW_DB.prepare(
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
    )
      .bind(
        slug,
        input.title,
        objectKey,
        password.hash,
        password.salt,
        password.iterations,
        input.publisherEmail,
        input.sourceUrl,
        now,
        input.expiresAt,
      )
      .run();
  } catch (error) {
    await env.HTML_PREVIEWS.delete(objectKey);
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
    expires_at: input.expiresAt,
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

export async function getActivePreview(env: PreviewStoreEnv, slug: string): Promise<PreviewRow> {
  const preview = await getPreview(env, slug);

  if (preview.deleted_at) {
    throw new HttpError(410, "preview_unpublished", "Preview has been unpublished");
  }

  if (Date.parse(preview.expires_at) <= Date.now()) {
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
  await env.HTML_PREVIEWS.delete(preview.object_key);
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

function ensurePreviewIsNotDeleted(preview: PreviewRow): void {
  if (preview.deleted_at) {
    throw new HttpError(410, "preview_unpublished", "Preview has been unpublished");
  }
}
