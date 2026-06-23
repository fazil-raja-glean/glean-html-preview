import { normalizePreviewExpiresAt, type PreviewRow } from "./preview-store";

export interface AdminPreview {
  createdAt: string;
  deletedAt: string | null;
  expiresAt: string | null;
  publisherEmail: string;
  slug: string;
  sourceUrl: string | null;
  title: string;
}

export function adminPreviewFromRow(preview: PreviewRow): AdminPreview {
  return {
    slug: preview.slug,
    title: preview.title,
    publisherEmail: preview.publisher_email,
    sourceUrl: preview.source_url,
    createdAt: preview.created_at,
    expiresAt: normalizePreviewExpiresAt(preview.expires_at),
    deletedAt: preview.deleted_at,
  };
}
