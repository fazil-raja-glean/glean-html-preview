import { fromBase64Url, randomBase64Url } from "./encoding";
import { HttpError } from "./http";

export type PreviewImageContentType = "image/png" | "image/jpeg" | "image/webp" | "image/gif" | "image/avif";

export interface PreviewAssetLimitsEnv {
  MAX_IMAGES_PER_PREVIEW?: string;
  MAX_IMAGE_BYTES?: string;
  MAX_TOTAL_IMAGE_BYTES?: string;
}

export interface PreviewImageInput {
  byteSize: number;
  bytes: Uint8Array;
  contentType: PreviewImageContentType;
  name: string;
}

export interface StoredPreviewAsset {
  assetId: string;
  byteSize: number;
  contentType: PreviewImageContentType;
  objectKey: string;
  originalName: string;
  slug: string;
}

export interface PreviewAssetReference {
  assetId: string;
  originalName: string;
  url: string;
}

export interface PreviewAssetUpload extends StoredPreviewAsset {
  bytes: Uint8Array;
}

export interface PreviewAssetUploadInput {
  images: PreviewImageInput[];
  slug: string;
  storagePrefix: string;
}

export interface PreviewAssetRow {
  asset_id: string;
  byte_size: number;
  content_type: PreviewImageContentType;
  created_at: string;
  object_key: string;
  original_name: string;
  slug: string;
}

interface PreviewAssetLimits {
  maxImageBytes: number;
  maxImages: number;
  maxTotalBytes: number;
}

const DEFAULT_MAX_IMAGES_PER_PREVIEW = 25;
const DEFAULT_MAX_IMAGE_BYTES = 5_000_000;
const DEFAULT_MAX_TOTAL_IMAGE_BYTES = 25_000_000;
const IMAGE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;
const IMAGE_CONTENT_TYPES = new Set<PreviewImageContentType>([
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
  "image/avif",
]);

export function parsePreviewImages(value: unknown, env: PreviewAssetLimitsEnv): PreviewImageInput[] {
  if (value === undefined || value === null) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new HttpError(400, "invalid_images", "images must be an array");
  }

  const limits = previewAssetLimits(env);
  if (value.length > limits.maxImages) {
    throw new HttpError(413, "too_many_images", `At most ${limits.maxImages} images are allowed per preview`);
  }

  const names = new Set<string>();
  let totalBytes = 0;
  return value.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "invalid_image", `images[${index}] must be an object`);
    }

    const record = item as Record<string, unknown>;
    const name = requireImageName(record.name, index);
    const nameKey = name.toLowerCase();
    if (names.has(nameKey)) {
      throw new HttpError(400, "duplicate_image_name", `Image name must be unique: ${name}`);
    }
    names.add(nameKey);

    const contentType = requireImageContentType(record.mimeType, index);
    const bytes = decodeImageData(record.dataBase64, index);
    const byteSize = bytes.byteLength;
    if (byteSize < 1) {
      throw new HttpError(400, "empty_image", `images[${index}] must not be empty`);
    }
    if (byteSize > limits.maxImageBytes) {
      throw new HttpError(413, "image_too_large", `Each image must be ${limits.maxImageBytes} bytes or smaller`);
    }

    totalBytes += byteSize;
    if (totalBytes > limits.maxTotalBytes) {
      throw new HttpError(413, "images_too_large", `Images must total ${limits.maxTotalBytes} bytes or smaller`);
    }

    return {
      name,
      contentType,
      bytes,
      byteSize,
    };
  });
}

export function previewAssetUploads(input: PreviewAssetUploadInput): PreviewAssetUpload[] {
  return input.images.map((image) => {
    const assetId = randomBase64Url(12);
    return {
      slug: input.slug,
      assetId,
      originalName: image.name,
      objectKey: `${input.storagePrefix}/assets/${assetId}`,
      contentType: image.contentType,
      byteSize: image.byteSize,
      bytes: image.bytes,
    };
  });
}

export function rewriteImageReferences(html: string, slug: string, assets: PreviewAssetReference[]): string {
  let rewritten = html;
  for (const asset of assets) {
    const bareAssetPath = `/p/${slug}/assets/${asset.assetId}`;
    rewritten = rewritten
      .replace(new RegExp(`${escapeRegExp(bareAssetPath)}(?!\\?token=)`, "g"), asset.url)
      .replaceAll(`cid:${asset.originalName}`, asset.url);
  }
  return rewritten;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function previewAssetLimits(env: PreviewAssetLimitsEnv): PreviewAssetLimits {
  return {
    maxImages: parsePositiveInteger(env.MAX_IMAGES_PER_PREVIEW, DEFAULT_MAX_IMAGES_PER_PREVIEW),
    maxImageBytes: parsePositiveInteger(env.MAX_IMAGE_BYTES, DEFAULT_MAX_IMAGE_BYTES),
    maxTotalBytes: parsePositiveInteger(env.MAX_TOTAL_IMAGE_BYTES, DEFAULT_MAX_TOTAL_IMAGE_BYTES),
  };
}

function requireImageName(value: unknown, index: number): string {
  if (typeof value !== "string" || !IMAGE_NAME_PATTERN.test(value)) {
    throw new HttpError(
      400,
      "invalid_image_name",
      `images[${index}].name must use letters, numbers, dots, underscores, or dashes`,
    );
  }
  return value;
}

function requireImageContentType(value: unknown, index: number): PreviewImageContentType {
  if (typeof value !== "string" || !isPreviewImageContentType(value)) {
    throw new HttpError(
      400,
      "invalid_image_type",
      `images[${index}].mimeType must be png, jpeg, webp, gif, or avif`,
    );
  }
  return value;
}

function decodeImageData(value: unknown, index: number): Uint8Array {
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_image_data", `images[${index}].dataBase64 must be a string`);
  }

  const base64 = value.includes(",") ? value.slice(value.indexOf(",") + 1) : value;
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(base64) || base64.length % 4 === 1) {
    throw new HttpError(400, "invalid_image_data", `images[${index}].dataBase64 must be valid base64`);
  }

  try {
    return /[+/]/.test(base64) ? fromBase64(base64) : fromBase64Url(base64);
  } catch {
    throw new HttpError(400, "invalid_image_data", `images[${index}].dataBase64 must be valid base64`);
  }
}

function isPreviewImageContentType(value: string): value is PreviewImageContentType {
  return IMAGE_CONTENT_TYPES.has(value as PreviewImageContentType);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
