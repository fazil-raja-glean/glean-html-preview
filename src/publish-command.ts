import { HttpError } from "./http";
import { parsePreviewImages, type PreviewAssetLimitsEnv, type PreviewImageInput } from "./preview-assets";
import type { PublishPrincipal } from "./publish-principal";

export interface PublishCommand {
  expiresAt: string | null;
  html: string;
  images: PreviewImageInput[];
  password: string;
  publisherEmail: string;
  slug: string;
  sourceUrl: string | null;
  title: string;
}

export interface PreviewPublishInput {
  expiresAt: string | null;
  html: string;
  images: PreviewImageInput[];
  password: string;
  slug: string;
  sourceUrl: string | null;
  title: string;
}

export interface PreviewHtmlUpdateInput {
  expiresAt?: string | null;
  html: string;
  images: PreviewImageInput[];
  sourceUrl?: string | null;
  title?: string;
}

export interface RotatePasswordCommand {
  password: string;
}

export interface UnpublishCommand {
  deleteObject: boolean;
}

interface PublishCommandEnv extends PreviewAssetLimitsEnv {
  MAX_HTML_BYTES?: string;
}

const DEFAULT_MAX_HTML_BYTES = 10_000_000;
const MIN_PASSWORD_LENGTH = 5;
const MAX_PASSWORD_LENGTH = 256;
export const CUSTOM_SLUG_MIN_LENGTH = 3;
export const CUSTOM_SLUG_MAX_LENGTH = 80;
export const CUSTOM_SLUG_PATTERN_SOURCE = "^[a-z0-9]+(?:-[a-z0-9]+)*$";
const CUSTOM_SLUG_PATTERN = new RegExp(CUSTOM_SLUG_PATTERN_SOURCE);

export function parsePublishCommand(
  body: Record<string, unknown>,
  env: PublishCommandEnv,
  principal: PublishPrincipal,
): PublishCommand {
  return {
    ...parsePreviewPublishInput(body, env),
    publisherEmail: principal.actorEmail,
  };
}

export function parsePreviewPublishInput(body: Record<string, unknown>, env: PublishCommandEnv): PreviewPublishInput {
  rejectRemovedField(body, "allowScripts");
  const title = requireString(body.title, "title").trim();
  const html = requireString(body.html, "html");
  const password = requireString(body.password, "password");
  const expiresAt = parseExpiresAt(body.expiresAt);
  const sourceUrl = parseOptionalUrl(body.sourceUrl, "sourceUrl");
  const slug = parseRequiredSlug(body.slug);
  const images = parsePreviewImages(body.images, env);
  const maxHtmlBytes = parsePositiveInteger(env.MAX_HTML_BYTES, DEFAULT_MAX_HTML_BYTES);

  validateTitle(title);
  validateHtml(html, maxHtmlBytes);
  validatePassword(password);

  return {
    title,
    html,
    images,
    password,
    slug,
    expiresAt,
    sourceUrl,
  };
}

export function parsePreviewHtmlUpdateInput(
  body: Record<string, unknown>,
  env: PublishCommandEnv,
): PreviewHtmlUpdateInput {
  rejectRemovedField(body, "allowScripts");
  rejectRemovedField(body, "password");
  const html = requireString(body.html, "html");
  const images = parsePreviewImages(body.images, env);
  const maxHtmlBytes = parsePositiveInteger(env.MAX_HTML_BYTES, DEFAULT_MAX_HTML_BYTES);
  const input: PreviewHtmlUpdateInput = { html, images };

  validateHtml(html, maxHtmlBytes);

  if (hasOwn(body, "title")) {
    const title = requireString(body.title, "title").trim();
    validateTitle(title);
    input.title = title;
  }

  if (hasOwn(body, "expiresAt")) {
    input.expiresAt = parseExpiresAt(body.expiresAt);
  }

  if (hasOwn(body, "sourceUrl")) {
    input.sourceUrl = parseOptionalUrl(body.sourceUrl, "sourceUrl");
  }

  return input;
}

export function parseUnpublishCommand(body: Record<string, unknown>): UnpublishCommand {
  return {
    deleteObject: body.deleteObject === true,
  };
}

export function parseRotatePasswordCommand(body: Record<string, unknown>): RotatePasswordCommand {
  const password = requireString(body.password, "password");
  validatePassword(password);

  return {
    password,
  };
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `${field} must be a string`);
  }

  return value;
}

function parseOptionalString(value: unknown, field: string): string | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `${field} must be a string`);
  }

  return value;
}

function parseOptionalUrl(value: unknown, field: string): string | null {
  const text = parseOptionalString(value, field);
  if (!text) {
    return null;
  }

  try {
    return new URL(text).toString();
  } catch {
    throw new HttpError(400, "invalid_url", `${field} must be a valid URL`);
  }
}

function parseRequiredSlug(value: unknown): string {
  if (value === undefined || value === null || value === "") {
    throw new HttpError(400, "missing_slug", "slug is required");
  }

  if (
    typeof value !== "string" ||
    value.length < CUSTOM_SLUG_MIN_LENGTH ||
    value.length > CUSTOM_SLUG_MAX_LENGTH ||
    !CUSTOM_SLUG_PATTERN.test(value)
  ) {
    throw new HttpError(
      400,
      "invalid_slug",
      "Slug must be 3-80 characters and use lowercase letters, numbers, and single hyphens",
    );
  }

  return value;
}

function parseExpiresAt(value: unknown): string | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const text = requireString(value, "expiresAt");
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp)) {
    throw new HttpError(400, "invalid_expiry", "expiresAt must be a valid ISO timestamp");
  }

  if (timestamp <= Date.now()) {
    throw new HttpError(400, "invalid_expiry", "expiresAt must be in the future");
  }

  return new Date(timestamp).toISOString();
}

function validatePassword(password: string): void {
  if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    throw new HttpError(
      400,
      "invalid_password",
      `Password must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters`,
    );
  }
}

function validateTitle(title: string): void {
  if (title.length < 1 || title.length > 160) {
    throw new HttpError(400, "invalid_title", "Title must be between 1 and 160 characters");
  }
}

function validateHtml(html: string, maxHtmlBytes: number): void {
  if (!looksLikeHtmlDocument(html)) {
    throw new HttpError(400, "invalid_html", "HTML must be a complete document with an html element");
  }

  if (new TextEncoder().encode(html).byteLength > maxHtmlBytes) {
    throw new HttpError(413, "html_too_large", `HTML must be ${maxHtmlBytes} bytes or smaller`);
  }
}

function looksLikeHtmlDocument(html: string): boolean {
  return /<html[\s>]/i.test(html);
}

function rejectRemovedField(body: Record<string, unknown>, field: string): void {
  if (hasOwn(body, field)) {
    throw new HttpError(400, "invalid_request", `${field} is not supported`);
  }
}

function hasOwn(body: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(body, field);
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
