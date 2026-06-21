import { HttpError } from "./http";
import type { PublishPrincipal } from "./publish-principal";

export interface PublishCommand {
  expiresAt: string;
  html: string;
  password: string;
  publisherEmail: string;
  sourceUrl: string | null;
  title: string;
}

export interface PreviewPublishInput {
  expiresAt: string;
  html: string;
  password: string;
  sourceUrl: string | null;
  title: string;
}

export interface RotatePasswordCommand {
  password: string;
}

export interface UnpublishCommand {
  deleteObject: boolean;
}

interface PublishCommandEnv {
  DEFAULT_EXPIRES_DAYS?: string;
  MAX_HTML_BYTES?: string;
}

const DEFAULT_EXPIRES_DAYS = 60;
const DEFAULT_MAX_HTML_BYTES = 2_000_000;
const MIN_PASSWORD_LENGTH = 5;
const MAX_PASSWORD_LENGTH = 256;

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
  const title = requireString(body.title, "title").trim();
  const html = requireString(body.html, "html");
  const password = requireString(body.password, "password");
  const expiresAt = parseExpiresAt(body.expiresAt, env);
  const sourceUrl = parseOptionalUrl(body.sourceUrl, "sourceUrl");
  const maxHtmlBytes = parsePositiveInteger(env.MAX_HTML_BYTES, DEFAULT_MAX_HTML_BYTES);

  if (title.length < 1 || title.length > 160) {
    throw new HttpError(400, "invalid_title", "Title must be between 1 and 160 characters");
  }

  if (!looksLikeHtmlDocument(html)) {
    throw new HttpError(400, "invalid_html", "HTML must be a complete document with an html element");
  }

  if (new TextEncoder().encode(html).byteLength > maxHtmlBytes) {
    throw new HttpError(413, "html_too_large", `HTML must be ${maxHtmlBytes} bytes or smaller`);
  }

  validatePassword(password);

  return {
    title,
    html,
    password,
    expiresAt,
    sourceUrl,
  };
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

function parseExpiresAt(value: unknown, env: PublishCommandEnv): string {
  if (value === undefined || value === null || value === "") {
    const days = parsePositiveInteger(env.DEFAULT_EXPIRES_DAYS, DEFAULT_EXPIRES_DAYS);
    const date = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    return date.toISOString();
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

function looksLikeHtmlDocument(html: string): boolean {
  return /<html[\s>]/i.test(html);
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
