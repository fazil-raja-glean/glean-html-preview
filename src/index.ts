import { randomBase64Url } from "./encoding";
import { enforceEdgeRateLimit } from "./edge-rate-limit";
import { HttpError, errorResponse, jsonResponse, methodNotAllowed, readJsonObject } from "./http";
import { handleMcpRequest } from "./mcp";
import type { McpOAuthEnv } from "./oauth-config";
import { handleOAuthRoute } from "./oauth-router";
import { enforceConfiguredRouteOrigin, publicBaseUrl } from "./origin-policy";
import {
  parsePublishCommand,
  parseRotatePasswordCommand,
  parseUnpublishCommand,
} from "./publish-command";
import { requirePublishPrincipal, type PublishPrincipal } from "./publish-principal";
import { handleAdminRoute, type AdminRouteEnv } from "./admin-api";
import { recordAudit } from "./audit";
import { getCookie } from "./cookies";
import {
  createPreview,
  getActivePreview,
  getPreview,
  rotatePreviewPassword,
  softDeletePreview,
  type PreviewRow,
} from "./preview-store";
import { routeForPath } from "./routes";
import {
  hashViewerIp,
  signAccessCookie,
  verifyAccessCookie,
  verifyPassword,
} from "./security";

interface Env extends McpOAuthEnv, AdminRouteEnv {
  HTML_PREVIEWS: R2Bucket;
  PREVIEW_DB: D1Database;
  EDGE_ACCESS_RATE_LIMITER?: RateLimit;
  EDGE_MCP_RATE_LIMITER?: RateLimit;
  EDGE_PUBLISH_RATE_LIMITER?: RateLimit;
  PUBLISH_API_TOKEN: string;
  PUBLISH_INTERNAL_SERVICE_TOKEN?: string;
  PUBLISH_ACCESS_TEAM_DOMAIN?: string;
  PUBLISH_ACCESS_AUD?: string;
  PUBLISH_ADMIN_LOCAL_BYPASS_SECRET?: string;
  ADMIN_ALLOWED_EMAIL_DOMAIN?: string;
  ADMIN_ALLOWED_EMAILS?: string;
  ADMIN_LOCAL_BYPASS_EMAIL?: string;
  ADMIN_SESSION_SECRET?: string;
  ADMIN_SESSION_TTL_SECONDS?: string;
  GLEAN_OAUTH_AUTHORIZATION_URL?: string;
  GLEAN_OAUTH_CLIENT_ID?: string;
  GLEAN_OAUTH_CLIENT_SECRET?: string;
  GLEAN_OAUTH_DISCOVERY_URL?: string;
  GLEAN_OAUTH_ISSUER?: string;
  GLEAN_OAUTH_SCOPES?: string;
  GLEAN_OAUTH_TOKEN_URL?: string;
  GLEAN_OAUTH_USERINFO_URL?: string;
  COOKIE_SIGNING_SECRET: string;
  PASSWORD_PEPPER: string;
  API_BASE_URL?: string;
  PUBLIC_BASE_URL?: string;
  WORKER_ROLE?: string;
  PUBLISHER_EMAIL_DOMAIN?: string;
  TRUSTED_PUBLISHER_EMAIL?: string;
  DEFAULT_EXPIRES_DAYS?: string;
  MAX_HTML_BYTES?: string;
  ACCESS_RATE_LIMIT_WINDOW_SECONDS?: string;
  ACCESS_RATE_LIMIT_LOCK_SECONDS?: string;
  MAX_ACCESS_FAILURES_PER_IP?: string;
  MAX_ACCESS_FAILURES_PER_PREVIEW?: string;
}

interface AccessRateLimitRow {
  scope: string;
  failed_count: number;
  window_started_at: string;
  locked_until: string | null;
}

interface AccessRateLimitPolicy {
  maxFailures: number;
  windowSeconds: number;
  lockSeconds: number;
}

interface AccessRateLimitScope {
  scope: string;
  policy: AccessRateLimitPolicy;
}

interface AccessRateLimitBlock {
  lockedUntil: string;
  retryAfterSeconds: number;
}

const ACCESS_COOKIE_NAME = "html_preview_access";
const ACCESS_COOKIE_TTL_SECONDS = 60 * 60 * 12;
const DEFAULT_ACCESS_RATE_LIMIT_WINDOW_SECONDS = 10 * 60;
const DEFAULT_ACCESS_RATE_LIMIT_LOCK_SECONDS = 15 * 60;
const DEFAULT_MAX_ACCESS_FAILURES_PER_IP = 8;
const DEFAULT_MAX_ACCESS_FAILURES_PER_PREVIEW = 100;
export const HTML_SECURITY_HEADERS = {
  "Content-Security-Policy":
    "sandbox; default-src 'none'; script-src 'none'; script-src-attr 'none'; style-src 'unsafe-inline'; img-src data: blob:; media-src data: blob:; font-src data:; connect-src 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Frame-Options": "DENY",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await routeRequest(request, env);
    } catch (error) {
      console.error("request_failed", error);
      return errorResponse(error);
    }
  },
};

async function routeRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const route = routeForPath(url.pathname);
  const originMismatch = enforceConfiguredRouteOrigin(request, url, env, route);
  if (originMismatch) {
    return originMismatch;
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  switch (route.kind) {
    case "health":
      return request.method === "GET" ? jsonResponse({ status: "ok" }) : methodNotAllowed();
    case "publish": {
      if (request.method !== "POST") {
        return methodNotAllowed();
      }

      const edgeRateLimit = await enforceEdgeRateLimit(request, env, {
        limiter: env.EDGE_PUBLISH_RATE_LIMITER,
        routeKey: "post:/v1/html-previews",
      });
      if (edgeRateLimit) {
        return edgeRateLimit;
      }

      const principal = await requirePublishPrincipal(request, env, url);
      return publishPreview(request, env, url, principal);
    }
    case "mcp": {
      if (request.method !== "POST") {
        return methodNotAllowed();
      }

      const edgeRateLimit = await enforceEdgeRateLimit(request, env, {
        limiter: env.EDGE_MCP_RATE_LIMITER,
        routeKey: "post:/mcp",
      });
      if (edgeRateLimit) {
        return edgeRateLimit;
      }

      return handleMcpRequest(request, env);
    }
    case "oauth":
      return handleOAuthRoute(request, env, route.action);
    case "admin":
      return handleAdminRoute(request, env, route);
    case "unpublish": {
      if (request.method !== "POST") {
        return methodNotAllowed();
      }

      const principal = await requirePublishPrincipal(request, env, url);
      return unpublishPreview(request, env, route.slug, principal);
    }
    case "rotatePassword": {
      if (request.method !== "POST") {
        return methodNotAllowed();
      }

      const principal = await requirePublishPrincipal(request, env, url);
      return rotatePassword(request, env, route.slug, principal);
    }
    case "access": {
      if (request.method !== "POST") {
        return methodNotAllowed();
      }

      const edgeRateLimit = await enforceEdgeRateLimit(request, env, {
        limiter: env.EDGE_ACCESS_RATE_LIMITER,
        routeKey: `post:/p/${route.slug}/access`,
      });
      if (edgeRateLimit) {
        return edgeRateLimit;
      }

      return handleAccessRequest(request, env, route.slug);
    }
    case "preview":
      if (request.method !== "GET") {
        return methodNotAllowed();
      }

      return handlePreviewRequest(request, env, route.slug);
    case "unknown":
      break;
  }

  return jsonResponse(
    {
      error: {
        code: "not_found",
        message: "Not found",
      },
    },
    404,
  );
}

async function publishPreview(
  request: Request,
  env: Env,
  url: URL,
  principal: PublishPrincipal,
): Promise<Response> {
  const input = parsePublishCommand(await readJsonObject(request), env, principal);
  const preview = await createPreview(env, input);

  await recordAudit(env, {
    slug: preview.slug,
    eventType: "published",
    actorEmail: input.publisherEmail,
    request,
    details: { sourceUrl: input.sourceUrl },
  });

  return jsonResponse(
    {
      url: `${publicBaseUrl(env, url, request)}/p/${preview.slug}`,
      slug: preview.slug,
      expiresAt: input.expiresAt,
      status: "active",
    },
    201,
  );
}

async function unpublishPreview(
  request: Request,
  env: Env,
  slug: string,
  principal: PublishPrincipal,
): Promise<Response> {
  const existing = await getPreview(env, slug);
  const input = parseUnpublishCommand(await readJsonObject(request));
  const deletedAt = await softDeletePreview(env, slug);

  if (input.deleteObject) {
    await env.HTML_PREVIEWS.delete(existing.object_key);
  }

  await recordAudit(env, {
    slug,
    eventType: "unpublished",
    actorEmail: principal.actorEmail,
    request,
    details: { deleteObject: input.deleteObject },
  });

  return jsonResponse({ slug, status: "unpublished", deletedAt });
}

async function rotatePassword(
  request: Request,
  env: Env,
  slug: string,
  principal: PublishPrincipal,
): Promise<Response> {
  const input = parseRotatePasswordCommand(await readJsonObject(request));
  await rotatePreviewPassword(env, slug, input.password);

  await recordAudit(env, {
    slug,
    eventType: "password_rotated",
    actorEmail: principal.actorEmail,
    request,
    details: null,
  });

  return jsonResponse({ slug, status: "active" });
}

async function handlePreviewRequest(request: Request, env: Env, slug: string): Promise<Response> {
  const preview = await getActivePreview(env, slug);
  const cookie = getCookie(request, ACCESS_COOKIE_NAME);
  const hasAccess =
    cookie !== null &&
    (await verifyAccessCookie(cookie, env.COOKIE_SIGNING_SECRET, preview.slug, preview.password_version));

  if (!hasAccess) {
    return passwordForm(preview, null, 200);
  }

  const object = await env.HTML_PREVIEWS.get(preview.object_key);
  if (!object?.body) {
    throw new HttpError(404, "preview_object_missing", "Preview content is missing");
  }

  const headers = new Headers(HTML_SECURITY_HEADERS);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "private, no-store");

  return new Response(object.body, { headers });
}

async function handleAccessRequest(request: Request, env: Env, slug: string): Promise<Response> {
  const preview = await getActivePreview(env, slug);
  const submittedPassword = await readPasswordFromRequest(request);
  const rateLimitScopes = await accessRateLimitScopes(env, request, slug);
  const activeRateLimit = await checkAccessRateLimit(env, rateLimitScopes);
  if (activeRateLimit) {
    await recordAudit(env, {
      slug,
      eventType: "viewer_access_rate_limited",
      actorEmail: null,
      request,
      details: { lockedUntil: activeRateLimit.lockedUntil },
    });
    return passwordForm(preview, "Too many failed attempts. Try again later.", 429, {
      "Retry-After": activeRateLimit.retryAfterSeconds.toString(),
    });
  }

  const passwordMatches = await verifyPassword(
    submittedPassword,
    env.PASSWORD_PEPPER,
    preview.password_hash,
    preview.password_salt,
    preview.password_iterations,
  );

  if (!passwordMatches) {
    const newRateLimit = await recordAccessFailure(env, rateLimitScopes);
    await recordAudit(env, {
      slug,
      eventType: "viewer_access_denied",
      actorEmail: null,
      request,
      details: newRateLimit ? { lockedUntil: newRateLimit.lockedUntil } : null,
    });
    if (newRateLimit) {
      return passwordForm(preview, "Too many failed attempts. Try again later.", 429, {
        "Retry-After": newRateLimit.retryAfterSeconds.toString(),
      });
    }

    return passwordForm(preview, "Invalid password", 401);
  }

  await clearAccessFailures(env, rateLimitScopes);

  const expiresAt = Date.now() + ACCESS_COOKIE_TTL_SECONDS * 1000;
  const cookie = await signAccessCookie(
    {
      slug,
      passwordVersion: preview.password_version,
      expiresAt,
    },
    env.COOKIE_SIGNING_SECRET,
  );

  await recordAudit(env, {
    slug,
    eventType: "viewer_access_granted",
    actorEmail: null,
    request,
    details: null,
  });

  return new Response(null, {
    status: 303,
    headers: {
      Location: `/p/${slug}`,
      "Set-Cookie": `${ACCESS_COOKIE_NAME}=${cookie}; Path=/p/${slug}; Max-Age=${ACCESS_COOKIE_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
      "Cache-Control": "no-store",
    },
  });
}

async function accessRateLimitScopes(env: Env, request: Request, slug: string): Promise<AccessRateLimitScope[]> {
  const windowSeconds = parsePositiveInteger(
    env.ACCESS_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_ACCESS_RATE_LIMIT_WINDOW_SECONDS,
  );
  const lockSeconds = parsePositiveInteger(env.ACCESS_RATE_LIMIT_LOCK_SECONDS, DEFAULT_ACCESS_RATE_LIMIT_LOCK_SECONDS);
  const viewerIpHash =
    (await hashViewerIp(request.headers.get("CF-Connecting-IP"), env.COOKIE_SIGNING_SECRET)) ?? "unknown";

  return [
    {
      scope: `preview:${slug}:ip:${viewerIpHash}`,
      policy: {
        maxFailures: parsePositiveInteger(env.MAX_ACCESS_FAILURES_PER_IP, DEFAULT_MAX_ACCESS_FAILURES_PER_IP),
        windowSeconds,
        lockSeconds,
      },
    },
    {
      scope: `preview:${slug}:all`,
      policy: {
        maxFailures: parsePositiveInteger(
          env.MAX_ACCESS_FAILURES_PER_PREVIEW,
          DEFAULT_MAX_ACCESS_FAILURES_PER_PREVIEW,
        ),
        windowSeconds,
        lockSeconds,
      },
    },
  ];
}

async function checkAccessRateLimit(
  env: Env,
  scopes: AccessRateLimitScope[],
  now = Date.now(),
): Promise<AccessRateLimitBlock | null> {
  let block: AccessRateLimitBlock | null = null;
  for (const scope of scopes) {
    const row = await env.PREVIEW_DB.prepare("SELECT * FROM access_rate_limits WHERE scope = ?")
      .bind(scope.scope)
      .first<AccessRateLimitRow>();
    const scopeBlock = accessRateLimitBlockFromRow(row, now);
    if (!scopeBlock) {
      continue;
    }

    if (!block || scopeBlock.retryAfterSeconds > block.retryAfterSeconds) {
      block = scopeBlock;
    }
  }

  return block;
}

async function recordAccessFailure(
  env: Env,
  scopes: AccessRateLimitScope[],
  now = Date.now(),
): Promise<AccessRateLimitBlock | null> {
  let block: AccessRateLimitBlock | null = null;
  for (const scope of scopes) {
    const scopeBlock = await recordAccessFailureForScope(env, scope, now);
    if (!scopeBlock) {
      continue;
    }

    if (!block || scopeBlock.retryAfterSeconds > block.retryAfterSeconds) {
      block = scopeBlock;
    }
  }

  return block;
}

async function recordAccessFailureForScope(
  env: Env,
  scope: AccessRateLimitScope,
  now: number,
): Promise<AccessRateLimitBlock | null> {
  const row = await env.PREVIEW_DB.prepare("SELECT * FROM access_rate_limits WHERE scope = ?")
    .bind(scope.scope)
    .first<AccessRateLimitRow>();
  const windowStartedAt = parseTimestamp(row?.window_started_at);
  const shouldResetWindow =
    !row || windowStartedAt === null || windowStartedAt + scope.policy.windowSeconds * 1000 <= now;
  const failedCount = shouldResetWindow ? 1 : row.failed_count + 1;
  const nextWindowStartedAt = shouldResetWindow ? new Date(now).toISOString() : row.window_started_at;
  const lockedUntil =
    failedCount >= scope.policy.maxFailures ? new Date(now + scope.policy.lockSeconds * 1000).toISOString() : null;

  await env.PREVIEW_DB.prepare(
    `INSERT INTO access_rate_limits (
      scope,
      failed_count,
      window_started_at,
      locked_until
    ) VALUES (?, ?, ?, ?)
    ON CONFLICT(scope) DO UPDATE SET
      failed_count = excluded.failed_count,
      window_started_at = excluded.window_started_at,
      locked_until = excluded.locked_until`,
  )
    .bind(scope.scope, failedCount, nextWindowStartedAt, lockedUntil)
    .run();

  if (!lockedUntil) {
    return null;
  }

  return {
    lockedUntil,
    retryAfterSeconds: Math.max(1, Math.ceil((Date.parse(lockedUntil) - now) / 1000)),
  };
}

async function clearAccessFailures(env: Env, scopes: AccessRateLimitScope[]): Promise<void> {
  for (const scope of scopes) {
    await env.PREVIEW_DB.prepare("DELETE FROM access_rate_limits WHERE scope = ?").bind(scope.scope).run();
  }
}

function accessRateLimitBlockFromRow(row: AccessRateLimitRow | null, now: number): AccessRateLimitBlock | null {
  const lockedUntil = parseTimestamp(row?.locked_until);
  if (lockedUntil === null || lockedUntil <= now) {
    return null;
  }

  return {
    lockedUntil: new Date(lockedUntil).toISOString(),
    retryAfterSeconds: Math.max(1, Math.ceil((lockedUntil - now) / 1000)),
  };
}

async function readPasswordFromRequest(request: Request): Promise<string> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    const body = await readJsonObject(request);
    return requireString(body.password, "password");
  }

  const form = await request.formData();
  const password = form.get("password");
  if (typeof password !== "string") {
    throw new HttpError(400, "missing_password", "Password is required");
  }

  return password;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `${field} must be a string`);
  }

  return value;
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseTimestamp(value: string | null | undefined): number | null {
  if (!value) {
    return null;
  }

  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function passwordForm(
  preview: PreviewRow,
  error: string | null,
  status: number,
  extraHeaders: Record<string, string> = {},
): Response {
  const nonce = randomBase64Url(12);
  const errorMarkup = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(preview.title)}</title>
    <style nonce="${nonce}">
      :root { color-scheme: light dark; }
      body {
        align-items: center;
        background: #f7f7f6;
        color: #1b1b1b;
        display: flex;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        justify-content: center;
        min-height: 100vh;
        margin: 0;
        padding: 24px;
      }
      main {
        background: #fff;
        border: 1px solid #e5e5e2;
        border-radius: 8px;
        box-shadow: 0 12px 34px rgba(0, 0, 0, 0.08);
        max-width: 420px;
        padding: 24px;
        width: 100%;
      }
      h1 { font-size: 20px; line-height: 1.2; margin: 0 0 8px; }
      p { color: #686867; font-size: 14px; margin: 0 0 18px; }
      label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; }
      input {
        border: 1px solid #cfcfcc;
        border-radius: 6px;
        box-sizing: border-box;
        font: inherit;
        margin-bottom: 14px;
        padding: 10px 12px;
        width: 100%;
      }
      button {
        background: #1b1b1b;
        border: 0;
        border-radius: 6px;
        color: #fff;
        cursor: pointer;
        font: inherit;
        font-weight: 650;
        padding: 10px 14px;
        width: 100%;
      }
      .error { color: #8a1f1f; font-weight: 600; }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(preview.title)}</h1>
      <p>This HTML preview is password protected.</p>
      ${errorMarkup}
      <form method="post" action="/p/${preview.slug}/access">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
        <button type="submit">View preview</button>
      </form>
    </main>
  </body>
</html>`;

  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
  for (const [name, value] of Object.entries(extraHeaders)) {
    headers.set(name, value);
  }

  return new Response(html, { status, headers });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
