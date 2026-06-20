import { ADMIN_GLEAN_OAUTH_FLOW, completeGleanOAuthLogin, startGleanOAuthLogin, type GleanOAuthEnv } from "./auth/glean-oauth";
import { requireCsrfToken } from "./auth/csrf";
import {
  clearIdentitySessionCookie,
  createIdentitySession,
  localBypassUser,
  requireAllowedAdminUser,
  requireIdentitySession,
  type AdminSessionPayload,
} from "./auth/session";
import { HttpError, jsonResponse, methodNotAllowed, readJsonObject } from "./http";
import { publicBaseUrl } from "./origin-policy";
import { parseRotatePasswordCommand } from "./publish-command";
import {
  getPreviewForPublisher,
  hardDeletePreview,
  listPreviewsForPublisher,
  readPreviewHtml,
  rotatePreviewPassword,
  softDeletePreview,
  type PreviewStoreEnv,
} from "./preview-store";
import { recordAudit, listAuditEvents } from "./audit";
import type { AdminRoute } from "./routes";
import { adminHtmlResponse, ADMIN_SECURITY_HEADERS } from "./admin-ui";
import { adminPreviewFromRow } from "./admin-preview";

export interface AdminRouteEnv extends GleanOAuthEnv, PreviewStoreEnv {
  COOKIE_SIGNING_SECRET: string;
  PUBLIC_BASE_URL?: string;
}

interface AdminActionBody {
  isForm: boolean;
  values: Record<string, unknown>;
}

export async function handleAdminRoute(
  request: Request,
  env: AdminRouteEnv,
  route: AdminRoute,
): Promise<Response> {
  switch (route.action) {
    case "home":
      return request.method === "GET" ? handleAdminHome(request, env) : methodNotAllowed();
    case "login":
      return request.method === "GET" ? handleAdminLogin(request, env) : methodNotAllowed();
    case "oauthCallback":
      return request.method === "GET" ? completeGleanOAuthLogin(request, env, ADMIN_GLEAN_OAUTH_FLOW) : methodNotAllowed();
    case "logout":
      return request.method === "POST" ? handleAdminLogout(request, env) : methodNotAllowed();
    case "session":
      return request.method === "GET" ? handleAdminSession(request, env) : methodNotAllowed();
    case "previews":
      return request.method === "GET" ? handleListPreviews(request, env) : methodNotAllowed();
    case "previewDetails":
      return request.method === "GET" ? handlePreviewDetails(request, env, route.slug) : methodNotAllowed();
    case "rotatePassword":
      return request.method === "POST" ? handleRotatePassword(request, env, route.slug) : methodNotAllowed();
    case "unpublish":
      return request.method === "POST" ? handleUnpublish(request, env, route.slug) : methodNotAllowed();
    case "hardDelete":
      return request.method === "DELETE" || request.method === "POST"
        ? handleHardDelete(request, env, route.slug)
        : methodNotAllowed();
    case "html":
      return request.method === "GET" ? handlePreviewHtml(request, env, route.slug) : methodNotAllowed();
  }
}

async function handleAdminHome(request: Request, env: AdminRouteEnv): Promise<Response> {
  const session = await requireAdminOrRedirect(request, env);
  if (session instanceof Response) {
    return session;
  }

  return adminHtmlResponse({
    session,
    previewBaseUrl: publicBaseUrl(env, new URL(request.url), request),
    previews: (await listPreviewsForPublisher(env, session.email)).map(adminPreviewFromRow),
  });
}

async function handleAdminLogin(request: Request, env: AdminRouteEnv): Promise<Response> {
  const bypassUser = localBypassUser(request, env);
  if (bypassUser) {
    const session = await createIdentitySession(requireAllowedAdminUser(bypassUser, env), env, "admin");
    return redirectResponse(returnToFromRequest(request), {
      "Set-Cookie": session.cookie,
    });
  }

  return startGleanOAuthLogin(request, env, ADMIN_GLEAN_OAUTH_FLOW, returnToFromRequest(request));
}

async function handleAdminLogout(request: Request, env: AdminRouteEnv): Promise<Response> {
  const session = await requireAdminSession(request, env);
  requireCsrfToken((await readAdminActionBody(request)).values.csrf as string | undefined, session.csrf);
  return redirectResponse("/admin/login", {
    "Set-Cookie": clearIdentitySessionCookie("admin"),
  });
}

async function handleAdminSession(request: Request, env: AdminRouteEnv): Promise<Response> {
  const session = await requireAdminSession(request, env);
  return jsonResponse({
    user: sessionUser(session),
    csrf: session.csrf,
  });
}

async function handleListPreviews(request: Request, env: AdminRouteEnv): Promise<Response> {
  const session = await requireAdminSession(request, env);
  return jsonResponse({
    previews: (await listPreviewsForPublisher(env, session.email)).map(adminPreviewFromRow),
  });
}

async function handlePreviewDetails(request: Request, env: AdminRouteEnv, slug: string): Promise<Response> {
  const session = await requireAdminSession(request, env);
  const preview = await getPreviewForPublisher(env, slug, session.email);
  const auditEvents = await listAuditEvents(env, slug);
  return jsonResponse({
    preview: adminPreviewFromRow(preview),
    auditEvents,
  });
}

async function handleRotatePassword(request: Request, env: AdminRouteEnv, slug: string): Promise<Response> {
  const session = await requireAdminSession(request, env);
  const body = await readAdminActionBody(request);
  requireCsrfToken(body.values.csrf as string | undefined, session.csrf);
  const input = parseRotatePasswordCommand(body.values);
  await requireOwnedPreview(env, slug, session);
  await rotatePreviewPassword(env, slug, input.password);
  await recordAudit(env, {
    slug,
    eventType: "admin_password_rotated",
    actorEmail: session.email,
    request,
    details: null,
  });

  return adminActionResponse(body, { slug, status: "active" });
}

async function handleUnpublish(request: Request, env: AdminRouteEnv, slug: string): Promise<Response> {
  const session = await requireAdminSession(request, env);
  const body = await readAdminActionBody(request);
  requireCsrfToken(body.values.csrf as string | undefined, session.csrf);
  await requireOwnedPreview(env, slug, session);
  const deletedAt = await softDeletePreview(env, slug);
  await recordAudit(env, {
    slug,
    eventType: "admin_unpublished",
    actorEmail: session.email,
    request,
    details: null,
  });

  return adminActionResponse(body, { slug, status: "unpublished", deletedAt });
}

async function handleHardDelete(request: Request, env: AdminRouteEnv, slug: string): Promise<Response> {
  const session = await requireAdminSession(request, env);
  const body = await readAdminActionBody(request);
  requireCsrfToken(body.values.csrf as string | undefined, session.csrf);
  if (body.values.confirmSlug !== slug) {
    throw new HttpError(400, "missing_delete_confirmation", "confirmSlug must match the preview slug");
  }

  await requireOwnedPreview(env, slug, session);
  await hardDeletePreview(env, slug);
  await recordAudit(env, {
    slug,
    eventType: "admin_hard_deleted",
    actorEmail: session.email,
    request,
    details: null,
  });

  return adminActionResponse(body, { slug, status: "deleted" });
}

async function handlePreviewHtml(request: Request, env: AdminRouteEnv, slug: string): Promise<Response> {
  const session = await requireAdminSession(request, env);
  await requireOwnedPreview(env, slug, session);
  const html = await readPreviewHtml(env, slug);
  return new Response(html, {
    headers: {
      ...ADMIN_SECURITY_HEADERS,
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${slug}.html"`,
    },
  });
}

async function requireAdminOrRedirect(request: Request, env: AdminRouteEnv): Promise<AdminSessionPayload | Response> {
  try {
    return await requireAdminSession(request, env);
  } catch (error) {
    if (error instanceof HttpError && error.status === 401) {
      const requestUrl = new URL(request.url);
      const login = new URL("/admin/login", requestUrl.origin);
      login.searchParams.set("return_to", `${requestUrl.pathname}${requestUrl.search}`);
      return redirectResponse(`${login.pathname}${login.search}`);
    }

    throw error;
  }
}

async function requireAdminSession(request: Request, env: AdminRouteEnv): Promise<AdminSessionPayload> {
  const session = await requireIdentitySession(request, env, "admin");
  requireAllowedAdminUser(session, env);
  return session;
}

async function requireOwnedPreview(
  env: AdminRouteEnv,
  slug: string,
  session: AdminSessionPayload,
): Promise<void> {
  await getPreviewForPublisher(env, slug, session.email);
}

async function readAdminActionBody(request: Request): Promise<AdminActionBody> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (contentType.toLowerCase().includes("application/json")) {
    return {
      isForm: false,
      values: await readJsonObject(request),
    };
  }

  const form = await request.formData();
  const values: Record<string, unknown> = {};
  for (const [name, value] of form.entries()) {
    values[name] = String(value);
  }

  return {
    isForm: true,
    values,
  };
}

function adminActionResponse(body: AdminActionBody, value: unknown): Response {
  return body.isForm ? redirectResponse("/admin") : jsonResponse(value);
}

function redirectResponse(location: string, headers: HeadersInit = {}): Response {
  return new Response(null, {
    status: 303,
    headers: {
      Location: location,
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function returnToFromRequest(request: Request): string {
  const value = new URL(request.url).searchParams.get("return_to");
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/admin";
}

function sessionUser(session: AdminSessionPayload): Record<string, string> {
  return {
    email: session.email,
    ...(session.name ? { name: session.name } : {}),
    ...(session.tenant ? { tenant: session.tenant } : {}),
  };
}
