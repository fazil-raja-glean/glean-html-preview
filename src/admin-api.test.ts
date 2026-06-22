import { describe, expect, it } from "vitest";

import { signAccessCookie } from "./security";
import worker from "./index";
import { createTestPreviewDb, createTestR2Bucket } from "./test-fixtures";
import type { PreviewRow } from "./preview-store";

const adminEmail = "admin@example.com";
const sessionSecret = "test-admin-session-secret";

describe("admin UI and API", () => {
  it("redirects logged-out admins to login and supports local Glean identity bypass", async () => {
    const env = createAdminEnv([previewRow()]);
    const loggedOut = await worker.fetch(new Request("http://localhost:8787/"), env as never);
    expect(loggedOut.status).toBe(303);
    expect(loggedOut.headers.get("Location")).toBe("/login?return_to=%2F");

    const login = await worker.fetch(new Request("http://localhost:8787/login"), env as never);
    const cookie = sessionCookie(login);
    expect(login.status).toBe(303);
    expect(cookie).toContain("html_admin_session=");

    const session = await worker.fetch(
      new Request("http://localhost:8787/api/session", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );

    expect(session.status).toBe(200);
    await expect(session.json()).resolves.toMatchObject({
      user: {
        email: adminEmail,
      },
      csrf: expect.any(String),
    });
  });

  it("keeps admin login return targets same-origin", async () => {
    const env = createAdminEnv([]);
    const backslashRedirect = encodeURIComponent(String.raw`/\evil.example.test/`);

    const safe = await worker.fetch(new Request("http://localhost:8787/login?return_to=/api/previews"), env as never);
    const absolute = await worker.fetch(
      new Request("http://localhost:8787/login?return_to=https://evil.example.test/"),
      env as never,
    );
    const networkPath = await worker.fetch(
      new Request("http://localhost:8787/login?return_to=//evil.example.test/"),
      env as never,
    );
    const backslash = await worker.fetch(
      new Request(`http://localhost:8787/login?return_to=${backslashRedirect}`),
      env as never,
    );

    expect(safe.headers.get("Location")).toBe("/api/previews");
    expect(absolute.headers.get("Location")).toBe("/");
    expect(networkPath.headers.get("Location")).toBe("/");
    expect(backslash.headers.get("Location")).toBe("/");
  });

  it("starts production admin OAuth with the API-origin callback path", async () => {
    const env = {
      ...createAdminEnv([]),
      API_BASE_URL: "https://api.example.test",
      GLEAN_OAUTH_AUTHORIZATION_URL: "https://glean.example.test/oauth/authorize",
      GLEAN_OAUTH_CLIENT_ID: "html-sharing-admin",
      GLEAN_OAUTH_CLIENT_SECRET: "secret",
      GLEAN_OAUTH_TOKEN_URL: "https://glean.example.test/oauth/token",
    };

    const response = await worker.fetch(
      new Request("https://api.example.test/login?return_to=/api/previews"),
      env as never,
    );
    const redirect = new URL(response.headers.get("Location") ?? "");
    const stateCookie = response.headers.get("Set-Cookie");

    expect(response.status).toBe(302);
    expect(redirect.origin + redirect.pathname).toBe("https://glean.example.test/oauth/authorize");
    expect(redirect.searchParams.get("client_id")).toBe("html-sharing-admin");
    expect(redirect.searchParams.get("redirect_uri")).toBe("https://api.example.test/auth/callback");
    expect(redirect.searchParams.get("scope")).toBe("openid email");
    expect(stateCookie).toContain("html_admin_oauth_state=");
    expect(stateCookie).toContain("Path=/auth");
  });

  it("serves the client-rendered admin shell without exposing publish credentials", async () => {
    const env = createAdminEnv([previewRow({ title: "<Preview>" })]);
    const cookie = sessionCookie(await worker.fetch(new Request("http://localhost:8787/login"), env as never));
    const response = await worker.fetch(
      new Request("http://localhost:8787/", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );
    const html = await response.text();

    expect(response.status).toBe(200);
    // The shell is static; preview data is fetched client-side from the JSON API.
    expect(html).toContain('src="/app.js"');
    expect(html).not.toContain("<Preview>");
    expect(html).not.toContain("secret</body>");
    expect(html).not.toContain("dev-publish-token");
    expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("Content-Security-Policy")).toContain("script-src 'self'");

    // The list endpoint carries the (raw) title; the client escapes it via textContent.
    const list = await worker.fetch(
      new Request("http://localhost:8787/api/previews", { headers: { Cookie: cookie } }),
      env as never,
    );
    const listBody = (await list.json()) as { previews: Array<{ title: string }> };
    expect(list.status).toBe(200);
    expect(listBody.previews[0].title).toBe("<Preview>");
  });

  it("serves the admin script and styles with the admin CSP", async () => {
    const env = createAdminEnv([]);
    const script = await worker.fetch(new Request("http://localhost:8787/app.js"), env as never);
    const styles = await worker.fetch(new Request("http://localhost:8787/app.css"), env as never);

    expect(script.status).toBe(200);
    expect(script.headers.get("Content-Type")).toContain("application/javascript");
    expect(script.headers.get("Content-Security-Policy")).toContain("script-src 'self'");
    expect(await script.text()).toContain("/api/previews");

    expect(styles.status).toBe(200);
    expect(styles.headers.get("Content-Type")).toContain("text/css");
  });

  it("publishes a new preview from the admin session and lists it", async () => {
    const env = createAdminEnv([]);
    const { cookie, csrf } = await adminSession(env);

    const created = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({
          csrf,
          title: "Uploaded Page",
          password: "correct horse",
          html: "<!doctype html><html><body>hi</body></html>",
        }),
      }),
      env as never,
    );
    expect(created.status).toBe(201);
    const createdBody = (await created.json()) as { slug: string; url: string };
    expect(createdBody.slug).toBeTruthy();
    expect(createdBody.url).toContain("/p/" + createdBody.slug);

    const list = await worker.fetch(
      new Request("http://localhost:8787/api/previews", { headers: { Cookie: cookie } }),
      env as never,
    );
    const listBody = (await list.json()) as { previews: Array<{ slug: string; title: string }> };
    expect(listBody.previews.some((preview) => preview.slug === createdBody.slug)).toBe(true);
  });

  it("rejects admin publishing without CSRF, session, or valid input", async () => {
    const env = createAdminEnv([]);
    const { cookie, csrf } = await adminSession(env);
    const validBody = {
      csrf,
      title: "X",
      password: "correct horse",
      html: "<!doctype html><html><body>hi</body></html>",
    };

    const noSession = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(validBody),
      }),
      env as never,
    );
    expect(noSession.status).toBe(401);

    const badCsrf = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ ...validBody, csrf: "wrong" }),
      }),
      env as never,
    );
    expect(badCsrf.status).toBe(403);

    const badHtml = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ ...validBody, html: "not html" }),
      }),
      env as never,
    );
    expect(badHtml.status).toBe(400);
  });

  it("keeps admin JSON responses on safe deployment metadata", async () => {
    const env = createAdminEnv([previewRow()]);
    const cookie = sessionCookie(await worker.fetch(new Request("http://localhost:8787/login"), env as never));
    const list = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );
    const details = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );

    expect(list.status).toBe(200);
    expect(details.status).toBe(200);
    const listBody = JSON.stringify(await list.json());
    const detailsBody = JSON.stringify(await details.json());
    expect(listBody).toContain(adminEmail);
    expect(listBody).not.toContain("password_hash");
    expect(listBody).not.toContain("password_salt");
    expect(listBody).not.toContain("previews/abc123/index.html");
    expect(detailsBody).not.toContain("password_hash");
    expect(detailsBody).not.toContain("password_salt");
    expect(detailsBody).not.toContain("previews/abc123/index.html");
  });

  it("shows only previews owned by the signed-in user", async () => {
    const env = createAdminEnv([
      previewRow(),
      previewRow({
        slug: "other456",
        title: "Other Preview",
        object_key: "previews/other456/index.html",
        publisher_email: "other@example.com",
      }),
    ]);
    const cookie = sessionCookie(await worker.fetch(new Request("http://localhost:8787/login"), env as never));
    const htmlResponse = await worker.fetch(
      new Request("http://localhost:8787/", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );
    const listResponse = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );

    const listBody = JSON.stringify(await listResponse.json());
    expect(htmlResponse.status).toBe(200);
    expect(listResponse.status).toBe(200);
    // Owner scoping is enforced in the JSON list; the static shell carries no preview data.
    expect(listBody).toContain("Admin Preview");
    expect(listBody).not.toContain("Other Preview");
    expect(listBody).toContain("abc123");
    expect(listBody).not.toContain("other456");
  });

  it("does not allow admin actions against another publisher's preview", async () => {
    const env = createAdminEnv([
      previewRow(),
      previewRow({
        slug: "other456",
        title: "Other Preview",
        object_key: "previews/other456/index.html",
        publisher_email: "other@example.com",
      }),
    ]);
    const { cookie, csrf } = await adminSession(env);

    const details = await worker.fetch(
      new Request("http://localhost:8787/api/previews/other456", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );
    const unpublished = await worker.fetch(
      new Request("http://localhost:8787/api/previews/other456/unpublish", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ csrf }),
      }),
      env as never,
    );
    const stillActive = await worker.fetch(new Request("http://localhost:8787/p/other456"), env as never);

    expect(details.status).toBe(404);
    expect(unpublished.status).toBe(404);
    expect(stillActive.status).toBe(200);
    expect(await stillActive.text()).toContain("password protected");
  });

  it("requires CSRF before admin mutations", async () => {
    const env = createAdminEnv([previewRow()]);
    const cookie = sessionCookie(await worker.fetch(new Request("http://localhost:8787/login"), env as never));
    const response = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123/unpublish", {
        method: "POST",
        headers: {
          Cookie: cookie,
        },
        body: new URLSearchParams(),
      }),
      env as never,
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "invalid_csrf",
      },
    });
  });

  it("rechecks the current admin domain for existing sessions", async () => {
    const env = createAdminEnv([previewRow()]);
    const cookie = sessionCookie(await worker.fetch(new Request("http://localhost:8787/login"), env as never));

    const response = await worker.fetch(
      new Request("http://localhost:8787/api/previews", {
        headers: {
          Cookie: cookie,
        },
      }),
      {
        ...env,
        ADMIN_ALLOWED_EMAIL_DOMAIN: "other-domain.example",
        PUBLISHER_EMAIL_DOMAIN: "other-domain.example",
      } as never,
    );

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "admin_email_forbidden",
      },
    });
  });

  it("rotates viewer passwords and invalidates old viewer cookies", async () => {
    const env = createAdminEnv([previewRow({ password_version: 1 })]);
    const { cookie, csrf } = await adminSession(env);
    const oldViewerCookie = await signAccessCookie(
      {
        slug: "abc123",
        passwordVersion: 1,
        expiresAt: Date.now() + 60_000,
      },
      sessionSecret,
    );

    const rotated = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123/password", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          csrf,
          password: "new correct horse",
        }),
      }),
      env as never,
    );
    expect(rotated.status).toBe(200);

    const preview = await worker.fetch(
      new Request("http://localhost:8787/p/abc123", {
        headers: {
          Cookie: `html_preview_access=${oldViewerCookie}`,
        },
      }),
      env as never,
    );
    expect(preview.status).toBe(200);
    expect(await preview.text()).toContain("password protected");
  });

  it("unpublishes and hard deletes only with explicit confirmation", async () => {
    const env = createAdminEnv([previewRow()]);
    const { cookie, csrf } = await adminSession(env);

    const missingConfirmation = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123/delete", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          csrf,
          confirmSlug: "wrong",
        }),
      }),
      env as never,
    );
    expect(missingConfirmation.status).toBe(400);

    const unpublished = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123/unpublish", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ csrf }),
      }),
      env as never,
    );
    expect(unpublished.status).toBe(200);

    const gone = await worker.fetch(new Request("http://localhost:8787/p/abc123"), env as never);
    expect(gone.status).toBe(410);

    const deleted = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123/delete", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          csrf,
          confirmSlug: "abc123",
        }),
      }),
      env as never,
    );
    expect(deleted.status).toBe(200);

    const details = await worker.fetch(
      new Request("http://localhost:8787/api/previews/abc123", {
        headers: {
          Cookie: cookie,
        },
      }),
      env as never,
    );
    expect(details.status).toBe(404);
  });
});

async function adminSession(env: Record<string, unknown>): Promise<{ cookie: string; csrf: string }> {
  const login = await worker.fetch(new Request("http://localhost:8787/login"), env as never);
  const cookie = sessionCookie(login);
  const session = await worker.fetch(
    new Request("http://localhost:8787/api/session", {
      headers: {
        Cookie: cookie,
      },
    }),
    env as never,
  );
  const body = (await session.json()) as { csrf: string };
  return {
    cookie,
    csrf: body.csrf,
  };
}

function createAdminEnv(previews: PreviewRow[]): Record<string, unknown> {
  return {
    WORKER_ROLE: "combined",
    ADMIN_ALLOWED_EMAIL_DOMAIN: "example.com",
    ADMIN_LOCAL_BYPASS_EMAIL: "Admin@Example.com",
    ADMIN_SESSION_SECRET: sessionSecret,
    COOKIE_SIGNING_SECRET: sessionSecret,
    PASSWORD_PEPPER: "pepper",
    PUBLISH_API_TOKEN: "dev-publish-token",
    PUBLISHER_EMAIL_DOMAIN: "example.com",
    PUBLIC_BASE_URL: "https://preview.example.test",
    HTML_PREVIEWS: createTestR2Bucket(
      Object.fromEntries(previews.map((preview) => [preview.object_key, "<!doctype html><html><body>secret</body></html>"])),
    ),
    PREVIEW_DB: createTestPreviewDb(previews),
  };
}

function previewRow(overrides: Partial<PreviewRow> = {}): PreviewRow {
  return {
    slug: "abc123",
    title: "Admin Preview",
    object_key: "previews/abc123/index.html",
    password_hash: "hash",
    password_salt: "salt",
    password_iterations: 100_000,
    password_version: 1,
    publisher_email: adminEmail,
    source_url: "https://source.example.test",
    created_at: "2026-06-20T12:00:00.000Z",
    expires_at: "2099-06-20T12:00:00.000Z",
    deleted_at: null,
    ...overrides,
  };
}

function sessionCookie(response: Response): string {
  const header = response.headers.get("Set-Cookie");
  expect(header).toBeTypeOf("string");
  return header?.split(";")[0] ?? "";
}
