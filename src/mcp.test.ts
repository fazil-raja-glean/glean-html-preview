import { describe, expect, it, vi } from "vitest";

import {
  authorizedRpc,
  codexClientId,
  codexRedirectUri,
  oauthActorEmail,
  requestAccessToken,
  requestPublicAuthorizationCodeAccessToken,
  postMcp,
} from "./mcp-test-helpers";
import worker from "./index";
import { createTestPreviewDb, createTestR2Bucket, requestOn, testApiOriginEnv, testOrigins } from "./test-fixtures";

const tinyPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";

interface CapturedRequest {
  body: unknown;
  headers: Headers;
  method: string;
  url: string;
}

describe("MCP endpoint", () => {
  it("requires an OAuth bearer token", async () => {
    const missing = await postMcp({ jsonrpc: "2.0", id: 1, method: "initialize" }, {});
    const invalid = await postMcp(
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      {
        Authorization: "Bearer wrong-token",
      },
    );

    expect(missing.status).toBe(401);
    expect(missing.headers.get("WWW-Authenticate")).toContain("/.well-known/oauth-protected-resource");
    await expect(missing.json()).resolves.toMatchObject({
      error: {
        code: "unauthorized",
      },
    });

    expect(invalid.status).toBe(401);
    expect(invalid.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
    await expect(invalid.json()).resolves.toMatchObject({
      error: {
        code: "invalid_token",
      },
    });
  });

  it("responds to initialize and lists the HTML management tools", async () => {
    const initialized = await postMcp(authorizedRpc("initialize"));
    const listed = await postMcp(authorizedRpc("tools/list"));

    expect(initialized.status).toBe(200);
    await expect(initialized.json()).resolves.toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: {
          tools: {
            listChanged: false,
          },
        },
        serverInfo: {
          name: "html-sharing",
        },
      },
    });

    expect(listed.status).toBe(200);
    const listedBody = (await listed.json()) as {
      result: { tools: Array<{ inputSchema: { properties: Record<string, unknown>; required: string[] }; name: string }> };
    };
    expect(listedBody.result.tools.map((tool) => tool.name)).toEqual([
      "deploy_html",
      "update_html",
      "update_html_password",
      "delete_html",
    ]);
    const deploySchema = listedBody.result.tools[0].inputSchema;
    expect(deploySchema.required).toEqual(["slug", "title", "html", "password"]);
    expect(deploySchema.properties.allowScripts).toBeUndefined();
    expect(deploySchema.properties.slug).toMatchObject({
      minLength: 3,
      maxLength: 80,
      pattern: "^[a-z0-9]+(?:-[a-z0-9]+)*$",
    });
    expect(listedBody.result.tools[1].inputSchema.required).toEqual(["slug", "html"]);
    expect(listedBody.result.tools[1].inputSchema.properties.password).toBeUndefined();
  });

  it("publishes HTML by forwarding through the API Worker service binding with an internal token", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    let capturedRequest:
      | {
          url: string;
          method: string;
          headers: Headers;
          body: unknown;
        }
      | undefined;
    const upstreamFetch = vi.fn(async (request: Request) => {
      capturedRequest = {
        url: request.url,
        method: request.method,
        headers: request.headers,
        body: await request.clone().json(),
      };
      return new Response(
        JSON.stringify({
          url: `${testOrigins.previewBaseUrl}/p/abc123`,
          slug: "abc123",
          expiresAt: null,
          status: "active",
        }),
        {
          status: 201,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    });

    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "deploy_html",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          images: [
            {
              name: "proof.png",
              mimeType: "image/png",
              dataBase64: tinyPngBase64,
            },
          ],
          password: "correct horse battery",
          slug: "hello-world-test",
          sourceUrl: "https://source.example.test/artifacts/test",
        },
      }),
      {
        Authorization: `Bearer ${accessToken}`,
      },
      {
        PUBLISH_API: {
          fetch: upstreamFetch,
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        content: [
          {
            type: "text",
            text: `Deployed HTML preview: ${testOrigins.previewBaseUrl}/p/abc123`,
          },
        ],
        structuredContent: {
          url: `${testOrigins.previewBaseUrl}/p/abc123`,
          slug: "abc123",
          expiresAt: null,
          status: "active",
        },
      },
    });

    expect(upstreamFetch).toHaveBeenCalledOnce();
    expect(capturedRequest?.url).toBe(`${testOrigins.apiBaseUrl}/v1/html-previews`);
    expect(capturedRequest?.method).toBe("POST");
    expect(capturedRequest?.headers.get("Authorization")).toBe("Bearer dev-publish-token");
    expect(capturedRequest?.headers.get("X-Publish-Internal-Service-Token")).toBe("internal-service-token");
    expect(capturedRequest?.headers.get("X-Publish-Actor-Email")).toBe(oauthActorEmail);
    expect(capturedRequest?.headers.get("CF-Access-Client-Id")).toBeNull();
    expect(capturedRequest?.headers.get("CF-Access-Client-Secret")).toBeNull();
    const capturedBody = toRecord(capturedRequest?.body);
    expect(capturedBody).toMatchObject({
      title: "Smoke Test",
      html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
      images: [
        {
          name: "proof.png",
          mimeType: "image/png",
          dataBase64: tinyPngBase64,
        },
      ],
      password: "correct horse battery",
      slug: "hello-world-test",
      sourceUrl: "https://source.example.test/artifacts/test",
    });
  });

  it("updates HTML by forwarding a PUT through the API Worker service binding", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    let capturedRequest: CapturedRequest | undefined;
    const upstreamFetch = vi.fn(async (request: Request) => {
      capturedRequest = await captureRequest(request);
      return jsonResponse({
        url: `${testOrigins.previewBaseUrl}/p/hello-world-test`,
        slug: "hello-world-test",
        expiresAt: null,
        status: "active",
      });
    });

    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "update_html",
        arguments: {
          slug: "hello-world-test",
          title: "Updated Smoke Test",
          html: "<!doctype html><html><body><h1>Updated</h1></body></html>",
          sourceUrl: "https://source.example.test/artifacts/updated",
        },
      }),
      {
        Authorization: `Bearer ${accessToken}`,
      },
      {
        PUBLISH_API: {
          fetch: upstreamFetch,
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      result: {
        content: [
          {
            type: "text",
            text: `Updated HTML preview: ${testOrigins.previewBaseUrl}/p/hello-world-test`,
          },
        ],
        structuredContent: {
          slug: "hello-world-test",
          status: "active",
        },
      },
    });

    expect(capturedRequest?.url).toBe(`${testOrigins.apiBaseUrl}/v1/html-previews/hello-world-test`);
    expect(capturedRequest?.method).toBe("PUT");
    expect(capturedRequest?.headers.get("X-Publish-Actor-Email")).toBe(oauthActorEmail);
    expect(toRecord(capturedRequest?.body)).toMatchObject({
      title: "Updated Smoke Test",
      html: "<!doctype html><html><body><h1>Updated</h1></body></html>",
      sourceUrl: "https://source.example.test/artifacts/updated",
    });
    expect(toRecord(capturedRequest?.body).slug).toBeUndefined();
  });

  it("rotates the viewer password through the API Worker service binding", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    let capturedRequest: CapturedRequest | undefined;
    const upstreamFetch = vi.fn(async (request: Request) => {
      capturedRequest = await captureRequest(request);
      return jsonResponse({ slug: "hello-world-test", status: "active" });
    });

    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "update_html_password",
        arguments: {
          slug: "hello-world-test",
          password: "new correct horse",
        },
      }),
      {
        Authorization: `Bearer ${accessToken}`,
      },
      {
        PUBLISH_API: {
          fetch: upstreamFetch,
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      result: {
        content: [
          {
            type: "text",
            text: "Updated HTML preview password: hello-world-test",
          },
        ],
        structuredContent: {
          slug: "hello-world-test",
          status: "active",
        },
      },
    });

    expect(capturedRequest?.url).toBe(`${testOrigins.apiBaseUrl}/v1/html-previews/hello-world-test/password`);
    expect(capturedRequest?.method).toBe("POST");
    expect(toRecord(capturedRequest?.body)).toEqual({ password: "new correct horse" });
  });

  it("deletes HTML through the API Worker service binding", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    let capturedRequest: CapturedRequest | undefined;
    const upstreamFetch = vi.fn(async (request: Request) => {
      capturedRequest = await captureRequest(request);
      return jsonResponse({ slug: "hello-world-test", status: "deleted" });
    });

    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "delete_html",
        arguments: {
          slug: "hello-world-test",
        },
      }),
      {
        Authorization: `Bearer ${accessToken}`,
      },
      {
        PUBLISH_API: {
          fetch: upstreamFetch,
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      result: {
        content: [
          {
            type: "text",
            text: "Deleted HTML preview: hello-world-test",
          },
        ],
        structuredContent: {
          slug: "hello-world-test",
          status: "deleted",
        },
      },
    });

    expect(capturedRequest?.url).toBe(`${testOrigins.apiBaseUrl}/v1/html-previews/hello-world-test`);
    expect(capturedRequest?.method).toBe("DELETE");
    expect(capturedRequest?.body).toBeNull();
  });

  it("runs the MCP deploy, update, password, and delete lifecycle through a local API binding", async () => {
    const previewDb = createTestPreviewDb();
    const bucket = createTestR2Bucket();
    const apiEnv = {
      ...testApiOriginEnv,
      COOKIE_SIGNING_SECRET: "test-cookie-secret",
      HTML_PREVIEWS: bucket,
      PASSWORD_PEPPER: "test-password-pepper",
      PREVIEW_DB: previewDb,
      PUBLISH_API_TOKEN: "dev-publish-token",
      PUBLISH_INTERNAL_SERVICE_TOKEN: "internal-service-token",
      PUBLISHER_EMAIL_DOMAIN: "example.com",
      TRUSTED_PUBLISHER_EMAIL: "service@example.com",
    };
    const mcpEnv = {
      PREVIEW_DB: previewDb,
      PUBLISH_API: {
        fetch: (request: Request) => worker.fetch(request, apiEnv as never),
      },
    };
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    const slug = "mcp-lifecycle-smoke";

    const deployed = await callMcpTool(accessToken, "deploy_html", {
      slug,
      title: "MCP Lifecycle Smoke",
      html: "<!doctype html><html><body><h1>Version one</h1></body></html>",
      password: "correct horse battery",
    }, mcpEnv);
    expect(deployed.structuredContent).toMatchObject({
      slug,
      status: "active",
      url: `${testOrigins.previewBaseUrl}/p/${slug}`,
    });

    const originalAccessCookie = await viewerAccessCookie(apiEnv, slug, "correct horse battery");
    await expect(previewText(apiEnv, slug, originalAccessCookie)).resolves.toContain("Version one");

    const updated = await callMcpTool(accessToken, "update_html", {
      slug,
      title: "MCP Lifecycle Smoke Updated",
      html: "<!doctype html><html><body><h1>Version two</h1></body></html>",
      sourceUrl: "https://source.example.test/mcp-lifecycle",
    }, mcpEnv);
    expect(updated.structuredContent).toMatchObject({
      slug,
      status: "active",
      url: `${testOrigins.previewBaseUrl}/p/${slug}`,
    });
    await expect(previewText(apiEnv, slug, originalAccessCookie)).resolves.toContain("Version two");

    const passwordUpdated = await callMcpTool(accessToken, "update_html_password", {
      slug,
      password: "rotated correct horse",
    }, mcpEnv);
    expect(passwordUpdated.structuredContent).toMatchObject({ slug, status: "active" });
    await expect(previewText(apiEnv, slug, originalAccessCookie)).resolves.toContain("password protected");

    const rotatedAccessCookie = await viewerAccessCookie(apiEnv, slug, "rotated correct horse");
    await expect(previewText(apiEnv, slug, rotatedAccessCookie)).resolves.toContain("Version two");

    const deleted = await callMcpTool(accessToken, "delete_html", { slug }, mcpEnv);
    expect(deleted.structuredContent).toMatchObject({ slug, status: "deleted" });
    await expect(previewStatus(apiEnv, slug, rotatedAccessCookie)).resolves.toBe(404);

    const redeployed = await callMcpTool(accessToken, "deploy_html", {
      slug,
      title: "MCP Lifecycle Smoke Redeployed",
      html: "<!doctype html><html><body><h1>Redeployed</h1></body></html>",
      password: "correct horse battery",
    }, mcpEnv);
    expect(redeployed.structuredContent).toMatchObject({ slug, status: "active" });

    await callMcpTool(accessToken, "delete_html", { slug }, mcpEnv);
  });

  it.each([
    {
      name: "deploy_html",
      arguments: {
        title: "Smoke Test",
        html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
        password: "correct horse battery",
        slug: "hello-world-test",
      },
    },
    {
      name: "update_html",
      arguments: {
        slug: "hello-world-test",
        html: "<!doctype html><html><body><h1>Updated</h1></body></html>",
      },
    },
    {
      name: "update_html_password",
      arguments: {
        slug: "hello-world-test",
        password: "new correct horse",
      },
    },
    {
      name: "delete_html",
      arguments: {
        slug: "hello-world-test",
      },
    },
  ])("rejects $name tool calls when the OAuth token is not bound to a Glean user", async (toolCall) => {
    const upstreamFetch = vi.fn(async () => new Response(null, { status: 500 }));
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: toolCall.name,
        arguments: toolCall.arguments,
      }),
      {
        Authorization: `Bearer ${await requestAccessToken()}`,
      },
      {
        PUBLISH_API: {
          fetch: upstreamFetch,
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: -32602,
        message: "OAuth token is not bound to an authenticated Glean user",
      },
    });
    expect(upstreamFetch).not.toHaveBeenCalled();
  });

  it("returns tool errors without exposing internal credentials when the API rejects a publish", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "deploy_html",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
          slug: "hello-world-test",
        },
      }),
      {
        Authorization: `Bearer ${accessToken}`,
      },
      {
        PUBLISH_API: {
          fetch: vi.fn(async () => {
            return new Response(
              JSON.stringify({
                error: {
                  code: "invalid_html",
                  message: "HTML must be a complete document with an html element",
                },
              }),
              {
                status: 400,
                headers: {
                  "Content-Type": "application/json",
                },
              },
            );
          }),
        },
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      result: {
        isError: true,
        content: [
          {
            type: "text",
            text: "Deploy failed: HTML must be a complete document with an html element",
          },
        ],
        structuredContent: {
          status: 400,
          error: "invalid_html",
        },
      },
    });
  });

  it("fails closed when the API Worker service binding is missing", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "deploy_html",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
          slug: "hello-world-test",
        },
      }),
      {
        Authorization: `Bearer ${accessToken}`,
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: -32603,
        message: "PUBLISH_API service binding is not configured",
      },
    });
  });
});

function toRecord(value: unknown): Record<string, unknown> {
  expect(value).toBeTypeOf("object");
  expect(value).not.toBeNull();
  return value as Record<string, unknown>;
}

async function captureRequest(request: Request): Promise<CapturedRequest> {
  const text = await request.clone().text();
  return {
    url: request.url,
    method: request.method,
    headers: request.headers,
    body: text ? JSON.parse(text) : null,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

async function callMcpTool(
  accessToken: string,
  name: string,
  args: Record<string, unknown>,
  envOverrides: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await postMcp(
    authorizedRpc("tools/call", {
      name,
      arguments: args,
    }),
    {
      Authorization: `Bearer ${accessToken}`,
    },
    envOverrides,
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    error?: unknown;
    result?: Record<string, unknown>;
  };
  expect(body.error).toBeUndefined();
  expect(body.result).toBeTypeOf("object");
  return body.result as Record<string, unknown>;
}

async function viewerAccessCookie(env: Record<string, unknown>, slug: string, password: string): Promise<string> {
  const response = await worker.fetch(
    requestOn("http://localhost:8787", `/p/${slug}/access`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ password }),
    }),
    env as never,
  );
  expect(response.status).toBe(303);
  const cookie = response.headers.get("Set-Cookie");
  expect(cookie).toBeTypeOf("string");
  return cookie?.match(/html_preview_access=([^;]+)/)?.[1] ?? "";
}

async function previewText(env: Record<string, unknown>, slug: string, accessCookie: string): Promise<string> {
  const response = await worker.fetch(
    requestOn("http://localhost:8787", `/p/${slug}`, {
      headers: {
        Cookie: `html_preview_access=${accessCookie}`,
      },
    }),
    env as never,
  );
  expect(response.status).toBe(200);
  return response.text();
}

async function previewStatus(env: Record<string, unknown>, slug: string, accessCookie: string): Promise<number> {
  const response = await worker.fetch(
    requestOn("http://localhost:8787", `/p/${slug}`, {
      headers: {
        Cookie: `html_preview_access=${accessCookie}`,
      },
    }),
    env as never,
  );
  return response.status;
}
