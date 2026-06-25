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
import { testOrigins } from "./test-fixtures";

const tinyPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";

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

  it("responds to initialize and lists the publish tool", async () => {
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
    await expect(listed.json()).resolves.toMatchObject({
      result: {
        tools: [
          {
            name: "publish_html_preview",
            inputSchema: {
              required: ["title", "html", "password"],
              properties: {
                allowScripts: {
                  type: "boolean",
                },
                password: {
                  minLength: 5,
                },
                slug: {
                  minLength: 3,
                  maxLength: 80,
                  pattern: "^[a-z0-9]+(?:-[a-z0-9]+)*$",
                },
              },
            },
          },
        ],
      },
    });
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
        name: "publish_html_preview",
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
          allowScripts: true,
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
            text: `Published HTML preview: ${testOrigins.previewBaseUrl}/p/abc123`,
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
      allowScripts: true,
      password: "correct horse battery",
      slug: "hello-world-test",
      sourceUrl: "https://source.example.test/artifacts/test",
    });
  });

  it("rejects publish tool calls when the OAuth token is not bound to a Glean user", async () => {
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
        },
      }),
      {
        Authorization: `Bearer ${await requestAccessToken()}`,
      },
      {
        PUBLISH_API: {
          fetch: vi.fn(async () => new Response(null, { status: 500 })),
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
  });

  it("returns tool errors without exposing internal credentials when the API rejects a publish", async () => {
    const accessToken = await requestPublicAuthorizationCodeAccessToken(codexClientId, codexRedirectUri);
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
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
            text: "Publish failed: HTML must be a complete document with an html element",
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
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
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
