import { describe, expect, it, vi } from "vitest";

import worker from "./index";

const mcpEnv = {
  MCP_API_TOKEN: "dev-mcp-token",
  API_BASE_URL: "https://html-api.glean-share.workers.dev",
  PUBLISH_API_TOKEN: "dev-publish-token",
  PUBLISH_INTERNAL_SERVICE_TOKEN: "internal-service-token",
};

describe("MCP endpoint", () => {
  it("requires its own bearer API key", async () => {
    const missing = await postMcp({ jsonrpc: "2.0", id: 1, method: "initialize" }, {});
    const invalid = await postMcp(
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      {
        Authorization: "Bearer wrong",
      },
    );

    expect(missing.status).toBe(401);
    await expect(missing.json()).resolves.toMatchObject({
      error: {
        code: "unauthorized",
      },
    });

    expect(invalid.status).toBe(403);
    await expect(invalid.json()).resolves.toMatchObject({
      error: {
        code: "forbidden",
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
                password: {
                  minLength: 12,
                },
              },
            },
          },
        ],
      },
    });
  });

  it("publishes HTML by forwarding through the API Worker service binding with an internal token", async () => {
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
          url: "https://html.glean-share.workers.dev/p/abc123",
          slug: "abc123",
          expiresAt: "2026-08-18T12:00:00.000Z",
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
          password: "correct horse battery",
          sourceUrl: "https://app.glean.com/chat/test",
        },
      }),
      undefined,
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
            text: "Published HTML preview: https://html.glean-share.workers.dev/p/abc123",
          },
        ],
        structuredContent: {
          url: "https://html.glean-share.workers.dev/p/abc123",
          slug: "abc123",
          status: "active",
        },
      },
    });

    expect(upstreamFetch).toHaveBeenCalledOnce();
    expect(capturedRequest?.url).toBe("https://html-api.glean-share.workers.dev/v1/html-previews");
    expect(capturedRequest?.method).toBe("POST");
    expect(capturedRequest?.headers.get("Authorization")).toBe("Bearer dev-publish-token");
    expect(capturedRequest?.headers.get("X-Publish-Internal-Service-Token")).toBe("internal-service-token");
    expect(capturedRequest?.headers.get("CF-Access-Client-Id")).toBeNull();
    expect(capturedRequest?.headers.get("CF-Access-Client-Secret")).toBeNull();
    expect(capturedRequest?.body).toEqual({
      title: "Smoke Test",
      html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
      password: "correct horse battery",
      sourceUrl: "https://app.glean.com/chat/test",
    });
  });

  it("returns tool errors without exposing internal credentials when the API rejects a publish", async () => {
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
        },
      }),
      undefined,
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
    const response = await postMcp(
      authorizedRpc("tools/call", {
        name: "publish_html_preview",
        arguments: {
          title: "Smoke Test",
          html: "<!doctype html><html><body><h1>Hello</h1></body></html>",
          password: "correct horse battery",
        },
      }),
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

function authorizedRpc(method: string, params?: unknown): unknown {
  return {
    jsonrpc: "2.0",
    id: 1,
    method,
    ...(params === undefined ? {} : { params }),
  };
}

async function postMcp(
  body: unknown,
  headers: Record<string, string> | undefined = { Authorization: "Bearer dev-mcp-token" },
  envOverrides: Record<string, unknown> = {},
) {
  return worker.fetch(
    new Request("http://localhost:8787/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(headers ?? {}),
      },
      body: JSON.stringify(body),
    }),
    {
      ...mcpEnv,
      ...envOverrides,
    } as never,
  );
}
