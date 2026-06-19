import { describe, expect, it } from "vitest";

import { enforceConfiguredRouteOrigin, publicBaseUrl } from "./origin-policy";
import { routeForPath } from "./routes";

const apiEnv = {
  WORKER_ROLE: "api",
  API_BASE_URL: "https://html-api.glean-share.workers.dev",
  MCP_BASE_URL: "https://html-mcp.glean-share.workers.dev",
  PUBLIC_BASE_URL: "https://html.glean-share.workers.dev",
};

const mcpEnv = {
  WORKER_ROLE: "mcp",
  API_BASE_URL: "https://html-api.glean-share.workers.dev",
  MCP_BASE_URL: "https://html-mcp.glean-share.workers.dev",
  PUBLIC_BASE_URL: "https://html.glean-share.workers.dev",
};

const previewEnv = {
  WORKER_ROLE: "preview",
  MCP_BASE_URL: "https://html-mcp.glean-share.workers.dev",
  PUBLIC_BASE_URL: "https://html.glean-share.workers.dev",
};

describe("route origin policy", () => {
  it("classifies API and preview paths once for routing and origin checks", () => {
    expect(routeForPath("/v1/html-previews")).toEqual({ kind: "publish", surface: "api" });
    expect(routeForPath("/v1/html-previews/abc123/unpublish")).toEqual({
      kind: "unpublish",
      slug: "abc123",
      surface: "api",
    });
    expect(routeForPath("/mcp")).toEqual({ kind: "mcp", surface: "mcp" });
    expect(routeForPath("/p/abc123/access")).toEqual({ kind: "access", slug: "abc123", surface: "preview" });
    expect(routeForPath("/p/abc123")).toEqual({ kind: "preview", slug: "abc123", surface: "preview" });
    expect(routeForPath("/nope")).toEqual({ kind: "unknown", surface: "unknown" });
  });

  it("keeps publish routes on the API worker and preview routes on the preview worker", () => {
    const apiRequest = new Request("https://html-api.glean-share.workers.dev/v1/html-previews");
    const previewRequest = new Request("https://html.glean-share.workers.dev/p/abc123");

    expect(
      enforceConfiguredRouteOrigin(apiRequest, new URL(apiRequest.url), apiEnv, routeForPath("/v1/html-previews")),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(
        previewRequest,
        new URL(previewRequest.url),
        previewEnv,
        routeForPath("/p/abc123"),
      ),
    ).toBeNull();
  });

  it("keeps MCP routes only on the MCP worker", () => {
    const mcpRequest = new Request("https://html-mcp.glean-share.workers.dev/mcp");
    const apiMcpRequest = new Request("https://html-api.glean-share.workers.dev/mcp");
    const previewMcpRequest = new Request("https://html.glean-share.workers.dev/mcp");

    expect(enforceConfiguredRouteOrigin(mcpRequest, new URL(mcpRequest.url), mcpEnv, routeForPath("/mcp"))).toBeNull();
    expect(enforceConfiguredRouteOrigin(apiMcpRequest, new URL(apiMcpRequest.url), apiEnv, routeForPath("/mcp"))?.status).toBe(
      404,
    );
    expect(
      enforceConfiguredRouteOrigin(previewMcpRequest, new URL(previewMcpRequest.url), previewEnv, routeForPath("/mcp"))
        ?.status,
    ).toBe(404);
  });

  it("hides the wrong route surface on each production worker", () => {
    const previewPublishRequest = new Request("https://html.glean-share.workers.dev/v1/html-previews");
    const apiPreviewRequest = new Request("https://html-api.glean-share.workers.dev/p/abc123");
    const mcpPreviewRequest = new Request("https://html-mcp.glean-share.workers.dev/p/abc123");

    expect(
      enforceConfiguredRouteOrigin(
        previewPublishRequest,
        new URL(previewPublishRequest.url),
        previewEnv,
        routeForPath("/v1/html-previews"),
      )?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(apiPreviewRequest, new URL(apiPreviewRequest.url), apiEnv, routeForPath("/p/abc123"))
        ?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(
        mcpPreviewRequest,
        new URL(mcpPreviewRequest.url),
        mcpEnv,
        routeForPath("/p/abc123"),
      )?.status,
    ).toBe(404);
  });

  it("returns preview links from the preview origin even when publishing through the API origin", () => {
    const request = new Request("https://html-api.glean-share.workers.dev/v1/html-previews");

    expect(publicBaseUrl(apiEnv, new URL(request.url), request)).toBe("https://html.glean-share.workers.dev");
  });

  it("fails closed when API and preview origins are configured to the same host", () => {
    const request = new Request("https://html.glean-share.workers.dev/v1/html-previews");

    expect(() =>
      enforceConfiguredRouteOrigin(
        request,
        new URL(request.url),
        {
          WORKER_ROLE: "api",
          API_BASE_URL: "https://html.glean-share.workers.dev",
          PUBLIC_BASE_URL: "https://html.glean-share.workers.dev",
        },
        routeForPath("/v1/html-previews"),
      ),
    ).toThrow("API_BASE_URL and PUBLIC_BASE_URL must use separate hosts");
  });
});
