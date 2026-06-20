import { describe, expect, it } from "vitest";

import { enforceConfiguredRouteOrigin, publicBaseUrl } from "./origin-policy";
import { routeForPath } from "./routes";
import { requestOn, testApiOriginEnv, testMcpOriginEnv, testPreviewOriginEnv } from "./test-fixtures";

describe("route origin policy", () => {
  it("classifies API and preview paths once for routing and origin checks", () => {
    expect(routeForPath("/v1/html-previews")).toEqual({ kind: "publish", surface: "api" });
    expect(routeForPath("/v1/html-previews/abc123/unpublish")).toEqual({
      kind: "unpublish",
      slug: "abc123",
      surface: "api",
    });
    expect(routeForPath("/mcp")).toEqual({ kind: "mcp", surface: "mcp" });
    expect(routeForPath("/oauth/token")).toEqual({ action: "token", kind: "oauth", surface: "mcp" });
    expect(routeForPath("/oauth/callback")).toEqual({ action: "callback", kind: "oauth", surface: "mcp" });
    expect(routeForPath("/.well-known/oauth-authorization-server")).toEqual({
      action: "authorizationServerMetadata",
      kind: "oauth",
      surface: "mcp",
    });
    expect(routeForPath("/.well-known/oauth-protected-resource")).toEqual({
      action: "protectedResourceMetadata",
      kind: "oauth",
      surface: "mcp",
    });
    expect(routeForPath("/.well-known/oauth-protected-resource/mcp")).toEqual({
      action: "protectedResourceMetadata",
      kind: "oauth",
      surface: "mcp",
    });
    expect(routeForPath("/oauth/authorize")).toEqual({ action: "authorize", kind: "oauth", surface: "mcp" });
    expect(routeForPath("/admin")).toEqual({ action: "home", kind: "admin", surface: "api" });
    expect(routeForPath("/admin/login")).toEqual({ action: "login", kind: "admin", surface: "api" });
    expect(routeForPath("/admin/api/previews")).toEqual({ action: "previews", kind: "admin", surface: "api" });
    expect(routeForPath("/admin/api/previews/abc123/password")).toEqual({
      action: "rotatePassword",
      kind: "admin",
      slug: "abc123",
      surface: "api",
    });
    expect(routeForPath("/p/abc123/access")).toEqual({ kind: "access", slug: "abc123", surface: "preview" });
    expect(routeForPath("/p/abc123")).toEqual({ kind: "preview", slug: "abc123", surface: "preview" });
    expect(routeForPath("/nope")).toEqual({ kind: "unknown", surface: "unknown" });
  });

  it("keeps publish and admin routes on the API worker and preview routes on the preview worker", () => {
    const apiRequest = requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews");
    const adminRequest = requestOn(testApiOriginEnv.API_BASE_URL, "/admin");
    const previewRequest = requestOn(testPreviewOriginEnv.PUBLIC_BASE_URL, "/p/abc123");

    expect(
      enforceConfiguredRouteOrigin(
        apiRequest,
        new URL(apiRequest.url),
        testApiOriginEnv,
        routeForPath("/v1/html-previews"),
      ),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(adminRequest, new URL(adminRequest.url), testApiOriginEnv, routeForPath("/admin")),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(
        previewRequest,
        new URL(previewRequest.url),
        testPreviewOriginEnv,
        routeForPath("/p/abc123"),
      ),
    ).toBeNull();
  });

  it("keeps MCP routes only on the MCP worker", () => {
    const mcpRequest = requestOn(testMcpOriginEnv.MCP_BASE_URL, "/mcp");
    const oauthAuthorizeRequest = requestOn(testMcpOriginEnv.MCP_BASE_URL, "/oauth/authorize");
    const oauthCallbackRequest = requestOn(testMcpOriginEnv.MCP_BASE_URL, "/oauth/callback");
    const oauthTokenRequest = requestOn(testMcpOriginEnv.MCP_BASE_URL, "/oauth/token");
    const apiMcpRequest = requestOn(testApiOriginEnv.API_BASE_URL, "/mcp");
    const previewMcpRequest = requestOn(testPreviewOriginEnv.PUBLIC_BASE_URL, "/mcp");

    expect(
      enforceConfiguredRouteOrigin(mcpRequest, new URL(mcpRequest.url), testMcpOriginEnv, routeForPath("/mcp")),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(
        oauthAuthorizeRequest,
        new URL(oauthAuthorizeRequest.url),
        testMcpOriginEnv,
        routeForPath("/oauth/authorize"),
      ),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(
        oauthTokenRequest,
        new URL(oauthTokenRequest.url),
        testMcpOriginEnv,
        routeForPath("/oauth/token"),
      ),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(
        oauthCallbackRequest,
        new URL(oauthCallbackRequest.url),
        testMcpOriginEnv,
        routeForPath("/oauth/callback"),
      ),
    ).toBeNull();
    expect(
      enforceConfiguredRouteOrigin(apiMcpRequest, new URL(apiMcpRequest.url), testApiOriginEnv, routeForPath("/mcp"))
        ?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(
        previewMcpRequest,
        new URL(previewMcpRequest.url),
        testPreviewOriginEnv,
        routeForPath("/mcp"),
      )
        ?.status,
    ).toBe(404);
  });

  it("hides the wrong route surface on each production worker", () => {
    const previewPublishRequest = requestOn(testPreviewOriginEnv.PUBLIC_BASE_URL, "/v1/html-previews");
    const previewAdminRequest = requestOn(testPreviewOriginEnv.PUBLIC_BASE_URL, "/admin");
    const apiPreviewRequest = requestOn(testApiOriginEnv.API_BASE_URL, "/p/abc123");
    const mcpAdminRequest = requestOn(testMcpOriginEnv.MCP_BASE_URL, "/admin");
    const mcpPreviewRequest = requestOn(testMcpOriginEnv.MCP_BASE_URL, "/p/abc123");

    expect(
      enforceConfiguredRouteOrigin(
        previewPublishRequest,
        new URL(previewPublishRequest.url),
        testPreviewOriginEnv,
        routeForPath("/v1/html-previews"),
      )?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(
        previewAdminRequest,
        new URL(previewAdminRequest.url),
        testPreviewOriginEnv,
        routeForPath("/admin"),
      )?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(
        apiPreviewRequest,
        new URL(apiPreviewRequest.url),
        testApiOriginEnv,
        routeForPath("/p/abc123"),
      )?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(
        mcpAdminRequest,
        new URL(mcpAdminRequest.url),
        testMcpOriginEnv,
        routeForPath("/admin"),
      )?.status,
    ).toBe(404);
    expect(
      enforceConfiguredRouteOrigin(
        mcpPreviewRequest,
        new URL(mcpPreviewRequest.url),
        testMcpOriginEnv,
        routeForPath("/p/abc123"),
      )?.status,
    ).toBe(404);
  });

  it("returns preview links from the preview origin even when publishing through the API origin", () => {
    const request = requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews");

    expect(publicBaseUrl(testApiOriginEnv, new URL(request.url), request)).toBe(testApiOriginEnv.PUBLIC_BASE_URL);
  });

  it("fails closed when API and preview origins are configured to the same host", () => {
    const sameOrigin = "https://same-origin.example.test";
    const request = requestOn(sameOrigin, "/v1/html-previews");

    expect(() =>
      enforceConfiguredRouteOrigin(
        request,
        new URL(request.url),
        {
          WORKER_ROLE: "api",
          API_BASE_URL: sameOrigin,
          PUBLIC_BASE_URL: sameOrigin,
        },
        routeForPath("/v1/html-previews"),
      ),
    ).toThrow("API_BASE_URL and PUBLIC_BASE_URL must use separate hosts");
  });
});
