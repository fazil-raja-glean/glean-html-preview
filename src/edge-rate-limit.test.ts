import { describe, expect, it, vi } from "vitest";

import { edgeRateLimitKey, enforceEdgeRateLimit } from "./edge-rate-limit";
import { requestOn, testApiOriginEnv, testPreviewOriginEnv } from "./test-fixtures";

describe("edge rate limiting", () => {
  it("keys limits by route and hashed Cloudflare IP", async () => {
    const request = requestOn(testPreviewOriginEnv.PUBLIC_BASE_URL, "/p/abc/access", {
      headers: {
        "CF-Connecting-IP": "203.0.113.10",
      },
    });

    const accessKey = await edgeRateLimitKey(request, "post:/p/abc/access", "secret");
    const sameAccessKey = await edgeRateLimitKey(request, "post:/p/abc/access", "secret");
    const publishKey = await edgeRateLimitKey(request, "post:/v1/html-previews", "secret");

    expect(accessKey).toBe(sameAccessKey);
    expect(accessKey).toMatch(/^post:\/p\/abc\/access:ip:[A-Za-z0-9_-]+$/);
    expect(accessKey).not.toContain("203.0.113.10");
    expect(publishKey).not.toBe(accessKey);
  });

  it("returns 429 when the Cloudflare edge limiter rejects a request", async () => {
    const limiter: RateLimit = {
      limit: vi.fn().mockResolvedValue({ success: false }),
    };
    const request = requestOn(testApiOriginEnv.API_BASE_URL, "/v1/html-previews", {
      headers: {
        "CF-Connecting-IP": "203.0.113.10",
      },
    });

    const response = await enforceEdgeRateLimit(
      request,
      { COOKIE_SIGNING_SECRET: "secret" },
      {
        limiter,
        routeKey: "post:/v1/html-previews",
      },
    );

    expect(limiter.limit).toHaveBeenCalledWith({
      key: expect.stringMatching(/^post:\/v1\/html-previews:ip:[A-Za-z0-9_-]+$/),
    });
    expect(response).not.toBeNull();
    if (!response) {
      throw new Error("Expected edge rate limit response");
    }

    expect(response.status).toBe(429);
    expect(response.headers.get("Retry-After")).toBe("60");
    await expect(response.json()).resolves.toEqual({
      error: {
        code: "rate_limited",
        message: "Too many requests",
      },
    });
  });

  it("continues to the app-level limiter when the edge binding is unavailable or fails", async () => {
    const request = requestOn(testPreviewOriginEnv.PUBLIC_BASE_URL, "/p/abc/access");
    const failingLimiter: RateLimit = {
      limit: vi.fn().mockRejectedValue(new Error("rate limit backend unavailable")),
    };
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);

    await expect(
      enforceEdgeRateLimit(request, { COOKIE_SIGNING_SECRET: "secret" }, {
        limiter: undefined,
        routeKey: "post:/p/abc/access",
      }),
    ).resolves.toBeNull();
    await expect(
      enforceEdgeRateLimit(request, { COOKIE_SIGNING_SECRET: "secret" }, {
        limiter: failingLimiter,
        routeKey: "post:/p/abc/access",
      }),
    ).resolves.toBeNull();

    expect(failingLimiter.limit).toHaveBeenCalledOnce();
    consoleError.mockRestore();
  });
});
