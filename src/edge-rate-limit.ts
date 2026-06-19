import { hashViewerIp } from "./security";

const EDGE_RATE_LIMIT_RETRY_AFTER_SECONDS = 60;

export interface EdgeRateLimitEnv {
  COOKIE_SIGNING_SECRET: string;
}

export async function edgeRateLimitKey(request: Request, routeKey: string, signingSecret: string): Promise<string> {
  const viewerIpHash = (await hashViewerIp(request.headers.get("CF-Connecting-IP"), signingSecret)) ?? "unknown";
  return `${routeKey}:ip:${viewerIpHash}`;
}

export async function enforceEdgeRateLimit(
  request: Request,
  env: EdgeRateLimitEnv,
  input: {
    limiter: RateLimit | undefined;
    routeKey: string;
  },
): Promise<Response | null> {
  if (!input.limiter) {
    return null;
  }

  let outcome: RateLimitOutcome;
  try {
    outcome = await input.limiter.limit({
      key: await edgeRateLimitKey(request, input.routeKey, env.COOKIE_SIGNING_SECRET),
    });
  } catch (error) {
    console.error("edge_rate_limit_failed", error);
    return null;
  }

  if (outcome.success) {
    return null;
  }

  return new Response(
    JSON.stringify(
      {
        error: {
          code: "rate_limited",
          message: "Too many requests",
        },
      },
      null,
      2,
    ),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Retry-After": EDGE_RATE_LIMIT_RETRY_AFTER_SECONDS.toString(),
      },
    },
  );
}
