import { enforceEdgeRateLimit } from "./edge-rate-limit";
import { methodNotAllowed } from "./http";
import {
  handleOAuthAuthorizeRequest,
  handleOAuthAuthorizationServerMetadata,
  handleOAuthProtectedResourceMetadata,
  handleOAuthTokenRequest,
} from "./oauth";
import type { McpOAuthEnv } from "./oauth-config";
import type { OAuthRouteAction } from "./routes";

interface OAuthRouteEnv extends McpOAuthEnv {
  COOKIE_SIGNING_SECRET: string;
  EDGE_MCP_RATE_LIMITER?: RateLimit;
}

const OAUTH_ROUTES: Record<
  OAuthRouteAction,
  {
    handler: (request: Request, env: OAuthRouteEnv) => Response | Promise<Response>;
    method: string;
    rateLimitKey?: string;
  }
> = {
  authorizationServerMetadata: {
    handler: handleOAuthAuthorizationServerMetadata,
    method: "GET",
  },
  protectedResourceMetadata: {
    handler: handleOAuthProtectedResourceMetadata,
    method: "GET",
  },
  authorize: {
    handler: handleOAuthAuthorizeRequest,
    method: "GET",
  },
  token: {
    handler: handleOAuthTokenRequest,
    method: "POST",
    rateLimitKey: "post:/oauth/token",
  },
};

export async function handleOAuthRoute(request: Request, env: OAuthRouteEnv, action: OAuthRouteAction): Promise<Response> {
  const route = OAUTH_ROUTES[action];
  if (request.method !== route.method) {
    return methodNotAllowed();
  }

  if (route.rateLimitKey) {
    const edgeRateLimit = await enforceEdgeRateLimit(request, env, {
      limiter: env.EDGE_MCP_RATE_LIMITER,
      routeKey: route.rateLimitKey,
    });
    if (edgeRateLimit) {
      return edgeRateLimit;
    }
  }

  return route.handler(request, env);
}
