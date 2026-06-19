export type RouteSurface = "api" | "preview" | "mcp" | "both" | "unknown";

export type OAuthRouteAction = "authorizationServerMetadata" | "protectedResourceMetadata" | "authorize" | "token";

const OAUTH_ROUTE_ACTIONS: Record<string, OAuthRouteAction> = {
  "/.well-known/oauth-authorization-server": "authorizationServerMetadata",
  "/.well-known/oauth-protected-resource": "protectedResourceMetadata",
  "/.well-known/oauth-protected-resource/mcp": "protectedResourceMetadata",
  "/oauth/authorize": "authorize",
  "/oauth/token": "token",
};

export type Route =
  | {
      kind: "health";
      surface: "both";
    }
  | {
      kind: "publish";
      surface: "api";
    }
  | {
      kind: "unpublish";
      slug: string;
      surface: "api";
    }
  | {
      kind: "rotatePassword";
      slug: string;
      surface: "api";
    }
  | {
      kind: "mcp";
      surface: "mcp";
    }
  | {
      action: OAuthRouteAction;
      kind: "oauth";
      surface: "mcp";
    }
  | {
      kind: "access";
      slug: string;
      surface: "preview";
    }
  | {
      kind: "preview";
      slug: string;
      surface: "preview";
    }
  | {
      kind: "unknown";
      surface: "unknown";
    };

export function routeForPath(pathname: string): Route {
  if (pathname === "/health") {
    return { kind: "health", surface: "both" };
  }

  if (pathname === "/v1/html-previews") {
    return { kind: "publish", surface: "api" };
  }

  if (pathname === "/mcp") {
    return { kind: "mcp", surface: "mcp" };
  }

  const oauthAction = oauthRouteAction(pathname);
  if (oauthAction) {
    return { action: oauthAction, kind: "oauth", surface: "mcp" };
  }

  const unpublishMatch = pathname.match(/^\/v1\/html-previews\/([A-Za-z0-9_-]+)\/unpublish$/);
  if (unpublishMatch) {
    return {
      kind: "unpublish",
      slug: unpublishMatch[1],
      surface: "api",
    };
  }

  const rotateMatch = pathname.match(/^\/v1\/html-previews\/([A-Za-z0-9_-]+)\/password$/);
  if (rotateMatch) {
    return {
      kind: "rotatePassword",
      slug: rotateMatch[1],
      surface: "api",
    };
  }

  const accessMatch = pathname.match(/^\/p\/([A-Za-z0-9_-]+)\/access$/);
  if (accessMatch) {
    return {
      kind: "access",
      slug: accessMatch[1],
      surface: "preview",
    };
  }

  const previewMatch = pathname.match(/^\/p\/([A-Za-z0-9_-]+)$/);
  if (previewMatch) {
    return {
      kind: "preview",
      slug: previewMatch[1],
      surface: "preview",
    };
  }

  return { kind: "unknown", surface: "unknown" };
}

function oauthRouteAction(pathname: string): OAuthRouteAction | null {
  return OAUTH_ROUTE_ACTIONS[pathname] ?? null;
}
