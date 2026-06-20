export type RouteSurface = "api" | "preview" | "mcp" | "both" | "unknown";

export type OAuthRouteAction =
  | "authorizationServerMetadata"
  | "protectedResourceMetadata"
  | "authorize"
  | "callback"
  | "token";

export type AdminRouteAction =
  | "home"
  | "login"
  | "oauthCallback"
  | "logout"
  | "session"
  | "previews"
  | "previewDetails"
  | "rotatePassword"
  | "unpublish"
  | "hardDelete"
  | "html";

type StaticAdminRouteAction = Extract<
  AdminRouteAction,
  "home" | "login" | "oauthCallback" | "logout" | "session" | "previews"
>;

type PreviewAdminRouteAction = Exclude<AdminRouteAction, StaticAdminRouteAction>;

const OAUTH_ROUTE_ACTIONS: Record<string, OAuthRouteAction> = {
  "/.well-known/oauth-authorization-server": "authorizationServerMetadata",
  "/.well-known/oauth-protected-resource": "protectedResourceMetadata",
  "/.well-known/oauth-protected-resource/mcp": "protectedResourceMetadata",
  "/oauth/authorize": "authorize",
  "/oauth/callback": "callback",
  "/oauth/token": "token",
};

export type AdminRoute =
  | {
      action: StaticAdminRouteAction;
      kind: "admin";
      surface: "api";
    }
  | {
      action: PreviewAdminRouteAction;
      kind: "admin";
      slug: string;
      surface: "api";
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
  | AdminRoute
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

  const adminRoute = adminRouteForPath(pathname);
  if (adminRoute) {
    return adminRoute;
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

function adminRouteForPath(pathname: string): AdminRoute | null {
  if (pathname === "/admin") {
    return { action: "home", kind: "admin", surface: "api" };
  }

  const staticRoutes: Record<string, StaticAdminRouteAction> = {
    "/admin/login": "login",
    "/admin/oauth/callback": "oauthCallback",
    "/admin/logout": "logout",
    "/admin/api/session": "session",
    "/admin/api/previews": "previews",
  };
  const staticAction = staticRoutes[pathname];
  if (staticAction) {
    return { action: staticAction, kind: "admin", surface: "api" };
  }

  const previewMatch = pathname.match(/^\/admin\/api\/previews\/([A-Za-z0-9_-]+)$/);
  if (previewMatch) {
    return { action: "previewDetails", kind: "admin", slug: previewMatch[1], surface: "api" };
  }

  const actionMatch = pathname.match(/^\/admin\/api\/previews\/([A-Za-z0-9_-]+)\/(password|unpublish|delete|html)$/);
  if (!actionMatch) {
    return null;
  }

  const action = previewAdminRouteAction(actionMatch[2]);
  if (!action) {
    return null;
  }

  return {
    action,
    kind: "admin",
    slug: actionMatch[1],
    surface: "api",
  };
}

function previewAdminRouteAction(value: string | undefined): PreviewAdminRouteAction | null {
  switch (value) {
    case "password":
      return "rotatePassword";
    case "unpublish":
      return "unpublish";
    case "delete":
      return "hardDelete";
    case "html":
      return "html";
    default:
      return null;
  }
}
