import { HttpError, jsonResponse } from "./http";
import type { Route } from "./routes";

type WorkerRole = "api" | "preview" | "mcp" | "combined";

export interface OriginPolicyEnv {
  API_BASE_URL?: string;
  MCP_BASE_URL?: string;
  PUBLIC_BASE_URL?: string;
  WORKER_ROLE?: string;
}

export function enforceConfiguredRouteOrigin(
  request: Request,
  requestUrl: URL,
  env: OriginPolicyEnv,
  route: Route,
): Response | null {
  if (isLocalDevelopmentRequest(request, requestUrl)) {
    return null;
  }

  if (route.surface === "unknown") {
    return null;
  }

  const role = workerRole(env);

  if (route.surface === "api") {
    if (role === "preview" || role === "mcp") {
      return notFoundResponse();
    }

    ensureDistinctConfiguredOrigins(env);
    ensureMcpDistinctIfConfigured(env);
    return enforceRequestOrigin(requestUrl, configuredApiBaseUrl(env));
  }

  if (route.surface === "preview") {
    if (role === "api" || role === "mcp") {
      return notFoundResponse();
    }

    ensureDistinctConfiguredOriginsIfBothConfigured(env);
    ensureMcpDistinctIfConfigured(env);
    return enforceRequestOrigin(requestUrl, configuredPreviewBaseUrl(env));
  }

  if (route.surface === "mcp") {
    if (role === "api" || role === "preview") {
      return notFoundResponse();
    }

    ensureMcpDistinctFromConfiguredOrigins(env);
    return enforceRequestOrigin(requestUrl, configuredMcpBaseUrl(env));
  }

  if (role === "api") {
    ensureDistinctConfiguredOrigins(env);
    ensureMcpDistinctIfConfigured(env);
    return enforceRequestOrigin(requestUrl, configuredApiBaseUrl(env));
  }

  if (role === "preview") {
    ensureDistinctConfiguredOriginsIfBothConfigured(env);
    ensureMcpDistinctIfConfigured(env);
    return enforceRequestOrigin(requestUrl, configuredPreviewBaseUrl(env));
  }

  if (role === "mcp") {
    ensureMcpDistinctFromConfiguredOrigins(env);
    return enforceRequestOrigin(requestUrl, configuredMcpBaseUrl(env));
  }

  ensureDistinctConfiguredOrigins(env);
  ensureMcpDistinctIfConfigured(env);
  const allowedOrigins = [configuredApiBaseUrl(env), configuredPreviewBaseUrl(env)];
  const mcpOrigin = configuredOptionalBaseUrl(env.MCP_BASE_URL, "MCP_BASE_URL");
  if (mcpOrigin) {
    allowedOrigins.push(mcpOrigin);
  }
  return allowedOrigins.some((origin) => hostsMatch(requestUrl, origin)) ? null : notFoundResponse();
}

export function publicBaseUrl(env: OriginPolicyEnv, requestUrl: URL, request: Request): string {
  if (isLocalDevelopmentRequest(request, requestUrl)) {
    return requestUrl.origin.replace(/\/+$/, "");
  }

  return configuredPreviewBaseUrl(env).origin.replace(/\/+$/, "");
}

export function isLocalDevelopmentRequest(request: Request, requestUrl: URL): boolean {
  return isLocalDevelopmentHost(requestUrl.hostname) || isLocalDevelopmentHost(hostnameFromHostHeader(request.headers));
}

function enforceRequestOrigin(requestUrl: URL, expectedOrigin: URL): Response | null {
  return hostsMatch(requestUrl, expectedOrigin) ? null : notFoundResponse();
}

function workerRole(env: Pick<OriginPolicyEnv, "WORKER_ROLE">): WorkerRole {
  const role = env.WORKER_ROLE ?? "combined";
  if (role === "api" || role === "preview" || role === "mcp" || role === "combined") {
    return role;
  }

  throw new HttpError(500, "invalid_worker_role", "WORKER_ROLE must be api, preview, mcp, or combined");
}

function ensureDistinctConfiguredOrigins(env: Pick<OriginPolicyEnv, "API_BASE_URL" | "PUBLIC_BASE_URL">): void {
  ensureConfiguredOriginsAreDistinct([
    { name: "API_BASE_URL", url: configuredApiBaseUrl(env) },
    { name: "PUBLIC_BASE_URL", url: configuredPreviewBaseUrl(env) },
  ]);
}

function ensureDistinctConfiguredOriginsIfBothConfigured(
  env: Pick<OriginPolicyEnv, "API_BASE_URL" | "PUBLIC_BASE_URL">,
): void {
  if (!env.API_BASE_URL) {
    return;
  }

  ensureDistinctConfiguredOrigins(env);
}

function ensureMcpDistinctFromConfiguredOrigins(
  env: Pick<OriginPolicyEnv, "API_BASE_URL" | "MCP_BASE_URL" | "PUBLIC_BASE_URL">,
): void {
  const origins = [{ name: "MCP_BASE_URL", url: configuredMcpBaseUrl(env) }];
  const apiUrl = configuredOptionalBaseUrl(env.API_BASE_URL, "API_BASE_URL");
  const previewUrl = configuredOptionalBaseUrl(env.PUBLIC_BASE_URL, "PUBLIC_BASE_URL");
  if (apiUrl) {
    origins.push({ name: "API_BASE_URL", url: apiUrl });
  }
  if (previewUrl) {
    origins.push({ name: "PUBLIC_BASE_URL", url: previewUrl });
  }

  ensureConfiguredOriginsAreDistinct(origins);
}

function ensureMcpDistinctIfConfigured(
  env: Pick<OriginPolicyEnv, "API_BASE_URL" | "MCP_BASE_URL" | "PUBLIC_BASE_URL">,
): void {
  if (!env.MCP_BASE_URL) {
    return;
  }

  ensureMcpDistinctFromConfiguredOrigins(env);
}

function configuredApiBaseUrl(env: Pick<OriginPolicyEnv, "API_BASE_URL">): URL {
  return configuredBaseUrl(env.API_BASE_URL, "API_BASE_URL", "API_BASE_URL is not configured");
}

function configuredMcpBaseUrl(env: Pick<OriginPolicyEnv, "MCP_BASE_URL">): URL {
  return configuredBaseUrl(env.MCP_BASE_URL, "MCP_BASE_URL", "MCP_BASE_URL is not configured");
}

function configuredPreviewBaseUrl(env: Pick<OriginPolicyEnv, "PUBLIC_BASE_URL">): URL {
  return configuredBaseUrl(env.PUBLIC_BASE_URL, "PUBLIC_BASE_URL", "PUBLIC_BASE_URL is not configured");
}

function configuredOptionalBaseUrl(value: string | undefined, name: string): URL | null {
  return value ? configuredBaseUrl(value, name, `${name} is not configured`) : null;
}

function configuredBaseUrl(value: string | undefined, name: string, missingMessage: string): URL {
  if (!value) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, missingMessage);
  }

  try {
    return new URL(value);
  } catch {
    throw new HttpError(500, `invalid_${name.toLowerCase()}`, `${name} is not a valid URL`);
  }
}

function ensureConfiguredOriginsAreDistinct(origins: Array<{ name: string; url: URL }>): void {
  for (let index = 0; index < origins.length; index += 1) {
    for (let nextIndex = index + 1; nextIndex < origins.length; nextIndex += 1) {
      const left = origins[index];
      const right = origins[nextIndex];
      if (hostsMatch(left.url, right.url)) {
        throw new HttpError(500, "invalid_origin_config", `${left.name} and ${right.name} must use separate hosts`);
      }
    }
  }
}

function hostsMatch(left: URL, right: URL): boolean {
  return left.host.toLowerCase() === right.host.toLowerCase();
}

function notFoundResponse(): Response {
  return jsonResponse(
    {
      error: {
        code: "not_found",
        message: "Not found",
      },
    },
    404,
  );
}

function isLocalDevelopmentHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function hostnameFromHostHeader(headers: Headers): string {
  const host = headers.get("Host") ?? "";
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end === -1 ? host : host.slice(1, end);
  }

  return host.split(":")[0] ?? "";
}
