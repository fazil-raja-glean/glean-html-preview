import { constantTimeEqual } from "./encoding";

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export function errorResponse(error: unknown): Response {
  if (error instanceof HttpError) {
    return jsonResponse(
      {
        error: {
          code: error.code,
          message: error.message,
        },
      },
      error.status,
    );
  }

  return jsonResponse(
    {
      error: {
        code: "internal_error",
        message: "Unexpected server error",
      },
    },
    500,
  );
}

export async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  let value: unknown;
  try {
    value = await request.json();
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid JSON");
  }

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_json", "Request body must be a JSON object");
  }

  return value as Record<string, unknown>;
}

export function requireBearerToken(
  request: Request,
  expectedToken: string,
  options: {
    missingCode?: string;
    missingMessage?: string;
  } = {},
): void {
  if (!expectedToken) {
    throw new HttpError(
      500,
      options.missingCode ?? "missing_api_token",
      options.missingMessage ?? "Publish API token is not configured",
    );
  }

  const authorization = request.headers.get("Authorization");
  const prefix = "Bearer ";
  if (!authorization?.startsWith(prefix)) {
    throw new HttpError(401, "unauthorized", "Missing bearer token");
  }

  const actualToken = authorization.slice(prefix.length);
  if (!constantTimeEqual(actualToken, expectedToken)) {
    throw new HttpError(403, "forbidden", "Invalid bearer token");
  }
}

export function methodNotAllowed(): Response {
  return jsonResponse(
    {
      error: {
        code: "method_not_allowed",
        message: "Method not allowed",
      },
    },
    405,
  );
}
