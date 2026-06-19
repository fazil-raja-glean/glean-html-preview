import { HttpError, jsonResponse } from "./http";
import { type McpOAuthEnv, requireMcpOAuthAccessToken } from "./oauth";

interface McpEnv extends McpOAuthEnv {
  PUBLISH_API?: Fetcher;
  API_BASE_URL?: string;
  PUBLISH_API_TOKEN?: string;
  PUBLISH_INTERNAL_SERVICE_TOKEN?: string;
}

interface JsonRpcRequest {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

type JsonRpcId = string | number | null;

interface ToolResult {
  content: Array<{
    type: "text";
    text: string;
  }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

interface PublishToolArguments {
  title: string;
  html: string;
  password: string;
  expiresAt?: string;
  sourceUrl?: string;
}

const JSON_RPC_VERSION = "2.0";
const MCP_PROTOCOL_VERSION = "2025-03-26";
const PUBLISH_TOOL_NAME = "publish_html_preview";
export const INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER = "X-Publish-Internal-Service-Token";

export async function handleMcpRequest(request: Request, env: McpEnv): Promise<Response> {
  await requireMcpOAuthAccessToken(request, env);

  const payload = await readJsonRpcPayload(request);
  const inputs = Array.isArray(payload) ? payload : [payload];
  if (inputs.length === 0) {
    return jsonRpcErrorResponse(null, -32600, "Invalid Request");
  }

  const responses = [];
  for (const input of inputs) {
    const response = await handleJsonRpcMessage(input, env);
    if (response) {
      responses.push(response);
    }
  }

  if (responses.length === 0) {
    return new Response(null, { status: 204 });
  }

  return jsonResponse(Array.isArray(payload) ? responses : responses[0]);
}

async function readJsonRpcPayload(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid JSON");
  }
}

async function handleJsonRpcMessage(input: unknown, env: McpEnv): Promise<Record<string, unknown> | null> {
  if (!isRecord(input)) {
    return jsonRpcError(null, -32600, "Invalid Request");
  }

  const request = input as JsonRpcRequest;
  const id = parseJsonRpcId(request.id);
  if (request.id !== undefined && id === undefined) {
    return jsonRpcError(null, -32600, "Invalid Request");
  }

  if (request.jsonrpc !== JSON_RPC_VERSION || typeof request.method !== "string") {
    return jsonRpcError(id ?? null, -32600, "Invalid Request");
  }

  if (request.id === undefined) {
    await handleJsonRpcNotification(request, env);
    return null;
  }

  const responseId = id ?? null;
  try {
    switch (request.method) {
      case "initialize":
        return jsonRpcResult(responseId, initializeResult());
      case "ping":
        return jsonRpcResult(responseId, {});
      case "tools/list":
        return jsonRpcResult(responseId, { tools: [publishHtmlPreviewTool()] });
      case "tools/call":
        return await handleToolsCall(responseId, request.params, env);
      default:
        return jsonRpcError(responseId, -32601, "Method not found");
    }
  } catch (error) {
    return jsonRpcErrorFromException(responseId, error);
  }
}

async function handleJsonRpcNotification(request: JsonRpcRequest, env: McpEnv): Promise<void> {
  if (request.method === "notifications/initialized" || request.method === "notifications/cancelled") {
    return;
  }

  if (request.method === "tools/call") {
    await handleToolsCall(null, request.params, env);
  }
}

function initializeResult(): Record<string, unknown> {
  return {
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: {
      tools: {
        listChanged: false,
      },
    },
    serverInfo: {
      name: "html-sharing",
      version: "0.1.0",
    },
  };
}

function publishHtmlPreviewTool(): Record<string, unknown> {
  return {
    name: PUBLISH_TOOL_NAME,
    description:
      "Publish a complete HTML document as a password-protected, sandboxed preview and return a shareable URL.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        title: {
          type: "string",
          minLength: 1,
          maxLength: 160,
          description: "Concise preview title.",
        },
        html: {
          type: "string",
          description: "Complete HTML document, including an html element.",
        },
        password: {
          type: "string",
          minLength: 12,
          maxLength: 256,
          description: "Viewer password for the preview.",
        },
        expiresAt: {
          type: "string",
          format: "date-time",
          description: "Optional ISO timestamp when the preview should expire.",
        },
        sourceUrl: {
          type: "string",
          format: "uri",
          description: "Optional URL for the source artifact or conversation.",
        },
      },
      required: ["title", "html", "password"],
    },
  };
}

async function handleToolsCall(
  id: JsonRpcId,
  params: unknown,
  env: McpEnv,
): Promise<Record<string, unknown>> {
  const call = parseToolCall(params);
  if (call.name !== PUBLISH_TOOL_NAME) {
    return jsonRpcError(id, -32602, `Unknown tool: ${call.name}`);
  }

  const args = parsePublishToolArguments(call.arguments);
  return jsonRpcResult(id, await publishHtmlPreview(args, env));
}

function parseToolCall(params: unknown): { name: string; arguments: unknown } {
  if (!isRecord(params) || typeof params.name !== "string") {
    throw new HttpError(400, "invalid_tool_call", "Tool call params must include a tool name");
  }

  return {
    name: params.name,
    arguments: params.arguments,
  };
}

function parsePublishToolArguments(value: unknown): PublishToolArguments {
  if (!isRecord(value)) {
    throw new HttpError(400, "invalid_tool_arguments", "Tool arguments must be an object");
  }

  const title = requireString(value.title, "title").trim();
  const html = requireString(value.html, "html");
  const password = requireString(value.password, "password");
  const expiresAt = optionalString(value.expiresAt, "expiresAt");
  const sourceUrl = optionalString(value.sourceUrl, "sourceUrl");

  if (title.length < 1 || title.length > 160) {
    throw new HttpError(400, "invalid_title", "Title must be between 1 and 160 characters");
  }

  if (password.length < 12 || password.length > 256) {
    throw new HttpError(400, "invalid_password", "Password must be between 12 and 256 characters");
  }

  if (!/<html[\s>]/i.test(html)) {
    throw new HttpError(400, "invalid_html", "HTML must be a complete document with an html element");
  }

  if (expiresAt) {
    const expires = Date.parse(expiresAt);
    if (!Number.isFinite(expires) || expires <= Date.now()) {
      throw new HttpError(400, "invalid_expiry", "expiresAt must be a future ISO timestamp");
    }
  }

  if (sourceUrl) {
    try {
      new URL(sourceUrl);
    } catch {
      throw new HttpError(400, "invalid_url", "sourceUrl must be a valid URL");
    }
  }

  return {
    title,
    html,
    password,
    ...(expiresAt ? { expiresAt: new Date(Date.parse(expiresAt)).toISOString() } : {}),
    ...(sourceUrl ? { sourceUrl: new URL(sourceUrl).toString() } : {}),
  };
}

async function publishHtmlPreview(args: PublishToolArguments, env: McpEnv): Promise<ToolResult> {
  const apiUrl = publishApiUrl(env);
  const request = new Request(apiUrl, {
    method: "POST",
    headers: publishApiHeaders(env),
    body: JSON.stringify(args),
  });
  const publishApi = requirePublishApiBinding(env);
  const response = await publishApi.fetch(request);
  const body = await readJsonResponse(response);

  if (!response.ok) {
    const error = upstreamError(body);
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `Publish failed: ${error.message}`,
        },
      ],
      structuredContent: {
        status: response.status,
        error: error.code,
      },
    };
  }

  const result = parsePublishApiResult(body);
  return {
    content: [
      {
        type: "text",
        text: `Published HTML preview: ${result.url}`,
      },
    ],
    structuredContent: result,
  };
}

function publishApiUrl(env: McpEnv): string {
  const base = configuredUrl(env.API_BASE_URL, "API_BASE_URL");
  return new URL("/v1/html-previews", base).toString();
}

function publishApiHeaders(env: McpEnv): Headers {
  const publishToken = requireConfiguredSecret(env.PUBLISH_API_TOKEN, "PUBLISH_API_TOKEN");
  const headers = new Headers({
    Authorization: `Bearer ${publishToken}`,
    "Content-Type": "application/json",
  });
  headers.set(
    INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER,
    requireConfiguredSecret(env.PUBLISH_INTERNAL_SERVICE_TOKEN, "PUBLISH_INTERNAL_SERVICE_TOKEN"),
  );
  return headers;
}

function requirePublishApiBinding(env: McpEnv): Fetcher {
  if (!env.PUBLISH_API) {
    throw new HttpError(500, "missing_publish_api_binding", "PUBLISH_API service binding is not configured");
  }

  return env.PUBLISH_API;
}

async function readJsonResponse(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function parsePublishApiResult(value: unknown): Record<string, unknown> {
  if (!isRecord(value) || typeof value.url !== "string" || typeof value.slug !== "string") {
    return {
      status: "published",
    };
  }

  return {
    url: value.url,
    slug: value.slug,
    expiresAt: typeof value.expiresAt === "string" ? value.expiresAt : null,
    status: typeof value.status === "string" ? value.status : "active",
  };
}

function upstreamError(value: unknown): { code: string; message: string } {
  if (isRecord(value) && isRecord(value.error)) {
    return {
      code: typeof value.error.code === "string" ? value.error.code : "publish_failed",
      message: typeof value.error.message === "string" ? value.error.message : "Preview API rejected the request",
    };
  }

  return {
    code: "publish_failed",
    message: "Preview API rejected the request",
  };
}

function configuredUrl(value: string | undefined, name: string): URL {
  if (!value) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, `${name} is not configured`);
  }

  try {
    return new URL(value);
  } catch {
    throw new HttpError(500, `invalid_${name.toLowerCase()}`, `${name} is not a valid URL`);
  }
}

function requireConfiguredSecret(value: string | undefined, name: string): string {
  if (!value) {
    throw new HttpError(500, `missing_${name.toLowerCase()}`, `${name} is not configured`);
  }

  return value;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `${field} must be a string`);
  }

  return value;
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `${field} must be a string`);
  }

  return value;
}

function jsonRpcResult(id: JsonRpcId, result: unknown): Record<string, unknown> {
  return {
    jsonrpc: JSON_RPC_VERSION,
    id,
    result,
  };
}

function jsonRpcErrorResponse(id: JsonRpcId, code: number, message: string): Response {
  return jsonResponse(jsonRpcError(id, code, message));
}

function jsonRpcError(id: JsonRpcId, code: number, message: string): Record<string, unknown> {
  return {
    jsonrpc: JSON_RPC_VERSION,
    id,
    error: {
      code,
      message,
    },
  };
}

function jsonRpcErrorFromException(id: JsonRpcId, error: unknown): Record<string, unknown> {
  if (error instanceof HttpError) {
    return jsonRpcError(id, error.status >= 500 ? -32603 : -32602, error.message);
  }

  console.error("mcp_request_failed", error);
  return jsonRpcError(id, -32603, "Internal error");
}

function parseJsonRpcId(value: unknown): JsonRpcId | undefined {
  if (value === null || typeof value === "string" || typeof value === "number") {
    return value;
  }

  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
