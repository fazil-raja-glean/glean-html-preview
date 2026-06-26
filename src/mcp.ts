import { HttpError, jsonResponse } from "./http";
import { type McpOAuthAccessContext, type McpOAuthEnv, requireMcpOAuthAccessToken } from "./oauth";
import {
  CUSTOM_SLUG_MAX_LENGTH,
  CUSTOM_SLUG_MIN_LENGTH,
  CUSTOM_SLUG_PATTERN_SOURCE,
} from "./publish-command";

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

type ToolArguments = Record<string, unknown>;

const JSON_RPC_VERSION = "2.0";
const MCP_PROTOCOL_VERSION = "2025-03-26";
const DEPLOY_TOOL_NAME = "deploy_html";
const UPDATE_TOOL_NAME = "update_html";
const UPDATE_PASSWORD_TOOL_NAME = "update_html_password";
const DELETE_TOOL_NAME = "delete_html";
export const INTERNAL_PUBLISH_ACTOR_EMAIL_HEADER = "X-Publish-Actor-Email";
export const INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER = "X-Publish-Internal-Service-Token";

export async function handleMcpRequest(request: Request, env: McpEnv): Promise<Response> {
  const accessContext = await requireMcpOAuthAccessToken(request, env);

  const payload = await readJsonRpcPayload(request);
  const inputs = Array.isArray(payload) ? payload : [payload];
  if (inputs.length === 0) {
    return jsonRpcErrorResponse(null, -32600, "Invalid Request");
  }

  const responses = [];
  for (const input of inputs) {
    const response = await handleJsonRpcMessage(input, env, accessContext);
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

async function handleJsonRpcMessage(
  input: unknown,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<Record<string, unknown> | null> {
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
    await handleJsonRpcNotification(request, env, accessContext);
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
        return jsonRpcResult(responseId, { tools: mcpTools() });
      case "tools/call":
        return await handleToolsCall(responseId, request.params, env, accessContext);
      default:
        return jsonRpcError(responseId, -32601, "Method not found");
    }
  } catch (error) {
    return jsonRpcErrorFromException(responseId, error);
  }
}

async function handleJsonRpcNotification(
  request: JsonRpcRequest,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<void> {
  if (request.method === "notifications/initialized" || request.method === "notifications/cancelled") {
    return;
  }

  if (request.method === "tools/call") {
    await handleToolsCall(null, request.params, env, accessContext);
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

function mcpTools(): Record<string, unknown>[] {
  return [
    deployHtmlTool(),
    updateHtmlTool(),
    updateHtmlPasswordTool(),
    deleteHtmlTool(),
  ];
}

function deployHtmlTool(): Record<string, unknown> {
  return {
    name: DEPLOY_TOOL_NAME,
    description:
      "Deploy a complete HTML document as a password-protected, sandboxed preview URL. A slug is required. If the user did not provide one, derive a readable lower-kebab-case slug from the title or artifact purpose.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        slug: slugSchema(
          "Required stable URL slug. Derive a short descriptive lower-kebab-case slug from the title or artifact purpose when the user does not provide one.",
        ),
        title: {
          type: "string",
          minLength: 1,
          maxLength: 160,
          description: "Concise preview title.",
        },
        html: {
          type: "string",
          description:
            "Complete HTML document, including an html element. Use cid:image-name.png references for images supplied through images[].",
        },
        images: imagesSchema(),
        password: {
          type: "string",
          minLength: 5,
          maxLength: 256,
          description: "Viewer password for the preview.",
        },
        expiresAt: expiresAtSchema(false),
        sourceUrl: sourceUrlSchema(false),
      },
      required: ["slug", "title", "html", "password"],
    },
  };
}

function updateHtmlTool(): Record<string, unknown> {
  return {
    name: UPDATE_TOOL_NAME,
    description:
      "Update the HTML and image attachments for an existing preview slug while preserving the same URL and viewer password.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        slug: slugSchema("Existing preview slug to update."),
        html: {
          type: "string",
          description:
            "Replacement complete HTML document, including an html element. The images array is a full replacement set.",
        },
        title: {
          type: "string",
          minLength: 1,
          maxLength: 160,
          description: "Optional replacement preview title.",
        },
        images: imagesSchema(),
        expiresAt: expiresAtSchema(true),
        sourceUrl: sourceUrlSchema(true),
      },
      required: ["slug", "html"],
    },
  };
}

function updateHtmlPasswordTool(): Record<string, unknown> {
  return {
    name: UPDATE_PASSWORD_TOOL_NAME,
    description:
      "Rotate the viewer password for an existing HTML preview. The preview URL and HTML content do not change.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        slug: slugSchema("Existing preview slug whose viewer password should rotate."),
        password: {
          type: "string",
          minLength: 5,
          maxLength: 256,
          description: "New viewer password.",
        },
      },
      required: ["slug", "password"],
    },
  };
}

function deleteHtmlTool(): Record<string, unknown> {
  return {
    name: DELETE_TOOL_NAME,
    description: "Delete an existing HTML preview owned by the signed-in user and free its slug for reuse.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        slug: slugSchema("Existing preview slug to delete."),
      },
      required: ["slug"],
    },
  };
}

function slugSchema(description: string): Record<string, unknown> {
  return {
    type: "string",
    minLength: CUSTOM_SLUG_MIN_LENGTH,
    maxLength: CUSTOM_SLUG_MAX_LENGTH,
    pattern: CUSTOM_SLUG_PATTERN_SOURCE,
    description,
  };
}

function imagesSchema(): Record<string, unknown> {
  return {
    type: "array",
    description: "Optional image attachments referenced from the HTML as cid:name.",
    items: {
      type: "object",
      additionalProperties: false,
      properties: {
        name: {
          type: "string",
          description: "Unique cid name, for example proof.png.",
        },
        mimeType: {
          type: "string",
          enum: ["image/png", "image/jpeg", "image/webp", "image/gif", "image/avif"],
        },
        dataBase64: {
          type: "string",
          description: "Base64 image bytes. Data URLs are accepted.",
        },
      },
      required: ["name", "mimeType", "dataBase64"],
    },
  };
}

function expiresAtSchema(nullable: boolean): Record<string, unknown> {
  return {
    type: nullable ? ["string", "null"] : "string",
    format: "date-time",
    description: "Optional ISO timestamp when the preview should expire.",
  };
}

function sourceUrlSchema(nullable: boolean): Record<string, unknown> {
  return {
    type: nullable ? ["string", "null"] : "string",
    format: "uri",
    description: "Optional URL for the source artifact or conversation.",
  };
}

async function handleToolsCall(
  id: JsonRpcId,
  params: unknown,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<Record<string, unknown>> {
  const call = parseToolCall(params);
  const args = parseToolArguments(call.arguments);

  switch (call.name) {
    case DEPLOY_TOOL_NAME:
      return jsonRpcResult(id, await deployHtml(args, env, accessContext));
    case UPDATE_TOOL_NAME:
      return jsonRpcResult(id, await updateHtml(args, env, accessContext));
    case UPDATE_PASSWORD_TOOL_NAME:
      return jsonRpcResult(id, await updateHtmlPassword(args, env, accessContext));
    case DELETE_TOOL_NAME:
      return jsonRpcResult(id, await deleteHtml(args, env, accessContext));
    default:
      return jsonRpcError(id, -32602, `Unknown tool: ${call.name}`);
  }
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

function parseToolArguments(value: unknown): ToolArguments {
  if (!isRecord(value)) {
    throw new HttpError(400, "invalid_tool_arguments", "Tool arguments must be an object");
  }

  return value;
}

async function deployHtml(
  args: ToolArguments,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<ToolResult> {
  return callPreviewApi(env, accessContext, {
    actionLabel: "Deploy",
    body: args,
    method: "POST",
    path: "/v1/html-previews",
    successLabel: "Deployed HTML preview",
    successStatus: "active",
  });
}

async function updateHtml(
  args: ToolArguments,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<ToolResult> {
  const { slug, body } = slugPathBody(args);
  return callPreviewApi(env, accessContext, {
    actionLabel: "Update",
    body,
    method: "PUT",
    path: `/v1/html-previews/${encodeURIComponent(slug)}`,
    successLabel: "Updated HTML preview",
    successStatus: "active",
  });
}

async function updateHtmlPassword(
  args: ToolArguments,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<ToolResult> {
  const { slug, body } = slugPathBody(args);
  return callPreviewApi(env, accessContext, {
    actionLabel: "Password update",
    body,
    method: "POST",
    path: `/v1/html-previews/${encodeURIComponent(slug)}/password`,
    successLabel: "Updated HTML preview password",
    successStatus: "active",
  });
}

async function deleteHtml(
  args: ToolArguments,
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
): Promise<ToolResult> {
  const slug = requireToolString(args.slug, "slug");
  return callPreviewApi(env, accessContext, {
    actionLabel: "Delete",
    body: null,
    method: "DELETE",
    path: `/v1/html-previews/${encodeURIComponent(slug)}`,
    successLabel: "Deleted HTML preview",
    successStatus: "deleted",
  });
}

async function callPreviewApi(
  env: McpEnv,
  accessContext: McpOAuthAccessContext,
  input: {
    actionLabel: string;
    body: Record<string, unknown> | null;
    method: string;
    path: string;
    successLabel: string;
    successStatus: string;
  },
): Promise<ToolResult> {
  const actorEmail = requireMcpActorEmail(accessContext);
  const request = new Request(publishApiUrl(env, input.path), {
    method: input.method,
    headers: publishApiHeaders(env, actorEmail),
    ...(input.body === null ? {} : { body: JSON.stringify(input.body) }),
  });
  const publishApi = requirePublishApiBinding(env);
  const response = await publishApi.fetch(request);
  const body = await readJsonResponse(response);

  if (!response.ok) {
    const error = upstreamError(body);
    return toolError(`${input.actionLabel} failed`, response.status, error.code, error.message);
  }

  return toolSuccess(input.successLabel, parsePreviewApiResult(body, input.successStatus));
}

function publishApiUrl(env: McpEnv, path: string): string {
  const base = configuredUrl(env.API_BASE_URL, "API_BASE_URL");
  return new URL(path, base).toString();
}

function publishApiHeaders(env: McpEnv, actorEmail: string): Headers {
  const publishToken = requireConfiguredSecret(env.PUBLISH_API_TOKEN, "PUBLISH_API_TOKEN");
  const headers = new Headers({
    Authorization: `Bearer ${publishToken}`,
    "Content-Type": "application/json",
  });
  headers.set(INTERNAL_PUBLISH_ACTOR_EMAIL_HEADER, actorEmail);
  headers.set(
    INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER,
    requireConfiguredSecret(env.PUBLISH_INTERNAL_SERVICE_TOKEN, "PUBLISH_INTERNAL_SERVICE_TOKEN"),
  );
  return headers;
}

function slugPathBody(args: ToolArguments): { body: Record<string, unknown>; slug: string } {
  const slug = requireToolString(args.slug, "slug");
  const body = { ...args };
  delete body.slug;
  return { slug, body };
}

function requireToolString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new HttpError(400, "invalid_tool_arguments", `${field} must be a string`);
  }

  return value;
}

function requireMcpActorEmail(accessContext: McpOAuthAccessContext): string {
  if (!accessContext.actorEmail) {
    throw new HttpError(401, "missing_mcp_actor", "OAuth token is not bound to an authenticated Glean user");
  }

  return accessContext.actorEmail;
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

function parsePreviewApiResult(value: unknown, fallbackStatus: string): Record<string, unknown> {
  if (!isRecord(value)) {
    return { status: fallbackStatus };
  }

  return {
    ...(typeof value.url === "string" ? { url: value.url } : {}),
    ...(typeof value.slug === "string" ? { slug: value.slug } : {}),
    ...(value.expiresAt === null || typeof value.expiresAt === "string" ? { expiresAt: value.expiresAt } : {}),
    status: typeof value.status === "string" ? value.status : fallbackStatus,
  };
}

function toolSuccess(label: string, structuredContent: Record<string, unknown>): ToolResult {
  const target =
    typeof structuredContent.url === "string"
      ? structuredContent.url
      : typeof structuredContent.slug === "string"
        ? structuredContent.slug
        : null;

  return {
    content: [
      {
        type: "text",
        text: target ? `${label}: ${target}` : label,
      },
    ],
    structuredContent,
  };
}

function toolError(label: string, status: number, code: string, message: string): ToolResult {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: `${label}: ${message}`,
      },
    ],
    structuredContent: {
      status,
      error: code,
    },
  };
}

function upstreamError(value: unknown): { code: string; message: string } {
  if (isRecord(value) && isRecord(value.error)) {
    return {
      code: typeof value.error.code === "string" ? value.error.code : "preview_api_failed",
      message: typeof value.error.message === "string" ? value.error.message : "Preview API rejected the request",
    };
  }

  return {
    code: "preview_api_failed",
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
