export const testOrigins = {
  apiBaseUrl: "https://api.example.test",
  mcpBaseUrl: "https://mcp.example.test",
  previewBaseUrl: "https://preview.example.test",
} as const;

export const testApiOriginEnv = {
  WORKER_ROLE: "api",
  API_BASE_URL: testOrigins.apiBaseUrl,
  MCP_BASE_URL: testOrigins.mcpBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
} as const;

export const testMcpOriginEnv = {
  WORKER_ROLE: "mcp",
  API_BASE_URL: testOrigins.apiBaseUrl,
  MCP_BASE_URL: testOrigins.mcpBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
} as const;

export const testPreviewOriginEnv = {
  WORKER_ROLE: "preview",
  MCP_BASE_URL: testOrigins.mcpBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
} as const;

export function requestOn(baseUrl: string, path: string, init?: RequestInit): Request {
  return new Request(new URL(path, baseUrl).toString(), init);
}
