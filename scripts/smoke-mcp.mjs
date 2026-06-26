#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";

const args = new Set(process.argv.slice(2));
const metadataOnly = args.has("--metadata-only");

async function main() {
  const baseUrl = configuredBaseUrl();
  const clientId = process.env.MCP_OAUTH_CLIENT_ID;
  const clientSecret = process.env.MCP_OAUTH_CLIENT_SECRET;
  const scope = process.env.MCP_OAUTH_SCOPES || "mcp:tools";
  const suppliedToken = process.env.MCP_ACCESS_TOKEN;

  console.log(`MCP base: ${redactedOrigin(baseUrl)}`);

  await checkMetadata(baseUrl);
  await checkUnauthenticatedChallenge(baseUrl);
  await checkWrongCredentials(baseUrl);

  const accessToken = suppliedToken || (!metadataOnly && clientId && clientSecret
    ? await fetchClientCredentialsToken(baseUrl, clientId, clientSecret, scope)
    : null);

  if (!accessToken) {
    console.log("Skipped authenticated initialize/tools checks; set MCP_ACCESS_TOKEN or MCP_OAUTH_CLIENT_ID and MCP_OAUTH_CLIENT_SECRET.");
    return;
  }

  await checkInitialize(baseUrl, accessToken);
  await checkToolsList(baseUrl, accessToken);
}

async function checkMetadata(baseUrl) {
  const authorization = await getJson(new URL("/.well-known/oauth-authorization-server", baseUrl));
  expect(authorization.authorization_endpoint?.endsWith("/oauth/authorize"), "authorization metadata exposes /oauth/authorize");
  expect(authorization.token_endpoint?.endsWith("/oauth/token"), "authorization metadata exposes /oauth/token");
  expect(authorization.scopes_supported?.includes("mcp:tools"), "authorization metadata supports mcp:tools");

  const resource = await getJson(new URL("/.well-known/oauth-protected-resource", baseUrl));
  expect(resource.resource?.endsWith("/mcp"), "protected resource metadata points at /mcp");
  expect(resource.authorization_servers?.length > 0, "protected resource metadata lists authorization server");
  console.log("OAuth metadata checks passed.");
}

async function checkUnauthenticatedChallenge(baseUrl) {
  const response = await fetch(new URL("/mcp", baseUrl), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });

  expect(response.status === 401, "unauthenticated MCP request returns 401");
  expect(response.headers.get("www-authenticate")?.toLowerCase().includes("bearer"), "401 includes bearer challenge");
  console.log("Unauthenticated challenge check passed.");
}

async function checkWrongCredentials(baseUrl) {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: "wrong",
    client_secret: "wrong",
  });
  const response = await fetch(new URL("/oauth/token", baseUrl), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  expect(response.status === 401, "wrong OAuth client credentials return 401");
  console.log("Wrong credentials check passed.");
}

async function fetchClientCredentialsToken(baseUrl, clientId, clientSecret, scope) {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: clientId,
    client_secret: clientSecret,
    scope,
  });
  const token = await postJson(new URL("/oauth/token", baseUrl), body, {
    "Content-Type": "application/x-www-form-urlencoded",
  });
  expect(typeof token.access_token === "string" && token.access_token.length > 0, "client_credentials returns access_token");
  console.log("Client credentials token check passed.");
  return token.access_token;
}

async function checkInitialize(baseUrl, accessToken) {
  const result = await mcpRequest(baseUrl, accessToken, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "html-sharing-smoke", version: "1.0.0" },
    },
  });
  expect(result.result?.serverInfo?.name === "html-sharing", "initialize returns html-sharing serverInfo");
  console.log("MCP initialize check passed.");
}

async function checkToolsList(baseUrl, accessToken) {
  const result = await mcpRequest(baseUrl, accessToken, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  });
  const tools = result.result?.tools ?? [];
  const names = new Set(tools.map((tool) => tool.name));
  for (const name of ["deploy_html", "update_html", "update_html_password", "delete_html"]) {
    expect(names.has(name), `tools/list exposes ${name}`);
  }
  console.log("MCP tools/list check passed.");
}

async function mcpRequest(baseUrl, accessToken, payload) {
  return postJson(new URL("/mcp", baseUrl), JSON.stringify(payload), {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  });
}

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url.pathname} returned ${response.status}`);
  }
  return response.json();
}

async function postJson(url, body, headers) {
  const response = await fetch(url, { method: "POST", headers, body });
  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${url.pathname} returned non-JSON response with status ${response.status}`);
  }
  if (!response.ok || parsed.error) {
    throw new Error(`${url.pathname} failed with status ${response.status}: ${JSON.stringify(parsed.error ?? parsed)}`);
  }
  return parsed;
}

function configuredBaseUrl() {
  const fromEnv = process.env.MCP_BASE_URL || process.env.MCP;
  if (fromEnv) {
    return normalizedBaseUrl(fromEnv);
  }

  const fromLocalConfig = readMcpBaseUrl("wrangler.local.toml");
  if (fromLocalConfig) {
    return normalizedBaseUrl(fromLocalConfig);
  }

  throw new Error("Set MCP_BASE_URL, or create wrangler.local.toml with env.mcp.vars.MCP_BASE_URL.");
}

function readMcpBaseUrl(path) {
  if (!existsSync(path)) {
    return null;
  }
  const content = readFileSync(path, "utf8");
  const inMcpVars = content.match(/\[env\.mcp\.vars]\n(?<body>[\s\S]*?)(?:\n\[|\n\[\[|$)/);
  const body = inMcpVars?.groups?.body;
  if (!body) {
    return null;
  }
  return body.match(/^MCP_BASE_URL\s*=\s*"(?<url>[^"]+)"/m)?.groups?.url ?? null;
}

function normalizedBaseUrl(value) {
  const url = new URL(value);
  if (url.pathname.endsWith("/mcp")) {
    url.pathname = url.pathname.slice(0, -"/mcp".length) || "/";
  }
  if (url.pathname !== "/") {
    throw new Error("MCP_BASE_URL should be the origin/base URL, not a nested path other than /mcp.");
  }
  if (url.hostname.includes("your-workers-subdomain")) {
    throw new Error("MCP_BASE_URL still contains placeholder hostname.");
  }
  return url;
}

function redactedOrigin(url) {
  return url.origin;
}

function expect(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

main().catch((error) => {
  console.error(`smoke-mcp: ${error.message}`);
  process.exit(1);
});
