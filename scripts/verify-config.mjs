#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";

const publicConfig = "wrangler.toml";
const localConfig = "wrangler.local.toml";

const optionalLocalPlaceholderKeys = new Set(["PUBLISH_ACCESS_TEAM_DOMAIN", "PUBLISH_ACCESS_AUD"]);

function main() {
  const args = new Set(process.argv.slice(2));
  const publicOnly = args.has("--public-only");
  const localOnly = args.has("--local-only");

  if (!localOnly) {
    verifyFile(publicConfig, { kind: "template" });
  }

  if (!publicOnly) {
    if (existsSync(localConfig)) {
      verifyFile(localConfig, { kind: "local" });
    } else {
      console.log(`Skipped ${localConfig}; file does not exist.`);
    }
  }
}

function verifyFile(path, options) {
  const content = readFileSync(path, "utf8");
  const doc = parseToml(content, path);
  const checks = [];

  const check = (condition, message) => {
    checks.push({ condition, message });
  };

  const root = doc.root;
  const previewVars = section(doc, "vars");
  const api = section(doc, "env.api");
  const apiVars = section(doc, "env.api.vars");
  const mcp = section(doc, "env.mcp");
  const mcpVars = section(doc, "env.mcp.vars");

  check(root.name === "html", "top-level Worker name must be html");
  check(root.main === "src/index.ts", "top-level Worker main must be src/index.ts");
  check(root.preview_urls === false, "preview Worker preview_urls must be false");
  check(previewVars.WORKER_ROLE === "preview", "top-level WORKER_ROLE must be preview");
  check(api.name === "admin", "env.api Worker name must be admin");
  check(api.preview_urls === false, "API Worker preview_urls must be false");
  check(apiVars.WORKER_ROLE === "api", "env.api WORKER_ROLE must be api");
  check(mcp.name === "html-mcp", "env.mcp Worker name must be html-mcp");
  check(mcp.preview_urls === false, "MCP Worker preview_urls must be false");
  check(mcpVars.WORKER_ROLE === "mcp", "env.mcp WORKER_ROLE must be mcp");

  check(isUrl(previewVars.PUBLIC_BASE_URL), "preview PUBLIC_BASE_URL must be a URL");
  check(isUrl(apiVars.API_BASE_URL), "API_BASE_URL must be a URL");
  check(isUrl(apiVars.PUBLIC_BASE_URL), "API PUBLIC_BASE_URL must be a URL");
  check(isUrl(mcpVars.MCP_BASE_URL), "MCP_BASE_URL must be a URL");
  check(isUrl(mcpVars.API_BASE_URL), "MCP API_BASE_URL must be a URL");
  check(isUrl(mcpVars.PUBLIC_BASE_URL), "MCP PUBLIC_BASE_URL must be a URL");
  check(apiVars.PUBLIC_BASE_URL === previewVars.PUBLIC_BASE_URL, "API publish responses must use preview PUBLIC_BASE_URL");
  check(mcpVars.PUBLIC_BASE_URL === previewVars.PUBLIC_BASE_URL, "MCP publish responses must use preview PUBLIC_BASE_URL");
  check(mcpVars.API_BASE_URL === apiVars.API_BASE_URL, "MCP must call the API origin");
  check(
    distinctUrlOrigins([previewVars.PUBLIC_BASE_URL, apiVars.API_BASE_URL, mcpVars.MCP_BASE_URL]),
    "preview, API, and MCP origins must be distinct",
  );

  check(hasBinding(arrays(doc, "r2_buckets"), "HTML_PREVIEWS"), "preview Worker must bind HTML_PREVIEWS R2");
  check(hasBinding(arrays(doc, "d1_databases"), "PREVIEW_DB"), "preview Worker must bind PREVIEW_DB D1");
  check(hasBinding(arrays(doc, "env.api.r2_buckets"), "HTML_PREVIEWS"), "API Worker must bind HTML_PREVIEWS R2");
  check(hasBinding(arrays(doc, "env.api.d1_databases"), "PREVIEW_DB"), "API Worker must bind PREVIEW_DB D1");
  check(hasBinding(arrays(doc, "env.mcp.d1_databases"), "PREVIEW_DB"), "MCP Worker must bind PREVIEW_DB D1");
  check(mcpHasNoR2(doc, mcp), "MCP Worker must not bind R2");
  check(hasBinding(arrays(doc, "ratelimits"), "EDGE_ACCESS_RATE_LIMITER"), "preview access rate limiter must exist");
  check(
    hasBinding(arrays(doc, "env.api.ratelimits"), "EDGE_PUBLISH_RATE_LIMITER"),
    "API publish rate limiter must exist",
  );
  check(hasBinding(arrays(doc, "env.mcp.ratelimits"), "EDGE_MCP_RATE_LIMITER"), "MCP rate limiter must exist");
  check(
    arrays(doc, "env.mcp.services").some((service) => service.binding === "PUBLISH_API" && service.service === api.name),
    "MCP Worker must call the API Worker through the PUBLISH_API service binding",
  );

  check(mcpVars.MCP_OAUTH_SCOPES === "mcp:tools", "MCP OAuth scope should default to mcp:tools");
  check(
    includesListValue(mcpVars.MCP_OAUTH_PUBLIC_CLIENT_IDS, "codex-html-sharing-mcp"),
    "Codex public MCP client id must be configured",
  );
  check(
    includesListValue(mcpVars.MCP_OAUTH_PUBLIC_CLIENT_IDS, "claude-code-html-sharing-mcp"),
    "Claude Code public MCP client id must be configured",
  );
  check(
    includesListValue(mcpVars.MCP_OAUTH_PUBLIC_CLIENT_IDS, "cursor-html-sharing-mcp"),
    "Cursor public MCP client id must be configured",
  );
  check(
    includesListValue(mcpVars.MCP_OAUTH_ALLOWED_REDIRECT_URIS, "cursor://anysphere.cursor-mcp/oauth/callback"),
    "Cursor MCP redirect URI must be allow-listed",
  );
  check(
    includesListValue(mcpVars.MCP_OAUTH_ALLOWED_REDIRECT_URIS, "http://127.0.0.1:5555/callback"),
    "Codex loopback redirect URI must be allow-listed",
  );
  check(
    includesListValue(mcpVars.MCP_OAUTH_ALLOWED_REDIRECT_URIS, "http://localhost:5555/callback"),
    "Claude Code loopback redirect URI must be allow-listed",
  );
  check(apiVars.GLEAN_OAUTH_CLIENT_ID === undefined, "API admin OAuth must use dynamic client registration, not a static client id");
  check(apiVars.GLEAN_OAUTH_CLIENT_SECRET === undefined, "API admin OAuth must not configure a static client secret");
  check(
    hasText(apiVars.GLEAN_OAUTH_DISCOVERY_URL) || hasText(apiVars.GLEAN_OAUTH_ISSUER),
    "API admin dynamic OAuth must configure GLEAN_OAUTH_DISCOVERY_URL or GLEAN_OAUTH_ISSUER",
  );
  check(hasText(mcpVars.GLEAN_OAUTH_CLIENT_ID), "MCP Glean OAuth must keep its configured static client id");
  check(apiVars.GLEAN_OAUTH_SCOPES === undefined, "API admin OAuth scopes are code-owned and must not be configured");
  check(mcpVars.GLEAN_OAUTH_SCOPES === "openid email", "MCP Glean OAuth scopes must stay identity-only");

  if (options.kind === "template") {
    check(content.includes("your-workers-subdomain"), "public template should keep placeholder Worker hostnames");
    check(content.includes("<r2-production-bucket-name>"), "public template should keep placeholder R2 bucket names");
    check(content.includes("<d1-production-database-name>"), "public template should keep placeholder D1 database names");
    check(content.includes("<d1-production-database-id>"), "public template should keep placeholder D1 ids");
    check(content.includes("<mcp-rate-limit-namespace-id>"), "public template should keep placeholder rate-limit ids");
    check(!content.includes("glean-share"), "public template should not contain deployment-specific Worker hostnames");
    check(!content.includes("scio-prod-be"), "public template should not contain deployment-specific Glean hosts");
  }

  if (options.kind === "local") {
    for (const item of placeholderLocations(doc)) {
      if (!optionalLocalPlaceholderKeys.has(item.key)) {
        check(false, `${path} still has placeholder value for ${item.context}.${item.key}`);
      }
    }
  }

  const failures = checks.filter((item) => !item.condition);
  if (failures.length > 0) {
    console.error(`${path}: ${failures.length} config check(s) failed:`);
    for (const failure of failures) {
      console.error(`- ${failure.message}`);
    }
    process.exit(1);
  }

  console.log(`${path}: ${checks.length} config checks passed.`);
}

function parseToml(content, path) {
  const doc = { root: {}, sections: new Map(), arrays: new Map() };
  let current = doc.root;
  let context = "root";

  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    const line = stripComment(rawLine).trim();
    if (!line) {
      continue;
    }

    const arrayMatch = line.match(/^\[\[([^\]]+)]]$/);
    if (arrayMatch) {
      context = arrayMatch[1].trim();
      current = {};
      if (!doc.arrays.has(context)) {
        doc.arrays.set(context, []);
      }
      doc.arrays.get(context).push(current);
      continue;
    }

    const sectionMatch = line.match(/^\[([^\]]+)]$/);
    if (sectionMatch) {
      context = sectionMatch[1].trim();
      if (!doc.sections.has(context)) {
        doc.sections.set(context, {});
      }
      current = doc.sections.get(context);
      continue;
    }

    const assignmentMatch = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!assignmentMatch) {
      throw new Error(`${path}:${index + 1}: unsupported TOML line: ${rawLine}`);
    }

    current[assignmentMatch[1]] = parseTomlValue(assignmentMatch[2].trim(), path, index + 1);
  }

  return doc;
}

function stripComment(line) {
  let inString = false;
  let escaped = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === '"') {
      inString = !inString;
      continue;
    }
    if (char === "#" && !inString) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseTomlValue(value, path, lineNumber) {
  if (value.startsWith('"')) {
    try {
      return JSON.parse(value);
    } catch {
      throw new Error(`${path}:${lineNumber}: invalid quoted string`);
    }
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  if (value === "[]") {
    return [];
  }
  if (value.startsWith("[") && value.endsWith("]")) {
    const inner = value.slice(1, -1).trim();
    if (!inner) {
      return [];
    }
    return inner.split(",").map((item) => parseTomlValue(item.trim(), path, lineNumber));
  }
  if (/^-?\d+$/.test(value)) {
    return Number(value);
  }
  return value;
}

function section(doc, name) {
  return doc.sections.get(name) ?? {};
}

function arrays(doc, name) {
  return doc.arrays.get(name) ?? [];
}

function hasBinding(entries, binding) {
  return entries.some((entry) => entry.binding === binding || entry.name === binding);
}

function mcpHasNoR2(doc, mcp) {
  const arrayBindings = arrays(doc, "env.mcp.r2_buckets");
  const inlineBindings = mcp.r2_buckets;
  return arrayBindings.length === 0 && (inlineBindings === undefined || (Array.isArray(inlineBindings) && inlineBindings.length === 0));
}

function isUrl(value) {
  if (typeof value !== "string") {
    return false;
  }
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.hostname === "localhost" || url.hostname === "127.0.0.1";
  } catch {
    return false;
  }
}

function distinctUrlOrigins(values) {
  if (!values.every((value) => typeof value === "string")) {
    return false;
  }
  const origins = values.map((value) => new URL(value).origin);
  return new Set(origins).size === origins.length;
}

function includesListValue(value, expected) {
  if (typeof value !== "string") {
    return false;
  }
  return value.split(/[\n,]+/).map((item) => item.trim()).includes(expected);
}

function hasText(value) {
  return typeof value === "string" && value.trim() !== "";
}

function placeholderLocations(doc) {
  const locations = [];
  for (const [context, table] of [["root", doc.root], ...doc.sections.entries()]) {
    collectPlaceholders(locations, context, table);
  }
  for (const [context, entries] of doc.arrays.entries()) {
    entries.forEach((entry, index) => collectPlaceholders(locations, `${context}[${index}]`, entry));
  }
  return locations;
}

function collectPlaceholders(locations, context, table) {
  for (const [key, value] of Object.entries(table)) {
    if (typeof value !== "string") {
      continue;
    }
    if (/<[^>]+>/.test(value) || value.includes("your-workers-subdomain") || value.includes("your-glean-domain") || value.includes("your-glean-backend")) {
      locations.push({ context, key });
    }
  }
}

main();
