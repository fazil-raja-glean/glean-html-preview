#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const rootFiles = ["package.json", "wrangler.toml", "schema.sql"];

function main() {
  assertRepoRoot();
  ensureDependencies();
  ensureLocalWranglerConfig();
  ensureDevVars();
  printNextSteps();
}

function assertRepoRoot() {
  for (const file of rootFiles) {
    if (!existsSync(file)) {
      fail(`Run this from the repo root; missing ${file}.`);
    }
  }

  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  if (pkg.name !== "html-sharing") {
    fail(`Expected package name html-sharing, found ${pkg.name}.`);
  }
}

function ensureDependencies() {
  if (existsSync("node_modules/.package-lock.json") || existsSync("node_modules/typescript")) {
    console.log("Dependencies already installed.");
    return;
  }

  console.log("Installing npm dependencies with --ignore-scripts...");
  const result = spawnSync("npm", ["install", "--ignore-scripts"], { stdio: "inherit" });
  if (result.status !== 0) {
    fail("npm install --ignore-scripts failed.");
  }
}

function ensureLocalWranglerConfig() {
  if (existsSync("wrangler.local.toml")) {
    console.log("wrangler.local.toml already exists; leaving it untouched.");
    return;
  }

  const source = existsSync("wrangler.local.example.toml") ? "wrangler.local.example.toml" : "wrangler.toml";
  writeFileSync("wrangler.local.toml", readFileSync(source, "utf8"));
  console.log(`Created wrangler.local.toml from ${source}.`);
}

function ensureDevVars() {
  if (existsSync(".dev.vars")) {
    console.log(".dev.vars already exists; leaving it untouched.");
    return;
  }

  const publishApiToken = secret();
  const mcpClientSecret = secret();
  const mcpTokenSecret = secret();
  const adminBypassSecret = secret();
  const adminDynamicOauthSecret = secret();
  const adminSessionSecret = secret();
  const gleanClientSecret = secret();
  const cookieSigningSecret = secret();
  const passwordPepper = secret();

  const devVars = `PUBLISH_API_TOKEN=${publishApiToken}
MCP_OAUTH_CLIENT_ID=local-html-sharing-mcp
MCP_OAUTH_PUBLIC_CLIENT_IDS=codex-html-sharing-mcp,claude-code-html-sharing-mcp,cursor-html-sharing-mcp
MCP_OAUTH_ALLOWED_REDIRECT_URIS=http://localhost:8787/oauth/local-callback,http://127.0.0.1:5555/callback,http://localhost:5555/callback,cursor://anysphere.cursor-mcp/oauth/callback
MCP_OAUTH_REQUIRE_USER_AUTH=true
MCP_OAUTH_LOCAL_BYPASS_EMAIL=html-sharing@example.com
MCP_OAUTH_ALLOWED_EMAIL_DOMAIN=example.com
MCP_OAUTH_SCOPES=mcp:tools
MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS=2592000
MCP_OAUTH_CLIENT_SECRET=${mcpClientSecret}
MCP_OAUTH_TOKEN_SECRET=${mcpTokenSecret}
ADMIN_ALLOWED_EMAIL_DOMAIN=example.com
ADMIN_LOCAL_BYPASS_EMAIL=html-sharing@example.com
ADMIN_DYNAMIC_OAUTH_ENCRYPTION_SECRET=${adminDynamicOauthSecret}
ADMIN_SESSION_SECRET=${adminSessionSecret}
GLEAN_OAUTH_CLIENT_ID=local-html-sharing-admin
GLEAN_OAUTH_CLIENT_SECRET=${gleanClientSecret}
GLEAN_OAUTH_AUTHORIZATION_URL=http://localhost:8787/oauth/dev/authorize
GLEAN_OAUTH_TOKEN_URL=http://localhost:8787/oauth/dev/token
GLEAN_OAUTH_USERINFO_URL=http://localhost:8787/oauth/dev/userinfo
GLEAN_OAUTH_SCOPES=openid email
PUBLISH_ADMIN_LOCAL_BYPASS_SECRET=${adminBypassSecret}
COOKIE_SIGNING_SECRET=${cookieSigningSecret}
PASSWORD_PEPPER=${passwordPepper}
TRUSTED_PUBLISHER_EMAIL=html-sharing@example.com
PUBLISHER_EMAIL_DOMAIN=example.com
WORKER_ROLE=combined
`;

  writeFileSync(".dev.vars", devVars, { mode: 0o600 });
  console.log("Created .dev.vars with generated local-only secrets.");
}

function printNextSteps() {
  console.log(`
Next steps:
1. Edit wrangler.local.toml and replace placeholders with real Cloudflare and OAuth values.
2. Run npm run verify:config.
3. Run npm run d1:migrate:local.
4. Run npm run dev.

For production deploys, read SETUP.md before uploading secrets or running npm run deploy.
`);
}

function secret() {
  return randomBytes(48).toString("base64");
}

function fail(message) {
  console.error(`setup-agent: ${message}`);
  process.exit(1);
}

main();
