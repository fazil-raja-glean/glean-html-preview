# Glean HTML Preview

Cloudflare Workers service for publishing untrusted HTML as password-protected, sandboxed preview URLs from Glean.

The preferred integration is a Glean remote MCP server:

- Glean calls `https://html-mcp.glean-share.workers.dev/mcp` with one API key.
- The MCP Worker calls the protected API Worker through a Cloudflare service binding.
- Uploaded HTML is stored privately in R2 and served only through the preview Worker.
- The preview Worker requires a viewer password and serves the uploaded HTML with a restrictive CSP sandbox.

## Security Model

This repo intentionally has three Worker surfaces:

| Surface | Worker | URL | Purpose |
| --- | --- | --- | --- |
| Preview | `html` | `https://html.glean-share.workers.dev` | Viewer password gate and sandboxed HTML serving |
| API | `html-api` | `https://html-api.glean-share.workers.dev` | Publish, unpublish, and password rotation |
| MCP | `html-mcp` | `https://html-mcp.glean-share.workers.dev` | Glean MCP JSON-RPC endpoint |

Key rules:

- Do not put publish/admin routes on the preview Worker.
- Do not put preview routes on the API or MCP Workers.
- Do not give the MCP Worker direct R2 or D1 bindings.
- Do not give Glean the Cloudflare Access service-token secret.
- Do not weaken `HTML_SECURITY_HEADERS` in `src/index.ts`; the uploaded HTML must stay sandboxed.

Uploaded HTML is served with headers that block scripts, network calls, form posts, frames, workers, plugins, and remote beacons.

## Secrets

Do not commit real secrets. `.env`, `.dev.vars`, `.wrangler/`, and `node_modules/` are ignored.

| Secret | Preview Worker | API Worker | MCP Worker | Given to Glean |
| --- | --- | --- | --- | --- |
| `COOKIE_SIGNING_SECRET` | yes | yes | yes | no |
| `PASSWORD_PEPPER` | yes | yes | no | no |
| `PUBLISH_API_TOKEN` | no | yes | yes | no |
| `PUBLISH_INTERNAL_SERVICE_TOKEN` | no | yes | yes | no |
| `MCP_API_TOKEN` | no | no | yes | yes |

`PUBLISH_ACCESS_TEAM_DOMAIN`, `PUBLISH_ACCESS_AUD`, Worker names, R2 bucket names, D1 IDs, and rate-limit namespace IDs are configuration, not bearer secrets. They can live in `wrangler.toml`.

## Deploy MCP From Scratch

### 1. Install and log in

```sh
npm install --ignore-scripts
npx wrangler whoami || npx wrangler login
```

### 2. Create Cloudflare storage

Create one private R2 bucket and one D1 database for production:

```sh
npx wrangler r2 bucket create html-sharing-previews-prod
npx wrangler d1 create html-sharing-metadata-prod
```

For local/dev previews, create dev resources too:

```sh
npx wrangler r2 bucket create html-sharing-previews-dev
npx wrangler d1 create html-sharing-metadata-dev
```

Put the returned D1 IDs into `wrangler.toml`:

- top-level `[[d1_databases]].database_id`
- top-level `[[d1_databases]].preview_database_id`
- `[[env.api.d1_databases]].database_id`
- `[[env.api.d1_databases]].preview_database_id`

The R2 bucket names are also configured in `wrangler.toml`.

### 3. Create rate-limit namespaces

Create three Cloudflare Worker Rate Limiting namespaces, then put their IDs into `wrangler.toml`:

| Binding | Route | Current limit |
| --- | --- | --- |
| `EDGE_ACCESS_RATE_LIMITER` | `POST /p/:slug/access` | 30/min |
| `EDGE_PUBLISH_RATE_LIMITER` | `POST /v1/html-previews` | 20/min |
| `EDGE_MCP_RATE_LIMITER` | `POST /mcp` | 30/min |

### 4. Configure Cloudflare Access for the API Worker

In Cloudflare Zero Trust:

1. Open **Access -> Applications**.
2. Create an application for `https://html-api.glean-share.workers.dev`.
3. Do not protect `https://html.glean-share.workers.dev`.
4. Copy the Access team domain, for example `https://<team>.cloudflareaccess.com`.
5. Copy the application AUD tag.
6. Update `wrangler.toml`:

```toml
PUBLISH_ACCESS_TEAM_DOMAIN = "https://<team>.cloudflareaccess.com"
PUBLISH_ACCESS_AUD = "<access-application-aud-tag>"
```

This protects external API requests. The MCP Worker does not need the Cloudflare Access client id or client secret because it reaches the API Worker through the `PUBLISH_API` service binding.

### 5. Generate production tokens

Generate the Worker secrets locally:

```sh
export COOKIE_SIGNING_SECRET="$(openssl rand -base64 48)"
export PASSWORD_PEPPER="$(openssl rand -base64 48)"
export PUBLISH_API_TOKEN="$(openssl rand -base64 48)"
export PUBLISH_INTERNAL_SERVICE_TOKEN="$(openssl rand -base64 48)"
export MCP_API_TOKEN="$(openssl rand -base64 48)"
```

Only rotate `PASSWORD_PEPPER` before real traffic exists, or when invalidating existing preview passwords is acceptable.

Upload the secrets:

```sh
printf '%s' "$COOKIE_SIGNING_SECRET" | npx wrangler secret put COOKIE_SIGNING_SECRET --env=""
printf '%s' "$COOKIE_SIGNING_SECRET" | npx wrangler secret put COOKIE_SIGNING_SECRET --env api
printf '%s' "$COOKIE_SIGNING_SECRET" | npx wrangler secret put COOKIE_SIGNING_SECRET --env mcp

printf '%s' "$PASSWORD_PEPPER" | npx wrangler secret put PASSWORD_PEPPER --env=""
printf '%s' "$PASSWORD_PEPPER" | npx wrangler secret put PASSWORD_PEPPER --env api

printf '%s' "$PUBLISH_API_TOKEN" | npx wrangler secret put PUBLISH_API_TOKEN --env api
printf '%s' "$PUBLISH_API_TOKEN" | npx wrangler secret put PUBLISH_API_TOKEN --env mcp

printf '%s' "$PUBLISH_INTERNAL_SERVICE_TOKEN" | npx wrangler secret put PUBLISH_INTERNAL_SERVICE_TOKEN --env api
printf '%s' "$PUBLISH_INTERNAL_SERVICE_TOKEN" | npx wrangler secret put PUBLISH_INTERNAL_SERVICE_TOKEN --env mcp

printf '%s' "$MCP_API_TOKEN" | npx wrangler secret put MCP_API_TOKEN --env mcp
```

### 6. Apply the schema

```sh
npm run d1:migrate:prod
```

The schema is idempotent.

### 7. Deploy

Run a dry run first:

```sh
npm run deploy:dry-run
```

Expected dry-run shape:

- Preview Worker lists `HTML_PREVIEWS`, `PREVIEW_DB`, and `EDGE_ACCESS_RATE_LIMITER`.
- API Worker lists `HTML_PREVIEWS`, `PREVIEW_DB`, and `EDGE_PUBLISH_RATE_LIMITER`.
- MCP Worker lists `PUBLISH_API` and `EDGE_MCP_RATE_LIMITER`.
- MCP Worker does not list `HTML_PREVIEWS` or `PREVIEW_DB`.
- Wrangler may warn that top-level R2/D1 bindings are absent from `env.mcp`; that is intentional least privilege.

Deploy:

```sh
npm run deploy
```

### 8. Smoke test the live MCP endpoint

```sh
export MCP="https://html-mcp.glean-share.workers.dev"
```

Auth checks:

```sh
curl -i "$MCP/mcp" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize"}'

curl -i "$MCP/mcp" \
  -H "Authorization: Bearer wrong-token" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
```

Expected:

- missing bearer token returns `401`
- wrong bearer token returns `403`

MCP handshake and tool discovery:

```sh
curl -sS "$MCP/mcp" \
  -H "Authorization: Bearer $MCP_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl-smoke","version":"1.0.0"}}}'

curl -sS "$MCP/mcp" \
  -H "Authorization: Bearer $MCP_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Expected:

- `initialize` returns `serverInfo.name = "html-sharing"`
- `tools/list` returns `publish_html_preview`

Publish through MCP:

```sh
curl -sS "$MCP/mcp" \
  -H "Authorization: Bearer $MCP_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "publish_html_preview",
      "arguments": {
        "title": "MCP smoke test",
        "html": "<!doctype html><html><body><h1>Hello from MCP</h1></body></html>",
        "password": "correct horse battery"
      }
    }
  }'
```

Expected response includes:

```json
{
  "result": {
    "structuredContent": {
      "url": "https://html.glean-share.workers.dev/p/<slug>",
      "slug": "<slug>",
      "status": "active"
    }
  }
}
```

### 9. Create the Glean MCP server

In Glean Admin Console:

1. Open **Admin Console -> Platform -> Tools (formerly Actions)**.
2. Select **Vendor Provided Tools (via MCP)**.
3. Click **Add**.
4. Select **Vendor provided tools (via MCP)**.
5. Choose **Import tools from MCP server**.
6. Set **MCP server name** to `Secure HTML Preview Publisher`.
7. Set **Description** to `Publishes password-protected sandboxed HTML previews and returns shareable URLs.`
8. Set **MCP server URL** to `https://html-mcp.glean-share.workers.dev/mcp`.
9. Leave **Transport type** as **Streaming HTTP**.
10. Set **Authentication method** to **API Key**.
11. Paste `MCP_API_TOKEN` into **Enter API key**.
12. Click **Initiate connection**.
13. Click **Save** if Glean asks you to save before discovery.
14. Click **Fetch tools** or **Refresh tools**.
15. Confirm the discovered tool is **Publish Html Preview**.
16. Keep Chat visibility off until you intentionally choose who can use it.
17. Enable only the users or groups that should be allowed to publish hosted HTML previews.

Glean should send only:

```text
Authorization: Bearer <MCP_API_TOKEN>
```

Glean should not know `PUBLISH_API_TOKEN`, `PUBLISH_INTERNAL_SERVICE_TOKEN`, `COOKIE_SIGNING_SECRET`, or `PASSWORD_PEPPER`.

## Local Development

Create `.dev.vars` with local-only random values:

```sh
LOCAL_PUBLISH_API_TOKEN="$(openssl rand -base64 48)"
LOCAL_MCP_API_TOKEN="$(openssl rand -base64 48)"
LOCAL_ADMIN_BYPASS_SECRET="$(openssl rand -base64 48)"
LOCAL_COOKIE_SIGNING_SECRET="$(openssl rand -base64 48)"
LOCAL_PASSWORD_PEPPER="$(openssl rand -base64 48)"

cat > .dev.vars <<EOF
PUBLISH_API_TOKEN=$LOCAL_PUBLISH_API_TOKEN
MCP_API_TOKEN=$LOCAL_MCP_API_TOKEN
PUBLISH_ADMIN_LOCAL_BYPASS_SECRET=$LOCAL_ADMIN_BYPASS_SECRET
COOKIE_SIGNING_SECRET=$LOCAL_COOKIE_SIGNING_SECRET
PASSWORD_PEPPER=$LOCAL_PASSWORD_PEPPER
TRUSTED_PUBLISHER_EMAIL=html-sharing@glean.com
WORKER_ROLE=combined
EOF
```

Run locally:

```sh
npm install --ignore-scripts
npm run d1:migrate:local
npm run dev
```

Publish locally through the API route:

```sh
curl -i http://localhost:8787/v1/html-previews \
  -H "Authorization: Bearer $LOCAL_PUBLISH_API_TOKEN" \
  -H "X-Publish-Admin-Secret: $LOCAL_ADMIN_BYPASS_SECRET" \
  -H "Content-Type: application/json" \
  --data '{
    "title": "Local smoke test",
    "html": "<!doctype html><html><body><h1>Hello</h1></body></html>",
    "password": "correct horse battery"
  }'
```

## Rotation

Rotate `MCP_API_TOKEN` when a Glean credential is exposed:

```sh
export MCP_API_TOKEN="$(openssl rand -base64 48)"
printf '%s' "$MCP_API_TOKEN" | npx wrangler secret put MCP_API_TOKEN --env mcp
```

Then update the API key in the Glean MCP server configuration.

Rotate `PUBLISH_API_TOKEN` or `PUBLISH_INTERNAL_SERVICE_TOKEN` when Worker-to-Worker credentials are exposed:

```sh
export PUBLISH_API_TOKEN="$(openssl rand -base64 48)"
export PUBLISH_INTERNAL_SERVICE_TOKEN="$(openssl rand -base64 48)"

printf '%s' "$PUBLISH_API_TOKEN" | npx wrangler secret put PUBLISH_API_TOKEN --env api
printf '%s' "$PUBLISH_API_TOKEN" | npx wrangler secret put PUBLISH_API_TOKEN --env mcp

printf '%s' "$PUBLISH_INTERNAL_SERVICE_TOKEN" | npx wrangler secret put PUBLISH_INTERNAL_SERVICE_TOKEN --env api
printf '%s' "$PUBLISH_INTERNAL_SERVICE_TOKEN" | npx wrangler secret put PUBLISH_INTERNAL_SERVICE_TOKEN --env mcp
```

Rotate `COOKIE_SIGNING_SECRET` only when invalidating existing viewer sessions is acceptable.

Rotate `PASSWORD_PEPPER` only when invalidating existing preview passwords is acceptable.

## Legacy Custom Action

The custom-action path is still supported by `action/openapi.yaml`, but MCP is preferred.

The legacy custom action requires Glean to hold:

- `Authorization: Bearer <PUBLISH_API_TOKEN>`
- `CF-Access-Client-Id: <access-service-token-client-id>`
- `CF-Access-Client-Secret: <access-service-token-client-secret>`

Use MCP whenever possible because Glean only needs `MCP_API_TOKEN`.
