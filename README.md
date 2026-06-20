# Glean HTML Preview

Cloudflare Workers service for publishing untrusted HTML as password-protected, sandboxed preview URLs from Glean.

The preferred integration is a Glean remote MCP server:

- Glean users authenticate through Glean OAuth.
- Glean obtains short-lived OAuth access tokens from `${MCP_BASE_URL}/oauth/token`.
- Glean calls `${MCP_BASE_URL}/mcp` with those OAuth bearer tokens.
- The MCP Worker calls the protected API Worker through a Cloudflare service binding.
- Uploaded HTML is stored privately in R2 and served only through the preview Worker.
- The preview Worker requires a viewer password and serves the uploaded HTML with a restrictive CSP sandbox.
- Signed-in users use `${API_BASE_URL}/admin` to list their own previews, reset viewer passwords, unpublish, and delete their own previews.

## Security Model

This repo intentionally has three Worker surfaces:

| Surface | Worker | URL | Purpose |
| --- | --- | --- | --- |
| Preview | `html` | `${PUBLIC_BASE_URL}` | Viewer password gate and sandboxed HTML serving |
| API | `html-api` | `${API_BASE_URL}` | Publish routes and Glean-authenticated self-service UI |
| MCP | `html-mcp` | `${MCP_BASE_URL}` | Glean MCP JSON-RPC endpoint |

Key rules:

- Do not put publish/admin routes on the preview Worker.
- Do not put preview routes on the API or MCP Workers.
- Do not give the MCP Worker direct R2 access. It only gets D1 for OAuth grant and refresh-token state.
- Do not expose R2, D1, publish, OAuth-token-signing, cookie-signing, or password-pepper secrets to browser JavaScript.
- Do not weaken `HTML_SECURITY_HEADERS` in `src/index.ts`; the uploaded HTML must stay sandboxed.
- Do not render uploaded HTML inside the admin UI. Admin HTML downloads are served as `text/plain`.

Uploaded HTML is served with headers that block scripts, network calls, form posts, frames, workers, plugins, and remote beacons.

## Secrets

Do not commit real secrets. `.env`, `.dev.vars`, `.wrangler/`, and `node_modules/` are ignored.

| Secret | Preview Worker | API Worker | MCP Worker | Given to Glean |
| --- | --- | --- | --- | --- |
| `COOKIE_SIGNING_SECRET` | yes | yes | yes | no |
| `PASSWORD_PEPPER` | yes | yes | no | no |
| `PUBLISH_API_TOKEN` | no | yes | yes | no |
| `PUBLISH_INTERNAL_SERVICE_TOKEN` | no | yes | yes | no |
| `ADMIN_SESSION_SECRET` | no | yes | yes | no |
| `GLEAN_OAUTH_CLIENT_SECRET` | no | yes | yes | no |
| `MCP_OAUTH_CLIENT_ID` | no | no | yes | yes |
| `MCP_OAUTH_CLIENT_SECRET` | no | no | yes | yes |
| `MCP_OAUTH_TOKEN_SECRET` | no | no | yes | no |

`GLEAN_OAUTH_CLIENT_ID`, `GLEAN_OAUTH_AUTHORIZATION_URL`, `GLEAN_OAUTH_TOKEN_URL`, `GLEAN_OAUTH_USERINFO_URL`, `GLEAN_OAUTH_SCOPES`, `ADMIN_ALLOWED_EMAIL_DOMAIN`, `ADMIN_ALLOWED_EMAILS`, `PUBLISH_ACCESS_TEAM_DOMAIN`, `PUBLISH_ACCESS_AUD`, `MCP_OAUTH_ALLOWED_REDIRECT_URIS`, `MCP_OAUTH_PUBLIC_CLIENT_IDS`, `MCP_OAUTH_SCOPES`, `MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS`, Worker names, R2 bucket names, D1 IDs, and rate-limit namespace IDs are configuration, not bearer secrets. They can live in `wrangler.toml`.

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

### 4. Configure Glean OAuth

Create a Glean OAuth client for this deployment and allow-list these redirect URIs:

- `${API_BASE_URL}/admin/oauth/callback`
- `${MCP_BASE_URL}/oauth/callback`

Set the Glean OAuth endpoints in `wrangler.toml` for both `env.api` and `env.mcp`:

```toml
GLEAN_OAUTH_CLIENT_ID = "html-sharing-admin"
GLEAN_OAUTH_AUTHORIZATION_URL = "https://<glean-domain>/oauth/authorize"
GLEAN_OAUTH_TOKEN_URL = "https://<glean-domain>/oauth/token"
GLEAN_OAUTH_USERINFO_URL = "https://<glean-domain>/oauth/userinfo"
GLEAN_OAUTH_SCOPES = "openid email profile"
```

If Glean provides OpenID discovery for this OAuth client, you can set `GLEAN_OAUTH_ISSUER` or `GLEAN_OAUTH_DISCOVERY_URL` instead of the three endpoint URLs.

Configure self-service console authorization:

```toml
ADMIN_ALLOWED_EMAIL_DOMAIN = "example.com"
ADMIN_ALLOWED_EMAILS = ""
ADMIN_SESSION_TTL_SECONDS = "28800"
MCP_OAUTH_ALLOWED_EMAIL_DOMAIN = "example.com"
MCP_OAUTH_REQUIRE_USER_AUTH = "true"
```

If `ADMIN_ALLOWED_EMAILS` is set, only those exact emails can use `/admin`. Otherwise, any verified user in `ADMIN_ALLOWED_EMAIL_DOMAIN` can use `/admin`.

The `/admin` console is owner-scoped by default: a signed-in user only sees and manages previews whose `publisher_email` matches their Glean email. The allowlist controls who can enter the console; it does not make every allowed user a global administrator.

The API and MCP workers share the same Glean OAuth client configuration, but they use separate session cookies because they run on separate production origins:

- `/admin` sessions are scoped to the API Worker.
- `/oauth/authorize` sessions are scoped to the MCP Worker.

### 5. Configure legacy direct API Access, if needed

The preferred Glean and admin paths do not require Cloudflare Access service tokens in the browser or in Glean. The direct `/v1/html-previews*` API can still keep the old second lock for backend scripts or legacy custom Actions:

```toml
PUBLISH_ACCESS_TEAM_DOMAIN = "https://<team>.cloudflareaccess.com"
PUBLISH_ACCESS_AUD = "<access-application-aud-tag>"
```

Do not protect `${PUBLIC_BASE_URL}`. The MCP Worker does not need the Cloudflare Access client id or client secret because it reaches the API Worker through the `PUBLISH_API` service binding.

### 6. Generate production tokens

Generate the Worker secrets locally:

```sh
export COOKIE_SIGNING_SECRET="$(openssl rand -base64 48)"
export ADMIN_SESSION_SECRET="$(openssl rand -base64 48)"
export PASSWORD_PEPPER="$(openssl rand -base64 48)"
export PUBLISH_API_TOKEN="$(openssl rand -base64 48)"
export PUBLISH_INTERNAL_SERVICE_TOKEN="$(openssl rand -base64 48)"
export GLEAN_OAUTH_CLIENT_SECRET="$(openssl rand -base64 48)"
export MCP_OAUTH_CLIENT_SECRET="$(openssl rand -base64 48)"
export MCP_OAUTH_TOKEN_SECRET="$(openssl rand -base64 48)"
```

Only rotate `PASSWORD_PEPPER` before real traffic exists, or when invalidating existing preview passwords is acceptable.

Upload the secrets:

```sh
printf '%s' "$COOKIE_SIGNING_SECRET" | npx wrangler secret put COOKIE_SIGNING_SECRET --env=""
printf '%s' "$COOKIE_SIGNING_SECRET" | npx wrangler secret put COOKIE_SIGNING_SECRET --env api
printf '%s' "$COOKIE_SIGNING_SECRET" | npx wrangler secret put COOKIE_SIGNING_SECRET --env mcp

printf '%s' "$ADMIN_SESSION_SECRET" | npx wrangler secret put ADMIN_SESSION_SECRET --env api
printf '%s' "$ADMIN_SESSION_SECRET" | npx wrangler secret put ADMIN_SESSION_SECRET --env mcp

printf '%s' "$PASSWORD_PEPPER" | npx wrangler secret put PASSWORD_PEPPER --env=""
printf '%s' "$PASSWORD_PEPPER" | npx wrangler secret put PASSWORD_PEPPER --env api

printf '%s' "$PUBLISH_API_TOKEN" | npx wrangler secret put PUBLISH_API_TOKEN --env api
printf '%s' "$PUBLISH_API_TOKEN" | npx wrangler secret put PUBLISH_API_TOKEN --env mcp

printf '%s' "$PUBLISH_INTERNAL_SERVICE_TOKEN" | npx wrangler secret put PUBLISH_INTERNAL_SERVICE_TOKEN --env api
printf '%s' "$PUBLISH_INTERNAL_SERVICE_TOKEN" | npx wrangler secret put PUBLISH_INTERNAL_SERVICE_TOKEN --env mcp

printf '%s' "$GLEAN_OAUTH_CLIENT_SECRET" | npx wrangler secret put GLEAN_OAUTH_CLIENT_SECRET --env api
printf '%s' "$GLEAN_OAUTH_CLIENT_SECRET" | npx wrangler secret put GLEAN_OAUTH_CLIENT_SECRET --env mcp

printf '%s' "$MCP_OAUTH_CLIENT_SECRET" | npx wrangler secret put MCP_OAUTH_CLIENT_SECRET --env mcp
printf '%s' "$MCP_OAUTH_TOKEN_SECRET" | npx wrangler secret put MCP_OAUTH_TOKEN_SECRET --env mcp
```

### 7. Apply the schema

```sh
npm run d1:migrate:prod
```

The schema is idempotent.

### 8. Deploy

Run a dry run first:

```sh
npm run deploy:dry-run
```

Expected dry-run shape:

- Preview Worker lists `HTML_PREVIEWS`, `PREVIEW_DB`, and `EDGE_ACCESS_RATE_LIMITER`.
- API Worker lists `HTML_PREVIEWS`, `PREVIEW_DB`, and `EDGE_PUBLISH_RATE_LIMITER`.
- MCP Worker lists `PUBLISH_API`, `PREVIEW_DB`, and `EDGE_MCP_RATE_LIMITER`.
- MCP Worker does not list `HTML_PREVIEWS`.
- Wrangler may warn that top-level R2 bindings are absent from `env.mcp`; that is intentional least privilege.

Deploy:

```sh
npm run deploy
```

### 9. Smoke test the live MCP endpoint

```sh
export MCP="https://your-mcp-worker.example.com"
export MCP_OAUTH_CLIENT_ID="glean-html-sharing-mcp"
export MCP_OAUTH_CLIENT_SECRET="<client-secret-configured-in-glean>"
export MCP_OAUTH_SCOPES="mcp:tools"
export MCP_OAUTH_REDIRECT_URI="https://your-oauth-client.example.com/oauth/callback"
```

Auth checks:

```sh
curl -i "$MCP/mcp" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize"}'

curl -i "$MCP/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'grant_type=client_credentials&client_id=wrong&client_secret=wrong'
```

Expected:

- missing MCP bearer token returns `401` with a `WWW-Authenticate` OAuth challenge
- wrong OAuth client credentials return `401`

Get a machine OAuth access token for handshake and tool discovery:

```sh
ACCESS_TOKEN="$(
  curl -sS "$MCP/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode "client_id=$MCP_OAUTH_CLIENT_ID" \
    --data-urlencode "client_secret=$MCP_OAUTH_CLIENT_SECRET" \
    --data-urlencode "scope=$MCP_OAUTH_SCOPES" \
    | node -e 'let data=""; process.stdin.on("data", c => data += c); process.stdin.on("end", () => console.log(JSON.parse(data).access_token));'
)"
```

Authorization-code login smoke test, matching Glean, Codex, Claude Code, and Cursor user OAuth:

```sh
AUTH_URL="$(
  node -e 'const [base, clientId, redirectUri, scope] = process.argv.slice(1); const url = new URL("/oauth/authorize", base); url.searchParams.set("response_type", "code"); url.searchParams.set("client_id", clientId); url.searchParams.set("redirect_uri", redirectUri); url.searchParams.set("scope", scope); console.log(url.toString())' \
    "$MCP" \
    "$MCP_OAUTH_CLIENT_ID" \
    "$MCP_OAUTH_REDIRECT_URI" \
    "$MCP_OAUTH_SCOPES"
)"
open "$AUTH_URL"
```

After the browser redirects to `$MCP_OAUTH_REDIRECT_URI`, copy the `code` query parameter from the redirected URL. Exchange it for a user-bound token:

```sh
export OAUTH_CODE="<code-from-redirect-url>"

USER_ACCESS_TOKEN="$(
  curl -sS "$MCP/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "client_id=$MCP_OAUTH_CLIENT_ID" \
    --data-urlencode "client_secret=$MCP_OAUTH_CLIENT_SECRET" \
    --data-urlencode "code=$OAUTH_CODE" \
    --data-urlencode "redirect_uri=$MCP_OAUTH_REDIRECT_URI" \
    --data-urlencode "resource=$MCP/mcp" \
    | node -e 'let data=""; process.stdin.on("data", c => data += c); process.stdin.on("end", () => console.log(JSON.parse(data).access_token));'
)"
```

MCP handshake and tool discovery:

```sh
curl -sS "$MCP/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl-smoke","version":"1.0.0"}}}'

curl -sS "$MCP/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Expected:

- `initialize` returns `serverInfo.name = "html-sharing"`
- `tools/list` returns `publish_html_preview`

Publish through MCP with a user-bound authorization-code token. `client_credentials` tokens can initialize and list tools, but publish calls fail because they are not tied to a Glean user:

```sh
curl -sS "$MCP/mcp" \
  -H "Authorization: Bearer $USER_ACCESS_TOKEN" \
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
      "url": "${PUBLIC_BASE_URL}/p/<slug>",
      "slug": "<slug>",
      "status": "active"
    }
  }
}
```

### 10. Create the Glean MCP server

In Glean Admin Console:

1. Open **Admin Console -> Platform -> Tools (formerly Actions)**.
2. Select **Vendor Provided Tools (via MCP)**.
3. Click **Add**.
4. Select **Vendor provided tools (via MCP)**.
5. Choose **Import tools from MCP server**.
6. Set **MCP server name** to `Secure HTML Preview Publisher`.
7. Set **Description** to `Publishes password-protected sandboxed HTML previews and returns shareable URLs.`
8. Set **MCP server URL** to `${MCP_BASE_URL}/mcp`.
9. Leave **Transport type** as **Streaming HTTP**.
10. Set **Authentication method** to **OAuth**.
11. Set **Token endpoint auth method** to **Client Secret (POST)**.
12. Set **Client ID** to the configured `MCP_OAUTH_CLIENT_ID`.
13. Paste `MCP_OAUTH_CLIENT_SECRET` into **Client secret**.
14. Set **Authorization URL** to `${MCP_BASE_URL}/oauth/authorize`.
15. Set **Token URL** to `${MCP_BASE_URL}/oauth/token`.
16. Set **Scopes** to the configured `MCP_OAUTH_SCOPES`.
17. Confirm the **Callback URL** is included in `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.
18. Click **Initiate connection** or **Refresh tools**.
19. Click **Save** if Glean asks you to save before discovery.
20. Click **Fetch tools** or **Refresh tools**.
21. Confirm the discovered tool is **Publish Html Preview**.
22. Keep Chat visibility off until you intentionally choose who can use it.
23. Enable only the users or groups that should be allowed to publish hosted HTML previews.

Glean should send only short-lived access tokens to `/mcp`:

```text
Authorization: Bearer <oauth-access-token>
```

Glean should not know `PUBLISH_API_TOKEN`, `PUBLISH_INTERNAL_SERVICE_TOKEN`, `MCP_OAUTH_TOKEN_SECRET`, `COOKIE_SIGNING_SECRET`, or `PASSWORD_PEPPER`.

If the tool is enabled for chat users, each publisher should complete the authorization-code flow through Glean SSO. Machine-only `client_credentials` tokens are accepted for handshake and discovery, but the `publish_html_preview` tool rejects tokens that do not contain a verified user email.

### 11. Connect Codex, Claude Code, and Cursor

Codex, Claude Code, and Cursor should use public OAuth clients with S256 PKCE. Configure the MCP Worker with:

```toml
MCP_OAUTH_PUBLIC_CLIENT_IDS = "codex-html-sharing-mcp,claude-code-html-sharing-mcp,cursor-html-sharing-mcp"
MCP_OAUTH_ALLOWED_REDIRECT_URIS = "https://your-glean-callback.example.com/oauth/callback,http://127.0.0.1:5555/callback,http://localhost:5555/callback,cursor://anysphere.cursor-mcp/oauth/callback"
MCP_OAUTH_REQUIRE_USER_AUTH = "true"
MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS = "2592000"
```

Authorization-code logins return refresh tokens so Glean and coding clients can keep the MCP connection alive without hourly re-auth. `client_credentials` tokens remain access-token-only and should be used only for setup, handshake, and tool discovery.

For Codex, use a fixed callback URL so the Worker can allow-list it:

```toml
# ~/.codex/config.toml
mcp_oauth_callback_port = 5555
mcp_oauth_callback_url = "http://127.0.0.1:5555/callback"
```

Then add and log in:

```sh
codex mcp add html_sharing \
  --url "$MCP/mcp" \
  --oauth-client-id codex-html-sharing-mcp \
  --oauth-resource "$MCP/mcp"

codex mcp login html_sharing
```

For Claude Code:

```sh
claude mcp add \
  --transport http \
  --client-id claude-code-html-sharing-mcp \
  --callback-port 5555 \
  html-sharing \
  "$MCP/mcp"
```

Then run `/mcp` in Claude Code and authenticate the `html-sharing` server.

For Cursor, add a remote server to `.cursor/mcp.json` or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "html-sharing": {
      "url": "https://html-mcp.your-workers-subdomain.workers.dev/mcp",
      "auth": {
        "CLIENT_ID": "cursor-html-sharing-mcp",
        "scopes": ["mcp:tools"]
      }
    }
  }
}
```

Cursor uses the fixed OAuth redirect URI `cursor://anysphere.cursor-mcp/oauth/callback`; keep that value in `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.

## Local Development

Create `.dev.vars` with local-only random values:

```sh
LOCAL_PUBLISH_API_TOKEN="$(openssl rand -base64 48)"
LOCAL_MCP_OAUTH_CLIENT_SECRET="$(openssl rand -base64 48)"
LOCAL_MCP_OAUTH_TOKEN_SECRET="$(openssl rand -base64 48)"
LOCAL_ADMIN_BYPASS_SECRET="$(openssl rand -base64 48)"
LOCAL_ADMIN_SESSION_SECRET="$(openssl rand -base64 48)"
LOCAL_GLEAN_OAUTH_CLIENT_SECRET="$(openssl rand -base64 48)"
LOCAL_COOKIE_SIGNING_SECRET="$(openssl rand -base64 48)"
LOCAL_PASSWORD_PEPPER="$(openssl rand -base64 48)"

cat > .dev.vars <<EOF
PUBLISH_API_TOKEN=$LOCAL_PUBLISH_API_TOKEN
MCP_OAUTH_CLIENT_ID=local-html-sharing-mcp
MCP_OAUTH_PUBLIC_CLIENT_IDS=codex-html-sharing-mcp,claude-code-html-sharing-mcp
MCP_OAUTH_ALLOWED_REDIRECT_URIS=http://localhost:8787/oauth/local-callback,http://127.0.0.1:5555/callback,http://localhost:5555/callback
MCP_OAUTH_REQUIRE_USER_AUTH=true
MCP_OAUTH_LOCAL_BYPASS_EMAIL=html-sharing@example.com
MCP_OAUTH_ALLOWED_EMAIL_DOMAIN=example.com
MCP_OAUTH_SCOPES=mcp:tools
MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS=2592000
MCP_OAUTH_CLIENT_SECRET=$LOCAL_MCP_OAUTH_CLIENT_SECRET
MCP_OAUTH_TOKEN_SECRET=$LOCAL_MCP_OAUTH_TOKEN_SECRET
ADMIN_ALLOWED_EMAIL_DOMAIN=example.com
ADMIN_LOCAL_BYPASS_EMAIL=html-sharing@example.com
ADMIN_SESSION_SECRET=$LOCAL_ADMIN_SESSION_SECRET
GLEAN_OAUTH_CLIENT_ID=local-html-sharing-admin
GLEAN_OAUTH_CLIENT_SECRET=$LOCAL_GLEAN_OAUTH_CLIENT_SECRET
GLEAN_OAUTH_AUTHORIZATION_URL=http://localhost:8787/oauth/dev/authorize
GLEAN_OAUTH_TOKEN_URL=http://localhost:8787/oauth/dev/token
GLEAN_OAUTH_USERINFO_URL=http://localhost:8787/oauth/dev/userinfo
PUBLISH_ADMIN_LOCAL_BYPASS_SECRET=$LOCAL_ADMIN_BYPASS_SECRET
COOKIE_SIGNING_SECRET=$LOCAL_COOKIE_SIGNING_SECRET
PASSWORD_PEPPER=$LOCAL_PASSWORD_PEPPER
TRUSTED_PUBLISHER_EMAIL=html-sharing@example.com
PUBLISHER_EMAIL_DOMAIN=example.com
WORKER_ROLE=combined
EOF
```

Run locally:

```sh
npm install --ignore-scripts
npm run d1:migrate:local
npm run dev
```

Open the local admin UI:

```sh
open http://localhost:8787/admin
```

With `ADMIN_LOCAL_BYPASS_EMAIL` set on localhost, `/admin/login` mints a local admin session without calling Glean OAuth. Production never uses this bypass because it is accepted only for local development hosts.

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

Rotate `MCP_OAUTH_CLIENT_SECRET` when the credential configured in Glean is exposed:

```sh
export MCP_OAUTH_CLIENT_SECRET="$(openssl rand -base64 48)"
printf '%s' "$MCP_OAUTH_CLIENT_SECRET" | npx wrangler secret put MCP_OAUTH_CLIENT_SECRET --env mcp
```

Then update the client secret in the Glean MCP server configuration.

Rotate `MCP_OAUTH_TOKEN_SECRET` when the Worker-side token signing secret is exposed. This immediately invalidates outstanding MCP access tokens:

```sh
export MCP_OAUTH_TOKEN_SECRET="$(openssl rand -base64 48)"
printf '%s' "$MCP_OAUTH_TOKEN_SECRET" | npx wrangler secret put MCP_OAUTH_TOKEN_SECRET --env mcp
```

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

Use MCP whenever possible because Glean only needs the OAuth client credential, and the MCP Worker keeps the publish credentials internal.
