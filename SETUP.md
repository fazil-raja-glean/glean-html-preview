# Setup

This is the operational guide for deploying, running, and forking `html-sharing`.

The core idea: keep the Worker implementation host-agnostic, keep deployment-specific values out of git, and preserve the security split between preview, API, and MCP surfaces.

## Mental Model

There are three production Workers:

| Worker | Role | Has R2? | Has D1? | Main job |
| --- | --- | --- | --- | --- |
| `html` | `preview` | yes | yes | Serves password-gated preview pages and sandboxed HTML |
| `admin` | `api` | yes | yes | Publishes, manages, and deletes previews |
| `html-mcp` | `mcp` | no | yes | Authenticates MCP clients and calls `admin` through a service binding |

Do not collapse these roles for production. `WORKER_ROLE=combined` exists for local development only.

## Files To Know

- `src/index.ts` - Worker entrypoint and route dispatch.
- `src/routes.ts` - route surface mapping for preview, API, admin, and MCP paths.
- `src/mcp.ts` - MCP JSON-RPC handler and `publish_html_preview` tool.
- `src/oauth.ts` - MCP OAuth metadata, authorization, token, and bearer validation.
- `src/oauth-config.ts` - MCP OAuth clients, scopes, redirect allow-listing, and token TTLs.
- `src/auth/glean-oauth.ts` - Glean OAuth identity flow for admin and MCP user login.
- `src/admin-api.ts` - self-service preview routes (serves the admin shell/assets, JSON APIs, in-UI publish).
- `src/admin-ui.ts` - admin security headers (`ADMIN_SECURITY_HEADERS`).
- `src/ui/admin.html`, `src/ui/admin.css`, `src/ui/admin.js` - editable source for the client-rendered admin console.
- `src/admin-assets.ts` - generated from `src/ui/*` by `npm run build:admin`; do not edit by hand.
- `src/security.ts` - password hashing and preview security helpers.
- `schema.sql` - D1 schema.
- `wrangler.toml` - committed public template.
- `wrangler.local.toml` - ignored deployment config with real resource IDs and origins.
- `.dev.vars` - ignored local secret file.

## Security Invariants

- Treat uploaded HTML as hostile content.
- Do not put publish/admin routes on the preview Worker.
- Do not put preview routes on the API or MCP Workers.
- Do not give the MCP Worker direct R2 access.
- Do not expose secrets or storage bindings to browser JavaScript.
- Keep `previewHtmlSecurityHeaders()` restrictive.
- Serve admin HTML downloads as `text/plain`; do not render uploaded HTML in admin UI.
- Keep Glean OAuth scopes identity-only by default, usually `openid email`.
- Keep `wrangler.toml` free of real Cloudflare IDs, real hostnames, real emails, and secrets.

## Prerequisites

- Node.js and npm.
- Cloudflare account with Workers, R2, D1, and Worker Rate Limiting available.
- Wrangler login: `npx wrangler whoami || npx wrangler login`.
- A Glean OAuth client for admin and MCP user identity.
- For internal Glean usage, permission to create or update a Glean MCP server in Admin Console.

Install dependencies:

```sh
npm install --ignore-scripts
```

For a coding-agent-friendly local bootstrap, run:

```sh
npm run setup:agent
```

That command installs dependencies if needed, creates `wrangler.local.toml` from `wrangler.local.example.toml` when missing, and creates `.dev.vars` with generated local-only secrets when missing. It never overwrites existing local files.

## 1. Initialize Local Config

```sh
npm run config:init:local
```

Edit `wrangler.local.toml`. Replace every placeholder with real deployment values.

Use:

- `wrangler.toml` as the public template.
- `wrangler.local.toml` for real Cloudflare resource IDs, real Worker URLs, and non-secret deployment config.
- `.dev.vars` or Wrangler secrets for true secrets.

## 2. Choose Origins

Use separate origins:

```toml
PUBLIC_BASE_URL = "https://html.your-workers-subdomain.workers.dev"
API_BASE_URL = "https://admin.your-workers-subdomain.workers.dev"
MCP_BASE_URL = "https://html-mcp.your-workers-subdomain.workers.dev"
```

`PUBLIC_BASE_URL` must always be the preview origin returned to viewers.

## 3. Create Cloudflare Storage

Create production resources:

```sh
npx wrangler r2 bucket create html-sharing-previews-prod
npx wrangler d1 create html-sharing-metadata-prod
```

Create dev resources if you want isolated local/preview state:

```sh
npx wrangler r2 bucket create html-sharing-previews-dev
npx wrangler d1 create html-sharing-metadata-dev
```

Put the returned D1 IDs into every `PREVIEW_DB` binding in `wrangler.local.toml`:

- top-level `[[d1_databases]].database_id`
- top-level `[[d1_databases]].preview_database_id`
- `[[env.api.d1_databases]].database_id`
- `[[env.api.d1_databases]].preview_database_id`
- `[[env.mcp.d1_databases]].database_id`
- `[[env.mcp.d1_databases]].preview_database_id`

The MCP Worker uses D1 for OAuth grant and refresh-token state, but it should not get R2.

## 4. Create Rate Limit Namespaces

Create three Cloudflare Worker Rate Limiting namespaces and put their IDs into `wrangler.local.toml`.

| Binding | Route | Current limit |
| --- | --- | --- |
| `EDGE_ACCESS_RATE_LIMITER` | `POST /p/:slug/access` | 30/min |
| `EDGE_PUBLISH_RATE_LIMITER` | `POST /v1/html-previews` | 20/min |
| `EDGE_MCP_RATE_LIMITER` | `POST /mcp` | 30/min |

These edge limits sit in front of app-level D1 throttling.

## 5. Configure Glean OAuth

Create a Glean OAuth client and allow-list:

- `${API_BASE_URL}/auth/callback`
- `${MCP_BASE_URL}/oauth/callback`

Configure both `env.api.vars` and `env.mcp.vars`:

```toml
GLEAN_OAUTH_CLIENT_ID = "html-sharing-admin"
GLEAN_OAUTH_ISSUER = "https://<glean-domain>/oauth"
GLEAN_OAUTH_AUTHORIZATION_URL = "https://<glean-domain>/oauth/authorize"
GLEAN_OAUTH_TOKEN_URL = "https://<glean-domain>/oauth/token"
GLEAN_OAUTH_USERINFO_URL = ""
GLEAN_OAUTH_JWKS_URL = "https://<glean-domain>/api/oauth/jwks"
GLEAN_OAUTH_SCOPES = "openid email"
```

If Glean provides OAuth discovery metadata, you can set `GLEAN_OAUTH_DISCOVERY_URL` instead of explicit endpoint and JWKS URLs.

Configure authorization:

```toml
ADMIN_ALLOWED_EMAIL_DOMAIN = "example.com"
ADMIN_SESSION_TTL_SECONDS = "28800"
MCP_OAUTH_ALLOWED_EMAIL_DOMAIN = "example.com"
MCP_OAUTH_REQUIRE_USER_AUTH = "true"
```

The console is domain-gated, not person-gated: any verified Glean user in `ADMIN_ALLOWED_EMAIL_DOMAIN` can sign in at the API origin root and self-serve. There is no per-person allowlist. Set `ADMIN_ALLOWED_EMAIL_DOMAIN` to the same domain as `MCP_OAUTH_ALLOWED_EMAIL_DOMAIN` so anyone who can use the MCP can also use the console. Management remains owner-scoped by `publisher_email`.

## 6. Configure MCP OAuth Clients

Use one confidential client for Glean and public PKCE clients for coding tools:

```toml
MCP_OAUTH_CLIENT_ID = "glean-html-sharing-mcp"
MCP_OAUTH_PUBLIC_CLIENT_IDS = "codex-html-sharing-mcp,claude-code-html-sharing-mcp,cursor-html-sharing-mcp"
MCP_OAUTH_ALLOWED_REDIRECT_URIS = "https://your-glean-backend.example.com/tools/oauth/verify_code,http://127.0.0.1:5555/callback,http://localhost:5555/callback,cursor://anysphere.cursor-mcp/oauth/callback"
MCP_OAUTH_SCOPES = "mcp:tools"
MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS = "3600"
MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS = "2592000"
```

Notes:

- Glean uses the confidential client with `MCP_OAUTH_CLIENT_SECRET`.
- Codex and Claude Code use public clients with S256 PKCE.
- Cursor uses the fixed redirect URI `cursor://anysphere.cursor-mcp/oauth/callback`.
- Loopback redirect allow-list entries are prefix-matched by path, so `http://127.0.0.1:5555/callback` also permits Codex callback paths under `/callback/...`.

## 7. Configure Legacy Direct API Access

MCP is preferred. If backend scripts or a legacy Glean custom Action must call `/v1/html-previews*` directly, configure Cloudflare Access verification:

```toml
PUBLISH_ACCESS_TEAM_DOMAIN = "https://<team>.cloudflareaccess.com"
PUBLISH_ACCESS_AUD = "<access-application-aud-tag>"
```

Do not protect `${PUBLIC_BASE_URL}` with Cloudflare Access. Viewer previews keep their own password flow.

## 8. Generate And Upload Secrets

Generate secrets locally:

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

Upload them:

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

Only rotate `PASSWORD_PEPPER` when invalidating existing preview passwords is acceptable.

## 9. Apply Schema

```sh
npm run d1:migrate:prod
```

The schema is idempotent.

## 10. Dry Run And Deploy

Validate the committed public template:

```sh
npm run deploy:dry-run
```

Validate your ignored deployment config:

```sh
npm run deploy:dry-run:local
```

Expected binding shape:

- Preview Worker lists `HTML_PREVIEWS`, `PREVIEW_DB`, and `EDGE_ACCESS_RATE_LIMITER`.
- API Worker lists `HTML_PREVIEWS`, `PREVIEW_DB`, and `EDGE_PUBLISH_RATE_LIMITER`.
- MCP Worker lists `PUBLISH_API`, `PREVIEW_DB`, and `EDGE_MCP_RATE_LIMITER`.
- MCP Worker does not list `HTML_PREVIEWS`.

Deploy:

```sh
npm run deploy
```

## 11. Smoke Test MCP

Set values:

```sh
export MCP_BASE_URL="https://html-mcp.your-workers-subdomain.workers.dev"
export MCP_OAUTH_CLIENT_ID="glean-html-sharing-mcp"
export MCP_OAUTH_CLIENT_SECRET="<client-secret-configured-in-glean>"
export MCP_OAUTH_SCOPES="mcp:tools"
```

Unauthenticated MCP requests should be challenged:

```sh
curl -i "$MCP_BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
```

Wrong credentials should fail:

```sh
curl -i "$MCP_BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'grant_type=client_credentials&client_id=wrong&client_secret=wrong'
```

Get a machine token for handshake and discovery:

```sh
ACCESS_TOKEN="$(
  curl -sS "$MCP_BASE_URL/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode "client_id=$MCP_OAUTH_CLIENT_ID" \
    --data-urlencode "client_secret=$MCP_OAUTH_CLIENT_SECRET" \
    --data-urlencode "scope=$MCP_OAUTH_SCOPES" \
    | node -e 'let data=""; process.stdin.on("data", c => data += c); process.stdin.on("end", () => console.log(JSON.parse(data).access_token));'
)"
```

Discover tools:

```sh
curl -sS "$MCP_BASE_URL/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl-smoke","version":"1.0.0"}}}'

curl -sS "$MCP_BASE_URL/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Expected:

- `initialize` returns `serverInfo.name = "html-sharing"`.
- `tools/list` returns `publish_html_preview`.

Publishing requires a user-bound authorization-code token. `client_credentials` tokens can initialize and list tools, but publish calls should fail because they are not tied to a verified user email.

## 12. Configure Glean Internally

In Glean Admin Console, create a purpose-built MCP server for this tool:

1. Open **Admin Console -> Platform -> Tools**.
2. Select **Vendor Provided Tools (via MCP)**.
3. Import tools from `${MCP_BASE_URL}/mcp`.
4. Use **Streaming HTTP** transport.
5. Use **OAuth** authentication.
6. Use **Client Secret (POST)** token endpoint auth.
7. Set client id to `MCP_OAUTH_CLIENT_ID`.
8. Set client secret to `MCP_OAUTH_CLIENT_SECRET`.
9. Set authorization URL to `${MCP_BASE_URL}/oauth/authorize`.
10. Set token URL to `${MCP_BASE_URL}/oauth/token`.
11. Set scopes to `mcp:tools`.
12. Copy the callback URL from Glean into `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.
13. Fetch tools and confirm **Publish Html Preview** appears.
14. Enable only the users or groups that should be able to publish hosted HTML.

Do not add this tool to a large default MCP server unless that is an explicit product choice. A purpose-built server keeps tool descriptions and access easier to reason about.

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
MCP_OAUTH_PUBLIC_CLIENT_IDS=codex-html-sharing-mcp,claude-code-html-sharing-mcp,cursor-html-sharing-mcp
MCP_OAUTH_ALLOWED_REDIRECT_URIS=http://localhost:8787/oauth/local-callback,http://127.0.0.1:5555/callback,http://localhost:5555/callback,cursor://anysphere.cursor-mcp/oauth/callback
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
GLEAN_OAUTH_SCOPES=openid email
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
open http://localhost:8787/
```

The admin console is a client-rendered app served at the API origin root: `/` serves a static shell that loads
`/app.js` + `/app.css` and calls the `/api/*` JSON endpoints. The page lets you
publish HTML (file, drag-and-drop, or paste), and after a publish or password reset it shows a
copyable `link:`/`password:` block (passwords are hashed, so this is only available at set time).
Editing the UI means editing `src/ui/admin.{html,css,js}` and re-running `npm run build:admin`
(`check`, `test`, `dev`, and `deploy` run it automatically via pre-hooks).

HTML can reference attached images with `cid:name` URLs. API and MCP callers pass those images in an `images`
array with `name`, `mimeType`, and `dataBase64`; the API Worker stores them under the same R2 preview prefix
and rewrites the HTML to `/p/{slug}/assets/{assetId}`. Asset routes require the same viewer password cookie as
the HTML page, so image bytes remain private R2 objects rather than public bucket URLs. The default limits are
`MAX_HTML_BYTES=10000000`, `MAX_IMAGES_PER_PREVIEW=25`, `MAX_IMAGE_BYTES=5000000`, and
`MAX_TOTAL_IMAGE_BYTES=25000000`.

Scripts are blocked by default. Set `allowScripts: true` only when a preview needs local interactivity. Interactive
previews use `sandbox allow-scripts` without `allow-same-origin`, and still keep `connect-src 'none'`,
`form-action 'none'`, `frame-src 'none'`, `worker-src 'none'`, and `navigate-to 'none'`.

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

Publish with an attached image:

```sh
curl -i http://localhost:8787/v1/html-previews \
  -H "Authorization: Bearer $LOCAL_PUBLISH_API_TOKEN" \
  -H "X-Publish-Admin-Secret: $LOCAL_ADMIN_BYPASS_SECRET" \
  -H "Content-Type: application/json" \
  --data '{
    "title": "Local image smoke test",
    "html": "<!doctype html><html><body><img alt=\"proof\" src=\"cid:proof.png\"></body></html>",
    "images": [
      {
        "name": "proof.png",
        "mimeType": "image/png",
        "dataBase64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
      }
    ],
    "password": "correct horse battery"
  }'
```

Publish an interactive preview:

```sh
curl -i http://localhost:8787/v1/html-previews \
  -H "Authorization: Bearer $LOCAL_PUBLISH_API_TOKEN" \
  -H "X-Publish-Admin-Secret: $LOCAL_ADMIN_BYPASS_SECRET" \
  -H "Content-Type: application/json" \
  --data '{
    "title": "Local interactive smoke test",
    "html": "<!doctype html><html><body><button id=\"b\">0</button><script>b.onclick=()=>b.textContent=String(Number(b.textContent)+1)</script></body></html>",
    "allowScripts": true,
    "password": "correct horse battery"
  }'
```

## Forking Guidance

For a new organization or fork:

1. Replace every hostname and resource ID in `wrangler.local.toml`.
2. Create fresh R2, D1, rate-limit namespaces, and secrets.
3. Choose the OAuth identity source for admin and MCP user login.
4. If you are not using Glean OAuth, adapt `src/auth/glean-oauth.ts` to your provider while preserving verified email, issuer, audience, expiry, and JWKS checks.
5. Keep MCP OAuth client setup explicit: one confidential client for hosted admin systems, public PKCE clients for local coding tools.
6. Re-run `npm run check`, `npm run deploy:dry-run`, and `npm run deploy:dry-run:local`.
7. Smoke test publish and preview flows before sharing the service.

The most important portability boundary is this: client-specific setup belongs in config and docs; core publishing and preview isolation should stay host-agnostic.

## Verification Gates

Before merging changes:

```sh
npm run verify:config
npm run check
npm run deploy:dry-run
```

Before deploying a real environment:

```sh
npm run verify:config
npm run deploy:dry-run:local
npm run d1:migrate:prod
npm run deploy
```

After deploying:

- Verify `${MCP_BASE_URL}/mcp` returns an OAuth challenge without a token.
- Verify `tools/list` returns `publish_html_preview`.
- Publish one preview with a user-bound token.
- Open the returned preview URL.
- Confirm the viewer password gate works.
- Confirm uploaded HTML is sandboxed and cannot reach admin/API surfaces.

You can automate the deployed MCP checks:

```sh
MCP_BASE_URL="https://html-mcp.your-workers-subdomain.workers.dev" npm run smoke:mcp -- --metadata-only
```

Set `MCP_OAUTH_CLIENT_ID` and `MCP_OAUTH_CLIENT_SECRET` to also verify `initialize` and `tools/list` with a machine token.

## Secret Rotation

Rotate `MCP_OAUTH_CLIENT_SECRET` if the credential configured in Glean is exposed:

```sh
export MCP_OAUTH_CLIENT_SECRET="$(openssl rand -base64 48)"
printf '%s' "$MCP_OAUTH_CLIENT_SECRET" | npx wrangler secret put MCP_OAUTH_CLIENT_SECRET --env mcp
```

Then update the Glean MCP server configuration.

Rotate `MCP_OAUTH_TOKEN_SECRET` if the Worker-side token signing secret is exposed. This invalidates outstanding MCP access tokens:

```sh
export MCP_OAUTH_TOKEN_SECRET="$(openssl rand -base64 48)"
printf '%s' "$MCP_OAUTH_TOKEN_SECRET" | npx wrangler secret put MCP_OAUTH_TOKEN_SECRET --env mcp
```

Rotate Worker-to-Worker credentials if exposed:

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

## Troubleshooting

- The console (API origin root `/`) shows a Cloudflare 403 before Worker code runs: check whether a Cloudflare Access application is still protecting the API host.
- MCP Worker dry-run does not list R2: expected. It should not have direct R2 access.
- Publish through MCP fails with a machine token: expected. `publish_html_preview` needs a user-bound token with a verified email.
- Preview URL points at the API host: check `PUBLIC_BASE_URL`; preview links must use the preview origin.
- Glean cannot discover tools: verify `${MCP_BASE_URL}/mcp`, OAuth metadata endpoints, callback allow-listing, and `MCP_OAUTH_CLIENT_SECRET`.
- Codex or Claude login fails after callback: verify loopback host, port, and base callback path are present in `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.
