# Glean HTML Preview

Cloudflare Workers service for publishing generated or uploaded HTML as password-protected, sandboxed preview URLs from Glean and MCP-capable coding tools.

This repo turns AI-generated HTML artifacts into shareable pages without treating arbitrary HTML as trusted application UI. Uploaded HTML is stored privately in R2, tracked in D1, served from a preview-only Worker, and rendered behind a viewer password with a restrictive CSP sandbox.

## Worker Surfaces

| Surface | Worker | Purpose |
| --- | --- | --- |
| Preview | `html` | Viewer password gate and sandboxed HTML serving |
| API | `admin` | Publish routes and Glean-authenticated self-service admin UI |
| MCP | `html-mcp` | OAuth-backed MCP endpoint exposing `publish_html_preview` |

Keep those surfaces separate. The preview Worker renders hostile HTML. The API and MCP Workers make trusted publish, admin, OAuth, and ownership decisions.

For deployment, local development, verification, and fork guidance, see [SETUP.md](./SETUP.md). For contribution checks, see [CONTRIBUTING.md](./CONTRIBUTING.md). For failure modes discovered during real work on this repo, see [docs/KNOWN_GOTCHAS.md](./docs/KNOWN_GOTCHAS.md).

## Connect The MCP

Before connecting clients, deploy the MCP Worker and make sure `${MCP_BASE_URL}/mcp` is reachable. The deployed server should expose:

- OAuth authorization metadata at `${MCP_BASE_URL}/.well-known/oauth-authorization-server`
- OAuth protected-resource metadata at `${MCP_BASE_URL}/.well-known/oauth-protected-resource`
- the MCP endpoint at `${MCP_BASE_URL}/mcp`
- the `publish_html_preview` tool after MCP tool discovery

The default MCP scope is `mcp:tools`.

`publish_html_preview` accepts optional image attachments. Reference them from the HTML as `cid:name`, then send
matching `images[]` entries with `name`, `mimeType`, and `dataBase64`. The API Worker stores those bytes in private
R2 objects and rewrites the HTML to password-gated preview asset URLs.

`publish_html_preview` also accepts an optional `slug`. Omit it to get the existing random preview URL. If you send
one, it must be 3-80 lowercase letters, numbers, and single hyphens, with no leading or trailing hyphen. The Worker
uses that exact slug or rejects the publish with `409 slug_taken`; it never auto-suffixes, suggests alternatives, or
overwrites an existing preview. Soft-deleted and expired previews still reserve their slugs until hard delete removes
the D1 row.

Scripts are blocked by default. Set `allowScripts: true` only for interactive previews that need local JavaScript;
the Worker still serves them without `allow-same-origin`, network access, forms, frames, or workers.

### Glean

Create a purpose-built Glean MCP server for this tool instead of adding it to a broad default server.

In Glean Admin Console:

1. Open **Admin Console -> Platform -> Tools**.
2. Add or import a **Vendor provided tools (via MCP)** server.
3. Set the MCP server URL to `${MCP_BASE_URL}/mcp`.
4. Use **Streaming HTTP** transport.
5. Use **OAuth** authentication.
6. Use the confidential MCP client configured by `MCP_OAUTH_CLIENT_ID` and `MCP_OAUTH_CLIENT_SECRET`.
7. Set the authorization URL to `${MCP_BASE_URL}/oauth/authorize`.
8. Set the token URL to `${MCP_BASE_URL}/oauth/token`.
9. Set scopes to `mcp:tools`.
10. Copy the Glean callback URL shown in the UI into `MCP_OAUTH_ALLOWED_REDIRECT_URIS`.
11. Fetch tools and confirm Glean discovers **Publish Html Preview**.
12. Enable chat visibility only for the users or groups that should publish hosted HTML previews.

Glean should only receive the MCP OAuth client id and client secret. It should not know `PUBLISH_API_TOKEN`, `PUBLISH_INTERNAL_SERVICE_TOKEN`, `MCP_OAUTH_TOKEN_SECRET`, `COOKIE_SIGNING_SECRET`, or `PASSWORD_PEPPER`.

### Claude Code

Use a public OAuth client and a fixed local callback port so the Worker can allow-list the redirect URI.

Make sure `wrangler.local.toml` includes:

```toml
MCP_OAUTH_PUBLIC_CLIENT_IDS = "claude-code-html-sharing-mcp"
MCP_OAUTH_ALLOWED_REDIRECT_URIS = "http://localhost:5555/callback"
```

Add the server:

```sh
export MCP_BASE_URL="https://html-mcp.your-workers-subdomain.workers.dev"

claude mcp add --transport http \
  --client-id claude-code-html-sharing-mcp \
  --callback-port 5555 \
  html-sharing "$MCP_BASE_URL/mcp"
```

Then run `/mcp` in Claude Code and authenticate the `html-sharing` server.

### Codex

Use a public OAuth client and a fixed callback URL. Codex may append a server-specific path segment after `/callback`; this Worker allows loopback redirect URI prefixes, so allow-list the base callback path.

In `~/.codex/config.toml`:

```toml
mcp_oauth_callback_port = 5555
mcp_oauth_callback_url = "http://127.0.0.1:5555/callback"
```

Make sure `wrangler.local.toml` includes:

```toml
MCP_OAUTH_PUBLIC_CLIENT_IDS = "codex-html-sharing-mcp"
MCP_OAUTH_ALLOWED_REDIRECT_URIS = "http://127.0.0.1:5555/callback"
```

Add and log in:

```sh
export MCP_BASE_URL="https://html-mcp.your-workers-subdomain.workers.dev"

codex mcp add html_sharing \
  --url "$MCP_BASE_URL/mcp" \
  --oauth-client-id codex-html-sharing-mcp \
  --oauth-resource "$MCP_BASE_URL/mcp"

codex mcp login html_sharing --scopes mcp:tools
```

### Cursor

Cursor uses a fixed OAuth redirect URI:

```text
cursor://anysphere.cursor-mcp/oauth/callback
```

Make sure that value is in `MCP_OAUTH_ALLOWED_REDIRECT_URIS`, and make sure `cursor-html-sharing-mcp` is listed in `MCP_OAUTH_PUBLIC_CLIENT_IDS`.

Add a remote server to `.cursor/mcp.json` or `~/.cursor/mcp.json`:

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

Then open Cursor settings for MCP, authenticate the server, and confirm `publish_html_preview` appears under available tools.
