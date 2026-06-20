# Glean legacy action notes

- Prefer the OAuth-backed MCP server at `${MCP_BASE_URL}/mcp` for Glean, Codex, Claude Code, and Cursor.
- Use the API endpoint in `action/openapi.yaml` only for legacy direct custom Actions or backend scripts.
- The action server is `${API_BASE_URL}`; never call publish/admin routes on the preview
  origin.
- Configure authentication with all headers declared in `action/openapi.yaml`:
  - `Authorization: Bearer <PUBLISH_API_TOKEN>`
  - `CF-Access-Client-Id: <access-service-token-client-id>`
  - `CF-Access-Client-Secret: <access-service-token-client-secret>`
- Configure Cloudflare Access only for legacy `/v1/html-previews*` direct API calls; do not put `/p/:slug`, `/admin`, or `/mcp` behind Access for the preferred setup.
- Publisher identity is configured server-side as `TRUSTED_PUBLISHER_EMAIL`; the action must not pass a user-supplied publisher email.
- Require a password before calling the action. Generated passwords should be at least 12 characters.
- Return the preview URL from the publish response. It will be on `${PUBLIC_BASE_URL}`; tell the user
  to share the password separately.
- Uploaded HTML is served with a restrictive CSP sandbox: scripts, forms, frames, workers, objects, and remote network beacons are blocked.
- Do not send secrets, API keys, customer credentials, or internal-only asset URLs inside the HTML.
