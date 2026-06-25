# Known Gotchas

These are the traps previous work on this repo actually hit.

## Setup And Dependencies

- Run commands from the repo root. Scripts expect `package.json`, `wrangler.toml`, and `schema.sql` in the current directory.
- If `npm run check` fails with `tsc: command not found`, run `npm install --ignore-scripts`.
- Use `npm run setup:agent` for a first local pass. It creates ignored local files without overwriting existing ones.
- The admin console lives in `src/ui/admin.{html,css,js}` and is compiled into the committed `src/admin-assets.ts` by `npm run build:admin`. Edit the `src/ui/*` files, not the generated `.ts`. `check`/`test`/`dev`/`deploy` run the codegen via pre-hooks; a raw `wrangler deploy` does not, so run `npm run build:admin` first or it ships stale UI.

## Cloudflare

- The account-wide `workers.dev` subdomain must exist before deployed preview URLs work.
- Use explicit deploy targets. The repo has a top-level preview Worker plus `env.api` and `env.mcp`; do not rely on an implicit Wrangler environment.
- `env.mcp` should not list R2 bindings. That is intentional least privilege if `PUBLISH_API`, `PREVIEW_DB`, and `EDGE_MCP_RATE_LIMITER` are present.
- If the console (API origin root `/`) returns a Cloudflare 403 before Worker code runs, check whether a Cloudflare Access application is still protecting the API host.
- Remote storage verification should use `--remote`; otherwise Wrangler may inspect local D1/R2 state.

## Security

- Uploaded HTML is hostile content. Do not weaken `HTML_SECURITY_HEADERS`.
- `PUBLIC_BASE_URL` is the preview origin, even when publish requests hit the API Worker.
- Trusted publisher and audit attribution should come from server-side config, not caller-provided JSON.
- Glean OAuth scopes should stay identity-only (`openid email`) unless the Worker itself starts calling broader Glean APIs. The admin flow hardcodes those identity scopes for the authorization request; do not add `GLEAN_OAUTH_SCOPES` back to `env.api.vars`.
- Admin and MCP OAuth are intentionally different: admin uses Glean Dynamic Client Registration, while MCP keeps explicit configured OAuth clients. Do not reintroduce `GLEAN_OAUTH_CLIENT_ID` in `env.api.vars`.
- Glean DCR can return a broader tenant-level scope set in registration metadata even when the Worker asks for `openid email`. Do not treat that metadata as the admin session permission envelope; the authorization request and consumed identity fields remain the boundary.
- `PASSWORD_PEPPER` rotation invalidates existing preview passwords.
- Custom slugs are D1 row identity. Soft-deleted and expired previews still reserve their slugs; only hard delete frees
  the slug. New R2 object keys should stay under `previews/objects/{random-id}/...`, not under the public slug.

## MCP And OAuth

- Read live OAuth metadata or deploy output before configuring clients. Do not guess the MCP host URL from placeholders.
- `client_credentials` tokens are only for setup, initialize, and tool discovery. Publishing requires a user-bound authorization-code token with a verified email.
- Codex may append a path segment under the configured callback path. Allow-list the base loopback callback URL.
- Glean MCP gateway exposure is separate from this repo defining `publish_html_preview`. Check live tool exposure before saying the tool is available through Glean.
- If an OAuth verifier script fails because of `require` plus top-level `await`, rerun it as an ES module.

## Runtime Limits

- This Cloudflare Workers environment rejected PBKDF2 iteration counts above `100000`. Keep password hashing within supported runtime limits.
- If edge rate-limit bindings are absent or error, the helper currently fails open so app-level D1 throttling still protects the app.
