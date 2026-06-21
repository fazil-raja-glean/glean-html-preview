# Contributing

Keep changes small, verified, and respectful of the preview/API/MCP security split.

## First-Time Setup

```sh
npm run setup:agent
```

Then edit `wrangler.local.toml` and replace placeholders with real deployment values.

## Verification

Before merging code or config changes:

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

For a deployed MCP endpoint:

```sh
MCP_BASE_URL="https://html-mcp.your-workers-subdomain.workers.dev" npm run smoke:mcp -- --metadata-only
```

Set `MCP_OAUTH_CLIENT_ID` and `MCP_OAUTH_CLIENT_SECRET` to include authenticated MCP initialize and tool discovery checks.

## Rules

- Do not commit `.dev.vars`, `.env`, `.wrangler/`, `node_modules/`, or `wrangler.local.toml`.
- Do not put publish/admin routes on the preview Worker.
- Do not put preview routes on the API or MCP Workers.
- Do not give the MCP Worker direct R2 access.
- Do not weaken the uploaded HTML sandbox.
- Keep Glean OAuth scopes identity-only by default.
- Update `SETUP.md` and `docs/KNOWN_GOTCHAS.md` when a new operational trap is discovered.
