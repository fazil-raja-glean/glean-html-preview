# Project Context

`html-sharing` is a Cloudflare Workers service for publishing generated or uploaded HTML as shareable, password-protected preview pages for Glean workflows.

The project exists because Glean's AI workflows increasingly produce rich HTML artifacts: dashboards, slides, client-ready pages, workshop outputs, and interactive internal deliverables. Those artifacts are most useful when they behave like standalone shareable pages, but arbitrary HTML cannot be treated like trusted application UI. This repo was built to close that gap: make HTML easy to publish and share while keeping the uploaded page isolated from Glean, admin tools, secrets, and internal APIs.

The original goal was deliberately small: provide a short, reliable path from a Glean action or agent to a preview URL. The Worker owns the hard parts: accepting publish requests, storing HTML privately in R2, tracking metadata in D1, generating preview links, requiring a viewer password, and serving the page with a restrictive sandbox. The Glean-side integration can stay thin because the security and lifecycle behavior live here.

The project later grew into a three-surface deployment:

- `html` is the preview surface. It serves viewer password gates and sandboxed HTML.
- `admin` is the publish and admin surface. It handles publish routes and the Glean-authenticated self-service admin UI.
- `html-mcp` is the MCP surface. It exposes HTML deployment and management tools through OAuth-backed MCP flows and calls the API Worker through a service binding.

That split matters. The preview origin is where hostile HTML is rendered. The API and MCP origins are where trusted publish, admin, OAuth, and ownership decisions happen. Keeping those surfaces separate is part of the product, not incidental deployment detail.

The company context behind this repo is broader than one tool. Internal conversations around HTML artifacts point to a real user need: generated HTML should be easy to share, inspect, and consume as the destination itself, not only as a file buried inside a broader workspace. Internal MCP conversations also exposed a practical integration need: a "publish html preview" tool should be usable from Glean Chat and other MCP hosts, but exposing an external MCP tool through Glean's shared gateway is a different path from merely registering that external server for configuration. This repo became the concrete, purpose-built service behind that capability.

The security posture is the heart of the project:

- Uploaded HTML is hostile content.
- Preview links should never weaken the password flow, CSP sandbox, origin separation, rate limits, or R2 privacy.
- Browser JavaScript must never receive publish tokens, OAuth secrets, cookie-signing secrets, password peppers, R2 bindings, D1 bindings, or admin-only data.
- Glean OAuth is used for identity and ownership, not broad Glean API access by default.
- Admin views are owner-scoped: a signed-in user manages their own previews.
- The MCP Worker should remain least-privilege and reach publishing through the API service binding instead of direct R2 access.

The intended end state is a small, forkable, reusable service that lets Glean, Codex, Claude Code, Cursor, or another MCP-capable host publish HTML safely. Glean-specific setup belongs at the integration edge, while the core Worker should stay host-agnostic enough for another deployment to bring its own OAuth client, domains, storage, and policy choices.

Use `README.md` for the short overview and MCP connection snippets. Use `SETUP.md` for operational setup and current commands. Use `CONTRIBUTING.md` for verification gates and `docs/KNOWN_GOTCHAS.md` for prior failure modes. Use this file for the project story: this repo matters because it turns AI-generated HTML into shareable artifacts without pretending that arbitrary HTML is safe.
