# Glean action notes

- Use the API endpoint in `action/openapi.yaml` as the first Glean custom action.
- The action server is `https://html-api.glean-share.workers.dev`; never call publish/admin routes on the preview
  origin.
- Configure authentication with all headers declared in `action/openapi.yaml`:
  - `Authorization: Bearer <PUBLISH_API_TOKEN>`
  - `CF-Access-Client-Id: <access-service-token-client-id>`
  - `CF-Access-Client-Secret: <access-service-token-client-secret>`
- Configure Cloudflare Access only for `/v1/html-previews*`; do not put `/p/:slug` behind Access.
- Publisher identity is configured server-side as `TRUSTED_PUBLISHER_EMAIL`; the action must not pass a user-supplied publisher email.
- Require a password before calling the action. Generated passwords should be at least 12 characters.
- Return the preview URL from the publish response. It will be on `https://html.glean-share.workers.dev`; tell the user
  to share the password separately.
- Uploaded HTML is served with a restrictive CSP sandbox: scripts, forms, frames, workers, objects, and remote network beacons are blocked.
- Do not send secrets, API keys, customer credentials, or internal-only asset URLs inside the HTML.
