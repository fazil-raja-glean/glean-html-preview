// Canonical OAuth callback (redirect URI) paths, shared by the route table (routes.ts)
// and the OAuth flow definitions (auth/glean-oauth.ts). Each must match the redirect URI
// registered with its OAuth provider. Keeping one literal per flow avoids silent drift
// between the router and the redirect_uri sent during login (a mismatch fails only at runtime).
export const ADMIN_OAUTH_CALLBACK_PATH = "/auth/callback";
export const MCP_OAUTH_CALLBACK_PATH = "/oauth/callback";
