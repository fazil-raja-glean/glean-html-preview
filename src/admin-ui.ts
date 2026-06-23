// Security headers for the admin surface (served by the admin worker).
// The admin console itself is a client-rendered static app: see src/ui/admin.html,
// src/ui/admin.css, src/ui/admin.js (compiled into src/admin-assets.ts).
//
// `script-src 'self'` permits the same-origin /app.js but no inline scripts.
// This is a separate origin from the hostile-HTML preview worker, so admin JS never
// touches the preview sandbox CSP in src/preview-renderer.ts.
export const ADMIN_SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
