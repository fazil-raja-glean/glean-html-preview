import type { AdminSessionPayload } from "./auth/session";
import type { AdminPreview } from "./admin-preview";

export interface AdminPageInput {
  previewBaseUrl: string;
  previews: AdminPreview[];
  session: AdminSessionPayload;
}

export const ADMIN_SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

export function adminHtmlResponse(input: AdminPageInput): Response {
  return new Response(renderAdminPage(input), {
    headers: {
      ...ADMIN_SECURITY_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}

export function renderAdminPage({ previewBaseUrl, previews, session }: AdminPageInput): string {
  const rows = previews.map((preview) => previewRow(previewBaseUrl, preview, session.csrf)).join("");
  const empty = previews.length === 0 ? `<tr><td colspan="7" class="empty">No previews</td></tr>` : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HTML Sharing Admin</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f6f7f5;
        --ink: #202124;
        --muted: #626861;
        --line: #dfe3dc;
        --panel: #ffffff;
        --accent: #146c5c;
        --warn: #9b2f21;
      }
      * { box-sizing: border-box; }
      body {
        background: var(--bg);
        color: var(--ink);
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        margin: 0;
      }
      header {
        align-items: center;
        background: var(--panel);
        border-bottom: 1px solid var(--line);
        display: flex;
        gap: 16px;
        justify-content: space-between;
        padding: 14px 20px;
      }
      h1 { font-size: 20px; margin: 0; }
      main { margin: 0 auto; max-width: 1220px; padding: 20px; }
      .user { color: var(--muted); font-size: 13px; }
      table {
        background: var(--panel);
        border: 1px solid var(--line);
        border-collapse: collapse;
        width: 100%;
      }
      th, td {
        border-bottom: 1px solid var(--line);
        font-size: 13px;
        padding: 10px;
        text-align: left;
        vertical-align: top;
      }
      th {
        background: #eef2ec;
        color: #30352f;
        font-weight: 700;
      }
      a { color: var(--accent); font-weight: 650; text-decoration: none; }
      input {
        border: 1px solid #cbd2c8;
        border-radius: 6px;
        font: inherit;
        max-width: 220px;
        padding: 7px 8px;
      }
      button {
        background: var(--accent);
        border: 0;
        border-radius: 6px;
        color: #fff;
        cursor: pointer;
        font: inherit;
        font-weight: 700;
        padding: 7px 10px;
      }
      .danger { background: var(--warn); }
      .muted { color: var(--muted); }
      .actions {
        display: grid;
        gap: 8px;
        grid-template-columns: minmax(180px, 1fr);
      }
      .inline {
        align-items: center;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .empty { color: var(--muted); padding: 24px; text-align: center; }
      @media (max-width: 820px) {
        main { padding: 12px; }
        table, thead, tbody, tr, th, td { display: block; }
        thead { display: none; }
        tr { border-bottom: 1px solid var(--line); padding: 10px; }
        td { border: 0; padding: 6px 0; }
        td::before { color: var(--muted); content: attr(data-label); display: block; font-size: 12px; font-weight: 700; }
      }
    </style>
  </head>
  <body>
    <header>
      <h1>HTML Sharing Admin</h1>
      <form method="post" action="/admin/logout" class="inline">
        <span class="user">${escapeHtml(session.email)}</span>
        <input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}">
        <button type="submit">Log out</button>
      </form>
    </header>
    <main>
      <table>
        <thead>
          <tr>
            <th>Preview</th>
            <th>Slug</th>
            <th>Publisher</th>
            <th>Created</th>
            <th>Expires</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows}${empty}</tbody>
      </table>
    </main>
  </body>
</html>`;
}

function previewRow(previewBaseUrl: string, preview: AdminPreview, csrf: string): string {
  const status = preview.deletedAt ? "Unpublished" : Date.parse(preview.expiresAt) <= Date.now() ? "Expired" : "Active";
  const previewUrl = new URL(`/p/${preview.slug}`, previewBaseUrl).toString();
  return `<tr>
    <td data-label="Preview"><a href="${escapeHtml(previewUrl)}">${escapeHtml(preview.title)}</a></td>
    <td data-label="Slug"><code>${escapeHtml(preview.slug)}</code></td>
    <td data-label="Publisher">${escapeHtml(preview.publisherEmail)}</td>
    <td data-label="Created">${formatDate(preview.createdAt)}</td>
    <td data-label="Expires">${formatDate(preview.expiresAt)}</td>
    <td data-label="Status">${status}</td>
    <td data-label="Actions">
      <div class="actions">
        <form method="post" action="/admin/api/previews/${encodeURIComponent(preview.slug)}/password" class="inline">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <input name="password" type="password" minlength="12" maxlength="256" autocomplete="new-password" required>
          <button type="submit">Reset</button>
        </form>
        <form method="post" action="/admin/api/previews/${encodeURIComponent(preview.slug)}/unpublish" class="inline">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <button type="submit">Unpublish</button>
        </form>
        <form method="post" action="/admin/api/previews/${encodeURIComponent(preview.slug)}/delete" class="inline">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <input name="confirmSlug" value="" placeholder="${escapeHtml(preview.slug)}" required>
          <button type="submit" class="danger">Delete</button>
        </form>
        <a href="/admin/api/previews/${encodeURIComponent(preview.slug)}/html">HTML</a>
      </div>
    </td>
  </tr>`;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDate(value: string): string {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString().replace(".000Z", "Z") : escapeHtml(value);
}
