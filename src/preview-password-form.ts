import { randomBase64Url } from "./encoding";
import type { PreviewRow } from "./preview-store";

export function passwordForm(
  preview: PreviewRow,
  error: string | null,
  status: number,
  extraHeaders: Record<string, string> = {},
): Response {
  const nonce = randomBase64Url(12);
  const errorMarkup = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(preview.title)}</title>
    <style nonce="${nonce}">
      :root { color-scheme: light dark; }
      body {
        align-items: center;
        background: #f7f7f6;
        color: #1b1b1b;
        display: flex;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        justify-content: center;
        min-height: 100vh;
        margin: 0;
        padding: 24px;
      }
      main {
        background: #fff;
        border: 1px solid #e5e5e2;
        border-radius: 8px;
        box-shadow: 0 12px 34px rgba(0, 0, 0, 0.08);
        max-width: 420px;
        padding: 24px;
        width: 100%;
      }
      h1 { font-size: 20px; line-height: 1.2; margin: 0 0 8px; }
      p { color: #686867; font-size: 14px; margin: 0 0 18px; }
      label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; }
      input {
        border: 1px solid #cfcfcc;
        border-radius: 6px;
        box-sizing: border-box;
        font: inherit;
        margin-bottom: 14px;
        padding: 10px 12px;
        width: 100%;
      }
      button {
        background: #1b1b1b;
        border: 0;
        border-radius: 6px;
        color: #fff;
        cursor: pointer;
        font: inherit;
        font-weight: 650;
        padding: 10px 14px;
        width: 100%;
      }
      .error { color: #8a1f1f; font-weight: 600; }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(preview.title)}</h1>
      <p>This HTML preview is password protected.</p>
      ${errorMarkup}
      <form method="post" action="/p/${preview.slug}/access">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
        <button type="submit">View preview</button>
      </form>
    </main>
  </body>
</html>`;

  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
  for (const [name, value] of Object.entries(extraHeaders)) {
    headers.set(name, value);
  }

  return new Response(html, { status, headers });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
