import { HttpError } from "./http";
import { ACCESS_COOKIE_TTL_SECONDS, hasPreviewAccess, type PreviewAccessEnv } from "./preview-access";
import {
  listPreviewAssets,
  readPreviewAsset,
  type PreviewAssetStoreEnv,
} from "./preview-asset-store";
import { rewriteImageReferences, type PreviewAssetReference } from "./preview-assets";
import { passwordForm } from "./preview-password-form";
import {
  getActivePreview,
  getPreviewRenderOptions,
  type PreviewRenderOptions,
  type PreviewRow,
  type PreviewStoreEnv,
} from "./preview-store";
import { signPreviewAssetToken, verifyPreviewAssetToken } from "./security";

export interface PreviewRenderEnv extends PreviewStoreEnv, PreviewAssetStoreEnv, PreviewAccessEnv {
  PUBLIC_BASE_URL?: string;
}

const STATIC_PREVIEW_RENDER_OPTIONS: PreviewRenderOptions = {
  allowScripts: false,
};

const HTML_SECURITY_HEADER_BASE = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Frame-Options": "DENY",
};

const GLEAN_GENERATED_HTML_SCRIPT_SOURCES = [
  "https://cdn.jsdelivr.net",
  "https://unpkg.com",
  "https://cdnjs.cloudflare.com",
  "https://esm.sh",
  "https://cdn.tailwindcss.com",
  "https://cdn.plot.ly",
  "https://d3js.org",
  "https://cdn.sheetjs.com",
  "https://ajax.googleapis.com",
];

const GLEAN_GENERATED_HTML_STYLE_SOURCES = [
  "https://fonts.googleapis.com",
  "https://cdn.jsdelivr.net",
  "https://unpkg.com",
  "https://cdnjs.cloudflare.com",
  "https://esm.sh",
  "https://cdn.tailwindcss.com",
];

const GLEAN_GENERATED_HTML_FONT_SOURCES = [
  "https://fonts.gstatic.com",
  "https://cdn.jsdelivr.net",
  "https://cdnjs.cloudflare.com",
];

export async function handlePreviewRequest(
  request: Request,
  env: PreviewRenderEnv,
  slug: string,
): Promise<Response> {
  const preview = await getActivePreview(env, slug);

  if (!(await hasPreviewAccess(request, env, preview))) {
    return passwordForm(preview, null, 200);
  }

  const object = await env.HTML_PREVIEWS.get(preview.object_key);
  if (!object?.body) {
    throw new HttpError(404, "preview_object_missing", "Preview content is missing");
  }

  const html = await object.text();
  const renderOptions = await getPreviewRenderOptions(env, preview.slug);
  const rewrittenHtml = rewriteImageReferences(
    html,
    preview.slug,
    await previewAssetReferences(env, preview),
  );
  const headers = new Headers(previewHtmlSecurityHeaders(previewOrigin(request, env), renderOptions));
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "private, no-store");

  return new Response(rewrittenHtml, { headers });
}

export async function handlePreviewAssetRequest(
  request: Request,
  env: PreviewRenderEnv,
  slug: string,
  assetId: string,
): Promise<Response> {
  const preview = await getActivePreview(env, slug);
  const hasAccess =
    (await hasPreviewAccess(request, env, preview)) || (await hasPreviewAssetAccess(request, env, preview, assetId));
  if (!hasAccess) {
    throw new HttpError(404, "preview_asset_not_found", "Preview asset not found");
  }

  const asset = await readPreviewAsset(env, slug, assetId);
  const headers = new Headers({
    "Content-Type": asset.contentType,
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });

  return new Response(request.method === "HEAD" ? null : asset.body, { headers });
}

export function previewHtmlSecurityHeaders(
  previewOriginValue: string,
  options: PreviewRenderOptions = STATIC_PREVIEW_RENDER_OPTIONS,
): Record<string, string> {
  return {
    "Content-Security-Policy": previewContentSecurityPolicy(previewOriginValue, options),
    ...HTML_SECURITY_HEADER_BASE,
  };
}

function previewContentSecurityPolicy(
  previewOriginValue: string,
  options: PreviewRenderOptions,
): string {
  const sandbox = options.allowScripts ? "sandbox allow-scripts" : "sandbox";
  const scriptSources = ["'unsafe-inline'", ...GLEAN_GENERATED_HTML_SCRIPT_SOURCES].join(" ");
  const scriptSrc = options.allowScripts ? `script-src ${scriptSources}` : "script-src 'none'";
  const styleSources = ["'unsafe-inline'", ...GLEAN_GENERATED_HTML_STYLE_SOURCES].join(" ");
  const fontSources = ["data:", ...GLEAN_GENERATED_HTML_FONT_SOURCES].join(" ");
  const navigateTo = options.allowScripts ? "; navigate-to 'none'" : "";

  return `${sandbox}; default-src 'none'; ${scriptSrc}; script-src-attr 'none'; style-src ${styleSources}; img-src ${previewOriginValue} data: blob:; media-src data: blob:; font-src ${fontSources}; connect-src 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; frame-ancestors 'none'${navigateTo}`;
}

function previewOrigin(request: Request, env: PreviewRenderEnv): string {
  try {
    return new URL(env.PUBLIC_BASE_URL ?? request.url).origin;
  } catch {
    return new URL(request.url).origin;
  }
}

async function previewAssetReferences(env: PreviewRenderEnv, preview: PreviewRow): Promise<PreviewAssetReference[]> {
  const expiresAt = Date.now() + ACCESS_COOKIE_TTL_SECONDS * 1000;
  const assets = await listPreviewAssets(env, preview.slug);

  return Promise.all(
    assets.map(async (asset) => ({
      assetId: asset.asset_id,
      originalName: asset.original_name,
      url: `/p/${preview.slug}/assets/${asset.asset_id}?token=${await signPreviewAssetToken(
        {
          slug: preview.slug,
          assetId: asset.asset_id,
          passwordVersion: preview.password_version,
          expiresAt,
        },
        env.COOKIE_SIGNING_SECRET,
      )}`,
    })),
  );
}

async function hasPreviewAssetAccess(
  request: Request,
  env: PreviewRenderEnv,
  preview: PreviewRow,
  assetId: string,
): Promise<boolean> {
  const token = new URL(request.url).searchParams.get("token");
  return (
    token !== null &&
    (await verifyPreviewAssetToken(
      token,
      env.COOKIE_SIGNING_SECRET,
      preview.slug,
      assetId,
      preview.password_version,
    ))
  );
}
