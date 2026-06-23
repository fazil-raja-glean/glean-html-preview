import { getCookie } from "./cookies";
import type { PreviewRow } from "./preview-store";
import { verifyAccessCookie } from "./security";

export interface PreviewAccessEnv {
  COOKIE_SIGNING_SECRET: string;
}

export const ACCESS_COOKIE_NAME = "html_preview_access";
export const ACCESS_COOKIE_TTL_SECONDS = 60 * 60 * 12;

export async function hasPreviewAccess(
  request: Request,
  env: PreviewAccessEnv,
  preview: PreviewRow,
): Promise<boolean> {
  const cookie = getCookie(request, ACCESS_COOKIE_NAME);
  return (
    cookie !== null &&
    (await verifyAccessCookie(cookie, env.COOKIE_SIGNING_SECRET, preview.slug, preview.password_version))
  );
}
