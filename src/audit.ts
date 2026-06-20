import { hashViewerIp } from "./security";

export interface AuditEnv {
  COOKIE_SIGNING_SECRET: string;
  PREVIEW_DB: D1Database;
}

export interface AuditEventInput {
  actorEmail: string | null;
  details: Record<string, unknown> | null;
  eventType: string;
  request: Request;
  slug: string;
}

export interface AuditEventRow {
  actor_email: string | null;
  created_at: string;
  details_json: string | null;
  event_type: string;
  id: number;
  slug: string;
}

export async function recordAudit(env: AuditEnv, input: AuditEventInput): Promise<void> {
  const viewerIpHash = await hashViewerIp(input.request.headers.get("CF-Connecting-IP"), env.COOKIE_SIGNING_SECRET);
  await env.PREVIEW_DB.prepare(
    `INSERT INTO audit_events (
      slug,
      event_type,
      actor_email,
      viewer_ip_hash,
      created_at,
      details_json
    ) VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      input.slug,
      input.eventType,
      input.actorEmail,
      viewerIpHash,
      new Date().toISOString(),
      input.details ? JSON.stringify(input.details) : null,
    )
    .run();
}

export async function listAuditEvents(env: AuditEnv, slug: string, limit = 25): Promise<AuditEventRow[]> {
  const result = await env.PREVIEW_DB.prepare(
    `SELECT id, slug, event_type, actor_email, created_at, details_json
      FROM audit_events
      WHERE slug = ?
      ORDER BY created_at DESC
      LIMIT ?`,
  )
    .bind(slug, limit)
    .all<AuditEventRow>();

  return result.results;
}
