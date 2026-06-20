import { HttpError } from "./http";

export type OAuthGrantKind = "authorization_code" | "refresh_token";

export interface OAuthGrantStore {
  consume(input: ConsumeOAuthGrantInput): Promise<boolean>;
  create(input: CreateOAuthGrantInput): Promise<void>;
  revoke(input: RevokeOAuthGrantInput): Promise<void>;
}

export interface OAuthGrantStoreEnv {
  PREVIEW_DB?: D1Database;
}

interface CreateOAuthGrantInput {
  actorEmail?: string;
  clientId: string;
  expiresAt: number;
  issuedAt: number;
  jti: string;
  kind: OAuthGrantKind;
  scope: string;
}

interface ConsumeOAuthGrantInput {
  actorEmail?: string;
  clientId: string;
  consumedByJti?: string;
  jti: string;
  kind: OAuthGrantKind;
  now: Date;
  scope: string;
}

interface RevokeOAuthGrantInput {
  jti: string;
  now: Date;
}

export function d1OAuthGrantStore(env: OAuthGrantStoreEnv): OAuthGrantStore {
  if (!env.PREVIEW_DB) {
    throw new HttpError(500, "missing_oauth_grant_store", "OAuth grant state database is not configured");
  }

  return {
    async create(input) {
      await env.PREVIEW_DB!.prepare(
        `INSERT INTO oauth_grants (
          jti,
          kind,
          client_id,
          scope,
          actor_email,
          issued_at,
          expires_at,
          consumed_at,
          consumed_by_jti,
          revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`,
      )
        .bind(
          input.jti,
          input.kind,
          input.clientId,
          input.scope,
          input.actorEmail ?? null,
          secondsToIso(input.issuedAt),
          secondsToIso(input.expiresAt),
        )
        .run();
    },

    async consume(input) {
      const result = await env.PREVIEW_DB!.prepare(
        `UPDATE oauth_grants
          SET consumed_at = ?,
              consumed_by_jti = ?
          WHERE jti = ?
            AND kind = ?
            AND client_id = ?
            AND scope = ?
            AND COALESCE(actor_email, '') = COALESCE(?, '')
            AND consumed_at IS NULL
            AND revoked_at IS NULL
            AND expires_at > ?`,
      )
        .bind(
          input.now.toISOString(),
          input.consumedByJti ?? null,
          input.jti,
          input.kind,
          input.clientId,
          input.scope,
          input.actorEmail ?? null,
          input.now.toISOString(),
        )
        .run();

      return result.meta.changes === 1;
    },

    async revoke(input) {
      await env.PREVIEW_DB!.prepare(
        `UPDATE oauth_grants
          SET revoked_at = ?
          WHERE jti = ?
            AND consumed_at IS NULL
            AND revoked_at IS NULL`,
      )
        .bind(input.now.toISOString(), input.jti)
        .run();
    },
  };
}

function secondsToIso(value: number): string {
  return new Date(value * 1000).toISOString();
}
