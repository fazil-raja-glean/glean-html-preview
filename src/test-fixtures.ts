import type { AuditEventRow } from "./audit";
import type { PreviewAssetRow } from "./preview-assets";
import type { PreviewRow, PreviewSettingsRow } from "./preview-store";

export const testOrigins = {
  apiBaseUrl: "https://api.example.test",
  mcpBaseUrl: "https://mcp.example.test",
  previewBaseUrl: "https://preview.example.test",
} as const;

export const testApiOriginEnv = {
  WORKER_ROLE: "api",
  API_BASE_URL: testOrigins.apiBaseUrl,
  MCP_BASE_URL: testOrigins.mcpBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
} as const;

export const testMcpOriginEnv = {
  WORKER_ROLE: "mcp",
  API_BASE_URL: testOrigins.apiBaseUrl,
  MCP_BASE_URL: testOrigins.mcpBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
} as const;

export const testPreviewOriginEnv = {
  WORKER_ROLE: "preview",
  MCP_BASE_URL: testOrigins.mcpBaseUrl,
  PUBLIC_BASE_URL: testOrigins.previewBaseUrl,
} as const;

export function requestOn(baseUrl: string, path: string, init?: RequestInit): Request {
  return new Request(new URL(path, baseUrl).toString(), init);
}

interface TestOAuthGrantRow {
  actor_email: string | null;
  client_id: string;
  consumed_at: string | null;
  consumed_by_jti: string | null;
  expires_at: string;
  issued_at: string;
  jti: string;
  kind: string;
  revoked_at: string | null;
  scope: string;
}

export function createTestPreviewDb(seedPreviews: PreviewRow[] = []): D1Database {
  const oauthGrants = new Map<string, TestOAuthGrantRow>();
  const previews = new Map(seedPreviews.map((preview) => [preview.slug, { ...preview }]));
  const previewSettings = new Map<string, PreviewSettingsRow>();
  const assets = new Map<string, PreviewAssetRow>();
  const auditEvents: AuditEventRow[] = [];

  return {
    prepare(query: string): D1PreparedStatement {
      const normalizedQuery = query.replace(/\s+/g, " ").trim().toUpperCase();
      const statement = {
        values: [] as unknown[],
        bind(...values: unknown[]): D1PreparedStatement {
          statement.values = values;
          return statement as D1PreparedStatement;
        },
        async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
          if (normalizedQuery.startsWith("INSERT INTO OAUTH_GRANTS")) {
            const [jti, kind, clientId, scope, actorEmail, issuedAt, expiresAt] = statement.values;
            oauthGrants.set(String(jti), {
              jti: String(jti),
              kind: String(kind),
              client_id: String(clientId),
              scope: String(scope),
              actor_email: typeof actorEmail === "string" ? actorEmail : null,
              issued_at: String(issuedAt),
              expires_at: String(expiresAt),
              consumed_at: null,
              consumed_by_jti: null,
              revoked_at: null,
            });
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("INSERT INTO PREVIEWS")) {
            const [
              slug,
              title,
              objectKey,
              passwordHash,
              passwordSalt,
              passwordIterations,
              publisherEmail,
              sourceUrl,
              createdAt,
              expiresAt,
            ] = statement.values;
            previews.set(String(slug), {
              slug: String(slug),
              title: String(title),
              object_key: String(objectKey),
              password_hash: String(passwordHash),
              password_salt: String(passwordSalt),
              password_iterations: Number(passwordIterations),
              password_version: 1,
              publisher_email: String(publisherEmail),
              source_url: typeof sourceUrl === "string" ? sourceUrl : null,
              created_at: String(createdAt),
              expires_at: typeof expiresAt === "string" ? expiresAt : "",
              deleted_at: null,
            });
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("INSERT INTO PREVIEW_SETTINGS")) {
            const [slug, allowScripts, createdAt] = statement.values;
            previewSettings.set(String(slug), {
              slug: String(slug),
              allow_scripts: Number(allowScripts),
              created_at: String(createdAt),
            });
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("INSERT INTO PREVIEW_ASSETS")) {
            const [slug, assetId, objectKey, contentType, byteSize, originalName, createdAt] = statement.values;
            assets.set(assetKey(String(slug), String(assetId)), {
              slug: String(slug),
              asset_id: String(assetId),
              object_key: String(objectKey),
              content_type: String(contentType) as PreviewAssetRow["content_type"],
              byte_size: Number(byteSize),
              original_name: String(originalName),
              created_at: String(createdAt),
            });
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("UPDATE PREVIEWS SET PASSWORD_HASH")) {
            const [passwordHash, passwordSalt, passwordIterations, slug] = statement.values;
            const preview = previews.get(String(slug));
            if (!preview || preview.deleted_at) {
              return d1Result<T>(0);
            }

            preview.password_hash = String(passwordHash);
            preview.password_salt = String(passwordSalt);
            preview.password_iterations = Number(passwordIterations);
            preview.password_version += 1;
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("UPDATE PREVIEWS SET DELETED_AT")) {
            const [deletedAt, slug] = statement.values;
            const preview = previews.get(String(slug));
            if (!preview || preview.deleted_at) {
              return d1Result<T>(0);
            }

            preview.deleted_at = String(deletedAt);
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("DELETE FROM PREVIEWS")) {
            return d1Result<T>(previews.delete(String(statement.values[0])) ? 1 : 0);
          }

          if (normalizedQuery.startsWith("DELETE FROM PREVIEW_ASSETS")) {
            const slug = String(statement.values[0]);
            let changes = 0;
            for (const key of assets.keys()) {
              if (key.startsWith(`${slug}:`)) {
                assets.delete(key);
                changes += 1;
              }
            }
            return d1Result<T>(changes);
          }

          if (normalizedQuery.startsWith("INSERT INTO AUDIT_EVENTS")) {
            const [slug, eventType, actorEmail, , createdAt, detailsJson] = statement.values;
            auditEvents.push({
              id: auditEvents.length + 1,
              slug: String(slug),
              event_type: String(eventType),
              actor_email: typeof actorEmail === "string" ? actorEmail : null,
              created_at: String(createdAt),
              details_json: typeof detailsJson === "string" ? detailsJson : null,
            });
            return d1Result<T>(1);
          }

          if (normalizedQuery.startsWith("UPDATE OAUTH_GRANTS SET CONSUMED_AT")) {
            const [consumedAt, consumedByJti, jti, kind, clientId, scope, actorEmail, now] = statement.values;
            const row = oauthGrants.get(String(jti));
            if (
              row &&
              row.kind === kind &&
              row.client_id === clientId &&
              row.scope === scope &&
              (row.actor_email ?? "") === (typeof actorEmail === "string" ? actorEmail : "") &&
              row.consumed_at === null &&
              row.revoked_at === null &&
              row.expires_at > String(now)
            ) {
              row.consumed_at = String(consumedAt);
              row.consumed_by_jti = typeof consumedByJti === "string" ? consumedByJti : null;
              return d1Result<T>(1);
            }

            return d1Result<T>(0);
          }

          if (normalizedQuery.startsWith("UPDATE OAUTH_GRANTS SET REVOKED_AT")) {
            const [revokedAt, jti] = statement.values;
            const row = oauthGrants.get(String(jti));
            if (row && row.consumed_at === null && row.revoked_at === null) {
              row.revoked_at = String(revokedAt);
              return d1Result<T>(1);
            }

            return d1Result<T>(0);
          }

          return d1Result<T>(0);
        },
        async first<T = Record<string, unknown>>(): Promise<T | null> {
          if (normalizedQuery.startsWith("SELECT * FROM PREVIEWS WHERE SLUG = ? AND LOWER(PUBLISHER_EMAIL)")) {
            const preview = previews.get(String(statement.values[0]));
            const publisherEmail = String(statement.values[1]).toLowerCase();
            return preview?.publisher_email.toLowerCase() === publisherEmail ? (preview as T) : null;
          }

          if (normalizedQuery.startsWith("SELECT * FROM PREVIEWS WHERE SLUG")) {
            return (previews.get(String(statement.values[0])) as T | undefined) ?? null;
          }

          if (normalizedQuery.startsWith("SELECT * FROM PREVIEW_SETTINGS WHERE SLUG")) {
            return (previewSettings.get(String(statement.values[0])) as T | undefined) ?? null;
          }

          if (normalizedQuery.startsWith("SELECT * FROM PREVIEW_ASSETS WHERE SLUG = ? AND ASSET_ID")) {
            return (assets.get(assetKey(String(statement.values[0]), String(statement.values[1]))) as T | undefined) ?? null;
          }

          return null;
        },
        async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
          if (normalizedQuery.startsWith("SELECT * FROM PREVIEW_ASSETS WHERE SLUG")) {
            const slug = String(statement.values[0]);
            return d1Rows([...assets.values()].filter((asset) => asset.slug === slug) as T[]);
          }

          if (normalizedQuery.startsWith("SELECT * FROM PREVIEWS WHERE LOWER(PUBLISHER_EMAIL)")) {
            const publisherEmail = String(statement.values[0]).toLowerCase();
            const limit = Number(statement.values[1] ?? 100);
            const rows = [...previews.values()]
              .filter((preview) => preview.publisher_email.toLowerCase() === publisherEmail)
              .sort((left, right) => right.created_at.localeCompare(left.created_at))
              .slice(0, limit);
            return d1Rows(rows as T[]);
          }

          if (normalizedQuery.startsWith("SELECT * FROM PREVIEWS")) {
            const rows = [...previews.values()].sort((left, right) => right.created_at.localeCompare(left.created_at));
            return d1Rows(rows as T[]);
          }

          if (normalizedQuery.startsWith("SELECT ID, SLUG, EVENT_TYPE")) {
            const slug = String(statement.values[0]);
            const limit = Number(statement.values[1] ?? 25);
            const rows = auditEvents
              .filter((event) => event.slug === slug)
              .sort((left, right) => right.created_at.localeCompare(left.created_at))
              .slice(0, limit);
            return d1Rows(rows as T[]);
          }

          return d1Result<T>(0);
        },
        async raw<T = unknown[]>(options?: { columnNames?: boolean }): Promise<T[] | [string[], ...T[]]> {
          return options?.columnNames ? [[]] : [];
        },
      };

      return statement as D1PreparedStatement;
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      const results = [];
      for (const statement of statements) {
        results.push(await statement.run<T>());
      }
      return results;
    },
  } as D1Database;
}

export function createTestR2Bucket(initialObjects: Record<string, string | Uint8Array> = {}): R2Bucket {
  const objects = new Map(Object.entries(initialObjects));
  return {
    async get(key: string): Promise<R2ObjectBody | null> {
      const value = objects.get(key);
      if (value === undefined) {
        return null;
      }

      return {
        body: new Response(value).body,
        text: async () => (typeof value === "string" ? value : new TextDecoder().decode(value)),
        arrayBuffer: async () =>
          typeof value === "string" ? new TextEncoder().encode(value).buffer : value.buffer.slice(0),
      } as R2ObjectBody;
    },
    async put(key: string, value: string | ReadableStream | ArrayBuffer | ArrayBufferView | Blob): Promise<R2Object> {
      objects.set(key, storedR2Value(value));
      return {} as R2Object;
    },
    async delete(key: string): Promise<void> {
      objects.delete(key);
    },
  } as R2Bucket;
}

function assetKey(slug: string, assetId: string): string {
  return `${slug}:${assetId}`;
}

function storedR2Value(value: string | ReadableStream | ArrayBuffer | ArrayBufferView | Blob): string | Uint8Array {
  if (typeof value === "string") {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  return "";
}

function d1Result<T>(changes: number): D1Result<T> {
  return {
    success: true,
    meta: {
      changed_db: changes > 0,
      changes,
      duration: 0,
      last_row_id: 0,
      rows_read: 0,
      rows_written: changes,
      size_after: 0,
    },
    results: [],
  };
}

function d1Rows<T>(rows: T[]): D1Result<T> {
  return {
    success: true,
    meta: {
      changed_db: false,
      changes: 0,
      duration: 0,
      last_row_id: 0,
      rows_read: rows.length,
      rows_written: 0,
      size_after: 0,
    },
    results: rows,
  };
}
