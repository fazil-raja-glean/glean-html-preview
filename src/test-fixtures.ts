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

export function createTestPreviewDb(): D1Database {
  const oauthGrants = new Map<string, TestOAuthGrantRow>();

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
          return null;
        },
        async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
          return d1Result<T>(0);
        },
        async raw<T = unknown[]>(options?: { columnNames?: boolean }): Promise<T[] | [string[], ...T[]]> {
          return options?.columnNames ? [[]] : [];
        },
      };

      return statement as D1PreparedStatement;
    },
  } as D1Database;
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
