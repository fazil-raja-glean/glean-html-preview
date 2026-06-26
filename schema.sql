CREATE TABLE IF NOT EXISTS previews (
  slug TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  object_key TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_iterations INTEGER NOT NULL,
  password_version INTEGER NOT NULL DEFAULT 1,
  publisher_email TEXT NOT NULL,
  source_url TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL DEFAULT '',
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS previews_publisher_email_idx
  ON previews (publisher_email);

CREATE INDEX IF NOT EXISTS previews_expires_at_idx
  ON previews (expires_at);

CREATE TABLE IF NOT EXISTS preview_assets (
  slug TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  content_type TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  original_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (slug, asset_id),
  FOREIGN KEY (slug) REFERENCES previews(slug) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS preview_assets_slug_idx
  ON preview_assets (slug);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_email TEXT,
  viewer_ip_hash TEXT,
  created_at TEXT NOT NULL,
  details_json TEXT
);

CREATE INDEX IF NOT EXISTS audit_events_slug_created_at_idx
  ON audit_events (slug, created_at);

CREATE TABLE IF NOT EXISTS access_rate_limits (
  scope TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL,
  window_started_at TEXT NOT NULL,
  locked_until TEXT
);

CREATE INDEX IF NOT EXISTS access_rate_limits_locked_until_idx
  ON access_rate_limits (locked_until);

CREATE TABLE IF NOT EXISTS oauth_grants (
  jti TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  actor_email TEXT,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_by_jti TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS oauth_grants_client_kind_idx
  ON oauth_grants (client_id, kind);

CREATE INDEX IF NOT EXISTS oauth_grants_expires_at_idx
  ON oauth_grants (expires_at);

CREATE TABLE IF NOT EXISTS admin_oauth_clients (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  api_base_url TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret_ciphertext TEXT,
  client_secret_iv TEXT,
  token_endpoint_auth_method TEXT NOT NULL,
  scopes TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS admin_oauth_clients_issuer_api_base_url_idx
  ON admin_oauth_clients (issuer, api_base_url);
