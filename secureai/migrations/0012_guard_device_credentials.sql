-- Device-scoped credentials for runtime Guard adapters.
--
-- Raw credentials are returned once at registration and never stored. The table
-- keeps only sha256(rawCredential), scoped to one user, device, integration, and
-- the `guard:decision` permission.

CREATE TABLE IF NOT EXISTS guard_device_credentials (
  id                TEXT PRIMARY KEY,
  credential_sha256 TEXT NOT NULL UNIQUE,
  user_id           TEXT NOT NULL,
  device_id         TEXT NOT NULL,
  name              TEXT,
  integration       TEXT NOT NULL,
  scopes            TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'active',
  created_at        TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  last_seen_at      TEXT,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX IF NOT EXISTS idx_guard_devices_user_id
  ON guard_device_credentials (user_id);

CREATE INDEX IF NOT EXISTS idx_guard_devices_lookup
  ON guard_device_credentials (credential_sha256, status, expires_at);
