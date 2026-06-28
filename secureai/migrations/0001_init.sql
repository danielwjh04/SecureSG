-- SecureAI accounts layer — initial D1 schema.
--
-- Three tables back API-key auth, tier resolution, and per-subject daily usage
-- metering:
--   users     — one row per account; `tier` gates the paid AI stage.
--   api_keys  — credentials, keyed by sha256(rawKey). The raw key is NEVER
--               stored; only its hex SHA-256 digest is persisted.
--   usage     — per (subject, UTC day) counters for caps and AI metering.
--
-- All timestamps are ISO-8601 UTC strings. `subject` in `usage` is either a
-- user id or `anon:<ip>` for unauthenticated callers. Lookups on the auth and
-- billing paths are O(1) via the primary keys / unique indexes below.

CREATE TABLE IF NOT EXISTS users (
  id                 TEXT PRIMARY KEY,
  email              TEXT NOT NULL UNIQUE,
  tier               TEXT NOT NULL DEFAULT 'free',
  stripe_customer_id TEXT,
  created_at         TEXT NOT NULL
);

-- Stripe webhook → tier update looks up by customer id; index it so that path
-- stays O(1) rather than a table scan. Partial index skips the NULL rows.
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer_id
  ON users (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS api_keys (
  key_sha256 TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Reverse lookup (all keys for a user) used by key rotation / revocation.
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id);

CREATE TABLE IF NOT EXISTS usage (
  subject   TEXT NOT NULL,
  day       TEXT NOT NULL,
  scans     INTEGER NOT NULL DEFAULT 0,
  ai_scans  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (subject, day)
);
