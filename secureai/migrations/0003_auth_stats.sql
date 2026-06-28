-- SecureAI auth + protection-stats layer — email/password sessions and
-- per-verdict usage counters.
--
-- Two surgical schema additions:
--   users.password_hash   — a serialized PBKDF2 password hash for accounts that
--                            registered with email + password. NULLABLE: existing
--                            and API-key-only accounts (provisioned via signup)
--                            have no password and authenticate by Bearer key only.
--   usage.{allows,reviews,blocks,flagged}
--                         — per (subject, UTC day) verdict + indicator counters,
--                           bumped alongside `scans` by recordVerdict so the
--                           dashboard can aggregate protection stats over time.
--                           NOT NULL DEFAULT 0 so existing rows read as zeros and
--                           the upsert can `+ 1` unconditionally.

ALTER TABLE users ADD COLUMN password_hash TEXT;

ALTER TABLE usage ADD COLUMN allows  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage ADD COLUMN reviews INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage ADD COLUMN blocks  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE usage ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0;
