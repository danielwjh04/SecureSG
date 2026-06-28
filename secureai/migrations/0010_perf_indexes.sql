-- SecureAI performance indexes — cover the two admin hot reads that previously
-- forced a full scan + in-memory sort, keeping their cost O(log n) at the index.
--
--   scan_history(verdict, scanned_at) — the blocked-threats report filters
--     `WHERE verdict = 'BLOCK' ORDER BY scanned_at DESC` (db/admin.ts listThreats
--     / countThreats). The existing (user_id, scanned_at) index does not help (no
--     user filter); this composite serves both the verdict filter and the order.
--
--   users(created_at) — the members directory orders `ORDER BY created_at ASC`
--     (db/admin.ts listMembers); a plain column index serves the sort.
--
--   users(date(created_at)) — the daily-signups aggregate filters
--     `WHERE date(created_at) >= ?` (db/admin.ts signupsByDay). The predicate
--     wraps the column in a function, so only an EXPRESSION index on the same
--     expression can be used — a plain column index would not be.
--
-- All three are additive (no data change) and IF NOT EXISTS, so re-applying is a
-- no-op.

CREATE INDEX IF NOT EXISTS idx_scan_history_verdict_scanned_at
  ON scan_history (verdict, scanned_at);

CREATE INDEX IF NOT EXISTS idx_users_created_at
  ON users (created_at);

CREATE INDEX IF NOT EXISTS idx_users_created_day
  ON users (date(created_at));
