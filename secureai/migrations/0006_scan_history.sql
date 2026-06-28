-- SecureAI per-user recent-scans history — a privacy-conscious audit trail of
-- the scans an AUTHENTICATED account ran, surfaced by GET /api/scans/recent.
--
-- One row per successful authenticated scan. Anonymous (anon:<ip>) callers are
-- NOT recorded here — recent scans are a per-account feature. Privacy: the row
-- stores ONLY the source label/URL (or the literal 'paste'), truncated to 200
-- chars, NEVER the full scanned content, so the history can never re-leak the
-- bytes that were scanned. `head_hash` ties each row back to the scan's
-- tamper-evident proof so a history entry remains verifiable.
--
-- All timestamps are ISO-8601 UTC strings, stamped at the edge (outside the
-- hashed proof) by the route, exactly as `scannedAt` is on the ScanResult.

CREATE TABLE IF NOT EXISTS scan_history (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  verdict     TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  source_ref  TEXT NOT NULL,
  flagged     INTEGER NOT NULL DEFAULT 0,
  head_hash   TEXT NOT NULL,
  scanned_at  TEXT NOT NULL
);

-- The recent-scans read is "newest first for one user": an index on
-- (user_id, scanned_at) lets that ORDER BY ... DESC LIMIT k read be served from
-- the index without a table scan.
CREATE INDEX IF NOT EXISTS idx_scan_history_user_scanned_at
  ON scan_history (user_id, scanned_at);
