-- SecureAI caught-scan detail store — the actual scanned content + structured
-- findings of a MALICIOUS skill/artifact, so an admin can review what was caught.
--
-- One row per non-clean AUTHENTICATED scan (verdict != 'ALLOW', i.e.
-- HUMAN_APPROVAL_REQUIRED or BLOCK). Clean ALLOW scans are NEVER persisted here
-- (privacy: nothing flagged, nothing to review) and anonymous callers are never
-- recorded (this is a per-account review surface). `scan_id` pairs 1:1 with
-- scan_history.id, so the detail joins back to the recorded scan and its owner.
--
-- `content` is the scanned text TRUNCATED to SCANNER_DETAIL_MAX_BYTES by the
-- route, or NULL when the content was unavailable (e.g. a verdict-cache hit
-- recomputed nothing). `result_json` is the serialized {findings, chains,
-- injections, reputation} evidence. `created_at` is an ISO-8601 UTC string
-- stamped at the edge.

CREATE TABLE IF NOT EXISTS scan_details (
  scan_id     TEXT PRIMARY KEY,
  content     TEXT,
  result_json TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
