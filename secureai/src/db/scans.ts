/**
 * Recent-scans history repository over the narrow {@link Database} seam.
 *
 * One row records one successful AUTHENTICATED scan: its verdict, source
 * provenance (kind + a truncated label/URL — NEVER the scanned content), the
 * flagged-indicator count, and the proof head hash that ties the row back to the
 * scan's tamper-evident chain. Anonymous callers are never written here (recent
 * scans are a per-account feature); the route enforces that before calling
 * {@link insertScan}.
 *
 * Privacy discipline (CLAUDE.md §6): `sourceRef` is the source LABEL only (a URL
 * or the literal `paste`), already truncated by the caller. The full scanned
 * skill text never reaches this layer, so the history can never re-leak it.
 */

import type { Database, Row } from './database'

/** A row to persist into `scan_history` — one successful authenticated scan. */
export interface ScanHistoryRow {
  readonly id: string
  readonly userId: string
  readonly verdict: string
  readonly sourceKind: string
  readonly sourceRef: string
  readonly flagged: number
  readonly headHash: string
  readonly scannedAt: string
}

/** A history entry as read back for the recent-scans endpoint, newest first. */
export interface RecentScan {
  readonly id: string
  readonly verdict: string
  readonly source: { readonly kind: string; readonly ref: string }
  readonly flagged: number
  readonly headHash: string
  readonly scannedAt: string
}

/** Read a column as a string, defaulting to `''` for a malformed/absent value. */
function readString(row: Row, column: string): string {
  const value = row[column]
  return typeof value === 'string' ? value : ''
}

/** Read a column as a non-negative integer, defaulting to 0. */
function readCount(row: Row, column: string): number {
  const value = row[column]
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0
}

/**
 * Insert one recent-scan history row.
 *
 * A single insert; the id is a caller-minted `crypto.randomUUID()` so replaying
 * the same logical scan with a fresh id appends a distinct entry (a re-scan is a
 * new event, not an update). The caller invokes this best-effort AFTER the scan
 * response is computed — a failure here must be caught at the call site and must
 * never fail the scan.
 *
 * Time complexity: O(1) — single indexed insert. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param row - The history row to persist.
 */
export async function insertScan(db: Database, row: ScanHistoryRow): Promise<void> {
  await db.execute(
    'INSERT INTO scan_history ' +
      '(id, user_id, verdict, source_kind, source_ref, flagged, head_hash, scanned_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [
      row.id,
      row.userId,
      row.verdict,
      row.sourceKind,
      row.sourceRef,
      row.flagged,
      row.headHash,
      row.scannedAt,
    ],
  )
}

/**
 * List a user's most recent scans, newest first, capped at `limit` rows.
 *
 * One indexed range read over `(user_id, scanned_at)`: `WHERE user_id = ?
 * ORDER BY scanned_at DESC LIMIT ?`. The `LIMIT` bounds the read so a busy
 * account never returns its whole history; the caller validates `limit` against
 * its own max before calling.
 *
 * Time complexity: O(limit) rows read from the index. Space complexity: O(limit).
 *
 * @param db - The persistence seam.
 * @param userId - The authenticated account id whose history is read.
 * @param limit - Max rows to return (caller-validated, positive).
 * @returns The newest-first list of recent scans, at most `limit` long.
 */
export async function listRecentScans(
  db: Database,
  userId: string,
  limit: number,
): Promise<RecentScan[]> {
  const rows = await db.queryAll(
    'SELECT id, verdict, source_kind, source_ref, flagged, head_hash, scanned_at ' +
      'FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC LIMIT ?',
    [userId, limit],
  )
  return rows.map((row) => ({
    id: readString(row, 'id'),
    verdict: readString(row, 'verdict'),
    source: { kind: readString(row, 'source_kind'), ref: readString(row, 'source_ref') },
    flagged: readCount(row, 'flagged'),
    headHash: readString(row, 'head_hash'),
    scannedAt: readString(row, 'scanned_at'),
  }))
}
