/**
 * Recent-scans history repository over the narrow {@link Database} seam.
 *
 * One row records one successful AUTHENTICATED scan: its verdict, source
 * provenance (kind + a truncated label/URL, NEVER the scanned content), the
 * flagged-indicator count, and the proof head hash that ties the row back to the
 * scan's tamper-evident chain. Anonymous callers are never written here (recent
 * scans are a per-account feature); the route enforces that before calling
 * {@link insertScan}.
 *
 * Privacy discipline (CLAUDE.md §6): `sourceRef` is the source LABEL only (a URL
 * or the literal `paste`), already truncated by the caller. The full scanned
 * skill text never reaches this layer, so the history can never re-leak it.
 */

import type { BatchStatement, Database, Row } from './database'
import type {
  InjectionFinding,
  LinkChain,
  ReputationReport,
  RuleFinding,
} from '../schemas/contract'
import { log } from '../observability/logger'

/** A row to persist into `scan_history`, one successful authenticated scan. */
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

/**
 * A caught-scan detail row to persist into `scan_details`, the scanned content
 * plus the serialized evidence of ONE non-clean authenticated scan, for admin
 * review.
 *
 * `content` is the scanned skill/artifact text already TRUNCATED to the
 * configured detail byte cap by the caller, or `null` when the content was
 * unavailable (e.g. a verdict-cache hit recomputed nothing). `resultJson` is the
 * pre-serialized `{ findings, chains, injections, reputation }` evidence so this
 * layer never re-derives the shape. `scanId` pairs 1:1 with the `scan_history`
 * row's id.
 */
export interface ScanDetailRow {
  readonly scanId: string
  readonly content: string | null
  readonly resultJson: string
  readonly createdAt: string
}

/**
 * One caught-scan detail as read back for the admin detail endpoint: the scanned
 * `content` (or `null`) plus the raw `result_json` string (the route parses it),
 * joined to the recorded scan's verdict/source/proof and its owner's email.
 */
export interface ScanDetail {
  readonly id: string
  readonly email: string
  readonly verdict: string
  readonly source: { readonly kind: string; readonly ref: string }
  readonly flagged: number
  readonly headHash: string
  readonly scannedAt: string
  readonly content: string | null
  /** The serialized `{ findings, chains, injections, reputation }` evidence. */
  readonly resultJson: string
}

/**
 * One caught-scan detail as read back for the OWNER-scoped detail endpoint
 * (`GET /api/scans/:id`): the same evidence as {@link ScanDetail} minus the owner
 * email (the caller IS the owner). The read is gated on `user_id` so a caller can
 * only ever read their own scans.
 */
export interface UserScanDetail {
  readonly id: string
  readonly verdict: string
  readonly source: { readonly kind: string; readonly ref: string }
  readonly flagged: number
  readonly headHash: string
  readonly scannedAt: string
  readonly content: string | null
  /** The serialized `{ findings, chains, injections, reputation }` evidence. */
  readonly resultJson: string
}

/** The parsed shape of a `scan_details.result_json` payload. */
export interface StoredScanEvidence {
  readonly findings: readonly RuleFinding[]
  readonly chains: readonly LinkChain[]
  readonly injections: readonly InjectionFinding[]
  readonly reputation: readonly ReputationReport[]
}

/** Read a column as a string, defaulting to `''` for a malformed/absent value. */
function readString(row: Row, column: string): string {
  const value = row[column]
  return typeof value === 'string' ? value : ''
}

/**
 * Read a column as a string, preserving SQL `NULL` as `null` (distinct from an
 * absent/malformed value, which also reads as `null`). Used for the nullable
 * `scan_details.content` column, where `null` is a meaningful state (the content
 * was unavailable, e.g. a verdict-cache hit) rather than the empty string.
 */
function readNullableString(row: Row, column: string): string | null {
  const value = row[column]
  return typeof value === 'string' ? value : null
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
 * response is computed, a failure here must be caught at the call site and must
 * never fail the scan.
 *
 * Time complexity: O(1), single indexed insert. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param row - The history row to persist.
 */
export async function insertScan(db: Database, row: ScanHistoryRow): Promise<void> {
  const statement = scanHistoryStatement(row)
  await db.execute(statement.sql, statement.params)
}

/**
 * Build the `scan_history` insert {@link BatchStatement} {@link insertScan} runs,
 * exposed so the scan write path can include it in an atomic {@link Database.batch}.
 * Produces byte-identical SQL to the standalone insert.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function scanHistoryStatement(row: ScanHistoryRow): BatchStatement {
  return {
    sql:
      'INSERT INTO scan_history ' +
      '(id, user_id, verdict, source_kind, source_ref, flagged, head_hash, scanned_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    params: [
      row.id,
      row.userId,
      row.verdict,
      row.sourceKind,
      row.sourceRef,
      row.flagged,
      row.headHash,
      row.scannedAt,
    ],
  }
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

/**
 * Insert one caught-scan detail row (the scanned content + serialized evidence).
 *
 * A single insert keyed on `scan_id` (the paired `scan_history.id`). The caller
 * invokes this best-effort AFTER the `scan_history` row is written and ONLY for a
 * non-clean (verdict != `ALLOW`) AUTHENTICATED scan, clean and anonymous scans
 * are never recorded here (CLAUDE.md §6 privacy). A failure here must be caught
 * at the call site and must never fail the scan response.
 *
 * Idempotent for a given `scanId`: the `scan_id` primary key means a replay with
 * the same id is a no-op via `ON CONFLICT DO NOTHING` (a re-scan mints a fresh
 * `scan_history` id, so it is a distinct detail row, never an overwrite).
 *
 * Time complexity: O(1), single indexed insert. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param row - The detail row to persist (content already truncated by caller).
 */
export async function insertScanDetail(db: Database, row: ScanDetailRow): Promise<void> {
  const statement = scanDetailStatement(row)
  await db.execute(statement.sql, statement.params)
}

/**
 * Build the `scan_details` insert {@link BatchStatement} {@link insertScanDetail}
 * runs, exposed so the scan write path can include it in an atomic
 * {@link Database.batch}. Produces byte-identical SQL (incl. the
 * `ON CONFLICT (scan_id) DO NOTHING` idempotency guard) to the standalone insert.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function scanDetailStatement(row: ScanDetailRow): BatchStatement {
  return {
    sql:
      'INSERT INTO scan_details (scan_id, content, result_json, created_at) ' +
      'VALUES (?, ?, ?, ?) ON CONFLICT (scan_id) DO NOTHING',
    params: [row.scanId, row.content, row.resultJson, row.createdAt],
  }
}

/**
 * Read one caught-scan detail by its scan id, joined to the recorded scan and its
 * owner's email, or `null` when no detail row exists for that id.
 *
 * One INNER JOIN `scan_details → scan_history → users` on the scan id / user id:
 * `scan_details` carries the content + evidence, `scan_history` the
 * verdict/source/proof, and `users` the owner email. A detail whose scan or owner
 * has been removed is excluded (it can no longer be attributed), reading as
 * `null`, a 404 at the route.
 *
 * Time complexity: O(1), three primary-key/indexed lookups. Space complexity:
 * O(d) in the stored content length.
 *
 * @param db - The persistence seam.
 * @param scanId - The `scan_history.id` (= `scan_details.scan_id`) to read.
 * @returns The joined detail, or `null` when absent / unattributable.
 */
export async function getScanDetail(db: Database, scanId: string): Promise<ScanDetail | null> {
  const row = await db.queryOne(
    'SELECT s.id AS id, u.email AS email, s.verdict AS verdict, ' +
      's.source_kind AS source_kind, s.source_ref AS source_ref, ' +
      's.flagged AS flagged, s.head_hash AS head_hash, s.scanned_at AS scanned_at, ' +
      'd.content AS content, d.result_json AS result_json ' +
      'FROM scan_details d ' +
      'JOIN scan_history s ON s.id = d.scan_id ' +
      'JOIN users u ON u.id = s.user_id ' +
      'WHERE d.scan_id = ?',
    [scanId],
  )
  if (row === null) {
    return null
  }
  return {
    id: readString(row, 'id'),
    email: readString(row, 'email'),
    verdict: readString(row, 'verdict'),
    source: { kind: readString(row, 'source_kind'), ref: readString(row, 'source_ref') },
    flagged: readCount(row, 'flagged'),
    headHash: readString(row, 'head_hash'),
    scannedAt: readString(row, 'scanned_at'),
    content: readNullableString(row, 'content'),
    resultJson: readString(row, 'result_json'),
  }
}

/**
 * Read one of the CALLER'S OWN caught-scan details by scan id, or `null` when no
 * detail row exists for that id OR the scan is not owned by `userId`.
 *
 * One INNER JOIN `scan_details → scan_history` on the scan id, with the ownership
 * check `s.user_id = ?` in the query itself so a scan belonging to another
 * account reads as `null` (a 404 at the route) and never leaks a peer's evidence.
 * No `users` join is needed: the owner is the authenticated caller.
 *
 * Time complexity: O(1), two primary-key/indexed lookups. Space complexity: O(d)
 * in the stored content length.
 *
 * @param db - The persistence seam.
 * @param scanId - The `scan_history.id` (= `scan_details.scan_id`) to read.
 * @param userId - The authenticated account id; the scan must belong to it.
 * @returns The joined owner-scoped detail, or `null` when absent / not owned.
 */
export async function getUserScanDetail(
  db: Database,
  scanId: string,
  userId: string,
): Promise<UserScanDetail | null> {
  const row = await db.queryOne(
    'SELECT s.id AS id, s.verdict AS verdict, ' +
      's.source_kind AS source_kind, s.source_ref AS source_ref, ' +
      's.flagged AS flagged, s.head_hash AS head_hash, s.scanned_at AS scanned_at, ' +
      'd.content AS content, d.result_json AS result_json ' +
      'FROM scan_details d ' +
      'JOIN scan_history s ON s.id = d.scan_id ' +
      'WHERE d.scan_id = ? AND s.user_id = ?',
    [scanId, userId],
  )
  if (row === null) {
    return null
  }
  return {
    id: readString(row, 'id'),
    verdict: readString(row, 'verdict'),
    source: { kind: readString(row, 'source_kind'), ref: readString(row, 'source_ref') },
    flagged: readCount(row, 'flagged'),
    headHash: readString(row, 'head_hash'),
    scannedAt: readString(row, 'scanned_at'),
    content: readNullableString(row, 'content'),
    resultJson: readString(row, 'result_json'),
  }
}

/**
 * Parse a stored `result_json` string into the structured evidence shape. A
 * corrupt / non-object payload yields empty arrays for every field rather than
 * throwing: a malformed evidence blob must not fail the detail read; the rest of
 * the row (verdict, source, proof, content) is still useful for review. Shared by
 * the admin threat-detail and the owner-scoped scan-detail routes so the parse is
 * identical.
 *
 * Time complexity: O(n) in the JSON length. Space complexity: O(n).
 *
 * @param resultJson - The stored `scan_details.result_json` string.
 * @returns The parsed evidence, or all-empty arrays on a malformed payload.
 */
export function parseScanEvidence(resultJson: string): StoredScanEvidence {
  let raw: unknown
  try {
    raw = JSON.parse(resultJson)
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.warn('scans', 'unparseable result_json; empty evidence', { errorClass: className })
    return { findings: [], chains: [], injections: [], reputation: [] }
  }
  const obj = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>) : {}
  const asArray = <T>(value: unknown): readonly T[] => (Array.isArray(value) ? (value as T[]) : [])
  return {
    findings: asArray<RuleFinding>(obj['findings']),
    chains: asArray<LinkChain>(obj['chains']),
    injections: asArray<InjectionFinding>(obj['injections']),
    reputation: asArray<ReputationReport>(obj['reputation']),
  }
}
