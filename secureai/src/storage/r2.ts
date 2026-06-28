/**
 * R2 object-storage offload for caught-scan content.
 *
 * D1 only ever stores a TRUNCATED preview of flagged scan content (bounded by
 * `SCANNER_DETAIL_MAX_BYTES`) to keep the row store lean. When R2 is enabled, the
 * FULL untruncated content of a caught (non-clean, authenticated) scan is written
 * to object storage, keyed by the scan id, so an admin can review the complete
 * payload while D1 keeps only the cheap preview + pointer.
 *
 * Privacy (CLAUDE.md §6): this stores MORE than the D1 preview, so it is gated
 * behind `SCANNER_R2_ENABLED` and applies only to already-flagged, authenticated
 * scans (never clean or anonymous ones). All operations are best-effort — a
 * failure is logged and swallowed so object storage never fails a scan or an
 * admin read; the caller falls back to the D1 preview.
 */

import { log } from '../observability/logger'

/**
 * The minimal R2 surface used here (structural subset of `R2Bucket`): `put` a
 * string body and `get` an object whose body can be read as text. Declared
 * structurally so a `{ put, get }` fake can be injected in tests.
 */
export interface ObjectStore {
  put(key: string, value: string): Promise<unknown>
  get(key: string): Promise<{ text(): Promise<string> } | null>
}

/** Key prefix for caught-scan content objects. */
const KEY_PREFIX = 'scan-content/'

/** The R2 object key for a scan's full content. */
function contentKey(scanId: string): string {
  return `${KEY_PREFIX}${scanId}`
}

/**
 * Persist the full scan content for `scanId`, best-effort. A failure is logged
 * (class only — never the content) and swallowed: object storage must never fail
 * the scan, and the D1 preview remains the durable record.
 *
 * Time complexity: O(n) in the content length (one PUT). Space complexity: O(n).
 */
export async function putScanContent(
  store: ObjectStore,
  scanId: string,
  content: string,
): Promise<void> {
  try {
    await store.put(contentKey(scanId), content)
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.warn('r2', 'scan-content put failed; D1 preview remains the record', { errorClass: className })
  }
}

/**
 * Read the full scan content for `scanId`, or `null` when absent / on any error.
 * Best-effort: a fault returns `null` so the admin read falls back to the D1
 * preview rather than failing.
 *
 * Time complexity: O(n) in the stored content length (one GET). Space O(n).
 */
export async function getScanContent(store: ObjectStore, scanId: string): Promise<string | null> {
  try {
    const object = await store.get(contentKey(scanId))
    return object === null ? null : await object.text()
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.warn('r2', 'scan-content get failed; falling back to the D1 preview', { errorClass: className })
    return null
  }
}
