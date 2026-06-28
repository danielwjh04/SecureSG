export function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const VERDICT_CLASS: Record<string, string> = {
  ALLOW: 'pill--allow',
  HUMAN_APPROVAL_REQUIRED: 'pill--approval',
  BLOCK: 'pill--block',
}

export function verdictClass(verdict: string): string {
  return VERDICT_CLASS[verdict] ?? 'pill--approval'
}

export function verdictLabel(verdict: string): string {
  return verdict === 'HUMAN_APPROVAL_REQUIRED' ? 'APPROVAL' : verdict
}

/**
 * Extract a display hostname from a URL string.
 *
 * Falls back to the raw input when the value is not a parseable absolute URL
 * (e.g. a bare host or a malformed redirect target), so the UI always renders
 * something rather than throwing.
 *
 * Time complexity: O(n) in the URL length. Space complexity: O(1).
 */
export function hostname(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

/**
 * Shorten a hex digest for display as `head…tail`.
 *
 * Hashes shorter than the combined head+tail window are returned unchanged so
 * no characters are ever silently dropped.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function truncateHash(hex: string): string {
  const head = 8
  const tail = 6
  if (hex.length <= head + tail + 1) return hex
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`
}

/**
 * Render an ISO timestamp as a compact relative time against `now`:
 * "just now" (< 1 min), "Nm ago", "Nh ago", "Nd ago" up to a week, then a short
 * absolute date. An unparseable timestamp is returned verbatim so the UI never
 * shows "NaN ago". A future timestamp (clock skew) reads as "just now".
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso
  const seconds = Math.max(0, Math.floor((now - then) / 1000))
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  if (hours < 24) return `${hours}h ago`
  if (days < 7) return `${days}d ago`
  const date = new Date(then)
  return date.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' })
}
