/**
 * The single home for every configurable literal the SPA needs: API paths, the
 * gallery data location, the scan progress step labels, and the animation
 * pacing. No component hardcodes any of these, they import from here so the
 * worker contract and the UI copy stay in lockstep.
 */

/**
 * API base URL. Empty string (the default) keeps the API same-origin: the
 * Worker serves both the SPA and the routes. Set it to the SecureAI Worker's
 * origin (e.g. `https://secureai.example`) to point the SPA at a remote
 * backend. No remote URL is hardcoded here.
 */
export const API_BASE = '' as const

/**
 * API endpoints, prefixed with {@link API_BASE}. With the default empty base
 * these resolve to same-origin relative paths.
 */
export const API = {
  scan: `${API_BASE}/api/scan`,
  verify: `${API_BASE}/api/verify`,
  register: `${API_BASE}/api/register`,
  login: `${API_BASE}/api/login`,
  loginVerify: `${API_BASE}/api/login/verify`,
  loginResend: `${API_BASE}/api/login/resend`,
  logout: `${API_BASE}/api/logout`,
  me: `${API_BASE}/api/me`,
  stats: `${API_BASE}/api/stats`,
  recentScans: `${API_BASE}/api/scans/recent`,
  rotateKey: `${API_BASE}/api/key/rotate`,
  checkout: `${API_BASE}/api/checkout`,
  portal: `${API_BASE}/api/portal`,
  billingChange: `${API_BASE}/api/billing/change`,
  billingCancel: `${API_BASE}/api/billing/cancel`,
  billingSubscription: `${API_BASE}/api/billing/subscription`,
  contact: `${API_BASE}/api/contact`,
  adminOverview: `${API_BASE}/api/admin/overview`,
  adminMembers: `${API_BASE}/api/admin/members`,
  adminMemberRole: `${API_BASE}/api/admin/members/role`,
  adminMemberTier: `${API_BASE}/api/admin/members/tier`,
  adminMemberRemove: `${API_BASE}/api/admin/members/remove`,
  adminThreats: `${API_BASE}/api/admin/threats`,
} as const

/**
 * The admin per-scan detail endpoint, `GET /api/admin/scans/<id>`. Parameterized
 * by the scan id (the {@link AdminThreat} row's `id`), so it is a builder rather
 * than a static path. The id is percent-encoded so an unexpected character in a
 * stored id can never break out of the path segment.
 */
export function adminScanDetailPath(id: string): string {
  return `${API_BASE}/api/admin/scans/${encodeURIComponent(id)}`
}

/**
 * The owner-scoped per-scan detail endpoint, `GET /api/scans/<id>`, the "block
 * report" the Activity view opens for one of the caller's OWN scans (only
 * BLOCK/REVIEW scans retain a detail). Parameterized by the scan id, so it is a
 * builder; the id is percent-encoded so an unexpected character can never break
 * out of the path segment.
 */
export function scanDetailPath(id: string): string {
  return `${API_BASE}/api/scans/${encodeURIComponent(id)}`
}

/** How many trailing days the dashboard trend chart covers (zero-filled). */
export const STATS_TREND_DAYS = 30

/** How many recent scans the dashboard's recent-scans list requests. */
export const RECENT_SCANS_LIMIT = 3

/**
 * Debounce window (ms) before an admin search input refetches. Keeps the
 * members/threats search off the keystroke hot path: the query is only sent once
 * typing pauses, so a fast typist triggers one request, not one per character.
 */
export const ADMIN_SEARCH_DEBOUNCE_MS = 300

/**
 * Default page size for the admin blocked-threats report. The worker clamps the
 * authoritative cap; this is the display request so the report shows the newest
 * blocked threats first and only fetches more on demand.
 */
export const ADMIN_THREATS_LIMIT = 50

/** Static path to the prebuilt gallery dataset shipped alongside the SPA. */
export const GALLERY_DATA_PATH = '/gallery.json' as const

/**
 * Static path to the real-world AI-agent incident list rendered on the landing
 * page's "It's already happening" section. A public JSON asset (like the gallery)
 * so the list is edited as data, not code, and every entry is a real, sourced
 * event with a link. Reuses the gallery fetch timeout/attempts.
 */
export const INCIDENTS_DATA_PATH = '/incidents.json' as const

/**
 * Per-attempt timeout (ms) and attempt count for loading the gallery dataset.
 * `fetch` has no inherent timeout, so a stalled request (e.g. a connection-pool
 * stall after a heavy result view) would otherwise leave the gallery stuck on
 * its loading line forever. A bounded retry recovers from a transient stall;
 * exhausting the attempts degrades to the empty "coming soon" state.
 */
export const GALLERY_FETCH_TIMEOUT_MS = 6000
export const GALLERY_FETCH_ATTEMPTS = 3

/**
 * Fullscreen hero background video. An HLS stream (Mux); non-Safari browsers
 * need hls.js to play it (see {@link BackgroundVideo}).
 */
export const BACKGROUND_VIDEO_SRC =
  'https://stream.mux.com/kimF2ha9zLrX64H00UgLGPflCzNtl1T0215MlAmeOztv8.m3u8' as const

/**
 * The SecureAI Guard install surface. `GUARD_DOWNLOAD_PATH` is the same-origin
 * path the Guard hook script is served from (a static public asset), so the
 * member dashboard's "Download the Guard" button resolves it against the current
 * origin. `GUARD_INSTALL_URL` is the absolute URL of the one-line installer
 * (`install.sh`) that wires selected endpoint hooks; it must be absolute
 * because `curl` runs it from the user's own shell, and it is the public
 * SecureAI host, not a secret.
 */
export const GUARD_DOWNLOAD_PATH = '/secureai-guard.mjs' as const
export const GUARD_INSTALL_URL =
  'https://secureai.software/install.sh' as const
export const BROWSER_EXTENSION_STORE_URL = '' as const
export const BROWSER_PAIRING_HASH = '#browser-pair=' as const

/** The public source repository, linked from the site footer. */
export const REPO_URL = 'https://github.com/danielwjh04/SecureAI' as const

/**
 * Build the key-embedded one-line Guard installer the member dashboard reveals
 * after minting a fresh API key. The installer reads the key from the
 * `SECUREAI_API_KEY` environment variable, so it is exported into the piped
 * `bash` rather than passed as an argument. The raw key is only ever available
 * at mint time, so this command is the single moment it can be embedded.
 *
 * The key is wrapped in double quotes so a shell never word-splits or globs it;
 * minted keys are an opaque token alphabet (no quotes), so no further escaping is
 * required.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function guardInstallCommand(apiKey: string): string {
  return `curl -fsSL ${GUARD_INSTALL_URL} | SECUREAI_API_KEY="${apiKey}" bash`
}

/** Build the browser-extension pairing link for a freshly minted API key. */
export function browserPairingUrl(apiKey: string): string {
  return `${window.location.origin}/${BROWSER_PAIRING_HASH}${encodeURIComponent(apiKey)}`
}

/**
 * The three skill-input modes offered by the hero's segmented control. The
 * `content`/`url` modes map to the scan request fields; `file` loads a `.md`
 * into the `content` path.
 */
export const INPUT_MODES = [
  { id: 'paste', label: 'Paste' },
  { id: 'url', label: 'URL' },
  { id: 'file', label: 'Upload .md' },
] as const

export type InputModeId = (typeof INPUT_MODES)[number]['id']

/**
 * Ordered labels for the scan progress stepper. The order mirrors the proof
 * step kinds the Worker emits, so the animation reads as the real pipeline.
 */
export const SCAN_STEP_LABELS = [
  'Parsing SKILL.md',
  'Extracting links',
  'Resolving redirect cascades',
  'Screening known-bad indicators',
  'Running prompt-injection check',
  'Sealing proof chain',
] as const

/**
 * Milliseconds between progress-step advances (decoupled from scan latency). A
 * live scan (GitHub resolve + redirect traces + reputation + AI analysis) runs
 * ~10-15s, so the stepper is paced to walk the pipeline over several seconds and
 * then hold on the injection-check stage (see the scan machine) rather than
 * racing to the end in under a second and sitting frozen on the final stage.
 */
export const SCAN_STEP_PACING_MS = 1500

/**
 * Client-side ceiling for an uploaded SKILL.md, in bytes. Mirrors the worker's
 * default skill-size cap so an oversized file is rejected before it is loaded
 * into the editor; the worker enforces the authoritative limit.
 */
export const UPLOAD_MAX_BYTES = 100_000

/**
 * Debounce window before the proof inspector re-hashes the chain after an edit.
 * Keeps the in-browser `verifyChain` pass off the keystroke hot path without
 * feeling laggy.
 */
export const PROOF_REHASH_DEBOUNCE_MS = 180

/**
 * The scanner's safety caps, surfaced in the UI so users see the bounded
 * guarantees of each pass. These mirror the worker's enforced limits (redirect
 * depth, reputation fan-out, analyzed content size); they are display copy, not
 * the authority, the Worker enforces the real bounds.
 */
export const CAPS = {
  redirectDepth: 'Redirect cascades traced up to a bounded depth',
  reputationFanOut: 'Known-bad indicators matched on final destinations only',
  injectionContent: 'Prompt-injection check runs on the parsed skill text',
} as const
