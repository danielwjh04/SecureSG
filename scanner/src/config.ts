/**
 * The single home for every configurable literal the SPA needs: API paths, the
 * gallery data location, the scan progress step labels, and the animation
 * pacing. No component hardcodes any of these — they import from here so the
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
  logout: `${API_BASE}/api/logout`,
  me: `${API_BASE}/api/me`,
  stats: `${API_BASE}/api/stats`,
  rotateKey: `${API_BASE}/api/key/rotate`,
  checkout: `${API_BASE}/api/checkout`,
  adminOverview: `${API_BASE}/api/admin/overview`,
} as const

/** Where to email enterprise sales when the Pricing page Contact CTA is used. */
export const ENTERPRISE_CONTACT_EMAIL = 'sales@secureai.example' as const

/** How many trailing days the dashboard trend chart covers (zero-filled). */
export const STATS_TREND_DAYS = 30

/** Static path to the prebuilt gallery dataset shipped alongside the SPA. */
export const GALLERY_DATA_PATH = '/gallery.json' as const

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

/** Public source repository, linked from the navbar. */
export const REPO_URL = 'https://github.com/danielwjh04/SecureAI' as const

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
  'Querying reputation',
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
 * the authority — the Worker enforces the real bounds.
 */
export const CAPS = {
  redirectDepth: 'Redirect cascades traced up to a bounded depth',
  reputationFanOut: 'Reputation queried for final destinations only',
  injectionContent: 'Prompt-injection check runs on the parsed skill text',
} as const
