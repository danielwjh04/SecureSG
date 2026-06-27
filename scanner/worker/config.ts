/**
 * Runtime configuration for the Skill Safety Scanner Worker, loaded from the
 * environment.
 *
 * Every configurable value lives here (per CLAUDE.md: no hardcoded literals in
 * logic). `loadConfig` is the single entry point: it reads each field from a
 * `SCANNER_*` env var, falls back to a documented default, validates ranges,
 * and throws `ConfigError` on any bad value. This mirrors the model-validator
 * discipline of `secureSG/config/settings.py` — fail-closed at startup rather
 * than carrying an invalid config into a request path.
 *
 * Security invariants that must never be weakened — the proof hash algorithm —
 * are pinned constants here, deliberately *not* exposed as env-overridable.
 */

import { ConfigError } from './errors'

/**
 * The Worker's environment bindings. `ASSETS` serves the built SPA; the two
 * sponsor keys are optional at the binding level (a missing key is a
 * fail-closed runtime condition handled by the Exa/judge clients, not a config
 * fault), so they are typed optional here. The index signature admits the
 * `SCANNER_*` tunables, which arrive as strings.
 */
export interface Env {
  ASSETS: Fetcher
  EXA_API_KEY?: string
  OPENAI_API_KEY?: string
  /** Optional GitHub token (any scope) to lift the API rate limit to 5000/hr. */
  GITHUB_TOKEN?: string
  [k: string]: unknown
}

/**
 * Fully-resolved, validated scanner configuration. Every field is non-optional
 * here: `loadConfig` has already applied defaults and checked ranges, so
 * downstream code never re-validates or re-defaults.
 */
export interface ScannerConfig {
  /** Proof hash algorithm. Pinned to 'SHA-256' — never env-overridable. */
  readonly hashAlgorithm: 'SHA-256'
  /** Seed for the proof-chain genesis hash; changing it starts a new chain. */
  readonly genesisSeed: string
  /** Max URLs extracted-and-traced per skill (subrequest budget input). */
  readonly maxUrls: number
  /** Max redirect hops traced per URL before `depthExceeded` (budget input). */
  readonly maxRedirectHops: number
  /** Per-hop redirect fetch timeout, milliseconds. */
  readonly redirectTimeoutMs: number
  /** Allowlisted URL schemes; everything else is rejected by the SSRF guard. */
  readonly allowedSchemes: readonly string[]
  /** Known URL-shortener hosts that warrant extra redirect scrutiny. */
  readonly shortenerHosts: readonly string[]
  /** Max characters of page text Exa returns per URL. */
  readonly exaMaxCharacters: number
  /** Exa content freshness ceiling, hours (0 = always livecrawl). */
  readonly exaMaxAgeHours: number
  /** Exa livecrawl timeout, milliseconds. */
  readonly exaLivecrawlTimeoutMs: number
  /** OpenAI judge model id. */
  readonly openaiModel: string
  /** OpenAI judge request timeout, milliseconds. */
  readonly openaiTimeoutMs: number
  /** p(injection) at/above which the judge escalates to HUMAN_APPROVAL. */
  readonly judgeReviewThreshold: number
  /** p(injection) at/above which the judge escalates to BLOCK. */
  readonly judgeBlockThreshold: number
  /** Max bytes of skill content accepted by the parser. */
  readonly skillMaxBytes: number
  /** Cloudflare free-plan subrequest ceiling the budget must stay under. */
  readonly subrequestCap: number
}

const HASH_ALGORITHM = 'SHA-256' as const
/** Audit/proof hash algorithm. SHA-256 only — never weaken (CLAUDE.md §6). */

const ENV_PREFIX = 'SCANNER_'

/** Documented defaults, applied when the corresponding env var is unset. */
const DEFAULTS = {
  genesisSeed: 'securesg-scanner-genesis-v1',
  maxUrls: 8,
  maxRedirectHops: 5,
  redirectTimeoutMs: 5000,
  allowedSchemes: ['https'],
  shortenerHosts: [
    'bit.ly',
    't.co',
    'tinyurl.com',
    'goo.gl',
    'ow.ly',
    'is.gd',
    'buff.ly',
    'rebrand.ly',
  ],
  exaMaxCharacters: 2000,
  exaMaxAgeHours: 0,
  exaLivecrawlTimeoutMs: 12000,
  openaiModel: 'gpt-5.5',
  openaiTimeoutMs: 20000,
  judgeReviewThreshold: 0.5,
  judgeBlockThreshold: 0.8,
  skillMaxBytes: 100000,
  subrequestCap: 50,
} as const

/**
 * Read a raw string env var by its un-prefixed name, or `undefined` if unset or
 * blank. Whitespace-only values are treated as unset so an empty line in a
 * `.dev.vars` file falls through to the default.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function readRaw(env: Env, field: string): string | undefined {
  const value = env[ENV_PREFIX + field]
  if (typeof value !== 'string') {
    return undefined
  }
  const trimmed = value.trim()
  return trimmed.length === 0 ? undefined : trimmed
}

/**
 * Parse a comma-separated env list into a deduplicated, lowercased,
 * blank-stripped string array. Used for `allowedSchemes` and `shortenerHosts`.
 * Falls back to the supplied default when the var is unset or yields no items.
 *
 * Time complexity: O(n) in the number of items. Space complexity: O(n).
 *
 * @param env - The Worker environment.
 * @param field - Un-prefixed env var name (e.g. 'ALLOWED_SCHEMES').
 * @param fallback - Default list when unset/empty.
 * @returns A frozen, deduplicated, lowercased list.
 */
function parseList(
  env: Env,
  field: string,
  fallback: readonly string[],
): readonly string[] {
  const raw = readRaw(env, field)
  if (raw === undefined) {
    return Object.freeze([...fallback])
  }
  const items = raw
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter((item) => item.length > 0)
  if (items.length === 0) {
    return Object.freeze([...fallback])
  }
  return Object.freeze([...new Set(items)])
}

/**
 * Parse a string env var, falling back to a default when unset.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function parseString(env: Env, field: string, fallback: string): string {
  return readRaw(env, field) ?? fallback
}

/**
 * Parse an integer env var and assert it lies in `[min, max]` inclusive.
 * Rejects non-integers (floats, NaN, blank, garbage) and out-of-range values
 * with a `ConfigError` naming the field — fail-closed at load time.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @throws {ConfigError} when the value is not an integer in range.
 */
function parseIntInRange(
  env: Env,
  field: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = readRaw(env, field)
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isInteger(value)) {
    throw new ConfigError(
      `${ENV_PREFIX}${field} must be an integer; got '${raw ?? ''}'`,
    )
  }
  if (value < min || value > max) {
    throw new ConfigError(
      `${ENV_PREFIX}${field} must be in [${min}, ${max}]; got ${value}`,
    )
  }
  return value
}

/**
 * Parse a finite float env var and assert it lies in `[min, max]` inclusive.
 * Used for the judge thresholds. Cross-field threshold ordering is enforced
 * separately in `loadConfig`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @throws {ConfigError} when the value is not a finite number in range.
 */
function parseFloatInRange(
  env: Env,
  field: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = readRaw(env, field)
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isFinite(value)) {
    throw new ConfigError(
      `${ENV_PREFIX}${field} must be a number; got '${raw ?? ''}'`,
    )
  }
  if (value < min || value > max) {
    throw new ConfigError(
      `${ENV_PREFIX}${field} must be in [${min}, ${max}]; got ${value}`,
    )
  }
  return value
}

/**
 * Load and validate the scanner configuration from the Worker environment.
 *
 * Every field is read from a `SCANNER_*` env var with a documented default,
 * then range-checked. Two cross-field invariants are enforced last, mirroring
 * the model-validators in `secureSG/config/settings.py`:
 *   1. `0 < judgeReviewThreshold < judgeBlockThreshold <= 1` (monotone gates).
 *   2. `maxUrls * maxRedirectHops + 2 <= subrequestCap` (Cloudflare free-plan
 *      subrequest budget; the `+ 2` reserves the batched Exa call and the judge
 *      call). A config that could exceed the cap is rejected at load time.
 *
 * Time complexity: O(n) in the combined length of the list env vars.
 * Space complexity: O(n) for the parsed lists.
 *
 * @param env - The Worker environment bindings.
 * @returns A fully-resolved, validated `ScannerConfig`.
 * @throws {ConfigError} on any out-of-range or inconsistent value.
 */
export function loadConfig(env: Env): ScannerConfig {
  const genesisSeed = parseString(env, 'GENESIS_SEED', DEFAULTS.genesisSeed)
  const maxUrls = parseIntInRange(env, 'MAX_URLS', DEFAULTS.maxUrls, 1, 1024)
  const maxRedirectHops = parseIntInRange(
    env,
    'MAX_REDIRECT_HOPS',
    DEFAULTS.maxRedirectHops,
    1,
    64,
  )
  const redirectTimeoutMs = parseIntInRange(
    env,
    'REDIRECT_TIMEOUT_MS',
    DEFAULTS.redirectTimeoutMs,
    1,
    600000,
  )
  const allowedSchemes = parseList(
    env,
    'ALLOWED_SCHEMES',
    DEFAULTS.allowedSchemes,
  )
  const shortenerHosts = parseList(
    env,
    'URL_SHORTENERS',
    DEFAULTS.shortenerHosts,
  )
  const exaMaxCharacters = parseIntInRange(
    env,
    'EXA_MAX_CHARACTERS',
    DEFAULTS.exaMaxCharacters,
    1,
    1000000,
  )
  const exaMaxAgeHours = parseIntInRange(
    env,
    'EXA_MAX_AGE_HOURS',
    DEFAULTS.exaMaxAgeHours,
    0,
    8760,
  )
  const exaLivecrawlTimeoutMs = parseIntInRange(
    env,
    'EXA_TIMEOUT_MS',
    DEFAULTS.exaLivecrawlTimeoutMs,
    1,
    600000,
  )
  const openaiModel = parseString(env, 'OPENAI_MODEL', DEFAULTS.openaiModel)
  const openaiTimeoutMs = parseIntInRange(
    env,
    'JUDGE_TIMEOUT_MS',
    DEFAULTS.openaiTimeoutMs,
    1,
    600000,
  )
  const judgeReviewThreshold = parseFloatInRange(
    env,
    'REVIEW_THRESHOLD',
    DEFAULTS.judgeReviewThreshold,
    0,
    1,
  )
  const judgeBlockThreshold = parseFloatInRange(
    env,
    'BLOCK_THRESHOLD',
    DEFAULTS.judgeBlockThreshold,
    0,
    1,
  )
  const skillMaxBytes = parseIntInRange(
    env,
    'SKILL_MAX_BYTES',
    DEFAULTS.skillMaxBytes,
    1,
    100000000,
  )
  const subrequestCap = parseIntInRange(
    env,
    'SUBREQUEST_CAP',
    DEFAULTS.subrequestCap,
    1,
    1000,
  )

  // Cross-field invariant 1: monotone threshold gates, strictly 0 < review <
  // block <= 1 (matches `_validate_thresholds` in settings.py).
  if (
    !(
      judgeReviewThreshold > 0 &&
      judgeReviewThreshold < judgeBlockThreshold &&
      judgeBlockThreshold <= 1
    )
  ) {
    throw new ConfigError(
      'judge thresholds must satisfy 0 < judgeReviewThreshold < ' +
        `judgeBlockThreshold <= 1; got review=${judgeReviewThreshold}, ` +
        `block=${judgeBlockThreshold}`,
    )
  }

  // Cross-field invariant 2: the worst-case subrequest fan-out (every URL
  // traced to full hop depth) plus the reserved Exa + judge calls must stay
  // under the platform cap, or the scanner could be killed mid-request.
  const reservedSponsorSubrequests = 2
  const worstCaseSubrequests =
    maxUrls * maxRedirectHops + reservedSponsorSubrequests
  if (worstCaseSubrequests > subrequestCap) {
    throw new ConfigError(
      'subrequest budget exceeds cap: maxUrls * maxRedirectHops + 2 = ' +
        `${worstCaseSubrequests} > subrequestCap ${subrequestCap}`,
    )
  }

  return {
    hashAlgorithm: HASH_ALGORITHM,
    genesisSeed,
    maxUrls,
    maxRedirectHops,
    redirectTimeoutMs,
    allowedSchemes,
    shortenerHosts,
    exaMaxCharacters,
    exaMaxAgeHours,
    exaLivecrawlTimeoutMs,
    openaiModel,
    openaiTimeoutMs,
    judgeReviewThreshold,
    judgeBlockThreshold,
    skillMaxBytes,
    subrequestCap,
  }
}
