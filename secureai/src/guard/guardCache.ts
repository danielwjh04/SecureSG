/**
 * Edge cache for {@link GuardDecision}s — the guard-route analogue of the scan
 * {@link ../scanner/verdictCache}. The guard is the latency-critical inline path
 * (Claude Code blocks on it before every tool call), so caching a repeated
 * identical decision skips the redirect trace + AI compute and returns in O(1).
 *
 * It caches the DECISION only; the route still authenticates, enforces the daily
 * cap, and meters usage on a hit (those live in the route, not here). The key is
 * `guard:v1:` + sha256(canonical({tool_name, tool_input})) — only the
 * load-bearing scannable fields, so field ordering / unrelated context never
 * perturbs it. Unlike a scan result a {@link GuardDecision} carries no
 * time-varying field, so the cached value is returned verbatim.
 *
 * Security tradeoff (same as the verdict cache): a short TTL bounds how long a
 * denylist/indicator change can be masked; `0` disables the cache.
 */

import type { PreToolUsePayload } from '../schemas/validate'
import type { GuardDecision } from './claudeCode'
import { canonicalJson } from '../audit/chain'

/** Namespaced, versioned prefix for every guard-decision cache key. */
const CACHE_KEY_PREFIX = 'guard:v1:'

const textEncoder = new TextEncoder()

/** The minimal KV surface the guard cache uses (injectable `{ get, put }` fake). */
export interface GuardCacheKv {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/** Lowercase-hex SHA-256 of a UTF-8 string (fixed-length cache key from payload). */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  let hex = ''
  for (const byte of new Uint8Array(digest)) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Derive the cache key from ONLY the scannable fields of a PreToolUse payload:
 * the tool name and its input record. The context fields (`session_id`, `cwd`, …)
 * never enter the key, so the same tool call from different sessions shares an entry.
 *
 * Time complexity: O(n) in the payload byte length. Space complexity: O(n).
 */
export async function cacheKeyForPayload(payload: PreToolUsePayload): Promise<string> {
  const scannable = { tool_name: payload.tool_name, tool_input: payload.tool_input }
  return CACHE_KEY_PREFIX + (await sha256Hex(canonicalJson(scannable)))
}

/** Parse a cached decision, or `null` (treated as a MISS) on a corrupt entry. */
function parseCached(value: string): GuardDecision | null {
  try {
    return JSON.parse(value) as GuardDecision
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.warn(`[guardCache] discarding unparseable cache entry (${className})`)
    return null
  }
}

/**
 * Resolve a guard decision, serving from cache when available and recomputing
 * (then populating the cache) on a miss. Does NOT meter, cap, or authenticate —
 * those run in the route on a hit just as on a miss; only `compute()` is skipped.
 *
 * Resolution:
 *   - Cache disabled (no KV, or `ttlSeconds <= 0`): always `compute()`.
 *   - HIT: return the cached {@link GuardDecision} verbatim.
 *   - MISS: `compute()`, write the serialized decision with `expirationTtl`, return it.
 *
 * Time complexity: one KV read (+ one write on a miss) plus `compute()` on a
 *   miss. Space complexity: O(decision size).
 */
export async function resolveCachedDecision(
  payload: PreToolUsePayload,
  kv: GuardCacheKv | null,
  ttlSeconds: number,
  compute: () => Promise<GuardDecision>,
): Promise<GuardDecision> {
  if (kv === null || ttlSeconds <= 0) {
    return compute()
  }
  const key = await cacheKeyForPayload(payload)
  const hit = await kv.get(key)
  if (hit !== null) {
    const parsed = parseCached(hit)
    if (parsed !== null) {
      return parsed
    }
  }
  const decision = await compute()
  await kv.put(key, JSON.stringify(decision), { expirationTtl: ttlSeconds })
  return decision
}
