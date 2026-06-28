/**
 * Tier gating and daily-cap enforcement shared by the metered scan routes.
 *
 * Two cost-discipline decisions live here so `/api/scan` and `/api/guard` apply
 * them identically:
 *   1. {@link capForTier} — the per-tier daily scan cap (enterprise is
 *      unmetered, returning {@link UNLIMITED}).
 *   2. {@link enforceDailyCap} — fail-closed cap check BEFORE any scan runs,
 *      throwing {@link QuotaExceededError} (→ 429) at or above the cap.
 *   3. {@link aiAllowedForTier} — whether the caller's tier may invoke the paid
 *      AI stage, gated by `config.aiTiers`.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { AuthTier } from './auth'
import { QuotaExceededError } from '../errors'
import { getUsage } from '../db/usage'

/** Sentinel cap meaning "no daily limit" (enterprise tier). */
export const UNLIMITED = Number.POSITIVE_INFINITY

/**
 * The daily metered-scan cap for a tier. Anonymous / free / pro caps come from
 * config; enterprise is unmetered ({@link UNLIMITED}). The mapping is exhaustive
 * over {@link AuthTier} so a new tier cannot silently fall through.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function capForTier(tier: AuthTier, config: ScannerConfig): number {
  switch (tier) {
    case 'anonymous':
      return config.capAnonymousPerDay
    case 'free':
      return config.capFreePerDay
    case 'pro':
      return config.capProPerDay
    case 'enterprise':
      return UNLIMITED
  }
}

/**
 * Whether `tier` is granted the paid AI stage, per `config.aiTiers`. Anonymous
 * callers are never eligible regardless of config. Enterprise is included only
 * if `aiTiers` lists it — the gate is purely config-driven for paid tiers.
 *
 * Time complexity: O(1) — set membership. Space complexity: O(1).
 */
export function aiAllowedForTier(tier: AuthTier, config: ScannerConfig): boolean {
  if (tier === 'anonymous') {
    return false
  }
  return config.aiTiers.has(tier)
}

/**
 * Enforce the subject's daily cap BEFORE running a scan. Reads the subject's
 * `scans` for `day` and throws {@link QuotaExceededError} when the count is at
 * or above the tier cap. An unmetered tier ({@link UNLIMITED}) short-circuits
 * with no read.
 *
 * Time complexity: O(1) — at most one `(subject, day)` lookup.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param subject - User id, or `anon:<ip>`.
 * @param tier - The caller's tier (selects the cap).
 * @param day - UTC `YYYY-MM-DD` string, supplied by the route edge.
 * @param config - Resolved config holding the per-tier caps.
 * @throws {QuotaExceededError} When the subject is at or above its daily cap.
 */
export async function enforceDailyCap(
  db: Database,
  subject: string,
  tier: AuthTier,
  day: string,
  config: ScannerConfig,
): Promise<void> {
  const cap = capForTier(tier, config)
  if (cap === UNLIMITED) {
    return
  }
  const usage = await getUsage(db, subject, day)
  if (usage.scans >= cap) {
    throw new QuotaExceededError(
      `daily scan cap reached for tier '${tier}': ${usage.scans}/${cap}`,
    )
  }
}
