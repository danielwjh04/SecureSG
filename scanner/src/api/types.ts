/**
 * The SPA's type surface. Re-exports the shared proof-core contract so every
 * component imports its types from one app-local path, then adds the gallery
 * shapes the SPA needs but the worker contract does not define.
 *
 * `contract.ts` is types-only, so it is re-exported with `export type *` (which
 * verbatimModuleSyntax requires for type-only modules). `proof.ts` also exports
 * runtime values (`verifyChain`, `ProofBuilder`), so its symbols are re-exported
 * with a plain `export *`.
 */

export type * from '../../shared/contract'
export * from '../../shared/proof'

import type { ScanResult } from '../../shared/contract'

/** One entry in the curated scan gallery (a recorded benign or attack scan). */
export interface GalleryEntry {
  id: string
  title: string
  tag: 'benign' | 'attack'
  result: ScanResult
}

/** The full gallery dataset loaded from {@link GALLERY_DATA_PATH}. */
export interface GalleryData {
  generatedAt: string
  entries: GalleryEntry[]
}

/** The account tier returned by the auth + stats endpoints. */
export type AccountTier = 'free' | 'pro' | 'enterprise'

/** The minimal user identity returned by register/login. */
export interface AuthUser {
  email: string
  tier: AccountTier
}

/** Response body for `POST /api/register` and `POST /api/login`. */
export interface AuthResponse {
  user: AuthUser
}

/** Response body for `GET /api/me`: the signed-in account. */
export interface MeResponse {
  email: string
  tier: AccountTier
  createdAt: string
  /** The non-secret prefix of the account's API key, safe to display. */
  apiKeyPrefix: string
}

/** The credentials body for register/login. */
export interface AuthCredentials {
  email: string
  password: string
}

/** One day's verdict tallies in the protection-stats trend series. */
export interface StatsDay {
  /** ISO calendar day, `YYYY-MM-DD`. */
  day: string
  scans: number
  allows: number
  reviews: number
  blocks: number
  flagged: number
}

/** Lifetime verdict totals across the account. */
export interface StatsTotals {
  scans: number
  allows: number
  reviews: number
  blocks: number
  flagged: number
}

/** Response body for `GET /api/stats`: the account's protection metrics. */
export interface StatsResponse {
  tier: AccountTier
  totals: StatsTotals
  daily: StatsDay[]
}

/** Response body for `POST /api/key/rotate`: the freshly minted key, shown once. */
export interface RotateKeyResponse {
  apiKey: string
}

/** Response body for `POST /api/checkout`: the Stripe checkout URL. */
export interface CheckoutResponse {
  url: string
}
