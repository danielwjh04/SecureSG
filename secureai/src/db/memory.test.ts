/**
 * In-memory fake of the Cloudflare D1 binding, plus its own self-tests.
 *
 * The fake implements the `prepare().bind().first()/run()` surface the
 * {@link d1Database} adapter calls, so tests exercise the SAME code path as
 * production: route → `d1Database(env.DB)` → repositories. It recognizes exactly
 * the statements the repositories emit (matched by stable substrings) and
 * applies them against plain `Map`s, faithfully modeling D1's
 * primary-key/upsert semantics. It is defined in a `.test.ts` file so it is
 * excluded from the production coverage surface yet importable by other suites.
 *
 * Use {@link memoryDatabase} to obtain a `(Database fake, MemoryStore)` pair, or
 * pass a {@link MemoryD1} instance directly as a fake `env.DB`.
 */

import { describe, expect, it } from 'vitest'
import type { Database, WriteResult } from './database'
import { d1Database } from './database'

interface UserRecord {
  id: string
  email: string
  tier: string
  /** Granted role column (migration 0005): defaults to 'member' on insert. */
  role: string
  stripe_customer_id: string | null
  created_at: string
  password_hash: string | null
  /**
   * Email-verification flag (migration 0008): 1 = verified, 0 = unverified. An
   * unverified account authenticates via neither its API key nor its session
   * cookie. DEFAULTs to 0 on a bare insert; createFreeUser / verified register
   * set 1, and markEmailVerified flips it to 1.
   */
  email_verified: number
}

interface ApiKeyRecord {
  key_sha256: string
  user_id: string
  status: string
  created_at: string
}

interface UsageRecord {
  subject: string
  day: string
  scans: number
  ai_scans: number
  allows: number
  reviews: number
  blocks: number
  flagged: number
}

interface SubscriptionRecord {
  user_id: string
  status: string
  price_id: string
  current_period_end: string | null
}

interface WebhookEventRecord {
  event_id: string
  type: string
  created_at: string
}

interface OtpChallengeRecord {
  id: string
  user_id: string
  code_hash: string
  expires_at: string
  attempts: number
  created_at: string
}

interface ScanHistoryRecord {
  id: string
  user_id: string
  verdict: string
  source_kind: string
  source_ref: string
  flagged: number
  head_hash: string
  scanned_at: string
}

interface ScanDetailRecord {
  scan_id: string
  content: string | null
  result_json: string
  created_at: string
}

/** Composite key for the usage map, mirroring the `(subject, day)` PK. */
function usageKey(subject: string, day: string): string {
  return `${subject} ${day}`
}

/**
 * Backing store for the fake. Exposed so assertions can confirm what was (and
 * was NOT) persisted — notably that no raw API key is ever stored.
 */
export class MemoryStore {
  public readonly users = new Map<string, UserRecord>()
  /** Keyed by `key_sha256`, so the raw key never appears as a key or value. */
  public readonly apiKeys = new Map<string, ApiKeyRecord>()
  /** Keyed by `${subject} ${day}`. */
  public readonly usage = new Map<string, UsageRecord>()
  /** Keyed by `user_id` (the subscription mirror's primary key). */
  public readonly subscriptions = new Map<string, SubscriptionRecord>()
  /** Keyed by Stripe `event_id` (the webhook idempotency ledger). */
  public readonly webhookEvents = new Map<string, WebhookEventRecord>()
  /** Keyed by challenge `id` (the 2FA OTP challenge store). */
  public readonly otpChallenges = new Map<string, OtpChallengeRecord>()
  /** Keyed by scan-history row `id` (the per-user recent-scans store). */
  public readonly scanHistory = new Map<string, ScanHistoryRecord>()
  /** Keyed by `scan_id` (= scan_history.id); the caught-scan detail store. */
  public readonly scanDetails = new Map<string, ScanDetailRecord>()

  /** Per-statement failure injection: when armed, the next call throws once. */
  public failNext = false

  /** Throw once if failure injection is armed, then disarm. */
  public maybeFail(): void {
    if (this.failNext) {
      this.failNext = false
      throw new Error('injected database failure')
    }
  }

  /** Apply a read returning at most one row. */
  public queryOne(sql: string, params: readonly unknown[]): Record<string, unknown> | null {
    this.maybeFail()
    if (sql.includes('FROM api_keys k JOIN users u')) {
      const key = this.apiKeys.get(String(params[0]))
      if (key === undefined || key.status !== 'active') {
        return null
      }
      const user = this.users.get(key.user_id)
      if (user === undefined) {
        return null
      }
      // Honor `AND u.email_verified = 1` (migration 0008): an UNVERIFIED account's
      // key resolves to null (an auth miss), so it has no working credential.
      if (sql.includes('u.email_verified = 1') && user.email_verified !== 1) {
        return null
      }
      return { id: user.id, tier: user.tier }
    }
    if (sql.includes('FROM usage WHERE subject')) {
      const record = this.usage.get(usageKey(String(params[0]), String(params[1])))
      return record === undefined ? null : { scans: record.scans, ai_scans: record.ai_scans }
    }
    if (sql.includes('FROM api_keys WHERE user_id')) {
      // Active-key existence probe (getAccountProfile).
      const userId = String(params[0])
      for (const key of this.apiKeys.values()) {
        if (key.user_id === userId && key.status === 'active') {
          return { present: 1 }
        }
      }
      return null
    }
    if (sql.includes('email, tier, password_hash FROM users WHERE email')) {
      const email = String(params[0])
      for (const user of this.users.values()) {
        if (user.email === email) {
          return {
            id: user.id,
            email: user.email,
            tier: user.tier,
            password_hash: user.password_hash,
          }
        }
      }
      return null
    }
    if (sql.includes('SELECT tier FROM users WHERE id')) {
      const user = this.users.get(String(params[0]))
      return user === undefined ? null : { tier: user.tier }
    }
    if (sql.includes('SELECT role FROM users WHERE id')) {
      const user = this.users.get(String(params[0]))
      return user === undefined ? null : { role: user.role }
    }
    if (sql.includes('SELECT email_verified FROM users WHERE id')) {
      const user = this.users.get(String(params[0]))
      return user === undefined ? null : { email_verified: user.email_verified }
    }
    if (sql.includes('email, tier, created_at FROM users WHERE id')) {
      // getAccountProfile user read.
      const user = this.users.get(String(params[0]))
      return user === undefined
        ? null
        : { email: user.email, tier: user.tier, created_at: user.created_at }
    }
    if (sql.includes('FROM users WHERE id')) {
      const user = this.users.get(String(params[0]))
      return user === undefined
        ? null
        : { id: user.id, email: user.email, stripe_customer_id: user.stripe_customer_id }
    }
    if (sql.includes('FROM users WHERE stripe_customer_id')) {
      const customerId = String(params[0])
      for (const user of this.users.values()) {
        if (user.stripe_customer_id === customerId) {
          return { id: user.id, email: user.email, stripe_customer_id: user.stripe_customer_id }
        }
      }
      return null
    }
    // Admin aggregates (queryOne).
    // Blocked-threats count: scan_history INNER JOIN users, verdict='BLOCK', with
    // an optional (source_ref OR email) LIKE filter. Matched BEFORE the users
    // count below because it too selects `COUNT(*) AS total`.
    if (sql.includes('COUNT(*) AS total') && sql.includes('FROM scan_history s JOIN users u')) {
      const filtered = sql.includes('lower(s.source_ref) LIKE')
      const needle = filtered ? String(params[0]).toLowerCase() : ''
      let total = 0
      for (const record of this.scanHistory.values()) {
        if (record.verdict !== 'BLOCK') {
          continue
        }
        const user = this.users.get(record.user_id)
        if (user === undefined) {
          continue
        }
        if (
          filtered &&
          !record.source_ref.toLowerCase().includes(needle) &&
          !user.email.toLowerCase().includes(needle)
        ) {
          continue
        }
        total += 1
      }
      return { total }
    }
    if (sql.includes('COUNT(*) AS total FROM users')) {
      // Members directory count, with an optional `(lower(email) LIKE q OR
      // lower(tier) LIKE q)` filter — `q` is bound twice, so both binds equal it.
      if (sql.includes('lower(email) LIKE')) {
        const needle = String(params[0]).toLowerCase()
        let total = 0
        for (const user of this.users.values()) {
          if (
            user.email.toLowerCase().includes(needle) ||
            user.tier.toLowerCase().includes(needle)
          ) {
            total += 1
          }
        }
        return { total }
      }
      return { total: this.users.size }
    }
    if (sql.includes('SUM(scans)') && sql.includes('FROM usage')) {
      // usageTotals: SUM over the whole usage table. An empty table yields null
      // (mirroring SQL's SUM-over-zero-rows), which the repo coerces to 0.
      if (this.usage.size === 0) {
        return { scans: null, allows: null, reviews: null, blocks: null, flagged: null }
      }
      let scans = 0
      let allows = 0
      let reviews = 0
      let blocks = 0
      let flagged = 0
      for (const record of this.usage.values()) {
        scans += record.scans
        allows += record.allows
        reviews += record.reviews
        blocks += record.blocks
        flagged += record.flagged
      }
      return { scans, allows, reviews, blocks, flagged }
    }
    if (sql.includes('COUNT(*) AS count FROM subscriptions')) {
      let count = 0
      for (const sub of this.subscriptions.values()) {
        if (sub.status === 'active' || sub.status === 'trialing') {
          count += 1
        }
      }
      return { count }
    }
    if (sql.includes('FROM otp_challenges WHERE id')) {
      const challenge = this.otpChallenges.get(String(params[0]))
      return challenge === undefined
        ? null
        : {
            id: challenge.id,
            user_id: challenge.user_id,
            code_hash: challenge.code_hash,
            expires_at: challenge.expires_at,
            attempts: challenge.attempts,
            created_at: challenge.created_at,
          }
    }
    // Caught-scan detail: scan_details INNER JOIN scan_history INNER JOIN users
    // on the scan id / user id. A detail whose scan or owner is gone is excluded
    // (reads as null → 404), mirroring the INNER JOINs.
    if (sql.includes('FROM scan_details d')) {
      const detail = this.scanDetails.get(String(params[0]))
      if (detail === undefined) {
        return null
      }
      const scan = this.scanHistory.get(detail.scan_id)
      if (scan === undefined) {
        return null
      }
      const user = this.users.get(scan.user_id)
      if (user === undefined) {
        return null
      }
      return {
        id: scan.id,
        email: user.email,
        verdict: scan.verdict,
        source_kind: scan.source_kind,
        source_ref: scan.source_ref,
        flagged: scan.flagged,
        head_hash: scan.head_hash,
        scanned_at: scan.scanned_at,
        content: detail.content,
        result_json: detail.result_json,
      }
    }
    throw new Error(`MemoryStore: unrecognized queryOne SQL: ${sql}`)
  }

  /** Apply a read that may return many rows (the stats range read). */
  public queryAll(sql: string, params: readonly unknown[]): Record<string, unknown>[] {
    this.maybeFail()
    if (sql.includes('FROM usage') && sql.includes('day >=')) {
      const subject = String(params[0])
      const sinceDay = String(params[1])
      const rows: Record<string, unknown>[] = []
      for (const record of this.usage.values()) {
        if (record.subject === subject && record.day >= sinceDay) {
          rows.push({
            day: record.day,
            scans: record.scans,
            allows: record.allows,
            reviews: record.reviews,
            blocks: record.blocks,
            flagged: record.flagged,
          })
        }
      }
      // ORDER BY day ASC.
      rows.sort((a, b) => String(a['day']).localeCompare(String(b['day'])))
      return rows
    }
    // Recent scans: a user's history, newest first, capped by LIMIT.
    if (sql.includes('FROM scan_history WHERE user_id')) {
      const userId = String(params[0])
      const limit = Number(params[1])
      const rows: Record<string, unknown>[] = []
      for (const record of this.scanHistory.values()) {
        if (record.user_id === userId) {
          rows.push({
            id: record.id,
            verdict: record.verdict,
            source_kind: record.source_kind,
            source_ref: record.source_ref,
            flagged: record.flagged,
            head_hash: record.head_hash,
            scanned_at: record.scanned_at,
          })
        }
      }
      // ORDER BY scanned_at DESC (newest first), then LIMIT.
      rows.sort((a, b) => String(b['scanned_at']).localeCompare(String(a['scanned_at'])))
      return rows.slice(0, limit)
    }
    // Admin: accounts grouped by tier.
    if (sql.includes('COUNT(*) AS count FROM users GROUP BY tier')) {
      const byTier = new Map<string, number>()
      for (const user of this.users.values()) {
        byTier.set(user.tier, (byTier.get(user.tier) ?? 0) + 1)
      }
      const rows: Record<string, unknown>[] = []
      for (const [tier, count] of byTier) {
        rows.push({ tier, count })
      }
      return rows
    }
    // Admin: daily signups from sinceDay onward. `date(created_at)` is the UTC
    // calendar day, which for an ISO timestamp is its first 10 chars.
    if (sql.includes('date(created_at)') && sql.includes('FROM users')) {
      const sinceDay = String(params[0])
      const counts = new Map<string, number>()
      for (const user of this.users.values()) {
        const day = user.created_at.slice(0, 10)
        if (day >= sinceDay) {
          counts.set(day, (counts.get(day) ?? 0) + 1)
        }
      }
      const rows: Record<string, unknown>[] = []
      for (const [day, count] of counts) {
        rows.push({ day, count })
      }
      // GROUP BY day ORDER BY day ASC.
      rows.sort((a, b) => String(a['day']).localeCompare(String(b['day'])))
      return rows
    }
    // Admin members directory: each user LEFT JOIN usage, summed to a scan total
    // (zero-scan users still appear), ordered oldest-first, paged by LIMIT/OFFSET.
    // An optional `(lower(email) LIKE q OR lower(tier) LIKE q)` filter binds `q`
    // TWICE first, so the LIMIT/OFFSET params shift right by two when present.
    if (sql.includes('FROM users u LEFT JOIN usage g ON g.subject = u.id')) {
      const filtered = sql.includes('lower(u.email) LIKE')
      const needle = filtered ? String(params[0]).toLowerCase() : ''
      const limit = Number(params[filtered ? 2 : 0])
      const offset = Number(params[filtered ? 3 : 1])
      const rows: Record<string, unknown>[] = []
      for (const user of this.users.values()) {
        if (
          filtered &&
          !user.email.toLowerCase().includes(needle) &&
          !user.tier.toLowerCase().includes(needle)
        ) {
          continue
        }
        let scans = 0
        for (const record of this.usage.values()) {
          if (record.subject === user.id) {
            scans += record.scans
          }
        }
        rows.push({
          id: user.id,
          email: user.email,
          tier: user.tier,
          role: user.role,
          created_at: user.created_at,
          scans,
        })
      }
      // ORDER BY created_at ASC, id ASC.
      rows.sort((a, b) => {
        const byDay = String(a['created_at']).localeCompare(String(b['created_at']))
        return byDay !== 0 ? byDay : String(a['id']).localeCompare(String(b['id']))
      })
      return rows.slice(offset, offset + limit)
    }
    // Admin blocked-threats report: scan_history INNER JOIN users on the user id,
    // filtered to verdict='BLOCK', newest-first, paged by LIMIT/OFFSET. An optional
    // `(source_ref LIKE q OR email LIKE q)` filter binds `q` TWICE first, so the
    // LIMIT/OFFSET params shift right by two when the filter is present.
    if (sql.includes('FROM scan_history s JOIN users u ON u.id = s.user_id')) {
      const filtered = sql.includes('lower(s.source_ref) LIKE')
      const needle = filtered ? String(params[0]).toLowerCase() : ''
      const limit = Number(params[filtered ? 2 : 0])
      const offset = Number(params[filtered ? 3 : 1])
      const rows: Record<string, unknown>[] = []
      for (const record of this.scanHistory.values()) {
        if (record.verdict !== 'BLOCK') {
          continue
        }
        const user = this.users.get(record.user_id)
        if (user === undefined) {
          // INNER JOIN: a blocked scan with no surviving owner is excluded.
          continue
        }
        if (
          filtered &&
          !record.source_ref.toLowerCase().includes(needle) &&
          !user.email.toLowerCase().includes(needle)
        ) {
          continue
        }
        rows.push({
          id: record.id,
          email: user.email,
          verdict: record.verdict,
          source_kind: record.source_kind,
          source_ref: record.source_ref,
          flagged: record.flagged,
          head_hash: record.head_hash,
          scanned_at: record.scanned_at,
        })
      }
      // ORDER BY scanned_at DESC (newest first), then LIMIT/OFFSET.
      rows.sort((a, b) => String(b['scanned_at']).localeCompare(String(a['scanned_at'])))
      return rows.slice(offset, offset + limit)
    }
    throw new Error(`MemoryStore: unrecognized queryAll SQL: ${sql}`)
  }

  /** Apply a write (insert / update / upsert), returning the row-change count. */
  public execute(sql: string, params: readonly unknown[]): WriteResult {
    this.maybeFail()
    if (sql.startsWith('INSERT INTO users')) {
      const id = String(params[0])
      const email = String(params[1])
      for (const existing of this.users.values()) {
        if (existing.email === email) {
          throw new Error('UNIQUE constraint failed: users.email')
        }
      }
      // Three INSERT shapes, distinguished by the named columns (not param count):
      //   createUserWithPassword — names password_hash (param 5) AND email_verified
      //     (param 6, the 1/0 flag the register route computes).
      //   createFreeUser — names email_verified as a literal `1` (no bound param),
      //     5 params, no password (the API-key signup path is verified at birth).
      //   bare test inserts — name neither, 5 params: per migration 0008 the
      //     email_verified column DEFAULTs to 0 (and password_hash to NULL).
      const hasPassword = sql.includes('password_hash')
      const passwordHash = hasPassword && params[5] !== null && params[5] !== undefined
        ? String(params[5])
        : null
      // email_verified column default is 0 (migration 0008). createUserWithPassword
      // binds it (param 6); createFreeUser hardcodes it to 1 in the SQL.
      let emailVerified = 0
      if (sql.includes('email_verified')) {
        emailVerified = hasPassword ? (params[6] === 1 ? 1 : 0) : 1
      }
      this.users.set(id, {
        id,
        email,
        tier: String(params[2]),
        // Migration 0005 default: a fresh account is a 'member' until promoted.
        role: 'member',
        stripe_customer_id: params[3] === null ? null : String(params[3]),
        created_at: String(params[4]),
        password_hash: passwordHash,
        email_verified: emailVerified,
      })
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO api_keys')) {
      const keyHash = String(params[0])
      this.apiKeys.set(keyHash, {
        key_sha256: keyHash,
        user_id: String(params[1]),
        status: String(params[2]),
        created_at: String(params[3]),
      })
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO usage') && sql.includes('allows')) {
      // recordVerdict: scans + ai_scans + the verdict column + flagged.
      // Params: subject, day, aiDelta, allowsDelta, reviewsDelta, blocksDelta,
      //         flaggedDelta, aiDelta(update), flaggedDelta(update).
      const subject = String(params[0])
      const day = String(params[1])
      const aiDelta = Number(params[2])
      const allowsDelta = Number(params[3])
      const reviewsDelta = Number(params[4])
      const blocksDelta = Number(params[5])
      const flaggedDelta = Number(params[6])
      const composite = usageKey(subject, day)
      const existing = this.usage.get(composite)
      if (existing === undefined) {
        this.usage.set(composite, {
          subject,
          day,
          scans: 1,
          ai_scans: aiDelta,
          allows: allowsDelta,
          reviews: reviewsDelta,
          blocks: blocksDelta,
          flagged: flaggedDelta,
        })
      } else {
        existing.scans += 1
        existing.ai_scans += aiDelta
        existing.allows += allowsDelta
        existing.reviews += reviewsDelta
        existing.blocks += blocksDelta
        existing.flagged += flaggedDelta
      }
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO usage')) {
      const subject = String(params[0])
      const day = String(params[1])
      const aiDelta = Number(params[2])
      const composite = usageKey(subject, day)
      const existing = this.usage.get(composite)
      if (existing === undefined) {
        this.usage.set(composite, {
          subject,
          day,
          scans: 1,
          ai_scans: aiDelta,
          allows: 0,
          reviews: 0,
          blocks: 0,
          flagged: 0,
        })
      } else {
        existing.scans += 1
        existing.ai_scans += aiDelta
      }
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO webhook_events')) {
      const eventId = String(params[0])
      // ON CONFLICT (event_id) DO NOTHING: a replay changes zero rows.
      if (this.webhookEvents.has(eventId)) {
        return { changes: 0 }
      }
      this.webhookEvents.set(eventId, {
        event_id: eventId,
        type: String(params[1]),
        created_at: String(params[2]),
      })
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO subscriptions')) {
      const userId = String(params[0])
      this.subscriptions.set(userId, {
        user_id: userId,
        status: String(params[1]),
        price_id: String(params[2]),
        current_period_end: params[3] === null ? null : String(params[3]),
      })
      return { changes: 1 }
    }
    if (sql.startsWith('UPDATE users SET tier = ? WHERE stripe_customer_id')) {
      const tier = String(params[0])
      const customerId = String(params[1])
      let changes = 0
      for (const user of this.users.values()) {
        if (user.stripe_customer_id === customerId) {
          user.tier = tier
          changes += 1
        }
      }
      return { changes }
    }
    if (sql.startsWith('UPDATE users SET tier = ? WHERE id')) {
      const tier = String(params[0])
      const user = this.users.get(String(params[1]))
      if (user === undefined) {
        return { changes: 0 }
      }
      user.tier = tier
      return { changes: 1 }
    }
    if (sql.startsWith('UPDATE users SET role = ? WHERE id')) {
      const role = String(params[0])
      const user = this.users.get(String(params[1]))
      if (user === undefined) {
        return { changes: 0 }
      }
      user.role = role
      return { changes: 1 }
    }
    // markEmailVerified: flip the verification flag to 1 (idempotent; an unknown
    // id changes zero rows). The value is a SQL literal, so the only bind is the id.
    if (sql.startsWith('UPDATE users SET email_verified = 1 WHERE id')) {
      const user = this.users.get(String(params[0]))
      if (user === undefined) {
        return { changes: 0 }
      }
      user.email_verified = 1
      return { changes: 1 }
    }
    if (sql.startsWith('UPDATE users SET stripe_customer_id = ? WHERE id')) {
      const customerId = String(params[0])
      const user = this.users.get(String(params[1]))
      if (user === undefined) {
        return { changes: 0 }
      }
      user.stripe_customer_id = customerId
      return { changes: 1 }
    }
    if (sql.startsWith("UPDATE api_keys SET status = 'revoked' WHERE user_id")) {
      const userId = String(params[0])
      let changes = 0
      for (const key of this.apiKeys.values()) {
        if (key.user_id === userId && key.status === 'active') {
          key.status = 'revoked'
          changes += 1
        }
      }
      return { changes }
    }
    if (sql.startsWith('INSERT INTO scan_history')) {
      const id = String(params[0])
      this.scanHistory.set(id, {
        id,
        user_id: String(params[1]),
        verdict: String(params[2]),
        source_kind: String(params[3]),
        source_ref: String(params[4]),
        flagged: Number(params[5]),
        head_hash: String(params[6]),
        scanned_at: String(params[7]),
      })
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO scan_details')) {
      const scanId = String(params[0])
      // ON CONFLICT (scan_id) DO NOTHING: a replay for the same id is a no-op.
      if (this.scanDetails.has(scanId)) {
        return { changes: 0 }
      }
      this.scanDetails.set(scanId, {
        scan_id: scanId,
        content: params[1] === null ? null : String(params[1]),
        result_json: String(params[2]),
        created_at: String(params[3]),
      })
      return { changes: 1 }
    }
    if (sql.startsWith('INSERT INTO otp_challenges')) {
      const id = String(params[0])
      this.otpChallenges.set(id, {
        id,
        user_id: String(params[1]),
        code_hash: String(params[2]),
        expires_at: String(params[3]),
        attempts: 0,
        created_at: String(params[4]),
      })
      return { changes: 1 }
    }
    if (sql.startsWith('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id')) {
      const challenge = this.otpChallenges.get(String(params[0]))
      if (challenge === undefined) {
        return { changes: 0 }
      }
      challenge.attempts += 1
      return { changes: 1 }
    }
    if (sql.startsWith('DELETE FROM otp_challenges WHERE id')) {
      return { changes: this.otpChallenges.delete(String(params[0])) ? 1 : 0 }
    }
    if (sql.startsWith('DELETE FROM otp_challenges WHERE user_id')) {
      const userId = String(params[0])
      let changes = 0
      for (const [id, challenge] of this.otpChallenges) {
        if (challenge.user_id === userId) {
          this.otpChallenges.delete(id)
          changes += 1
        }
      }
      return { changes }
    }
    // Member removal: hard-delete every row keyed by a user id, dependents first.
    if (sql.startsWith('DELETE FROM api_keys WHERE user_id')) {
      const userId = String(params[0])
      let changes = 0
      for (const [keyHash, key] of this.apiKeys) {
        if (key.user_id === userId) {
          this.apiKeys.delete(keyHash)
          changes += 1
        }
      }
      return { changes }
    }
    if (sql.startsWith('DELETE FROM usage WHERE subject')) {
      const userId = String(params[0])
      let changes = 0
      for (const [composite, record] of this.usage) {
        if (record.subject === userId) {
          this.usage.delete(composite)
          changes += 1
        }
      }
      return { changes }
    }
    // scan_details has no user_id; it is deleted via a `scan_id IN (SELECT id
    // FROM scan_history WHERE user_id = ?)` subquery, so resolve the account's
    // scan_history ids first, then drop the matching details. Must run BEFORE the
    // scan_history delete below (which would otherwise remove the parent rows the
    // subquery resolves against).
    if (sql.startsWith('DELETE FROM scan_details WHERE scan_id IN')) {
      const userId = String(params[0])
      const scanIds = new Set<string>()
      for (const record of this.scanHistory.values()) {
        if (record.user_id === userId) {
          scanIds.add(record.id)
        }
      }
      let changes = 0
      for (const [scanId] of this.scanDetails) {
        if (scanIds.has(scanId)) {
          this.scanDetails.delete(scanId)
          changes += 1
        }
      }
      return { changes }
    }
    if (sql.startsWith('DELETE FROM scan_history WHERE user_id')) {
      const userId = String(params[0])
      let changes = 0
      for (const [id, record] of this.scanHistory) {
        if (record.user_id === userId) {
          this.scanHistory.delete(id)
          changes += 1
        }
      }
      return { changes }
    }
    if (sql.startsWith('DELETE FROM subscriptions WHERE user_id')) {
      return { changes: this.subscriptions.delete(String(params[0])) ? 1 : 0 }
    }
    if (sql.startsWith('DELETE FROM users WHERE id')) {
      return { changes: this.users.delete(String(params[0])) ? 1 : 0 }
    }
    throw new Error(`MemoryStore: unrecognized execute SQL: ${sql}`)
  }
}

/** A prepared statement over the {@link MemoryStore}, capturing the SQL + binds. */
class MemoryStatement {
  private params: readonly unknown[] = []
  public constructor(
    private readonly store: MemoryStore,
    private readonly sql: string,
  ) {}

  public bind(...values: unknown[]): MemoryStatement {
    this.params = values
    return this
  }

  public async first<T = Record<string, unknown>>(): Promise<T | null> {
    return this.store.queryOne(this.sql, this.params) as T | null
  }

  public async all<T = Record<string, unknown>>(): Promise<{ results: T[] }> {
    return { results: this.store.queryAll(this.sql, this.params) as T[] }
  }

  public async run(): Promise<{ meta: { changes: number } }> {
    const result = this.store.execute(this.sql, this.params)
    // Mirror D1's `run()` result shape so the d1Database adapter reads the same
    // `meta.changes` field in tests as in production.
    return { meta: { changes: result.changes } }
  }
}

/**
 * A fake `D1Database` binding backed by a {@link MemoryStore}. Implements only
 * the `prepare()` surface the {@link d1Database} adapter uses; the unused D1
 * methods would never be reached, so they are intentionally omitted (the cast at
 * the env boundary is how production already supplies the binding).
 */
export class MemoryD1 {
  public constructor(public readonly store: MemoryStore = new MemoryStore()) {}

  public prepare(sql: string): MemoryStatement {
    return new MemoryStatement(this.store, sql)
  }
}

/**
 * Build a `(Database, MemoryStore)` pair for direct repository unit tests: the
 * adapter-wrapped fake plus its backing store for assertions.
 */
export function memoryDatabase(): { db: Database; store: MemoryStore } {
  const store = new MemoryStore()
  const d1 = new MemoryD1(store)
  return { db: d1Database(d1 as unknown as D1Database), store }
}

// The fake is a test double; this trivial suite keeps the file a valid test
// module and asserts the double's own invariants (it backs every other suite).
describe('MemoryD1', () => {
  it('upserts usage rows on the composite (subject, day) key via the adapter', async () => {
    const { db, store } = memoryDatabase()
    const upsert =
      'INSERT INTO usage (subject, day, scans, ai_scans) VALUES (?, ?, 1, ?) ' +
      'ON CONFLICT (subject, day) DO UPDATE SET scans = scans + 1, ai_scans = ai_scans + ?'
    await db.execute(upsert, ['u1', '2026-06-28', 1, 1])
    await db.execute(upsert, ['u1', '2026-06-28', 0, 0])
    expect(store.usage.get('u1 2026-06-28')).toMatchObject({ scans: 2, ai_scans: 1 })
  })

  it('stores and reads back scan_history rows newest-first under LIMIT', async () => {
    const { db, store } = memoryDatabase()
    const insert =
      'INSERT INTO scan_history ' +
      '(id, user_id, verdict, source_kind, source_ref, flagged, head_hash, scanned_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    await db.execute(insert, ['a', 'u1', 'ALLOW', 'paste', 'paste', 0, 'h1', '2026-06-28T01:00:00.000Z'])
    await db.execute(insert, ['b', 'u1', 'BLOCK', 'url', 'https://x.test', 2, 'h2', '2026-06-28T02:00:00.000Z'])
    await db.execute(insert, ['c', 'u2', 'ALLOW', 'paste', 'paste', 0, 'h3', '2026-06-28T03:00:00.000Z'])
    expect(store.scanHistory.size).toBe(3)

    const select =
      'SELECT id, verdict, source_kind, source_ref, flagged, head_hash, scanned_at ' +
      'FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC LIMIT ?'
    const { results } = await new MemoryD1(store)
      .prepare(select)
      .bind('u1', 1)
      .all<{ id: string }>()
    // Only u1's rows, newest first, capped at 1 → the BLOCK at 02:00 (id 'b').
    expect(results).toHaveLength(1)
    expect(results[0]?.id).toBe('b')
  })

  it('stores a scan_details row (ON CONFLICT DO NOTHING) and joins it back with the owner', async () => {
    const { db, store } = memoryDatabase()
    // A scan_history row + its owner, so the detail join resolves.
    await db.execute('INSERT INTO users (id, email, tier, stripe_customer_id, created_at) VALUES (?, ?, ?, ?, ?)', [
      'u1',
      'owner@x.test',
      'pro',
      null,
      '2026-06-28T00:00:00.000Z',
    ])
    await db.execute(
      'INSERT INTO scan_history (id, user_id, verdict, source_kind, source_ref, flagged, head_hash, scanned_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ['scan-1', 'u1', 'BLOCK', 'paste', 'paste', 1, 'head-1', '2026-06-28T01:00:00.000Z'],
    )
    const insert =
      'INSERT INTO scan_details (scan_id, content, result_json, created_at) ' +
      'VALUES (?, ?, ?, ?) ON CONFLICT (scan_id) DO NOTHING'
    const first = await db.execute(insert, ['scan-1', 'malicious body', '{"findings":[]}', '2026-06-28T01:00:00.000Z'])
    expect(first.changes).toBe(1)
    // A replay on the same scan_id is a no-op (ON CONFLICT DO NOTHING).
    const replay = await db.execute(insert, ['scan-1', 'other', '{}', '2026-06-28T02:00:00.000Z'])
    expect(replay.changes).toBe(0)
    expect(store.scanDetails.size).toBe(1)

    const select =
      'SELECT s.id AS id, u.email AS email, s.verdict AS verdict, s.source_kind AS source_kind, ' +
      's.source_ref AS source_ref, s.flagged AS flagged, s.head_hash AS head_hash, ' +
      's.scanned_at AS scanned_at, d.content AS content, d.result_json AS result_json ' +
      'FROM scan_details d JOIN scan_history s ON s.id = d.scan_id ' +
      'JOIN users u ON u.id = s.user_id WHERE d.scan_id = ?'
    const row = await db.queryOne(select, ['scan-1'])
    expect(row).toMatchObject({
      id: 'scan-1',
      email: 'owner@x.test',
      verdict: 'BLOCK',
      content: 'malicious body',
      result_json: '{"findings":[]}',
    })
    // An unknown id joins to nothing.
    expect(await db.queryOne(select, ['ghost'])).toBeNull()
  })

  it('throws on an unrecognized statement', async () => {
    const { db } = memoryDatabase()
    await expect(db.execute('DROP TABLE users', [])).rejects.toThrow(/unrecognized/)
    await expect(db.queryOne('SELECT 1', [])).rejects.toThrow(/unrecognized/)
  })

  it('injects a failure exactly once when armed', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(db.execute('INSERT INTO users (id) VALUES (?)', ['x'])).rejects.toThrow(/injected/)
    expect(store.failNext).toBe(false)
  })
})
