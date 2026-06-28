/**
 * Admin route handlers — gated, fail-closed reads/writes over the account store:
 *   - `GET  /api/admin/overview`     — sitewide analytics (view: owner OR admin).
 *   - `GET  /api/admin/members`      — the members directory (view: owner OR admin).
 *   - `POST /api/admin/members/role` — grant a role (manage: OWNER only).
 *
 * Gating is strict (CLAUDE.md §6, fail-closed). Every handler authenticates via
 * Bearer key OR session cookie; an anonymous caller is 401. The VIEW endpoints
 * require {@link canViewAdmin} (effective role owner or admin) — a member is 403.
 * The MANAGE endpoint requires {@link canManageRoles} (effective role owner) —
 * an admin or member is 403. The effective role is derived from the resolved
 * account email + its stored `role` column via {@link effectiveRole}, so owners
 * (email allowlist) always pass and a corrupt stored role fails closed to member.
 * Requires `env.DB` (503 otherwise).
 */

import type { ScannerConfig } from '../config/env'
import type { AccountTier } from '../db/accounts'
import type { Database } from '../db/database'
import type { MemberRow, SignupDay, ThreatRow, TierCounts, UsageTotals } from '../db/admin'
import type { ScanDetail } from '../db/scans'
import type {
  InjectionFinding,
  LinkChain,
  ReputationReport,
  RuleFinding,
} from '../schemas/contract'
import type { Role } from '../auth/roles'
import { ParseError } from '../errors'
import { authenticate } from '../middleware/auth'
import { findRoleByUserId, getAccountProfile, parseAccountTier, setUserTier } from '../db/accounts'
import { getScanDetail } from '../db/scans'
import { canManageRoles, canViewAdmin, effectiveRole, parseAssignableRole } from '../auth/roles'
import {
  adminSearchQuerySchema,
  memberRoleSchema,
  memberTierSchema,
  removeMemberSchema,
  threatsLimitSchema,
  threatsOffsetSchema,
} from '../schemas/validate'
import {
  activeSubscriptions,
  countMembers,
  countThreats,
  countUsers,
  deleteMember,
  listMembers,
  listThreats,
  setUserRole,
  signupsByDay,
  usageTotals,
  usersByTier,
} from '../db/admin'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_FORBIDDEN = 403
const STATUS_NOT_FOUND = 404
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** Inclusive signup-window length in days (today plus the 29 prior days). */
const SIGNUP_WINDOW_DAYS = 30
/** Milliseconds in one day, for the window lower-bound computation. */
const MS_PER_DAY = 86_400_000

/** Default page size for the members directory when no `limit` is given. */
const MEMBERS_DEFAULT_LIMIT = 100
/** Hard cap on a members page, so a caller cannot request an unbounded scan. */
const MEMBERS_MAX_LIMIT = 500

/** A configured admin route's dependencies, assembled by the worker entry. */
export interface AdminDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
  readonly config: ScannerConfig
}

/** The 200 body of `GET /api/admin/overview`. */
export interface AdminOverview {
  readonly totalUsers: number
  readonly usersByTier: TierCounts
  readonly signupsDaily: readonly SignupDay[]
  readonly usageTotals: UsageTotals
  readonly activeSubscriptions: number
  /** ISO timestamp the edge stamped the response; outside any hash. */
  readonly generatedAt: string
}

/** One member in the directory response, with the EFFECTIVE (owner-aware) role. */
export interface AdminMember {
  readonly id: string
  readonly email: string
  readonly tier: string
  /** Effective role: `owner` for an allowlisted email, else the stored role. */
  readonly role: Role
  readonly createdAt: string
  readonly scans: number
}

/** The 200 body of `GET /api/admin/members`. */
export interface AdminMembersPage {
  readonly members: readonly AdminMember[]
  readonly total: number
}

/** One blocked-threat entry in the report response (owner email + provenance). */
export interface AdminThreat {
  readonly id: string
  /** The owner account's email (from the scan_history → users join). */
  readonly email: string
  readonly verdict: string
  readonly source: { readonly kind: string; readonly ref: string }
  readonly flagged: number
  readonly headHash: string
  readonly scannedAt: string
}

/** The 200 body of `GET /api/admin/threats`. */
export interface AdminThreatsPage {
  readonly threats: readonly AdminThreat[]
  readonly total: number
}

/**
 * The 200 body of `GET /api/admin/scans/:id` — the full caught-scan detail: the
 * recorded scan's verdict/source/proof + owner email, plus the scanned `content`
 * (or `null` when unavailable, e.g. a verdict-cache hit) and the structured
 * evidence parsed back from the stored `result_json`.
 */
export interface AdminScanDetail {
  readonly id: string
  readonly email: string
  readonly verdict: string
  readonly source: { readonly kind: string; readonly ref: string }
  readonly scannedAt: string
  /** The flagged-indicator count carried on the recorded scan-history row. */
  readonly flagged: number
  readonly headHash: string
  /** The scanned skill/artifact text (truncated at write time), or `null`. */
  readonly content: string | null
  readonly findings: readonly RuleFinding[]
  readonly chains: readonly LinkChain[]
  readonly injections: readonly InjectionFinding[]
  readonly reputation: readonly ReputationReport[]
}

/** The parsed shape of a `scan_details.result_json` payload. */
interface StoredScanEvidence {
  readonly findings: readonly RuleFinding[]
  readonly chains: readonly LinkChain[]
  readonly injections: readonly InjectionFinding[]
  readonly reputation: readonly ReputationReport[]
}

/**
 * The viewer identity an admin gate resolved: the authenticated user id and the
 * effective role derived from the email allowlist + stored role column.
 */
interface AdminViewer {
  readonly userId: string
  readonly role: Role
}

/**
 * Compute the inclusive UTC `YYYY-MM-DD` lower bound of the signup window:
 * `now - (SIGNUP_WINDOW_DAYS - 1)` days. With 30 days the window spans today and
 * the 29 days before it.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function windowStart(now: Date): string {
  const start = new Date(now.getTime() - (SIGNUP_WINDOW_DAYS - 1) * MS_PER_DAY)
  return start.toISOString().slice(0, 10)
}

/** Build a 401 with the shared unauthenticated body. */
function unauthorized(): Response {
  return Response.json(
    { error: 'unauthorized', message: 'authentication required' },
    { status: STATUS_UNAUTHORIZED },
  )
}

/** Build a 503 when the account store is not configured. */
function unavailable(): Response {
  return Response.json(
    { error: 'service_unavailable', message: 'account store is not configured' },
    { status: STATUS_SERVICE_UNAVAILABLE },
  )
}

/** Build a 403 forbidden body (insufficient role). */
function forbidden(): Response {
  return Response.json({ error: 'forbidden' }, { status: STATUS_FORBIDDEN })
}

/** Build a 422 for a malformed query param (invalid limit/offset/q). */
function unprocessable(error: string): Response {
  return Response.json({ error }, { status: STATUS_UNPROCESSABLE })
}

/**
 * Resolve the calling request to an {@link AdminViewer}, or a `Response` to
 * return directly (401 anonymous / vanished, 403 insufficient role). Shared by
 * every admin handler so the gate is identical: authenticate, derive the
 * effective role from the email allowlist + stored role column, then require
 * `requirement(role)`.
 *
 * Time complexity: O(1) — two indexed reads + O(1) checks. Space complexity: O(1).
 */
async function resolveViewer(
  request: Request,
  deps: AdminDeps,
  db: Database,
  requirement: (role: Role) => boolean,
): Promise<AdminViewer | Response> {
  const ctx = await authenticate(request, db, deps.sessionSecret ?? undefined)
  if (ctx.tier === 'anonymous') {
    return unauthorized()
  }
  const profile = await getAccountProfile(db, ctx.subject)
  if (profile === null) {
    // Resolved to a user id that no longer exists — treat as unauthenticated.
    return unauthorized()
  }
  const roleColumn = await findRoleByUserId(db, ctx.subject)
  const role = effectiveRole(profile.email, roleColumn, deps.config.adminEmails)
  if (!requirement(role)) {
    return forbidden()
  }
  return { userId: ctx.subject, role }
}

/**
 * Handle `GET /api/admin/overview`. Authenticates the caller and requires the
 * effective role to be owner OR admin ({@link canViewAdmin}; 403 otherwise), then
 * returns the sitewide {@link AdminOverview}. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(r) in the active signup days in the window (every other
 * metric is an O(1) aggregate). Space complexity: O(r).
 */
export async function handleAdminOverview(
  request: Request,
  deps: AdminDeps,
): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canViewAdmin)
    if (viewer instanceof Response) {
      return viewer
    }

    const now = new Date()
    const [totalUsers, tierCounts, signupsDaily, totals, subscriptions] = await Promise.all([
      countUsers(db),
      usersByTier(db),
      signupsByDay(db, windowStart(now)),
      usageTotals(db),
      activeSubscriptions(db),
    ])

    const body: AdminOverview = {
      totalUsers,
      usersByTier: tierCounts,
      signupsDaily,
      usageTotals: totals,
      activeSubscriptions: subscriptions,
      generatedAt: now.toISOString(),
    }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminOverview] ${className}`)
    return Response.json({ error: 'admin_overview_failed' }, { status: STATUS_SERVER_ERROR })
  }
}

/**
 * Clamp a `limit` query param to `[1, MEMBERS_MAX_LIMIT]`, defaulting to
 * {@link MEMBERS_DEFAULT_LIMIT} when absent or unparseable. A non-integer or
 * out-of-range value is coerced rather than rejected — pagination params are
 * display-only, so a sane clamp is friendlier than a 4xx.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function clampLimit(raw: string | null): number {
  const value = raw === null ? MEMBERS_DEFAULT_LIMIT : Number(raw)
  if (!Number.isInteger(value) || value < 1) {
    return MEMBERS_DEFAULT_LIMIT
  }
  return Math.min(value, MEMBERS_MAX_LIMIT)
}

/** Clamp an `offset` query param to a non-negative integer (default 0). */
function clampOffset(raw: string | null): number {
  const value = raw === null ? 0 : Number(raw)
  return Number.isInteger(value) && value >= 0 ? value : 0
}

/**
 * Project a stored {@link MemberRow} to an {@link AdminMember} with the EFFECTIVE
 * role: an account whose email is in the owner allowlist is shown as `owner`
 * (overriding its stored column), otherwise the validated stored role
 * (fail-closed to `member`).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function toAdminMember(row: MemberRow, adminEmails: ReadonlySet<string>): AdminMember {
  return {
    id: row.id,
    email: row.email,
    tier: row.tier,
    role: effectiveRole(row.email, row.role, adminEmails),
    createdAt: row.createdAt,
    scans: row.scans,
  }
}

/**
 * Handle `GET /api/admin/members?q&limit&offset`. Authenticates the caller and
 * requires the effective role to be owner OR admin ({@link canViewAdmin}; 403
 * otherwise), then returns a page of the members directory plus the total count
 * for pagination. An optional `q` filters by a case-insensitive substring on the
 * email OR the tier/plan (so `pro` / `free` / `enterprise` filters by plan); the
 * `total` reflects the filtered count, and an over-length `q` is a 422. Each row
 * carries its effective (owner-aware) role. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(p log p) in the page size p (the ordered LIMIT/OFFSET page).
 * Space complexity: O(p).
 */
export async function handleAdminMembers(request: Request, deps: AdminDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canViewAdmin)
    if (viewer instanceof Response) {
      return viewer
    }

    const url = new URL(request.url)
    const parsedQuery = adminSearchQuerySchema.safeParse(url.searchParams.get('q') ?? undefined)
    if (!parsedQuery.success) {
      return unprocessable('invalid_query')
    }
    const q = parsedQuery.data
    const limit = clampLimit(url.searchParams.get('limit'))
    const offset = clampOffset(url.searchParams.get('offset'))

    const [rows, total] = await Promise.all([
      listMembers(db, limit, offset, q),
      countMembers(db, q),
    ])
    const members = rows.map((row) => toAdminMember(row, deps.config.adminEmails))

    const body: AdminMembersPage = { members, total }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminMembers] ${className}`)
    return Response.json({ error: 'admin_members_failed' }, { status: STATUS_SERVER_ERROR })
  }
}

/**
 * Project a stored {@link ThreatRow} to an {@link AdminThreat}: the same nested
 * `source: { kind, ref }` shape the recent-scans endpoint uses, plus the owner
 * email and proof head hash. `ref` is the source LABEL only (never the scanned
 * content), exactly as persisted.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function toAdminThreat(row: ThreatRow): AdminThreat {
  return {
    id: row.id,
    email: row.email,
    verdict: row.verdict,
    source: { kind: row.sourceKind, ref: row.sourceRef },
    flagged: row.flagged,
    headHash: row.headHash,
    scannedAt: row.scannedAt,
  }
}

/**
 * Handle `GET /api/admin/threats?q&limit&offset`. Authenticates the caller and
 * requires the effective role to be owner OR admin ({@link canViewAdmin}; a
 * member is 403, an anonymous caller is 401), then returns a newest-first page of
 * the sitewide blocked-threats report (every `BLOCK`-verdict scan with its owner
 * email) plus the filtered total. An optional `q` filters by a case-insensitive
 * substring on the source ref OR owner email. `limit`/`offset` are Zod-validated
 * integers (clamped limit, default 50 / cap 500) and `q` is a bounded string; a
 * malformed param is a 422. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(p log p) in the page size p (the ordered LIMIT/OFFSET page).
 * Space complexity: O(p).
 */
export async function handleAdminThreats(request: Request, deps: AdminDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canViewAdmin)
    if (viewer instanceof Response) {
      return viewer
    }

    const url = new URL(request.url)
    const parsedLimit = threatsLimitSchema.safeParse(url.searchParams.get('limit') ?? undefined)
    const parsedOffset = threatsOffsetSchema.safeParse(url.searchParams.get('offset') ?? undefined)
    const parsedQuery = adminSearchQuerySchema.safeParse(url.searchParams.get('q') ?? undefined)
    if (!parsedLimit.success || !parsedOffset.success || !parsedQuery.success) {
      return unprocessable('invalid_query')
    }
    const q = parsedQuery.data

    const [rows, total] = await Promise.all([
      listThreats(db, { limit: parsedLimit.data, offset: parsedOffset.data, q }),
      countThreats(db, q),
    ])
    const threats = rows.map(toAdminThreat)

    const body: AdminThreatsPage = { threats, total }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminThreats] ${className}`)
    return Response.json({ error: 'admin_threats_failed' }, { status: STATUS_SERVER_ERROR })
  }
}

/**
 * Parse a stored `result_json` string into the structured evidence shape. A
 * corrupt / non-object payload yields empty arrays for every field rather than
 * throwing — a malformed evidence blob must not 500 the detail read; the rest of
 * the row (verdict, source, proof, content) is still useful for review.
 *
 * Time complexity: O(n) in the JSON length. Space complexity: O(n).
 */
function parseStoredEvidence(resultJson: string): StoredScanEvidence {
  let raw: unknown
  try {
    raw = JSON.parse(resultJson)
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.warn(`[handleAdminScanDetail] unparseable result_json (${className}); empty evidence`)
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

/**
 * Project a stored {@link ScanDetail} to the {@link AdminScanDetail} response,
 * parsing the `result_json` evidence back into typed arrays.
 *
 * Time complexity: O(n) in the stored evidence length. Space complexity: O(n).
 */
function toAdminScanDetail(detail: ScanDetail): AdminScanDetail {
  const evidence = parseStoredEvidence(detail.resultJson)
  return {
    id: detail.id,
    email: detail.email,
    verdict: detail.verdict,
    source: detail.source,
    scannedAt: detail.scannedAt,
    flagged: detail.flagged,
    headHash: detail.headHash,
    content: detail.content,
    findings: evidence.findings,
    chains: evidence.chains,
    injections: evidence.injections,
    reputation: evidence.reputation,
  }
}

/**
 * Handle `GET /api/admin/scans/:id`. Authenticates the caller and requires the
 * effective role to be owner OR admin ({@link canViewAdmin}; a member is 403, an
 * anonymous caller is 401), then returns the full {@link AdminScanDetail} for the
 * caught scan with id `scanId` — the recorded verdict/source/proof + owner email,
 * the scanned content (or `null`), and the structured evidence parsed from the
 * stored `result_json`. A scan id with no detail row (a clean / anonymous scan
 * was never detail-persisted, or the id is unknown) is a 404. Requires `env.DB`
 * (503 otherwise).
 *
 * Time complexity: O(1) gate + O(d) in the stored evidence length. Space
 * complexity: O(d).
 *
 * @param scanId - The scan id extracted from the request path by the entry point.
 */
export async function handleAdminScanDetail(
  request: Request,
  deps: AdminDeps,
  scanId: string,
): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canViewAdmin)
    if (viewer instanceof Response) {
      return viewer
    }

    const detail = await getScanDetail(db, scanId)
    if (detail === null) {
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }
    return Response.json(toAdminScanDetail(detail), { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminScanDetail] ${className}`)
    return Response.json({ error: 'admin_scan_detail_failed' }, { status: STATUS_SERVER_ERROR })
  }
}

/**
 * Parse + Zod-validate the role-change body, or throw {@link ParseError} (→ 422).
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 */
async function parseRoleBody(request: Request): Promise<{ userId: string; role: 'member' | 'admin' }> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = memberRoleSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid member role request: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Handle `POST /api/admin/members/role`. Authenticates the caller and requires
 * the effective role to be OWNER ({@link canManageRoles}; an admin or member is
 * 403). Validates `{ userId, role }` where `role` is allowlisted to
 * {`member`, `admin`} (422 otherwise — `owner` is never assignable). Rejects
 * changing an OWNER (target email in the allowlist) with 403, and an unknown
 * `userId` with 404. On success sets the target's role and returns
 * `200 { id, role }`. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(1) — a bounded set of indexed reads + one PK update.
 * Space complexity: O(1).
 */
export async function handleAdminMemberRole(request: Request, deps: AdminDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canManageRoles)
    if (viewer instanceof Response) {
      return viewer
    }

    const body = await parseRoleBody(request)
    // Defense in depth: the schema already allowlists role, but re-validate so a
    // value can never slip past into the write (CLAUDE.md §6).
    const role = parseAssignableRole(body.role)
    if (role === null) {
      return Response.json({ error: 'invalid_role' }, { status: STATUS_UNPROCESSABLE })
    }

    // The target must exist. Read its profile first so an unknown id is a 404 and
    // an owner-by-email target is a 403 — BEFORE any write.
    const target = await getAccountProfile(db, body.userId)
    if (target === null) {
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }
    if (deps.config.adminEmails.has(target.email.toLowerCase())) {
      // An owner is conferred by the allowlist and can never be changed via the API.
      return forbidden()
    }

    const changes = await setUserRole(db, body.userId, role)
    if (changes === 0) {
      // Lost a race (the row vanished between the profile read and the update).
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }
    return Response.json({ id: body.userId, role }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminMemberRole] ${className}`)
    if (error instanceof ParseError) {
      return Response.json({ error: 'invalid_role' }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'admin_member_role_failed' }, { status: STATUS_SERVER_ERROR })
  }
}

/**
 * Parse + Zod-validate the tier-change body, or throw {@link ParseError} (→ 422).
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 */
async function parseTierBody(
  request: Request,
): Promise<{ userId: string; tier: AccountTier }> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = memberTierSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid member tier request: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Handle `POST /api/admin/members/tier`. Authenticates the caller and requires
 * the effective role to be OWNER ({@link canManageRoles}; an admin or member is
 * 403, an anonymous caller is 401). Validates `{ userId, tier }` where `tier` is
 * allowlisted to {`free`, `pro`, `enterprise`} (422 otherwise). Rejects an
 * unknown `userId` with 404 — read BEFORE any write. On success sets the
 * target's tier and returns `200 { id, tier }`. Requires `env.DB` (503
 * otherwise).
 *
 * Unlike role, tier is not conferred by the email allowlist, so an owner-by-email
 * target is a legitimate subject (an owner may sit on any plan); the gate is
 * solely {@link canManageRoles}.
 *
 * Time complexity: O(1) — a bounded set of indexed reads + one PK update.
 * Space complexity: O(1).
 */
export async function handleAdminMemberTier(request: Request, deps: AdminDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canManageRoles)
    if (viewer instanceof Response) {
      return viewer
    }

    const body = await parseTierBody(request)
    // Defense in depth: the schema already allowlists tier, but re-validate so a
    // value can never slip past into the write (CLAUDE.md §6).
    const tier = parseAccountTier(body.tier)
    if (tier === null) {
      return Response.json({ error: 'invalid_tier' }, { status: STATUS_UNPROCESSABLE })
    }

    // The target must exist. Read its profile first so an unknown id is a 404 —
    // BEFORE any write.
    const target = await getAccountProfile(db, body.userId)
    if (target === null) {
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }

    await setUserTier(db, body.userId, tier)
    return Response.json({ id: body.userId, tier }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminMemberTier] ${className}`)
    if (error instanceof ParseError) {
      return Response.json({ error: 'invalid_tier' }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'admin_member_tier_failed' }, { status: STATUS_SERVER_ERROR })
  }
}

/**
 * Parse + Zod-validate the member-removal body, or throw {@link ParseError}
 * (→ 422).
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 */
async function parseRemoveBody(request: Request): Promise<{ userId: string }> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = removeMemberSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid member remove request: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Handle `POST /api/admin/members/remove`. Authenticates the caller and requires
 * the effective role to be OWNER ({@link canManageRoles}; an admin or member is
 * 403, an anonymous caller is 401). Validates `{ userId }`. Refuses to remove the
 * caller's OWN account (403) and refuses to remove an OWNER-by-email target
 * (403), and an unknown `userId` is a 404 — all BEFORE any delete. On success
 * hard-deletes the account and every row keyed by its user id (api_keys, usage,
 * scan_history, subscriptions, otp_challenges, then users), returning
 * `200 { removed: userId }`. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(k) in the target's dependent rows (a bounded set of indexed
 * deletes). Space complexity: O(1).
 */
export async function handleAdminMemberRemove(
  request: Request,
  deps: AdminDeps,
): Promise<Response> {
  if (deps.db === null) {
    return unavailable()
  }
  const db = deps.db
  try {
    const viewer = await resolveViewer(request, deps, db, canManageRoles)
    if (viewer instanceof Response) {
      return viewer
    }

    const body = await parseRemoveBody(request)

    // An owner can never delete their own account via the API — guard the self
    // case first, before any read, so it is unambiguous regardless of the target.
    if (body.userId === viewer.userId) {
      return forbidden()
    }

    // The target must exist. Read its profile first so an unknown id is a 404 and
    // an owner-by-email target is a 403 — BEFORE any delete.
    const target = await getAccountProfile(db, body.userId)
    if (target === null) {
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }
    if (deps.config.adminEmails.has(target.email.toLowerCase())) {
      // An owner is conferred by the allowlist and can never be removed via the API.
      return forbidden()
    }

    const changes = await deleteMember(db, body.userId)
    if (changes === 0) {
      // Lost a race (the row vanished between the profile read and the delete).
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }
    return Response.json({ removed: body.userId }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminMemberRemove] ${className}`)
    if (error instanceof ParseError) {
      return Response.json({ error: 'invalid_remove' }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'admin_member_remove_failed' }, { status: STATUS_SERVER_ERROR })
  }
}
