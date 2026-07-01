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

import type {
  InjectionFinding,
  LinkChain,
  ReputationReport,
  RuleFinding,
  ScanResult,
  Verdict,
} from '../../shared/contract'

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

/**
 * One real-world AI-agent security incident shown on the landing page. Every
 * field is real and sourced: `title` is a plain-language headline, `source` names
 * the outlet / advisory, `date` is a short display date, and `url` links to the
 * original report.
 */
export interface Incident {
  id: string
  title: string
  source: string
  date: string
  url: string
}

/** The incident list loaded from {@link INCIDENTS_DATA_PATH}. */
export interface IncidentsData {
  incidents: Incident[]
}

/** The account tier returned by the auth + stats endpoints. */
export type AccountTier = 'free' | 'personal' | 'pro' | 'enterprise'

/** The minimal user identity returned by register/login. */
export interface AuthUser {
  email: string
  tier: AccountTier
}

/** The signed-in shape of an auth response: the user is established (session set). */
export interface AuthUserResponse {
  user: AuthUser
}

/**
 * The two-factor-challenge shape of a login or register response: the
 * credentials were accepted but a session was NOT issued. The client must
 * collect the emailed 6-digit code and POST it to `/api/login/verify` to
 * complete the flow. `email` is masked (e.g. `z***@gmail.com`) for display.
 */
export interface TwoFactorChallenge {
  twoFactor: true
  challengeId: string
  email: string
}

/**
 * Response body for `POST /api/login`: EITHER a completed login (`{ user }`, no
 * 2FA configured) OR a two-factor challenge (`{ twoFactor, challengeId, email }`,
 * 2FA active). Discriminate on the `twoFactor` field.
 */
export type LoginResponse = AuthUserResponse | TwoFactorChallenge

/**
 * The verification-deferred shape of a register response: the account was
 * created but a session was NOT issued and NO code was sent. Verification now
 * happens at login, so the client must immediately sign in with the same
 * credentials, that login returns the {@link TwoFactorChallenge} that drives
 * the emailed-code step. Discriminated by the `registered` field.
 */
export interface RegisteredResponse {
  registered: true
}

/**
 * Response body for `POST /api/register`: EITHER a completed signup (`{ user }`,
 * no email verification configured, the session cookie is already set) OR a
 * verification-deferred signup (`{ registered: true }`, verification active, NO
 * session and NO code yet; the account is created but verification happens at
 * login, so the caller signs in next). Discriminate on the `user`/`registered`
 * field.
 */
export type AuthResponse = AuthUserResponse | RegisteredResponse

/** Response body for `POST /api/login/verify`: the completed login. */
export type VerifyLoginResponse = AuthUserResponse

/** Response body for `POST /api/login/resend`: the rotated challenge id. */
export interface ResendResponse {
  challengeId: string
}

/** The three effective access-control roles (`owner` > `admin` > `member`). */
export type Role = 'owner' | 'admin' | 'member'

/** The roles an owner may grant another account via the members directory. */
export type AssignableRole = 'admin' | 'member'

/** Response body for `GET /api/me`: the signed-in account. */
export interface MeResponse {
  email: string
  tier: AccountTier
  createdAt: string
  /** The non-secret prefix of the account's API key, safe to display. */
  apiKeyPrefix: string
  /** Account holder's given name, or `null` for a nameless (legacy / API-key) account. */
  firstName: string | null
  /** Account holder's family name, or `null` for a nameless account. */
  lastName: string | null
  /** The effective role: `owner` (allowlisted email), `admin`, or `member`. */
  role: Role
  /** Whether this account may VIEW the admin surface (owner or admin). */
  isAdmin: boolean
  /** Whether this account may MANAGE roles (owner only). */
  isOwner: boolean
}

/** The credentials body for login (and the base for registration). */
export interface AuthCredentials {
  email: string
  password: string
}

/**
 * The registration body: credentials plus the account holder's name, so the app
 * can greet the person by name instead of echoing their email.
 */
export interface RegisterCredentials extends AuthCredentials {
  firstName: string
  lastName: string
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

/**
 * One row in the dashboard's recent-scans list. `source.ref` is the scanned URL
 * (`kind: 'url'`) or an opaque label for a pasted skill (`kind: 'paste'`);
 * `flagged` is the count of malicious indicators caught; `scannedAt` is an ISO
 * timestamp rendered as a relative time. `headHash` keys the row stably.
 */
export interface RecentScan {
  id: string
  verdict: Verdict
  source: { kind: 'paste' | 'url' | 'mcp'; ref: string }
  flagged: number
  headHash: string
  scannedAt: string
}

/** Response body for `GET /api/scans/recent`: the newest scans, newest first. */
export interface RecentScansResponse {
  scans: RecentScan[]
}

/** Response body for `POST /api/checkout`: the Stripe checkout URL. */
export interface CheckoutResponse {
  url: string
}

/**
 * Response body for `GET /api/billing/subscription` (and `POST /api/billing/cancel`):
 * whether the account has an active subscription, whether a cancellation is
 * already scheduled, and the ISO end of the current period (or `null`). Drives the
 * dynamic pricing page's current-plan and "cancels on <date>" states.
 */
export interface SubscriptionStatus {
  hasSubscription: boolean
  cancelAtPeriodEnd: boolean
  currentPeriodEnd: string | null
}

/** Response body for `POST /api/billing/change`: the newly active paid tier. */
export interface ChangePlanResponse {
  tier: 'personal' | 'pro'
}

/**
 * Request body for `POST /api/contact`: an enterprise sales enquiry from the
 * pricing page's contact form. The recipient addresses live server-side; this
 * body carries only what the visitor typed. The worker re-validates every field.
 */
export interface ContactRequest {
  name: string
  email: string
  message: string
}

/** Response body for `POST /api/contact`: the enquiry was accepted and sent. */
export interface ContactResponse {
  ok: true
}

/** Per-tier account counts in the admin overview. */
export interface AdminTierCounts {
  free: number
  personal: number
  pro: number
  enterprise: number
}

/** One day's signup count in the admin signup series, `day` an ISO `YYYY-MM-DD`. */
export interface AdminSignupDay {
  day: string
  count: number
}

/** Sitewide verdict + indicator totals in the admin overview. */
export interface AdminUsageTotals {
  scans: number
  allows: number
  reviews: number
  blocks: number
  flagged: number
}

/** Response body for `GET /api/admin/overview`: sitewide analytics. */
export interface AdminOverview {
  totalUsers: number
  usersByTier: AdminTierCounts
  signupsDaily: AdminSignupDay[]
  usageTotals: AdminUsageTotals
  activeSubscriptions: number
  /** ISO timestamp the edge stamped the response. */
  generatedAt: string
}

/** One account in the members directory, with its EFFECTIVE (owner-aware) role. */
export interface AdminMember {
  id: string
  email: string
  tier: AccountTier
  role: Role
  createdAt: string
  /** This account's lifetime scan count (summed across all days). */
  scans: number
}

/** Response body for `GET /api/admin/members`: one page plus the total count. */
export interface AdminMembersPage {
  members: AdminMember[]
  total: number
}

/** Response body for `POST /api/admin/members/role`: the updated id + role. */
export interface SetRoleResponse {
  id: string
  role: AssignableRole
}

/** Response body for `POST /api/admin/members/tier`: the updated id + tier. */
export interface SetTierResponse {
  id: string
  tier: AccountTier
}

/** Response body for `POST /api/admin/members/remove`: the removed account id. */
export interface RemoveMemberResponse {
  removed: string
}

/**
 * One blocked-threat row in the admin threats report. Every row is a `BLOCK`
 * verdict (the report lists only blocked threats). `email` is the member the
 * scan belongs to; `source.ref` is the scanned URL (`kind: 'url'`) or an opaque
 * label for a pasted skill (`kind: 'paste'`); `flagged` is the count of
 * malicious indicators caught; `headHash` keys the row stably and proves the
 * sealed proof chain; `scannedAt` is an ISO timestamp rendered as a relative
 * time.
 */
export interface AdminThreat {
  id: string
  email: string
  verdict: 'BLOCK'
  source: { kind: 'paste' | 'url' | 'mcp'; ref: string }
  flagged: number
  headHash: string
  scannedAt: string
}

/** Response body for `GET /api/admin/threats`: one page plus the total count. */
export interface AdminThreatsPage {
  threats: AdminThreat[]
  total: number
}

/**
 * The full per-scan detail an admin opens from a {@link AdminThreat} row, served
 * by `GET /api/admin/scans/<id>`. It mirrors a {@link ScanResult}'s evidence
 * deterministic rule findings, traced redirect chains, reputation reports, and
 * injection findings, plus the owning member's `email`, the verdict, the scan
 * `source`, the `headHash` that proves the sealed (re-verifiable) proof chain,
 * and `flagged` (the indicator count). `content` is the scanned skill/artifact
 * text the verdict was reached on, or `null` when it was not retained server-side
 * (rendered as "content not stored").
 */
export interface AdminScanDetail {
  id: string
  email: string
  verdict: Verdict
  source: { kind: 'paste' | 'url' | 'mcp'; ref: string }
  scannedAt: string
  flagged: number
  headHash: string
  content: string | null
  findings: RuleFinding[]
  chains: LinkChain[]
  injections: InjectionFinding[]
  reputation: ReputationReport[]
}

/**
 * The owner-scoped per-scan detail a user opens from an Activity row, served by
 * `GET /api/scans/<id>`. Same evidence as {@link AdminScanDetail} minus the owner
 * `email` (the caller is the owner): the verdict, scan `source`, `scannedAt`, the
 * `flagged` count, the `headHash` proving the sealed re-verifiable chain, the
 * scanned `content` (or `null`), and the parsed rule / redirect / injection /
 * reputation evidence.
 */
export interface ScanReport {
  id: string
  verdict: Verdict
  source: { kind: 'paste' | 'url' | 'mcp'; ref: string }
  scannedAt: string
  flagged: number
  headHash: string
  content: string | null
  findings: RuleFinding[]
  chains: LinkChain[]
  injections: InjectionFinding[]
  reputation: ReputationReport[]
}
