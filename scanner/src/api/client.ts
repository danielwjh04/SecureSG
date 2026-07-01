import { adminScanDetailPath, API, scanDetailPath } from '../config'
import type {
  AccountTier,
  AdminMembersPage,
  AdminOverview,
  AdminScanDetail,
  AdminThreatsPage,
  AssignableRole,
  AuthCredentials,
  AuthResponse,
  ChangePlanResponse,
  CheckoutResponse,
  ContactRequest,
  ContactResponse,
  SubscriptionStatus,
  LoginResponse,
  MeResponse,
  Proof,
  RecentScansResponse,
  RegisterCredentials,
  RemoveMemberResponse,
  ResendResponse,
  RotateKeyResponse,
  ScanReport,
  ScanRequest,
  ScanResult,
  SetRoleResponse,
  SetTierResponse,
  StatsResponse,
  VerifyLoginResponse,
  VerifyResult,
} from './types'

const JSON_HEADERS = { 'content-type': 'application/json' }

/** A failed API exchange: a non-2xx response or an unreachable backend. */
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/**
 * Same-origin JSON request helper.
 *
 * Throws {@link ApiError} on a transport failure (status 0) or a non-ok
 * response, so callers branch on one error type. Relative paths are used
 * deliberately: the Worker serves both this SPA and the API.
 *
 * Time complexity: O(n) in the response body size. Space complexity: O(n).
 */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, init)
  } catch {
    throw new ApiError(0, 'scanner backend unreachable')
  }
  if (!response.ok) {
    // Surface the worker's typed error message (e.g. "no SKILL.md found in …")
    // rather than a bare status, so the user sees exactly what to do next.
    let detail = `request to ${path} failed (${response.status})`
    try {
      const body = (await response.json()) as { message?: unknown }
      if (typeof body.message === 'string' && body.message.length > 0) {
        detail = body.message
      }
    } catch {
      /* non-JSON error body: keep the generic detail */
    }
    throw new ApiError(response.status, detail)
  }
  return (await response.json()) as T
}

/** Run a full skill scan. POSTs the request body to {@link API.scan}. */
export async function scanSkill(req: ScanRequest): Promise<ScanResult> {
  return request<ScanResult>(API.scan, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(req),
  })
}

/**
 * Server-side re-verification of a proof chain. POSTs to {@link API.verify}.
 *
 * Note: the in-browser ProofViewer tamper feature does NOT use this, it calls
 * the shared `verifyChain` directly so re-verification needs no network round
 * trip and is provably client-side.
 */
export async function verifyProof(proof: Proof): Promise<VerifyResult> {
  return request<VerifyResult>(API.verify, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ proof }),
  })
}

/** The scan capability the UI depends on, injectable for tests and the gallery. */
export interface ScanClient {
  scanSkill(r: ScanRequest): Promise<ScanResult>
}

/** The production scan client, backed by the live API. */
export const defaultScanClient: ScanClient = { scanSkill }

/**
 * Send the session cookie on every account call. The Worker serves the SPA and
 * the API from one origin; `include` keeps the httpOnly session cookie flowing
 * even when a remote {@link API_BASE} is configured.
 */
const WITH_CREDENTIALS = { credentials: 'include' } as const

/**
 * Register a new account. 409 if the email exists.
 *
 * The response is a union: when no email verification is configured server-side,
 * it returns `{ user }` and the session cookie is already set. When verification
 * IS active, it returns `{ registered: true }` and NO cookie and NO code
 * verification is deferred to login, so the caller must immediately {@link login}
 * with the same credentials and handle the {@link TwoFactorChallenge} that login
 * returns (collect the emailed code and complete via {@link loginVerify}).
 * Discriminate on the `user`/`registered` field.
 */
export async function register(
  credentials: RegisterCredentials,
): Promise<AuthResponse> {
  return request<AuthResponse>(API.register, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(credentials),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Sign in to an existing account. 401 on bad creds.
 *
 * The response is a union: when email 2FA is NOT configured server-side, it
 * returns `{ user }` and the session cookie is already set. When 2FA IS
 * configured, it returns `{ twoFactor: true, challengeId, email }` and NO cookie
 * the caller must then collect the emailed code and call {@link loginVerify}.
 * Discriminate on the `twoFactor` field.
 */
export async function login(
  credentials: AuthCredentials,
): Promise<LoginResponse> {
  return request<LoginResponse>(API.login, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(credentials),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Complete a 2FA login by submitting the emailed code for a challenge. On
 * success sets the session cookie and returns `{ user }`. Throws
 * {@link ApiError}(401) on a wrong/expired/exhausted code, (422) on a malformed
 * code.
 */
export async function loginVerify(
  challengeId: string,
  code: string,
): Promise<VerifyLoginResponse> {
  return request<VerifyLoginResponse>(API.loginVerify, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ challengeId, code }),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Request a fresh 2FA code for a pending challenge. Returns the (possibly new)
 * challenge id to use for the next {@link loginVerify}. Throws
 * {@link ApiError}(401) when the challenge is gone/expired.
 */
export async function loginResend(challengeId: string): Promise<ResendResponse> {
  return request<ResendResponse>(API.loginResend, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ challengeId }),
    ...WITH_CREDENTIALS,
  })
}

/** Sign out, clearing the session cookie. */
export async function logout(): Promise<void> {
  await request<unknown>(API.logout, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}

/** Fetch the signed-in account. Throws {@link ApiError}(401) when logged out. */
export async function fetchMe(): Promise<MeResponse> {
  return request<MeResponse>(API.me, { ...WITH_CREDENTIALS })
}

/** Fetch the account's protection statistics. */
export async function fetchStats(): Promise<StatsResponse> {
  return request<StatsResponse>(API.stats, { ...WITH_CREDENTIALS })
}

/**
 * Fetch the account's most recent scans, newest first. `limit` (display-only)
 * is clamped server-side; omitting it returns the server default. Throws
 * {@link ApiError}(401) when logged out.
 */
export async function fetchRecentScans(limit?: number): Promise<RecentScansResponse> {
  const path =
    limit !== undefined ? `${API.recentScans}?limit=${limit}` : API.recentScans
  return request<RecentScansResponse>(path, { ...WITH_CREDENTIALS })
}

/**
 * Fetch the sitewide admin analytics overview. Throws {@link ApiError}(403) when
 * the signed-in account is not an admin, or (401) when logged out.
 */
export async function fetchAdminOverview(): Promise<AdminOverview> {
  return request<AdminOverview>(API.adminOverview, { ...WITH_CREDENTIALS })
}

/**
 * Fetch a page of the members directory, optionally filtered by an email query.
 * Throws {@link ApiError}(403) when the signed-in account may not view the admin
 * surface, or (401) when logged out.
 *
 * `q` (case-insensitive email substring), `limit`, and `offset` are all
 * display-only filter/pagination params; the worker trims `q`, lowercases the
 * match, and clamps `limit`/`offset` server-side (default 100, cap 500), so
 * omitting them returns the first unfiltered page.
 */
export async function fetchMembers(
  q?: string,
  limit?: number,
  offset?: number,
): Promise<AdminMembersPage> {
  const params = new URLSearchParams()
  if (q !== undefined && q.length > 0) params.set('q', q)
  if (limit !== undefined) params.set('limit', String(limit))
  if (offset !== undefined) params.set('offset', String(offset))
  const query = params.toString()
  const path = query.length > 0 ? `${API.adminMembers}?${query}` : API.adminMembers
  return request<AdminMembersPage>(path, { ...WITH_CREDENTIALS })
}

/**
 * Fetch a page of the blocked-threats report, optionally filtered by a query
 * that matches the scanned URL or the owning member's email. Throws
 * {@link ApiError}(403) when the signed-in account may not view the admin
 * surface, or (401) when logged out.
 *
 * `q` (case-insensitive URL-or-email substring), `limit`, and `offset` are
 * display-only filter/pagination params; the worker clamps them server-side, so
 * omitting them returns the first unfiltered page (every row is a `BLOCK`).
 */
export async function fetchThreats(
  q?: string,
  limit?: number,
  offset?: number,
): Promise<AdminThreatsPage> {
  const params = new URLSearchParams()
  if (q !== undefined && q.length > 0) params.set('q', q)
  if (limit !== undefined) params.set('limit', String(limit))
  if (offset !== undefined) params.set('offset', String(offset))
  const query = params.toString()
  const path = query.length > 0 ? `${API.adminThreats}?${query}` : API.adminThreats
  return request<AdminThreatsPage>(path, { ...WITH_CREDENTIALS })
}

/**
 * Fetch the full detail of one scanned skill/artifact for the admin detail view,
 * keyed by the scan id from an {@link AdminThreat} row. Throws
 * {@link ApiError}(404) when the scan id is unknown or its detail is no longer
 * available, (403) when the signed-in account may not view the admin surface, or
 * (401) when logged out.
 */
export async function fetchScanDetail(id: string): Promise<AdminScanDetail> {
  return request<AdminScanDetail>(adminScanDetailPath(id), { ...WITH_CREDENTIALS })
}

/**
 * Fetch the full detail of one of the CALLER'S OWN scans for the Activity block
 * report, keyed by the scan id from a {@link RecentScan} row. Only BLOCK/REVIEW
 * scans retain a detail, so an ALLOW row (or a scan owned by someone else) is a
 * 404. Throws {@link ApiError}(404) when the scan has no detail / is not owned,
 * or (401) when logged out.
 */
export async function fetchOwnScanDetail(id: string): Promise<ScanReport> {
  return request<ScanReport>(scanDetailPath(id), { ...WITH_CREDENTIALS })
}

/**
 * Grant a role to another account (owner-only). Throws {@link ApiError}(403)
 * when the caller is not an owner or the target is an owner, (404) for an unknown
 * user, (422) for an invalid role.
 */
export async function setMemberRole(
  userId: string,
  role: AssignableRole,
): Promise<SetRoleResponse> {
  return request<SetRoleResponse>(API.adminMemberRole, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ userId, role }),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Switch another account's plan/tier (owner-only). Throws {@link ApiError}(403)
 * when the caller is not an owner, (404) for an unknown user, (422) for an
 * invalid tier.
 */
export async function setMemberTier(
  userId: string,
  tier: AccountTier,
): Promise<SetTierResponse> {
  return request<SetTierResponse>(API.adminMemberTier, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ userId, tier }),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Permanently remove another account (owner-only): hard-deletes the user and all
 * of its data. Throws {@link ApiError}(403) when the caller is not an owner, the
 * target is an owner, or the target is the caller themselves; (404) for an
 * unknown user.
 */
export async function removeMember(userId: string): Promise<RemoveMemberResponse> {
  return request<RemoveMemberResponse>(API.adminMemberRemove, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ userId }),
    ...WITH_CREDENTIALS,
  })
}

/** Rotate the account's API key. The new key is returned once and not stored. */
export async function rotateApiKey(): Promise<RotateKeyResponse> {
  return request<RotateKeyResponse>(API.rotateKey, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}

/** Start a Stripe checkout session and return the URL to redirect to. */
export async function startCheckout(tier: 'personal' | 'pro' = 'pro'): Promise<CheckoutResponse> {
  return request<CheckoutResponse>(API.checkout, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ tier }),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Open the Stripe billing portal for the signed-in paid account and return the
 * URL to redirect to, so a subscriber can switch plan or cancel. Takes no body:
 * the customer is resolved from the session. Throws {@link ApiError}(422) when
 * the account has no Stripe customer yet, or (502) when the customer portal is
 * not enabled in the Stripe dashboard.
 */
export async function openPortal(): Promise<CheckoutResponse> {
  return request<CheckoutResponse>(API.portal, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}

/**
 * Change an active subscription to another paid tier IN PLACE (upgrade/downgrade),
 * without leaving the site. Returns the newly active tier. Throws
 * {@link ApiError}(422) when there is no active subscription or it is already on
 * that plan, or (401) when logged out.
 */
export async function changePlan(tier: 'personal' | 'pro'): Promise<ChangePlanResponse> {
  return request<ChangePlanResponse>(API.billingChange, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ tier }),
    ...WITH_CREDENTIALS,
  })
}

/**
 * Schedule the active subscription to cancel at the end of the current period
 * (access is kept until then). Returns the updated subscription snapshot so the
 * caller can show the effective date. Throws {@link ApiError}(422) when there is
 * no active subscription, or (401) when logged out.
 */
export async function cancelPlan(): Promise<SubscriptionStatus> {
  return request<SubscriptionStatus>(API.billingCancel, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}

/**
 * Fetch the account's live subscription snapshot for the dynamic pricing page:
 * whether a subscription is active, whether a cancellation is scheduled, and when
 * the current period ends. Degrades to `hasSubscription: false` server-side when
 * billing is unavailable, so it never blocks the page.
 */
export async function fetchSubscriptionStatus(): Promise<SubscriptionStatus> {
  return request<SubscriptionStatus>(API.billingSubscription, { ...WITH_CREDENTIALS })
}

/**
 * Submit an enterprise sales enquiry from the pricing page's contact form. POSTs
 * the visitor's name, email, and message to {@link API.contact}; the recipient
 * addresses are server-side, so the body never carries them. This is a public,
 * unauthenticated endpoint (no session cookie is sent).
 *
 * Throws {@link ApiError} with the worker's status so the form maps it to inline
 * copy: 422 (a field failed re-validation), 429 (rate-limited), 502/503 (the
 * send path is unavailable), or 0 (the backend is unreachable).
 */
export async function submitContact(
  req: ContactRequest,
): Promise<ContactResponse> {
  return request<ContactResponse>(API.contact, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(req),
  })
}
