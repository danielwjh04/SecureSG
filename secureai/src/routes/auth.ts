/**
 * Email + password authentication routes: register, login, logout, me, and
 * key rotation. These sit alongside the existing Bearer-API-key auth — a
 * registered, email-verified account gets BOTH a session cookie (for the
 * browser) and an API key (for programmatic callers). When email verification
 * is active (a provider is configured), register creates the account UNVERIFIED
 * and neither credential authenticates it until its emailed code is verified via
 * `POST /api/login/verify`.
 *
 * Session model: a stateless, HMAC-signed cookie (see `auth/session.ts`). There
 * is no server-side session table; logout simply clears the cookie. Register and
 * login require `env.DB` (the account store) AND `env.SESSION_SECRET` (to sign
 * the cookie); without the secret they return 503 rather than minting an
 * unverifiable session.
 *
 * Security posture (CLAUDE.md §6): plaintext passwords are hashed with PBKDF2 and
 * NEVER logged or returned; login failures are generic (no field-level hints);
 * the freshly minted API key on register and on rotate is the only secret ever
 * returned, and only once.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { EmailSender } from '../email/sender'
import type {
  LoginPayload,
  LoginResendPayload,
  LoginVerifyPayload,
  RegisterPayload,
} from '../schemas/validate'
import { AuthError, EmailError, ParseError, ScannerError } from '../errors'
import {
  loginResendSchema,
  loginSchema,
  loginVerifySchema,
  registerSchema,
} from '../schemas/validate'
import {
  createUserWithPassword,
  findRoleByUserId,
  findTierByUserId,
  findUserByEmail,
  getAccountProfile,
  markEmailVerified,
  rotateApiKey,
} from '../db/accounts'
import { canManageRoles, canViewAdmin, effectiveRole } from '../auth/roles'
import {
  createChallenge,
  deleteChallenge,
  deleteUserChallenges,
  getChallenge,
  incrementAttempt,
} from '../db/otp'
import { generateCode, hashCode, verifyCode } from '../auth/otp'
import { hashPassword, verifyPassword } from '../auth/password'
import { assessPasswordStrength } from '../auth/passwordPolicy'
import { isPasswordBreached } from '../auth/breachCheck'
import { authenticate } from '../middleware/auth'
import { clientIp, withinHourlyLimit } from '../middleware/rateLimit'
import type { RateLimitKv } from '../middleware/rateLimit'
import {
  buildClearedSessionCookie,
  buildSessionCookie,
  signSession,
} from '../auth/session'
import { log } from '../observability/logger'

const STATUS_OK = 200
const STATUS_CREATED = 201
const STATUS_UNAUTHORIZED = 401
const STATUS_CONFLICT = 409
const STATUS_UNPROCESSABLE = 422
const STATUS_TOO_MANY_REQUESTS = 429
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502
const STATUS_SERVICE_UNAVAILABLE = 503

// Per-endpoint, versioned rate-limit key namespaces so a burst against one
// endpoint never consumes another's budget (each gets its own per-IP bucket).
const RATE_PREFIX_LOGIN = 'auth:login:v1:'
const RATE_PREFIX_REGISTER = 'auth:register:v1:'
const RATE_PREFIX_VERIFY = 'auth:verify:v1:'
const RATE_PREFIX_RESEND = 'auth:resend:v1:'

/**
 * A configured auth route's dependencies, assembled by the worker entry.
 *
 * `emailSender` is the email-verification gate for BOTH register and login:
 * `null` (no provider configured) means register and login each issue a session
 * immediately, and a new account is created already-verified, exactly as before;
 * a non-`null` sender activates the emailed-code challenge so (a) login mints a
 * session only after the code is verified and (b) a new account is created
 * UNVERIFIED — unusable until its emailed code is verified via
 * `POST /api/login/verify`.
 */
export interface AuthDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
  readonly config: ScannerConfig
  readonly emailSender: EmailSender | null
  /**
   * Per-IP rate-limit store for the auth endpoints, or `null` when KV is unbound
   * (the brute-force limit is then skipped, exactly as the contact route degrades).
   */
  readonly kv: RateLimitKv | null
}

/** Current UNIX time in whole seconds, stamped once per request at the edge. */
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/** Build a 503 when the account store / session secret is not configured. */
function unavailable(message: string): Response {
  return Response.json(
    { error: 'service_unavailable', message },
    { status: STATUS_SERVICE_UNAVAILABLE },
  )
}

/** Build a 401 with a generic, field-agnostic message (no credential hints). */
function invalidCredentials(): Response {
  return Response.json(
    { error: 'invalid_credentials', message: 'invalid email or password' },
    { status: STATUS_UNAUTHORIZED },
  )
}

/** Build a generic 401 for an invalid/expired/exhausted 2FA challenge or code. */
function invalidChallenge(): Response {
  return Response.json(
    { error: 'invalid_code', message: 'that code is invalid or has expired' },
    { status: STATUS_UNAUTHORIZED },
  )
}

/**
 * Enforce the per-IP hourly auth rate limit for `keyPrefix`, returning a 429
 * {@link Response} when the caller is over budget or `null` when within it (or
 * when no KV store is configured — the limit is then skipped, matching the
 * contact route's degradation). Counts every attempt, so it throttles brute force
 * before any password/DB/email work runs.
 *
 * Time complexity: O(1) (one KV read + write). Space complexity: O(1).
 */
async function rateLimited(
  deps: AuthDeps,
  request: Request,
  keyPrefix: string,
): Promise<Response | null> {
  if (deps.kv === null) {
    return null
  }
  const allowed = await withinHourlyLimit(
    deps.kv,
    keyPrefix,
    clientIp(request),
    deps.config.authRatePerHour,
    nowSeconds(),
  )
  if (allowed) {
    return null
  }
  return Response.json(
    { error: 'rate_limited', message: 'too many attempts; please try again later' },
    { status: STATUS_TOO_MANY_REQUESTS },
  )
}

/**
 * Mask an email for display in the 2FA-challenge response: keep the first local
 * character and the full domain, replace the rest of the local part with `***`
 * (e.g. `zuriel@gmail.com` → `z***@gmail.com`). A single-character or empty
 * local part is masked without revealing it. The address is only shown back to a
 * caller who already proved the password, so this leaks nothing new; the mask
 * keeps it out of shoulder-surf / screenshot range.
 *
 * Time complexity: O(n) in the email length. Space complexity: O(n).
 */
function maskEmail(email: string): string {
  const at = email.lastIndexOf('@')
  if (at <= 0) {
    return '***'
  }
  const local = email.slice(0, at)
  const domain = email.slice(at)
  const firstChar = local.charAt(0)
  return `${firstChar}***${domain}`
}

/**
 * Render the 2FA code email's `subject`, `html`, and `text`. The code is
 * embedded verbatim (it is the message), and the expiry window is stated in
 * whole minutes so the recipient knows how long they have.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function buildCodeEmail(code: string, ttlSeconds: number): {
  subject: string
  html: string
  text: string
} {
  const minutes = Math.max(1, Math.round(ttlSeconds / 60))
  const subject = 'Your SecureAI sign-in code'
  const text =
    `Your SecureAI sign-in code is ${code}. ` +
    `It expires in ${minutes} minute${minutes === 1 ? '' : 's'}. ` +
    `If you did not try to sign in, you can ignore this email.`
  const html =
    `<p>Your SecureAI sign-in code is:</p>` +
    `<p style="font-size:28px;font-weight:700;letter-spacing:0.2em;">${code}</p>` +
    `<p>It expires in ${minutes} minute${minutes === 1 ? '' : 's'}.</p>` +
    `<p style="color:#888;">If you did not try to sign in, you can ignore this email.</p>`
  return { subject, html, text }
}

/**
 * Open a fresh 2FA challenge for a user: generate an unbiased 6-digit code,
 * invalidate any prior pending challenges for the user, persist a new challenge
 * row (hash-only) with the configured TTL, and email the code. Returns the new
 * challenge id.
 *
 * Order matters for fail-closed delivery: the row is created BEFORE the email is
 * sent, so a delivery failure leaves a valid challenge the user can `resend`
 * against rather than a code with no backing row. A send failure propagates
 * {@link EmailError} so the caller issues NO session.
 *
 * Time complexity: O(1) DB + one email round trip. Space complexity: O(1).
 *
 * @throws {OtpError} On a persistence failure. {@link EmailError} On a send failure.
 */
async function openChallenge(
  db: Database,
  emailSender: EmailSender,
  config: ScannerConfig,
  userId: string,
  email: string,
): Promise<string> {
  const code = generateCode()
  const codeHash = await hashCode(code)
  const now = nowSeconds()
  const createdAt = new Date(now * 1000).toISOString()
  const expiresAt = new Date((now + config.otpTtlSeconds) * 1000).toISOString()
  const id = crypto.randomUUID()

  await deleteUserChallenges(db, userId)
  await createChallenge(db, { id, userId, codeHash, expiresAt, createdAt })

  const { subject, html, text } = buildCodeEmail(code, config.otpTtlSeconds)
  await emailSender.send({ to: email, subject, html, text })
  return id
}

/**
 * Parse + Zod-validate a JSON body with the given schema, or throw
 * {@link ParseError} (→ 422). Shared by register and login.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 */
async function parseBody<T>(
  request: Request,
  schema: { safeParse(value: unknown): { success: true; data: T } | { success: false; error: { message: string } } },
  label: string,
): Promise<T> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = schema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid ${label} request: ${parsed.error.message}`)
  }
  return parsed.data
}

/** Map a non-Parse error to its status: AuthError → 500 (opaque), else 500. */
function statusForError(error: unknown): number {
  if (error instanceof ParseError) {
    return STATUS_UNPROCESSABLE
  }
  if (error instanceof AuthError || error instanceof ScannerError) {
    return STATUS_SERVER_ERROR
  }
  return STATUS_SERVER_ERROR
}

/** Build the standard `{ user }` body + Set-Cookie session for a logged-in user. */
async function sessionResponse(
  userId: string,
  email: string,
  tier: string,
  deps: { sessionSecret: string; config: ScannerConfig },
  extra: Record<string, unknown>,
  status: number,
): Promise<Response> {
  const token = await signSession(
    userId,
    nowSeconds(),
    deps.config.sessionTtlSeconds,
    deps.sessionSecret,
  )
  const cookie = buildSessionCookie(token, deps.config.sessionTtlSeconds)
  return Response.json(
    { user: { email, tier }, ...extra },
    { status, headers: { 'Set-Cookie': cookie } },
  )
}

/**
 * Handle `POST /api/register`. Validates `{ email, password }`, rejects a
 * duplicate email with 409 (before anything else), hashes the password (PBKDF2),
 * and provisions a free user with an API key. The outcome GATES on whether email
 * verification is configured (`deps.emailSender`):
 *   - sender `null` (no provider) → the account is created VERIFIED (no code can
 *     be sent), the session cookie is issued immediately, and the route returns
 *     `201 { user: { email, tier } }`, exactly as before this feature existed.
 *   - sender present → the account is created UNVERIFIED and is NOT usable yet
 *     (its API key does not resolve and no session is issued). Register sends NO
 *     code and issues NO session; it returns `201 { registered: true }` with NO
 *     Set-Cookie. Verification is DEFERRED to the user's first login: login (which
 *     2FAs on every attempt) opens the emailed-code challenge — the single code —
 *     and `POST /api/login/verify` flips the account to verified and mints the
 *     session. This yields one code total, at login, instead of one at signup and
 *     one at first login.
 *
 * The minted API key is NOT returned by register (the contract returns only the
 * user under the no-provider branch); programmatic callers obtain one via
 * `POST /api/key/rotate` once the account is verified.
 *
 * Requires `env.DB` and `env.SESSION_SECRET` (503 otherwise).
 *
 * Time complexity: O(iterations) (PBKDF2) + O(1) inserts. Space complexity: O(1).
 */
export async function handleRegister(request: Request, deps: AuthDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable('account store is not configured')
  }
  if (deps.sessionSecret === null) {
    return unavailable('session secret is not configured')
  }
  const db = deps.db
  const sessionSecret = deps.sessionSecret
  const limited = await rateLimited(deps, request, RATE_PREFIX_REGISTER)
  if (limited !== null) {
    return limited
  }
  try {
    const body: RegisterPayload = await parseBody(request, registerSchema, 'register')

    // Offline strength gate (cheap, deterministic) before any DB/network work.
    const strength = assessPasswordStrength(body.password, deps.config.passwordMinClasses)
    if (!strength.ok) {
      return Response.json(
        { error: 'weak_password', message: strength.reason },
        { status: STATUS_UNPROCESSABLE },
      )
    }

    const existing = await findUserByEmail(db, body.email)
    if (existing !== null) {
      return Response.json(
        { error: 'email_taken', message: 'an account with this email already exists' },
        { status: STATUS_CONFLICT },
      )
    }

    // Online leaked-password check (k-anonymity), gated by config and fail-open:
    // only after the email is known-free, to avoid a HIBP call on a 409.
    if (
      deps.config.pwnedCheckEnabled &&
      (await isPasswordBreached(body.password, deps.config.pwnedTimeoutMs))
    ) {
      return Response.json(
        {
          error: 'breached_password',
          message: 'this password has appeared in a known data breach; choose another',
        },
        { status: STATUS_UNPROCESSABLE },
      )
    }

    const passwordHash = await hashPassword(body.password, deps.config.pbkdf2Iterations)
    // With a provider the account is UNVERIFIED until the emailed code is
    // verified; without one it is verified at creation (no code can be sent).
    const verifiedAtCreation = deps.emailSender === null
    const { user } = await createUserWithPassword(
      db,
      body.email,
      passwordHash,
      verifiedAtCreation,
      body.firstName ?? null,
      body.lastName ?? null,
    )

    // Verification active: the account exists but is UNVERIFIED and not usable
    // yet. Register sends NO code and issues NO session — verification is deferred
    // to the user's first login, which opens the single emailed-code challenge and
    // (via verify) marks the account verified. Return 201 { registered: true } with
    // no Set-Cookie.
    if (deps.emailSender !== null) {
      return Response.json({ registered: true }, { status: STATUS_CREATED })
    }

    return await sessionResponse(
      user.id,
      user.email,
      user.tier,
      { sessionSecret, config: deps.config },
      {},
      STATUS_CREATED,
    )
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleRegister', 'request failed', { errorClass: className })
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'registration_failed' }, { status: statusForError(error) })
  }
}

/**
 * Handle `POST /api/login`. Validates `{ email, password }`, resolves the account
 * by email, and verifies the password against the stored PBKDF2 hash. Any
 * failure — unknown email, account with no password (API-key-only), or wrong
 * password — returns the SAME generic 401, never revealing which.
 *
 * On a correct password the outcome GATES on whether email two-factor is
 * configured (`deps.emailSender`):
 *   - sender `null` (no provider) → issue the session cookie immediately and
 *     return `200 { user: { email, tier } }`, exactly as before 2FA existed.
 *   - sender present → DO NOT issue a session. Open an emailed-code challenge and
 *     return `200 { twoFactor: true, challengeId, email: <masked> }`; the session
 *     is minted later by `POST /api/login/verify`. If the email cannot be sent,
 *     return 502 and issue no session.
 *
 * Requires `env.DB` and `env.SESSION_SECRET` (503 otherwise).
 *
 * Time complexity: O(iterations) (PBKDF2 verify) + O(1) lookup [+ one email
 * round trip when 2FA is active]. Space complexity: O(1).
 */
export async function handleLogin(request: Request, deps: AuthDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable('account store is not configured')
  }
  if (deps.sessionSecret === null) {
    return unavailable('session secret is not configured')
  }
  const db = deps.db
  const sessionSecret = deps.sessionSecret
  const limited = await rateLimited(deps, request, RATE_PREFIX_LOGIN)
  if (limited !== null) {
    return limited
  }
  try {
    const body: LoginPayload = await parseBody(request, loginSchema, 'login')

    const account = await findUserByEmail(db, body.email)
    if (account === null || account.passwordHash === null) {
      return invalidCredentials()
    }
    const ok = await verifyPassword(body.password, account.passwordHash)
    if (!ok) {
      return invalidCredentials()
    }

    // Gate: with no email provider, behave exactly as today (session now). With
    // one, start an emailed-code challenge and withhold the session.
    if (deps.emailSender !== null) {
      const challengeId = await openChallenge(
        db,
        deps.emailSender,
        deps.config,
        account.id,
        account.email,
      )
      return Response.json(
        { twoFactor: true, challengeId, email: maskEmail(account.email) },
        { status: STATUS_OK },
      )
    }

    return await sessionResponse(
      account.id,
      account.email,
      account.tier,
      { sessionSecret, config: deps.config },
      {},
      STATUS_OK,
    )
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleLogin', 'request failed', { errorClass: className })
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    // A 2FA code that could not be delivered fails closed: NO session is issued.
    if (error instanceof EmailError) {
      return Response.json({ error: 'email_send_failed' }, { status: STATUS_BAD_GATEWAY })
    }
    return Response.json({ error: 'login_failed' }, { status: statusForError(error) })
  }
}

/**
 * Handle `POST /api/login/verify`. Validates `{ challengeId, code }`, loads the
 * challenge, and on a correct, unexpired, non-exhausted code mints the session
 * cookie and returns `200 { user: { email, tier } }`. The challenge is deleted
 * on success (single-use). Every failure path — missing challenge, expired,
 * over the attempt cap, wrong code, or a vanished user — returns the SAME
 * generic 401, so the response cannot be used to probe challenge state. A wrong
 * code additionally increments the attempt counter (fail-closed brute-force cap).
 *
 * This endpoint ALSO completes a signup verification: a correct emailed code
 * proves control of the address, so before minting the session the account is
 * marked email-verified ({@link markEmailVerified}, idempotent). For an account
 * that registered while verification was active, this is the step that makes it
 * usable (its API key and session begin to authenticate); for the login flow it
 * is a harmless no-op (the account was already verified). Marking BEFORE the
 * session is built means the freshly minted cookie passes the middleware's
 * email-verified gate on the very next request.
 *
 * Requires `env.DB` and `env.SESSION_SECRET` (503 otherwise).
 *
 * Time complexity: O(1) lookup + O(n) constant-time compare. Space complexity: O(1).
 */
export async function handleLoginVerify(request: Request, deps: AuthDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable('account store is not configured')
  }
  if (deps.sessionSecret === null) {
    return unavailable('session secret is not configured')
  }
  const db = deps.db
  const sessionSecret = deps.sessionSecret
  const limited = await rateLimited(deps, request, RATE_PREFIX_VERIFY)
  if (limited !== null) {
    return limited
  }
  try {
    const body: LoginVerifyPayload = await parseBody(request, loginVerifySchema, 'login verify')

    const challenge = await getChallenge(db, body.challengeId)
    if (challenge === null) {
      return invalidChallenge()
    }
    // Expired or exhausted: spend the challenge so a stale row cannot linger.
    const expired = nowSeconds() >= Math.floor(Date.parse(challenge.expiresAt) / 1000)
    if (expired || challenge.attempts >= deps.config.otpMaxAttempts) {
      await deleteChallenge(db, challenge.id)
      return invalidChallenge()
    }

    const matches = await verifyCode(body.code, challenge.codeHash)
    if (!matches) {
      await incrementAttempt(db, challenge.id)
      return invalidChallenge()
    }

    // Correct code: the challenge is single-use, so delete it before minting the
    // session — a replay of the same code then finds no challenge (generic 401).
    await deleteChallenge(db, challenge.id)
    // A correct emailed code proves control of the address, which completes a
    // signup verification: mark the account verified (idempotent) BEFORE the
    // session is built so the new cookie — and the account's API key — begin to
    // authenticate. For an already-verified login account this is a no-op.
    await markEmailVerified(db, challenge.userId)
    const tier = await findTierByUserId(db, challenge.userId)
    const profile = await getAccountProfile(db, challenge.userId)
    if (tier === null || profile === null) {
      // The account vanished between login and verify — treat as a bad challenge.
      return invalidChallenge()
    }
    return await sessionResponse(
      challenge.userId,
      profile.email,
      tier,
      { sessionSecret, config: deps.config },
      {},
      STATUS_OK,
    )
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleLoginVerify', 'request failed', { errorClass: className })
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'verify_failed' }, { status: statusForError(error) })
  }
}

/**
 * Handle `POST /api/login/resend`. Validates `{ challengeId }`, looks up the
 * pending challenge, and — for the SAME user — rotates to a fresh code and
 * expiry, re-sending the email. Returns `200 { challengeId }` (the id is stable
 * across a resend; only the code/expiry rotate). A missing/expired challenge
 * returns a generic 401 so resend cannot probe challenge state. The per-challenge
 * attempt cap that bounds verify ALSO bounds resends implicitly: a resend reuses
 * the user's challenge slot (prior challenges are deleted), and the verify cap
 * still spends the code, so resends cannot be used to bypass the brute-force cap.
 *
 * Requires `env.DB` and `env.SESSION_SECRET` (503 otherwise). Email 2FA must be
 * configured (`deps.emailSender`), else 503 — a resend is meaningless without a
 * provider.
 *
 * Time complexity: O(1) DB + one email round trip. Space complexity: O(1).
 */
export async function handleLoginResend(request: Request, deps: AuthDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable('account store is not configured')
  }
  if (deps.sessionSecret === null) {
    return unavailable('session secret is not configured')
  }
  if (deps.emailSender === null) {
    return unavailable('email two-factor is not configured')
  }
  const db = deps.db
  const emailSender = deps.emailSender
  const limited = await rateLimited(deps, request, RATE_PREFIX_RESEND)
  if (limited !== null) {
    return limited
  }
  try {
    const body: LoginResendPayload = await parseBody(request, loginResendSchema, 'login resend')

    const challenge = await getChallenge(db, body.challengeId)
    if (challenge === null) {
      return invalidChallenge()
    }
    const profile = await getAccountProfile(db, challenge.userId)
    if (profile === null) {
      return invalidChallenge()
    }
    // Rotate to a fresh code+expiry for the same user. openChallenge deletes the
    // user's prior challenge(s) first, so exactly one live code remains.
    const challengeId = await openChallenge(
      db,
      emailSender,
      deps.config,
      challenge.userId,
      profile.email,
    )
    return Response.json({ challengeId }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleLoginResend', 'request failed', { errorClass: className })
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    if (error instanceof EmailError) {
      return Response.json({ error: 'email_send_failed' }, { status: STATUS_BAD_GATEWAY })
    }
    return Response.json({ error: 'resend_failed' }, { status: statusForError(error) })
  }
}

/**
 * Handle `POST /api/logout`. Stateless: there is no server session to destroy, so
 * this simply returns `200 { ok: true }` with a `Set-Cookie` that clears the
 * session cookie (`Max-Age=0`). Always succeeds, even when no session was set.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function handleLogout(): Response {
  return Response.json(
    { ok: true },
    { status: STATUS_OK, headers: { 'Set-Cookie': buildClearedSessionCookie() } },
  )
}

/**
 * Handle `GET /api/me`. Authenticates via Bearer key OR session cookie; an
 * unauthenticated caller is 401. Returns `200 { email, tier, createdAt,
 * apiKeyPrefix, firstName, lastName, role, isAdmin, isOwner }`, where `firstName`
 * / `lastName` are `null` for a nameless (legacy / API-key) account and
 * `apiKeyPrefix` is the non-secret
 * brand prefix when an active key exists, else `null`. `role` is the EFFECTIVE
 * role (`owner` for an allowlisted email, else the stored role, fail-closed to
 * `member`); `isAdmin` is whether that role may VIEW the admin surface
 * ({@link canViewAdmin}, owner OR admin); `isOwner` is whether it may MANAGE roles
 * ({@link canManageRoles}, owner only). Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(1) — two indexed reads. Space complexity: O(1).
 */
export async function handleMe(request: Request, deps: AuthDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable('account store is not configured')
  }
  const db = deps.db
  try {
    const ctx = await authenticate(request, db, deps.sessionSecret ?? undefined)
    if (ctx.tier === 'anonymous') {
      return Response.json(
        { error: 'unauthorized', message: 'authentication required' },
        { status: STATUS_UNAUTHORIZED },
      )
    }
    const profile = await getAccountProfile(db, ctx.subject)
    if (profile === null) {
      // Resolved to a user id that no longer exists — treat as unauthenticated.
      return Response.json(
        { error: 'unauthorized', message: 'authentication required' },
        { status: STATUS_UNAUTHORIZED },
      )
    }
    const roleColumn = await findRoleByUserId(db, ctx.subject)
    const role = effectiveRole(profile.email, roleColumn, deps.config.adminEmails)
    return Response.json(
      {
        email: profile.email,
        tier: profile.tier,
        createdAt: profile.createdAt,
        apiKeyPrefix: profile.apiKeyPrefix,
        firstName: profile.firstName,
        lastName: profile.lastName,
        role,
        isAdmin: canViewAdmin(role),
        isOwner: canManageRoles(role),
      },
      { status: STATUS_OK },
    )
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.error('handleMe', 'request failed', { errorClass: className })
    return Response.json({ error: 'me_failed' }, { status: statusForError(error) })
  }
}

/**
 * Handle `POST /api/key/rotate`. Authenticates via Bearer key OR session cookie
 * (401 if anonymous), revokes the caller's existing active key(s), mints a fresh
 * one, and returns `200 { apiKey }` — the only time the new key is shown.
 * Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(k) (revoke active keys) + O(1) mint. Space complexity: O(1).
 */
export async function handleKeyRotate(request: Request, deps: AuthDeps): Promise<Response> {
  if (deps.db === null) {
    return unavailable('account store is not configured')
  }
  const db = deps.db
  try {
    const ctx = await authenticate(request, db, deps.sessionSecret ?? undefined)
    if (ctx.tier === 'anonymous') {
      return Response.json(
        { error: 'unauthorized', message: 'authentication required' },
        { status: STATUS_UNAUTHORIZED },
      )
    }
    const apiKey = await rotateApiKey(db, ctx.subject)
    return Response.json({ apiKey }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.error('handleKeyRotate', 'request failed', { errorClass: className })
    return Response.json({ error: 'rotate_failed' }, { status: statusForError(error) })
  }
}
