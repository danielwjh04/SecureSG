/**
 * Email + password authentication routes: register, login, logout, me, and
 * key rotation. These sit alongside the existing Bearer-API-key auth — a
 * registered account gets BOTH a session cookie (for the browser) and an API key
 * (for programmatic callers).
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
import type { LoginPayload, RegisterPayload } from '../schemas/validate'
import { AuthError, ParseError, ScannerError } from '../errors'
import { loginSchema, registerSchema } from '../schemas/validate'
import {
  createUserWithPassword,
  findUserByEmail,
  getAccountProfile,
  rotateApiKey,
} from '../db/accounts'
import { hashPassword, verifyPassword } from '../auth/password'
import { authenticate } from '../middleware/auth'
import {
  buildClearedSessionCookie,
  buildSessionCookie,
  signSession,
} from '../auth/session'

const STATUS_OK = 200
const STATUS_CREATED = 201
const STATUS_UNAUTHORIZED = 401
const STATUS_CONFLICT = 409
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** A configured auth route's dependencies, assembled by the worker entry. */
export interface AuthDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
  readonly config: ScannerConfig
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
 * duplicate email with 409, hashes the password (PBKDF2), provisions a free user
 * with an API key, and returns `201 { user: { email, tier } }` with a session
 * cookie. Requires `env.DB` and `env.SESSION_SECRET` (503 otherwise).
 *
 * The minted API key is NOT returned by register (the contract returns only the
 * user); programmatic callers obtain one via `POST /api/key/rotate`.
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
  try {
    const body: RegisterPayload = await parseBody(request, registerSchema, 'register')

    const existing = await findUserByEmail(db, body.email)
    if (existing !== null) {
      return Response.json(
        { error: 'email_taken', message: 'an account with this email already exists' },
        { status: STATUS_CONFLICT },
      )
    }

    const passwordHash = await hashPassword(body.password, deps.config.pbkdf2Iterations)
    const { user } = await createUserWithPassword(db, body.email, passwordHash)

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
    console.error(`[handleRegister] ${className}`)
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'registration_failed' }, { status: statusForError(error) })
  }
}

/**
 * Handle `POST /api/login`. Validates `{ email, password }`, resolves the account
 * by email, and verifies the password against the stored PBKDF2 hash. On success
 * returns `200 { user: { email, tier } }` with a fresh session cookie. Any
 * failure — unknown email, account with no password (API-key-only), or wrong
 * password — returns the SAME generic 401, never revealing which.
 *
 * Requires `env.DB` and `env.SESSION_SECRET` (503 otherwise).
 *
 * Time complexity: O(iterations) (PBKDF2 verify) + O(1) lookup.
 * Space complexity: O(1).
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
    console.error(`[handleLogin] ${className}`)
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    return Response.json({ error: 'login_failed' }, { status: statusForError(error) })
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
 * apiKeyPrefix, isAdmin }`, where `apiKeyPrefix` is the non-secret brand prefix
 * when an active key exists, else `null`, and `isAdmin` is whether the profile
 * email is in `config.adminEmails`. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(1). Space complexity: O(1).
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
    return Response.json(
      {
        email: profile.email,
        tier: profile.tier,
        createdAt: profile.createdAt,
        apiKeyPrefix: profile.apiKeyPrefix,
        isAdmin: deps.config.adminEmails.has(profile.email.toLowerCase()),
      },
      { status: STATUS_OK },
    )
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleMe] ${className}`)
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
    console.error(`[handleKeyRotate] ${className}`)
    return Response.json({ error: 'rotate_failed' }, { status: statusForError(error) })
  }
}
