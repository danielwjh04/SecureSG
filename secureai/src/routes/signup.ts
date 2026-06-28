/**
 * `POST /api/signup` handler — provisions a free-tier account and returns its
 * API key exactly once.
 *
 * Validates the `{ email }` body with Zod at the edge, mints a user + key via
 * the accounts repository (which persists ONLY the key's SHA-256 digest), and
 * returns `{ apiKey, tier: 'free' }` at 201. The raw key is shown here and never
 * again — it cannot be recovered from the store.
 *
 * Signup requires persistence: with no `env.DB` binding there is nowhere to
 * provision the account, so the route returns 503 with a clear message rather
 * than fabricating a key it cannot honor.
 */

import type { Env } from '../config/env'
import type { SignupPayload } from '../schemas/validate'
import { AuthError, ParseError, ScannerError } from '../errors'
import { signupSchema } from '../schemas/validate'
import { d1Database, type Database } from '../db/database'
import { createFreeUser } from '../db/accounts'
import { log } from '../observability/logger'

const STATUS_CREATED = 201
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/**
 * Parse and Zod-validate the JSON body into a {@link SignupPayload}. A body that
 * is not JSON, or fails the signup schema, is a {@link ParseError} (mapped to
 * 422), never an unhandled throw.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} On non-JSON or schema-invalid input.
 */
async function parseSignupBody(request: Request): Promise<SignupPayload> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = signupSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid signup request: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Handle `POST /api/signup`. Requires `env.DB`; without it, returns 503. On
 * success, returns `{ apiKey, tier: 'free' }` at 201 — the only time the raw key
 * is ever exposed.
 *
 * Time complexity: O(1) (validate + two single-row inserts).
 * Space complexity: O(1).
 */
export async function handleSignup(
  request: Request,
  env: Env,
  db: Database | null = env.DB !== undefined && env.DB !== null ? d1Database(env.DB) : null,
): Promise<Response> {
  try {
    const body = await parseSignupBody(request)

    if (db === null) {
      return Response.json(
        { error: 'service_unavailable', message: 'account store is not configured' },
        { status: STATUS_SERVICE_UNAVAILABLE },
      )
    }

    const { user, apiKey } = await createFreeUser(db, body.email)

    return Response.json({ apiKey, tier: user.tier }, { status: STATUS_CREATED })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleSignup', 'request failed', { errorClass: className })
    if (error instanceof ParseError) {
      return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
    }
    if (error instanceof AuthError || error instanceof ScannerError) {
      // A failed provision (e.g. duplicate email) is a client-correctable fault,
      // but we do not leak which constraint tripped; a generic 500 with the
      // class name suffices for the caller and keeps the store opaque.
      return Response.json({ error: className, message }, { status: STATUS_SERVER_ERROR })
    }
    return Response.json({ error: className, message }, { status: STATUS_SERVER_ERROR })
  }
}
