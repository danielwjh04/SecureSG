/**
 * Device credential management for Guard adapters. Account credentials or a
 * session can register, list, and revoke local Guard devices. The raw device
 * credential is returned once from registration and never stored.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type {
  GuardDeviceRegisterPayload,
  GuardDeviceRevokePayload,
} from '../schemas/validate'
import { AuthError, GuardDeviceLimitError, ParseError, ScannerError } from '../errors'
import {
  guardDeviceRegisterSchema,
  guardDeviceRevokeSchema,
} from '../schemas/validate'
import {
  activeGuardDeviceExists,
  countActiveGuardDevices,
  createGuardDeviceCredential,
  listGuardDevices,
  revokeGuardDevice,
  type GuardDeviceRecord,
} from '../db/guardDevices'
import { authenticate } from '../middleware/auth'
import { log } from '../observability/logger'

const STATUS_OK = 200
const STATUS_CREATED = 201
const STATUS_UNAUTHORIZED = 401
const STATUS_TOO_MANY_REQUESTS = 429
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503
const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000

export interface GuardDeviceDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
  readonly config: ScannerConfig
}

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

async function authenticatedSubject(request: Request, deps: GuardDeviceDeps): Promise<string | Response> {
  if (deps.db === null) {
    return Response.json(
      { error: 'service_unavailable', message: 'account store is not configured' },
      { status: STATUS_SERVICE_UNAVAILABLE },
    )
  }
  const ctx = await authenticate(request, deps.db, deps.sessionSecret ?? undefined)
  if (ctx.tier === 'anonymous') {
    return Response.json(
      { error: 'unauthorized', message: 'authentication required' },
      { status: STATUS_UNAUTHORIZED },
    )
  }
  return ctx.subject
}

function publicDevice(device: GuardDeviceRecord): Record<string, unknown> {
  return {
    id: device.id,
    deviceId: device.deviceId,
    name: device.name,
    integration: device.integration,
    scopes: device.scopes,
    status: device.status,
    createdAt: device.createdAt,
    expiresAt: device.expiresAt,
    lastSeenAt: device.lastSeenAt,
  }
}

function errorResponse(module: string, error: unknown): Response {
  const className = error instanceof Error ? error.constructor.name : typeof error
  const message = error instanceof Error ? error.message : String(error)
  log.error(module, 'request failed', { errorClass: className })
  if (error instanceof ParseError) {
    return Response.json({ error: className, message }, { status: STATUS_UNPROCESSABLE })
  }
  if (error instanceof GuardDeviceLimitError) {
    return Response.json({ error: className, message }, { status: STATUS_TOO_MANY_REQUESTS })
  }
  if (error instanceof AuthError || error instanceof ScannerError) {
    return Response.json({ error: className, message }, { status: STATUS_SERVER_ERROR })
  }
  return Response.json({ error: className, message }, { status: STATUS_SERVER_ERROR })
}

/** Register one Guard device and return its one-time raw credential. */
export async function handleGuardDeviceRegister(
  request: Request,
  deps: GuardDeviceDeps,
): Promise<Response> {
  try {
    const subject = await authenticatedSubject(request, deps)
    if (typeof subject !== 'string') {
      return subject
    }
    const db = deps.db
    if (db === null) {
      return Response.json(
        { error: 'service_unavailable', message: 'account store is not configured' },
        { status: STATUS_SERVICE_UNAVAILABLE },
      )
    }
    const body: GuardDeviceRegisterPayload = await parseBody(
      request,
      guardDeviceRegisterSchema,
      'guard device register',
    )
    const deviceId = body.deviceId ?? crypto.randomUUID()
    if (!(await activeGuardDeviceExists(db, subject, deviceId, body.integration))) {
      if ((await countActiveGuardDevices(db, subject)) >= deps.config.guardMaxDevicesPerAccount) {
        throw new GuardDeviceLimitError('active device limit reached for this account')
      }
    }
    const createdAt = new Date()
    const expiresAt = new Date(
      createdAt.getTime() + deps.config.guardDeviceCredentialTtlDays * MILLISECONDS_PER_DAY,
    )
    const minted = await createGuardDeviceCredential(db, {
      userId: subject,
      deviceId,
      name: body.name ?? null,
      integration: body.integration,
      scopes: body.scopes ?? ['guard:decision'],
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    })
    return Response.json(
      { device: publicDevice(minted.device), credential: minted.credential },
      { status: STATUS_CREATED },
    )
  } catch (error: unknown) {
    return errorResponse('handleGuardDeviceRegister', error)
  }
}

/** List Guard devices for the authenticated account. */
export async function handleGuardDeviceList(
  request: Request,
  deps: GuardDeviceDeps,
): Promise<Response> {
  try {
    const subject = await authenticatedSubject(request, deps)
    if (typeof subject !== 'string') {
      return subject
    }
    if (deps.db === null) {
      return Response.json(
        { error: 'service_unavailable', message: 'account store is not configured' },
        { status: STATUS_SERVICE_UNAVAILABLE },
      )
    }
    const devices = await listGuardDevices(deps.db, subject)
    return Response.json({ devices: devices.map(publicDevice) }, { status: STATUS_OK })
  } catch (error: unknown) {
    return errorResponse('handleGuardDeviceList', error)
  }
}

/** Revoke one Guard device credential owned by the authenticated account. */
export async function handleGuardDeviceRevoke(
  request: Request,
  deps: GuardDeviceDeps,
): Promise<Response> {
  try {
    const subject = await authenticatedSubject(request, deps)
    if (typeof subject !== 'string') {
      return subject
    }
    if (deps.db === null) {
      return Response.json(
        { error: 'service_unavailable', message: 'account store is not configured' },
        { status: STATUS_SERVICE_UNAVAILABLE },
      )
    }
    const body: GuardDeviceRevokePayload = await parseBody(
      request,
      guardDeviceRevokeSchema,
      'guard device revoke',
    )
    const revoked = await revokeGuardDevice(deps.db, subject, body.id)
    return Response.json({ revoked }, { status: STATUS_OK })
  } catch (error: unknown) {
    return errorResponse('handleGuardDeviceRevoke', error)
  }
}
