/**
 * Guard-specific authentication. Generic API routes still accept account API
 * keys or sessions through `authenticate`; runtime Guard calls prefer
 * device-scoped credentials and only accept account credentials when explicitly
 * configured as a compatibility fallback.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { AuthTier } from './auth'
import { authenticate } from './auth'
import {
  findGuardDeviceByCredential,
  touchGuardDeviceCredential,
} from '../db/guardDevices'
import { log, errorClassOf } from '../observability/logger'

const AUTHORIZATION_HEADER = 'Authorization'
const BEARER_SCHEME = /^Bearer\s+(.+)$/i
const CLIENT_IP_HEADER = 'CF-Connecting-IP'
const UNKNOWN_IP = 'unknown'
const ANON_SUBJECT_PREFIX = 'anon:'

export type GuardCredentialKind = 'guard_device' | 'account'

export interface GuardAuthContext {
  readonly subject: string
  readonly tier: AuthTier
  readonly credentialKind: GuardCredentialKind | 'anonymous'
  readonly deviceId?: string
  readonly integration?: string
}

function extractBearerKey(request: Request): string | null {
  const header = request.headers.get(AUTHORIZATION_HEADER)
  if (header === null) {
    return null
  }
  const match = BEARER_SCHEME.exec(header.trim())
  if (match === null) {
    return null
  }
  const key = (match[1] ?? '').trim()
  return key.length === 0 ? null : key
}

function anonymousContext(request: Request): GuardAuthContext {
  const ip = request.headers.get(CLIENT_IP_HEADER)?.trim()
  return {
    subject: `${ANON_SUBJECT_PREFIX}${ip && ip.length > 0 ? ip : UNKNOWN_IP}`,
    tier: 'anonymous',
    credentialKind: 'anonymous',
  }
}

/**
 * Return true when a last_seen_at write is due: null means never written, or
 * the elapsed time since the last write meets or exceeds the throttle window.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function lastSeenWriteDue(
  lastSeenAt: string | null,
  nowIso: string,
  throttleSeconds: number,
): boolean {
  if (lastSeenAt === null) {
    return true
  }
  return Date.parse(nowIso) - Date.parse(lastSeenAt) >= throttleSeconds * 1000
}

/**
 * Resolve a runtime Guard caller. A valid device credential wins. Account API
 * keys or sessions are accepted only when `guardAllowAccountCredentials` is on.
 *
 * Time complexity: O(1), one credential lookup plus optional fallback auth.
 * Space complexity: O(1).
 */
export async function authenticateGuard(
  request: Request,
  db: Database,
  config: ScannerConfig,
  nowIso: string,
  sessionSecret?: string,
): Promise<GuardAuthContext> {
  const rawKey = extractBearerKey(request)
  if (rawKey !== null) {
    const device = await findGuardDeviceByCredential(db, rawKey, nowIso)
    if (device !== null) {
      if (lastSeenWriteDue(device.lastSeenAt, nowIso, config.guardLastSeenThrottleSeconds)) {
        try {
          await touchGuardDeviceCredential(db, device.credentialId, nowIso)
        } catch (error: unknown) {
          log.warn('guardAuth', 'last-seen update failed', { errorClass: errorClassOf(error) })
        }
      }
      return {
        subject: device.userId,
        tier: device.tier,
        credentialKind: 'guard_device',
        deviceId: device.deviceId,
        integration: device.integration,
      }
    }
  }

  if (config.guardAllowAccountCredentials) {
    const account = await authenticate(request, db, sessionSecret)
    if (account.tier !== 'anonymous') {
      return { ...account, credentialKind: 'account' }
    }
  }

  return anonymousContext(request)
}
