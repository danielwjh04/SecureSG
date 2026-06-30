/**
 * Guard device credential repository. Runtime Guard adapters use these
 * credentials instead of broad account API keys. Raw credentials are generated
 * once, returned to the caller once, and only their SHA-256 digest is stored.
 */

import type { Database, Row } from './database'
import type { AccountTier } from './accounts'
import { AuthError } from '../errors'
import { parseAccountTier, sha256Hex } from './accounts'
import { log } from '../observability/logger'

const DEVICE_CREDENTIAL_PREFIX = 'gd_secureai_'
const DEVICE_CREDENTIAL_BYTES = 32
const REQUIRED_SCOPE = 'guard:decision'

export interface GuardDeviceRecord {
  readonly id: string
  readonly userId: string
  readonly deviceId: string
  readonly name: string | null
  readonly integration: string
  readonly scopes: readonly string[]
  readonly status: string
  readonly createdAt: string
  readonly expiresAt: string
  readonly lastSeenAt: string | null
}

export interface MintedGuardDevice {
  readonly device: GuardDeviceRecord
  readonly credential: string
}

export interface ResolvedGuardDeviceCredential {
  readonly userId: string
  readonly tier: AccountTier
  readonly deviceId: string
  readonly integration: string
  readonly scopes: readonly string[]
  readonly credentialId: string
  readonly lastSeenAt: string | null
}

export interface CreateGuardDeviceInput {
  readonly userId: string
  readonly deviceId: string
  readonly name: string | null
  readonly integration: string
  readonly scopes: readonly string[]
  readonly createdAt: string
  readonly expiresAt: string
}

function generateGuardDeviceCredential(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(DEVICE_CREDENTIAL_BYTES))
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return `${DEVICE_CREDENTIAL_PREFIX}${hex}`
}

function requireString(row: Row, column: string): string {
  const value = row[column]
  if (typeof value !== 'string' || value.length === 0) {
    throw new AuthError(`stored guard device record missing string column: ${column}`)
  }
  return value
}

function optionalString(row: Row, column: string): string | null {
  const value = row[column]
  return typeof value === 'string' && value.length > 0 ? value : null
}

function parseTier(row: Row): AccountTier {
  const tier = parseAccountTier(row['tier'])
  if (tier === null) {
    throw new AuthError(`stored account tier is not recognized: ${String(row['tier'])}`)
  }
  return tier
}

function parseScopes(raw: unknown): readonly string[] {
  if (typeof raw !== 'string') {
    throw new AuthError('stored guard device record missing scopes')
  }
  return raw
    .split(',')
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0)
}

function rowToDevice(row: Row): GuardDeviceRecord {
  return {
    id: requireString(row, 'id'),
    userId: requireString(row, 'user_id'),
    deviceId: requireString(row, 'device_id'),
    name: optionalString(row, 'name'),
    integration: requireString(row, 'integration'),
    scopes: parseScopes(row['scopes']),
    status: requireString(row, 'status'),
    createdAt: requireString(row, 'created_at'),
    expiresAt: requireString(row, 'expires_at'),
    lastSeenAt: optionalString(row, 'last_seen_at'),
  }
}

/**
 * Register a device-scoped Guard credential for a user.
 *
 * Time complexity: O(1), one insert. Space complexity: O(1).
 */
export async function createGuardDeviceCredential(
  db: Database,
  input: CreateGuardDeviceInput,
): Promise<MintedGuardDevice> {
  const credential = generateGuardDeviceCredential()
  const credentialHash = await sha256Hex(credential)
  const id = crypto.randomUUID()
  const scopes = input.scopes.includes(REQUIRED_SCOPE)
    ? input.scopes
    : [REQUIRED_SCOPE, ...input.scopes]
  try {
    await db.execute(
      'INSERT INTO guard_device_credentials ' +
        '(id, credential_sha256, user_id, device_id, name, integration, scopes, status, created_at, expires_at, last_seen_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        id,
        credentialHash,
        input.userId,
        input.deviceId,
        input.name,
        input.integration,
        scopes.join(','),
        'active',
        input.createdAt,
        input.expiresAt,
        null,
      ],
    )
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    log.error('guardDevices', 'create failed', { errorClass: name })
    throw new AuthError('failed to register guard device', { cause: error })
  }

  return {
    credential,
    device: {
      id,
      userId: input.userId,
      deviceId: input.deviceId,
      name: input.name,
      integration: input.integration,
      scopes,
      status: 'active',
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      lastSeenAt: null,
    },
  }
}

/**
 * Resolve a presented Guard device credential, or null on miss, expiry, revoked
 * status, missing scope, or unverified owner account.
 *
 * Time complexity: O(1), digest primary-key lookup plus user join. Space: O(1).
 */
export async function findGuardDeviceByCredential(
  db: Database,
  rawCredential: string,
  nowIso: string,
): Promise<ResolvedGuardDeviceCredential | null> {
  const credentialHash = await sha256Hex(rawCredential)
  const row = await db.queryOne(
    'SELECT g.id AS id, g.user_id AS user_id, g.device_id AS device_id, g.integration AS integration, ' +
      'g.scopes AS scopes, u.tier AS tier, g.last_seen_at AS last_seen_at ' +
      'FROM guard_device_credentials g JOIN users u ON u.id = g.user_id ' +
      "WHERE g.credential_sha256 = ? AND g.status = 'active' AND g.expires_at > ? AND u.email_verified = 1",
    [credentialHash, nowIso],
  )
  if (row === null) {
    return null
  }
  const scopes = parseScopes(row['scopes'])
  if (!scopes.includes(REQUIRED_SCOPE)) {
    return null
  }
  return {
    userId: requireString(row, 'user_id'),
    tier: parseTier(row),
    deviceId: requireString(row, 'device_id'),
    integration: requireString(row, 'integration'),
    scopes,
    credentialId: requireString(row, 'id'),
    lastSeenAt: optionalString(row, 'last_seen_at'),
  }
}

/** Mark a resolved Guard device credential as recently seen. */
export async function touchGuardDeviceCredential(
  db: Database,
  credentialId: string,
  lastSeenAt: string,
): Promise<void> {
  await db.execute(
    'UPDATE guard_device_credentials SET last_seen_at = ? WHERE id = ?',
    [lastSeenAt, credentialId],
  )
}

/** List all Guard device credentials for one account, newest first. */
export async function listGuardDevices(
  db: Database,
  userId: string,
): Promise<readonly GuardDeviceRecord[]> {
  const rows = await db.queryAll(
    'SELECT id, user_id, device_id, name, integration, scopes, status, created_at, expires_at, last_seen_at ' +
      'FROM guard_device_credentials WHERE user_id = ? ORDER BY created_at DESC',
    [userId],
  )
  return rows.map(rowToDevice)
}

/** Revoke one account-owned Guard device credential. */
export async function revokeGuardDevice(
  db: Database,
  userId: string,
  id: string,
): Promise<boolean> {
  const result = await db.execute(
    "UPDATE guard_device_credentials SET status = 'revoked' WHERE user_id = ? AND id = ? AND status = 'active'",
    [userId, id],
  )
  return result.changes > 0
}
