import { describe, expect, it } from 'vitest'
import {
  ASSIGNABLE_ROLES,
  canManageRoles,
  canViewAdmin,
  effectiveRole,
  parseAssignableRole,
  parseStoredRole,
} from './roles'

const OWNERS: ReadonlySet<string> = new Set(['owner@example.com'])

describe('parseStoredRole', () => {
  it('accepts the two assignable roles verbatim', () => {
    expect(parseStoredRole('member')).toBe('member')
    expect(parseStoredRole('admin')).toBe('admin')
  })

  it('fails closed to member for anything unrecognized', () => {
    expect(parseStoredRole('owner')).toBe('member')
    expect(parseStoredRole('superuser')).toBe('member')
    expect(parseStoredRole('')).toBe('member')
    expect(parseStoredRole(null)).toBe('member')
    expect(parseStoredRole(undefined)).toBe('member')
    expect(parseStoredRole(42)).toBe('member')
  })
})

describe('parseAssignableRole', () => {
  it('returns the role for an allowlisted value', () => {
    expect(parseAssignableRole('member')).toBe('member')
    expect(parseAssignableRole('admin')).toBe('admin')
  })

  it('returns null for owner and any other value (never assignable)', () => {
    expect(parseAssignableRole('owner')).toBeNull()
    expect(parseAssignableRole('root')).toBeNull()
    expect(parseAssignableRole(null)).toBeNull()
    expect(parseAssignableRole(7)).toBeNull()
  })

  it('exposes the assignable allowlist without owner', () => {
    expect(ASSIGNABLE_ROLES.has('member')).toBe(true)
    expect(ASSIGNABLE_ROLES.has('admin')).toBe(true)
    expect(ASSIGNABLE_ROLES.has('owner')).toBe(false)
  })
})

describe('effectiveRole', () => {
  it('returns owner for an allowlisted email regardless of the stored column', () => {
    expect(effectiveRole('owner@example.com', 'member', OWNERS)).toBe('owner')
    expect(effectiveRole('owner@example.com', 'admin', OWNERS)).toBe('owner')
    expect(effectiveRole('owner@example.com', null, OWNERS)).toBe('owner')
  })

  it('matches the owner allowlist case-insensitively', () => {
    expect(effectiveRole('OWNER@example.com', 'member', OWNERS)).toBe('owner')
  })

  it('returns the stored role for a non-owner email', () => {
    expect(effectiveRole('a@example.com', 'admin', OWNERS)).toBe('admin')
    expect(effectiveRole('a@example.com', 'member', OWNERS)).toBe('member')
  })

  it('fails closed to member for a corrupt stored role on a non-owner', () => {
    expect(effectiveRole('a@example.com', 'owner', OWNERS)).toBe('member')
    expect(effectiveRole('a@example.com', 'garbage', OWNERS)).toBe('member')
    expect(effectiveRole('a@example.com', null, OWNERS)).toBe('member')
  })
})

describe('canViewAdmin / canManageRoles', () => {
  it('lets owners and admins view, but only owners manage', () => {
    expect(canViewAdmin('owner')).toBe(true)
    expect(canViewAdmin('admin')).toBe(true)
    expect(canViewAdmin('member')).toBe(false)

    expect(canManageRoles('owner')).toBe(true)
    expect(canManageRoles('admin')).toBe(false)
    expect(canManageRoles('member')).toBe(false)
  })
})
