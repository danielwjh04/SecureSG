import { describe, expect, it } from 'vitest'
import { guardRedirect } from './routeGuard'

describe('guardRedirect', () => {
  it('leaves open routes untouched regardless of auth', () => {
    expect(guardRedirect('scanner', 'anonymous', false)).toBeNull()
    expect(guardRedirect('pricing', 'authenticated', false)).toBeNull()
  })

  describe('#dashboard', () => {
    it('redirects an anonymous visitor to login', () => {
      expect(guardRedirect('dashboard', 'anonymous', false)).toBe('#login')
    })

    it('lets an authenticated visitor through, and holds while loading', () => {
      expect(guardRedirect('dashboard', 'authenticated', false)).toBeNull()
      expect(guardRedirect('dashboard', 'loading', false)).toBeNull()
    })
  })

  it.each(['activity', 'integrations', 'settings'] as const)(
    'gates #%s for authenticated users',
    (route) => {
      expect(guardRedirect(route, 'anonymous', false)).toBe('#login')
      expect(guardRedirect(route, 'authenticated', false)).toBeNull()
      expect(guardRedirect(route, 'loading', false)).toBeNull()
    },
  )

  describe('#admin', () => {
    it('redirects an anonymous visitor to login', () => {
      expect(guardRedirect('admin', 'anonymous', false)).toBe('#login')
    })

    it('redirects an authenticated NON-admin to their dashboard', () => {
      expect(guardRedirect('admin', 'authenticated', false)).toBe('#dashboard')
    })

    it('lets an authenticated admin through', () => {
      expect(guardRedirect('admin', 'authenticated', true)).toBeNull()
    })

    it('holds (no redirect) while the session is still loading', () => {
      expect(guardRedirect('admin', 'loading', false)).toBeNull()
    })
  })
})
