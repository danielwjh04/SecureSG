import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { useHashRoute } from './useHashRoute'

function replaceHash(hash: string): void {
  window.history.replaceState(null, '', `${window.location.pathname}${hash}`)
}

function dispatchHash(hash: string): void {
  replaceHash(hash)
  window.dispatchEvent(new HashChangeEvent('hashchange'))
}

describe('useHashRoute', () => {
  it('treats the old enterprise hash as the scanner route', () => {
    replaceHash('#enterprise')

    const { result } = renderHook(() => useHashRoute())

    expect(result.current).toEqual({ route: 'scanner', target: 'top' })
  })

  it('maps the how-it-works hash to the scanner route and how target', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#how'))

    expect(result.current).toEqual({ route: 'scanner', target: 'how' })
  })

  it('maps the verify hash to the scanner route and verify target', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#verify'))

    expect(result.current).toEqual({ route: 'scanner', target: 'verify' })
  })

  it.each([
    ['#pricing', 'pricing'],
    ['#login', 'login'],
    ['#register', 'register'],
    ['#dashboard', 'dashboard'],
    ['#scan', 'scanner'],
    ['#protection', 'protection'],
    ['#activity', 'activity'],
    ['#integrations', 'integrations'],
    ['#settings', 'settings'],
    ['#admin', 'admin'],
  ])('maps %s to the %s route at the top target', (hash, route) => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash(hash))

    expect(result.current).toEqual({ route, target: 'top' })
  })

  it('falls back to the scanner route for an unknown hash', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#nope'))

    expect(result.current).toEqual({ route: 'scanner', target: 'top' })
  })

  it('no longer treats #guard as a deep-link target (falls back to the scanner top)', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#guard'))

    // The Guard section was removed from the landing; #guard is now just an
    // unknown hash and must not resolve to a `guard` target.
    expect(result.current).toEqual({ route: 'scanner', target: 'top' })
  })

  it('uses manual scroll restoration while mounted', () => {
    replaceHash('')
    const previousScrollRestoration = window.history.scrollRestoration

    const { unmount } = renderHook(() => useHashRoute())

    expect(window.history.scrollRestoration).toBe('manual')
    unmount()
    expect(window.history.scrollRestoration).toBe(previousScrollRestoration)
  })
})
