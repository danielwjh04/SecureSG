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

    expect(result.current).toBe('scanner')
  })

  it('maps the how-it-works hash to the scanner landing (folded-in section anchor)', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#how'))

    expect(result.current).toBe('scanner')
  })

  it('maps the verify hash to the scanner landing (folded-in section anchor)', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#verify'))

    expect(result.current).toBe('scanner')
  })

  it.each([
    ['#pricing', 'pricing'],
    ['#login', 'login'],
    ['#register', 'register'],
    ['#dashboard', 'dashboard'],
    ['#scan', 'scanner'],
    ['#activity', 'activity'],
    ['#integrations', 'integrations'],
    ['#settings', 'settings'],
    ['#admin', 'admin'],
  ])('maps %s to the %s route', (hash, route) => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash(hash))

    expect(result.current).toBe(route)
  })

  it('falls back to the scanner route for an unknown hash', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#nope'))

    expect(result.current).toBe('scanner')
  })

  it('no longer treats #guard as a deep-link (falls back to the scanner)', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#guard'))

    // The Guard section was removed from the landing; #guard is just an unknown
    // hash and falls back to the scanner.
    expect(result.current).toBe('scanner')
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
