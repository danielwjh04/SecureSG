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
  it('maps the enterprise hash to the enterprise route at the top target', () => {
    replaceHash('#enterprise')

    const { result } = renderHook(() => useHashRoute())

    expect(result.current).toEqual({ route: 'enterprise', target: 'top' })
  })

  it('maps the how-it-works hash to the scanner route and how target', () => {
    replaceHash('')
    const { result } = renderHook(() => useHashRoute())

    act(() => dispatchHash('#how'))

    expect(result.current).toEqual({ route: 'scanner', target: 'how' })
  })

  it.each([
    ['#pricing', 'pricing'],
    ['#login', 'login'],
    ['#register', 'register'],
    ['#dashboard', 'dashboard'],
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

  it('uses manual scroll restoration while mounted', () => {
    replaceHash('')
    const previousScrollRestoration = window.history.scrollRestoration

    const { unmount } = renderHook(() => useHashRoute())

    expect(window.history.scrollRestoration).toBe('manual')
    unmount()
    expect(window.history.scrollRestoration).toBe(previousScrollRestoration)
  })
})
