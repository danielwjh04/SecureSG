import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import { webcrypto } from 'node:crypto'

// Proof re-verification hashes via globalThis.crypto.subtle (Web Crypto). jsdom
// does not always expose it, so polyfill from Node's webcrypto when absent.
// This keeps the browser proof tests byte-identical to the Worker.
if (globalThis.crypto?.subtle === undefined) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
  })
}

// motion's `whileInView` registers an IntersectionObserver, which jsdom does not
// implement. Polyfill a no-op observer so components that animate on scroll
// (e.g. the Pricing plan grid) render in tests; the elements simply never enter
// the "in view" state, which is correct for a zero-size jsdom viewport.
if (typeof globalThis.IntersectionObserver === 'undefined') {
  class NoopIntersectionObserver implements IntersectionObserver {
    readonly root = null
    readonly rootMargin = ''
    readonly scrollMargin = ''
    readonly thresholds: ReadonlyArray<number> = []
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
    takeRecords(): IntersectionObserverEntry[] {
      return []
    }
  }
  Object.defineProperty(globalThis, 'IntersectionObserver', {
    value: NoopIntersectionObserver,
    configurable: true,
    writable: true,
  })
}

afterEach(() => {
  cleanup()
})
