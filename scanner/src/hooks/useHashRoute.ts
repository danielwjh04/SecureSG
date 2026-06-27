/**
 * Minimal hash-based routing for the single-page scanner: no router dependency,
 * just the two top-level surfaces. `#enterprise` shows the Enterprise page;
 * anything else is the scanner. Hash routing keeps the URL shareable and the
 * back button working without a history library.
 */

import { useEffect, useState } from 'react'

export type Route = 'scanner' | 'enterprise'
export type RouteTarget = 'top' | 'how'

export interface HashRoute {
  route: Route
  target: RouteTarget
}

const ENTERPRISE_HASH = '#enterprise'
const HOW_HASH = '#how'

/** Map the current location hash to a known route. */
function routeFromHash(): HashRoute {
  if (window.location.hash === ENTERPRISE_HASH) {
    return { route: 'enterprise', target: 'top' }
  }
  if (window.location.hash === HOW_HASH) {
    return { route: 'scanner', target: 'how' }
  }
  return { route: 'scanner', target: 'top' }
}

/**
 * Subscribe to the location hash and return the current {@link Route}. Re-renders
 * the consumer on `hashchange` (navbar link clicks, back/forward).
 *
 * Time complexity: O(1) per change. Space complexity: O(1).
 */
export function useHashRoute(): HashRoute {
  const [route, setRoute] = useState<HashRoute>(routeFromHash)
  useEffect(() => {
    const onChange = (): void => setRoute(routeFromHash())
    const previousScrollRestoration = window.history.scrollRestoration
    window.history.scrollRestoration = 'manual'
    window.addEventListener('hashchange', onChange)
    return () => {
      window.history.scrollRestoration = previousScrollRestoration
      window.removeEventListener('hashchange', onChange)
    }
  }, [])
  return route
}
