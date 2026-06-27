/**
 * Minimal hash-based routing for the single-page scanner: no router dependency,
 * just the two top-level surfaces. `#enterprise` shows the Enterprise page;
 * anything else is the scanner. Hash routing keeps the URL shareable and the
 * back button working without a history library.
 */

import { useEffect, useState } from 'react'

export type Route = 'scanner' | 'enterprise'

/** Map the current location hash to a known route. */
function routeFromHash(): Route {
  return window.location.hash === '#enterprise' ? 'enterprise' : 'scanner'
}

/**
 * Subscribe to the location hash and return the current {@link Route}. Re-renders
 * the consumer on `hashchange` (navbar link clicks, back/forward).
 *
 * Time complexity: O(1) per change. Space complexity: O(1).
 */
export function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(routeFromHash)
  useEffect(() => {
    const onChange = (): void => setRoute(routeFromHash())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return route
}
