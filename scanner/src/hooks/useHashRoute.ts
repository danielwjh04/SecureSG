/**
 * Minimal hash-based routing for the single-page scanner: no router dependency,
 * just the top-level surfaces. The hash selects the surface — `#enterprise`,
 * `#pricing`, `#login`, `#register`, `#dashboard`, `#admin` — and anything else
 * is the scanner. Hash routing keeps the URL shareable and the back button
 * working without a history library.
 */

import { useEffect, useState } from 'react'

export type Route =
  | 'scanner'
  | 'enterprise'
  | 'pricing'
  | 'login'
  | 'register'
  | 'dashboard'
  | 'admin'
export type RouteTarget = 'top' | 'how'

export interface HashRoute {
  route: Route
  target: RouteTarget
}

/**
 * Map each known hash to its route. The leading `#` is stripped so a hash with a
 * trailing query (none today, but cheap insurance) still resolves. Every entry
 * lands on the `top` target except `#how`, which deep-links into the scanner
 * landing's how-it-works section.
 */
const HASH_ROUTES: Record<string, HashRoute> = {
  enterprise: { route: 'enterprise', target: 'top' },
  pricing: { route: 'pricing', target: 'top' },
  login: { route: 'login', target: 'top' },
  register: { route: 'register', target: 'top' },
  dashboard: { route: 'dashboard', target: 'top' },
  admin: { route: 'admin', target: 'top' },
  how: { route: 'scanner', target: 'how' },
}

const DEFAULT_ROUTE: HashRoute = { route: 'scanner', target: 'top' }

/** Map the current location hash to a known route. */
function routeFromHash(): HashRoute {
  const key = window.location.hash.replace(/^#/, '')
  return HASH_ROUTES[key] ?? DEFAULT_ROUTE
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
