/**
 * Minimal hash-based routing for the single-page scanner: no router dependency,
 * just the top-level surfaces. Hash routing keeps the URL shareable and the
 * back button working without a history library.
 */

import { useEffect, useState } from 'react'

export type Route =
  | 'scanner'
  | 'pricing'
  | 'login'
  | 'register'
  | 'dashboard'
  | 'protection'
  | 'activity'
  | 'integrations'
  | 'settings'
  | 'admin'
export type RouteTarget = 'top' | 'how' | 'verify'

export interface HashRoute {
  route: Route
  target: RouteTarget
}

/**
 * Map each known hash to its route. The leading `#` is stripped so a hash with a
 * trailing query (none today, but cheap insurance) still resolves. Every entry
 * lands on the `top` target except `#how`, which deep-links into the scanner
 * landing's how-it-works section, and `#verify`, which deep-links into the
 * verify-it section.
 */
const HASH_ROUTES: Record<string, HashRoute> = {
  pricing: { route: 'pricing', target: 'top' },
  login: { route: 'login', target: 'top' },
  register: { route: 'register', target: 'top' },
  dashboard: { route: 'dashboard', target: 'top' },
  scan: { route: 'scanner', target: 'top' },
  protection: { route: 'protection', target: 'top' },
  activity: { route: 'activity', target: 'top' },
  integrations: { route: 'integrations', target: 'top' },
  settings: { route: 'settings', target: 'top' },
  admin: { route: 'admin', target: 'top' },
  how: { route: 'scanner', target: 'how' },
  verify: { route: 'scanner', target: 'verify' },
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
