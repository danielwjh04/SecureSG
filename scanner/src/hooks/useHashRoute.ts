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
  | 'activity'
  | 'integrations'
  | 'settings'
  | 'admin'

/**
 * Map each known hash to its route. The leading `#` is stripped so a hash with a
 * trailing query (none today, but cheap insurance) still resolves. `#how` and
 * `#verify` resolve to the scanner landing (the How it works sections are folded
 * onto it as in-page anchors, scrolled to by id); `#scan` and any unknown hash
 * also fall back to the scanner landing.
 */
const HASH_ROUTES: Record<string, Route> = {
  pricing: 'pricing',
  login: 'login',
  register: 'register',
  dashboard: 'dashboard',
  scan: 'scanner',
  activity: 'activity',
  integrations: 'integrations',
  settings: 'settings',
  admin: 'admin',
  how: 'scanner',
  verify: 'scanner',
}

const DEFAULT_ROUTE: Route = 'scanner'

/** Map the current location hash to a known route. */
function routeFromHash(): Route {
  const key = window.location.hash.replace(/^#/, '')
  return HASH_ROUTES[key] ?? DEFAULT_ROUTE
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
