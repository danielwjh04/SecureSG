/**
 * Pure route-guard decisions for the gated SPA surfaces. Kept side-effect-free
 * so the redirect policy is unit-testable
 * without mounting the whole app; `App` calls these inside an effect and issues
 * the actual `window.location.assign`.
 */

import type { AuthStatus } from '../hooks/useAuth'
import type { Route } from '../hooks/useHashRoute'

const AUTH_ROUTES = new Set<Route>([
  'dashboard',
  'activity',
  'integrations',
  'settings',
])

/**
 * The hash to redirect a visitor to when the current gated route is not allowed
 * for them, or `null` when no redirect is needed (the route is open, or the
 * session is still resolving, or access is granted).
 *
 * - Authenticated app pages: anonymous visitors are bounced to `#login`. While
 *   the session is still `loading`, no decision is made (return `null`) so a
 *   brief load does not flash the login screen.
 * - `#admin`: anonymous visitors go to `#login`; an authenticated NON-admin is
 *   bounced to `#dashboard` (they have an account, just not admin rights). While
 *   loading, no decision is made.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @param route The current hash route.
 * @param status The resolved auth status.
 * @param isAdmin Whether the signed-in account is an admin.
 * @returns The redirect hash (e.g. `'#login'`), or `null` to stay put.
 */
export function guardRedirect(
  route: Route,
  status: AuthStatus,
  isAdmin: boolean,
): string | null {
  if (AUTH_ROUTES.has(route)) {
    return status === 'anonymous' ? '#login' : null
  }
  if (route === 'admin') {
    if (status === 'anonymous') {
      return '#login'
    }
    if (status === 'authenticated' && !isAdmin) {
      return '#dashboard'
    }
    return null
  }
  return null
}
