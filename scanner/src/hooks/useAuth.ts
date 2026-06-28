/**
 * App-level authentication state. Fetches `GET /api/me` once on mount to learn
 * whether a session cookie is present, then exposes the signed-in account plus a
 * `refresh` the auth screens call after a login/register/logout so the navbar
 * and dashboard re-read the session without a full reload.
 *
 * A 401 is the expected logged-out state, not an error: it resolves to a `null`
 * user. Any other transport failure also resolves to `null` (fail-closed to
 * "logged out") so a flaky `/api/me` never strands the UI.
 */

import { useCallback, useEffect, useState } from 'react'
import { ApiError, fetchMe } from '../api/client'
import type { MeResponse } from '../api/types'

export type AuthStatus = 'loading' | 'authenticated' | 'anonymous'

export interface AuthState {
  status: AuthStatus
  /** The signed-in account, or `null` while loading or when logged out. */
  user: MeResponse | null
  /** Whether the account may VIEW the admin surface (false while loading / logged out). */
  isAdmin: boolean
  /** Whether the account may MANAGE roles — owner only (false while loading / logged out). */
  isOwner: boolean
  /** Re-read `GET /api/me`; call after a login, register, or logout. */
  refresh: () => Promise<void>
}

/**
 * Subscribe to the current session.
 *
 * Time complexity: O(1) per refresh. Space complexity: O(1).
 */
export function useAuth(): AuthState {
  const [user, setUser] = useState<MeResponse | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const me = await fetchMe()
      setUser(me)
      setStatus('authenticated')
    } catch (error) {
      // 401 is the normal logged-out state; any other failure also degrades to
      // "anonymous" so the UI never hangs on a stuck `loading`.
      if (!(error instanceof ApiError)) {
        console.warn('useAuth: /api/me failed', error)
      }
      setUser(null)
      setStatus('anonymous')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  return {
    status,
    user,
    isAdmin: user?.isAdmin ?? false,
    isOwner: user?.isOwner ?? false,
    refresh,
  }
}
