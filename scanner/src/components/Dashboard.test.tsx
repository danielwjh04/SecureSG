import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Dashboard } from './Dashboard'
import type { AuthState } from '../hooks/useAuth'
import type { MeResponse, StatsResponse } from '../api/types'
import * as client from '../api/client'

const USER: MeResponse = {
  email: 'analyst@securesg.test',
  tier: 'free',
  createdAt: '2026-06-01T00:00:00.000Z',
  apiKeyPrefix: 'sk_live_42',
  isAdmin: false,
}

function authState(): AuthState {
  return { status: 'authenticated', user: USER, isAdmin: false, refresh: vi.fn() }
}

function emptyStats(): StatsResponse {
  return {
    tier: 'free',
    totals: { scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 },
    daily: [],
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Dashboard', () => {
  it('shows a loading line until the stats resolve', () => {
    // A never-resolving fetch holds the dashboard in its loading phase.
    vi.spyOn(client, 'fetchStats').mockReturnValue(new Promise(() => {}))
    render(<Dashboard user={USER} auth={authState()} />)

    expect(screen.getByText(/Loading your protection stats/)).toBeInTheDocument()
    // The greeting and key card render immediately around the loading body.
    expect(screen.getByText(USER.email)).toBeInTheDocument()
    expect(screen.getByText(/Regenerate key/)).toBeInTheDocument()
  })

  it('renders an intentional empty state for a new account with no scans', async () => {
    vi.spyOn(client, 'fetchStats').mockResolvedValue(emptyStats())
    render(<Dashboard user={USER} auth={authState()} />)

    await waitFor(() =>
      expect(screen.getByText('No scans yet')).toBeInTheDocument(),
    )
    // Stat tiles still render (all zero) and the upgrade CTA shows for free tier.
    expect(screen.getByText('Scans run')).toBeInTheDocument()
    expect(screen.getByText('Threats blocked')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Upgrade to Pro/ })).toBeInTheDocument()
  })
})
