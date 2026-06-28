import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Dashboard } from './Dashboard'
import type { AuthState } from '../hooks/useAuth'
import type { MeResponse, RecentScan, StatsResponse } from '../api/types'
import * as client from '../api/client'

const USER: MeResponse = {
  email: 'analyst@securesg.test',
  tier: 'free',
  createdAt: '2026-06-01T00:00:00.000Z',
  apiKeyPrefix: 'sk_live_42',
  role: 'member',
  isAdmin: false,
  isOwner: false,
}

function authState(): AuthState {
  return { status: 'authenticated', user: USER, isAdmin: false, isOwner: false, refresh: vi.fn() }
}

function emptyStats(): StatsResponse {
  return {
    tier: 'free',
    totals: { scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 },
    daily: [],
  }
}

function recentScan(partial: Partial<RecentScan> = {}): RecentScan {
  return {
    id: 'scan-1',
    verdict: 'BLOCK',
    source: { kind: 'url', ref: 'https://github.com/owner/evil-skill' },
    flagged: 2,
    headHash: 'a'.repeat(64),
    scannedAt: new Date().toISOString(),
    ...partial,
  }
}

/** Stub the recent-scans fetch so each test drives that section explicitly. */
function stubRecent(scans: RecentScan[]): void {
  vi.spyOn(client, 'fetchRecentScans').mockResolvedValue({ scans })
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Dashboard', () => {
  it('shows a loading line until the stats resolve', () => {
    // Never-resolving fetches hold both the stats and recent-scans sections in
    // their loading phase, with no async state update after the synchronous render.
    vi.spyOn(client, 'fetchStats').mockReturnValue(new Promise(() => {}))
    vi.spyOn(client, 'fetchRecentScans').mockReturnValue(new Promise(() => {}))
    render(<Dashboard user={USER} auth={authState()} />)

    expect(screen.getByText(/Loading your protection stats/)).toBeInTheDocument()
    // The greeting and key card render immediately around the loading body.
    expect(screen.getByText(USER.email)).toBeInTheDocument()
    expect(screen.getByText(/Regenerate key/)).toBeInTheDocument()
  })

  it('renders an intentional empty state for a new account with no scans', async () => {
    vi.spyOn(client, 'fetchStats').mockResolvedValue(emptyStats())
    stubRecent([])
    render(<Dashboard user={USER} auth={authState()} />)

    await waitFor(() =>
      expect(screen.getByText('No scans yet')).toBeInTheDocument(),
    )
    // Stat tiles still render (all zero) and the upgrade CTA shows for free tier.
    expect(screen.getByText('Scans run')).toBeInTheDocument()
    expect(screen.getByText('Threats blocked')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Upgrade to Pro/ })).toBeInTheDocument()
  })

  it('collapses the stat-card grid to a single column on mobile', async () => {
    vi.spyOn(client, 'fetchStats').mockResolvedValue(emptyStats())
    stubRecent([])
    const { container } = render(<Dashboard user={USER} auth={authState()} />)

    // The stat-card grid (rendered once stats resolve) is mobile-first single
    // column, widening to 2 at sm and 4 at lg.
    await waitFor(() => expect(screen.getByText('Scans run')).toBeInTheDocument())
    const grid = container.querySelector(
      '.grid.grid-cols-1.sm\\:grid-cols-2.lg\\:grid-cols-4',
    )
    expect(grid).not.toBeNull()
  })
})

describe('Dashboard · recent scans', () => {
  beforeEach(() => {
    vi.spyOn(client, 'fetchStats').mockResolvedValue(emptyStats())
  })

  it('renders the recent-scans rows with verdict, source, flagged chip, and time', async () => {
    stubRecent([
      recentScan({
        verdict: 'BLOCK',
        source: { kind: 'url', ref: 'https://github.com/owner/evil-skill' },
        flagged: 2,
        headHash: 'h1'.padEnd(64, '0'),
      }),
      recentScan({
        verdict: 'HUMAN_APPROVAL_REQUIRED',
        source: { kind: 'paste', ref: 'pasted-1' },
        flagged: 0,
        headHash: 'h2'.padEnd(64, '0'),
      }),
    ])
    render(<Dashboard user={USER} auth={authState()} />)

    await waitFor(() => expect(screen.getByText('Recent scans')).toBeInTheDocument())
    // Verdict pills: BLOCK shown, and HUMAN_APPROVAL_REQUIRED displays as REVIEW.
    expect(screen.getByText('BLOCK')).toBeInTheDocument()
    expect(screen.getByText('REVIEW')).toBeInTheDocument()
    // Sources: a URL renders by hostname; a paste renders the paste label.
    expect(screen.getByText('github.com')).toBeInTheDocument()
    expect(screen.getByText('Pasted skill')).toBeInTheDocument()
    // The flagged chip shows the count for the flagged row.
    expect(screen.getByText('2')).toBeInTheDocument()
    // A relative time renders for the just-now scan.
    expect(screen.getAllByText('just now').length).toBeGreaterThan(0)
  })

  it('shows the intentional empty state when there are no recent scans', async () => {
    stubRecent([])
    render(<Dashboard user={USER} auth={authState()} />)

    await waitFor(() =>
      expect(screen.getByText(/No scans yet — run one from the scanner/)).toBeInTheDocument(),
    )
  })

  it('falls back to the empty state when the recent-scans fetch fails', async () => {
    vi.spyOn(client, 'fetchRecentScans').mockRejectedValue(new Error('nope'))
    render(<Dashboard user={USER} auth={authState()} />)

    await waitFor(() =>
      expect(screen.getByText(/No scans yet — run one from the scanner/)).toBeInTheDocument(),
    )
  })
})

describe('Dashboard · API key copy', () => {
  beforeEach(() => {
    vi.spyOn(client, 'fetchStats').mockResolvedValue(emptyStats())
    stubRecent([])
  })

  it('copies the API key prefix and shows a "Copied" confirmation', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })

    render(<Dashboard user={USER} auth={authState()} />)

    // The persistent display shows the prefix with a copy button beside it.
    const copyButton = screen.getByRole('button', { name: /Copy API key prefix/ })
    expect(copyButton).toHaveTextContent('Copy')
    fireEvent.click(copyButton)

    expect(writeText).toHaveBeenCalledWith(USER.apiKeyPrefix)
    await waitFor(() => expect(copyButton).toHaveTextContent('Copied'))
  })
})
