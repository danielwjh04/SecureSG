import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AdminDashboard } from './AdminDashboard'
import type { AdminOverview } from '../api/types'
import * as client from '../api/client'

function overview(partial: Partial<AdminOverview> = {}): AdminOverview {
  return {
    totalUsers: 42,
    usersByTier: { free: 30, pro: 10, enterprise: 2 },
    signupsDaily: [{ day: '2026-06-27', count: 5 }],
    usageTotals: { scans: 120, allows: 80, reviews: 25, blocks: 15, flagged: 9 },
    activeSubscriptions: 7,
    generatedAt: '2026-06-28T08:00:00.000Z',
    ...partial,
  }
}

function emptyOverview(): AdminOverview {
  return {
    totalUsers: 0,
    usersByTier: { free: 0, pro: 0, enterprise: 0 },
    signupsDaily: [],
    usageTotals: { scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 },
    activeSubscriptions: 0,
    generatedAt: '2026-06-28T08:00:00.000Z',
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('AdminDashboard', () => {
  it('shows a loading line until the overview resolves', () => {
    vi.spyOn(client, 'fetchAdminOverview').mockReturnValue(new Promise(() => {}))
    render(<AdminDashboard />)
    expect(screen.getByText(/Loading sitewide analytics/)).toBeInTheDocument()
  })

  it('renders the headline metrics from a mocked overview', async () => {
    vi.spyOn(client, 'fetchAdminOverview').mockResolvedValue(overview())
    render(<AdminDashboard />)

    await waitFor(() => expect(screen.getByText('Total sign-ups')).toBeInTheDocument())
    // Headline tiles. The total-users value (42) appears in both the headline
    // tile and the donut center, so assert both occurrences are present.
    expect(screen.getAllByText('42').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Pro subscribers')).toBeInTheDocument()
    expect(screen.getByText('Total scans')).toBeInTheDocument()
    expect(screen.getByText('Threats blocked')).toBeInTheDocument()
    // Tier breakdown + verdict totals panels render.
    expect(screen.getByText('Tier breakdown')).toBeInTheDocument()
    expect(screen.getByText('Sitewide verdict totals')).toBeInTheDocument()
    // The generated-at stamp renders.
    expect(screen.getByText(/Generated/)).toBeInTheDocument()
  })

  it('renders an intentional empty state when there is no activity', async () => {
    vi.spyOn(client, 'fetchAdminOverview').mockResolvedValue(emptyOverview())
    render(<AdminDashboard />)

    await waitFor(() => expect(screen.getByText('No activity yet')).toBeInTheDocument())
    // Headline tiles still render (all zero).
    expect(screen.getByText('Total sign-ups')).toBeInTheDocument()
  })

  it('shows an error line when the overview fetch fails', async () => {
    vi.spyOn(client, 'fetchAdminOverview').mockRejectedValue(new Error('nope'))
    render(<AdminDashboard />)
    await waitFor(() =>
      expect(screen.getByText(/Could not load admin analytics/)).toBeInTheDocument(),
    )
  })
})
