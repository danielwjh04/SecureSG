import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Protection } from './Protection'
import { Activity } from './Activity'
import { Integrations } from './Integrations'
import { Settings } from './Settings'
import * as client from '../api/client'
import { browserPairingUrl, guardInstallCommand } from '../config'
import type { AuthState } from '../hooks/useAuth'
import type { MeResponse, RecentScan, StatsResponse } from '../api/types'

const USER: MeResponse = {
  email: 'ada@secureai.test',
  tier: 'personal',
  createdAt: '2026-06-01T00:00:00.000Z',
  apiKeyPrefix: 'sk_secureai_',
  firstName: 'Ada',
  lastName: 'Lovelace',
  role: 'member',
  isAdmin: false,
  isOwner: false,
}

function stats(): StatsResponse {
  return {
    tier: 'personal',
    totals: { scans: 12, allows: 8, reviews: 2, blocks: 2, flagged: 3 },
    daily: [{ day: new Date().toISOString().slice(0, 10), scans: 2, allows: 0, reviews: 0, blocks: 2, flagged: 2 }],
  }
}

function scan(partial: Partial<RecentScan> = {}): RecentScan {
  return {
    id: 'scan-1',
    verdict: 'HUMAN_APPROVAL_REQUIRED',
    source: { kind: 'mcp', ref: 'mcp-config' },
    flagged: 1,
    headHash: 'abcdef1234567890',
    scannedAt: new Date().toISOString(),
    ...partial,
  }
}

function authState(): AuthState {
  return {
    status: 'authenticated',
    user: USER,
    isAdmin: false,
    isOwner: false,
    refresh: vi.fn().mockResolvedValue(undefined),
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Personal app pages', () => {
  it('renders protection stats and the browser boundary', async () => {
    vi.spyOn(client, 'fetchStats').mockResolvedValue(stats())

    render(<Protection />)

    await waitFor(() => expect(screen.getByText('Your SecureAI coverage')).toBeInTheDocument())
    expect(screen.getByText('Browser ingestion')).toBeInTheDocument()
    expect(screen.getByText(/cannot see actions an AI provider runs only on its own servers/)).toBeInTheDocument()
  })

  it('renders recent activity for MCP and review scans', async () => {
    vi.spyOn(client, 'fetchRecentScans').mockResolvedValue({ scans: [scan()] })

    render(<Activity />)

    await waitFor(() => expect(screen.getByText('Recent SecureAI decisions')).toBeInTheDocument())
    expect(screen.getByText('REVIEW')).toBeInTheDocument()
    expect(screen.getByText('MCP config')).toBeInTheDocument()
  })

  it('generates installer and browser pairing links', async () => {
    const key = 'sk_secureai_testkey'
    vi.spyOn(client, 'rotateApiKey').mockResolvedValue({ apiKey: key })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)

    render(<Integrations />)

    fireEvent.click(screen.getByRole('button', { name: /Generate command/ }))
    await waitFor(() => expect(screen.getByText(guardInstallCommand(key))).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Pair browser/ }))
    await waitFor(() => expect(screen.getByText(browserPairingUrl(key))).toBeInTheDocument())
    expect(open).toHaveBeenCalledWith(browserPairingUrl(key), '_blank', 'noopener,noreferrer')
  })

  it('rotates a key from settings', async () => {
    const key = 'sk_secureai_rotated'
    vi.spyOn(client, 'rotateApiKey').mockResolvedValue({ apiKey: key })

    render(<Settings user={USER} auth={authState()} />)

    fireEvent.click(screen.getByRole('button', { name: /Rotate key/ }))

    await waitFor(() => expect(screen.getByText(key)).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /Copy new API key/ })).toBeInTheDocument()
  })
})
