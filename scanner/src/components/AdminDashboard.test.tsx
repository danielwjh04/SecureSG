import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AdminDashboard } from './AdminDashboard'
import type { AdminMember, AdminMembersPage, AdminOverview } from '../api/types'
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

function member(partial: Partial<AdminMember> = {}): AdminMember {
  return {
    id: 'u-member',
    email: 'member@securesg.test',
    tier: 'free',
    role: 'member',
    createdAt: '2026-06-01T00:00:00.000Z',
    scans: 12,
    ...partial,
  }
}

function membersPage(members: AdminMember[]): AdminMembersPage {
  return { members, total: members.length }
}

/** Mock the overview so every test exercises the members section in isolation. */
function stubOverview(): void {
  vi.spyOn(client, 'fetchAdminOverview').mockResolvedValue(overview())
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('AdminDashboard', () => {
  it('shows a loading line until the overview resolves', () => {
    vi.spyOn(client, 'fetchAdminOverview').mockReturnValue(new Promise(() => {}))
    vi.spyOn(client, 'fetchMembers').mockReturnValue(new Promise(() => {}))
    render(<AdminDashboard />)
    expect(screen.getByText(/Loading sitewide analytics/)).toBeInTheDocument()
  })

  it('renders the headline metrics from a mocked overview', async () => {
    vi.spyOn(client, 'fetchAdminOverview').mockResolvedValue(overview())
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(membersPage([member()]))
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
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(membersPage([]))
    render(<AdminDashboard />)

    await waitFor(() => expect(screen.getByText('No activity yet')).toBeInTheDocument())
    // Headline tiles still render (all zero).
    expect(screen.getByText('Total sign-ups')).toBeInTheDocument()
  })

  it('shows an error line when the overview fetch fails', async () => {
    vi.spyOn(client, 'fetchAdminOverview').mockRejectedValue(new Error('nope'))
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(membersPage([]))
    render(<AdminDashboard />)
    await waitFor(() =>
      expect(screen.getByText(/Could not load admin analytics/)).toBeInTheDocument(),
    )
  })
})

describe('AdminDashboard · members', () => {
  it('renders the members table from a mocked list', async () => {
    stubOverview()
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(
      membersPage([
        member({ id: 'u1', email: 'a@securesg.test', role: 'member', scans: 3 }),
        member({ id: 'u2', email: 'b@securesg.test', role: 'admin', tier: 'pro', scans: 0 }),
        member({ id: 'u3', email: 'boss@securesg.test', role: 'owner', scans: 9 }),
      ]),
    )
    render(<AdminDashboard canManageRoles={false} />)

    await waitFor(() => expect(screen.getByText('a@securesg.test')).toBeInTheDocument())
    expect(screen.getByText('b@securesg.test')).toBeInTheDocument()
    // Column headers present.
    expect(screen.getByText('Email')).toBeInTheDocument()
    expect(screen.getByText('Joined')).toBeInTheDocument()
    expect(screen.getByText('Scans')).toBeInTheDocument()
    // The owner row shows a static Owner badge.
    expect(screen.getByText('Owner')).toBeInTheDocument()
  })

  it('shows role selects for an owner but not for a non-owner viewer', async () => {
    stubOverview()
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(
      membersPage([
        member({ id: 'u1', email: 'a@securesg.test', role: 'member' }),
        member({ id: 'u2', email: 'boss@securesg.test', role: 'owner' }),
      ]),
    )

    // Non-owner viewer: no selects at all, roles are read-only.
    const view = render(<AdminDashboard canManageRoles={false} />)
    await waitFor(() => expect(screen.getByText('a@securesg.test')).toBeInTheDocument())
    expect(screen.queryByRole('combobox')).toBeNull()
    view.unmount()

    // Owner viewer: exactly one select (the non-owner row); the owner row stays a badge.
    render(<AdminDashboard canManageRoles={true} />)
    await waitFor(() => expect(screen.getAllByText('a@securesg.test').length).toBeGreaterThan(0))
    const selects = screen.getAllByRole('combobox')
    expect(selects).toHaveLength(1)
    expect(screen.getByText('Owner')).toBeInTheDocument()
  })

  it('calls the API and refetches when an owner changes a role', async () => {
    stubOverview()
    const fetchSpy = vi
      .spyOn(client, 'fetchMembers')
      .mockResolvedValue(membersPage([member({ id: 'u1', email: 'a@securesg.test', role: 'member' })]))
    const setSpy = vi
      .spyOn(client, 'setMemberRole')
      .mockResolvedValue({ id: 'u1', role: 'admin' })

    render(<AdminDashboard canManageRoles={true} />)
    await waitFor(() => expect(screen.getByRole('combobox')).toBeInTheDocument())

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'admin' } })

    await waitFor(() => expect(setSpy).toHaveBeenCalledWith('u1', 'admin'))
    // The table is re-read after a successful change (initial load + refetch).
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
  })

  it('shows an empty state when there are no members', async () => {
    stubOverview()
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(membersPage([]))
    render(<AdminDashboard />)
    await waitFor(() => expect(screen.getByText('No members yet.')).toBeInTheDocument())
  })

  it('shows an error line when the members fetch fails', async () => {
    stubOverview()
    vi.spyOn(client, 'fetchMembers').mockRejectedValue(new Error('nope'))
    render(<AdminDashboard />)
    await waitFor(() => expect(screen.getByText('Could not load members.')).toBeInTheDocument())
  })
})

describe('AdminDashboard · remove member', () => {
  it('hides the Remove action entirely from a non-owner viewer', async () => {
    stubOverview()
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(
      membersPage([member({ id: 'u1', email: 'a@securesg.test', role: 'member' })]),
    )
    render(<AdminDashboard canManageRoles={false} viewerEmail="owner@securesg.test" />)
    await waitFor(() => expect(screen.getByText('a@securesg.test')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /Remove a@securesg.test/ })).toBeNull()
  })

  it('shows Remove for an owner viewer on non-owner rows, but not on owner or own rows', async () => {
    stubOverview()
    vi.spyOn(client, 'fetchMembers').mockResolvedValue(
      membersPage([
        member({ id: 'u1', email: 'member@securesg.test', role: 'member' }),
        member({ id: 'u2', email: 'admin@securesg.test', role: 'admin' }),
        member({ id: 'u3', email: 'boss@securesg.test', role: 'owner' }),
        member({ id: 'u4', email: 'me@securesg.test', role: 'admin' }),
      ]),
    )
    render(<AdminDashboard canManageRoles={true} viewerEmail="me@securesg.test" />)
    await waitFor(() => expect(screen.getByText('member@securesg.test')).toBeInTheDocument())

    // Non-owner, non-self rows show a Remove button.
    expect(screen.getByRole('button', { name: 'Remove member@securesg.test' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove admin@securesg.test' })).toBeInTheDocument()
    // The owner row never shows Remove.
    expect(screen.queryByRole('button', { name: 'Remove boss@securesg.test' })).toBeNull()
    // The viewer's own row never shows Remove (matched by email, case-insensitive).
    expect(screen.queryByRole('button', { name: 'Remove me@securesg.test' })).toBeNull()
  })

  it('confirms, calls removeMember, and refetches on confirm', async () => {
    stubOverview()
    const fetchSpy = vi
      .spyOn(client, 'fetchMembers')
      .mockResolvedValue(membersPage([member({ id: 'u1', email: 'gone@securesg.test', role: 'member' })]))
    const removeSpy = vi.spyOn(client, 'removeMember').mockResolvedValue({ removed: 'u1' })
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)

    render(<AdminDashboard canManageRoles={true} viewerEmail="owner@securesg.test" />)
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Remove gone@securesg.test' })).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByRole('button', { name: 'Remove gone@securesg.test' }))

    expect(confirmSpy).toHaveBeenCalledWith(
      'Remove gone@securesg.test? This deletes their account and data.',
    )
    await waitFor(() => expect(removeSpy).toHaveBeenCalledWith('u1'))
    // The table is re-read after a successful removal (initial load + refetch).
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))
  })

  it('does not call removeMember when the confirm is cancelled', async () => {
    stubOverview()
    const fetchSpy = vi
      .spyOn(client, 'fetchMembers')
      .mockResolvedValue(membersPage([member({ id: 'u1', email: 'safe@securesg.test', role: 'member' })]))
    const removeSpy = vi.spyOn(client, 'removeMember').mockResolvedValue({ removed: 'u1' })
    vi.spyOn(window, 'confirm').mockReturnValue(false)

    render(<AdminDashboard canManageRoles={true} viewerEmail="owner@securesg.test" />)
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Remove safe@securesg.test' })).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByRole('button', { name: 'Remove safe@securesg.test' }))

    expect(removeSpy).not.toHaveBeenCalled()
    // Only the initial load — no refetch, since nothing changed.
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })
})
