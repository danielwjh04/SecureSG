import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Navbar } from './Navbar'
import type { AuthState } from '../hooks/useAuth'
import type { MeResponse } from '../api/types'

function user(isAdmin: boolean): MeResponse {
  return {
    email: 'a@b.com',
    tier: 'free',
    createdAt: '2026-06-01T00:00:00.000Z',
    apiKeyPrefix: 'sk_live_ab',
    isAdmin,
  }
}

function authState(overrides: Partial<AuthState> = {}): AuthState {
  return { status: 'anonymous', user: null, isAdmin: false, refresh: vi.fn(), ...overrides }
}

describe('Navbar admin link', () => {
  it('shows the Admin link for an authenticated admin', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(true), isAdmin: true })}
      />,
    )
    const admin = screen.getByRole('link', { name: /Admin/ })
    expect(admin).toBeInTheDocument()
    expect(admin).toHaveAttribute('href', '#admin')
    // Dashboard still renders alongside it.
    expect(screen.getByRole('link', { name: /Dashboard/ })).toBeInTheDocument()
  })

  it('hides the Admin link for an authenticated non-admin', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(false), isAdmin: false })}
      />,
    )
    expect(screen.queryByRole('link', { name: /Admin/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Dashboard/ })).toBeInTheDocument()
  })

  it('hides the Admin link for an anonymous visitor', () => {
    render(<Navbar auth={authState()} />)
    expect(screen.queryByRole('link', { name: /Admin/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Log in/ })).toBeInTheDocument()
  })
})
