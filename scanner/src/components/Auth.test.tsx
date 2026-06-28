import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Auth } from './Auth'
import type { AuthState } from '../hooks/useAuth'
import { ApiError } from '../api/client'
import * as client from '../api/client'

function authState(overrides: Partial<AuthState> = {}): AuthState {
  return {
    status: 'anonymous',
    user: null,
    isAdmin: false,
    isOwner: false,
    refresh: vi.fn(),
    ...overrides,
  }
}

/**
 * Capture `window.location.assign` calls. jsdom's `location.assign` is not
 * spyable, so swap in a minimal location stub whose `assign` records the target.
 * Restored in `afterEach`.
 */
function stubAssign(): { calls: string[] } {
  const calls: string[] = []
  const original = window.location
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...original, assign: (url: string | URL) => calls.push(String(url)) },
  })
  restoreLocation = () =>
    Object.defineProperty(window, 'location', { configurable: true, value: original })
  return { calls }
}

let restoreLocation: (() => void) | null = null

afterEach(() => {
  restoreLocation?.()
  restoreLocation = null
  vi.restoreAllMocks()
})

/** Fill the credentials form and submit it. */
function submitCredentials(): void {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password123' } })
  fireEvent.click(screen.getByRole('button', { name: 'Log in' }))
}

describe('Auth — login without 2FA', () => {
  it('logs straight in and redirects to the dashboard when the server returns { user }', async () => {
    const { calls } = stubAssign()
    const refresh = vi.fn().mockResolvedValue(undefined)
    vi.spyOn(client, 'login').mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="login" auth={authState({ refresh })} />)
    submitCredentials()

    await waitFor(() => expect(refresh).toHaveBeenCalled())
    expect(calls).toContain('#dashboard')
    // The 2FA step never rendered.
    expect(screen.queryByText('Enter your code')).not.toBeInTheDocument()
  })

  it('shows an inline error on a 401 and stays on the credentials step', async () => {
    vi.spyOn(client, 'login').mockRejectedValue(new ApiError(401, 'invalid'))
    render(<Auth mode="login" auth={authState()} />)
    submitCredentials()

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password.')
  })
})

describe('Auth — login with 2FA', () => {
  it('renders the code-entry step (with masked email) on a twoFactor response', async () => {
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'chal-1',
      email: 'a***@b.com',
    })
    render(<Auth mode="login" auth={authState()} />)
    submitCredentials()

    expect(await screen.findByText('Enter your code')).toBeInTheDocument()
    expect(screen.getByText('a***@b.com')).toBeInTheDocument()
    expect(screen.getByLabelText('Sign-in code')).toBeInTheDocument()
  })

  it('verifies the code and redirects to the dashboard on success', async () => {
    const { calls } = stubAssign()
    const refresh = vi.fn().mockResolvedValue(undefined)
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'chal-1',
      email: 'a***@b.com',
    })
    const verify = vi
      .spyOn(client, 'loginVerify')
      .mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="login" auth={authState({ refresh })} />)
    submitCredentials()

    const codeInput = await screen.findByLabelText('Sign-in code')
    fireEvent.change(codeInput, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

    await waitFor(() => expect(verify).toHaveBeenCalledWith('chal-1', '123456'))
    await waitFor(() => expect(calls).toContain('#dashboard'))
  })

  it('shows an inline error on a wrong/expired code and stays on the code step', async () => {
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'chal-1',
      email: 'a***@b.com',
    })
    vi.spyOn(client, 'loginVerify').mockRejectedValue(new ApiError(401, 'invalid'))

    render(<Auth mode="login" auth={authState()} />)
    submitCredentials()

    const codeInput = await screen.findByLabelText('Sign-in code')
    fireEvent.change(codeInput, { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('That code is invalid or has expired.')
    expect(screen.getByText('Enter your code')).toBeInTheDocument()
  })

  it('resends a fresh code when "Resend code" is clicked', async () => {
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'chal-1',
      email: 'a***@b.com',
    })
    const resend = vi.spyOn(client, 'loginResend').mockResolvedValue({ challengeId: 'chal-2' })
    const verify = vi
      .spyOn(client, 'loginVerify')
      .mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="login" auth={authState()} />)
    submitCredentials()

    await screen.findByLabelText('Sign-in code')
    fireEvent.click(screen.getByRole('button', { name: 'Resend code' }))
    await waitFor(() => expect(resend).toHaveBeenCalledWith('chal-1'))

    // The new challenge id is used for the next verify.
    fireEvent.change(screen.getByLabelText('Sign-in code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() => expect(verify).toHaveBeenCalledWith('chal-2', '654321'))
  })
})

describe('Auth — register (never 2FA)', () => {
  it('registers and redirects without a code step', async () => {
    const { calls } = stubAssign()
    const refresh = vi.fn().mockResolvedValue(undefined)
    const reg = vi
      .spyOn(client, 'register')
      .mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="register" auth={authState({ refresh })} />)
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }))

    await waitFor(() => expect(reg).toHaveBeenCalled())
    expect(calls).toContain('#dashboard')
  })
})
