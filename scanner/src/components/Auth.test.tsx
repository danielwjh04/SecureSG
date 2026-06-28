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

/**
 * Fill the credentials form and submit it. `submitLabel` is the submit button's
 * text — "Log in" for the login surface (the default) or "Create account" for
 * the register surface.
 */
function submitCredentials(submitLabel = 'Log in'): void {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password123' } })
  fireEvent.click(screen.getByRole('button', { name: submitLabel }))
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

  it('keeps the sign-in-code wording on a 502 from login (unchanged)', async () => {
    vi.spyOn(client, 'login').mockRejectedValue(new ApiError(502, 'send failed'))
    render(<Auth mode="login" auth={authState()} />)
    submitCredentials()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'We could not send your sign-in code. Please try again.',
    )
  })
})

describe('Auth — register without email verification', () => {
  it('registers and redirects straight to the dashboard when the server returns { user }', async () => {
    const { calls } = stubAssign()
    const refresh = vi.fn().mockResolvedValue(undefined)
    const reg = vi
      .spyOn(client, 'register')
      .mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="register" auth={authState({ refresh })} />)
    submitCredentials('Create account')

    await waitFor(() => expect(reg).toHaveBeenCalled())
    await waitFor(() => expect(refresh).toHaveBeenCalled())
    expect(calls).toContain('#dashboard')
    // No code step appeared.
    expect(screen.queryByText('Verify your email')).not.toBeInTheDocument()
  })

  it('shows an inline error on a 409 (email taken) and stays on the credentials step', async () => {
    vi.spyOn(client, 'register').mockRejectedValue(new ApiError(409, 'taken'))
    render(<Auth mode="register" auth={authState()} />)
    submitCredentials('Create account')

    expect(await screen.findByRole('alert')).toHaveTextContent('That email is already registered.')
    expect(screen.queryByText('Verify your email')).not.toBeInTheDocument()
  })
})

describe('Auth — register with email verification (deferred to login)', () => {
  it('auto-logs-in after register { registered } and shows the signup code step', async () => {
    // New contract: register returns { registered: true } (no session, no code);
    // the component immediately signs in, and that login returns the 2FA
    // challenge that drives the emailed-code step.
    const reg = vi.spyOn(client, 'register').mockResolvedValue({ registered: true })
    const signIn = vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'reg-1',
      email: 'a***@b.com',
    })

    render(<Auth mode="register" auth={authState()} />)
    submitCredentials('Create account')

    // register, then the follow-up login with the same credentials.
    await waitFor(() => expect(reg).toHaveBeenCalled())
    await waitFor(() =>
      expect(signIn).toHaveBeenCalledWith({ email: 'a@b.com', password: 'password123' }),
    )

    // The signup-specific copy, not the login wording.
    expect(await screen.findByText('Verify your email')).toBeInTheDocument()
    expect(
      screen.getByText(/enter it to finish creating your account/i),
    ).toBeInTheDocument()
    expect(screen.getByText('a***@b.com')).toBeInTheDocument()
    expect(screen.getByLabelText('Sign-in code')).toBeInTheDocument()
    // The login heading is NOT shown.
    expect(screen.queryByText('Enter your code')).not.toBeInTheDocument()
  })

  it('goes straight to the dashboard when the follow-up login returns { user }', async () => {
    // register defers, but the follow-up login itself has no 2FA: no code step.
    const { calls } = stubAssign()
    const refresh = vi.fn().mockResolvedValue(undefined)
    vi.spyOn(client, 'register').mockResolvedValue({ registered: true })
    vi.spyOn(client, 'login').mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="register" auth={authState({ refresh })} />)
    submitCredentials('Create account')

    await waitFor(() => expect(refresh).toHaveBeenCalled())
    expect(calls).toContain('#dashboard')
    expect(screen.queryByText('Verify your email')).not.toBeInTheDocument()
  })

  it('verifies the emailed code and redirects to the dashboard on success', async () => {
    const { calls } = stubAssign()
    const refresh = vi.fn().mockResolvedValue(undefined)
    vi.spyOn(client, 'register').mockResolvedValue({ registered: true })
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'reg-1',
      email: 'a***@b.com',
    })
    const verify = vi
      .spyOn(client, 'loginVerify')
      .mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="register" auth={authState({ refresh })} />)
    submitCredentials('Create account')

    const codeInput = await screen.findByLabelText('Sign-in code')
    fireEvent.change(codeInput, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

    await waitFor(() => expect(verify).toHaveBeenCalledWith('reg-1', '123456'))
    await waitFor(() => expect(calls).toContain('#dashboard'))
  })

  it('shows an inline error on a wrong/expired code and stays on the code step', async () => {
    vi.spyOn(client, 'register').mockResolvedValue({ registered: true })
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'reg-1',
      email: 'a***@b.com',
    })
    vi.spyOn(client, 'loginVerify').mockRejectedValue(new ApiError(401, 'invalid'))

    render(<Auth mode="register" auth={authState()} />)
    submitCredentials('Create account')

    const codeInput = await screen.findByLabelText('Sign-in code')
    fireEvent.change(codeInput, { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('That code is invalid or has expired.')
    expect(screen.getByText('Verify your email')).toBeInTheDocument()
  })

  it('resends a fresh code, then verifies with the rotated challenge id', async () => {
    vi.spyOn(client, 'register').mockResolvedValue({ registered: true })
    vi.spyOn(client, 'login').mockResolvedValue({
      twoFactor: true,
      challengeId: 'reg-1',
      email: 'a***@b.com',
    })
    const resend = vi.spyOn(client, 'loginResend').mockResolvedValue({ challengeId: 'reg-2' })
    const verify = vi
      .spyOn(client, 'loginVerify')
      .mockResolvedValue({ user: { email: 'a@b.com', tier: 'free' } })

    render(<Auth mode="register" auth={authState()} />)
    submitCredentials('Create account')

    await screen.findByLabelText('Sign-in code')
    fireEvent.click(screen.getByRole('button', { name: 'Resend code' }))
    await waitFor(() => expect(resend).toHaveBeenCalledWith('reg-1'))

    fireEvent.change(screen.getByLabelText('Sign-in code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    await waitFor(() => expect(verify).toHaveBeenCalledWith('reg-2', '654321'))
  })

  it('shows the verification-code send-failure message when the follow-up login 502s', async () => {
    // register succeeds (deferred), but the follow-up login fails to send the
    // code: the signup-mode 502 message names the verification code.
    vi.spyOn(client, 'register').mockResolvedValue({ registered: true })
    vi.spyOn(client, 'login').mockRejectedValue(new ApiError(502, 'send failed'))

    render(<Auth mode="register" auth={authState()} />)
    submitCredentials('Create account')

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'We could not send your verification code. Please try again.',
    )
    expect(screen.queryByText('Verify your email')).not.toBeInTheDocument()
  })
})
