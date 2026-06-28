/**
 * The login / register surface: one centered glass card that switches between
 * the two modes by route (`#login` vs `#register`). On success it refreshes the
 * app-level auth state and redirects to `#dashboard`. Errors from the API are
 * mapped to inline, human messages keyed off the {@link ApiError} status.
 *
 * Verification lives entirely at login. When the server has email verification
 * configured, `POST /api/login` returns `{ twoFactor, challengeId, email }`
 * instead of a session and the card flips to a 6-digit code-entry step; the code
 * is verified via `POST /api/login/verify`, with a "Resend code" link rotating a
 * fresh code via `POST /api/login/resend`. Signup reaches that same step without
 * its own code: `POST /api/register` returns `{ registered: true }` (no session,
 * no code), so the submit handler immediately signs in with the same credentials
 * and follows the login path — one form submission, one emailed code from login.
 * When no email provider is configured both register and login return `{ user }`
 * and go straight to the dashboard. The code step's copy is keyed off the mode so
 * signup reads as "finish creating your account" while login reads as "sign in".
 */

import { useState, type FormEvent } from 'react'
import { motion } from 'motion/react'
import { ShieldCheck, MailCheck } from 'lucide-react'
import { ApiError, login, loginResend, loginVerify, register } from '../api/client'
import type { AuthState } from '../hooks/useAuth'
import type { LoginResponse } from '../api/types'

export type AuthMode = 'login' | 'register'

interface AuthProps {
  mode: AuthMode
  auth: AuthState
}

/**
 * Translate an API failure into the inline message for the current mode. The
 * contract pins specific statuses: 401 (bad creds, login), 409 (email taken,
 * register), 422 (invalid field). Anything else is a generic, honest fallback.
 */
function errorMessage(error: unknown, mode: AuthMode): string {
  if (error instanceof ApiError) {
    if (mode === 'login' && error.status === 401) {
      return 'Invalid email or password.'
    }
    if (mode === 'register' && error.status === 409) {
      return 'That email is already registered.'
    }
    if (error.status === 422) {
      return 'Enter a valid email and a password of at least 8 characters.'
    }
    if (error.status === 502) {
      return EMAIL_SEND_FAILED[mode]
    }
    if (error.status === 0) {
      return 'Scanner backend unreachable. Please try again.'
    }
  }
  return 'Something went wrong. Please try again.'
}

/**
 * The inline message when the email provider failed to send the code (502),
 * keyed by mode so signup and login each describe the right code.
 */
const EMAIL_SEND_FAILED: Record<AuthMode, string> = {
  login: 'We could not send your sign-in code. Please try again.',
  register: 'We could not send your verification code. Please try again.',
}

/** Translate a verify/resend failure into the inline code-step message. */
function codeErrorMessage(error: unknown, mode: AuthMode): string {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return 'That code is invalid or has expired.'
    }
    if (error.status === 422) {
      return 'Enter the 6-digit code from your email.'
    }
    if (error.status === 502) {
      return EMAIL_SEND_FAILED[mode]
    }
    if (error.status === 0) {
      return 'Scanner backend unreachable. Please try again.'
    }
  }
  return 'Something went wrong. Please try again.'
}

const COPY: Record<AuthMode, {
  eyebrow: string
  title: string
  submit: string
  busy: string
  toggleText: string
  toggleCta: string
  toggleHref: string
}> = {
  login: {
    eyebrow: 'Welcome back',
    title: 'Log in',
    submit: 'Log in',
    busy: 'Logging in…',
    toggleText: 'New to SecureAI?',
    toggleCta: 'Create an account',
    toggleHref: '#register',
  },
  register: {
    eyebrow: 'Get started',
    title: 'Create your account',
    submit: 'Create account',
    busy: 'Creating account…',
    toggleText: 'Already have an account?',
    toggleCta: 'Log in',
    toggleHref: '#login',
  },
}

/**
 * Copy for the 6-digit code-entry step, keyed by the mode that reached it.
 * Login frames it as a sign-in code; register frames it as finishing signup.
 * The sentence is split around the masked email so the email always renders as
 * its own highlighted node, with mode-specific text before and after it.
 */
const CODE_COPY: Record<AuthMode, {
  eyebrow: string
  title: string
  bodyBefore: string
  bodyAfter: string
}> = {
  login: {
    eyebrow: 'Check your email',
    title: 'Enter your code',
    bodyBefore: 'We sent a 6-digit code to ',
    bodyAfter: '.',
  },
  register: {
    eyebrow: 'Finish signup',
    title: 'Verify your email',
    bodyBefore: 'We emailed a 6-digit code to ',
    bodyAfter: ' — enter it to finish creating your account.',
  },
}

/** The number of digits in a one-time 2FA code (mirrors the server contract). */
const CODE_LENGTH = 6

/** A pending 2FA challenge: its id and the masked email the code went to. */
interface Challenge {
  challengeId: string
  email: string
}

const cardMotion = {
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] as const },
}

const inputClass =
  'rounded-xl bg-white/[0.04] border border-white/10 px-4 py-2.5 text-[14px] text-white placeholder:text-white/30 outline-none focus:border-white/30 transition-colors'

const submitClass =
  'rounded-full bg-white text-black px-6 py-2.5 text-[14px] font-semibold hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'

export function Auth({ mode, auth }: AuthProps) {
  const copy = COPY[mode]
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // When set, login (2FA) or register (email verification) moved to the code step.
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const [code, setCode] = useState('')

  const finishLogin = async (): Promise<void> => {
    await auth.refresh()
    window.location.assign('#dashboard')
  }

  // Apply a login response (from the login path, or the register follow-up
  // login): a 2FA challenge flips to the emailed-code step with no session yet;
  // a completed `{ user }` finishes the login. Verification now lives entirely at
  // login, so signup reaches the code step by signing in right after registering.
  const applyLoginResult = async (result: LoginResponse): Promise<void> => {
    if ('twoFactor' in result) {
      setChallenge({ challengeId: result.challengeId, email: result.email })
      setCode('')
      setBusy(false)
      return
    }
    await finishLogin()
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    const credentials = { email, password }
    try {
      if (mode === 'register') {
        // Register no longer returns a session-less challenge or a code. It
        // returns either a completed session (`{ user }`, no verification) or
        // `{ registered: true }` (verification deferred to login). On the latter,
        // sign in immediately with the same credentials and handle that login's
        // result — including its 2FA challenge — exactly like the login path, so
        // the user submits the signup form once and flows straight into the one
        // emailed code that login issues.
        const registered = await register(credentials)
        if ('registered' in registered) {
          await applyLoginResult(await login(credentials))
          return
        }
        await finishLogin()
        return
      }
      await applyLoginResult(await login(credentials))
    } catch (caught) {
      setError(errorMessage(caught, mode))
      setBusy(false)
    }
  }

  const handleVerify = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    if (challenge === null) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      await loginVerify(challenge.challengeId, code)
      await finishLogin()
    } catch (caught) {
      setError(codeErrorMessage(caught, mode))
      setBusy(false)
    }
  }

  const handleResend = async (): Promise<void> => {
    if (challenge === null || busy) {
      return
    }
    setBusy(true)
    setError(null)
    try {
      const { challengeId } = await loginResend(challenge.challengeId)
      setChallenge({ challengeId, email: challenge.email })
      setCode('')
    } catch (caught) {
      setError(codeErrorMessage(caught, mode))
    } finally {
      setBusy(false)
    }
  }

  // ----------------------------------------------- email code-entry step ---
  // Reached by login (2FA) directly, and by register via its follow-up login;
  // the copy is keyed off the mode so signup reads as finishing the account.
  if (challenge !== null) {
    const codeCopy = CODE_COPY[mode]
    return (
      <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-16">
        <motion.div {...cardMotion} className="liquid-glass rounded-3xl w-full max-w-md p-8 flex flex-col gap-6">
          <div className="flex flex-col items-center text-center gap-3">
            <MailCheck className="w-7 h-7 text-allow" />
            <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
              {codeCopy.eyebrow}
            </span>
            <h1
              style={{ fontFamily: "'Instrument Serif', serif" }}
              className="text-3xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
            >
              {codeCopy.title}
            </h1>
            <p className="text-[13px] text-white/50">
              {codeCopy.bodyBefore}
              <span className="text-white/80">{challenge.email}</span>
              {codeCopy.bodyAfter}
            </p>
          </div>

          <form onSubmit={handleVerify} className="flex flex-col gap-4" noValidate>
            <label className="flex flex-col gap-1.5">
              <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
                Sign-in code
              </span>
              <input
                type="text"
                name="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                aria-label="Sign-in code"
                maxLength={CODE_LENGTH}
                required
                value={code}
                onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className={`${inputClass} text-center tracking-[0.5em] font-mono text-lg`}
              />
            </label>

            {error && (
              <p role="alert" className="text-block/90 font-mono text-[12px] leading-snug">
                {error}
              </p>
            )}

            <button type="submit" disabled={busy || code.length !== CODE_LENGTH} className={submitClass}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
          </form>

          <p className="text-center text-[13px] text-white/50">
            Did not get it?{' '}
            <button
              type="button"
              onClick={handleResend}
              disabled={busy}
              className="text-white hover:text-allow transition-colors disabled:opacity-50 cursor-pointer"
            >
              Resend code
            </button>
          </p>
        </motion.div>
      </section>
    )
  }

  // ----------------------------------------------------- credentials step ---
  return (
    <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-16">
      <motion.div {...cardMotion} className="liquid-glass rounded-3xl w-full max-w-md p-8 flex flex-col gap-6">
        <div className="flex flex-col items-center text-center gap-3">
          <ShieldCheck className="w-7 h-7 text-allow" />
          <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
            {copy.eyebrow}
          </span>
          <h1
            style={{ fontFamily: "'Instrument Serif', serif" }}
            className="text-3xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
          >
            {copy.title}
          </h1>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4" noValidate>
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
              Email
            </span>
            <input
              type="email"
              name="email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@company.com"
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
              Password
            </span>
            <input
              type="password"
              name="password"
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              className={inputClass}
            />
          </label>

          {error && (
            <p role="alert" className="text-block/90 font-mono text-[12px] leading-snug">
              {error}
            </p>
          )}

          <button type="submit" disabled={busy} className={submitClass}>
            {busy ? copy.busy : copy.submit}
          </button>
        </form>

        <p className="text-center text-[13px] text-white/50">
          {copy.toggleText}{' '}
          <a href={copy.toggleHref} className="text-white hover:text-allow transition-colors">
            {copy.toggleCta}
          </a>
        </p>
      </motion.div>
    </section>
  )
}
