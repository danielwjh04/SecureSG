/**
 * The login / register surface: one centered glass card that switches between
 * the two modes by route (`#login` vs `#register`). On success it refreshes the
 * app-level auth state and redirects to `#dashboard`. Errors from the API are
 * mapped to inline, human messages keyed off the {@link ApiError} status.
 */

import { useState, type FormEvent } from 'react'
import { motion } from 'motion/react'
import { ShieldCheck } from 'lucide-react'
import { ApiError, login, register } from '../api/client'
import type { AuthState } from '../hooks/useAuth'

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

export function Auth({ mode, auth }: AuthProps) {
  const copy = COPY[mode]
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const handleSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const credentials = { email, password }
      if (mode === 'login') {
        await login(credentials)
      } else {
        await register(credentials)
      }
      await auth.refresh()
      window.location.assign('#dashboard')
    } catch (caught) {
      setError(errorMessage(caught, mode))
      setBusy(false)
    }
  }

  return (
    <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-16">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="liquid-glass rounded-3xl w-full max-w-md p-8 flex flex-col gap-6"
      >
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
              className="rounded-xl bg-white/[0.04] border border-white/10 px-4 py-2.5 text-[14px] text-white placeholder:text-white/30 outline-none focus:border-white/30 transition-colors"
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
              className="rounded-xl bg-white/[0.04] border border-white/10 px-4 py-2.5 text-[14px] text-white placeholder:text-white/30 outline-none focus:border-white/30 transition-colors"
            />
          </label>

          {error && (
            <p role="alert" className="text-block/90 font-mono text-[12px] leading-snug">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="rounded-full bg-white text-black px-6 py-2.5 text-[14px] font-semibold hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
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
