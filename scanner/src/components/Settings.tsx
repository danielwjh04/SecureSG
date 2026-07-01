import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { motion } from 'motion/react'
import {
  Check,
  Copy,
  CreditCard,
  Key,
  LogOut,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { logout, rotateApiKey } from '../api/client'
import type { AuthState } from '../hooks/useAuth'
import type { MeResponse } from '../api/types'

const COPY_FEEDBACK_MS = 1500

/** Authenticated account settings page. */
export function Settings({ user, auth }: { user: MeResponse; auth: AuthState }) {
  const [apiKey, setApiKey] = useState<string | null>(null)
  const [busy, setBusy] = useState<'key' | 'logout' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const rotate = async (): Promise<void> => {
    setBusy('key')
    setError(null)
    try {
      const res = await rotateApiKey()
      setApiKey(res.apiKey)
    } catch {
      setError('Could not rotate the API key.')
    } finally {
      setBusy(null)
    }
  }

  // Manage plan routes to the pricing page, which adapts to the current tier
  // (upgrade / downgrade / cancel in place) rather than a single static page.
  const manageBilling = (): void => {
    window.location.assign('#pricing')
  }

  const signOut = async (): Promise<void> => {
    setBusy('logout')
    try {
      await logout()
    } finally {
      await auth.refresh()
      window.location.assign('#login')
    }
  }

  return (
    <section className="relative z-10 flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-6">
        <Header onLogout={signOut} disabled={busy !== null} />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Panel Icon={ShieldCheck} title="Account">
            <dl className="flex flex-col gap-3 text-[13px]">
              <Row label="Email" value={user.email} />
              <Row label="Tier" value={user.tier} />
              <Row label="Role" value={user.role} />
            </dl>
          </Panel>

          <Panel Icon={CreditCard} title="Billing">
            <p className="text-white/55 text-[13px] leading-relaxed">
              Manage the paid plan attached to this account.
            </p>
            <button
              type="button"
              onClick={manageBilling}
              className="mt-3 inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer"
            >
              <CreditCard className="w-4 h-4" />
              Manage plan
            </button>
          </Panel>
        </div>

        <Panel Icon={Key} title="API key">
          <div className="flex flex-col gap-3">
            <code className="rounded-xl bg-white/[0.04] border border-white/10 px-3 py-2 font-mono text-[13px] text-white/70 break-all">
              {apiKey ?? `${user.apiKeyPrefix}..........`}
            </code>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={rotate}
                disabled={busy !== null}
                className="glass-pill inline-flex items-center gap-2 px-4 py-2 text-[13px] font-medium text-white/80 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${busy === 'key' ? 'animate-spin' : ''}`} />
                Rotate key
              </button>
              {apiKey !== null && <CopyButton value={apiKey} label="Copy new API key" />}
            </div>
            {apiKey !== null && (
              <p className="text-review/90 font-mono text-[11px]">
                Copy this now. It will not be shown again.
              </p>
            )}
          </div>
        </Panel>

        {error !== null && <p className="text-block/90 font-mono text-sm">{error}</p>}
      </div>
    </section>
  )
}

function Header({ onLogout, disabled }: { onLogout: () => void; disabled: boolean }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex items-start justify-between gap-4"
    >
      <div className="flex flex-col gap-1.5">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
          Settings
        </span>
        <h1
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[38px] font-medium text-white leading-tight"
        >
          Account settings
        </h1>
      </div>
      <button
        type="button"
        onClick={onLogout}
        disabled={disabled}
        aria-label="Log out"
        title="Log out"
        className="glass-pill inline-flex items-center justify-center w-10 h-10 shrink-0 text-white/70 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <LogOut className="w-4 h-4" />
      </button>
    </motion.div>
  )
}

function Panel({
  Icon,
  title,
  children,
}: {
  Icon: LucideIcon
  title: string
  children: ReactNode
}) {
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Icon className="w-4 h-4 text-white/70" />
        <h2 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
          {title}
        </h2>
      </div>
      {children}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="text-white/45">{label}</dt>
      <dd className="text-white/85 font-mono text-[12px] text-right break-all">{value}</dd>
    </div>
  )
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current)
    }
  }, [])

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      if (timerRef.current !== null) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setCopied(false), COPY_FEEDBACK_MS)
    } catch {
      /* clipboard denied: the value stays visible */
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      className="glass-pill inline-flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-allow" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}
