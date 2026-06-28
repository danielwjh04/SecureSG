/**
 * The protection-stats dashboard. On mount it relies on the app-level auth state
 * (the parent redirects to `#login` on a 401), then loads `GET /api/stats` and
 * renders the account's protection metrics in the shared dark/glass shell:
 * verdict-colored stat cards, a verdict breakdown bar, a 30-day trend chart
 * (recharts, zero-filled client-side), and the API-key card with one-time
 * key reveal on rotation.
 *
 * Every chart is themed dark with the verdict palette (--allow / --review /
 * --block) — no default light recharts theme leaks through.
 */

import { useEffect, useMemo, useState } from 'react'
import { motion } from 'motion/react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  Check,
  Copy,
  Key,
  LogOut,
  RefreshCw,
  ScanLine,
  ShieldAlert,
  ShieldX,
  Sparkles,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { fetchStats, logout, rotateApiKey, startCheckout } from '../api/client'
import { STATS_TREND_DAYS } from '../config'
import { zeroFillDaily } from '../lib/stats'
import type { AccountTier, MeResponse, StatsResponse } from '../api/types'
import type { AuthState } from '../hooks/useAuth'

/** The verdict palette, read once so cards and charts share exact colors. */
const COLOR = {
  allow: '#34d399',
  review: '#fbbf24',
  block: '#f87171',
  axis: 'rgba(255,255,255,0.35)',
  scans: 'rgba(255,255,255,0.7)',
} as const

interface DashboardProps {
  /** The signed-in account; the parent guarantees this is non-null here. */
  user: MeResponse
  auth: AuthState
}

type LoadState =
  | { phase: 'loading' }
  | { phase: 'ready'; stats: StatsResponse }
  | { phase: 'error'; message: string }

export function Dashboard({ user, auth }: DashboardProps) {
  const [load, setLoad] = useState<LoadState>({ phase: 'loading' })

  useEffect(() => {
    let active = true
    fetchStats()
      .then((stats) => {
        if (active) setLoad({ phase: 'ready', stats })
      })
      .catch(() => {
        if (active) {
          setLoad({ phase: 'error', message: 'Could not load your stats.' })
        }
      })
    return () => {
      active = false
    }
  }, [])

  const handleLogout = async (): Promise<void> => {
    try {
      await logout()
    } finally {
      await auth.refresh()
      window.location.assign('#login')
    }
  }

  const handleUpgrade = async (): Promise<void> => {
    try {
      const { url } = await startCheckout()
      window.location.assign(url)
    } catch {
      /* a failed checkout leaves the dashboard intact; the button can be retried */
    }
  }

  return (
    <section className="relative z-10 bg-black flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-8">
        <DashboardHeader
          email={user.email}
          tier={user.tier}
          onLogout={handleLogout}
          onUpgrade={handleUpgrade}
        />

        {load.phase === 'loading' && (
          <p className="text-white/45 font-mono text-sm py-20 text-center">
            Loading your protection stats…
          </p>
        )}
        {load.phase === 'error' && (
          <p className="text-block/90 font-mono text-sm py-20 text-center">
            {load.message}
          </p>
        )}
        {load.phase === 'ready' && <StatsBody stats={load.stats} />}

        <ApiKeyCard apiKeyPrefix={user.apiKeyPrefix} />
      </div>
    </section>
  )
}

interface DashboardHeaderProps {
  email: string
  tier: AccountTier
  onLogout: () => void
  onUpgrade: () => void
}

/** The greeting row: account email, tier badge, upgrade (free only), log out. */
function DashboardHeader({ email, tier, onLogout, onUpgrade }: DashboardHeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4"
    >
      <div className="flex flex-col gap-1.5">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
          Protection dashboard
        </span>
        <h1
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[38px] font-medium tracking-[-0.01em] text-white leading-tight"
        >
          {email}
        </h1>
      </div>
      <div className="flex items-center gap-2.5">
        <TierBadge tier={tier} />
        {tier === 'free' && (
          <button
            type="button"
            onClick={onUpgrade}
            className="inline-flex items-center gap-1.5 rounded-full bg-white px-4 py-2 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Upgrade to Pro
          </button>
        )}
        <button
          type="button"
          onClick={onLogout}
          className="glass-pill inline-flex items-center gap-1.5 px-4 py-2 text-[13px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer"
        >
          <LogOut className="w-3.5 h-3.5" />
          Log out
        </button>
      </div>
    </motion.div>
  )
}

/** The account tier, rendered as a pill tinted by tier. */
function TierBadge({ tier }: { tier: AccountTier }) {
  const tint =
    tier === 'pro'
      ? 'text-allow'
      : tier === 'enterprise'
        ? 'text-white'
        : 'text-white/55'
  return (
    <span className={`glass-pill px-3 py-1.5 text-[11px] font-mono uppercase tracking-[0.14em] ${tint}`}>
      {tier}
    </span>
  )
}

/** One verdict-colored stat tile. */
interface StatTile {
  key: string
  Icon: LucideIcon
  label: string
  value: number
  accent: string
}

function StatsBody({ stats }: { stats: StatsResponse }) {
  const { totals } = stats
  const filled = useMemo(
    () => zeroFillDaily(stats.daily, STATS_TREND_DAYS),
    [stats.daily],
  )
  const hasActivity = totals.scans > 0

  const tiles: StatTile[] = [
    { key: 'scans', Icon: ScanLine, label: 'Scans run', value: totals.scans, accent: 'text-white' },
    { key: 'blocks', Icon: ShieldX, label: 'Threats blocked', value: totals.blocks, accent: 'text-block' },
    { key: 'flagged', Icon: ShieldAlert, label: 'Malicious IOCs caught', value: totals.flagged, accent: 'text-block' },
    { key: 'reviews', Icon: Sparkles, label: 'Reviews flagged', value: totals.reviews, accent: 'text-review' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-6"
    >
      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {tiles.map(({ key, Icon, label, value, accent }) => (
          <div key={key} className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
            <Icon className={`w-5 h-5 ${accent}`} />
            <div
              className={`text-3xl md:text-4xl font-medium tabular-nums ${accent}`}
              style={{ fontFamily: "'Instrument Serif', serif" }}
            >
              {value}
            </div>
            <div className="text-white/70 text-[13px] font-medium leading-snug">{label}</div>
          </div>
        ))}
      </div>

      {!hasActivity ? (
        <EmptyState />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <VerdictBreakdown totals={totals} />
          <TrendChart daily={filled} className="lg:col-span-2" />
        </div>
      )}
    </motion.div>
  )
}

/** The intentional empty state for a brand-new account with no scans yet. */
function EmptyState() {
  return (
    <div className="liquid-glass rounded-2xl p-10 flex flex-col items-center text-center gap-3">
      <ScanLine className="w-7 h-7 text-allow" />
      <h3
        style={{ fontFamily: "'Instrument Serif', serif" }}
        className="text-2xl font-medium text-white"
      >
        No scans yet
      </h3>
      <p className="text-white/55 text-[14px] max-w-md leading-relaxed">
        Run your first scan and your protection stats — threats blocked, IOCs
        caught, and the verdict trend — will appear here.
      </p>
      <a
        href="#"
        className="mt-2 inline-flex items-center gap-2 rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors"
      >
        Run a scan
      </a>
    </div>
  )
}

/** A verdict breakdown bar (Allow / Review / Block) themed with verdict colors. */
function VerdictBreakdown({ totals }: { totals: StatsResponse['totals'] }) {
  const data = [
    { name: 'Allow', value: totals.allows, color: COLOR.allow },
    { name: 'Review', value: totals.reviews, color: COLOR.review },
    { name: 'Block', value: totals.blocks, color: COLOR.block },
  ]
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Verdict breakdown
      </h3>
      <div className="h-[180px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: COLOR.axis, fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={56}
            />
            <Tooltip
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: '#fff' }}
            />
            <Bar dataKey="value" radius={[0, 6, 6, 0]} barSize={22}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/** A 30-day area chart of daily scans vs blocks, themed dark. */
function TrendChart({
  daily,
  className,
}: {
  daily: StatsResponse['daily']
  className?: string
}) {
  // Show a short day label (MM-DD) so the axis stays legible across 30 points.
  const data = daily.map((row) => ({ ...row, label: row.day.slice(5) }))
  return (
    <div className={`liquid-glass rounded-2xl p-5 flex flex-col gap-4 ${className ?? ''}`}>
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Last {daily.length} days · scans vs blocks
      </h3>
      <div className="h-[180px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="scansFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.scans} stopOpacity={0.3} />
                <stop offset="100%" stopColor={COLOR.scans} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blocksFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.block} stopOpacity={0.4} />
                <stop offset="100%" stopColor={COLOR.block} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="label"
              tick={{ fill: COLOR.axis, fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              minTickGap={24}
            />
            <YAxis
              tick={{ fill: COLOR.axis, fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
              width={28}
            />
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#fff' }} />
            <Area
              type="monotone"
              dataKey="scans"
              stroke={COLOR.scans}
              strokeWidth={1.5}
              fill="url(#scansFill)"
            />
            <Area
              type="monotone"
              dataKey="blocks"
              stroke={COLOR.block}
              strokeWidth={1.5}
              fill="url(#blocksFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/** Shared dark tooltip styling so recharts never paints its light default. */
const TOOLTIP_STYLE = {
  background: 'rgba(10,12,16,0.92)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 12,
  fontSize: 12,
  color: '#fff',
} as const

/** The API-key card: shows the prefix and reveals a rotated key once. */
function ApiKeyCard({ apiKeyPrefix }: { apiKeyPrefix: string }) {
  const [revealed, setRevealed] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleRotate = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    setCopied(false)
    try {
      const { apiKey } = await rotateApiKey()
      setRevealed(apiKey)
    } catch {
      setError('Could not regenerate the key. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  const handleCopy = async (): Promise<void> => {
    if (revealed === null) return
    try {
      await navigator.clipboard.writeText(revealed)
      setCopied(true)
    } catch {
      /* clipboard denied: the key is still visible to copy by hand */
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.05, ease: [0.16, 1, 0.3, 1] }}
      className="liquid-glass rounded-2xl p-5 flex flex-col gap-4"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Key className="w-4 h-4 text-white/70" />
          <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
            API key
          </h3>
        </div>
        <button
          type="button"
          onClick={handleRotate}
          disabled={busy}
          className="glass-pill inline-flex items-center gap-1.5 px-3.5 py-1.5 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${busy ? 'animate-spin' : ''}`} />
          Regenerate key
        </button>
      </div>

      {revealed === null ? (
        <div className="font-mono text-[13px] text-white/70">
          {apiKeyPrefix}
          <span className="text-white/30">··········</span>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded-lg bg-white/[0.04] border border-white/10 px-3 py-2 font-mono text-[13px] text-allow">
              {revealed}
            </code>
            <button
              type="button"
              onClick={handleCopy}
              className="glass-pill inline-flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer shrink-0"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-allow" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="text-review/90 font-mono text-[11px] leading-snug">
            Copy this now — it will not be shown again.
          </p>
        </div>
      )}

      {error && <p className="text-block/90 font-mono text-[12px]">{error}</p>}
    </motion.div>
  )
}
