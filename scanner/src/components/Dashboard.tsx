/**
 * The protection-stats dashboard. On mount it relies on the app-level auth state
 * (the parent redirects to `#login` on a 401), then loads `GET /api/stats` and
 * renders the account's protection metrics in the shared dark/glass shell:
 * verdict-colored stat cards, a verdict breakdown bar, a 30-day trend chart
 * (recharts, zero-filled client-side), and the API-key card with one-time
 * key reveal on rotation.
 *
 * Every chart is themed dark with the verdict palette (--allow / --review /
 * --block), no default light recharts theme leaks through.
 */

import { useEffect, useMemo, useRef, useState } from 'react'
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
  Download,
  FileText,
  Globe2,
  Key,
  Link2,
  RefreshCw,
  ScanLine,
  Settings,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Terminal,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  fetchRecentScans,
  fetchStats,
  rotateApiKey,
  startCheckout,
} from '../api/client'
import {
  GUARD_DOWNLOAD_PATH,
  guardInstallCommand,
  RECENT_SCANS_LIMIT,
  STATS_TREND_DAYS,
} from '../config'
import { zeroFillDaily } from '../lib/stats'
import { hostname, relativeTime } from '../lib/format'
import type { Verdict } from '../api/types'
import type {
  AccountTier,
  MeResponse,
  RecentScan,
  StatsResponse,
} from '../api/types'

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
}

type LoadState =
  | { phase: 'loading' }
  | { phase: 'ready'; stats: StatsResponse }
  | { phase: 'error'; message: string }

export function Dashboard({ user }: DashboardProps) {
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

  const handleUpgrade = async (): Promise<void> => {
    try {
      const { url } = await startCheckout()
      window.location.assign(url)
    } catch {
      /* a failed checkout leaves the dashboard intact; the button can be retried */
    }
  }

  return (
    <section className="relative z-10 flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-8">
        <DashboardHeader
          email={user.email}
          firstName={user.firstName}
          tier={user.tier}
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

        <RecentScans />

        <ApiKeyCard apiKeyPrefix={user.apiKeyPrefix} />

        <GuardSetupCard />

        <Coverage />
      </div>
    </section>
  )
}

/**
 * What SecureAI can observe, moved here from the former standalone Protection
 * page: three coverage cards and the browser-boundary note. Static copy (no data
 * fetch), so it renders immediately alongside the stats.
 */
function Coverage() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.09, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-4"
    >
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-4 h-4 text-white/70" />
        <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
          Your SecureAI coverage
        </h3>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <CoverageCard
          Icon={Terminal}
          title="Agent hooks"
          body="Claude Code, Cursor, and Codex actions can be checked through local hooks before execution."
        />
        <CoverageCard
          Icon={Globe2}
          title="Browser ingestion"
          body="Browser-visible pages, selected text, pasted text, and submit flows can be scanned before supported AI tools read them."
        />
        <CoverageCard
          Icon={ShieldX}
          title="Local egress"
          body="Risky destinations learned from your own scans can be blocked in the browser through MV3 DNR rules."
        />
      </div>
      <p className="liquid-glass rounded-2xl p-5 text-white/60 text-[13px] leading-relaxed">
        SecureAI cannot see actions an AI provider runs only on its own servers.
        Protection covers observable agent actions, browser-visible ingestion, and
        local browser destination blocking.
      </p>
    </motion.div>
  )
}

/** One coverage card: an icon, a title, and a short body. */
function CoverageCard({
  Icon,
  title,
  body,
}: {
  Icon: LucideIcon
  title: string
  body: string
}) {
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
      <Icon className="w-5 h-5 text-white/75" />
      <h4 className="text-white text-sm font-semibold">{title}</h4>
      <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
    </div>
  )
}

interface DashboardHeaderProps {
  email: string
  /** Account holder's given name; drives the greeting, falling back to the email. */
  firstName: string | null
  tier: AccountTier
  onUpgrade: () => void
}

/**
 * The greeting row: a "Hi <name>!" heading (email fallback) on the left, and on
 * the right, on the same line, the tier badge, the upgrade CTA (free/personal),
 * and a Settings gear. The gear is the account's single entry to the settings
 * page now that Settings has left the navbar.
 */
function DashboardHeader({ email, firstName, tier, onUpgrade }: DashboardHeaderProps) {
  // Greet by first name when the account has one; a nameless (legacy / API-key)
  // account falls back to its email so the heading is never empty.
  const greeting = firstName !== null && firstName.length > 0 ? `Hi ${firstName}!` : email
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
          {greeting}
        </h1>
      </div>
      <div className="flex items-center gap-2.5">
        <TierBadge tier={tier} />
        {(tier === 'free' || tier === 'personal') && (
          <button
            type="button"
            onClick={onUpgrade}
            className="inline-flex items-center gap-1.5 rounded-full bg-white px-4 py-2 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Upgrade to Pro
          </button>
        )}
        <a
          href="#settings"
          aria-label="Settings"
          className="glass-pill inline-flex items-center justify-center w-9 h-9 text-white/70 hover:text-white transition-colors"
        >
          <Settings className="w-4 h-4" />
        </a>
      </div>
    </motion.div>
  )
}

/** The account tier, rendered as a pill tinted by tier. */
function TierBadge({ tier }: { tier: AccountTier }) {
  const tint =
    tier === 'pro'
      ? 'text-allow'
      : tier === 'personal'
        ? 'text-sky-300'
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
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
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
        Run your first scan and your protection stats, threats blocked, IOCs
        caught, and the verdict trend, will appear here.
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
      <div className="flex-1 min-h-[180px]">
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

/** The verdict palette (text tint + chip background) for a recent-scan pill. */
const VERDICT_PILL: Record<Verdict, { label: string; className: string }> = {
  ALLOW: { label: 'ALLOW', className: 'text-allow bg-allow/10' },
  HUMAN_APPROVAL_REQUIRED: { label: 'REVIEW', className: 'text-review bg-review/10' },
  BLOCK: { label: 'BLOCK', className: 'text-block bg-block/10' },
}

/** A small verdict-colored pill. REVIEW is the display for HUMAN_APPROVAL_REQUIRED. */
function VerdictPill({ verdict }: { verdict: Verdict }) {
  const { label, className } = VERDICT_PILL[verdict]
  return (
    <span
      className={`inline-flex items-center justify-center rounded-full px-2.5 py-1 text-[10px] font-mono font-bold uppercase tracking-[0.1em] ${className}`}
    >
      {label}
    </span>
  )
}

/** The source label for a recent scan: a truncated URL, or a paste label. */
function recentSource(source: RecentScan['source']): string {
  return source.kind === 'url' ? hostname(source.ref) : 'Pasted skill'
}

type RecentState =
  | { phase: 'loading' }
  | { phase: 'ready'; scans: RecentScan[] }
  | { phase: 'error' }

/**
 * The dashboard's recent-scans list: the account's last few scans, each a
 * verdict pill, the source (truncated URL or a paste label), a flagged-count
 * chip when indicators were caught, and a relative time. A brand-new account
 * (or a transport failure) lands on the intentional empty state pointing back to
 * the scanner. Loads `GET /api/scans/recent?limit=RECENT_SCANS_LIMIT` on mount.
 */
function RecentScans() {
  const [state, setState] = useState<RecentState>({ phase: 'loading' })

  useEffect(() => {
    let active = true
    fetchRecentScans(RECENT_SCANS_LIMIT)
      .then(({ scans }) => {
        if (active) setState({ phase: 'ready', scans })
      })
      .catch(() => {
        if (active) setState({ phase: 'error' })
      })
    return () => {
      active = false
    }
  }, [])

  const scans = state.phase === 'ready' ? state.scans : []

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.03, ease: [0.16, 1, 0.3, 1] }}
      className="liquid-glass rounded-2xl p-5 flex flex-col gap-4"
    >
      <div className="flex items-center gap-2">
        <ScanLine className="w-4 h-4 text-white/70" />
        <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
          Recent scans
        </h3>
      </div>

      {state.phase === 'loading' && (
        <p className="text-white/45 font-mono text-sm py-6 text-center">
          Loading your recent scans…
        </p>
      )}

      {(state.phase === 'error' || (state.phase === 'ready' && scans.length === 0)) && (
        <p className="text-white/45 text-[13px] py-6 text-center leading-relaxed">
          No scans yet, run one from the scanner.
        </p>
      )}

      {state.phase === 'ready' && scans.length > 0 && (
        <ul className="flex flex-col divide-y divide-white/[0.06]">
          {scans.map((scan) => (
            <RecentScanRow key={scan.headHash} scan={scan} />
          ))}
        </ul>
      )}
    </motion.div>
  )
}

/** One recent-scan row: verdict pill, source, flagged chip, relative time. */
function RecentScanRow({ scan }: { scan: RecentScan }) {
  const SourceIcon = scan.source.kind === 'url' ? Link2 : FileText
  return (
    <li className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0">
      <VerdictPill verdict={scan.verdict} />
      <span className="flex min-w-0 flex-1 items-center gap-1.5">
        <SourceIcon className="w-3.5 h-3.5 shrink-0 text-white/40" />
        <span className="truncate text-[13px] text-white/80" title={scan.source.ref}>
          {recentSource(scan.source)}
        </span>
      </span>
      {scan.flagged > 0 && (
        <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-block/10 px-2 py-0.5 text-[11px] font-mono font-semibold text-block">
          <ShieldAlert className="w-3 h-3" />
          {scan.flagged}
        </span>
      )}
      <span className="shrink-0 font-mono text-[11px] text-white/40 tabular-nums">
        {relativeTime(scan.scannedAt)}
      </span>
    </li>
  )
}

/** How long (ms) the copy button stays in its confirmed "Copied" state. */
const COPY_FEEDBACK_MS = 1500

/**
 * A copy-to-clipboard button: copies `value` via `navigator.clipboard`, then
 * flips to a check + "Copied" for {@link COPY_FEEDBACK_MS} before reverting. A
 * denied clipboard leaves the button idle (the value stays visible to copy by
 * hand) rather than throwing.
 */
function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current)
    }
  }, [])

  const handleCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      if (timerRef.current !== null) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setCopied(false), COPY_FEEDBACK_MS)
    } catch {
      /* clipboard denied: the value is still visible to copy by hand */
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={label}
      className="glass-pill inline-flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer shrink-0"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-allow" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

/** The API-key card: shows the prefix and reveals a rotated key once. */
function ApiKeyCard({ apiKeyPrefix }: { apiKeyPrefix: string }) {
  const [revealed, setRevealed] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleRotate = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    try {
      const { apiKey } = await rotateApiKey()
      setRevealed(apiKey)
    } catch {
      setError('Could not regenerate the key. Please try again.')
    } finally {
      setBusy(false)
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
        <div className="flex items-center gap-2">
          <code className="flex-1 min-w-0 break-all rounded-lg bg-white/[0.04] border border-white/10 px-3 py-2 font-mono text-[13px] text-white/70">
            {apiKeyPrefix}
            <span className="text-white/30">··········</span>
          </code>
          <CopyButton value={apiKeyPrefix} label="Copy API key prefix" />
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <code className="flex-1 min-w-0 break-all rounded-lg bg-white/[0.04] border border-white/10 px-3 py-2 font-mono text-[13px] text-allow">
              {revealed}
            </code>
            <CopyButton value={revealed} label="Copy new API key" />
          </div>
          <p className="text-review/90 font-mono text-[11px] leading-snug">
            Copy this now, it will not be shown again.
          </p>
        </div>
      )}

      {error && <p className="text-block/90 font-mono text-[12px]">{error}</p>}
    </motion.div>
  )
}

/**
 * The "Set up the Guard" card: the runtime side of the account. It offers the
 * Guard hook as a direct download and, separately, the one-line installer with
 * the member's API key embedded.
 *
 * The raw key is never stored (the backend keeps a hash only), so it can only be
 * embedded at the moment a fresh one is minted. "Generate install command" calls
 * `POST /api/key/rotate`, which returns a brand-new key once and revokes every
 * prior key; the returned key is woven into {@link guardInstallCommand} and shown
 * in a copy box with an explicit warning that older keys are now dead and this is
 * the only time the command is shown. Before generating, a hint makes the
 * key-rotation side effect plain so the operator is never surprised.
 */
function GuardSetupCard() {
  const [command, setCommand] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async (): Promise<void> => {
    setBusy(true)
    setError(null)
    try {
      const { apiKey } = await rotateApiKey()
      setCommand(guardInstallCommand(apiKey))
    } catch {
      setError('Could not generate the install command. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.07, ease: [0.16, 1, 0.3, 1] }}
      className="liquid-glass rounded-2xl p-5 flex flex-col gap-5"
    >
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-allow" />
          <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
            Set up the Guard
          </h3>
        </div>
        <p className="text-white/55 text-[13px] leading-relaxed">
          Screen supported Claude Code, Cursor, and Codex actions before they run.
          Browser pairing opens the extension flow for visible-content scans and local DNR blocks.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex flex-col">
          <span className="text-white text-[14px] font-semibold">
            SecureAI Guard
          </span>
          <span className="text-white/50 text-[12px]">
            Zero-dependency adapters for your local agents.
          </span>
        </div>
        <a
          href={GUARD_DOWNLOAD_PATH}
          download
          className="inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer shrink-0"
        >
          <Download className="w-4 h-4" />
          Download the Guard
        </a>
      </div>

      <div className="flex flex-col gap-2 border-t border-white/[0.06] pt-5">
        <div className="flex items-center gap-2 text-white/55 text-[11px] font-mono uppercase tracking-[0.14em]">
          <Terminal className="w-3.5 h-3.5" />
          One-line install with your key
        </div>

        {command === null ? (
          <>
            <p className="text-white/45 text-[12px] leading-relaxed">
              Your key is stored hashed and shown only once, so generating the
              command mints a fresh API key and revokes your previous keys. The
              installer asks which endpoints to wire when run in a terminal.
            </p>
            <button
              type="button"
              onClick={handleGenerate}
              disabled={busy}
              className="glass-pill self-start inline-flex items-center gap-1.5 px-4 py-2 text-[13px] font-medium text-white/80 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${busy ? 'animate-spin' : ''}`} />
              Generate install command
            </button>
          </>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex items-stretch gap-2">
              <code className="flex-1 min-w-0 overflow-x-auto rounded-xl bg-white/[0.04] border border-white/10 px-3.5 py-2.5 font-mono text-[12px] sm:text-[13px] text-allow whitespace-nowrap">
                <span className="text-allow/60 select-none">$ </span>
                {command}
              </code>
              <CopyButton value={command} label="Copy install command" />
            </div>
            <p className="text-review/90 font-mono text-[11px] leading-snug">
              This generated a fresh API key, your previous keys are now revoked.
              Copy this command now; the key isn't shown again.
            </p>
          </div>
        )}

        {error && <p className="text-block/90 font-mono text-[12px]">{error}</p>}
      </div>
    </motion.div>
  )
}
