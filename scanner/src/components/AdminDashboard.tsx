/**
 * The owner-only admin analytics dashboard. The parent (`App`) gates the
 * `#admin` route so only an admin reaches this surface; on mount it loads
 * `GET /api/admin/overview` and renders sitewide metrics in the shared dark/glass
 * shell: headline stat cards, a 30-day sign-ups trend (recharts, zero-filled
 * client-side), a tier-breakdown donut, and verdict-colored sitewide totals.
 *
 * Every chart is themed dark with the verdict palette — no default light recharts
 * theme leaks through — matching the protection Dashboard.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion } from 'motion/react'
import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  CheckCircle2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Users,
  Wallet,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { fetchAdminOverview } from '../api/client'
import { STATS_TREND_DAYS } from '../config'
import { zeroFillSignups } from '../lib/stats'
import type { AdminOverview, AdminTierCounts } from '../api/types'

/** The shared palette, so cards and charts use exact, consistent colors. */
const COLOR = {
  allow: '#34d399',
  review: '#fbbf24',
  block: '#f87171',
  signups: 'rgba(255,255,255,0.7)',
  axis: 'rgba(255,255,255,0.35)',
  free: 'rgba(255,255,255,0.45)',
  pro: '#34d399',
  enterprise: '#60a5fa',
} as const

/** Shared dark tooltip styling so recharts never paints its light default. */
const TOOLTIP_STYLE = {
  background: 'rgba(10,12,16,0.92)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 12,
  fontSize: 12,
  color: '#fff',
} as const

type LoadState =
  | { phase: 'loading' }
  | { phase: 'ready'; overview: AdminOverview }
  | { phase: 'error'; message: string }

export function AdminDashboard() {
  const [load, setLoad] = useState<LoadState>({ phase: 'loading' })

  const refresh = useCallback((): (() => void) => {
    let active = true
    setLoad({ phase: 'loading' })
    fetchAdminOverview()
      .then((overview) => {
        if (active) setLoad({ phase: 'ready', overview })
      })
      .catch(() => {
        if (active) setLoad({ phase: 'error', message: 'Could not load admin analytics.' })
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => refresh(), [refresh])

  return (
    <section className="relative z-10 bg-black flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-8">
        <Header
          generatedAt={load.phase === 'ready' ? load.overview.generatedAt : null}
          onRefresh={() => refresh()}
          busy={load.phase === 'loading'}
        />

        {load.phase === 'loading' && (
          <p className="text-white/45 font-mono text-sm py-20 text-center">
            Loading sitewide analytics…
          </p>
        )}
        {load.phase === 'error' && (
          <p className="text-block/90 font-mono text-sm py-20 text-center">{load.message}</p>
        )}
        {load.phase === 'ready' && <OverviewBody overview={load.overview} />}
      </div>
    </section>
  )
}

interface HeaderProps {
  generatedAt: string | null
  onRefresh: () => void
  busy: boolean
}

/** The title row: admin label, heading, generated-at stamp, and refresh. */
function Header({ generatedAt, onRefresh, busy }: HeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4"
    >
      <div className="flex flex-col gap-1.5">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
          Admin analytics
        </span>
        <h1
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[38px] font-medium tracking-[-0.01em] text-white leading-tight"
        >
          Sitewide overview
        </h1>
      </div>
      <div className="flex items-center gap-3">
        {generatedAt !== null && (
          <span className="text-white/40 font-mono text-[11px]">
            Generated {formatStamp(generatedAt)}
          </span>
        )}
        <button
          type="button"
          onClick={onRefresh}
          disabled={busy}
          className="glass-pill inline-flex items-center gap-1.5 px-3.5 py-1.5 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${busy ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>
    </motion.div>
  )
}

/** One headline stat tile. */
interface StatTile {
  key: string
  Icon: LucideIcon
  label: string
  value: number
  accent: string
}

function OverviewBody({ overview }: { overview: AdminOverview }) {
  const filledSignups = useMemo(
    () => zeroFillSignups(overview.signupsDaily, STATS_TREND_DAYS),
    [overview.signupsDaily],
  )
  const hasAny =
    overview.totalUsers > 0 || overview.usageTotals.scans > 0 || overview.activeSubscriptions > 0

  const tiles: StatTile[] = [
    { key: 'users', Icon: Users, label: 'Total sign-ups', value: overview.totalUsers, accent: 'text-white' },
    { key: 'subs', Icon: Wallet, label: 'Pro subscribers', value: overview.activeSubscriptions, accent: 'text-allow' },
    { key: 'scans', Icon: ShieldCheck, label: 'Total scans', value: overview.usageTotals.scans, accent: 'text-white' },
    { key: 'blocks', Icon: ShieldX, label: 'Threats blocked', value: overview.usageTotals.blocks, accent: 'text-block' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-6"
    >
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {tiles.map(({ key, Icon, label, value, accent }) => (
          <div key={key} className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
            <Icon className={`w-5 h-5 ${accent}`} />
            <div
              className={`text-3xl md:text-4xl font-medium tabular-nums ${accent}`}
              style={{ fontFamily: "'Instrument Serif', serif" }}
            >
              {formatCount(value)}
            </div>
            <div className="text-white/70 text-[13px] font-medium leading-snug">{label}</div>
          </div>
        ))}
      </div>

      {!hasAny ? (
        <EmptyState />
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <SignupsTrend signups={filledSignups} className="lg:col-span-2" />
            <TierBreakdown tiers={overview.usersByTier} total={overview.totalUsers} />
          </div>
          <VerdictTotals totals={overview.usageTotals} />
        </>
      )}
    </motion.div>
  )
}

/** The intentional empty state when nothing has happened sitewide yet. */
function EmptyState() {
  return (
    <div className="liquid-glass rounded-2xl p-10 flex flex-col items-center text-center gap-3">
      <Users className="w-7 h-7 text-allow" />
      <h3 style={{ fontFamily: "'Instrument Serif', serif" }} className="text-2xl font-medium text-white">
        No activity yet
      </h3>
      <p className="text-white/55 text-[14px] max-w-md leading-relaxed">
        Once people sign up and run scans, sign-up trends, tier mix, and sitewide
        verdict totals will appear here.
      </p>
    </div>
  )
}

/** The 30-day sign-ups trend, themed dark. */
function SignupsTrend({
  signups,
  className,
}: {
  signups: AdminOverview['signupsDaily']
  className?: string
}) {
  const data = signups.map((row) => ({ ...row, label: row.day.slice(5) }))
  return (
    <div className={`liquid-glass rounded-2xl p-5 flex flex-col gap-4 ${className ?? ''}`}>
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Last {signups.length} days · sign-ups
      </h3>
      <div className="h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="adminSignupsFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLOR.signups} stopOpacity={0.32} />
                <stop offset="100%" stopColor={COLOR.signups} stopOpacity={0} />
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
              dataKey="count"
              name="Sign-ups"
              stroke={COLOR.signups}
              strokeWidth={1.5}
              fill="url(#adminSignupsFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/** Tier breakdown as a donut (free / pro / enterprise). */
function TierBreakdown({ tiers, total }: { tiers: AdminTierCounts; total: number }) {
  const data = [
    { name: 'Free', value: tiers.free, color: COLOR.free },
    { name: 'Pro', value: tiers.pro, color: COLOR.pro },
    { name: 'Enterprise', value: tiers.enterprise, color: COLOR.enterprise },
  ]
  const hasUsers = total > 0
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Tier breakdown
      </h3>
      <div className="h-[200px] relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={hasUsers ? data : [{ name: 'None', value: 1, color: 'rgba(255,255,255,0.08)' }]}
              dataKey="value"
              nameKey="name"
              innerRadius={52}
              outerRadius={78}
              paddingAngle={hasUsers ? 2 : 0}
              stroke="none"
            >
              {(hasUsers ? data : [{ name: 'None', value: 1, color: 'rgba(255,255,255,0.08)' }]).map(
                (entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ),
              )}
            </Pie>
            {hasUsers && (
              <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#fff' }} />
            )}
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span
            className="text-2xl font-medium text-white tabular-nums"
            style={{ fontFamily: "'Instrument Serif', serif" }}
          >
            {formatCount(total)}
          </span>
          <span className="text-white/45 font-mono text-[10px] uppercase tracking-[0.14em]">
            users
          </span>
        </div>
      </div>
      <div className="flex items-center justify-center gap-4 text-[11px] font-mono">
        {data.map((entry) => (
          <span key={entry.name} className="inline-flex items-center gap-1.5 text-white/60">
            <span className="w-2 h-2 rounded-full" style={{ background: entry.color }} />
            {entry.name} {entry.value}
          </span>
        ))}
      </div>
    </div>
  )
}

/** Sitewide verdict totals (Allow / Review / Block) + IOCs caught. */
function VerdictTotals({ totals }: { totals: AdminOverview['usageTotals'] }) {
  const cells = [
    { key: 'allows', Icon: CheckCircle2, label: 'Allowed', value: totals.allows, accent: 'text-allow' },
    { key: 'reviews', Icon: ShieldAlert, label: 'Reviews', value: totals.reviews, accent: 'text-review' },
    { key: 'blocks', Icon: ShieldX, label: 'Blocked', value: totals.blocks, accent: 'text-block' },
    { key: 'flagged', Icon: ShieldAlert, label: 'IOCs caught', value: totals.flagged, accent: 'text-block' },
  ]
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
      <h3 className="text-[12px] font-mono uppercase tracking-[0.14em] text-white/55">
        Sitewide verdict totals
      </h3>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {cells.map(({ key, Icon, label, value, accent }) => (
          <div key={key} className="flex flex-col gap-1.5">
            <Icon className={`w-4 h-4 ${accent}`} />
            <span className={`text-2xl font-medium tabular-nums ${accent}`} style={{ fontFamily: "'Instrument Serif', serif" }}>
              {formatCount(value)}
            </span>
            <span className="text-white/55 text-[12px]">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/** Format a count with thousands separators, never `NaN`. */
function formatCount(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString() : '0'
}

/** Format an ISO stamp as a short local date-time, falling back to the raw string. */
function formatStamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}
