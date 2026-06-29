import { useEffect, useMemo, useState } from 'react'
import { motion } from 'motion/react'
import {
  Activity,
  Globe2,
  ScanLine,
  ShieldCheck,
  ShieldX,
  Terminal,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { fetchStats } from '../api/client'
import { STATS_TREND_DAYS } from '../config'
import { zeroFillDaily } from '../lib/stats'
import type { StatsResponse } from '../api/types'

type LoadState =
  | { phase: 'loading' }
  | { phase: 'ready'; stats: StatsResponse }
  | { phase: 'error'; message: string }

/** Authenticated protection overview for SecureAI Personal. */
export function Protection() {
  const [state, setState] = useState<LoadState>({ phase: 'loading' })

  useEffect(() => {
    let active = true
    fetchStats()
      .then((stats) => {
        if (active) setState({ phase: 'ready', stats })
      })
      .catch(() => {
        if (active) setState({ phase: 'error', message: 'Could not load protection status.' })
      })
    return () => {
      active = false
    }
  }, [])

  return (
    <section className="relative z-10 flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-6">
        <Header />
        {state.phase === 'loading' && (
          <p className="text-white/45 font-mono text-sm py-20 text-center">
            Loading protection status...
          </p>
        )}
        {state.phase === 'error' && (
          <p className="text-block/90 font-mono text-sm py-20 text-center">
            {state.message}
          </p>
        )}
        {state.phase === 'ready' && <ProtectionBody stats={state.stats} />}
      </div>
    </section>
  )
}

function Header() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-1.5"
    >
      <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
        Protection
      </span>
      <h1
        style={{ fontFamily: "'Instrument Serif', serif" }}
        className="text-3xl md:text-[38px] font-medium text-white leading-tight"
      >
        Your SecureAI coverage
      </h1>
    </motion.div>
  )
}

function ProtectionBody({ stats }: { stats: StatsResponse }) {
  const filled = useMemo(
    () => zeroFillDaily(stats.daily, STATS_TREND_DAYS),
    [stats.daily],
  )
  const lastWeek = filled.slice(-7)
  const weekBlocks = lastWeek.reduce((sum, row) => sum + row.blocks, 0)

  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Metric Icon={ScanLine} label="Scans" value={stats.totals.scans} accent="text-white" />
        <Metric Icon={ShieldX} label="Blocked" value={stats.totals.blocks} accent="text-block" />
        <Metric Icon={Activity} label="Reviews" value={stats.totals.reviews} accent="text-review" />
        <Metric Icon={ShieldCheck} label="Last 7d blocks" value={weekBlocks} accent="text-allow" />
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
        Protection covers observable agent actions, browser-visible ingestion,
        and local browser destination blocking.
      </p>
    </div>
  )
}

function Metric({
  Icon,
  label,
  value,
  accent,
}: {
  Icon: LucideIcon
  label: string
  value: number
  accent: string
}) {
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
      <Icon className={`w-5 h-5 ${accent}`} />
      <span
        style={{ fontFamily: "'Instrument Serif', serif" }}
        className={`text-3xl md:text-4xl font-medium tabular-nums ${accent}`}
      >
        {value.toLocaleString()}
      </span>
      <span className="text-white/65 text-[13px] font-medium">{label}</span>
    </div>
  )
}

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
      <h2 className="text-white text-sm font-semibold">{title}</h2>
      <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
    </div>
  )
}
