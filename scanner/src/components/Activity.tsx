import { useEffect, useState } from 'react'
import { motion } from 'motion/react'
import { FileText, Link2, Server, ShieldAlert } from 'lucide-react'
import { fetchRecentScans } from '../api/client'
import { hostname, relativeTime } from '../lib/format'
import type { RecentScan, Verdict } from '../api/types'

const ACTIVITY_LIMIT = 20

type LoadState =
  | { phase: 'loading' }
  | { phase: 'ready'; scans: RecentScan[] }
  | { phase: 'error'; message: string }

const VERDICT_CLASS: Record<Verdict, string> = {
  ALLOW: 'text-allow bg-allow/10',
  HUMAN_APPROVAL_REQUIRED: 'text-review bg-review/10',
  BLOCK: 'text-block bg-block/10',
}

/** Authenticated scan activity page. */
export function Activity() {
  const [state, setState] = useState<LoadState>({ phase: 'loading' })

  useEffect(() => {
    let active = true
    fetchRecentScans(ACTIVITY_LIMIT)
      .then(({ scans }) => {
        if (active) setState({ phase: 'ready', scans })
      })
      .catch(() => {
        if (active) setState({ phase: 'error', message: 'Could not load activity.' })
      })
    return () => {
      active = false
    }
  }, [])

  return (
    <section className="relative z-10 flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-6">
        <Header />
        <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
          {state.phase === 'loading' && (
            <p className="text-white/45 font-mono text-sm py-12 text-center">
              Loading scan activity...
            </p>
          )}
          {state.phase === 'error' && (
            <p className="text-block/90 font-mono text-sm py-12 text-center">
              {state.message}
            </p>
          )}
          {state.phase === 'ready' && state.scans.length === 0 && (
            <p className="text-white/45 text-[13px] py-12 text-center">
              No scans yet.
            </p>
          )}
          {state.phase === 'ready' && state.scans.length > 0 && (
            <ul className="flex flex-col divide-y divide-white/[0.06]">
              {state.scans.map((scan) => (
                <ActivityRow key={scan.id} scan={scan} />
              ))}
            </ul>
          )}
        </div>
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
        Activity
      </span>
      <h1
        style={{ fontFamily: "'Instrument Serif', serif" }}
        className="text-3xl md:text-[38px] font-medium text-white leading-tight"
      >
        Recent SecureAI decisions
      </h1>
    </motion.div>
  )
}

function ActivityRow({ scan }: { scan: RecentScan }) {
  const SourceIcon =
    scan.source.kind === 'url' ? Link2 : scan.source.kind === 'mcp' ? Server : FileText
  const source =
    scan.source.kind === 'url'
      ? hostname(scan.source.ref)
      : scan.source.kind === 'mcp'
        ? 'MCP config'
        : 'Pasted content'
  const label = scan.verdict === 'HUMAN_APPROVAL_REQUIRED' ? 'REVIEW' : scan.verdict

  return (
    <li className="flex flex-col sm:flex-row sm:items-center gap-3 py-3 first:pt-0 last:pb-0">
      <span
        className={`inline-flex w-fit items-center justify-center rounded-full px-2.5 py-1 text-[10px] font-mono font-bold uppercase tracking-[0.1em] ${VERDICT_CLASS[scan.verdict]}`}
      >
        {label}
      </span>
      <span className="flex min-w-0 flex-1 items-center gap-2">
        <SourceIcon className="w-4 h-4 shrink-0 text-white/40" />
        <span className="truncate text-white/80 text-[13px]" title={scan.source.ref}>
          {source}
        </span>
      </span>
      {scan.flagged > 0 && (
        <span className="inline-flex w-fit items-center gap-1 rounded-full bg-block/10 px-2 py-0.5 text-[11px] font-mono font-semibold text-block">
          <ShieldAlert className="w-3 h-3" />
          {scan.flagged}
        </span>
      )}
      <span className="font-mono text-[11px] text-white/40 tabular-nums">
        {relativeTime(scan.scannedAt)}
      </span>
      <span className="font-mono text-[10px] text-white/25 truncate sm:max-w-[140px]">
        {scan.headHash.slice(0, 12)}
      </span>
    </li>
  )
}
