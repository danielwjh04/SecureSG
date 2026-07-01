/**
 * The landing page's "it's already happening" section: a wall of REAL, publicly
 * reported incidents where an AI assistant or coding agent was turned against its
 * owner. The list is data, loaded from {@link INCIDENTS_DATA_PATH} (a public JSON
 * asset), so entries are edited without a code change and every card links to its
 * original source. On any fetch failure the section omits itself rather than
 * showing an error (the same degrade-to-empty discipline as the gallery).
 */

import type { ReactNode } from 'react'
import { motion } from 'motion/react'
import { ArrowUpRight } from 'lucide-react'
import type { Incident, IncidentsData } from '../../api/types'
import {
  GALLERY_FETCH_ATTEMPTS,
  GALLERY_FETCH_TIMEOUT_MS,
  INCIDENTS_DATA_PATH,
} from '../../config'
import { useApiResource } from '../../hooks/useApiResource'

/** Shared entrance transition for landing sections. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

/** The empty dataset used whenever the incidents file is absent or unreadable. */
const EMPTY: IncidentsData = { incidents: [] }

/**
 * Fetch the incident list, degrading to an empty list on any failure. Each
 * attempt is bounded by {@link GALLERY_FETCH_TIMEOUT_MS} and retried up to
 * {@link GALLERY_FETCH_ATTEMPTS} times; a definitive 404 (or malformed body) is
 * not retried and resolves to {@link EMPTY}, so the section simply omits itself.
 *
 * Time complexity: O(a · n) for a = attempts, n = response body size.
 * Space complexity: O(n).
 */
async function fetchIncidents(): Promise<IncidentsData> {
  for (let attempt = 1; attempt <= GALLERY_FETCH_ATTEMPTS; attempt += 1) {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), GALLERY_FETCH_TIMEOUT_MS)
    try {
      const response = await fetch(INCIDENTS_DATA_PATH, { signal: controller.signal })
      if (!response.ok) return EMPTY
      const data = (await response.json()) as IncidentsData
      return Array.isArray(data.incidents) ? data : EMPTY
    } catch {
      if (attempt === GALLERY_FETCH_ATTEMPTS) return EMPTY
    } finally {
      clearTimeout(timeout)
    }
  }
  return EMPTY
}

export function Incidents(): ReactNode {
  const { data } = useApiResource<IncidentsData>(fetchIncidents, 0)
  const incidents = data?.incidents ?? []

  // Omit the whole section when there is nothing to show (loading or missing
  // data), so the landing never renders an empty or half-loaded band.
  if (incidents.length === 0) {
    return null
  }

  return (
    <section className="max-w-5xl mx-auto px-6 py-20">
      <motion.div {...RISE} className="flex flex-col gap-3 mb-10">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-block/80">
          It's already happening
        </span>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] leading-[1.1] text-white"
        >
          Real agents. Real breaches.
        </h2>
        <p className="text-white/60 text-[15px] leading-relaxed max-w-2xl">
          A sample of publicly reported incidents where an AI assistant or coding
          agent was turned against its owner. Every card links to the source.
        </p>
      </motion.div>

      <motion.div {...RISE} className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {incidents.map((incident) => (
          <IncidentCard key={incident.id} incident={incident} />
        ))}
      </motion.div>
    </section>
  )
}

/** One incident card: the headline, the source + date, and a link-out affordance. */
function IncidentCard({ incident }: { incident: Incident }): ReactNode {
  return (
    <a
      href={incident.url}
      target="_blank"
      rel="noreferrer"
      className="liquid-glass group rounded-2xl p-5 flex flex-col gap-4 hover:bg-white/[0.02] transition-colors"
    >
      <p className="text-white/85 text-[14px] leading-snug">{incident.title}</p>
      <div className="mt-auto flex items-center justify-between gap-3">
        <span className="text-white/45 text-[11px] font-mono uppercase tracking-[0.1em]">
          {incident.source} · {incident.date}
        </span>
        <ArrowUpRight className="w-4 h-4 shrink-0 text-white/40 group-hover:text-white transition-colors" />
      </div>
    </a>
  )
}
