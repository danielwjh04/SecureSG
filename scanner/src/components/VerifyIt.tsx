/**
 * The "Verify it yourself" section on the scanner landing (anchor `#verify`):
 * the proof moat, told plainly. Every verdict is a SHA-256 hash chain over the
 * evidence, so anyone can re-check it client-side with no server round trip;
 * tamper with one byte and it breaks at exactly that link.
 *
 * It pairs an on-brand depiction of the real `POST /api/scan` -> `POST
 * /api/verify` round trip (a static, accurate code box, not a live verifier
 * widget) with a "live" stat row derived from the committed public gallery,
 * reusing the same fetch + computation as the Enterprise KPI row. The stat row
 * degrades gracefully: an absent or empty gallery reads as zero, never an error.
 */

import { useEffect, useState } from 'react'
import { motion } from 'motion/react'
import { Boxes, FileCheck, Link2, ShieldAlert } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { API } from '../config'
import type { GalleryStats } from '../lib/galleryStats'
import { deriveStats, fetchGallery } from '../lib/galleryStats'
import { CodeBlock } from './CodeBlock'

/** Shared entrance transition, matching the hero's easing. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

/** One "live" stat card descriptor for the gallery-derived row. */
interface Stat {
  Icon: LucideIcon
  key: keyof GalleryStats
  label: string
  footnote: string
  accent: string
}

const STATS: Stat[] = [
  {
    Icon: Boxes,
    key: 'skills',
    label: 'Skills scanned',
    footnote: 'Live in our public gallery',
    accent: 'text-white',
  },
  {
    Icon: ShieldAlert,
    key: 'threats',
    label: 'Threats caught',
    footnote: 'Returned BLOCK before running',
    accent: 'text-block',
  },
  {
    Icon: Link2,
    key: 'proofLinks',
    label: 'Proof links sealed',
    footnote: 'SHA-256 steps across all scans',
    accent: 'text-allow',
  },
]

/**
 * The two-call proof round trip, depicted against the real endpoints. The scan
 * returns a proof; re-posting that proof to verify returns CHAIN_OK, and
 * flipping a single byte returns CHAIN_BROKEN at the first invalid index. This
 * is an accurate static depiction, not a runnable transcript, so the response
 * bodies are shown as the contract's real shapes.
 */
const PROOF_FLOW = `# 1 · Scan a skill; the verdict carries a proof.
POST ${API.scan}
  { "sourceUrl": "https://github.com/owner/skill" }
-> { "verdict": "...",
     "proof": { "genesisHash", "steps", "headHash" } }

# 2 · Re-check that exact proof, client-side.
POST ${API.verify}
  { "proof": { ...the proof from step 1... } }
-> { "status": "CHAIN_OK", "firstInvalidIndex": null }

# Change one byte of any step and re-verify:
-> { "status": "CHAIN_BROKEN", "firstInvalidIndex": 3 }`

export function VerifyIt() {
  const [stats, setStats] = useState<GalleryStats | null>(null)

  // Derive honest "live" numbers from the committed public gallery on mount.
  // An absent or empty gallery resolves to zeroed stats (handled in the lib),
  // so this never throws and never blocks the section from rendering.
  useEffect(() => {
    let active = true
    fetchGallery().then((data) => {
      if (active) setStats(deriveStats(data))
    })
    return () => {
      active = false
    }
  }, [])

  return (
    <section id="verify" className="max-w-5xl mx-auto px-6 pt-10 pb-20">
      <motion.div
        {...RISE}
        className="flex flex-col items-center text-center gap-3 mb-10"
      >
        <p className="flex items-center gap-2 text-white/60 text-[11px] font-mono uppercase tracking-[0.22em]">
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          Don't trust us
        </p>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] text-white"
        >
          Verify it yourself.
        </h2>
        <p className="text-white/65 text-sm md:text-[15px] max-w-2xl">
          Every verdict is a SHA-256 hash chain over the evidence we collected.
          Anyone can re-check it in their own browser, with no server round trip.
          Tamper with any step and the chain breaks at exactly that link.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
        {/* The two-call proof round trip, on the real endpoints. */}
        <motion.div {...RISE} className="flex flex-col gap-3">
          <CodeBlock language="http" code={PROOF_FLOW} />
          <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
            <div className="flex items-center gap-3 text-[13px]">
              <span className="glass-pill shrink-0 px-3 py-1.5 font-mono text-[12px] text-allow">
                CHAIN_OK
              </span>
              <span className="text-white/55">Untouched proof re-verifies.</span>
            </div>
            <div className="flex items-center gap-3 text-[13px]">
              <span className="glass-pill shrink-0 px-3 py-1.5 font-mono text-[12px] text-block">
                CHAIN_BROKEN
              </span>
              <span className="text-white/55">One changed byte, flagged at the exact link.</span>
            </div>
          </div>
        </motion.div>

        {/* "Live" stat row, derived from the committed public gallery. */}
        <motion.div {...RISE} className="flex flex-col gap-3">
          <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
            <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
            Live from our public gallery
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-1 gap-3">
            {STATS.map(({ Icon, key, label, footnote, accent }) => (
              <div
                key={key}
                className="liquid-glass rounded-2xl p-5 flex items-center gap-4"
              >
                <Icon className={`w-5 h-5 shrink-0 ${accent}`} />
                <div className="flex flex-col">
                  <span
                    className={`text-3xl font-medium tabular-nums ${accent}`}
                    style={{ fontFamily: "'Instrument Serif', serif" }}
                  >
                    {stats ? String(stats[key]) : '…'}
                  </span>
                  <span className="text-white/80 text-sm font-medium">
                    {label}
                  </span>
                  <span className="text-white/45 text-[11px] leading-snug font-mono">
                    {footnote}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <div className="liquid-glass rounded-2xl p-5 flex items-start gap-3">
            <FileCheck className="w-5 h-5 text-allow shrink-0 mt-0.5" />
            <p className="text-white/55 text-[13px] leading-relaxed">
              Every proof link above is one SHA-256 step you can recompute
              yourself. The whole chain re-verifies in a single forward pass.
            </p>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
