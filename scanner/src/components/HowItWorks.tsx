/**
 * The "How it works" landing section (anchored at `#how`): the real six-layer,
 * fail-closed scan pipeline, each shown as a glass card, followed by the two
 * invariants that hold across every scan (fail-closed, tighten-only). Purely
 * presentational, no state.
 */

import { motion } from 'motion/react'
import {
  FileSearch,
  GitBranch,
  Ruler,
  Database,
  ScanLine,
  Lock,
  ShieldCheck,
  ArrowUpCircle,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

interface Step {
  Icon: LucideIcon
  title: string
  body: string
}

const STEPS: Step[] = [
  {
    Icon: FileSearch,
    title: 'Parse',
    body: 'We read the skill and pull out every link and download-and-run command (curl | bash).',
  },
  {
    Icon: GitBranch,
    title: 'Trace',
    body: 'Each link is followed hop by hop behind an SSRF guard that refuses private, loopback, and cloud-metadata hosts on every hop, so a friendly URL that redirects to a payload is exposed and the scanner can never be pointed at your own network.',
  },
  {
    Icon: Ruler,
    title: 'Rules',
    body: 'Deterministic structural checks: raw-IP hosts, look-alike and punycode domains, URL shorteners, cross-origin hops, and embedded execution. Instant and certain.',
  },
  {
    Icon: Database,
    title: 'Indicators',
    body: 'Every final destination is matched against a known-bad denylist. An O(1) lookup, with no fetching of the hostile page itself.',
  },
  {
    Icon: ScanLine,
    title: 'Check',
    body: 'Only when the earlier layers are ambiguous, a small model reads the text for prompt injection. Reserved for Pro, and tighten-only: it can sharpen a verdict but never overturn a block.',
  },
  {
    Icon: Lock,
    title: 'Seal',
    body: 'Every step is hashed into a SHA-256 proof chain you can re-verify in your own browser: CHAIN_OK, or CHAIN_BROKEN at the exact tampered link.',
  },
]

/** The two invariants that hold across every scan, shown beneath the cards. */
interface Invariant {
  Icon: LucideIcon
  title: string
  body: string
}

const INVARIANTS: Invariant[] = [
  {
    Icon: ShieldCheck,
    title: 'Fail-closed',
    body: 'Anything we cannot judge safely is blocked, never waved through.',
  },
  {
    Icon: ArrowUpCircle,
    title: 'Tighten-only',
    body: 'The model can only raise severity; it never overturns a deterministic block.',
  },
]

const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

export function HowItWorks() {
  return (
    <section id="how" className="max-w-5xl mx-auto px-6 pt-10 pb-20">
      <motion.div
        {...RISE}
        className="flex flex-col items-center text-center gap-3 mb-10"
      >
        <p className="flex items-center gap-2 text-white/60 text-[11px] font-mono uppercase tracking-[0.22em]">
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          How it works
        </p>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] text-white"
        >
          Six checks. Cheapest first. AI last. One proof.
        </h2>
        <p className="text-white/65 text-sm md:text-[15px] max-w-2xl">
          Every scan runs the same fail-closed pipeline. The deterministic layers
          settle most verdicts on their own; the model runs last, rarely, and can
          only make a verdict stricter, never weaker.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
        {STEPS.map(({ Icon, title, body }, index) => (
          <motion.div
            key={title}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-60px' }}
            transition={{
              duration: 0.5,
              delay: index * 0.06,
              ease: [0.16, 1, 0.3, 1],
            }}
            className="liquid-glass reticle rounded-2xl p-5 flex flex-col gap-3"
          >
            <div className="flex items-center justify-between">
              <Icon className="w-5 h-5 text-allow" />
              <span className="font-mono text-[11px] text-white/35">
                0{index + 1}
              </span>
            </div>
            <div className="text-white text-[15px] font-semibold">{title}</div>
            <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
          </motion.div>
        ))}
      </div>

      {/* The two invariants that hold across every scan. */}
      <motion.div
        {...RISE}
        className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3"
      >
        {INVARIANTS.map(({ Icon, title, body }) => (
          <div
            key={title}
            className="liquid-glass rounded-2xl p-5 flex items-start gap-3"
          >
            <Icon className="w-5 h-5 text-allow shrink-0 mt-0.5" />
            <div className="flex flex-col gap-1">
              <div className="text-white text-[15px] font-semibold">{title}</div>
              <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
            </div>
          </div>
        ))}
      </motion.div>
    </section>
  )
}
