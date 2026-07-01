/**
 * The landing page's "solution" section: the antivirus + firewall framing. Two
 * glass cards, Scanner (check before you trust) and Guard (block inline,
 * fail-closed), tinted with the allow/green verdict color.
 */

import { motion } from 'motion/react'
import { ScanLine, ShieldCheck } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

/** Shared entrance transition for landing sections. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

interface Mode {
  Icon: LucideIcon
  name: string
  tagline: string
  body: string
}

const MODES: Mode[] = [
  {
    Icon: ScanLine,
    name: 'Scanner',
    tagline: 'Check before you trust',
    body: 'Submit a skill, tool, or link and get an ALLOW / REVIEW / BLOCK verdict in milliseconds, with the findings that drove it and a proof you can re-verify yourself.',
  },
  {
    Icon: ShieldCheck,
    name: 'Guard',
    tagline: 'Block inline, fail-closed',
    body: 'Drop one config file into your agent and every risky action is screened before it runs. If the check cannot run, the action is denied, never waved through.',
  },
]

export function Solution() {
  return (
    <section className="max-w-5xl mx-auto px-6 py-20">
      <motion.div {...RISE} className="flex flex-col gap-3 mb-10">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-allow">
          The solution
        </span>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] leading-[1.1] text-white"
        >
          An antivirus and a firewall for AI agents.
        </h2>
        <p className="text-white/60 text-[15px] leading-relaxed max-w-2xl">
          SecureAI inspects everything your agent is about to trust and blocks
          what's dangerous, in two ways.
        </p>
      </motion.div>

      <motion.div {...RISE} className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {MODES.map(({ Icon, name, tagline, body }) => (
          <div key={name} className="liquid-glass rounded-2xl p-6 flex flex-col gap-3">
            <div className="flex items-center gap-2.5">
              <Icon className="w-6 h-6 text-allow" />
              <div className="flex flex-col">
                <span className="text-white text-[15px] font-semibold">{name}</span>
                <span className="text-white/45 text-[11px] font-mono uppercase tracking-[0.14em]">
                  {tagline}
                </span>
              </div>
            </div>
            <p className="text-white/60 text-[13px] leading-relaxed">{body}</p>
          </div>
        ))}
      </motion.div>
    </section>
  )
}
