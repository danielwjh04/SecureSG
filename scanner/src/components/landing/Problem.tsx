/**
 * The landing page's "problem" section: why an AI coding agent is exposed. Three
 * glass cards framing the threat (skills inherit the agent's power, one poisoned
 * input is enough, it happens before you can review), tinted with the block/red
 * verdict color so the danger reads at a glance.
 */

import { motion } from 'motion/react'
import { FileWarning, KeyRound, Zap } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

/** Shared entrance transition for landing sections. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

interface Point {
  Icon: LucideIcon
  title: string
  body: string
}

const POINTS: Point[] = [
  {
    Icon: KeyRound,
    title: "Skills and tools inherit your agent's power",
    body: 'A skill, an MCP tool, or a pasted instruction runs with the same access your agent has to your files, secrets, and shell.',
  },
  {
    Icon: FileWarning,
    title: 'One poisoned input is enough',
    body: 'A hidden instruction in a SKILL.md, a web page, or a pull request can hijack the agent, run curl | bash, or quietly exfiltrate your keys.',
  },
  {
    Icon: Zap,
    title: 'It happens before you can review',
    body: 'The agent acts in milliseconds. By the time you notice, the secret is already gone or the command has already run.',
  },
]

export function Problem() {
  return (
    <section className="max-w-5xl mx-auto px-6 py-20">
      <motion.div {...RISE} className="flex flex-col gap-3 mb-10">
        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-block/80">
          The problem
        </span>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] leading-[1.1] text-white"
        >
          Your agent trusts everything it's handed.
        </h2>
        <p className="text-white/60 text-[15px] leading-relaxed max-w-2xl">
          Coding agents act on skills, tools, and links the moment they see them.
          That trust is the attack surface.
        </p>
      </motion.div>

      <motion.div {...RISE} className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {POINTS.map(({ Icon, title, body }) => (
          <div key={title} className="liquid-glass rounded-2xl p-6 flex flex-col gap-3">
            <Icon className="w-6 h-6 text-block" />
            <h3 className="text-white text-[15px] font-semibold leading-snug">{title}</h3>
            <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
          </div>
        ))}
      </motion.div>
    </section>
  )
}
