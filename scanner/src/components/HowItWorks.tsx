/**
 * The "How it works" section on the scanner landing (anchor `#how`): the five
 * fail-closed passes every scan runs, each shown as a glass card. Purely
 * presentational, no state.
 */

import { motion } from 'motion/react'
import { FileSearch, GitBranch, Radar, ScanLine, Lock } from 'lucide-react'
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
    body: 'We read the SKILL.md and pull out every link and download-execute command.',
  },
  {
    Icon: GitBranch,
    title: 'Trace',
    body: 'Each link is followed hop by hop, so a friendly URL that redirects to a payload is exposed.',
  },
  {
    Icon: Radar,
    title: 'Score',
    body: 'Exa checks what the live web says about every final destination, right now, not a stale blocklist.',
  },
  {
    Icon: ScanLine,
    title: 'Judge',
    body: 'OpenAI reads the skill and resolved pages for prompt injection. It can only tighten the verdict, never weaken it.',
  },
  {
    Icon: Lock,
    title: 'Seal',
    body: 'Every step is sealed into a SHA-256 proof chain you can re-verify in your own browser.',
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
    <section id="how" className="max-w-5xl mx-auto px-6 py-20">
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
          Five passes. One proof.
        </h2>
        <p className="text-white/65 text-sm md:text-[15px] max-w-2xl">
          Every scan runs the same fail-closed pipeline. Each pass can only make
          the verdict stricter, and the whole result is sealed so anyone can
          check it.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
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
    </section>
  )
}
