/**
 * The "how easy SecureAI is" explainer on the scanner landing (after How it
 * works): a three-step flow selling that protecting an agent is a sign-up and a
 * single line of setup, after which every risky tool call is screened and
 * blocked before it runs — fail-closed. Purely presentational, no state.
 *
 * The actual Guard download + key-embedded installer lives in the member
 * dashboard ("Set up the Guard"), reachable from step one's call to action;
 * this section sells the ease, it does not ship the artifact.
 */

import { motion } from 'motion/react'
import { KeyRound, ShieldCheck, Terminal } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

interface Step {
  Icon: LucideIcon
  title: string
  body: string
}

const STEPS: Step[] = [
  {
    Icon: KeyRound,
    title: 'Sign up & grab your key',
    body: 'Create an account and your API key is waiting in the dashboard. No card, no setup call.',
  },
  {
    Icon: Terminal,
    title: 'Drop in the Guard',
    body: 'One line wires the Guard into your agent as a PreToolUse hook. Re-run it anytime — it never duplicates.',
  },
  {
    Icon: ShieldCheck,
    title: 'Risky calls get blocked',
    body: 'Every tool call is screened before it runs. If the Guard cannot clear it, it is denied — fail-closed by default.',
  },
]

const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

export function EaseOfUse() {
  return (
    <section id="ease" className="max-w-5xl mx-auto px-6 py-20">
      <motion.div
        {...RISE}
        className="flex flex-col items-center text-center gap-3 mb-10"
      >
        <p className="flex items-center gap-2 text-white/60 text-[11px] font-mono uppercase tracking-[0.22em]">
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          Dead simple
        </p>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] text-white"
        >
          Protected in one line
        </h2>
        <p className="text-white/65 text-sm md:text-[15px] max-w-2xl">
          You should not need a security team to ship safe agents. Sign up, paste
          one line, and the Guard screens every tool call from then on — no
          rewrite, no glue code.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
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
            className="liquid-glass reticle rounded-2xl p-6 flex flex-col gap-3"
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

      <motion.p
        {...RISE}
        className="mt-8 text-center text-white/45 text-[13px]"
      >
        Grab the Guard and your key-embedded install command from your{' '}
        <a
          href="#dashboard"
          className="text-allow hover:text-white transition-colors underline underline-offset-4 decoration-allow/40"
        >
          dashboard
        </a>
        .
      </motion.p>
    </section>
  )
}
