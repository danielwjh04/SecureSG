/**
 * The hero: the dark cinematic landing surface. A category tagline, a threat-led
 * Instrument Serif headline, a one-line explanation of what SecureAI does, and the
 * scan control. While a scan runs, the control swaps to the live pipeline stepper
 * in place (same focal point), then the app transitions to the result. The
 * marketing narrative and the How it works sections scroll below this hero.
 */

import { AnimatePresence, motion } from 'motion/react'
import { GitBranch, Database, ScanLine, Lock } from 'lucide-react'
import { SkillInput } from './SkillInput'
import { ScanProgress } from './ScanProgress'
import type { ScanRequest } from '../api/types'
import type { ScanState } from '../scan/scanMachine'

interface HeroProps {
  state: Extract<ScanState, { phase: 'idle' | 'scanning' }>
  onScan: (request: ScanRequest) => void
}

const TRUST = [
  { Icon: GitBranch, label: 'Redirect tracing' },
  { Icon: Database, label: 'Known-bad indicators' },
  { Icon: ScanLine, label: 'Injection check' },
  { Icon: Lock, label: 'SHA-256 proof' },
] as const

export function Hero({ state, onScan }: HeroProps) {
  const scanning = state.phase === 'scanning'

  return (
    <section
      id="scan"
      className="relative z-10 min-h-[90svh] flex flex-col items-center justify-center px-6 pt-4 pb-16"
    >
      <div className="text-center max-w-3xl mx-auto flex flex-col items-center justify-center w-full gap-7">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="flex items-center gap-2 text-white/70 text-[10px] md:text-[11px] font-medium tracking-[0.22em] uppercase font-mono"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          Antivirus and firewall for AI agents
        </motion.p>

        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-5xl md:text-[68px] font-medium tracking-[-0.01em] leading-[1.05] text-white drop-shadow-[0_2px_20px_rgba(0,0,0,0.5)]"
        >
          Stop your AI agent
          <br className="hidden md:block" /> from getting hacked.
        </motion.h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="text-white/75 text-[15px] md:text-base leading-relaxed max-w-xl -mt-1"
        >
          Your agent trusts every skill, tool, and link it's handed. SecureAI scans
          each one, blocks the dangerous ones inline before they run, and seals
          every decision into a proof you can re-verify yourself.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="w-full"
        >
          <AnimatePresence mode="wait">
            {scanning ? (
              <motion.div
                key="progress"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={{ duration: 0.2 }}
                className="liquid-glass scanline rounded-3xl max-w-xl mx-auto p-4"
              >
                <ScanProgress stepIndex={state.stepIndex} labels={state.labels} />
              </motion.div>
            ) : (
              <motion.div
                key="input"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={{ duration: 0.2 }}
              >
                <SkillInput onScan={onScan} busy={false} />
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.8 }}
          className="flex flex-wrap items-center justify-center gap-2"
        >
          {TRUST.map(({ Icon, label }) => (
            <span
              key={label}
              className="glass-pill flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium text-white/60"
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </span>
          ))}
        </motion.div>
      </div>
    </section>
  )
}
