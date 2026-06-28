/**
 * The "Guard your agent" section on the scanner landing (anchor `#guard`): the
 * runtime side of SecureAI. Where the scanner audits a skill before you install
 * it, the Guard sits inline as a Claude Code PreToolUse hook and screens every
 * tool call before it runs — fail-closed, so an unreachable guard blocks rather
 * than waves the call through.
 *
 * Two ways in: download the hook script directly, or run the one-line installer
 * that wires it into Claude Code for you. The installer command sits in a copy
 * box reusing the dashboard's copy-confirm pattern. Purely presentational beyond
 * the local copy state.
 */

import { useEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import { Check, Copy, Download, ShieldCheck, Terminal } from 'lucide-react'
import { GUARD_DOWNLOAD_PATH, GUARD_INSTALL_COMMAND } from '../config'

const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

export function GuardInstall() {
  return (
    <section id="guard" className="max-w-5xl mx-auto px-6 py-20">
      <motion.div
        {...RISE}
        className="flex flex-col items-center text-center gap-3 mb-10"
      >
        <p className="flex items-center gap-2 text-white/60 text-[11px] font-mono uppercase tracking-[0.22em]">
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          The Guard
        </p>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-3xl md:text-[44px] font-medium tracking-[-0.01em] text-white"
        >
          Guard your agent
        </h2>
        <p className="text-white/65 text-sm md:text-[15px] max-w-2xl">
          Block malicious tools before they run. The Guard hooks into Claude Code
          and screens every tool call inline — fail-closed, so a call is denied
          unless it is verified safe.
        </p>
      </motion.div>

      <motion.div
        {...RISE}
        className="liquid-glass reticle rounded-2xl p-6 sm:p-8 flex flex-col gap-6 max-w-3xl mx-auto"
      >
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-6 h-6 text-allow shrink-0" />
            <div className="flex flex-col">
              <span className="text-white text-[15px] font-semibold">
                SecureAI Guard
              </span>
              <span className="text-white/55 text-[13px]">
                A zero-dependency PreToolUse hook for Claude Code.
              </span>
            </div>
          </div>
          <a
            href={GUARD_DOWNLOAD_PATH}
            download
            className="inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer shrink-0"
          >
            <Download className="w-4 h-4" />
            Download the Guard
          </a>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2 text-white/55 text-[11px] font-mono uppercase tracking-[0.14em]">
            <Terminal className="w-3.5 h-3.5" />
            Or install in one line
          </div>
          <InstallCommand command={GUARD_INSTALL_COMMAND} />
          <p className="text-white/45 text-[12px] leading-relaxed">
            Downloads the guard, wires the PreToolUse hook into Claude Code, and
            keeps your API key local. Re-run anytime — it never duplicates the
            hook.
          </p>
        </div>
      </motion.div>
    </section>
  )
}

/** How long the copy button stays in its confirmed "Copied" state, in ms. */
const COPIED_RESET_MS = 1500

/**
 * The installer command in a frosted code box with a copy-to-clipboard button
 * that flips to a confirmation check briefly after a successful copy. A denied
 * clipboard leaves the command visible to copy by hand rather than throwing.
 */
function InstallCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current)
    }
  }, [])

  const handleCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(command)
    } catch {
      // Clipboard unavailable (insecure context / denied): the command is still
      // visible to copy manually. This is a presentation surface, not a security
      // path, so surfacing nothing is correct.
      return
    }
    setCopied(true)
    if (timerRef.current !== null) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), COPIED_RESET_MS)
  }

  return (
    <div className="flex items-stretch gap-2">
      <code className="flex-1 min-w-0 overflow-x-auto rounded-xl bg-white/[0.04] border border-white/10 px-3.5 py-2.5 font-mono text-[12px] sm:text-[13px] text-white/80 whitespace-nowrap">
        <span className="text-allow select-none">$ </span>
        {command}
      </code>
      <button
        type="button"
        onClick={handleCopy}
        aria-label="Copy install command"
        className="glass-pill inline-flex items-center gap-1.5 px-3.5 py-2.5 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer shrink-0"
      >
        {copied ? (
          <>
            <Check className="w-3.5 h-3.5 text-allow" />
            <span className="text-allow hidden sm:inline">Copied</span>
          </>
        ) : (
          <>
            <Copy className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Copy</span>
          </>
        )}
      </button>
    </div>
  )
}
