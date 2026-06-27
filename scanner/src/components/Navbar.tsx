/**
 * Glassmorphism navbar for the dark hero. Animates in from the top, carries the
 * SecureSG mark, and surfaces a live status pill plus a link to the source.
 */

import { motion } from 'motion/react'
import { ShieldCheck } from 'lucide-react'
import { REPO_URL } from '../config'

export function Navbar() {
  return (
    <motion.nav
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="relative z-20 px-6 py-6 w-full"
    >
      <div className="liquid-glass rounded-full px-6 py-3 flex items-center justify-between max-w-5xl mx-auto">
        <div className="flex items-center gap-8">
          <a href="#top" className="flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-white" />
            <span className="text-white font-semibold text-lg tracking-tight">
              SecureSG
            </span>
          </a>
          <div className="hidden md:flex items-center gap-8 text-white/80 text-sm font-medium">
            <a
              href="#scan"
              className="hover:text-white transition-colors duration-300"
            >
              Scanner
            </a>
            <a
              href="#how"
              className="hover:text-white transition-colors duration-300"
            >
              How it works
            </a>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="hover:text-white transition-colors duration-300"
            >
              GitHub
            </a>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="hidden sm:flex items-center gap-2 text-white/65 text-[11px] font-mono uppercase tracking-[0.18em]">
            <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
            Live
          </span>
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="liquid-glass rounded-full px-6 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity cursor-pointer"
          >
            View source
          </a>
        </div>
      </div>
    </motion.nav>
  )
}
