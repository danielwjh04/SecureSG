/**
 * Glassmorphism navbar for the dark hero. Animates in from the top, carries the
 * Bastion mark, surfaces a live status pill and a link to the source, and routes
 * between the scanner and the Enterprise page with hash links. The mark and the
 * Scanner link call `onHome` so they always return to a fresh scanner landing.
 */

import { motion } from 'motion/react'
import { ShieldCheck } from 'lucide-react'
import { REPO_URL } from '../config'
import { useHashRoute } from '../hooks/useHashRoute'

interface NavbarProps {
  /** Return to the scanner landing, clearing any in-progress or finished scan. */
  onHome?: () => void
}

export function Navbar({ onHome }: NavbarProps) {
  const route = useHashRoute()
  const linkClass = (active: boolean): string =>
    active
      ? 'text-white transition-colors duration-300'
      : 'text-white/70 hover:text-white transition-colors duration-300'

  return (
    <motion.nav
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="relative z-20 px-6 py-6 w-full"
    >
      <div className="liquid-glass rounded-full px-6 py-3 flex items-center justify-between max-w-5xl mx-auto">
        <div className="flex items-center gap-8">
          <a href="#" onClick={onHome} className="flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-white" />
            <span className="text-white font-semibold text-lg tracking-tight">
              Bastion
            </span>
          </a>
          <div className="hidden md:flex items-center gap-7 text-sm font-medium">
            <a href="#" onClick={onHome} className={linkClass(route === 'scanner')}>
              Scanner
            </a>
            <a href="#how" className={linkClass(false)}>
              How it works
            </a>
            <a href="#enterprise" className={linkClass(route === 'enterprise')}>
              Enterprise
            </a>
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className={linkClass(false)}
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
