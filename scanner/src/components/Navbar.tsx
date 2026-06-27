/**
 * Glassmorphism navbar for the dark hero. Animates in from the top, carries the
 * Bastion mark, and routes between the scanner and the Enterprise page with hash
 * links. The mark calls `onHome` so it always returns to a fresh scanner landing.
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
  const { route, target } = useHashRoute()
  const linkClass = (active: boolean): string =>
    active
      ? 'text-white transition-colors duration-300'
      : 'text-white/70 hover:text-white transition-colors duration-300'
  const handleScannerSectionClick = (): void => {
    onHome?.()
  }

  return (
    <motion.nav
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="sticky top-0 z-50 px-6 py-6 w-full"
    >
      <div className="liquid-glass navbar-glass rounded-full px-6 py-3 max-w-5xl mx-auto">
        <div className="relative z-10 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <a href="#" onClick={onHome} className="flex items-center gap-2">
              <ShieldCheck className="w-6 h-6 text-white" />
              <span className="text-white font-semibold text-lg tracking-tight">
                Bastion
              </span>
            </a>
            <div className="hidden md:flex items-center gap-7 text-sm font-medium">
              <a
                href="#how"
                onClick={handleScannerSectionClick}
                className={linkClass(route === 'scanner' && target === 'how')}
              >
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
        </div>
      </div>
    </motion.nav>
  )
}
