/**
 * Glassmorphism navbar for the dark hero. Animates in from the top, carries the
 * SecureAI mark, and routes between the scanner, Pricing, and the Enterprise page
 * with hash links. The mark calls `onHome` so it always returns to a fresh
 * scanner landing. The right side is session-aware: a "Log in" link when logged
 * out, a "Dashboard" link once a session cookie is present.
 */

import { motion } from 'motion/react'
import { LayoutDashboard, ShieldCheck } from 'lucide-react'
import { REPO_URL } from '../config'
import { useHashRoute } from '../hooks/useHashRoute'
import type { AuthState } from '../hooks/useAuth'

interface NavbarProps {
  /** Return to the scanner landing, clearing any in-progress or finished scan. */
  onHome?: () => void
  /** App-level session state; drives the right-side Log in / Dashboard link. */
  auth: AuthState
}

export function Navbar({ onHome, auth }: NavbarProps) {
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
                SecureAI
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
              <a href="#pricing" className={linkClass(route === 'pricing')}>
                Pricing
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

          <div className="flex items-center text-sm font-medium">
            {auth.status === 'authenticated' ? (
              <a
                href="#dashboard"
                className={`glass-pill inline-flex items-center gap-1.5 px-4 py-1.5 ${
                  route === 'dashboard' ? 'text-white' : 'text-white/70 hover:text-white'
                } transition-colors`}
              >
                <LayoutDashboard className="w-4 h-4" />
                Dashboard
              </a>
            ) : auth.status === 'anonymous' ? (
              <a
                href="#login"
                className={`glass-pill px-4 py-1.5 ${
                  route === 'login' || route === 'register'
                    ? 'text-white'
                    : 'text-white/70 hover:text-white'
                } transition-colors`}
              >
                Log in
              </a>
            ) : null}
          </div>
        </div>
      </div>
    </motion.nav>
  )
}
