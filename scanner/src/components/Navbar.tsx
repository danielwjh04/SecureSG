/**
 * Glassmorphism navbar for the dark hero. Animates in from the top, carries the
 * SecureAI mark, and routes between public pages or the authenticated Personal
 * app with hash links. The mark calls `onHome` so it always returns to a fresh
 * scanner landing. The right side is session-aware: a "Log in / Sign up" link
 * when logged out, and app links once a session cookie is present.
 *
 * On phones the primary nav links collapse behind a hamburger toggle: tapping it
 * drops a glass menu with the same links, so every destination stays reachable on
 * a ~360px screen without changing the desktop layout (the inline links and the
 * hamburger are mutually exclusive via `md:` breakpoints).
 */

import { useState } from 'react'
import type { MouseEvent } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import {
  Activity,
  BarChart3,
  BookOpen,
  LayoutDashboard,
  Menu,
  PlugZap,
  ShieldCheck,
  X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useHashRoute } from '../hooks/useHashRoute'
import type { Route } from '../hooks/useHashRoute'
import type { AuthState } from '../hooks/useAuth'

interface NavbarProps {
  /** Return to the scanner landing, clearing any in-progress or finished scan. */
  onHome?: () => void
  /** App-level session state; drives the right-side Log in / Dashboard link. */
  auth: AuthState
}

interface NavLink {
  href: string
  label: string
  route: Route
  Icon: LucideIcon
}

const APP_LINKS: readonly NavLink[] = [
  { href: '#how', label: 'How it works', route: 'howItWorks', Icon: BookOpen },
  { href: '#activity', label: 'Activity', route: 'activity', Icon: Activity },
  { href: '#integrations', label: 'Integrations', route: 'integrations', Icon: PlugZap },
]

export function Navbar({ onHome, auth }: NavbarProps) {
  const route = useHashRoute()
  const [menuOpen, setMenuOpen] = useState(false)
  const linkClass = (active: boolean): string =>
    active
      ? 'text-white transition-colors duration-300'
      : 'text-white/70 hover:text-white transition-colors duration-300'
  const handleScannerSectionClick = (): void => {
    onHome?.()
    setMenuOpen(false)
  }
  const closeMenu = (): void => setMenuOpen(false)

  // Clicking a link to the route already on screen leaves the URL hash
  // unchanged, so no `hashchange` fires and the top-of-page scroll effect in
  // App.tsx never runs. Left to the browser's default same-document
  // navigation, a link whose target id exists in the DOM (e.g. `#how`) still
  // triggers a native fragment scroll that ignores the sticky navbar's
  // in-flow height, landing the page part-way down with its heading hidden
  // behind the navbar. Suppressing the default and scrolling to the true top
  // ourselves keeps every revisit clean, matching the "every route lands at
  // the top" rule the rest of routing already follows.
  const handleNavClick =
    (itemRoute: Route) =>
    (event: MouseEvent<HTMLAnchorElement>): void => {
      closeMenu()
      if (route === itemRoute) {
        event.preventDefault()
        window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
      }
    }

  return (
    <motion.nav
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className="sticky top-0 z-50 px-4 sm:px-6 py-6 w-full"
    >
      <div className="liquid-glass navbar-glass rounded-3xl md:rounded-full px-4 sm:px-6 py-3 max-w-5xl mx-auto">
        <div className="relative z-10 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <a href="#" onClick={handleScannerSectionClick} className="flex items-center gap-2">
              <ShieldCheck className="w-6 h-6 text-white" />
              <span className="text-white font-semibold text-lg tracking-tight">
                SecureAI
              </span>
            </a>
            <div className="hidden md:flex items-center gap-5 text-sm font-medium">
              {auth.status === 'authenticated' ? (
                APP_LINKS.map(({ href, label, route: itemRoute, Icon }) => (
                  <a
                    key={href}
                    href={href}
                    onClick={handleNavClick(itemRoute)}
                    className={`inline-flex items-center gap-1.5 whitespace-nowrap ${linkClass(route === itemRoute)}`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {label}
                  </a>
                ))
              ) : (
                <>
                  <a
                    href="#how"
                    onClick={handleNavClick('howItWorks')}
                    className={`whitespace-nowrap ${linkClass(route === 'howItWorks')}`}
                  >
                    How it works
                  </a>
                  <a
                    href="#pricing"
                    onClick={handleNavClick('pricing')}
                    className={linkClass(route === 'pricing')}
                  >
                    Pricing
                  </a>
                </>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 text-sm font-medium">
            {auth.status === 'authenticated' ? (
              <>
                {auth.isAdmin && (
                  <a
                    href="#admin"
                    onClick={handleNavClick('admin')}
                    className={`glass-pill inline-flex items-center gap-1.5 px-3 sm:px-4 py-1.5 ${
                      route === 'admin' ? 'text-white' : 'text-white/70 hover:text-white'
                    } transition-colors`}
                  >
                    <BarChart3 className="w-4 h-4" />
                    <span className="hidden sm:inline">Admin</span>
                  </a>
                )}
                <a
                  href="#dashboard"
                  onClick={handleNavClick('dashboard')}
                  className={`glass-pill inline-flex items-center gap-1.5 px-3 sm:px-4 py-1.5 ${
                    route === 'dashboard' ? 'text-white' : 'text-white/70 hover:text-white'
                  } transition-colors`}
                >
                  <LayoutDashboard className="w-4 h-4" />
                  <span className="hidden sm:inline">Dashboard</span>
                </a>
              </>
            ) : auth.status === 'anonymous' ? (
              <a
                href="#login"
                className={`glass-pill whitespace-nowrap px-4 py-1.5 ${
                  route === 'login' || route === 'register'
                    ? 'text-white'
                    : 'text-white/70 hover:text-white'
                } transition-colors`}
              >
                Log in / Sign up
              </a>
            ) : null}

            {/* Mobile menu toggle: hidden once the inline links appear at md. */}
            <button
              type="button"
              onClick={() => setMenuOpen((open) => !open)}
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={menuOpen}
              className="glass-pill md:hidden inline-flex items-center justify-center w-10 h-10 text-white/70 hover:text-white transition-colors cursor-pointer"
            >
              {menuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile dropdown: the primary links, reachable only below md. */}
        <AnimatePresence>
          {menuOpen && (
            <motion.div
              key="mobile-menu"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="md:hidden overflow-hidden"
            >
              <div className="flex flex-col gap-1 pt-3 mt-3 border-t border-white/10 text-sm font-medium">
                {auth.status === 'authenticated' ? (
                  APP_LINKS.map(({ href, label, route: itemRoute, Icon }) => (
                    <a
                      key={href}
                      href={href}
                      onClick={handleNavClick(itemRoute)}
                      className="px-2 py-2.5 rounded-xl hover:bg-white/5 text-white/80 hover:text-white transition-colors inline-flex items-center gap-2"
                    >
                      <Icon className="w-4 h-4" />
                      {label}
                    </a>
                  ))
                ) : (
                  <>
                    <a
                      href="#how"
                      onClick={handleNavClick('howItWorks')}
                      className="px-2 py-2.5 rounded-xl hover:bg-white/5 text-white/80 hover:text-white transition-colors"
                    >
                      How it works
                    </a>
                    <a
                      href="#pricing"
                      onClick={handleNavClick('pricing')}
                      className="px-2 py-2.5 rounded-xl hover:bg-white/5 text-white/80 hover:text-white transition-colors"
                    >
                      Pricing
                    </a>
                  </>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.nav>
  )
}
