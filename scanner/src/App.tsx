/**
 * The SecureAI Skill Safety Scanner SPA shell: a dark, cinematic surface with a
 * fullscreen background video behind a glass navbar. `useScan` owns the scan
 * lifecycle and `useHashRoute` selects the top-level surface:
 *   - #enterprise        -> the Enterprise page
 *   - scanner, idle/scan -> the scrollable landing (hero + how-it-works + examples)
 *   - scanner, done      -> the full result report (scrolls; video dimmed behind)
 *   - scanner, error     -> a fail-closed error card
 * The navbar mark calls `reset`, so it always returns to a fresh scanner
 * landing.
 */

import { useEffect, useRef, type ReactNode } from 'react'
import { motion } from 'motion/react'
import { ArrowLeft, ShieldAlert, ShieldCheck } from 'lucide-react'
import { BackgroundVideo } from './components/BackgroundVideo'
import { Navbar } from './components/Navbar'
import { Hero } from './components/Hero'
import { HowItWorks } from './components/HowItWorks'
import { GuardInstall } from './components/GuardInstall'
import { Gallery } from './components/Gallery'
import { ResultView } from './components/ResultView'
import { Enterprise } from './components/Enterprise'
import { Pricing } from './components/Pricing'
import { Auth } from './components/Auth'
import { Dashboard } from './components/Dashboard'
import { AdminDashboard } from './components/AdminDashboard'
import { useScan } from './scan/useScan'
import { useHashRoute } from './hooks/useHashRoute'
import { useAuth } from './hooks/useAuth'
import { guardRedirect } from './lib/routeGuard'
import { REPO_URL } from './config'
import type { ScanState } from './scan/scanMachine'

const SHELL =
  'relative bg-black w-screen min-h-screen flex flex-col selection:bg-white selection:text-black'

/** The site footer: the product mark (SecureAI) + links. */
function Footer(): ReactNode {
  return (
    <footer className="relative z-10 bg-black border-t border-white/[0.06]">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col sm:flex-row items-center justify-between gap-4 text-[13px]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-white/70" />
          <span className="text-white/80 font-semibold">SecureAI</span>
        </div>
        <div className="flex items-center gap-6 font-mono text-white/45">
          <a href="#" className="hover:text-white transition-colors">
            Scanner
          </a>
          <a href="#enterprise" className="hover:text-white transition-colors">
            Enterprise
          </a>
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="hover:text-white transition-colors"
          >
            GitHub
          </a>
        </div>
      </div>
    </footer>
  )
}

/** The finished report: a back action over the full evidence + proof view. */
function ResultSurface({
  state,
  onReset,
}: {
  state: Extract<ScanState, { phase: 'done' }>
  onReset: () => void
}): ReactNode {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="relative z-10 w-full max-w-5xl mx-auto px-6 pb-20"
    >
      <button
        type="button"
        onClick={onReset}
        className="glass-pill inline-flex items-center gap-2 px-4 py-2 my-6 text-sm font-medium text-white/80 hover:text-white transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4" />
        Scan another
      </button>
      <ResultView result={state.result} />
    </motion.div>
  )
}

/** The fail-closed error surface: a tasteful card naming the failure. */
function ErrorSurface({
  message,
  onRetry,
}: {
  message: string
  onRetry: () => void
}): ReactNode {
  return (
    <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-10">
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        className="liquid-glass glow-block rounded-3xl max-w-md w-full p-8 text-center"
      >
        <ShieldAlert className="w-8 h-8 text-block mx-auto mb-4" />
        <h2 className="text-white text-xl font-semibold mb-2">Scan failed</h2>
        <p className="text-block/90 font-mono text-[13px] break-words mb-6">
          {message}
        </p>
        <button
          type="button"
          onClick={onRetry}
          className="rounded-full bg-white text-black px-6 py-2.5 text-[13px] font-semibold hover:bg-white/90 transition-colors cursor-pointer"
        >
          Try another scan
        </button>
      </motion.div>
    </section>
  )
}

function App(): ReactNode {
  const { route, target } = useHashRoute()
  const controller = useScan()
  const auth = useAuth()
  const { state } = controller
  const previousRouteRef = useRef(route)

  // The dashboard and admin surfaces are gated. The redirect decision is a pure
  // function (testable in isolation): an anonymous visitor is bounced to login,
  // and a non-admin reaching #admin is bounced to their own dashboard. The
  // redirect runs in an effect (not during render) so it never fires mid-commit.
  useEffect(() => {
    const target = guardRedirect(route, auth.status, auth.isAdmin)
    if (target !== null) {
      window.location.assign(target)
    }
  }, [route, auth.status, auth.isAdmin])

  useEffect(() => {
    const sameRoute = previousRouteRef.current === route
    previousRouteRef.current = route
    const frame = window.requestAnimationFrame(() => {
      if (target === 'how' || target === 'guard') {
        // Jump straight to the section. A smooth scroll here can stall before it
        // arrives — interrupted by a route remount, or simply giving up on the
        // landing — and strand the page with the hero video still showing above
        // the section. Landing instantly puts it flush under the navbar (the
        // `:target` scroll-margin clears the navbar) with no gap.
        document
          .getElementById(target)
          ?.scrollIntoView({ block: 'start', behavior: 'instant' })
        return
      }
      window.scrollTo({ top: 0, left: 0, behavior: sameRoute ? 'auto' : 'instant' })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [route, target])

  // Enterprise surface.
  if (route === 'enterprise') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <Navbar onHome={controller.reset} auth={auth} />
        <Enterprise />
        <Footer />
      </main>
    )
  }

  // Pricing surface.
  if (route === 'pricing') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <Navbar onHome={controller.reset} auth={auth} />
        <Pricing auth={auth} />
        <Footer />
      </main>
    )
  }

  // Auth surfaces (login / register): a centered glass card over the video.
  if (route === 'login' || route === 'register') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/70" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        <Auth mode={route} auth={auth} />
        <Footer />
      </main>
    )
  }

  // Dashboard surface. While the session is resolving, hold a quiet loading
  // line; an anonymous visitor is redirected by the effect above.
  if (route === 'dashboard') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/80" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        {auth.status === 'authenticated' && auth.user !== null ? (
          <Dashboard user={auth.user} auth={auth} />
        ) : (
          <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-20">
            <p className="text-white/45 font-mono text-sm">Loading your dashboard…</p>
          </section>
        )}
        <Footer />
      </main>
    )
  }

  // Admin surface. Guarded by the effect above: a non-admin (or anonymous)
  // visitor is redirected away, so the analytics only render for an admin.
  if (route === 'admin') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/80" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        {auth.status === 'authenticated' && auth.isAdmin ? (
          <AdminDashboard canManageRoles={auth.isOwner} viewerEmail={auth.user?.email ?? null} />
        ) : (
          <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-20">
            <p className="text-white/45 font-mono text-sm">Loading admin analytics…</p>
          </section>
        )}
        <Footer />
      </main>
    )
  }

  // Finished report.
  if (state.phase === 'done') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/80" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        <ResultSurface state={state} onReset={controller.reset} />
        <Footer />
      </main>
    )
  }

  // Error.
  if (state.phase === 'error') {
    return (
      <main id="top" className="relative bg-black w-screen h-screen flex flex-col overflow-hidden selection:bg-white selection:text-black">
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/70" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        <ErrorSurface message={state.message} onRetry={controller.reset} />
      </main>
    )
  }

  // Landing (idle / scanning): the cinematic hero over the video, then the
  // solid-black content sections that scroll up over it.
  return (
    <main id="top" className={SHELL}>
      <BackgroundVideo />
      <Navbar onHome={controller.reset} auth={auth} />
      <Hero state={state} onScan={controller.scan} />
      <div className="relative z-10 bg-black">
        <HowItWorks />
        <GuardInstall />
        <section className="max-w-5xl mx-auto px-6 pb-20">
          <Gallery onPick={controller.loadResult} />
        </section>
      </div>
      <Footer />
    </main>
  )
}

export default App
