/**
 * The SecureAI Skill Safety Scanner SPA shell: a dark, cinematic surface with a
 * fullscreen background video behind a glass navbar. `useScan` owns the scan
 * lifecycle and `useHashRoute` selects the top-level surface:
 *   - #pricing           -> the pricing page
 *   - scanner, idle      -> the landing: hero + problem / incidents / solution /
 *                           example scan / How it works (#how, #verify anchor here)
 *   - scanner, scanning  -> the hero with the live pipeline stepper
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
import { EaseOfUse } from './components/EaseOfUse'
import { VerifyIt } from './components/VerifyIt'
import { Gallery } from './components/Gallery'
import { Problem } from './components/landing/Problem'
import { Incidents } from './components/landing/Incidents'
import { Solution } from './components/landing/Solution'
import { ResultView } from './components/ResultView'
import { Pricing } from './components/Pricing'
import { Auth } from './components/Auth'
import { Dashboard } from './components/Dashboard'
import { AdminDashboard } from './components/AdminDashboard'
import { Activity } from './components/Activity'
import { Integrations } from './components/Integrations'
import { Settings } from './components/Settings'
import { useScan } from './scan/useScan'
import { useHashRoute } from './hooks/useHashRoute'
import { useAuth } from './hooks/useAuth'
import { guardRedirect } from './lib/routeGuard'
import { REPO_URL } from './config'
import type { ScanState } from './scan/scanMachine'
import type { ScanResult } from './api/types'

const SHELL =
  'relative bg-black w-screen min-h-screen flex flex-col selection:bg-white selection:text-black'

/** The GitHub mark (lucide 1.x dropped its brand icons), tinted via `currentColor`. */
function GithubMark({ className }: { className?: string }): ReactNode {
  return (
    <svg viewBox="0 0 16 16" className={className} fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.03 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  )
}

/** The site footer: the product mark (SecureAI) + links. */
function Footer(): ReactNode {
  return (
    <footer className="relative z-10 bg-black/40 border-t border-white/[0.06]">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col sm:flex-row items-center justify-between gap-4 text-[13px]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-white/70" />
          <span className="text-white/80 font-semibold">SecureAI</span>
        </div>
        <div className="flex items-center gap-6 font-mono text-white/45">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 hover:text-white transition-colors"
          >
            <GithubMark className="w-3.5 h-3.5" />
            GitHub
          </a>
          <a href="#pricing" className="hover:text-white transition-colors">
            Pricing
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

function LoadingSurface({ label }: { label: string }): ReactNode {
  return (
    <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-20">
      <p className="text-white/45 font-mono text-sm">{label}</p>
    </section>
  )
}

function App(): ReactNode {
  const route = useHashRoute()
  const controller = useScan()
  const auth = useAuth()
  const { state } = controller
  const previousRouteRef = useRef(route)

  // Picking an example from the landing gallery loads it as a finished result,
  // then clears the hash so the scanner route's result view renders
  // (state.phase === 'done') instead of the landing sections.
  const handleGalleryPick = (result: ScanResult): void => {
    controller.loadResult(result)
    window.location.hash = ''
  }

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

  // Scroll behavior on navigation: if the hash names an on-page anchor that
  // exists (e.g. #how / #verify, folded onto the landing), scroll it into view;
  // otherwise land at the top. A same-route navigation animates; a route change
  // jumps.
  useEffect(() => {
    const sameRoute = previousRouteRef.current === route
    previousRouteRef.current = route
    const anchorId = window.location.hash.replace(/^#/, '')
    const frame = window.requestAnimationFrame(() => {
      const anchor = anchorId.length > 0 ? document.getElementById(anchorId) : null
      if (anchor !== null) {
        anchor.scrollIntoView({ behavior: sameRoute ? 'smooth' : 'auto', block: 'start' })
      } else {
        window.scrollTo({ top: 0, left: 0, behavior: sameRoute ? 'auto' : 'instant' })
      }
    })
    return () => window.cancelAnimationFrame(frame)
  }, [route])

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
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
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
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        {auth.status === 'authenticated' && auth.user !== null ? (
          <Dashboard user={auth.user} />
        ) : (
          <section className="relative z-10 flex-1 flex items-center justify-center px-6 py-20">
            <p className="text-white/45 font-mono text-sm">Loading your dashboard…</p>
          </section>
        )}
        <Footer />
      </main>
    )
  }

  if (route === 'activity') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        {auth.status === 'authenticated' && auth.user !== null ? (
          <Activity />
        ) : (
          <LoadingSurface label="Loading activity..." />
        )}
        <Footer />
      </main>
    )
  }

  if (route === 'integrations') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        {auth.status === 'authenticated' && auth.user !== null ? (
          <Integrations />
        ) : (
          <LoadingSurface label="Loading integrations..." />
        )}
        <Footer />
      </main>
    )
  }

  if (route === 'settings') {
    return (
      <main id="top" className={SHELL}>
        <BackgroundVideo />
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        {auth.status === 'authenticated' && auth.user !== null ? (
          <Settings user={auth.user} auth={auth} />
        ) : (
          <LoadingSurface label="Loading settings..." />
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
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
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
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
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
        <div className="fixed inset-0 bg-black/55" aria-hidden="true" />
        <Navbar onHome={controller.reset} auth={auth} />
        <ErrorSurface message={state.message} onRetry={controller.reset} />
      </main>
    )
  }

  // Landing (idle / scanning): the cinematic hero over the video, then, when idle,
  // the marketing narrative (problem -> incidents -> solution -> example scan) and
  // the folded How it works sections (#how / #verify anchor here). During a scan
  // only the hero shows, so the pipeline stepper stays the focus.
  return (
    <main id="top" className={SHELL}>
      <BackgroundVideo />
      <Navbar onHome={controller.reset} auth={auth} />
      <Hero state={state} onScan={controller.scan} />
      {state.phase === 'idle' && (
        <div className="relative z-10 bg-black">
          <Problem />
          <Incidents />
          <Solution />
          <section className="max-w-5xl mx-auto px-6 pt-4 pb-8">
            <Gallery onPick={handleGalleryPick} />
          </section>
          <HowItWorks />
          <EaseOfUse />
          <VerifyIt />
        </div>
      )}
      <Footer />
    </main>
  )
}

export default App
