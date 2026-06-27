/**
 * The Skill Safety Scanner SPA shell: a dark, cinematic single surface with a
 * fullscreen background video behind a glass navbar. `useScan` owns the
 * lifecycle; this component routes the current phase to the matching surface.
 *   - idle / scanning  -> the hero (the scan control swaps to the live stepper)
 *   - done             -> the full result report (scrolls; video dimmed behind)
 *   - error            -> a fail-closed error card
 * Live scans and gallery replays share one path; both land in `done`.
 */

import type { ReactNode } from 'react'
import { motion } from 'motion/react'
import { ArrowLeft, ShieldAlert } from 'lucide-react'
import { BackgroundVideo } from './components/BackgroundVideo'
import { Navbar } from './components/Navbar'
import { Hero } from './components/Hero'
import { ResultView } from './components/ResultView'
import { useScan } from './scan/useScan'
import type { ScanState } from './scan/scanMachine'

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
    <section className="relative z-10 flex-1 flex items-center justify-center px-6">
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
  const controller = useScan()
  const { state } = controller
  const isLanding = state.phase === 'idle' || state.phase === 'scanning'

  return (
    <main
      id="top"
      className={`relative bg-black w-screen flex flex-col selection:bg-white selection:text-black ${
        isLanding ? 'h-screen overflow-hidden' : 'min-h-screen overflow-x-hidden'
      }`}
    >
      <BackgroundVideo />
      {!isLanding && <div className="fixed inset-0 bg-black/80" aria-hidden="true" />}
      <Navbar />
      {isLanding ? (
        <Hero state={state} onScan={controller.scan} />
      ) : state.phase === 'done' ? (
        <ResultSurface state={state} onReset={controller.reset} />
      ) : (
        <ErrorSurface message={state.message} onRetry={controller.reset} />
      )}
    </main>
  )
}

export default App
