/**
 * The decorative left panel of the auth split card: the SecureAI mark over a
 * slow field of drifting SVG paths, with the product's verify-first line pinned
 * to the bottom. Purely cosmetic and `aria-hidden`; it carries no interactive
 * elements and is hidden below the `lg` breakpoint where the card collapses to a
 * single column.
 */

import { motion } from 'motion/react'
import { ShieldCheck } from 'lucide-react'

/** The number of layered paths drawn per {@link FloatingPaths} instance. */
const PATH_COUNT = 36

/**
 * One layer of animated background paths. Geometry, stroke width, and animation
 * duration are all derived from the path index, so the field is deterministic
 * across renders (no `Math.random`) while still reading as organic motion.
 *
 * @param position - direction multiplier; render `1` and `-1` for two mirrored layers.
 * Complexity: O(PATH_COUNT), fixed per layer.
 */
function FloatingPaths({ position }: { position: number }) {
  const paths = Array.from({ length: PATH_COUNT }, (_, i) => ({
    id: i,
    d: `M-${380 - i * 5 * position} -${189 + i * 6}C-${380 - i * 5 * position} -${189 + i * 6} -${312 - i * 5 * position} ${216 - i * 6} ${152 - i * 5 * position} ${343 - i * 6}C${616 - i * 5 * position} ${470 - i * 6} ${684 - i * 5 * position} ${875 - i * 6} ${684 - i * 5 * position} ${875 - i * 6}`,
    width: 0.5 + i * 0.03,
  }))

  return (
    <div className="pointer-events-none absolute inset-0" aria-hidden="true">
      <svg
        className="h-full w-full text-white/40"
        fill="none"
        viewBox="0 0 696 316"
        preserveAspectRatio="xMidYMid slice"
      >
        {paths.map((path) => (
          <motion.path
            key={path.id}
            d={path.d}
            stroke="currentColor"
            strokeOpacity={0.05 + path.id * 0.018}
            strokeWidth={path.width}
            initial={{ pathLength: 0.3, opacity: 0.6 }}
            animate={{ pathLength: 1, opacity: [0.2, 0.45, 0.2], pathOffset: [0, 1, 0] }}
            transition={{ duration: 20 + (path.id % 10), repeat: Number.POSITIVE_INFINITY, ease: 'linear' }}
          />
        ))}
      </svg>
    </div>
  )
}

/** The auth split card's left panel. Decorative only. */
export function AuthSidebar() {
  return (
    <div className="relative hidden lg:flex flex-col justify-between overflow-hidden border-r border-white/[0.06] bg-white/[0.02] p-10">
      <FloatingPaths position={1} />
      <FloatingPaths position={-1} />
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-black/50" />

      <div className="relative z-10 flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-white" />
        <span className="font-semibold text-white">SecureAI</span>
      </div>

      <blockquote className="relative z-10 flex flex-col gap-3">
        <p
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-2xl leading-snug text-white/90"
        >
          &ldquo;Don&rsquo;t trust us. Verify every decision yourself.&rdquo;
        </p>
        <footer className="font-mono text-sm text-white/50">
          Every verdict, sealed in a proof chain.
        </footer>
      </blockquote>
    </div>
  )
}
