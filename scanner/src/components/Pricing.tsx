/**
 * The Pricing page: three citadel-style plan cards in the shared dark/glass
 * shell. It renders inside the scanner shell (the parent supplies the fixed
 * background video and navbar); this component owns the pricing hero over the
 * video and the solid lower band with the plan cards.
 *
 * The Pro CTA is session-aware: a signed-in visitor goes straight to Stripe
 * checkout; an anonymous one is routed to `#register` first. Enterprise opens an
 * on-brand contact form that POSTs to `/api/contact` so a real conversation can
 * start. Nothing here is mocked.
 */

import { useState } from 'react'
import { motion } from 'motion/react'
import {
  ArrowRight,
  Building2,
  Check,
  Rocket,
  ShieldCheck,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { startCheckout } from '../api/client'
import { ContactModal } from './ContactModal'
import type { AuthState } from '../hooks/useAuth'

/** Shared entrance transition, matching the Enterprise page's easing. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

/** How a plan's primary call to action behaves. */
type PlanAction =
  | { kind: 'subscribe' }
  | { kind: 'link'; href: string }
  | { kind: 'contact' }

/** One pricing plan descriptor. */
interface Plan {
  id: 'free' | 'pro' | 'enterprise'
  Icon: LucideIcon
  name: string
  price: string
  cadence: string
  tagline: string
  features: string[]
  cta: string
  action: PlanAction
  /** The recommended plan: highlighted with an allow-tinted glow + badge. */
  featured: boolean
}

const PLANS: Plan[] = [
  {
    id: 'free',
    Icon: ShieldCheck,
    name: 'Free',
    price: 'S$0',
    cadence: 'forever',
    tagline: 'Scan a skill before your agent learns it.',
    features: [
      'Link & IOC tracing',
      'Deterministic rule screening',
      'Re-verifiable SHA-256 proof',
      'Capped daily scans',
    ],
    cta: 'Start scanning',
    action: { kind: 'link', href: '#' },
    featured: false,
  },
  {
    id: 'pro',
    Icon: Rocket,
    name: 'Pro',
    price: 'S$9.90',
    cadence: '/ month',
    tagline: 'AI-grade detection and your own dashboard.',
    features: [
      'Everything in Free',
      'AI prompt-injection detection',
      'Private scans (never published)',
      'Higher daily quota',
      'Scan history & protection dashboard',
    ],
    cta: 'Subscribe',
    action: { kind: 'subscribe' },
    featured: true,
  },
  {
    id: 'enterprise',
    Icon: Building2,
    name: 'Enterprise',
    price: 'Contact',
    cadence: 'us',
    tagline: 'Run it inside your own perimeter.',
    features: [
      'SSO & role-based access',
      'Self-hosted deployment',
      'Dedicated SLA & support',
      'Audit export & retention',
    ],
    cta: 'Contact sales',
    action: { kind: 'contact' },
    featured: false,
  },
]

interface PricingProps {
  auth: AuthState
}

export function Pricing({ auth }: PricingProps) {
  const [checkoutError, setCheckoutError] = useState<string | null>(null)
  const [checkoutBusy, setCheckoutBusy] = useState(false)
  // Whether the enterprise "Contact sales" form modal is open.
  const [contactOpen, setContactOpen] = useState(false)

  /**
   * Drive the Pro CTA. A signed-in visitor goes to Stripe checkout; an anonymous
   * one is sent to register first (they can subscribe from the dashboard after).
   */
  const handleSubscribe = async (): Promise<void> => {
    if (auth.status !== 'authenticated') {
      window.location.assign('#register')
      return
    }
    setCheckoutBusy(true)
    setCheckoutError(null)
    try {
      const { url } = await startCheckout()
      window.location.assign(url)
    } catch {
      setCheckoutError('Could not start checkout. Please try again.')
      setCheckoutBusy(false)
    }
  }

  return (
    <>
      {/* 1 · Intro --------------------------------------------------------- */}
      <section
        id="pricing-top"
        className="relative z-10 min-h-[60svh] flex flex-col items-center justify-center px-6 pt-4 pb-12"
      >
        <div className="text-center max-w-3xl mx-auto flex flex-col items-center justify-center w-full gap-6">
          <motion.p
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="flex items-center gap-2 text-white/70 text-[10px] md:text-[11px] font-medium tracking-[0.22em] uppercase font-mono"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
            Pricing
          </motion.p>
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
            style={{ fontFamily: "'Instrument Serif', serif" }}
            className="text-5xl md:text-[64px] font-medium tracking-[-0.01em] leading-[1.05] text-white drop-shadow-[0_2px_20px_rgba(0,0,0,0.5)]"
          >
            Verifiable safety, priced simply.
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="text-white/75 text-[15px] md:text-base leading-relaxed max-w-xl"
          >
            Start free with link, IOC, and rule screening backed by a proof you
            can re-verify. Upgrade for AI prompt-injection detection, private
            scans, and your own protection dashboard.
          </motion.p>
        </div>
      </section>

      {/* 2 · Plan cards ---------------------------------------------------- */}
      <div className="relative z-10 bg-black/60">
        <div className="max-w-5xl mx-auto px-6 pb-24">
          <motion.div
            {...RISE}
            className="grid grid-cols-1 md:grid-cols-3 gap-4 items-stretch"
          >
            {PLANS.map((plan) => (
              <PlanCard
                key={plan.id}
                plan={plan}
                busy={plan.id === 'pro' && checkoutBusy}
                onSubscribe={handleSubscribe}
                onContact={() => setContactOpen(true)}
              />
            ))}
          </motion.div>

          {checkoutError && (
            <p className="mt-4 text-center text-block/90 font-mono text-[13px]">
              {checkoutError}
            </p>
          )}

          <p className="mt-8 text-center text-white/40 text-[12px] font-mono">
            Every plan is fail-closed: anything we cannot judge is blocked before
            it runs.
          </p>
        </div>
      </div>

      {contactOpen && <ContactModal onClose={() => setContactOpen(false)} />}
    </>
  )
}

interface PlanCardProps {
  plan: Plan
  busy: boolean
  onSubscribe: () => void
  onContact: () => void
}

/** One pricing plan rendered as a glass card with a feature list and CTA. */
function PlanCard({ plan, busy, onSubscribe, onContact }: PlanCardProps) {
  const { Icon, name, price, cadence, tagline, features, cta, action, featured } =
    plan
  return (
    <div
      className={`liquid-glass rounded-3xl p-6 flex flex-col gap-5 ${
        featured ? 'glow-allow' : ''
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={`w-5 h-5 ${featured ? 'text-allow' : 'text-white/80'}`} />
          <span className="text-white text-sm font-semibold">{name}</span>
        </div>
        {featured && (
          <span className="glass-pill px-2.5 py-1 text-[10px] font-mono uppercase tracking-[0.14em] text-allow">
            Recommended
          </span>
        )}
      </div>

      <div className="flex items-baseline gap-1.5">
        <span
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-4xl md:text-[44px] font-medium tabular-nums text-white"
        >
          {price}
        </span>
        <span className="text-white/45 text-[13px] font-mono">{cadence}</span>
      </div>

      <p className="text-white/60 text-[13px] leading-relaxed">{tagline}</p>

      <ul className="flex flex-col gap-2.5 flex-1">
        {features.map((feature) => (
          <li key={feature} className="flex items-start gap-2.5 text-[13px]">
            <Check
              className={`w-4 h-4 mt-0.5 shrink-0 ${
                featured ? 'text-allow' : 'text-white/55'
              }`}
            />
            <span className="text-white/75 leading-snug">{feature}</span>
          </li>
        ))}
      </ul>

      <PlanCta
        cta={cta}
        action={action}
        featured={featured}
        busy={busy}
        onSubscribe={onSubscribe}
        onContact={onContact}
      />
    </div>
  )
}

interface PlanCtaProps {
  cta: string
  action: PlanAction
  featured: boolean
  busy: boolean
  onSubscribe: () => void
  onContact: () => void
}

/**
 * The plan CTA: a subscribe button for Pro, a button that opens the contact form
 * for Enterprise, and a link for the rest.
 */
function PlanCta({ cta, action, featured, busy, onSubscribe, onContact }: PlanCtaProps) {
  const solid =
    'inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-sm font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'
  const ghost =
    'glass-pill inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-medium text-white/80 hover:text-white transition-colors'

  if (action.kind === 'subscribe') {
    return (
      <button
        type="button"
        onClick={onSubscribe}
        disabled={busy}
        className={solid}
      >
        {busy ? 'Starting…' : cta}
        {!busy && <ArrowRight className="w-4 h-4" />}
      </button>
    )
  }
  if (action.kind === 'contact') {
    return (
      <button type="button" onClick={onContact} className={featured ? solid : ghost}>
        {cta}
        <ArrowRight className="w-4 h-4" />
      </button>
    )
  }
  return (
    <a href={action.href} className={featured ? solid : ghost}>
      {cta}
      <ArrowRight className="w-4 h-4" />
    </a>
  )
}
