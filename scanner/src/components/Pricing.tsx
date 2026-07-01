/**
 * The Pricing page: four plan cards (Free, Personal, Pro, Enterprise) in the
 * shared dark/glass shell. It renders inside the scanner shell (the parent
 * supplies the fixed background video and navbar); this component owns the pricing
 * hero over the video and the solid lower band with the plan cards.
 *
 * CTAs are session-aware. Anonymous visitors get the static pre-login CTAs (paid
 * plans route to `#register`). A signed-in visitor gets a DYNAMIC page that adapts
 * to their current tier and live subscription: current-plan, in-app upgrade /
 * downgrade (no redirect), cancel-at-period-end, and "Contact us" for Enterprise.
 * Free → paid still uses Stripe checkout (a card must be collected). Nothing is
 * mocked.
 */

import { useCallback, useEffect, useState } from 'react'
import { motion } from 'motion/react'
import {
  ArrowRight,
  Building2,
  Check,
  Rocket,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cancelPlan, changePlan, fetchSubscriptionStatus, startCheckout } from '../api/client'
import type { AuthState } from '../hooks/useAuth'
import type { AccountTier, SubscriptionStatus } from '../api/types'
import { ContactModal } from './ContactModal'

/** Shared entrance transition for pricing sections. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

/** How a plan's primary call to action behaves. */
type PlanAction =
  | { kind: 'subscribe'; tier: 'personal' | 'pro' }
  | { kind: 'link'; href: string }
  | { kind: 'contact' }

/** One pricing plan descriptor. */
interface Plan {
  id: 'free' | 'personal' | 'pro' | 'enterprise'
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
    id: 'personal',
    Icon: Sparkles,
    name: 'Personal',
    price: 'S$4.90',
    cadence: '/ month',
    tagline: 'Personal protection for everyday agent work.',
    features: [
      'Everything in Free',
      'AI prompt-injection detection',
      'Browser-visible content scans',
      'Local browser destination blocking',
      'Personal dashboard and scan history',
    ],
    cta: 'Start Personal',
    action: { kind: 'subscribe', tier: 'personal' },
    featured: true,
  },
  {
    id: 'pro',
    Icon: Rocket,
    name: 'Pro',
    price: 'S$9.90',
    cadence: '/ month',
    tagline: 'Higher-volume protection for active builders.',
    features: [
      'Everything in Personal',
      'Higher daily quota',
      'Priority AI checks',
      'Claude Code, Cursor, and Codex hooks',
      'SDK access for personal tools',
    ],
    cta: 'Upgrade to Pro',
    action: { kind: 'subscribe', tier: 'pro' },
    featured: false,
  },
  {
    id: 'enterprise',
    Icon: Building2,
    name: 'Enterprise',
    price: 'Custom',
    cadence: 'pricing',
    tagline: 'Fleet-wide protection with the controls your org needs.',
    features: [
      'Everything in Pro',
      'Central policy and rule control',
      'SSO and audit log export',
      'Priority support with SLAs',
      'Volume and seat-based pricing',
    ],
    cta: 'Contact us',
    action: { kind: 'contact' },
    featured: false,
  },
]

/** Tier ordering for upgrade/downgrade comparisons. */
const TIER_RANK: Record<AccountTier, number> = { free: 0, personal: 1, pro: 2, enterprise: 3 }

/** The resolved, session-aware call to action for one plan card. */
type Cta =
  | { kind: 'current'; label: string }
  | { kind: 'subscribe'; tier: 'personal' | 'pro'; label: string }
  | { kind: 'change'; tier: 'personal' | 'pro'; label: string }
  | { kind: 'cancel'; label: string }
  | { kind: 'contact'; label: string }
  | { kind: 'link'; href: string; label: string }

/** The no-subscription default shown before the live snapshot loads. */
const NO_SUB: SubscriptionStatus = {
  hasSubscription: false,
  cancelAtPeriodEnd: false,
  currentPeriodEnd: null,
}

/** Format an ISO period end as a short local date, tolerating a malformed value. */
function formatPeriodEnd(iso: string | null): string {
  if (iso === null) return 'the period end'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'the period end'
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

/**
 * Resolve a plan card's CTA from the viewer's auth + current tier and their live
 * subscription snapshot. Anonymous visitors get the static pre-login CTAs; a
 * signed-in visitor gets current-plan / upgrade / downgrade / cancel / contact, so
 * the page reflects exactly what they already have.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function resolveCta(plan: Plan, auth: AuthState, sub: SubscriptionStatus): Cta {
  if (auth.status !== 'authenticated' || auth.user === null) {
    if (plan.action.kind === 'contact') return { kind: 'contact', label: plan.cta }
    if (plan.action.kind === 'subscribe') {
      return { kind: 'subscribe', tier: plan.action.tier, label: plan.cta }
    }
    return { kind: 'link', href: plan.action.href, label: plan.cta }
  }
  const current = auth.user.tier
  const card = plan.id

  // Enterprise is contact-sales unless the account already is enterprise.
  if (card === 'enterprise') {
    return current === 'enterprise'
      ? { kind: 'current', label: 'Current plan' }
      : { kind: 'contact', label: 'Contact us' }
  }
  // Free card: the current plan for a free account, else the cancel action (or a
  // pending "active until" pill when a cancellation is already scheduled).
  if (card === 'free') {
    if (current === 'free') return { kind: 'current', label: 'Current plan' }
    if (sub.cancelAtPeriodEnd) {
      return { kind: 'current', label: `Active until ${formatPeriodEnd(sub.currentPeriodEnd)}` }
    }
    return { kind: 'cancel', label: 'Cancel plan' }
  }
  // A paid self-serve card (personal | pro).
  if (card === current) {
    if (sub.cancelAtPeriodEnd) {
      return { kind: 'current', label: `Cancels ${formatPeriodEnd(sub.currentPeriodEnd)}` }
    }
    return { kind: 'current', label: 'Current plan' }
  }
  if (current === 'free') {
    return { kind: 'subscribe', tier: card, label: plan.cta }
  }
  const upgrade = TIER_RANK[card] > TIER_RANK[current]
  return { kind: 'change', tier: card, label: `${upgrade ? 'Upgrade to' : 'Downgrade to'} ${plan.name}` }
}

interface PricingProps {
  auth: AuthState
}

export function Pricing({ auth }: PricingProps) {
  // The plan id currently processing (for its button's busy state), or null.
  const [busyId, setBusyId] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [contactOpen, setContactOpen] = useState(false)
  const [sub, setSub] = useState<SubscriptionStatus>(NO_SUB)

  // Load the live subscription snapshot for a signed-in visitor so the cards can
  // show current-plan and cancellation state; a failure leaves the benign default.
  const reloadSub = useCallback(async (): Promise<void> => {
    if (auth.status !== 'authenticated') {
      setSub(NO_SUB)
      return
    }
    try {
      setSub(await fetchSubscriptionStatus())
    } catch {
      setSub(NO_SUB)
    }
  }, [auth.status])

  useEffect(() => {
    void reloadSub()
  }, [reloadSub])

  /**
   * Free → paid subscribe. A signed-in visitor goes to Stripe checkout (a card
   * must be collected); an anonymous one is sent to register first.
   */
  const handleSubscribe = async (tier: 'personal' | 'pro'): Promise<void> => {
    if (auth.status !== 'authenticated') {
      window.location.assign('#register')
      return
    }
    setBusyId(tier)
    setActionError(null)
    try {
      const { url } = await startCheckout(tier)
      window.location.assign(url)
    } catch {
      setActionError('Could not start checkout. Please try again.')
      setBusyId(null)
    }
  }

  /**
   * Paid ↔ paid switch, in place (no redirect). Refreshes the account tier and the
   * subscription snapshot so the cards re-resolve to the new current plan.
   */
  const handleChange = async (tier: 'personal' | 'pro'): Promise<void> => {
    setBusyId(tier)
    setActionError(null)
    try {
      await changePlan(tier)
      await auth.refresh()
      await reloadSub()
    } catch {
      setActionError('Could not change your plan. Please try again.')
    } finally {
      setBusyId(null)
    }
  }

  /** Schedule cancellation at period end; the account stays paid until then. */
  const handleCancel = async (): Promise<void> => {
    setBusyId('free')
    setActionError(null)
    try {
      await cancelPlan()
      await reloadSub()
    } catch {
      setActionError('Could not cancel your plan. Please try again.')
    } finally {
      setBusyId(null)
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
            can re-verify. Upgrade for AI prompt-injection detection, local
            browser blocking, and your own protection dashboard.
          </motion.p>
        </div>
      </section>

      {/* 2 · Plan cards ---------------------------------------------------- */}
      <div className="relative z-10 bg-black/60">
        <div className="max-w-6xl mx-auto px-6 pb-24">
          <motion.div
            {...RISE}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 items-stretch"
          >
            {PLANS.map((plan) => (
              <PlanCard
                key={plan.id}
                plan={plan}
                cta={resolveCta(plan, auth, sub)}
                busy={busyId === plan.id}
                onSubscribe={handleSubscribe}
                onChange={handleChange}
                onCancel={handleCancel}
                onContact={() => setContactOpen(true)}
              />
            ))}
          </motion.div>

          {actionError && (
            <p className="mt-4 text-center text-block/90 font-mono text-[13px]">
              {actionError}
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
  /** The resolved, session-aware CTA for this card. */
  cta: Cta
  busy: boolean
  onSubscribe: (tier: 'personal' | 'pro') => void
  onChange: (tier: 'personal' | 'pro') => void
  onCancel: () => void
  onContact: () => void
}

/** One pricing plan rendered as a glass card with a feature list and CTA. */
function PlanCard({ plan, cta, busy, onSubscribe, onChange, onCancel, onContact }: PlanCardProps) {
  const { Icon, name, price, cadence, tagline, features, featured } = plan
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
        featured={featured}
        busy={busy}
        onSubscribe={onSubscribe}
        onChange={onChange}
        onCancel={onCancel}
        onContact={onContact}
      />
    </div>
  )
}

interface PlanCtaProps {
  cta: Cta
  featured: boolean
  busy: boolean
  onSubscribe: (tier: 'personal' | 'pro') => void
  onChange: (tier: 'personal' | 'pro') => void
  onCancel: () => void
  onContact: () => void
}

/**
 * Render a card's resolved CTA: a disabled current-plan pill, the Free link, the
 * Enterprise contact button, a checkout subscribe button (free → paid), an in-app
 * change button (paid ↔ paid), or a cancel button.
 */
function PlanCta({ cta, featured, busy, onSubscribe, onChange, onCancel, onContact }: PlanCtaProps) {
  const solid =
    'inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-sm font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'
  const ghost =
    'glass-pill inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-medium text-white/80 hover:text-white transition-colors cursor-pointer'
  const staticPill =
    'glass-pill inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-medium text-white/45'

  if (cta.kind === 'current') {
    return <div className={staticPill}>{cta.label}</div>
  }
  if (cta.kind === 'link') {
    return (
      <a href={cta.href} className={featured ? solid : ghost}>
        {cta.label}
        <ArrowRight className="w-4 h-4" />
      </a>
    )
  }
  if (cta.kind === 'contact') {
    return (
      <button type="button" onClick={onContact} className={ghost}>
        {cta.label}
        <ArrowRight className="w-4 h-4" />
      </button>
    )
  }
  if (cta.kind === 'subscribe') {
    return (
      <button type="button" onClick={() => onSubscribe(cta.tier)} disabled={busy} className={solid}>
        {busy ? 'Starting…' : cta.label}
        {!busy && <ArrowRight className="w-4 h-4" />}
      </button>
    )
  }
  if (cta.kind === 'change') {
    return (
      <button type="button" onClick={() => onChange(cta.tier)} disabled={busy} className={solid}>
        {busy ? 'Updating…' : cta.label}
        {!busy && <ArrowRight className="w-4 h-4" />}
      </button>
    )
  }
  return (
    <button type="button" onClick={onCancel} disabled={busy} className={ghost}>
      {busy ? 'Canceling…' : cta.label}
    </button>
  )
}
