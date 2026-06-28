/**
 * The enterprise "Contact sales" form: a dark/glass modal the pricing page opens
 * in place of the old mailto. The visitor types a name, email, and message, and
 * on submit the form POSTs to `/api/contact`; the recipient addresses live
 * server-side, so nothing here references them.
 *
 * It mirrors {@link ThreatDetailModal}'s overlay contract — portaled into
 * `document.body` so the fixed full-viewport overlay escapes any transformed,
 * clipping ancestor; closable three ways (the close button, the backdrop, and
 * Escape); and the page scroll is locked behind it while open. Fields are
 * validated client-side (all required, a real email shape) before the request,
 * the submit button is disabled while the request is in flight, and the API
 * status is mapped to inline copy. On success the form is replaced by a short
 * confirmation.
 */

import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Building2, CheckCircle2, X } from 'lucide-react'
import { ApiError, submitContact } from '../api/client'

interface ContactModalProps {
  /** Close handler: the close button, the backdrop, and Escape all call this. */
  onClose: () => void
}

/** The submit lifecycle of the contact form. */
type SubmitState =
  | { phase: 'idle' }
  | { phase: 'submitting' }
  | { phase: 'sent' }
  | { phase: 'error'; message: string }

/**
 * A pragmatic email shape check: a non-empty local part, an `@`, and a dotted
 * domain with no spaces. It only gates an obviously malformed address client-side
 * — the worker is the authority and re-validates every field, so this never has
 * to be RFC-exhaustive.
 */
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/**
 * Translate an API failure into the inline message. The contract pins specific
 * statuses: 422 (a field failed re-validation), 429 (rate-limited), 502/503 (the
 * send path is unavailable). A transport failure (status 0) and anything else
 * fall back to the same honest "try again" line.
 */
function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 422) return 'Check your details.'
    if (error.status === 429) return 'Too many requests, try again later.'
    if (error.status === 502 || error.status === 503) {
      return "Couldn't send right now, please try again."
    }
  }
  return "Couldn't send right now, please try again."
}

const inputClass =
  'rounded-xl bg-white/[0.04] border border-white/10 px-4 py-2.5 text-[14px] text-white placeholder:text-white/30 outline-none focus:border-white/30 transition-colors'

const submitClass =
  'rounded-full bg-white text-black px-6 py-2.5 text-[14px] font-semibold hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed'

/**
 * The enterprise contact form rendered as a modal overlay.
 *
 * Time complexity: O(1) — fixed field set, one request. Space complexity: O(1)
 * beyond the React tree.
 */
export function ContactModal({ onClose }: ContactModalProps): ReactNode {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const [state, setState] = useState<SubmitState>({ phase: 'idle' })
  const dialogRef = useRef<HTMLDivElement | null>(null)

  // Close on Escape, and lock the page scroll behind the overlay while open.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = previousOverflow
    }
  }, [onClose])

  // Move focus into the dialog on open so keyboard users land inside it.
  useEffect(() => {
    dialogRef.current?.focus()
  }, [])

  const handleSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault()
    const trimmedName = name.trim()
    const trimmedEmail = email.trim()
    const trimmedMessage = message.trim()
    // Validate client-side before the request: all fields required, a real email
    // shape. The worker re-validates; this only avoids an obviously bad POST.
    if (
      trimmedName.length === 0 ||
      trimmedMessage.length === 0 ||
      !EMAIL_PATTERN.test(trimmedEmail)
    ) {
      setState({ phase: 'error', message: 'Check your details.' })
      return
    }
    setState({ phase: 'submitting' })
    try {
      await submitContact({
        name: trimmedName,
        email: trimmedEmail,
        message: trimmedMessage,
      })
      setState({ phase: 'sent' })
    } catch (caught) {
      setState({ phase: 'error', message: errorMessage(caught) })
    }
  }

  // Portal to <body> so the fixed overlay is sized to the viewport, not trapped
  // inside a transformed, clipping ancestor (a CSS transform makes an ancestor
  // the containing block for `position: fixed`). The backdrop fills the viewport
  // and closes on click; the card stops propagation so clicks inside it stay open.
  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center overflow-y-auto bg-black/70 p-4 sm:p-8"
      style={{ backdropFilter: 'blur(6px)', WebkitBackdropFilter: 'blur(6px)' }}
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Contact sales"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        className="liquid-glass relative my-auto w-full max-w-md rounded-2xl p-0 outline-none"
      >
        <ContactHeader onClose={onClose} />
        <div className="px-5 py-5 sm:px-6">
          {state.phase === 'sent' ? (
            <SentConfirmation />
          ) : (
            <ContactForm
              name={name}
              email={email}
              message={message}
              onName={setName}
              onEmail={setEmail}
              onMessage={setMessage}
              onSubmit={handleSubmit}
              submitting={state.phase === 'submitting'}
              error={state.phase === 'error' ? state.message : null}
            />
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}

/** The sticky header: an enterprise icon, the title, and the close button. */
function ContactHeader({ onClose }: { onClose: () => void }): ReactNode {
  return (
    <div className="flex items-start justify-between gap-4 rounded-t-2xl border-b border-white/10 bg-black/40 px-5 py-4 sm:px-6">
      <div className="flex min-w-0 flex-col gap-1.5">
        <span className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
          <Building2 className="w-3.5 h-3.5 text-allow" />
          Enterprise
        </span>
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-2xl font-medium tracking-[-0.01em] text-white"
        >
          Contact sales
        </h2>
      </div>
      <button
        type="button"
        aria-label="Close contact form"
        onClick={onClose}
        className="glass-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-white/60 hover:text-white transition-colors cursor-pointer"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

interface ContactFormProps {
  name: string
  email: string
  message: string
  onName: (value: string) => void
  onEmail: (value: string) => void
  onMessage: (value: string) => void
  onSubmit: (event: FormEvent<HTMLFormElement>) => void
  submitting: boolean
  error: string | null
}

/** The name / email / message fields with the submit button and inline error. */
function ContactForm({
  name,
  email,
  message,
  onName,
  onEmail,
  onMessage,
  onSubmit,
  submitting,
  error,
}: ContactFormProps): ReactNode {
  return (
    <>
      <p className="mb-4 text-[13px] leading-relaxed text-white/55">
        Tell us about your team and we'll be in touch about running SecureAI
        inside your perimeter.
      </p>
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <label className="flex flex-col gap-1.5">
          <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
            Name
          </span>
          <input
            type="text"
            name="name"
            autoComplete="name"
            required
            value={name}
            onChange={(event) => onName(event.target.value)}
            placeholder="Ada Lovelace"
            className={inputClass}
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
            Email
          </span>
          <input
            type="email"
            name="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => onEmail(event.target.value)}
            placeholder="you@company.com"
            className={inputClass}
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[11px] font-mono uppercase tracking-[0.16em] text-white/45">
            Message
          </span>
          <textarea
            name="message"
            required
            rows={4}
            value={message}
            onChange={(event) => onMessage(event.target.value)}
            placeholder="What are you looking to protect?"
            className={`${inputClass} resize-y min-h-[96px]`}
          />
        </label>

        {error !== null && (
          <p role="alert" className="text-block/90 font-mono text-[12px] leading-snug">
            {error}
          </p>
        )}

        <button type="submit" disabled={submitting} className={submitClass}>
          {submitting ? 'Sending…' : 'Submit'}
        </button>
      </form>
    </>
  )
}

/** The success state shown in place of the form after a sent enquiry. */
function SentConfirmation(): ReactNode {
  return (
    <div className="flex flex-col items-center gap-3 py-8 text-center">
      <CheckCircle2 className="w-8 h-8 text-allow" />
      <p className="text-[15px] font-medium text-white">Thanks — we'll be in touch.</p>
    </div>
  )
}
