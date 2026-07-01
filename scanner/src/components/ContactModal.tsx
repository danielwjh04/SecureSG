/**
 * The Enterprise "Contact us" modal from the pricing page: a small sales-inquiry
 * form (name, email, message). On submit it POSTs to `POST /api/contact` via
 * {@link submitContact}; the recipient addresses live server-side, so this form
 * never carries them. A success swaps the form for a short confirmation; a
 * failure maps the worker's status to an inline line the visitor can act on
 * (invalid field / rate-limited / provider unavailable / unreachable).
 *
 * Renders through a portal into <body> so the fixed overlay is sized to the
 * viewport, not the pricing card. Close is wired to the button, the backdrop, and
 * Escape, and the page scroll is locked while it is open.
 */

import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { ReactNode } from 'react'
import { Check, Send, X } from 'lucide-react'
import { ApiError, submitContact } from '../api/client'

/** Field bounds mirroring the worker's `contactSchema` so the form pre-validates. */
const NAME_MAX = 100
const EMAIL_MAX = 254
const MESSAGE_MAX = 5000

/** A minimal, permissive email shape check; the worker is the authority. */
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

type SubmitState =
  | { phase: 'idle' }
  | { phase: 'submitting' }
  | { phase: 'sent' }
  | { phase: 'error'; message: string }

interface ContactModalProps {
  /** Close handler: the close button, the backdrop, and Escape all call this. */
  onClose: () => void
}

/** Map a failed submit to an inline message the visitor can act on. */
function messageForError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 422) return 'Please check your details and try again.'
    if (error.status === 429) return 'Too many messages just now. Please try again later.'
    if (error.status === 503) return 'Contact is unavailable right now. Please email us directly.'
    if (error.status === 502) return 'We could not send your message. Please try again.'
    if (error.status === 0) return 'Could not reach the server. Check your connection.'
  }
  return 'Something went wrong. Please try again.'
}

/**
 * Render the Enterprise contact form in a modal overlay.
 *
 * Time complexity: O(1). Space complexity: O(1).
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

  useEffect(() => {
    dialogRef.current?.focus()
  }, [])

  const submit = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault()
    const trimmed = { name: name.trim(), email: email.trim(), message: message.trim() }
    if (!trimmed.name || !trimmed.email || !trimmed.message) {
      setState({ phase: 'error', message: 'Please fill in every field.' })
      return
    }
    if (!EMAIL_PATTERN.test(trimmed.email)) {
      setState({ phase: 'error', message: 'Please enter a valid email address.' })
      return
    }
    setState({ phase: 'submitting' })
    try {
      await submitContact(trimmed)
      setState({ phase: 'sent' })
    } catch (error: unknown) {
      setState({ phase: 'error', message: messageForError(error) })
    }
  }

  const busy = state.phase === 'submitting'

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
        aria-label="Contact SecureAI sales"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        className="liquid-glass relative my-auto w-full max-w-lg rounded-2xl p-0 outline-none"
      >
        <div className="flex items-start justify-between gap-4 border-b border-white/10 px-5 py-4 sm:px-6">
          <div className="flex flex-col gap-1">
            <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
              Enterprise
            </span>
            <h2
              style={{ fontFamily: "'Instrument Serif', serif" }}
              className="text-2xl font-medium text-white leading-tight"
            >
              Talk to us
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

        <div className="px-5 py-5 sm:px-6">
          {state.phase === 'sent' ? (
            <div className="flex flex-col items-center gap-3 py-8 text-center">
              <Check className="w-8 h-8 text-allow" />
              <h3 className="text-white text-lg font-semibold">Message sent</h3>
              <p className="text-white/60 text-[14px] leading-relaxed max-w-sm">
                Thanks for reaching out. Our team will reply to your email shortly.
              </p>
              <button
                type="button"
                onClick={onClose}
                className="mt-2 inline-flex items-center justify-center rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer"
              >
                Done
              </button>
            </div>
          ) : (
            <form onSubmit={submit} className="flex flex-col gap-4">
              <p className="text-white/60 text-[13px] leading-relaxed">
                Tell us about your team and what you need. We will get back to you
                by email.
              </p>
              <Field label="Name">
                <input
                  type="text"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  maxLength={NAME_MAX}
                  autoComplete="name"
                  className={inputClass}
                  placeholder="Ada Lovelace"
                />
              </Field>
              <Field label="Work email">
                <input
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  maxLength={EMAIL_MAX}
                  autoComplete="email"
                  className={inputClass}
                  placeholder="ada@yourcompany.com"
                />
              </Field>
              <Field label="Message">
                <textarea
                  value={message}
                  onChange={(event) => setMessage(event.target.value)}
                  maxLength={MESSAGE_MAX}
                  rows={4}
                  className={`${inputClass} resize-none`}
                  placeholder="How many agents are you protecting, and what do you need?"
                />
              </Field>

              {state.phase === 'error' && (
                <p className="text-block/90 font-mono text-[12px]">{state.message}</p>
              )}

              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {busy ? 'Sending…' : 'Send message'}
                {!busy && <Send className="w-4 h-4" />}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}

/** Shared dark input styling for the form fields. */
const inputClass =
  'w-full rounded-xl bg-white/[0.04] border border-white/10 px-3.5 py-2.5 text-[14px] text-white placeholder:text-white/30 outline-none focus:border-white/30 transition-colors'

/** A labeled form field wrapper. */
function Field({ label, children }: { label: string; children: ReactNode }): ReactNode {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-[11px] font-mono uppercase tracking-[0.14em] text-white/55">
        {label}
      </span>
      {children}
    </label>
  )
}
