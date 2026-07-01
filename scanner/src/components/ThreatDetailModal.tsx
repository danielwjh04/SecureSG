/**
 * The admin malicious-skill/artifact detail viewer: a scrollable dark/glass modal
 * an admin opens from a row in the Threats blocked report. On open it fetches
 * `GET /api/admin/scans/<id>` and renders the full evidence the BLOCK verdict was
 * reached on, the scanned skill/artifact text, deterministic rule findings,
 * AI injection findings, traced redirect cascades, reputation reports, and the
 * proof head hash that proves the sealed chain is re-verifiable.
 *
 * It owns its own load lifecycle (loading / error / 404 "details not available" /
 * ready), keyed on the scan id, and reuses the scanner's evidence components
 * (InjectionFindings, Reputation, RedirectChain) so the admin sees the same
 * panels a user sees in a scan report. It renders through a portal into
 * `document.body` so the fixed full-viewport overlay escapes the Threats
 * section's transformed, clipping glass card rather than being constrained to it.
 * Closing is wired three ways, the close button, the backdrop, and the Escape
 * key, and the body scroll is locked while the modal is open so the page behind
 * it cannot scroll under the overlay.
 */

import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { ReactNode } from 'react'
import { FileText, Link2, X } from 'lucide-react'
import { ApiError, fetchScanDetail } from '../api/client'
import type { AdminScanDetail } from '../api/types'
import { ScanEvidence } from './ScanEvidence'
import { StatusPill } from './StatusPill'

/** The detail-fetch lifecycle, keyed on the open scan id. */
type DetailState =
  | { phase: 'loading' }
  | { phase: 'ready'; detail: AdminScanDetail }
  | { phase: 'notFound' }
  | { phase: 'error'; message: string }

interface ThreatDetailModalProps {
  /** The scan id to fetch and display (the {@link AdminThreat} row's id). */
  scanId: string
  /** Fallback owner email, shown in the header until the detail resolves. */
  email: string
  /** Close handler: the close button, the backdrop, and Escape all call this. */
  onClose: () => void
}

/**
 * Fetch and render one scanned malicious skill/artifact in a modal overlay.
 *
 * Time complexity: O(c + r + f + n) over chains, reputation reports, injection
 * findings, and rule findings rendered. Space complexity: O(1) beyond the tree.
 */
export function ThreatDetailModal({
  scanId,
  email,
  onClose,
}: ThreatDetailModalProps): ReactNode {
  const [state, setState] = useState<DetailState>({ phase: 'loading' })
  const dialogRef = useRef<HTMLDivElement | null>(null)

  // Fetch the detail when the id changes. The active flag drops a stale resolve
  // if the modal is closed (or reopened on another row) mid-flight.
  useEffect(() => {
    let active = true
    setState({ phase: 'loading' })
    fetchScanDetail(scanId)
      .then((detail) => {
        if (active) setState({ phase: 'ready', detail })
      })
      .catch((error: unknown) => {
        if (!active) return
        if (error instanceof ApiError && error.status === 404) {
          setState({ phase: 'notFound' })
        } else {
          setState({ phase: 'error', message: 'Could not load this scan.' })
        }
      })
    return () => {
      active = false
    }
  }, [scanId])

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

  // Portal to <body> so the fixed overlay is sized to the viewport, not trapped
  // inside the Threats section's transformed, `overflow-hidden` glass card (a CSS
  // transform on an ancestor makes it the containing block for `position: fixed`,
  // which would otherwise clip the modal to that card). The backdrop fills the
  // viewport; the card is vertically centered with `my-auto` and the evidence
  // body scrolls internally (`max-h`/`overflow-y-auto`) so long scanned content
  // never overflows the card.
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
        aria-label={`Scan detail for ${email}`}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        className="liquid-glass relative my-auto w-full max-w-3xl rounded-2xl p-0 outline-none"
      >
        <DetailBody state={state} email={email} onClose={onClose} />
      </div>
    </div>,
    document.body,
  )
}

/** The header + scrollable evidence body, switched on the load phase. */
function DetailBody({
  state,
  email,
  onClose,
}: {
  state: DetailState
  email: string
  onClose: () => void
}): ReactNode {
  return (
    <>
      <DetailHeader
        email={state.phase === 'ready' ? state.detail.email : email}
        detail={state.phase === 'ready' ? state.detail : null}
        onClose={onClose}
      />
      <div className="max-h-[70vh] overflow-y-auto px-5 py-5 sm:px-6">
        {state.phase === 'loading' && (
          <p className="text-white/45 font-mono text-sm py-12 text-center">
            Loading scan detail…
          </p>
        )}
        {state.phase === 'notFound' && (
          <p className="text-white/55 font-mono text-sm py-12 text-center">
            Details not available for this scan.
          </p>
        )}
        {state.phase === 'error' && (
          <p className="text-block/90 font-mono text-sm py-12 text-center">{state.message}</p>
        )}
        {state.phase === 'ready' && (
          <ScanEvidence
            content={state.detail.content}
            findings={state.detail.findings}
            injections={state.detail.injections}
            chains={state.detail.chains}
            reputation={state.detail.reputation}
            headHash={state.detail.headHash}
          />
        )}
      </div>
    </>
  )
}

/**
 * The sticky modal header: a red BLOCK pill (the report lists only blocks),
 * the owning member's email, the scan source, the relative time, and the close
 * button. The header shows the fallback email until the detail resolves.
 */
function DetailHeader({
  email,
  detail,
  onClose,
}: {
  email: string
  detail: AdminScanDetail | null
  onClose: () => void
}): ReactNode {
  const isUrl = detail?.source.kind === 'url'
  const SourceIcon = isUrl ? Link2 : FileText
  const sourceLabel = detail === null ? null : isUrl ? detail.source.ref : 'Pasted skill'
  return (
    <div className="sticky top-0 z-10 flex items-start justify-between gap-4 rounded-t-2xl border-b border-white/10 bg-black/40 px-5 py-4 sm:px-6">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex items-center gap-2">
          <StatusPill verdict={detail?.verdict ?? 'BLOCK'} />
          <span className="font-medium text-white break-all">{email}</span>
        </div>
        {sourceLabel !== null && (
          <span className="flex min-w-0 items-center gap-1.5 text-white/55 font-mono text-[11px]">
            <SourceIcon className="w-3.5 h-3.5 shrink-0 text-white/40" />
            <span className="truncate" title={detail?.source.ref}>
              {sourceLabel}
            </span>
          </span>
        )}
      </div>
      <button
        type="button"
        aria-label="Close scan detail"
        onClick={onClose}
        className="glass-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-white/60 hover:text-white transition-colors cursor-pointer"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

