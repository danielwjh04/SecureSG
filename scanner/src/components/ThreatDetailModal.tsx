/**
 * The admin malicious-skill/artifact detail viewer: a scrollable dark/glass modal
 * an admin opens from a row in the Threats blocked report. On open it fetches
 * `GET /api/admin/scans/<id>` and renders the full evidence the BLOCK verdict was
 * reached on — the scanned skill/artifact text, deterministic rule findings,
 * AI injection findings, traced redirect cascades, reputation reports, and the
 * proof head hash that proves the sealed chain is re-verifiable.
 *
 * It owns its own load lifecycle (loading / error / 404 "details not available" /
 * ready), keyed on the scan id, and reuses the scanner's evidence components
 * (InjectionFindings, Reputation, RedirectChain) so the admin sees the same
 * panels a user sees in a scan report. Closing is wired three ways — the close
 * button, the backdrop, and the Escape key — and the body scroll is locked while
 * the modal is open so the page behind it cannot scroll under the overlay.
 */

import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import {
  AlertTriangle,
  FileCode2,
  Fingerprint,
  FileText,
  Link2,
  X,
} from 'lucide-react'
import { ApiError, fetchScanDetail } from '../api/client'
import { truncateHash } from '../lib/format'
import type { AdminScanDetail, RuleFinding } from '../api/types'
import { InjectionFindings } from './InjectionFindings'
import { Reputation } from './Reputation'
import { RedirectChain } from './RedirectChain'
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

  return (
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
    </div>
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
        {state.phase === 'ready' && <DetailEvidence detail={state.detail} />}
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

/**
 * The resolved evidence: the scanned skill/artifact text, the deterministic rule
 * findings, the reused injection / reputation / redirect panels, and the proof
 * head hash. Empty sub-sections fall back to their own muted line so the admin
 * sees explicitly that a pass produced nothing rather than a missing panel.
 */
function DetailEvidence({ detail }: { detail: AdminScanDetail }): ReactNode {
  return (
    <div className="flex flex-col gap-6">
      <ScannedContent content={detail.content} />
      <RuleFindings findings={detail.findings} />
      <InjectionFindings findings={detail.injections} />
      {detail.chains.length > 0 && (
        <section className="flex flex-col gap-3">
          <SectionLabel icon={Link2}>Redirect cascades · {detail.chains.length}</SectionLabel>
          <div className="flex flex-col gap-3">
            {detail.chains.map((chain, index) => (
              <RedirectChain key={chain.origin} chain={chain} index={index} />
            ))}
          </div>
        </section>
      )}
      <Reputation reports={detail.reputation} />
      <ProofHash headHash={detail.headHash} />
    </div>
  )
}

/** A small uppercase mono section label with a leading icon. */
function SectionLabel({
  icon: Icon,
  children,
}: {
  icon: typeof FileCode2
  children: ReactNode
}): ReactNode {
  return (
    <h3 className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-[0.14em] text-white/55">
      <Icon className="w-3.5 h-3.5 text-white/40" />
      {children}
    </h3>
  )
}

/**
 * The scanned skill/artifact text in a monospace, scrollable code box. The text
 * may be long (so the box caps its height and scrolls) or `null` (so it reads
 * "content not stored" rather than rendering an empty box).
 */
function ScannedContent({ content }: { content: string | null }): ReactNode {
  return (
    <section className="flex flex-col gap-3">
      <SectionLabel icon={FileCode2}>Scanned content</SectionLabel>
      {content === null ? (
        <p className="text-white/45 font-mono text-[12px]">content not stored</p>
      ) : (
        <pre className="max-h-[320px] overflow-auto rounded-xl border border-white/10 bg-black/40 px-4 py-3 font-mono text-[12px] leading-relaxed text-white/80 whitespace-pre-wrap break-words">
          {content}
        </pre>
      )}
    </section>
  )
}

/**
 * The deterministic rule findings (ruleId + detail + severity). Distinct from
 * the AI {@link InjectionFindings}: these are the baseline-screening rules that
 * fired, each with its own severity pill.
 */
function RuleFindings({ findings }: { findings: RuleFinding[] }): ReactNode {
  return (
    <section className="flex flex-col gap-3">
      <SectionLabel icon={AlertTriangle}>Rule findings · {findings.length}</SectionLabel>
      {findings.length === 0 ? (
        <p className="text-white/45 font-mono text-[12px]">No rules fired.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {findings.map((finding, index) => (
            <li
              key={`${finding.ruleId}-${index}`}
              className="flex flex-col gap-1.5 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3"
            >
              <div className="flex items-center gap-2">
                <StatusPill verdict={finding.severity} />
                <code className="font-mono text-[12px] text-white/80 break-all">
                  {finding.ruleId}
                </code>
              </div>
              <p className="text-white/70 text-[13px] leading-snug">{finding.detail}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/**
 * The proof head hash with a note that the chain is re-verifiable. The hash is
 * shown truncated (`head…tail`) with the full digest on hover/title, so an admin
 * can confirm the row maps to the sealed proof a user can re-verify in the
 * scanner's proof inspector.
 */
function ProofHash({ headHash }: { headHash: string }): ReactNode {
  return (
    <section className="flex flex-col gap-3">
      <SectionLabel icon={Fingerprint}>Proof</SectionLabel>
      <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3.5 py-3">
        <code
          className="font-mono text-[12px] text-white/80 break-all"
          title={headHash}
          aria-label={`Proof head hash ${headHash}`}
        >
          {truncateHash(headHash)}
        </code>
        <p className="text-white/50 text-[12px] leading-snug">
          This proof chain is sealed and independently re-verifiable — re-hash it
          in the scanner's proof inspector to confirm it has not been tampered
          with.
        </p>
      </div>
    </section>
  )
}
