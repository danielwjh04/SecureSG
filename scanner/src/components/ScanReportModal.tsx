/**
 * The user's own scan "block report": a scrollable dark/glass modal opened from a
 * BLOCK or REVIEW row in the Activity view. On open it fetches `GET
 * /api/scans/<id>` (owner-scoped) and renders the same evidence panels the
 * scanner and the admin viewer use, via the shared {@link ScanEvidence} body: the
 * scanned text, rule findings, injection findings, redirect cascades, reputation
 * reports, and the re-verifiable proof head hash.
 *
 * It owns its load lifecycle (loading / notFound / error / ready) keyed on the
 * scan id, and renders through a portal into <body> so the fixed overlay is sized
 * to the viewport rather than trapped inside the Activity card. Close is wired to
 * the button, the backdrop, and Escape, and the page scroll is locked while it is
 * open.
 */

import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { ReactNode } from 'react'
import { FileText, Link2, Server, X } from 'lucide-react'
import { ApiError, fetchOwnScanDetail } from '../api/client'
import { hostname, relativeTime } from '../lib/format'
import type { ScanReport } from '../api/types'
import { ScanEvidence } from './ScanEvidence'
import { StatusPill } from './StatusPill'

/** The detail-fetch lifecycle, keyed on the open scan id. */
type ReportState =
  | { phase: 'loading' }
  | { phase: 'ready'; report: ScanReport }
  | { phase: 'notFound' }
  | { phase: 'error'; message: string }

interface ScanReportModalProps {
  /** The scan id to fetch and display (a {@link RecentScan} row's id). */
  scanId: string
  /** Close handler: the close button, the backdrop, and Escape all call this. */
  onClose: () => void
}

/**
 * Fetch and render one of the caller's own scan reports in a modal overlay.
 *
 * Time complexity: O(c + r + f + n) over the evidence rendered (see
 * {@link ScanEvidence}). Space complexity: O(1) beyond the tree.
 */
export function ScanReportModal({ scanId, onClose }: ScanReportModalProps): ReactNode {
  const [state, setState] = useState<ReportState>({ phase: 'loading' })
  const dialogRef = useRef<HTMLDivElement | null>(null)

  // Fetch the report when the id changes. The active flag drops a stale resolve
  // if the modal is closed (or reopened on another row) mid-flight.
  useEffect(() => {
    let active = true
    setState({ phase: 'loading' })
    fetchOwnScanDetail(scanId)
      .then((report) => {
        if (active) setState({ phase: 'ready', report })
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
        aria-label="Scan report"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        className="liquid-glass relative my-auto w-full max-w-3xl rounded-2xl p-0 outline-none"
      >
        <ReportHeader report={state.phase === 'ready' ? state.report : null} onClose={onClose} />
        <div className="max-h-[70vh] overflow-y-auto px-5 py-5 sm:px-6">
          {state.phase === 'loading' && (
            <p className="text-white/45 font-mono text-sm py-12 text-center">
              Loading scan report…
            </p>
          )}
          {state.phase === 'notFound' && (
            <p className="text-white/55 font-mono text-sm py-12 text-center">
              No report is available for this scan.
            </p>
          )}
          {state.phase === 'error' && (
            <p className="text-block/90 font-mono text-sm py-12 text-center">{state.message}</p>
          )}
          {state.phase === 'ready' && (
            <ScanEvidence
              content={state.report.content}
              findings={state.report.findings}
              injections={state.report.injections}
              chains={state.report.chains}
              reputation={state.report.reputation}
              headHash={state.report.headHash}
            />
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}

/** The source icon + label for a report header, matching the Activity row style. */
function sourceView(report: ScanReport): { Icon: typeof FileText; label: string } {
  if (report.source.kind === 'url') return { Icon: Link2, label: hostname(report.source.ref) }
  if (report.source.kind === 'mcp') return { Icon: Server, label: 'MCP config' }
  return { Icon: FileText, label: 'Pasted content' }
}

/**
 * The sticky modal header: the verdict pill, a "Scan report" title, and (once the
 * report resolves) the scan source + relative time, plus the close button.
 */
function ReportHeader({
  report,
  onClose,
}: {
  report: ScanReport | null
  onClose: () => void
}): ReactNode {
  const source = report === null ? null : sourceView(report)
  const SourceIcon = source?.Icon ?? FileText
  return (
    <div className="sticky top-0 z-10 flex items-start justify-between gap-4 rounded-t-2xl border-b border-white/10 bg-black/40 px-5 py-4 sm:px-6">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex items-center gap-2">
          <StatusPill verdict={report?.verdict ?? 'BLOCK'} />
          <span className="font-medium text-white">Scan report</span>
        </div>
        {report !== null && source !== null && (
          <span className="flex min-w-0 items-center gap-1.5 text-white/55 font-mono text-[11px]">
            <SourceIcon className="w-3.5 h-3.5 shrink-0 text-white/40" />
            <span className="truncate" title={report.source.ref}>
              {source.label}
            </span>
            <span className="text-white/30">· {relativeTime(report.scannedAt)}</span>
          </span>
        )}
      </div>
      <button
        type="button"
        aria-label="Close scan report"
        onClick={onClose}
        className="glass-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-white/60 hover:text-white transition-colors cursor-pointer"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}
