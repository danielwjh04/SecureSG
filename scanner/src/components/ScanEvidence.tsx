/**
 * The shared scan-evidence body: the scanned content, deterministic rule
 * findings, AI injection findings, traced redirect cascades, reputation reports,
 * and the re-verifiable proof head hash. Rendered identically in the admin
 * threat-detail modal ({@link ThreatDetailModal}) and the user's own Activity
 * block report ({@link ScanReportModal}), so the evidence panels live in one
 * place.
 *
 * Purely presentational: it takes the already-parsed evidence (the route parses
 * the stored `result_json`) and renders it. Empty sub-sections fall back to their
 * own muted line so a pass that produced nothing reads explicitly rather than as
 * a missing panel.
 */

import type { ReactNode } from 'react'
import { AlertTriangle, FileCode2, Fingerprint, Link2 } from 'lucide-react'
import { truncateHash } from '../lib/format'
import type {
  InjectionFinding,
  LinkChain,
  ReputationReport,
  RuleFinding,
} from '../api/types'
import { InjectionFindings } from './InjectionFindings'
import { Reputation } from './Reputation'
import { RedirectChain } from './RedirectChain'
import { StatusPill } from './StatusPill'

interface ScanEvidenceProps {
  /** The scanned skill/artifact text, or `null` when it was not retained. */
  content: string | null
  findings: RuleFinding[]
  injections: InjectionFinding[]
  chains: LinkChain[]
  reputation: ReputationReport[]
  /** The proof head hash of the sealed, re-verifiable chain. */
  headHash: string
}

/**
 * Render the full evidence a verdict was reached on.
 *
 * Time complexity: O(c + r + f + n) over chains, reputation reports, injection
 * findings, and rule findings rendered. Space complexity: O(1) beyond the tree.
 */
export function ScanEvidence({
  content,
  findings,
  injections,
  chains,
  reputation,
  headHash,
}: ScanEvidenceProps): ReactNode {
  return (
    <div className="flex flex-col gap-6">
      <ScannedContent content={content} />
      <RuleFindings findings={findings} />
      <InjectionFindings findings={injections} />
      {chains.length > 0 && (
        <section className="flex flex-col gap-3">
          <SectionLabel icon={Link2}>Redirect cascades · {chains.length}</SectionLabel>
          <div className="flex flex-col gap-3">
            {chains.map((chain, index) => (
              <RedirectChain key={chain.origin} chain={chain} index={index} />
            ))}
          </div>
        </section>
      )}
      <Reputation reports={reputation} />
      <ProofHash headHash={headHash} />
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
 * shown truncated (`head…tail`) with the full digest on hover/title, so the
 * viewer can confirm the row maps to the sealed proof re-verifiable in the
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
          This proof chain is sealed and independently re-verifiable, re-hash it
          in the scanner's proof inspector to confirm it has not been tampered
          with.
        </p>
      </div>
    </section>
  )
}
