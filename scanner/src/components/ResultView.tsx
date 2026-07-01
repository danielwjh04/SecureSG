import type { ReactNode } from 'react'
import type { ScanResult } from '../api/types'
import { cn } from '@/lib/utils'
import { CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { DashboardCard } from '@/components/dashboard-card'
import { VerdictBanner } from './VerdictBanner'
import { ScanDashboard } from './ScanDashboard'
import { RedirectChain } from './RedirectChain'
import { ReputationRows } from './Reputation'
import { InjectionRows } from './InjectionFindings'
import { ProofViewer } from './ProofViewer'
import { useScrollToTopOnChange } from '../hooks/useScrollToTopOnChange'
import { formatTimestamp } from '../lib/format'

interface ResultViewProps {
  result: ScanResult
}

interface EvidenceCardProps {
  title: string
  count: number
  isEmpty: boolean
  emptyText: string
  className?: string
  children: ReactNode
}

/**
 * One efferd-style evidence cell: a borderless dashboard card with a titled,
 * count-badged header and its content, or a muted empty state. It provides the
 * shared header/empty chrome so each evidence section renders the same way in
 * the seamed grid without repeating the markup.
 */
function EvidenceCard({
  title,
  count,
  isEmpty,
  emptyText,
  className,
  children,
}: EvidenceCardProps): ReactNode {
  return (
    <DashboardCard className={cn('gap-0', className)}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 border-b">
        <CardTitle className="text-base">{title}</CardTitle>
        <Badge
          variant="secondary"
          className="border-none tabular-nums text-muted-foreground"
        >
          {count}
        </Badge>
      </CardHeader>
      <CardContent className="pt-4">
        {isEmpty ? (
          <p className="text-sm text-muted-foreground">{emptyText}</p>
        ) : (
          children
        )}
      </CardContent>
    </DashboardCard>
  )
}

/**
 * The full scan report, identical for a live scan and a replayed gallery pick,
 * rendered in the efferd dashboard layout: the verdict banner, the at-a-glance
 * {@link ScanDashboard} overview, then a seamed grid of evidence cards, one
 * redirect cascade set, reputation, injection signals, and the re-verifiable
 * proof chain. It reads only the {@link ScanResult} prop and owns no scan or
 * network state, so the render path is byte-for-byte the same regardless of
 * where the result came from. Its sole side effect resets the window scroll to
 * the top when a new result is shown (keyed on the proof head hash), so every
 * report opens at the verdict and dashboard instead of inheriting the page's
 * prior scroll position.
 *
 * Time complexity: O(c + r + f + n) over chains, reputation reports, injection
 * findings and proof steps. Space complexity: O(1) beyond the rendered tree.
 */
export function ResultView({ result }: ResultViewProps): ReactNode {
  useScrollToTopOnChange(result.proof.headHash)
  return (
    <div className="result">
      <VerdictBanner verdict={result.verdict} findingsCount={result.findings.length} />

      <ScanDashboard result={result} />

      <div className="grid gap-px overflow-hidden rounded-xl bg-border p-px ring-1 ring-foreground/10 lg:grid-cols-2">
        <EvidenceCard
          title="Redirect Cascades"
          count={result.chains.length}
          isEmpty={result.chains.length === 0}
          emptyText="No links to trace."
          className="lg:col-span-2"
        >
          <div className="result__chains">
            {result.chains.map((chain, index) => (
              <RedirectChain key={chain.origin} chain={chain} index={index} />
            ))}
          </div>
        </EvidenceCard>

        <EvidenceCard
          title="Reputation"
          count={result.reputation.length}
          isEmpty={result.reputation.length === 0}
          emptyText="No destinations assessed."
        >
          <ReputationRows reports={result.reputation} />
        </EvidenceCard>

        <EvidenceCard
          title="Injection Signals"
          count={result.injections.length}
          isEmpty={result.injections.length === 0}
          emptyText="No injection detected"
        >
          <InjectionRows findings={result.injections} />
        </EvidenceCard>

        <EvidenceCard
          title="Proof Chain"
          count={result.proof.steps.length}
          isEmpty={result.proof.steps.length === 0}
          emptyText="No proof steps."
          className="lg:col-span-2"
        >
          <p className="result__scanned">Scanned {formatTimestamp(result.scannedAt)}</p>
          <ProofViewer proof={result.proof} />
        </EvidenceCard>
      </div>
    </div>
  )
}
