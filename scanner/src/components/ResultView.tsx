import type { ReactNode } from 'react'
import type { LinkChain, ScanResult } from '../api/types'
import type { ApiResource } from '../hooks/useApiResource'
import { VerdictBanner } from './VerdictBanner'
import { ScanDashboard } from './ScanDashboard'
import { RedirectChain } from './RedirectChain'
import { Reputation } from './Reputation'
import { InjectionFindings } from './InjectionFindings'
import { ProofViewer } from './ProofViewer'
import { Panel } from './Panel'
import { useScrollToTopOnChange } from '../hooks/useScrollToTopOnChange'
import { formatTimestamp } from '../lib/format'

interface ResultViewProps {
  result: ScanResult
}

/** Wrap an already-resolved value in a settled resource for {@link Panel}. */
function settled<T>(data: T): ApiResource<T> {
  return { data, error: null, loading: false, reload: () => {} }
}

/**
 * The full scan report, identical for a live scan and a replayed gallery pick.
 *
 * Composes the evidence in fixed order — verdict banner, the at-a-glance scan
 * dashboard, one redirect cascade per traced origin, reputation, injection
 * findings, then the re-verifiable proof chain. It reads only the
 * {@link ScanResult} prop and owns no scan or network state, so the render path
 * is byte-for-byte the same regardless of where the result came from. Its sole
 * side effect resets the window scroll to the top when a new result is shown
 * (keyed on the proof head hash), so every report opens at the verdict and
 * dashboard instead of inheriting the page's prior scroll position.
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

      <Panel<LinkChain[]>
        title="Redirect Cascades"
        count={result.chains.length}
        resource={settled(result.chains)}
        emptyText="No links to trace."
        isEmpty={(data) => data.length === 0}
      >
        {(chains) => (
          <div className="result__chains">
            {chains.map((chain, index) => (
              <RedirectChain key={chain.origin} chain={chain} index={index} />
            ))}
          </div>
        )}
      </Panel>

      <Reputation reports={result.reputation} />

      <InjectionFindings findings={result.injections} />

      <Panel<ScanResult>
        title="Proof Chain"
        count={result.proof.steps.length}
        resource={settled(result)}
        emptyText="No proof steps."
        isEmpty={(data) => data.proof.steps.length === 0}
      >
        {(data) => (
          <>
            <p className="result__scanned">Scanned {formatTimestamp(data.scannedAt)}</p>
            <ProofViewer proof={data.proof} />
          </>
        )}
      </Panel>
    </div>
  )
}
