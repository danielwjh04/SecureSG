import type { ReactNode } from 'react'
import type { InjectionFinding } from '../api/types'
import type { ApiResource } from '../hooks/useApiResource'
import { Panel } from './Panel'
import { StatusPill } from './StatusPill'

/**
 * Prompt-injection findings panel. Renders one block per signal surfaced by the
 * AI injection check: the category badge, a {@link StatusPill} for the finding's
 * severity, the flagged excerpt in a mono block, and the analysis rationale. The
 * empty state ("No injection detected") is owned by {@link Panel} via `isEmpty`.
 *
 * The incoming `findings` array rides on an already-resolved `ScanResult`, so it
 * is wrapped in a settled {@link ApiResource} to reuse Panel's head and
 * empty-state rendering without a redundant fetch.
 *
 * Time complexity: O(f) where f = findings.length. Space complexity: O(f).
 */
export function InjectionFindings({
  findings,
}: {
  findings: InjectionFinding[]
}): ReactNode {
  const resource: ApiResource<InjectionFinding[]> = {
    data: findings,
    error: null,
    loading: false,
    reload: () => {},
  }
  return (
    <Panel<InjectionFinding[]>
      title="Injection Findings"
      count={findings.length}
      resource={resource}
      emptyText="No injection detected"
      isEmpty={(data) => data.length === 0}
    >
      {(data) => (
        <div className="injection">
          {data.map((finding, index) => (
            <div className="injection__item" key={`${finding.category}-${index}`}>
              <span className="injection__cat">{finding.category}</span>
              <StatusPill verdict={finding.severity} />
              <pre className="injection__excerpt">{finding.excerpt}</pre>
              <p className="injection__rationale">{finding.rationale}</p>
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}
