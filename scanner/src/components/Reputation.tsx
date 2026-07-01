import type { ReactNode } from 'react'
import type { ReputationReport } from '../api/types'
import type { ApiResource } from '../hooks/useApiResource'
import { hostname } from '../lib/format'
import { Panel } from './Panel'

/**
 * Clamp a stringified reputation score to a 0-100% bar width.
 *
 * `ReputationReport.score` is a stringified float (the contract keeps floats out
 * of the hashed proof), so it is parsed here only for display. A score outside
 * [0, 1] or one that fails to parse collapses to 0% rather than producing an
 * invalid width, so the bar always renders.
 *
 * Time complexity: O(n) in the string length. Space complexity: O(1).
 */
function scoreWidth(score: string): string {
  const value = Number.parseFloat(score)
  if (Number.isNaN(value)) return '0%'
  const clamped = Math.min(Math.max(value, 0), 1)
  return `${clamped * 100}%`
}

/**
 * The reputation rows only: one row per assessed final destination (hostname,
 * the reputation score as a bar, the status text, and a block-tinted flagged
 * badge when the URL is flagged). Header and empty state are the caller's job,
 * so the same rows render inside the {@link Panel}-based {@link Reputation} and
 * inside the efferd dashboard cards without duplicating the row markup.
 *
 * Time complexity: O(r) where r = reports.length. Space complexity: O(r).
 */
export function ReputationRows({ reports }: { reports: ReputationReport[] }): ReactNode {
  return (
    <div className="exa">
      {reports.map((report) => (
        <div className="exa__row" key={report.url}>
          <span className="exa__host" title={report.url}>
            {hostname(report.url)}
          </span>
          <span
            className="exa__bar"
            role="img"
            aria-label={`reputation score ${report.score} of 1`}
            title={`score ${report.score}`}
          >
            <span
              className="exa__bar-fill"
              style={{ width: scoreWidth(report.score) }}
            />
          </span>
          {report.flagged ? (
            <span className="exa__flagged">{report.status}</span>
          ) : (
            <span className="exa__status">{report.status}</span>
          )}
        </div>
      ))}
    </div>
  )
}

/**
 * Reputation panel. Wraps {@link ReputationRows} in the shared {@link Panel} for
 * the modal surfaces, so it owns the header, count, and empty state.
 *
 * The incoming `reports` array rides on an already-resolved `ScanResult`, so it
 * is wrapped in a settled {@link ApiResource} to reuse Panel's head and
 * empty-state rendering without a redundant fetch.
 *
 * Time complexity: O(r) where r = reports.length. Space complexity: O(r).
 */
export function Reputation({ reports }: { reports: ReputationReport[] }): ReactNode {
  const resource: ApiResource<ReputationReport[]> = {
    data: reports,
    error: null,
    loading: false,
    reload: () => {},
  }
  return (
    <Panel<ReputationReport[]>
      title="Reputation"
      count={reports.length}
      resource={resource}
      emptyText="No destinations assessed."
      isEmpty={(data) => data.length === 0}
    >
      {(data) => <ReputationRows reports={data} />}
    </Panel>
  )
}
