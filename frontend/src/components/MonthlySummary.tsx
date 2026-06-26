import { getSummary } from '../api/client'
import type { CategoryCount, SummaryReport } from '../api/types'
import { useApiResource } from '../hooks/useApiResource'
import { Panel } from './Panel'

function SummaryRow({ row, max }: { row: CategoryCount; max: number }) {
  const width = (value: number): string => (max > 0 ? `${(value / max) * 100}%` : '0%')
  return (
    <div className="summary__row">
      <span className="summary__label">{row.category}</span>
      <div className="bar">
        <div className="bar__seg bar__seg--allow" style={{ width: width(row.allow) }} />
        <div
          className="bar__seg bar__seg--approval"
          style={{ width: width(row.human_approval_required) }}
        />
        <div className="bar__seg bar__seg--block" style={{ width: width(row.block) }} />
      </div>
      <span className="summary__total">{row.total}</span>
    </div>
  )
}

export function MonthlySummary({ refreshTick }: { refreshTick: number }) {
  const summary = useApiResource(() => getSummary(30), refreshTick)
  return (
    <Panel<SummaryReport>
      title="Monthly Summary"
      resource={summary}
      emptyText="No verdicts recorded in the window yet."
      isEmpty={(data) => data.categories.length === 0}
    >
      {(data) => {
        const max = Math.max(1, ...data.categories.map((category) => category.total))
        return (
          <>
            <div className="legend">
              <span className="legend__item">
                <span className="legend__swatch" style={{ background: 'var(--allow)' }} />
                Allow
              </span>
              <span className="legend__item">
                <span
                  className="legend__swatch"
                  style={{ background: 'var(--approval)' }}
                />
                Approval
              </span>
              <span className="legend__item">
                <span className="legend__swatch" style={{ background: 'var(--block)' }} />
                Block
              </span>
            </div>
            {data.categories.map((category) => (
              <SummaryRow key={category.category} row={category} max={max} />
            ))}
          </>
        )
      }}
    </Panel>
  )
}
