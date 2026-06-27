import { useState } from 'react'
import { ApiError, postReport } from '../api/client'
import type { AlertView, IncidentReport } from '../api/types'
import { formatTimestamp } from '../lib/format'

function categoryIcon(category: string): string {
  if (category.toLowerCase().includes('injection')) return 'bug_report'
  if (category.toLowerCase().includes('exfil')) return 'cloud_upload'
  if (category.toLowerCase().includes('secret')) return 'key'
  if (category.toLowerCase().includes('drift')) return 'trending_up'
  return 'warning'
}

export function AlertCard({ alert }: { alert: AlertView }) {
  const [report, setReport] = useState<IncidentReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const generate = async (): Promise<void> => {
    setLoading(true)
    setError(null)
    try {
      setReport(await postReport(alert.id))
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'report failed')
    } finally {
      setLoading(false)
    }
  }

  const chainOk = report?.chain_status === 'CHAIN_OK'

  return (
    <>
      <tr className="alert-row">
        <td className="alert-row__cell">
          <div className="alert-row__entity">
            <span className="material-symbols-outlined alert-row__icon">{categoryIcon(alert.category)}</span>
            <div>
              <span className="alert-row__name">{alert.category}</span>
              <span className="alert-row__sub">{alert.rule_id}</span>
            </div>
          </div>
        </td>
        <td className="alert-row__cell alert-row__date">{formatTimestamp(alert.created_at)}</td>
        <td className="alert-row__cell alert-row__preview">
          <div className="alert-row__content">{alert.reason}</div>
        </td>
        <td className="alert-row__cell">
          <div className="alert-row__actions">
            {alert.tool_name !== null && (
              <span className="alert-row__provenance">{alert.tool_name}</span>
            )}
            {report === null && (
              <button
                className="btn btn--ghost"
                onClick={() => void generate()}
                disabled={loading}
              >
                {loading ? 'Generating…' : 'Flag & report'}
              </button>
            )}
          </div>
        </td>
      </tr>
      {error !== null && (
        <tr className="alert-row alert-row--meta">
          <td className="alert-row__cell" colSpan={4}>
            <span className="panel__state--error" style={{ fontSize: 12 }}>{error}</span>
          </td>
        </tr>
      )}
      {report !== null && (
        <tr className="alert-row alert-row--meta">
          <td className="alert-row__cell" colSpan={4}>
            <div className="report">
              <span>Incident report</span>
              <span className={`chain ${chainOk ? 'chain--ok' : 'chain--broken'}`}>
                {chainOk ? '● CHAIN INTACT' : `● ${report.chain_status}`}
              </span>
              {report.first_invalid_seq !== null && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>seq {report.first_invalid_seq}</span>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
