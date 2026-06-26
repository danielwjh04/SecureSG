import { useState } from 'react'
import { ApiError, postReport } from '../api/client'
import type { AlertView, IncidentReport } from '../api/types'
import { formatTimestamp } from '../lib/format'

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
    <div className="alert">
      <div className="alert__top">
        <span className="alert__cat">{alert.category}</span>
        <span className="alert__rule">{alert.rule_id}</span>
      </div>
      <div className="alert__reason">{alert.reason}</div>
      <div className="alert__payload">{alert.redacted_payload}</div>
      <div className="alert__foot">
        <span className="alert__time">{formatTimestamp(alert.created_at)}</span>
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
      {error !== null && <div className="panel__state panel__state--error">{error}</div>}
      {report !== null && (
        <div className="report">
          <span>Incident report</span>
          <span className={`chain ${chainOk ? 'chain--ok' : 'chain--broken'}`}>
            {chainOk ? '● CHAIN INTACT' : `● ${report.chain_status}`}
          </span>
          {report.first_invalid_seq !== null && (
            <span className="mono">seq {report.first_invalid_seq}</span>
          )}
        </div>
      )}
    </div>
  )
}
