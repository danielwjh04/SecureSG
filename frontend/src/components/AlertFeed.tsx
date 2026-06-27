import { getAlerts } from '../api/client'
import type { AlertView } from '../api/types'
import { useApiResource } from '../hooks/useApiResource'
import { AlertCard } from './AlertCard'
import { Panel } from './Panel'

export function AlertFeed({ refreshTick }: { refreshTick: number }) {
  const alerts = useApiResource(getAlerts, refreshTick)
  return (
    <Panel<AlertView[]>
      title="Alert Feed"
      count={alerts.data?.length}
      resource={alerts}
      emptyText="No alerts yet — run the demo to trigger an injection."
      isEmpty={(data) => data.length === 0}
      flush
    >
      {(data) => (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Source Entity</th>
                <th>Date Processed</th>
                <th>Content Preview</th>
                <th>Provenance</th>
              </tr>
            </thead>
            <tbody>
              {data.map((alert) => (
                <AlertCard key={alert.id} alert={alert} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
