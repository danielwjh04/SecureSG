import { getRegistry } from '../api/client'
import type { RegistryEntry } from '../api/types'
import { useApiResource } from '../hooks/useApiResource'
import { formatTimestamp } from '../lib/format'
import { Panel } from './Panel'

export function SafeContentRegistry({ refreshTick }: { refreshTick: number }) {
  const registry = useApiResource(getRegistry, refreshTick)
  return (
    <Panel<RegistryEntry[]>
      title="Safe Content Registry"
      count={registry.data?.length}
      resource={registry}
      emptyText="No verified-clean content yet."
      isEmpty={(data) => data.length === 0}
    >
      {(data) => (
        <>
          {data.map((entry) => (
            <div className="registry__item" key={entry.id}>
              <div className="registry__top">
                <span className="registry__tool">{entry.tool_name}</span>
                <span className="alert__time">{formatTimestamp(entry.created_at)}</span>
              </div>
              <div className="registry__content">{entry.redacted_content}</div>
            </div>
          ))}
        </>
      )}
    </Panel>
  )
}
