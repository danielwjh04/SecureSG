import type { ReactNode } from 'react'
import type { ApiResource } from '../hooks/useApiResource'

interface PanelProps<T> {
  title: string
  count?: number
  resource: ApiResource<T>
  emptyText: string
  isEmpty: (data: T) => boolean
  children: (data: T) => ReactNode
}

// Shared panel chrome: shows a first-load spinner / error / empty state, but
// keeps rendering existing data during a background refetch (no flicker).
export function Panel<T>({
  title,
  count,
  resource,
  emptyText,
  isEmpty,
  children,
}: PanelProps<T>): ReactNode {
  const { data, error, loading } = resource
  let body: ReactNode
  if (data === null) {
    body = error ? (
      <div className="panel__state panel__state--error">{error}</div>
    ) : (
      <div className="panel__state">{loading ? 'Loading…' : emptyText}</div>
    )
  } else if (isEmpty(data)) {
    body = <div className="panel__state">{emptyText}</div>
  } else {
    body = children(data)
  }
  return (
    <section className="panel">
      <div className="panel__head">
        <h2>{title}</h2>
        {count !== undefined && <span className="panel__count">{count}</span>}
      </div>
      <div className="panel__body">{body}</div>
    </section>
  )
}
