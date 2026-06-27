import type { ReactNode } from 'react'
import type { ApiResource } from '../hooks/useApiResource'

interface PanelProps<T> {
  title: string
  count?: number
  resource: ApiResource<T>
  emptyText: string
  isEmpty: (data: T) => boolean
  flush?: boolean
  children: (data: T) => ReactNode
}

export function Panel<T>({
  title,
  count,
  resource,
  emptyText,
  isEmpty,
  flush,
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
  const bodyClass = flush ? 'panel__body panel__body--flush' : 'panel__body'
  return (
    <section className="panel">
      <div className="panel__head">
        <h2>{title}</h2>
        {count !== undefined && <span className="panel__count">{count}</span>}
      </div>
      <div className={bodyClass}>{body}</div>
    </section>
  )
}
