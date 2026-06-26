import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../api/client'

export interface ApiResource<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

// Generic GET resource: fetches on mount and whenever `refreshKey` changes,
// ignoring stale resolutions. The fetcher is read through a ref, so callers need
// not memoize it.
export function useApiResource<T>(
  fetcher: () => Promise<T>,
  refreshKey: number,
): ApiResource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    let active = true
    setLoading(true)
    fetcherRef.current()
      .then((result) => {
        if (active) {
          setData(result)
          setError(null)
        }
      })
      .catch((caught: unknown) => {
        if (active) {
          setError(caught instanceof ApiError ? caught.message : 'unexpected error')
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [refreshKey, nonce])

  return { data, error, loading, reload }
}
