import { useEffect, useState } from 'react'

// Coalesces a rapidly-changing value (the live event counter) so dependent
// panels refetch once per burst instead of once per event.
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}
