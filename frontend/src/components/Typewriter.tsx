import { useEffect, useState } from 'react'

// Reveals text client-side (the backend sends content once, unpaced).
export function Typewriter({
  text,
  charsPerTick = 3,
  tickMs = 30,
}: {
  text: string
  charsPerTick?: number
  tickMs?: number
}) {
  const [shown, setShown] = useState(0)
  useEffect(() => {
    setShown(0)
    if (text.length === 0) return
    const timer = setInterval(() => {
      setShown((value) => {
        if (value >= text.length) {
          clearInterval(timer)
          return value
        }
        return Math.min(value + charsPerTick, text.length)
      })
    }, tickMs)
    return () => clearInterval(timer)
  }, [text, charsPerTick, tickMs])

  const done = shown >= text.length
  return (
    <span className="statusbar__text">
      {text.slice(0, shown)}
      {!done && <span className="caret">▋</span>}
    </span>
  )
}
