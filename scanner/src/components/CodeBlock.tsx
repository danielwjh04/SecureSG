/**
 * A frosted, copy-to-clipboard code snippet. Renders monospace source inside a
 * `.liquid-glass` panel with a language header and a copy button that flips to a
 * confirmation check for a moment after a successful copy.
 *
 * Used by the Enterprise page's API-integration section; kept generic so any
 * surface can drop in a labelled snippet.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'

interface CodeBlockProps {
  /** Short language/format label shown in the header (e.g. "bash", "node"). */
  language: string
  /** The snippet body, rendered verbatim in a monospace block. */
  code: string
}

/** How long the copy button stays in its confirmed state, in milliseconds. */
const COPIED_RESET_MS = 1500

export function CodeBlock({ language, code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Clear any pending reset timer if the component unmounts mid-confirmation.
  useEffect(() => {
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current)
    }
  }, [])

  const handleCopy = useCallback(async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(code)
    } catch {
      // Clipboard may be unavailable (insecure context / denied permission).
      // Surfacing nothing is correct here: the snippet is still visible to copy
      // manually, and this is a presentation surface, not a security path.
      return
    }
    setCopied(true)
    if (timerRef.current !== null) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), COPIED_RESET_MS)
  }, [code])

  return (
    <div className="liquid-glass rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.06]">
        <span className="font-mono text-[10px] tracking-[0.2em] uppercase text-white/45">
          {language}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          aria-label="Copy code"
          className="glass-pill flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium text-white/60 hover:text-white transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-allow" />
              <span className="text-allow">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              Copy
            </>
          )}
        </button>
      </div>
      <pre className="px-4 py-3.5 overflow-x-auto font-mono text-[12px] leading-relaxed text-white/80">
        <code>{code}</code>
      </pre>
    </div>
  )
}
