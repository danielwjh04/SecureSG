import { useEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import {
  Check,
  Code2,
  Copy,
  Globe2,
  MonitorCog,
  RefreshCw,
  Terminal,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { rotateApiKey } from '../api/client'
import {
  BROWSER_EXTENSION_STORE_URL,
  browserPairingUrl,
  guardInstallCommand,
} from '../config'

const COPY_FEEDBACK_MS = 1500

/** Authenticated integrations setup page. */
export function Integrations() {
  const [command, setCommand] = useState<string | null>(null)
  const [pairing, setPairing] = useState<string | null>(null)
  const [busy, setBusy] = useState<'installer' | 'browser' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const mintInstaller = async (): Promise<void> => {
    setBusy('installer')
    setError(null)
    try {
      const { apiKey } = await rotateApiKey()
      setCommand(guardInstallCommand(apiKey))
    } catch {
      setError('Could not generate an install command.')
    } finally {
      setBusy(null)
    }
  }

  const pairBrowser = async (): Promise<void> => {
    setBusy('browser')
    setError(null)
    try {
      const { apiKey } = await rotateApiKey()
      const url = browserPairingUrl(apiKey)
      setPairing(url)
      window.open(url, '_blank', 'noopener,noreferrer')
      if (BROWSER_EXTENSION_STORE_URL.length > 0) {
        window.open(BROWSER_EXTENSION_STORE_URL, '_blank', 'noopener,noreferrer')
      }
    } catch {
      setError('Could not generate a browser pairing link.')
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="relative z-10 flex-1">
      <div className="max-w-5xl mx-auto px-6 py-10 flex flex-col gap-6">
        <Header />

        <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-white text-sm font-semibold">Endpoint installer</span>
              <span className="text-white/50 text-[13px]">
                Wire Claude Code, Cursor, Codex, and browser pairing from one command.
              </span>
            </div>
            <button
              type="button"
              onClick={mintInstaller}
              disabled={busy !== null}
              className="inline-flex items-center justify-center gap-2 rounded-full bg-white px-5 py-2.5 text-[13px] font-semibold text-black hover:bg-white/90 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-4 h-4 ${busy === 'installer' ? 'animate-spin' : ''}`} />
              Generate command
            </button>
          </div>
          {command !== null && (
            <div className="flex items-stretch gap-2">
              <code className="flex-1 min-w-0 overflow-x-auto rounded-xl bg-white/[0.04] border border-white/10 px-3.5 py-2.5 font-mono text-[12px] text-allow whitespace-nowrap">
                {command}
              </code>
              <CopyButton value={command} label="Copy install command" />
            </div>
          )}
          {error !== null && <p className="text-block/90 font-mono text-[12px]">{error}</p>}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <IntegrationCard
            Icon={Terminal}
            title="Claude Code"
            body="PreToolUse checks route shell and tool actions through SecureAI."
          />
          <IntegrationCard
            Icon={MonitorCog}
            title="Cursor"
            body="Shell and MCP hooks call the same guard contract and fail closed."
          />
          <IntegrationCard
            Icon={Code2}
            title="Codex"
            body="Tool calls can be checked before execution through the Codex adapter."
          />
          <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-4">
            <Globe2 className="w-5 h-5 text-white/75" />
            <div className="flex flex-col gap-1">
              <h2 className="text-white text-sm font-semibold">Browser</h2>
              <p className="text-white/55 text-[13px] leading-relaxed">
                Scans browser-visible content before supported AI tools read it and
                blocks learned risky destinations locally.
              </p>
            </div>
            <button
              type="button"
              onClick={pairBrowser}
              disabled={busy !== null}
              className="glass-pill self-start inline-flex items-center gap-2 px-4 py-2 text-[13px] font-medium text-white/80 hover:text-white transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${busy === 'browser' ? 'animate-spin' : ''}`} />
              Pair browser
            </button>
            {pairing !== null && (
              <div className="flex items-stretch gap-2">
                <code className="flex-1 min-w-0 overflow-x-auto rounded-xl bg-white/[0.04] border border-white/10 px-3 py-2 font-mono text-[12px] text-allow whitespace-nowrap">
                  {pairing}
                </code>
                <CopyButton value={pairing} label="Copy browser pairing link" />
              </div>
            )}
            <p className="text-white/40 text-[12px] leading-relaxed">
              SecureAI cannot see actions an AI provider runs only on its own servers.
            </p>
          </div>
        </div>
      </div>
    </section>
  )
}

function Header() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-1.5"
    >
      <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
        Integrations
      </span>
      <h1
        style={{ fontFamily: "'Instrument Serif', serif" }}
        className="text-3xl md:text-[38px] font-medium text-white leading-tight"
      >
        Connect your AI tools
      </h1>
    </motion.div>
  )
}

function IntegrationCard({
  Icon,
  title,
  body,
}: {
  Icon: LucideIcon
  title: string
  body: string
}) {
  return (
    <div className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
      <Icon className="w-5 h-5 text-white/75" />
      <h2 className="text-white text-sm font-semibold">{title}</h2>
      <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
    </div>
  )
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current)
    }
  }, [])

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      if (timerRef.current !== null) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setCopied(false), COPY_FEEDBACK_MS)
    } catch {
      /* clipboard denied: the value stays visible */
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      className="glass-pill inline-flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium text-white/70 hover:text-white transition-colors cursor-pointer shrink-0"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-allow" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}
