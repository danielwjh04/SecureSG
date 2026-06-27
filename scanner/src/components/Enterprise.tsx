/**
 * The Enterprise page: pitches teams on wiring the Skill Safety Scanner into
 * their agent pipeline so every skill or tool a coding agent is about to learn
 * or call is scanned and must return ALLOW (fail-closed) before it runs.
 *
 * It renders inside a scrollable dark page whose parent supplies the black
 * background, the fixed background video, and the navbar — so this component
 * sets no page background and owns only a centered max-width column.
 *
 * The KPI row uses REAL data: it fetches the committed public gallery and
 * derives honest counts (skills scanned, threats caught, proof links sealed)
 * rather than fabricating customer metrics.
 */

import { useEffect, useMemo, useState } from 'react'
import { motion } from 'motion/react'
import {
  ArrowRight,
  ArrowUpCircle,
  Boxes,
  FileCheck,
  GitBranch,
  Link2,
  Radar,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { GalleryData } from '../api/types'
import { GALLERY_DATA_PATH } from '../config'
import { REPO_URL } from '../config'
import { CodeBlock } from './CodeBlock'

/** The empty dataset used whenever the gallery file is absent or unreadable. */
const EMPTY_GALLERY: GalleryData = { generatedAt: '', entries: [] }

/** Honest, gallery-derived numbers shown in the KPI row. */
interface GalleryStats {
  skills: number
  threats: number
  proofLinks: number
}

/**
 * Fetch the prebuilt public gallery, degrading to an empty dataset on any
 * failure (a missing or malformed file is an expected, non-error state).
 *
 * Time complexity: O(n) in the response body size. Space complexity: O(n).
 */
async function fetchGallery(): Promise<GalleryData> {
  let response: Response
  try {
    response = await fetch(GALLERY_DATA_PATH)
  } catch {
    return EMPTY_GALLERY
  }
  if (!response.ok) return EMPTY_GALLERY
  try {
    const data = (await response.json()) as GalleryData
    return Array.isArray(data.entries) ? data : EMPTY_GALLERY
  } catch {
    return EMPTY_GALLERY
  }
}

/**
 * Reduce a gallery dataset to honest headline numbers: how many skills are in
 * the live public gallery, how many came back BLOCK (threats caught), and the
 * total number of sealed proof steps across every entry (cryptographic links).
 *
 * Time complexity: O(e) over entries e. Space complexity: O(1).
 */
function deriveStats(data: GalleryData): GalleryStats {
  let threats = 0
  let proofLinks = 0
  for (const entry of data.entries) {
    if (entry.result.verdict === 'BLOCK') threats += 1
    proofLinks += entry.result.proof.steps.length
  }
  return { skills: data.entries.length, threats, proofLinks }
}

/** A single API snippet tab. */
interface Snippet {
  id: string
  tab: string
  language: string
  code: string
}

/**
 * Build the three copy-paste-runnable API snippets against the live origin, so
 * a reader can run them as-is. `origin` is resolved at call time from
 * `window.location.origin` (with a safe fallback for non-browser builds).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function buildSnippets(origin: string): Snippet[] {
  return [
    {
      id: 'curl',
      tab: 'curl',
      language: 'bash',
      code: `# Scan a skill before an agent is allowed to learn it.
curl -sS -X POST ${origin}/api/scan \\
  -H 'content-type: application/json' \\
  -d '{"sourceUrl":"https://github.com/owner/repo"}'

# Or scan pasted SKILL.md text directly:
curl -sS -X POST ${origin}/api/scan \\
  -H 'content-type: application/json' \\
  -d '{"content":"# My Skill\\n..."}'`,
    },
    {
      id: 'node',
      tab: 'node · fetch',
      language: 'node',
      code: `// Gate a skill on the verdict: anything not ALLOW is refused.
const ORIGIN = '${origin}'

export async function scanOrThrow(input) {
  const res = await fetch(\`\${ORIGIN}/api/scan\`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input), // { content } or { sourceUrl }
  })
  if (!res.ok) throw new Error(\`scan failed: \${res.status}\`)

  const result = await res.json()
  // Fail-closed: only an explicit ALLOW lets the skill through.
  if (result.verdict !== 'ALLOW') {
    throw new Error(\`skill blocked (\${result.verdict})\`)
  }
  return result // carries a re-verifiable SHA-256 proof
}`,
    },
    {
      id: 'hook',
      tab: 'agent hook',
      language: 'node',
      code: `// PreToolUse-style guard: run before an agent loads a skill or
// calls a tool. Refuse unless Bastion returns ALLOW.
const ORIGIN = '${origin}'

export async function preToolUse({ skillUrl, skillText }) {
  const body = skillUrl ? { sourceUrl: skillUrl } : { content: skillText }
  const res = await fetch(\`\${ORIGIN}/api/scan\`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

  // Unjudged == unsafe. A transport failure is a BLOCK, never an ALLOW.
  if (!res.ok) return { decision: 'BLOCK', reason: 'scanner unreachable' }

  const { verdict, proof } = await res.json()
  if (verdict === 'ALLOW') return { decision: 'ALLOW', proof }

  // BLOCK / HUMAN_APPROVAL_REQUIRED: stop the agent, keep the proof.
  return { decision: 'BLOCK', verdict, proof }
}`,
    },
  ]
}

/** One stat card descriptor for the KPI row. */
interface Kpi {
  Icon: LucideIcon
  value: string
  label: string
  footnote: string
  accent: string
}

/** A guarantee card descriptor. */
interface Guarantee {
  Icon: LucideIcon
  title: string
  body: string
}

const GUARANTEES: Guarantee[] = [
  {
    Icon: ShieldCheck,
    title: 'Fail-closed',
    body: 'Anything we cannot judge is blocked. An unreachable scanner is a BLOCK, never an ALLOW.',
  },
  {
    Icon: ArrowUpCircle,
    title: 'Tighten-only',
    body: 'The model can only raise severity. It can sharpen a verdict but can never overturn a block.',
  },
  {
    Icon: FileCheck,
    title: 'Tamper-evident proof',
    body: 'Every verdict is a SHA-256 chain over the evidence. Anyone can re-verify it byte for byte.',
  },
]

/** Shared entrance transition, matching the hero's easing. */
const RISE = {
  initial: { opacity: 0, y: 20 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

export function Enterprise() {
  const [stats, setStats] = useState<GalleryStats | null>(null)
  const [activeTab, setActiveTab] = useState<string>('curl')

  // Derive honest KPI numbers from the committed public gallery on mount.
  useEffect(() => {
    let active = true
    fetchGallery().then((data) => {
      if (active) setStats(deriveStats(data))
    })
    return () => {
      active = false
    }
  }, [])

  const origin =
    typeof window !== 'undefined' ? window.location.origin : 'https://your-scanner.example'
  const snippets = useMemo(() => buildSnippets(origin), [origin])
  const activeSnippet =
    snippets.find((snippet) => snippet.id === activeTab) ?? snippets[0]

  const kpis: Kpi[] = useMemo(
    () => [
      {
        Icon: Boxes,
        value: stats ? String(stats.skills) : '…',
        label: 'Skills scanned',
        footnote: 'Live in our public gallery',
        accent: 'text-white',
      },
      {
        Icon: ShieldAlert,
        value: stats ? String(stats.threats) : '…',
        label: 'Threats caught',
        footnote: 'Returned BLOCK before running',
        accent: 'text-block',
      },
      {
        Icon: Link2,
        value: stats ? String(stats.proofLinks) : '…',
        label: 'Proof links sealed',
        footnote: 'SHA-256 steps across all scans',
        accent: 'text-allow',
      },
      {
        Icon: ShieldCheck,
        value: '100%',
        label: 'Re-verifiable',
        footnote: 'Fail-closed by construction',
        accent: 'text-allow',
      },
    ],
    [stats],
  )

  return (
    <div className="relative z-10 max-w-5xl mx-auto px-6 py-12 flex flex-col gap-20">
      {/* 1 · Intro --------------------------------------------------------- */}
      <motion.section {...RISE} className="flex flex-col items-center text-center gap-6">
        <p className="flex items-center gap-2 text-white/70 text-[10px] md:text-[11px] font-medium tracking-[0.22em] uppercase font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          Bastion for teams
        </p>
        <h1
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-4xl md:text-[56px] font-medium tracking-[-0.01em] leading-[1.08] bg-gradient-to-b from-white via-white to-white/85 bg-clip-text text-transparent"
        >
          Verify before your agents act.
        </h1>
        <p className="text-white/70 text-sm md:text-[15px] leading-relaxed max-w-2xl">
          Wire Bastion into your agent pipeline so every skill or tool a coding
          agent is about to learn or call is scanned first. Each request must
          come back <span className="text-allow font-medium">ALLOW</span>. It is
          fail-closed, so anything we cannot judge is blocked before it runs.
        </p>
      </motion.section>

      {/* 2 · KPI dashboard ------------------------------------------------- */}
      <motion.section {...RISE} className="flex flex-col gap-4">
        <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.22em] text-white/45">
          <span className="w-1.5 h-1.5 rounded-full bg-allow live-dot" />
          Live from our public gallery
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {kpis.map(({ Icon, value, label, footnote, accent }) => (
            <div key={label} className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
              <Icon className={`w-5 h-5 ${accent}`} />
              <div
                className={`text-3xl md:text-4xl font-medium tabular-nums ${accent}`}
                style={{ fontFamily: "'Instrument Serif', serif" }}
              >
                {value}
              </div>
              <div className="text-white/80 text-sm font-medium">{label}</div>
              <div className="text-white/45 text-[11px] leading-snug font-mono">
                {footnote}
              </div>
            </div>
          ))}
        </div>
      </motion.section>

      {/* 3 · API integration ---------------------------------------------- */}
      <motion.section {...RISE} className="flex flex-col gap-5">
        <div className="flex flex-col gap-2">
          <h2
            style={{ fontFamily: "'Instrument Serif', serif" }}
            className="text-2xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
          >
            Call it from your pipeline.
          </h2>
          <p className="text-white/55 text-sm md:text-[15px] leading-relaxed max-w-2xl">
            POST a skill (pasted <span className="font-mono text-white/80">content</span> or
            a <span className="font-mono text-white/80">sourceUrl</span>) to{' '}
            <span className="font-mono text-white/80">/api/scan</span>. You get a{' '}
            <span className="font-mono text-white/80">verdict</span> plus a
            re-verifiable proof. Re-check any proof later by POSTing it to{' '}
            <span className="font-mono text-white/80">/api/verify</span>, which
            returns <span className="font-mono text-allow">CHAIN_OK</span> or{' '}
            <span className="font-mono text-block">CHAIN_BROKEN</span>.
          </p>
        </div>

        {/* Tabbed snippet switcher */}
        <div className="flex flex-wrap gap-2">
          {snippets.map((snippet) => {
            const active = snippet.id === activeTab
            return (
              <button
                key={snippet.id}
                type="button"
                onClick={() => setActiveTab(snippet.id)}
                className={`glass-pill px-3.5 py-1.5 text-[11px] font-mono tracking-wide transition-colors ${
                  active ? 'text-white' : 'text-white/45 hover:text-white/70'
                }`}
              >
                {active && <span className="text-allow">› </span>}
                {snippet.tab}
              </button>
            )
          })}
        </div>

        <CodeBlock language={activeSnippet.language} code={activeSnippet.code} />
      </motion.section>

      {/* 4 · How it fits your agents -------------------------------------- */}
      <motion.section {...RISE} className="flex flex-col gap-5">
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-2xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
        >
          How it fits your agents.
        </h2>
        <div className="flex flex-col md:flex-row items-stretch gap-3">
          {/* Step 1 */}
          <div className="liquid-glass rounded-2xl p-5 flex-1 flex flex-col gap-3">
            <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-white/45">
              <span>01</span>
            </div>
            <ScanLine className="w-5 h-5 text-white/80" />
            <div className="text-white text-sm font-medium">Agent reaches a skill</div>
            <p className="text-white/55 text-[13px] leading-relaxed">
              Your agent is about to learn a new skill or call a tool. The
              PreToolUse hook intercepts it before anything executes.
            </p>
          </div>

          <Connector />

          {/* Step 2 */}
          <div className="liquid-glass rounded-2xl p-5 flex-1 flex flex-col gap-3">
            <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-white/45">
              <span>02</span>
            </div>
            <Radar className="w-5 h-5 text-allow" />
            <div className="text-white text-sm font-medium">Bastion scans it</div>
            <p className="text-white/55 text-[13px] leading-relaxed">
              One API call traces every redirect, checks each destination's
              reputation with Exa, and judges the text for injection with OpenAI.
            </p>
          </div>

          <Connector />

          {/* Step 3 */}
          <div className="liquid-glass rounded-2xl p-5 flex-1 flex flex-col gap-3">
            <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-white/45">
              <span>03</span>
            </div>
            <ShieldX className="w-5 h-5 text-block" />
            <div className="text-white text-sm font-medium">
              <span className="text-allow">ALLOW</span> forwards,{' '}
              <span className="text-block">BLOCK</span> stops
            </div>
            <p className="text-white/55 text-[13px] leading-relaxed">
              An ALLOW is forwarded and the skill runs. A{' '}
              <span className="text-block">BLOCK</span> halts the agent and hands
              back a tamper-evident proof of why.
            </p>
          </div>
        </div>
      </motion.section>

      {/* 5 · Guarantees --------------------------------------------------- */}
      <motion.section {...RISE} className="flex flex-col gap-5">
        <h2
          style={{ fontFamily: "'Instrument Serif', serif" }}
          className="text-2xl md:text-[34px] font-medium tracking-[-0.01em] text-white"
        >
          The guarantees you get.
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {GUARANTEES.map(({ Icon, title, body }) => (
            <div key={title} className="liquid-glass rounded-2xl p-5 flex flex-col gap-3">
              <Icon className="w-5 h-5 text-allow" />
              <div className="text-white text-sm font-medium">{title}</div>
              <p className="text-white/55 text-[13px] leading-relaxed">{body}</p>
            </div>
          ))}
        </div>
      </motion.section>

      {/* 6 · CTA ----------------------------------------------------------- */}
      <motion.section
        {...RISE}
        className="flex flex-col sm:flex-row items-center justify-center gap-3 pb-8"
      >
        <a
          href="#"
          className="inline-flex items-center gap-2 rounded-full bg-white px-6 py-3 text-sm font-medium text-black hover:bg-white/90 transition-colors"
        >
          Start scanning
          <ArrowRight className="w-4 h-4" />
        </a>
        <a
          href={REPO_URL}
          target="_blank"
          rel="noreferrer"
          className="glass-pill inline-flex items-center gap-2 px-6 py-3 text-sm font-medium text-white/70 hover:text-white transition-colors"
        >
          <GitBranch className="w-4 h-4" />
          Read the source
        </a>
      </motion.section>
    </div>
  )
}

/** A directional connector (arrow) drawn between the agent-flow steps. */
function Connector() {
  return (
    <div className="flex items-center justify-center text-white/25 md:px-0">
      <ArrowRight className="w-5 h-5 rotate-90 md:rotate-0" />
    </div>
  )
}
