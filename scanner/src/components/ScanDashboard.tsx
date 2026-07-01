import type { ReactNode } from 'react'
import type { LinkChain, ScanResult, Verdict } from '../api/types'
import { cn } from '@/lib/utils'
import { CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { DashboardCard } from '@/components/dashboard-card'
import { formatTimestamp, hostname, truncateHash, verdictLabel } from '../lib/format'

/**
 * The verdict severities in most-to-least severe order. This is the single
 * ordered runtime list of the {@link Verdict} union, so the severity chart and
 * its legend render worst-first without any other dashboard code re-listing the
 * verdicts.
 */
const VERDICTS_BY_SEVERITY: readonly Verdict[] = [
  'BLOCK',
  'HUMAN_APPROVAL_REQUIRED',
  'ALLOW',
]

/**
 * Map a verdict to its design-token color reference, so the chart bars and the
 * legend swatches track the exact same `--block` / `--review` / `--allow`
 * tokens the rest of the app uses. Reading the token keeps the palette in
 * config, never hardcoded here.
 */
const VERDICT_TOKEN: Record<Verdict, string> = {
  BLOCK: 'var(--block)',
  HUMAN_APPROVAL_REQUIRED: 'var(--review)',
  ALLOW: 'var(--allow)',
}

/**
 * A chain is dangerous when it has a flagged hop, loops back on itself, or
 * exceeded the maximum redirect depth. Time complexity: O(1). Space: O(1).
 */
function isDangerousChain(chain: LinkChain): boolean {
  return (
    chain.dangerousHopIndex !== null || chain.loopDetected || chain.depthExceeded
  )
}

/** One at-a-glance metric tile. All fields are derived from the scan result. */
interface StatCard {
  key: string
  label: string
  value: number
  detail: string
  danger: boolean
}

/**
 * Derive the at-a-glance stat tiles from a scan result. Every count and the
 * danger flag are computed from the result; nothing is hardcoded. The danger
 * tint turns on only when that metric contributes a blocking/flagged signal.
 *
 * Time complexity: O(f + c + i + e) over findings, chains, injections and
 * reputation reports. Space complexity: O(1), a fixed set of tiles.
 */
function buildStatCards(result: ScanResult): StatCard[] {
  const blockingFindings = result.findings.filter(
    (finding) => finding.severity === 'BLOCK',
  ).length
  const dangerousChains = result.chains.filter(isDangerousChain).length
  const highInjections = result.injections.filter(
    (injection) => injection.severity === 'BLOCK',
  ).length
  const flaggedReputation = result.reputation.filter((report) => report.flagged).length

  return [
    {
      key: 'findings',
      label: 'Rule Findings',
      value: result.findings.length,
      detail: `${blockingFindings} blocking`,
      danger: blockingFindings > 0,
    },
    {
      key: 'chains',
      label: 'Redirect Cascades',
      value: result.chains.length,
      detail: `${dangerousChains} dangerous`,
      danger: dangerousChains > 0,
    },
    {
      key: 'injections',
      label: 'Injection Signals',
      value: result.injections.length,
      detail: `${highInjections} high-severity`,
      danger: highInjections > 0,
    },
    {
      key: 'reputation',
      label: 'Reputation',
      value: result.reputation.length,
      detail: `${flaggedReputation} flagged`,
      danger: flaggedReputation > 0,
    },
    {
      key: 'proof',
      label: 'Proof Steps',
      value: result.proof.steps.length,
      detail: truncateHash(result.proof.headHash),
      danger: false,
    },
  ]
}

/**
 * Tally every screened signal, rule findings plus injection findings, by
 * verdict severity. Returns the per-verdict counts and their total so the caller
 * sizes the chart and legend without re-summing.
 *
 * Time complexity: O(f + i). Space complexity: O(1).
 */
function tallySeverities(result: ScanResult): {
  counts: Record<Verdict, number>
  total: number
} {
  const counts: Record<Verdict, number> = {
    BLOCK: 0,
    HUMAN_APPROVAL_REQUIRED: 0,
    ALLOW: 0,
  }
  for (const finding of result.findings) counts[finding.severity] += 1
  for (const injection of result.injections) counts[injection.severity] += 1
  const total = counts.BLOCK + counts.HUMAN_APPROVAL_REQUIRED + counts.ALLOW
  return { counts, total }
}

/** The scan source label: the hostname for a URL scan, else a paste label. */
function sourceLabel(source: ScanResult['source']): string {
  return source.kind === 'url' ? hostname(source.ref) : 'Pasted skill'
}

/** One efferd-style KPI tile: label, big value, and a verdict-tinted detail. */
function StatTile({ card }: { card: StatCard }): ReactNode {
  return (
    <DashboardCard
      className="gap-0"
      data-testid={`stat-${card.key}`}
      data-danger={card.danger ? 'true' : 'false'}
    >
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-0">
        <CardTitle
          data-slot="stat-label"
          className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground"
        >
          {card.label}
        </CardTitle>
        <span
          aria-hidden="true"
          className={cn(
            'size-1.5 shrink-0 rounded-full',
            card.danger ? 'bg-block' : 'bg-muted-foreground/40',
          )}
        />
      </CardHeader>
      <CardContent className="py-2">
        <p data-slot="stat-value" className="font-semibold text-3xl tabular-nums">
          {card.value}
        </p>
      </CardContent>
      <CardFooter
        data-slot="stat-detail"
        className={cn(
          'gap-1 border-t-0 bg-transparent pt-0 text-xs',
          card.danger ? 'text-block' : 'text-muted-foreground',
        )}
      >
        {card.detail}
      </CardFooter>
    </DashboardCard>
  )
}

/**
 * The severity-distribution card: a compact horizontal bar chart of screened
 * signals by verdict, worst-first, with a per-verdict count legend. A scan with
 * no screened signals renders an explicit "content clear" state instead.
 */
function SeverityCard({ result }: { result: ScanResult }): ReactNode {
  const { counts, total } = tallySeverities(result)
  const severityLabel =
    total === 0
      ? 'No screened signals'
      : VERDICTS_BY_SEVERITY.map(
          (verdict) => `${counts[verdict]} ${verdictLabel(verdict)}`,
        ).join(', ')

  return (
    <DashboardCard className="col-span-2 gap-0 sm:col-span-3 lg:col-span-5">
      <CardHeader className="border-b">
        <CardTitle className="text-base">Signal severity</CardTitle>
        <CardDescription>
          Screened rule findings and injection signals by verdict.
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-4">
        {total === 0 ? (
          <p data-slot="severity-empty" className="text-sm text-muted-foreground">
            No screened signals, content clear.
          </p>
        ) : (
          <>
            <div
              role="img"
              aria-label={severityLabel}
              className="flex h-2.5 overflow-hidden rounded-full bg-muted"
            >
              {VERDICTS_BY_SEVERITY.filter((verdict) => counts[verdict] > 0).map(
                (verdict) => (
                  <span
                    key={verdict}
                    style={{
                      width: `${(counts[verdict] / total) * 100}%`,
                      background: VERDICT_TOKEN[verdict],
                    }}
                  />
                ),
              )}
            </div>
            <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1">
              {VERDICTS_BY_SEVERITY.map((verdict) => (
                <li
                  key={verdict}
                  className="flex items-center gap-2 text-xs text-muted-foreground"
                >
                  <span
                    aria-hidden="true"
                    className="size-2 rounded-[2px]"
                    style={{ background: VERDICT_TOKEN[verdict] }}
                  />
                  {verdictLabel(verdict)}
                  <span
                    data-slot="severity-count"
                    className="tabular-nums text-foreground"
                  >
                    {counts[verdict]}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </DashboardCard>
  )
}

/**
 * The at-a-glance scan dashboard that sits above the detailed evidence panels,
 * rendered in the efferd seamed-tile layout: a header with the scan source and
 * time, a grid of KPI tiles, and a severity-distribution chart.
 *
 * Purely presentational and fully derived: it reads only the {@link ScanResult}
 * prop and computes every tile value, danger tint, and chart magnitude from it,
 * so a benign scan and an attack scan render the same component with different
 * numbers and no hardcoded content.
 *
 * Time complexity: O(f + c + i + r) over the result's evidence arrays. Space
 * complexity: O(1) beyond the rendered tree.
 */
export function ScanDashboard({ result }: { result: ScanResult }): ReactNode {
  const cards = buildStatCards(result)

  return (
    <section aria-label="Scan overview" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-semibold">Scan Overview</h2>
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <span data-testid="scan-source" title={result.source.ref}>
            {sourceLabel(result.source)}
          </span>
          <span aria-hidden="true">·</span>
          <span className="font-mono">{formatTimestamp(result.scannedAt)}</span>
        </span>
      </div>

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border p-px ring-1 ring-foreground/10 sm:grid-cols-3 lg:grid-cols-5">
        {cards.map((card) => (
          <StatTile key={card.key} card={card} />
        ))}
        <SeverityCard result={result} />
      </div>
    </section>
  )
}
