import type { ReactNode } from 'react'
import type { LinkChain, ScanResult, Verdict } from '../api/types'
import {
  formatTimestamp,
  hostname,
  truncateHash,
  verdictClass,
  verdictLabel,
} from '../lib/format'

/**
 * The verdict severities in most-to-least severe order. This is the single
 * ordered runtime list of the {@link Verdict} union, so the severity bar and its
 * legend render worst-first without any other dashboard code re-listing the
 * verdicts.
 */
const VERDICTS_BY_SEVERITY: readonly Verdict[] = [
  'BLOCK',
  'HUMAN_APPROVAL_REQUIRED',
  'ALLOW',
]

/**
 * Map a verdict to its design-token suffix (`allow` / `approval` / `block`),
 * reusing the same pill-class idiom the verdict banner uses so the bar segments
 * and legend swatches track the exact same `--allow` / `--approval` / `--block`
 * tokens. Time complexity: O(1). Space complexity: O(1).
 */
function severitySuffix(verdict: Verdict): string {
  return verdictClass(verdict).replace('pill--', '')
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
 * reputation reports. Space complexity: O(1) — a fixed set of tiles.
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
 * Tally every screened signal — rule findings plus injection findings — by
 * verdict severity. Returns the per-verdict counts and their total so the caller
 * sizes the stacked bar without re-summing.
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

/**
 * The at-a-glance scan dashboard that sits above the detailed evidence panels.
 *
 * Purely presentational and fully derived: it reads only the {@link ScanResult}
 * prop and computes every tile value, danger tint, and severity-bar width from
 * it, so a benign scan and an attack scan render the same component with
 * different numbers and no hardcoded content.
 *
 * Time complexity: O(f + c + i + r) over the result's evidence arrays. Space
 * complexity: O(1) beyond the rendered tree.
 */
export function ScanDashboard({ result }: { result: ScanResult }): ReactNode {
  const cards = buildStatCards(result)
  const { counts, total } = tallySeverities(result)
  const severityLabel =
    total === 0
      ? 'No screened signals'
      : VERDICTS_BY_SEVERITY.map(
          (verdict) => `${counts[verdict]} ${verdictLabel(verdict)}`,
        ).join(', ')

  return (
    <section className="dashboard" aria-label="Scan overview">
      <div className="dashboard__head">
        <h2 className="dashboard__title">Scan Overview</h2>
        <span className="dashboard__meta">
          <span className="dashboard__source" title={result.source.ref}>
            {sourceLabel(result.source)}
          </span>
          <span className="dashboard__dot" aria-hidden="true">
            ·
          </span>
          <span>{formatTimestamp(result.scannedAt)}</span>
        </span>
      </div>

      <div className="dashboard__grid">
        {cards.map((card) => (
          <div
            key={card.key}
            className={card.danger ? 'stat-card stat-card--danger' : 'stat-card'}
          >
            <span className="stat-card__label">{card.label}</span>
            <span className="stat-card__value">{card.value}</span>
            <span className="stat-card__detail">{card.detail}</span>
          </div>
        ))}
      </div>

      <div className="dashboard__severity">
        <div className="severity-bar" role="img" aria-label={severityLabel}>
          {total === 0 ? (
            <span
              className="severity-bar__seg severity-bar__seg--empty"
              style={{ width: '100%' }}
            />
          ) : (
            VERDICTS_BY_SEVERITY.filter((verdict) => counts[verdict] > 0).map(
              (verdict) => (
                <span
                  key={verdict}
                  className={`severity-bar__seg severity-bar__seg--${severitySuffix(verdict)}`}
                  style={{ width: `${(counts[verdict] / total) * 100}%` }}
                />
              ),
            )
          )}
        </div>
        <div className="severity-legend">
          {total === 0 ? (
            <span className="severity-legend__item severity-legend__item--clear">
              No screened signals — content clear
            </span>
          ) : (
            VERDICTS_BY_SEVERITY.map((verdict) => (
              <span key={verdict} className="severity-legend__item">
                <span
                  className={`severity-legend__swatch severity-legend__swatch--${severitySuffix(verdict)}`}
                  aria-hidden="true"
                />
                {verdictLabel(verdict)}
                <span className="severity-legend__count">{counts[verdict]}</span>
              </span>
            ))
          )}
        </div>
      </div>
    </section>
  )
}
