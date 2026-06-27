import type { ReactNode } from 'react'
import type { Verdict } from '../api/types'
import { StatusPill } from './StatusPill'
import { verdictClass, verdictLabel } from '../lib/format'

interface VerdictBannerProps {
  verdict: Verdict
  findingsCount: number
}

/**
 * Map a verdict to its scanner-banner modifier. Reuses the pill class idiom
 * (pill--allow / pill--approval / pill--block) as the banner tint suffix so the
 * banner background tracks the same --allow-bg / --approval-bg / --block-bg
 * tokens the pill uses, keeping the two surfaces in lockstep.
 */
function bannerClass(verdict: Verdict): string {
  return `verdict-banner--${verdictClass(verdict).replace('pill--', '')}`
}

/**
 * The one-line detail under the verdict. A clean ALLOW with no findings reads as
 * an explicit pass; otherwise it states the finding count so the banner always
 * explains why the evidence panels below are worth reading.
 */
function detailLine(verdict: Verdict, findingsCount: number): string {
  if (verdict === 'ALLOW' && findingsCount === 0) {
    return 'No risks detected. Content cleared by every screening pass.'
  }
  const noun = findingsCount === 1 ? 'finding' : 'findings'
  return `${findingsCount} ${noun}`
}

/**
 * The overall scan verdict, shown as a tinted banner above the evidence panels.
 *
 * Pure mapping from (verdict, findingsCount) → DOM: a {@link StatusPill} carries
 * the verdict color, a bold label restates it, the background is tinted by
 * verdict, and one detail line summarizes the finding count.
 */
export function VerdictBanner({ verdict, findingsCount }: VerdictBannerProps): ReactNode {
  return (
    <section className={`verdict-banner ${bannerClass(verdict)}`}>
      <StatusPill verdict={verdict} />
      <span className="verdict-banner__label">{verdictLabel(verdict)}</span>
      <span className="verdict-banner__detail">{detailLine(verdict, findingsCount)}</span>
    </section>
  )
}
