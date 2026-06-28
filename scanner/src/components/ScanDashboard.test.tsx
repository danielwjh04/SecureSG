import { render } from '@testing-library/react'
import type {
  ReputationReport,
  InjectionFinding,
  LinkChain,
  ProofStep,
  RuleFinding,
  ScanResult,
  Verdict,
} from '../api/types'
import { ScanDashboard } from './ScanDashboard'

/** A clean ScanResult; each test overrides only the evidence it exercises. */
function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    verdict: 'ALLOW',
    chains: [],
    reputation: [],
    injections: [],
    findings: [],
    proof: { genesisHash: '0'.repeat(64), steps: [], headHash: 'a'.repeat(64) },
    scannedAt: '2026-06-27T12:00:00.000Z',
    source: { kind: 'paste', ref: 'paste' },
    ...overrides,
  }
}

function finding(severity: Verdict): RuleFinding {
  return { ruleId: 'rule', severity, detail: 'detail' }
}

function injection(severity: Verdict): InjectionFinding {
  return { excerpt: 'x', category: 'cat', severity, rationale: 'why' }
}

function reputation(flagged: boolean): ReputationReport {
  return {
    url: 'https://evil.example/x',
    score: '0.5',
    summary: 's',
    title: 't',
    flagged,
    status: 'OK',
  }
}

function chain(overrides: Partial<LinkChain> = {}): LinkChain {
  return {
    origin: 'https://o.example',
    hops: [],
    finalUrl: 'https://o.example',
    dangerousHopIndex: null,
    depthExceeded: false,
    loopDetected: false,
    ...overrides,
  }
}

function step(index: number): ProofStep {
  return { index, kind: 'VERDICT', payload: {}, prevHash: 'p', currHash: 'c' }
}

/** Locate a stat tile by its label and return one of its parts. */
function card(container: HTMLElement, label: string): HTMLElement | undefined {
  return Array.from(container.querySelectorAll<HTMLElement>('.stat-card')).find(
    (node) => node.querySelector('.stat-card__label')?.textContent === label,
  )
}

function value(container: HTMLElement, label: string): string | null | undefined {
  return card(container, label)?.querySelector('.stat-card__value')?.textContent
}

function detail(container: HTMLElement, label: string): string | null | undefined {
  return card(container, label)?.querySelector('.stat-card__detail')?.textContent
}

function isDanger(container: HTMLElement, label: string): boolean {
  return card(container, label)?.classList.contains('stat-card--danger') ?? false
}

describe('ScanDashboard', () => {
  it('renders all-zero tiles, an empty severity bar, and a clear legend for a benign scan', () => {
    const { container } = render(<ScanDashboard result={makeResult()} />)

    expect(value(container, 'Rule Findings')).toBe('0')
    expect(value(container, 'Redirect Cascades')).toBe('0')
    expect(value(container, 'Injection Signals')).toBe('0')
    expect(value(container, 'Reputation')).toBe('0')
    expect(value(container, 'Proof Steps')).toBe('0')

    // No metric contributes a blocking/flagged signal, so no tile is tinted.
    expect(container.querySelectorAll('.stat-card--danger')).toHaveLength(0)

    // The severity bar collapses to a single neutral segment, not a verdict tint.
    expect(container.querySelector('.severity-bar__seg--empty')).not.toBeNull()
    expect(
      container.querySelectorAll(
        '.severity-bar__seg--block, .severity-bar__seg--approval, .severity-bar__seg--allow',
      ),
    ).toHaveLength(0)
    expect(
      container.querySelector('.severity-legend__item--clear')?.textContent,
    ).toContain('content clear')

    // The proof tile still summarizes the head hash even with zero steps.
    expect(detail(container, 'Proof Steps')).toContain('…')
    expect(container.querySelector('.dashboard__source')?.textContent).toBe(
      'Pasted skill',
    )
  })

  it('derives every count, danger tint, and source label from an attack scan', () => {
    const result = makeResult({
      verdict: 'BLOCK',
      source: { kind: 'url', ref: 'https://malicious.test/path' },
      findings: [finding('BLOCK'), finding('ALLOW')],
      chains: [chain({ dangerousHopIndex: 1 }), chain()],
      injections: [injection('BLOCK')],
      reputation: [reputation(true), reputation(false)],
      proof: { genesisHash: '0'.repeat(64), steps: [step(0), step(1)], headHash: 'b'.repeat(64) },
    })
    const { container } = render(<ScanDashboard result={result} />)

    expect(value(container, 'Rule Findings')).toBe('2')
    expect(detail(container, 'Rule Findings')).toBe('1 blocking')
    expect(isDanger(container, 'Rule Findings')).toBe(true)

    expect(value(container, 'Redirect Cascades')).toBe('2')
    expect(detail(container, 'Redirect Cascades')).toBe('1 dangerous')
    expect(isDanger(container, 'Redirect Cascades')).toBe(true)

    expect(value(container, 'Injection Signals')).toBe('1')
    expect(detail(container, 'Injection Signals')).toBe('1 high-severity')
    expect(isDanger(container, 'Injection Signals')).toBe(true)

    expect(value(container, 'Reputation')).toBe('2')
    expect(detail(container, 'Reputation')).toBe('1 flagged')
    expect(isDanger(container, 'Reputation')).toBe(true)

    // The proof tile counts steps and never tints, even on a blocking scan.
    expect(value(container, 'Proof Steps')).toBe('2')
    expect(isDanger(container, 'Proof Steps')).toBe(false)

    expect(container.querySelector('.dashboard__source')?.textContent).toBe(
      'malicious.test',
    )
  })

  it('counts a loop-detected chain as dangerous without a flagged hop index', () => {
    const result = makeResult({
      chains: [chain({ loopDetected: true }), chain({ depthExceeded: true })],
    })
    const { container } = render(<ScanDashboard result={result} />)

    expect(value(container, 'Redirect Cascades')).toBe('2')
    expect(detail(container, 'Redirect Cascades')).toBe('2 dangerous')
    expect(isDanger(container, 'Redirect Cascades')).toBe(true)
  })

  it('sizes the severity bar by the blended findings + injections distribution', () => {
    const result = makeResult({
      findings: [finding('BLOCK'), finding('HUMAN_APPROVAL_REQUIRED')],
      injections: [injection('BLOCK'), injection('ALLOW')],
    })
    const { container } = render(<ScanDashboard result={result} />)

    // 2 BLOCK + 1 APPROVAL + 1 ALLOW over a total of 4 → 50% / 25% / 25%.
    expect(
      container.querySelector<HTMLElement>('.severity-bar__seg--block')?.style.width,
    ).toBe('50%')
    expect(
      container.querySelector<HTMLElement>('.severity-bar__seg--approval')?.style.width,
    ).toBe('25%')
    expect(
      container.querySelector<HTMLElement>('.severity-bar__seg--allow')?.style.width,
    ).toBe('25%')

    // The legend reports every verdict's count in worst-first order.
    const counts = Array.from(
      container.querySelectorAll('.severity-legend__count'),
    ).map((node) => node.textContent)
    expect(counts).toEqual(['2', '1', '1'])
  })
})
