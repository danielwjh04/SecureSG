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

/** Locate a stat tile by its metric key (`findings`, `chains`, ...). */
function tile(container: HTMLElement, key: string): HTMLElement | null {
  return container.querySelector<HTMLElement>(`[data-testid="stat-${key}"]`)
}

function value(container: HTMLElement, key: string): string | null | undefined {
  return tile(container, key)?.querySelector('[data-slot="stat-value"]')?.textContent
}

function detail(container: HTMLElement, key: string): string | null | undefined {
  return tile(container, key)?.querySelector('[data-slot="stat-detail"]')?.textContent
}

function isDanger(container: HTMLElement, key: string): boolean {
  return tile(container, key)?.getAttribute('data-danger') === 'true'
}

describe('ScanDashboard', () => {
  it('renders all-zero tiles, no danger tint, and a clear severity state for a benign scan', () => {
    const { container } = render(<ScanDashboard result={makeResult()} />)

    expect(value(container, 'findings')).toBe('0')
    expect(value(container, 'chains')).toBe('0')
    expect(value(container, 'injections')).toBe('0')
    expect(value(container, 'reputation')).toBe('0')
    expect(value(container, 'proof')).toBe('0')

    // No metric contributes a blocking/flagged signal, so no tile is tinted.
    expect(container.querySelectorAll('[data-danger="true"]')).toHaveLength(0)

    // With no screened signals the severity card shows the explicit clear state.
    expect(
      container.querySelector('[data-slot="severity-empty"]')?.textContent,
    ).toContain('content clear')

    // The proof tile still summarizes the head hash even with zero steps.
    expect(detail(container, 'proof')).toContain('…')
    expect(container.querySelector('[data-testid="scan-source"]')?.textContent).toBe(
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

    expect(value(container, 'findings')).toBe('2')
    expect(detail(container, 'findings')).toBe('1 blocking')
    expect(isDanger(container, 'findings')).toBe(true)

    expect(value(container, 'chains')).toBe('2')
    expect(detail(container, 'chains')).toBe('1 dangerous')
    expect(isDanger(container, 'chains')).toBe(true)

    expect(value(container, 'injections')).toBe('1')
    expect(detail(container, 'injections')).toBe('1 high-severity')
    expect(isDanger(container, 'injections')).toBe(true)

    expect(value(container, 'reputation')).toBe('2')
    expect(detail(container, 'reputation')).toBe('1 flagged')
    expect(isDanger(container, 'reputation')).toBe(true)

    // The proof tile counts steps and never tints, even on a blocking scan.
    expect(value(container, 'proof')).toBe('2')
    expect(isDanger(container, 'proof')).toBe(false)

    expect(container.querySelector('[data-testid="scan-source"]')?.textContent).toBe(
      'malicious.test',
    )
  })

  it('counts a loop-detected chain as dangerous without a flagged hop index', () => {
    const result = makeResult({
      chains: [chain({ loopDetected: true }), chain({ depthExceeded: true })],
    })
    const { container } = render(<ScanDashboard result={result} />)

    expect(value(container, 'chains')).toBe('2')
    expect(detail(container, 'chains')).toBe('2 dangerous')
    expect(isDanger(container, 'chains')).toBe(true)
  })

  it('reports the severity legend counts in worst-first order', () => {
    const result = makeResult({
      findings: [finding('BLOCK'), finding('HUMAN_APPROVAL_REQUIRED')],
      injections: [injection('BLOCK'), injection('ALLOW')],
    })
    const { container } = render(<ScanDashboard result={result} />)

    // 2 BLOCK + 1 APPROVAL + 1 ALLOW, listed worst-first in the legend.
    const counts = Array.from(
      container.querySelectorAll('[data-slot="severity-count"]'),
    ).map((node) => node.textContent)
    expect(counts).toEqual(['2', '1', '1'])

    // With screened signals present the clear state is gone.
    expect(container.querySelector('[data-slot="severity-empty"]')).toBeNull()
  })
})
