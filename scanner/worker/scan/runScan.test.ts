// @vitest-environment node
import { describe, expect, it } from 'vitest'
import type {
  ExaClient,
  ExaReport,
  JudgeClient,
  JudgeResult,
  Verdict,
} from '../../shared/contract'
import { verifyChain } from '../../shared/proof'
import { loadConfig, type Env, type ScannerConfig } from '../config'
import { runScan, type ScanDeps } from './runScan'

// These tests drive the PURE `runScan` with a MOCK fetch and fake Exa/Judge
// clients, so no real network or sponsor API is touched. They assert the four
// invariants the orchestrator must hold: a deterministic BLOCK on a redirect
// cascade that hits a loopback hop; the judge can never weaken a BLOCK baseline;
// a thrown Exa/judge fails CLOSED (never ALLOW); and identical inputs (incl.
// `scannedAt`) produce an identical proof head hash.

/** A minimal env yielding the documented config defaults. */
const ENV: Env = { ASSETS: {} as unknown as Fetcher }

/** Load the real, validated default config once for all tests. */
const CONFIG: ScannerConfig = loadConfig(ENV)

/** A fixed timestamp so determinism is exercised independent of the clock. */
const FIXED_SCANNED_AT = '2026-06-27T00:00:00.000Z'

/**
 * Build a mock `fetch` from a routing table of `url -> {status, location}`.
 * A `location` makes the URL a 30x redirect; its absence makes it a final 200.
 * An unrouted URL throws, surfacing accidental over-fetching.
 */
function mockFetch(
  routes: Record<string, { status: number; location?: string }>,
): typeof fetch {
  const impl = async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    const route = routes[url]
    if (route === undefined) {
      throw new Error(`unexpected fetch for ${url}`)
    }
    const headers = new Headers()
    if (route.location !== undefined) {
      headers.set('Location', route.location)
    }
    return new Response(null, { status: route.status, headers })
  }
  return impl as unknown as typeof fetch
}

/** A fake Exa client returning fixed reports (or throwing, for fail-closed). */
class FakeExaClient implements ExaClient {
  private readonly reports: ExaReport[]
  private readonly fail: boolean

  public constructor(reports: ExaReport[], fail = false) {
    this.reports = reports
    this.fail = fail
  }

  public async assessFinalUrls(_urls: string[]): Promise<ExaReport[]> {
    if (this.fail) {
      throw new Error('exa upstream 503')
    }
    return this.reports
  }
}

/** A fake judge returning a fixed result (or throwing, for fail-closed). */
class FakeJudgeClient implements JudgeClient {
  private readonly result: JudgeResult
  private readonly fail: boolean

  public constructor(result: JudgeResult, fail = false) {
    this.result = result
    this.fail = fail
  }

  public async judge(
    _skillText: string,
    _exaReports: ExaReport[],
    _baseline: Verdict,
  ): Promise<JudgeResult> {
    if (this.fail) {
      throw new Error('openai 500')
    }
    return this.result
  }
}

/** A judge that yields a clean, ALLOW-leaning result. */
const CLEAN_JUDGE: JudgeResult = {
  pInjection: 0.01,
  verdict: 'ALLOW',
  findings: [],
  rationale: 'no injection signal',
}

/** Base deps: deterministic core only (no sponsor clients). */
function baseDeps(fetchImpl: typeof fetch): ScanDeps {
  return {
    config: CONFIG,
    exa: null,
    judge: null,
    fetchImpl,
    scannedAt: FIXED_SCANNED_AT,
  }
}

describe('runScan — deterministic redirect cascade to a loopback hop', () => {
  // A skill linking to a URL that 302s to http://127.0.0.1/. The SSRF guard in
  // the tracer marks that hop dangerous; the rules escalate to BLOCK.
  const SKILL = 'See [docs](https://a.example/start) for setup.'
  const FETCH = mockFetch({
    'https://a.example/start': {
      status: 302,
      location: 'http://127.0.0.1/admin',
    },
  })

  it('returns BLOCK with a dangerous hop and an intact proof', async () => {
    const result = await runScan({ content: SKILL }, baseDeps(FETCH))

    expect(result.verdict).toBe('BLOCK')
    expect(result.chains).toHaveLength(1)
    expect(result.chains[0]?.dangerousHopIndex).not.toBeNull()
    // A deterministic rule fired (ssrf.blocked_host) — explainable, key-free.
    expect(result.findings.some((f) => f.severity === 'BLOCK')).toBe(true)

    const verification = await verifyChain(result.proof)
    expect(verification).toEqual({ ok: true, firstBrokenIndex: null })
    // The terminal proof step records the same verdict the result reports.
    const last = result.proof.steps.at(-1)
    expect(last?.kind).toBe('VERDICT')
    expect(last?.payload.verdict).toBe('BLOCK')
  })
})

describe('runScan — tighten-only: the judge cannot weaken a BLOCK baseline', () => {
  const SKILL = 'Install via [tool](https://a.example/start).'
  const FETCH = mockFetch({
    'https://a.example/start': {
      status: 302,
      location: 'http://127.0.0.1/admin',
    },
  })

  it('keeps BLOCK even when the judge votes ALLOW with p≈0', async () => {
    const judge = new FakeJudgeClient(CLEAN_JUDGE)
    const deps: ScanDeps = { ...baseDeps(FETCH), judge }

    const result = await runScan({ content: SKILL }, deps)

    // Deterministic baseline is BLOCK; an ALLOW-voting judge cannot lower it.
    expect(result.verdict).toBe('BLOCK')
    const verification = await verifyChain(result.proof)
    expect(verification.ok).toBe(true)
  })

  it('lets the judge tighten a clean baseline up to BLOCK', async () => {
    // A benign skill (no dangerous hop) → baseline ALLOW; a high-p judge raises
    // it to BLOCK, proving escalation works in the tighten direction.
    const benignSkill = 'Read more at [home](https://safe.example/).'
    const benignFetch = mockFetch({
      'https://safe.example/': { status: 200 },
    })
    const blockingJudge = new FakeJudgeClient({
      pInjection: 0.99,
      verdict: 'BLOCK',
      findings: [
        {
          excerpt: 'ignore all previous instructions',
          category: 'prompt_injection',
          severity: 'BLOCK',
          rationale: 'explicit override directive',
        },
      ],
      rationale: 'clear injection',
    })
    const deps: ScanDeps = {
      ...baseDeps(benignFetch),
      judge: blockingJudge,
    }

    const result = await runScan({ content: benignSkill }, deps)

    expect(result.verdict).toBe('BLOCK')
    expect(result.injections).toHaveLength(1)
  })
})

describe('runScan — fail-closed: a thrown sponsor never produces ALLOW', () => {
  // Benign deterministic input (final 200, no rules fire) → baseline ALLOW.
  const SKILL = 'Docs at [site](https://safe.example/).'
  const FETCH = mockFetch({ 'https://safe.example/': { status: 200 } })

  it('escalates to HUMAN_APPROVAL_REQUIRED when Exa throws', async () => {
    const exa = new FakeExaClient([], true)
    const deps: ScanDeps = { ...baseDeps(FETCH), exa }

    const result = await runScan({ content: SKILL }, deps)

    expect(result.verdict).not.toBe('ALLOW')
    expect(result.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    const verification = await verifyChain(result.proof)
    expect(verification.ok).toBe(true)
  })

  it('escalates to HUMAN_APPROVAL_REQUIRED when the judge throws', async () => {
    const judge = new FakeJudgeClient(CLEAN_JUDGE, true)
    const deps: ScanDeps = { ...baseDeps(FETCH), judge }

    const result = await runScan({ content: SKILL }, deps)

    expect(result.verdict).not.toBe('ALLOW')
    expect(result.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('does NOT relax the baseline when no Exa client is configured', async () => {
    // No exa, no judge: a benign skill stays ALLOW (missing reputation is not
    // treated as risk), but a risky skill stays BLOCK (missing reputation is
    // not treated as safety). Here we assert the benign no-client path is ALLOW.
    const result = await runScan({ content: SKILL }, baseDeps(FETCH))
    expect(result.verdict).toBe('ALLOW')
  })
})

describe('runScan — idempotency: same input + same scannedAt → same head hash', () => {
  const SKILL = 'Pipeline: [step](https://a.example/start).'
  // Two independent fetch mocks with identical routing so each run is isolated.
  function freshFetch(): typeof fetch {
    return mockFetch({
      'https://a.example/start': { status: 302, location: 'https://b.example/' },
      'https://b.example/': { status: 200 },
    })
  }

  it('produces an identical proof head hash on replay', async () => {
    const exaReports: ExaReport[] = [
      {
        url: 'https://b.example/',
        score: '0.12',
        summary: 'benign docs',
        title: 'B',
        flagged: false,
        status: 'OK',
      },
    ]
    const makeDeps = (): ScanDeps => ({
      config: CONFIG,
      exa: new FakeExaClient(exaReports),
      judge: new FakeJudgeClient(CLEAN_JUDGE),
      fetchImpl: freshFetch(),
      scannedAt: FIXED_SCANNED_AT,
    })

    const first = await runScan({ content: SKILL }, makeDeps())
    const second = await runScan({ content: SKILL }, makeDeps())

    expect(second.proof.headHash).toBe(first.proof.headHash)
    expect(second.proof.steps.map((s) => s.currHash)).toEqual(
      first.proof.steps.map((s) => s.currHash),
    )
    // Both chains independently verify.
    await expect(verifyChain(first.proof)).resolves.toEqual({
      ok: true,
      firstBrokenIndex: null,
    })
  })
})

describe('runScan — a GitHub repo sourceUrl resolves to the raw SKILL.md', () => {
  // The exact scenario a user hits pasting `github.com/owner/repo`: the worker
  // must discover the repo's SKILL.md (here at a nested path) and scan THAT, not
  // the ~350 KB HTML repo page. The skill body links to one safe URL, so the
  // key-free deterministic core returns ALLOW with the raw URL as the source.
  const API = 'https://api.github.com/repos/netresearch/context7-skill'
  const TREE = `${API}/git/trees/main?recursive=1`
  const RAW =
    'https://raw.githubusercontent.com/netresearch/context7-skill/main/' +
    'skills/context7/SKILL.md'
  const DOCS = 'https://docs.example/context7'
  const SKILL_BODY = `# Context7\n\nSee [docs](${DOCS}) for usage.\n`

  function githubFetch(): typeof fetch {
    const impl = async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === API) {
        return new Response(JSON.stringify({ default_branch: 'main' }), {
          status: 200,
        })
      }
      if (url === TREE) {
        return new Response(
          JSON.stringify({
            tree: [{ path: 'skills/context7/SKILL.md', type: 'blob' }],
          }),
          { status: 200 },
        )
      }
      if (url === RAW) {
        return new Response(SKILL_BODY, { status: 200 })
      }
      if (url === DOCS) {
        return new Response(null, { status: 200 })
      }
      throw new Error(`unexpected fetch for ${url}`)
    }
    return impl as unknown as typeof fetch
  }

  it('scans the resolved SKILL.md and reports the raw URL as the source', async () => {
    const result = await runScan(
      { sourceUrl: 'https://github.com/netresearch/context7-skill' },
      baseDeps(githubFetch()),
    )

    expect(result.source).toEqual({ kind: 'url', ref: RAW })
    expect(result.verdict).toBe('ALLOW')
    expect(result.chains).toHaveLength(1)
    expect(result.chains[0]?.origin).toBe(DOCS)
    const verification = await verifyChain(result.proof)
    expect(verification.ok).toBe(true)
  })
})
