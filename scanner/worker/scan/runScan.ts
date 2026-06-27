/**
 * Pure scan orchestrator — the single function that turns a `ScanRequest` into a
 * `ScanResult` with a self-contained, re-verifiable cryptographic proof.
 *
 * `runScan` is deliberately a pure function over its injected dependencies
 * ({@link ScanDeps}): it reads no `globalThis`, no environment, no clock, and no
 * randomness directly. Every external capability — the config, the Exa
 * reputation client, the OpenAI judge, the `fetch` used by the redirect tracer,
 * and the response timestamp — arrives through `deps`. This is what lets the
 * exact same logic run inside the Cloudflare Worker (`/api/scan`) and inside a
 * plain Node process (the hermetic gallery build) with recorded sponsor clients,
 * and what makes every stage independently testable.
 *
 * Safety posture (CLAUDE.md §1, §6):
 *   - Tighten-only: the deterministic rules produce the `baseline`; Exa and the
 *     judge can only *raise* severity, never lower it. Every fold is through
 *     `escalate(baseline, candidate)`.
 *   - Fail-closed: a missing reputation client does NOT relax the baseline, and a
 *     thrown `ReputationError` / `JudgeError` escalates toward
 *     HUMAN_APPROVAL_REQUIRED rather than silently allowing. A sponsor failure
 *     can never turn a risky skill into an ALLOW.
 *   - Idempotent proof: nothing time-varying enters a hashed step. `scannedAt`
 *     is supplied by the caller and lives outside the chain.
 */

import type {
  ExaClient,
  ExaReport,
  InjectionFinding,
  JudgeClient,
  JudgeResult,
  LinkChain,
  Proof,
  RuleFinding,
  ScanRequest,
  ScanResult,
  Verdict,
} from '../../shared/contract'
import { ProofBuilder } from '../../shared/proof'
import { deriveGenesisHash } from '../../shared/hash'
import type { ScannerConfig } from '../config'
import { ParseError, SourceResolutionError } from '../errors'
import { parseSkill } from './parser'
import { parseGithubWebUrl, resolveGithubSkillUrl } from './github'
import { traceRedirects } from './redirect'
import { assertSafeUrl } from './ssrf'
import { evaluateRules } from '../verdict/rules'
import { escalate, mapProbabilityToVerdict } from '../verdict/verdict'

/**
 * Injected dependencies for {@link runScan}. Keeping every capability here is
 * what keeps `runScan` pure and Node-runnable.
 */
export interface ScanDeps {
  /** Fully-resolved, validated scanner configuration. */
  config: ScannerConfig
  /** Exa reputation client, or `null` when no key is configured. */
  exa: ExaClient | null
  /** OpenAI injection judge, or `null` when no key is configured. */
  judge: JudgeClient | null
  /** Injected `fetch` for the redirect tracer (and source-URL load). */
  fetchImpl?: typeof fetch
  /** ISO timestamp for the response — set OUTSIDE the hashed proof. */
  scannedAt: string
  /** Optional GitHub token to authenticate source-resolution API calls. */
  githubToken?: string
}

/** The escalation applied when a sponsor stage fails fail-closed. */
const SPONSOR_FAILURE_FLOOR: Verdict = 'HUMAN_APPROVAL_REQUIRED'

/**
 * Lowercase-hex SHA-256 of the skill text, used as the (float-free) identity of
 * the input in the `SKILL_INPUT` proof step. Hashing the content rather than
 * embedding it keeps the proof compact and avoids leaking the full skill body
 * into the chain while still binding the proof to the exact input.
 *
 * Time complexity: O(n) in the text byte length. Space complexity: O(n).
 *
 * @param text - The skill document.
 * @returns Lowercase-hex SHA-256 digest of the UTF-8 text.
 */
async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  const view = new Uint8Array(digest)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Resolve the skill text to scan from the request, fetching a source URL when
 * `content` is absent. The source URL is run through the SSRF guard before any
 * network access and fetched under the per-hop redirect timeout, so a malicious
 * `sourceUrl` cannot be used to pivot at the internal network the same way a
 * redirect hop cannot.
 *
 * A GitHub *web* URL (repo root, tree, or blob) is first resolved to the raw
 * `SKILL.md` it points at — fetching the web page itself would scan GitHub's
 * ~350 KB HTML chrome, not the manifest. Non-GitHub URLs are fetched unchanged.
 * The resolved URL is re-checked by the SSRF guard before it is fetched.
 *
 * Time complexity: O(n) in the fetched body length (plus a bounded, constant
 *   number of GitHub discovery calls). Space complexity: O(n).
 *
 * @returns The skill text and the source descriptor for the result.
 * @throws {ParseError} If neither `content` nor `sourceUrl` is provided, or the
 *   source URL is malformed.
 * @throws {RedirectResolutionError} If the source (or resolved) URL trips the
 *   SSRF guard.
 * @throws {SourceResolutionError} If a GitHub URL resolves to no `SKILL.md`, or
 *   the fetched source returns a non-OK HTTP status.
 */
async function resolveSkillText(
  request: ScanRequest,
  config: ScannerConfig,
  fetchImpl: typeof fetch,
  githubToken: string | undefined,
): Promise<{ text: string; source: ScanResult['source'] }> {
  const content = request.content
  if (content !== undefined && content.trim().length > 0) {
    return { text: content, source: { kind: 'paste', ref: 'paste' } }
  }

  const sourceUrl = request.sourceUrl?.trim()
  if (sourceUrl === undefined || sourceUrl.length === 0) {
    throw new ParseError('scan request has neither content nor sourceUrl')
  }

  let parsed: URL
  try {
    parsed = new URL(sourceUrl)
  } catch (error: unknown) {
    throw new ParseError(`sourceUrl is not a valid URL: ${sourceUrl}`, {
      cause: error,
    })
  }

  const schemes = new Set(config.allowedSchemes)
  assertSafeUrl(parsed, { allowedSchemes: schemes })

  // A GitHub web URL (repo / tree / blob) is resolved to the raw SKILL.md the
  // agent would actually learn; a non-GitHub URL (null target) is fetched as-is.
  // The resolved raw URL passes back through the SSRF guard before any fetch.
  const githubTarget = parseGithubWebUrl(parsed)
  let fetchUrl = parsed
  if (githubTarget !== null) {
    const rawUrl = await resolveGithubSkillUrl(
      githubTarget,
      fetchImpl,
      config.redirectTimeoutMs,
      githubToken,
    )
    fetchUrl = new URL(rawUrl)
    assertSafeUrl(fetchUrl, { allowedSchemes: schemes })
  }

  const response = await fetchImpl(fetchUrl.href, {
    signal: AbortSignal.timeout(config.redirectTimeoutMs),
  })
  if (!response.ok) {
    throw new SourceResolutionError(
      `source URL returned HTTP ${response.status}: ${fetchUrl.href}`,
    )
  }
  const text = await response.text()
  return { text, source: { kind: 'url', ref: fetchUrl.href } }
}

/**
 * Run the Exa reputation stage fail-closed.
 *
 * On success the reports are returned and the candidate verdict is escalated by
 * any `flagged` report (a flagged destination is at least HUMAN_APPROVAL). On a
 * `ReputationError` (or any other failure) the verdict is escalated toward
 * HUMAN_APPROVAL_REQUIRED and the error class name is logged — a reputation
 * outage must never let a risky skill through as ALLOW.
 *
 * Time complexity: O(r) in the report count. Space complexity: O(r).
 *
 * @returns The reports (empty on failure) and the verdict after escalation.
 */
async function runReputationStage(
  exa: ExaClient | null,
  finalUrls: string[],
  baseline: Verdict,
): Promise<{ reports: ExaReport[]; verdict: Verdict }> {
  // No client configured: do NOT treat missing reputation as evidence of
  // safety. Keep the baseline exactly — never relax it.
  if (exa === null || finalUrls.length === 0) {
    return { reports: [], verdict: baseline }
  }

  try {
    const reports = await exa.assessFinalUrls(finalUrls)
    let verdict = baseline
    for (const report of reports) {
      if (report.flagged) {
        verdict = escalate(verdict, SPONSOR_FAILURE_FLOOR)
      }
    }
    return { reports, verdict }
  } catch (error: unknown) {
    // Fail-closed: a reputation failure escalates toward HUMAN_APPROVAL, never
    // allows. The exact error class is logged (CLAUDE.md §1).
    logErrorClass('reputation', error)
    return { reports: [], verdict: escalate(baseline, SPONSOR_FAILURE_FLOOR) }
  }
}

/**
 * Run the OpenAI judge stage fail-closed and tighten-only.
 *
 * On success the candidate is `escalate(baseline, escalate(judge.verdict,
 * mapProbabilityToVerdict(pInjection, review, block)))` — the model can only
 * raise severity. On a `JudgeError` (or any failure) the verdict escalates
 * toward HUMAN_APPROVAL_REQUIRED and the error class is logged.
 *
 * Time complexity: O(f) in the finding count. Space complexity: O(f).
 *
 * @returns The judge findings (empty on failure) and the verdict after fold.
 */
async function runJudgeStage(
  judge: JudgeClient | null,
  skillText: string,
  exaReports: ExaReport[],
  baseline: Verdict,
  config: ScannerConfig,
): Promise<{ result: JudgeResult | null; verdict: Verdict }> {
  if (judge === null) {
    return { result: null, verdict: baseline }
  }

  try {
    const result = await judge.judge(skillText, exaReports, baseline)
    const banded = mapProbabilityToVerdict(
      result.pInjection,
      config.judgeReviewThreshold,
      config.judgeBlockThreshold,
    )
    // Tighten-only: fold the model verdict and the probability band into the
    // baseline; neither can lower it.
    const verdict = escalate(baseline, escalate(result.verdict, banded))
    return { result, verdict }
  } catch (error: unknown) {
    // Fail-closed: a judge failure escalates toward HUMAN_APPROVAL, never
    // allows. The exact error class is logged (CLAUDE.md §1).
    logErrorClass('judge', error)
    return { result: null, verdict: escalate(baseline, SPONSOR_FAILURE_FLOOR) }
  }
}

/**
 * Log the exact error class name of an I/O fault (CLAUDE.md §1: never swallow a
 * provider exception silently — log a warning naming the class).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function logErrorClass(stage: string, error: unknown): void {
  const className =
    error instanceof Error ? error.constructor.name : typeof error
  console.warn(`[runScan] ${stage} stage failed (${className}); failing closed`)
}

/**
 * Orchestrate a full scan and return a `ScanResult` with a tamper-evident proof.
 *
 * Pipeline (each stage can only tighten the verdict):
 *   1. Resolve skill text (paste or fetched source URL through the SSRF guard).
 *   2. `parseSkill` → URLs + exec patterns.
 *   3. `traceRedirects` per URL → redirect cascades.
 *   4. `evaluateRules` → deterministic `baseline` verdict + findings.
 *   5. Exa reputation over the final URLs (fail-closed; null client never
 *      relaxes the baseline).
 *   6. OpenAI judge (fail-closed, tighten-only).
 *   7. Build the proof: SKILL_INPUT, URL_EXTRACTED·n, REDIRECT_HOP·h,
 *      EXA_REPUTATION·r, JUDGE_FINDING, terminal VERDICT.
 *
 * Determinism: the only inputs are the request and `deps`; with the same request
 * and the same recorded clients the produced proof (and `headHash`) is identical.
 * `scannedAt` is the sole time-varying field and is never hashed.
 *
 * Time complexity: O(U·H + R + F) where U = URLs, H = max hops, R = Exa reports,
 *   F = judge findings — a single pass per stage, no nested rescans.
 * Space complexity: O(U·H + R + F) for the chains, reports, findings, and proof.
 *
 * @param request - The scan request (exactly one of `content`/`sourceUrl`).
 * @param deps - Injected config, sponsor clients, fetch, and timestamp.
 * @returns The full `ScanResult`.
 * @throws {ParseError} If the input is empty or unparseable.
 * @throws {RedirectResolutionError} On a transport failure tracing a cascade.
 */
export async function runScan(
  request: ScanRequest,
  deps: ScanDeps,
): Promise<ScanResult> {
  const { config } = deps
  const fetchImpl = deps.fetchImpl ?? fetch

  // 1. Resolve the skill text and its provenance.
  const { text: skillText, source } = await resolveSkillText(
    request,
    config,
    fetchImpl,
    deps.githubToken,
  )

  // 2. Deterministic extraction.
  const parsed = parseSkill(skillText, config)

  // 3. Trace each URL's redirect cascade.
  const chains: LinkChain[] = []
  for (const url of parsed.urls) {
    const chain = await traceRedirects(
      url,
      {
        maxRedirectHops: config.maxRedirectHops,
        redirectTimeoutMs: config.redirectTimeoutMs,
        allowedSchemes: new Set(config.allowedSchemes),
      },
      fetchImpl,
    )
    chains.push(chain)
  }

  // 4. Deterministic baseline verdict from the hard rules.
  const ruleOutcome = evaluateRules({
    chains,
    execPatterns: [...parsed.execPatterns],
    config: { shortenerHosts: new Set(config.shortenerHosts) },
  })
  const baseline: Verdict = ruleOutcome.verdict
  const findings: RuleFinding[] = ruleOutcome.findings

  // 5. Exa reputation (fail-closed; tighten-only).
  const finalUrls = chains.map((chain) => chain.finalUrl)
  const reputation = await runReputationStage(deps.exa, finalUrls, baseline)
  const exaReports: ExaReport[] = reputation.reports

  // 6. OpenAI judge (fail-closed; tighten-only). The judge sees the
  //    post-reputation verdict as its baseline so it can only tighten further.
  const judgeStage = await runJudgeStage(
    deps.judge,
    skillText,
    exaReports,
    reputation.verdict,
    config,
  )
  const injections: InjectionFinding[] = judgeStage.result?.findings ?? []
  const verdict: Verdict = judgeStage.verdict

  // 7. Build the tamper-evident proof. Payloads are float-free: floats (scores,
  //    probabilities) are serialized as strings; booleans as 0/1 where a number
  //    reads cleaner, else as booleans.
  const proof = await buildProof({
    config,
    skillText,
    source,
    urls: parsed.urls,
    chains,
    exaReports,
    judge: judgeStage.result,
    verdict,
  })

  return {
    verdict,
    chains,
    exa: exaReports,
    injections,
    findings,
    proof,
    scannedAt: deps.scannedAt,
    source,
  }
}

/**
 * Append every evidence stage to a fresh {@link ProofBuilder} in a fixed order
 * and snapshot the chain. The order and payload shape are the contract the
 * verifier (and the browser re-verifier) depend on, so they are spelled out
 * here rather than derived implicitly.
 *
 * No payload value is a float or a timestamp (CLAUDE.md idempotency rule):
 *   - SKILL_INPUT   → { skillSha256, length, source }
 *   - URL_EXTRACTED → { ordinal, url } per extracted URL
 *   - REDIRECT_HOP  → { chain, hop, from, to, status, dangerous } per hop
 *   - EXA_REPUTATION→ { url, status, flagged, score } per report (score string)
 *   - JUDGE_FINDING → { pInjection (string), modelVerdict, findingCount }
 *   - VERDICT       → { verdict }
 *
 * Time complexity: O(U + H + R) appends, each O(payload). Space: O(steps).
 *
 * @returns The immutable proof snapshot.
 */
async function buildProof(input: {
  config: ScannerConfig
  skillText: string
  source: ScanResult['source']
  urls: readonly string[]
  chains: readonly LinkChain[]
  exaReports: readonly ExaReport[]
  judge: JudgeResult | null
  verdict: Verdict
}): Promise<Proof> {
  const genesis = await deriveGenesisHash(input.config.genesisSeed)
  const builder = new ProofBuilder(genesis)

  const skillSha256 = await sha256Hex(input.skillText)
  await builder.append('SKILL_INPUT', {
    skillSha256,
    length: input.skillText.length,
    source: input.source.kind,
  })

  for (const [index, url] of input.urls.entries()) {
    await builder.append('URL_EXTRACTED', { ordinal: index + 1, url })
  }

  for (const [chainIndex, chain] of input.chains.entries()) {
    for (const [hopIndex, hop] of chain.hops.entries()) {
      await builder.append('REDIRECT_HOP', {
        chain: chainIndex,
        hop: hopIndex,
        from: hop.from,
        to: hop.to,
        status: hop.status,
        dangerous: hop.dangerous,
      })
    }
  }

  for (const report of input.exaReports) {
    await builder.append('EXA_REPUTATION', {
      url: report.url,
      status: report.status,
      flagged: report.flagged ? 1 : 0,
      score: report.score,
    })
  }

  if (input.judge !== null) {
    await builder.append('JUDGE_FINDING', {
      pInjection: input.judge.pInjection.toString(),
      modelVerdict: input.judge.verdict,
      findingCount: input.judge.findings.length,
    })
  }

  await builder.append('VERDICT', { verdict: input.verdict })

  return builder.toProof()
}
