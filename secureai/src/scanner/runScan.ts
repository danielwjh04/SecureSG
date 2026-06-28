/**
 * Pure scan orchestrator — the single function that turns a {@link ScanRequest}
 * into a {@link ScanResult} with a self-contained, re-verifiable cryptographic
 * proof.
 *
 * `runScan` is a pure function over its injected dependencies ({@link ScanDeps}):
 * it reads no environment, no clock, and no randomness directly (only
 * `crypto.subtle` for hashing). Every external capability — config, the
 * reputation client, the Workers AI inference client, the `fetch` used by the
 * tracer, and the response timestamp — arrives through `deps`, which keeps the
 * logic Node-runnable and every stage independently testable.
 *
 * Safety posture (CLAUDE.md §1, §5):
 *   - Tighten-only: the deterministic rules produce the `baseline`; reputation
 *     and inference can only *raise* severity, never lower it. Every fold is
 *     through `escalate`.
 *   - Fail-closed: a missing client never relaxes the baseline; a thrown
 *     ReputationError / InferenceError escalates toward HUMAN_APPROVAL_REQUIRED.
 *   - Cost discipline: inference (the only paid, AI stage) runs LAST and only
 *     when the verdict is still ambiguous — a BLOCK is already maximal and
 *     inference is tighten-only, so the model call is skipped.
 *   - Idempotent proof: nothing time-varying enters a hashed step; `scannedAt`
 *     is supplied by the caller and lives outside the chain.
 */

import type {
  InferenceClient,
  InjectionFinding,
  InjectionResult,
  LinkChain,
  Proof,
  ReputationClient,
  ReputationReport,
  RuleFinding,
  ScanRequest,
  ScanResult,
  Verdict,
} from '../schemas/contract'
import type { ScannerConfig } from '../config/env'
import { ProofBuilder, deriveGenesisHash } from '../audit/chain'
import { ParseError, SourceResolutionError } from '../errors'
import { parseSkill } from '../pipeline/parse'
import { assertSafeUrl, traceRedirects } from '../pipeline/redirects'
import { evaluateRules } from '../pipeline/rules'
import { escalate } from '../verdict'
import { parseGithubWebUrl, resolveGithubSkillUrl } from './github'

/**
 * Injected dependencies for {@link runScan}. Keeping every capability here is
 * what keeps `runScan` pure and Node-runnable.
 */
export interface ScanDeps {
  /** Fully-resolved, validated scanner configuration. */
  config: ScannerConfig
  /** Known-bad reputation client, or `null` when none is configured. */
  reputation: ReputationClient | null
  /** Workers AI injection-inference client, or `null` (free tier / no AI). */
  inference: InferenceClient | null
  /** Injected `fetch` for the redirect tracer (and source-URL load). */
  fetchImpl?: typeof fetch
  /** ISO timestamp for the response — set OUTSIDE the hashed proof. */
  scannedAt: string
  /** Optional GitHub token to authenticate source-resolution API calls. */
  githubToken?: string
}

/** The escalation applied when a stage fails fail-closed. */
const STAGE_FAILURE_FLOOR: Verdict = 'HUMAN_APPROVAL_REQUIRED'

/**
 * Lowercase-hex SHA-256 of the skill text, used as the (float-free) identity of
 * the input in the `SKILL_INPUT` proof step. Hashing rather than embedding the
 * body keeps the proof compact and avoids leaking the full skill into the chain
 * while still binding the proof to the exact input.
 *
 * Time complexity: O(n) in the text byte length. Space complexity: O(n).
 */
async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  const view = new Uint8Array(digest)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Resolve the skill text to scan from the request, fetching a source URL when
 * `content` is absent. The source URL passes the SSRF guard before any network
 * access; a GitHub web URL is first resolved to the raw `SKILL.md` it points at,
 * and the resolved URL is re-checked by the guard before it is fetched.
 *
 * Time complexity: O(n) in the fetched body length plus a bounded number of
 *   GitHub discovery calls. Space complexity: O(n).
 *
 * @throws {ParseError} If neither field is provided or the URL is malformed.
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
    throw new ParseError(`sourceUrl is not a valid URL: ${sourceUrl}`, { cause: error })
  }

  const schemes = new Set(config.allowedSchemes)
  assertSafeUrl(parsed, { allowedSchemes: schemes })

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
 * Run the reputation stage fail-closed. A flagged destination escalates toward
 * HUMAN_APPROVAL_REQUIRED; a null client never relaxes the baseline; a thrown
 * error escalates and logs the exact class.
 *
 * Time complexity: O(r) in the report count. Space complexity: O(r).
 */
async function runReputationStage(
  reputation: ReputationClient | null,
  finalUrls: string[],
  baseline: Verdict,
): Promise<{ reports: ReputationReport[]; verdict: Verdict }> {
  if (reputation === null || finalUrls.length === 0) {
    return { reports: [], verdict: baseline }
  }
  try {
    const reports = await reputation.assessFinalUrls(finalUrls)
    let verdict = baseline
    for (const report of reports) {
      if (report.flagged) {
        verdict = escalate(verdict, STAGE_FAILURE_FLOOR)
      }
    }
    return { reports, verdict }
  } catch (error: unknown) {
    logErrorClass('reputation', error)
    return { reports: [], verdict: escalate(baseline, STAGE_FAILURE_FLOOR) }
  }
}

/**
 * Run the Workers AI inference stage fail-closed and tighten-only.
 *
 * Cost discipline (CLAUDE.md §5): the model is the only paid stage, so it runs
 * LAST and only when the verdict is still ambiguous. A `null` client (free tier)
 * or a baseline that is already BLOCK skips the call — inference is tighten-only,
 * so it could never change a BLOCK, and skipping spends zero Neurons.
 *
 * Time complexity: O(f) in the finding count. Space complexity: O(f).
 */
async function runInferenceStage(
  inference: InferenceClient | null,
  skillText: string,
  reputation: ReputationReport[],
  baseline: Verdict,
): Promise<{ result: InjectionResult | null; verdict: Verdict }> {
  if (inference === null || baseline === 'BLOCK') {
    return { result: null, verdict: baseline }
  }
  try {
    const result = await inference.detect(skillText, reputation, baseline)
    // Belt-and-suspenders: re-escalate against the baseline so the stage is
    // tighten-only even if a future inference impl forgets to fold.
    return { result, verdict: escalate(baseline, result.verdict) }
  } catch (error: unknown) {
    logErrorClass('inference', error)
    return { result: null, verdict: escalate(baseline, STAGE_FAILURE_FLOOR) }
  }
}

/**
 * Log the exact error class name of an I/O fault (CLAUDE.md §1: never swallow a
 * provider exception silently).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function logErrorClass(stage: string, error: unknown): void {
  const className = error instanceof Error ? error.constructor.name : typeof error
  console.warn(`[runScan] ${stage} stage failed (${className}); failing closed`)
}

/**
 * Orchestrate a full scan and return a {@link ScanResult} with a tamper-evident
 * proof.
 *
 * Pipeline (each stage can only tighten the verdict):
 *   1. Resolve skill text (paste or fetched source URL through the SSRF guard).
 *   2. `parseSkill` → URLs + exec patterns.
 *   3. `traceRedirects` per URL → redirect cascades.
 *   4. `evaluateRules` → deterministic `baseline` verdict + findings.
 *   5. Reputation over the final URLs (fail-closed; null client never relaxes).
 *   6. Workers AI inference (fail-closed, tighten-only, ambiguous-only).
 *   7. Build the proof: SKILL_INPUT, URL_EXTRACTED·n, REDIRECT_HOP·h,
 *      REPUTATION·r, INJECTION, terminal VERDICT.
 *
 * Determinism: the only inputs are the request and `deps`; with the same request
 * and the same recorded clients, the produced proof (and `headHash`) is
 * identical. `scannedAt` is the sole time-varying field and is never hashed.
 *
 * Time complexity: O(U·H + R + F). Space complexity: O(U·H + R + F).
 *
 * @throws {ParseError} If the input is empty or unparseable.
 * @throws {RedirectResolutionError} On a transport failure tracing a cascade.
 */
export async function runScan(request: ScanRequest, deps: ScanDeps): Promise<ScanResult> {
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

  // 5. Reputation (fail-closed; tighten-only).
  const finalUrls = chains.map((chain) => chain.finalUrl)
  const reputationStage = await runReputationStage(deps.reputation, finalUrls, baseline)
  const reputationReports: ReputationReport[] = reputationStage.reports

  // 6. Workers AI inference (fail-closed; tighten-only; ambiguous-only). It sees
  //    the post-reputation verdict as its baseline so it can only tighten.
  const inferenceStage = await runInferenceStage(
    deps.inference,
    skillText,
    reputationReports,
    reputationStage.verdict,
  )
  const injections: InjectionFinding[] = inferenceStage.result?.findings ?? []
  const verdict: Verdict = inferenceStage.verdict

  // 7. Build the tamper-evident proof.
  const proof = await buildProof({
    config,
    skillText,
    source,
    urls: parsed.urls,
    chains,
    reputationReports,
    inference: inferenceStage.result,
    verdict,
  })

  return {
    verdict,
    chains,
    reputation: reputationReports,
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
 * verifier depends on, so they are spelled out explicitly. No payload value is a
 * float or a timestamp:
 *   - SKILL_INPUT   → { skillSha256, length, source }
 *   - URL_EXTRACTED → { ordinal, url } per extracted URL
 *   - REDIRECT_HOP  → { chain, hop, from, to, status, dangerous } per hop
 *   - REPUTATION    → { url, status, flagged, score } per report (score string)
 *   - INJECTION     → { pInjection (string), modelVerdict, findingCount }
 *   - VERDICT       → { verdict }
 *
 * Time complexity: O(U + H + R) appends. Space complexity: O(steps).
 */
async function buildProof(input: {
  config: ScannerConfig
  skillText: string
  source: ScanResult['source']
  urls: readonly string[]
  chains: readonly LinkChain[]
  reputationReports: readonly ReputationReport[]
  inference: InjectionResult | null
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

  for (const report of input.reputationReports) {
    await builder.append('REPUTATION', {
      url: report.url,
      status: report.status,
      flagged: report.flagged ? 1 : 0,
      score: report.score,
    })
  }

  if (input.inference !== null) {
    await builder.append('INJECTION', {
      pInjection: input.inference.pInjection.toString(),
      modelVerdict: input.inference.verdict,
      findingCount: input.inference.findings.length,
    })
  }

  await builder.append('VERDICT', { verdict: input.verdict })

  return builder.toProof()
}
