import {
  SecureAiConfigError,
  SecureAiError,
  SecureAiHttpError,
  SecureAiParseError,
  SecureAiTimeoutError,
} from './errors'
import type {
  GuardDecision,
  GuardToolCall,
  InjectionFinding,
  LinkChain,
  Proof,
  ProofStep,
  ReputationReport,
  RuleFinding,
  ScanInput,
  ScanResult,
  SecureAiClientOptions,
  Verdict,
  VerifyResult,
} from './types'

const DEFAULT_API_BASE = 'https://secureai.software'
const DEFAULT_TIMEOUT_MS = 8000

type WireVerdict = Verdict | 'REVIEW'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function normalizeVerdict(value: unknown): Verdict | null {
  const verdict = value as WireVerdict
  if (verdict === 'REVIEW') return 'HUMAN_APPROVAL_REQUIRED'
  if (verdict === 'ALLOW' || verdict === 'HUMAN_APPROVAL_REQUIRED' || verdict === 'BLOCK') {
    return verdict
  }
  return null
}

function parseFinding(value: unknown): RuleFinding | null {
  if (!isRecord(value)) return null
  const severity = normalizeVerdict(value.severity)
  if (
    typeof value.ruleId !== 'string' ||
    typeof value.detail !== 'string' ||
    severity === null
  ) {
    return null
  }
  return { ruleId: value.ruleId, detail: value.detail, severity }
}

function parseInjection(value: unknown): InjectionFinding | null {
  if (!isRecord(value)) return null
  const severity = normalizeVerdict(value.severity)
  if (
    typeof value.excerpt !== 'string' ||
    typeof value.category !== 'string' ||
    typeof value.rationale !== 'string' ||
    severity === null
  ) {
    return null
  }
  return {
    excerpt: value.excerpt,
    category: value.category,
    severity,
    rationale: value.rationale,
  }
}

function parseReputation(value: unknown): ReputationReport | null {
  if (!isRecord(value)) return null
  if (
    typeof value.url !== 'string' ||
    typeof value.score !== 'string' ||
    typeof value.summary !== 'string' ||
    typeof value.title !== 'string' ||
    typeof value.flagged !== 'boolean' ||
    typeof value.status !== 'string'
  ) {
    return null
  }
  return {
    url: value.url,
    score: value.score,
    summary: value.summary,
    title: value.title,
    flagged: value.flagged,
    status: value.status,
  }
}

function parseChain(value: unknown): LinkChain | null {
  if (!isRecord(value)) return null
  if (
    typeof value.origin !== 'string' ||
    typeof value.finalUrl !== 'string' ||
    !Array.isArray(value.hops) ||
    typeof value.depthExceeded !== 'boolean' ||
    typeof value.loopDetected !== 'boolean'
  ) {
    return null
  }
  const dangerousHopIndex =
    typeof value.dangerousHopIndex === 'number' || value.dangerousHopIndex === null
      ? value.dangerousHopIndex
      : null
  const hops = value.hops.map((hop) => {
    if (!isRecord(hop)) return null
    if (
      typeof hop.from !== 'string' ||
      typeof hop.to !== 'string' ||
      typeof hop.status !== 'number' ||
      typeof hop.dangerous !== 'boolean' ||
      !(typeof hop.reason === 'string' || hop.reason === null)
    ) {
      return null
    }
    return {
      from: hop.from,
      to: hop.to,
      status: hop.status,
      dangerous: hop.dangerous,
      reason: hop.reason,
    }
  })
  if (hops.some((hop) => hop === null)) return null
  return {
    origin: value.origin,
    hops: hops as LinkChain['hops'],
    finalUrl: value.finalUrl,
    dangerousHopIndex,
    depthExceeded: value.depthExceeded,
    loopDetected: value.loopDetected,
  }
}

function parseProofStep(value: unknown): ProofStep | null {
  if (!isRecord(value)) return null
  if (
    typeof value.index !== 'number' ||
    typeof value.kind !== 'string' ||
    !isRecord(value.payload) ||
    typeof value.prevHash !== 'string' ||
    typeof value.currHash !== 'string'
  ) {
    return null
  }
  return {
    index: value.index,
    // Carried through verbatim for re-verification: the server only emits valid
    // ProofStepKind values and the SDK never switches on the kind.
    kind: value.kind as ProofStep['kind'],
    payload: value.payload as ProofStep['payload'],
    prevHash: value.prevHash,
    currHash: value.currHash,
  }
}

function parseProof(value: unknown): Proof | null {
  if (!isRecord(value)) return null
  if (
    typeof value.genesisHash !== 'string' ||
    typeof value.headHash !== 'string' ||
    !Array.isArray(value.steps)
  ) {
    return null
  }
  const steps = value.steps.map(parseProofStep)
  if (steps.some((step) => step === null)) return null
  return { genesisHash: value.genesisHash, headHash: value.headHash, steps: steps as ProofStep[] }
}

function parseArray<T>(value: unknown, parse: (entry: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) return null
  const parsed = value.map(parse)
  if (parsed.some((entry) => entry === null)) return null
  return parsed as T[]
}

function parseScanResult(value: unknown): ScanResult | null {
  if (!isRecord(value)) return null
  const verdict = normalizeVerdict(value.verdict)
  const chains = parseArray(value.chains, parseChain)
  const reputation = parseArray(value.reputation, parseReputation)
  const injections = parseArray(value.injections, parseInjection)
  const findings = parseArray(value.findings, parseFinding)
  const proof = parseProof(value.proof)
  const source = value.source
  if (
    verdict === null ||
    chains === null ||
    reputation === null ||
    injections === null ||
    findings === null ||
    proof === null ||
    typeof value.scannedAt !== 'string' ||
    !isRecord(source) ||
    !(source.kind === 'paste' || source.kind === 'url' || source.kind === 'mcp') ||
    typeof source.ref !== 'string'
  ) {
    return null
  }
  return {
    verdict,
    chains,
    reputation,
    injections,
    findings,
    proof,
    scannedAt: value.scannedAt,
    source: { kind: source.kind, ref: source.ref },
  }
}

function parseVerifyResult(value: unknown): VerifyResult | null {
  if (!isRecord(value)) return null
  if (
    !(value.status === 'CHAIN_OK' || value.status === 'CHAIN_BROKEN') ||
    !(typeof value.firstInvalidIndex === 'number' || value.firstInvalidIndex === null)
  ) {
    return null
  }
  return { status: value.status, firstInvalidIndex: value.firstInvalidIndex }
}

function parseGuardDecision(value: unknown): GuardDecision | null {
  if (!isRecord(value)) return null
  const proof = value.proof === undefined ? undefined : parseProof(value.proof)
  // verdict is Verdict | null: the server returns null for a benign allow when
  // nothing scannable was present. A present-but-invalid verdict is still a parse
  // failure, so the client fail-closes on a malformed response.
  const verdict = value.verdict === null ? null : normalizeVerdict(value.verdict)
  if (
    !(value.decision === 'allow' || value.decision === 'ask' || value.decision === 'deny') ||
    typeof value.reason !== 'string' ||
    (value.verdict !== null && verdict === null) ||
    proof === null
  ) {
    return null
  }
  return {
    decision: value.decision,
    reason: value.reason,
    verdict,
    ...(proof === undefined ? {} : { proof }),
  }
}

function normalizeApiBase(apiBase: string): string {
  return apiBase.replace(/\/+$/, '')
}

function exactlyOneScanInput(input: ScanInput): boolean {
  return [input.content, input.sourceUrl, input.mcp].filter((value) => value !== undefined).length === 1
}

/**
 * Client for SecureAI scan, verify, and guard APIs.
 *
 * Time complexity: each method is O(n) in request and response size. Space
 * complexity: O(n).
 */
export class SecureAiClient {
  private readonly apiBase: string
  private readonly apiKey: string | undefined
  private readonly timeoutMs: number
  private readonly fetchImpl: typeof fetch

  constructor(options: SecureAiClientOptions = {}) {
    this.apiBase = normalizeApiBase(options.apiBase ?? DEFAULT_API_BASE)
    this.apiKey = options.apiKey
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    const fetchImpl = options.fetch ?? globalThis.fetch
    if (fetchImpl === undefined) {
      throw new SecureAiConfigError('fetch is not available; pass a custom fetch implementation')
    }
    this.fetchImpl = fetchImpl
  }

  /**
   * Scan a URL, text payload, or MCP config.
   *
   * Time complexity: O(n) in request and response size. Space complexity: O(n).
   */
  async scan(input: ScanInput): Promise<ScanResult> {
    if (!exactlyOneScanInput(input)) {
      throw new SecureAiConfigError('provide exactly one scan input')
    }
    return this.request('/api/scan', input, parseScanResult, false)
  }

  /**
   * Re-verify a SecureAI proof through the API.
   *
   * Time complexity: O(n) in proof size. Space complexity: O(n).
   */
  async verify(proof: Proof): Promise<VerifyResult> {
    return this.request('/api/verify', { proof }, parseVerifyResult, false)
  }

  /**
   * Guard one tool call through `/api/guard`.
   *
   * Time complexity: O(n) in tool input and response size. Space complexity: O(n).
   */
  async guard(toolCall: GuardToolCall): Promise<GuardDecision> {
    return this.request('/api/guard', toolCall, parseGuardDecision, true)
  }

  private async request<T>(
    path: string,
    body: unknown,
    parse: (value: unknown) => T | null,
    requireApiKey: boolean,
  ): Promise<T> {
    if (requireApiKey && (this.apiKey === undefined || this.apiKey.trim().length === 0)) {
      throw new SecureAiConfigError('SecureAI API key is required for this request')
    }

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs)
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' }
      if (this.apiKey !== undefined && this.apiKey.trim().length > 0) {
        headers['authorization'] = `Bearer ${this.apiKey}`
      }
      const response = await this.fetchImpl(`${this.apiBase}${path}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      })
      if (!response.ok) {
        throw new SecureAiHttpError(response.status, await readErrorMessage(response))
      }
      const parsed = parse(await response.json())
      if (parsed === null) {
        throw new SecureAiParseError(`invalid SecureAI response from ${path}`)
      }
      return parsed
    } catch (error: unknown) {
      if (error instanceof SecureAiError) throw error
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new SecureAiTimeoutError(`SecureAI request to ${path} timed out`)
      }
      throw new SecureAiHttpError(0, `SecureAI request to ${path} failed`)
    } finally {
      clearTimeout(timeout)
    }
  }
}

async function readErrorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as unknown
    if (isRecord(body) && typeof body.message === 'string') return body.message
  } catch {
    return `SecureAI API returned HTTP ${response.status}`
  }
  return `SecureAI API returned HTTP ${response.status}`
}
