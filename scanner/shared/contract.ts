/**
 * The single source of truth for every type that crosses a module boundary in
 * the scanner: worker handlers, the orchestrator, the SPA, and the gallery
 * build script all import from here. Keeping these definitions in one place is
 * what lets the proof be built by the Worker and re-verified, byte-identically,
 * in the browser.
 *
 * Port note: `Verdict` mirrors `secureSG/schemas/verdict.py` (same three
 * outcomes). Everything else is scanner-specific. All identifiers are camelCase.
 */

/** The outcome of evaluating a piece of content or a tool call. */
export type Verdict = 'ALLOW' | 'HUMAN_APPROVAL_REQUIRED' | 'BLOCK'

/** A single deterministic rule that fired during baseline screening. */
export interface RuleFinding {
  ruleId: string
  severity: Verdict
  detail: string
}

/** One hop in a URL's redirect cascade. */
export interface RedirectHop {
  from: string
  to: string
  status: number
  dangerous: boolean
  reason: string | null
}

/** The full traced redirect cascade for a single origin URL. */
export interface LinkChain {
  origin: string
  hops: RedirectHop[]
  finalUrl: string
  dangerousHopIndex: number | null
  depthExceeded: boolean
  loopDetected: boolean
}

/**
 * A reputation assessment of one final destination URL/host against the
 * known-bad indicator feeds. `score` is a stringified float so it never enters
 * a hashed proof payload as a float.
 */
export interface ReputationReport {
  url: string
  score: string
  summary: string
  title: string
  flagged: boolean
  status: string
}

/** One injection signal surfaced by the AI inference layer. */
export interface InjectionFinding {
  excerpt: string
  category: string
  severity: Verdict
  rationale: string
}

/** The provenance of a proof step. */
export type ProofStepKind =
  | 'SKILL_INPUT'
  | 'URL_EXTRACTED'
  | 'REDIRECT_HOP'
  | 'REPUTATION'
  | 'INJECTION'
  | 'VERDICT'

/**
 * One link in the tamper-evident proof chain.
 *
 * Payload values are JSON-safe and FLOAT-FREE: only `string`, integer `number`,
 * or `boolean`. Floats (reputation scores, injection probabilities) are
 * serialized as strings so the canonical bytes, and therefore the hash, are
 * stable across the Worker and the browser. No timestamps or random values may
 * appear here; anything time-varying lives outside hashed steps (see
 * `ScanResult.scannedAt`).
 */
export interface ProofStep {
  index: number
  kind: ProofStepKind
  payload: Record<string, string | number | boolean>
  prevHash: string
  currHash: string
}

/** A self-contained, re-verifiable SHA-256 hash chain over scan evidence. */
export interface Proof {
  genesisHash: string
  steps: ProofStep[]
  headHash: string
}

/** One MCP tool exposed by an MCP server config. */
export interface McpToolInput {
  name: string
  description?: string
  permissions?: string[]
  inputSchema?: unknown
}

/** MCP server config/setup data accepted by `POST /api/scan`. */
export interface McpScanInput {
  name?: string
  transport?: string
  command?: string
  args?: string[]
  endpoint?: string
  endpoints?: string[]
  permissions?: string[]
  env?: string[] | Record<string, unknown>
  tools?: McpToolInput[]
  setup?: string
  config?: unknown
}

/** The request body for `POST /api/scan`. Exactly one field is expected. */
export interface ScanRequest {
  content?: string
  sourceUrl?: string
  mcp?: McpScanInput
}

/** The full result of a scan, including the proof and out-of-band metadata. */
export interface ScanResult {
  verdict: Verdict
  chains: LinkChain[]
  reputation: ReputationReport[]
  injections: InjectionFinding[]
  findings: RuleFinding[]
  proof: Proof
  /** ISO string, set OUTSIDE hashed steps, passed in by the caller. */
  scannedAt: string
  source: { kind: 'paste' | 'url' | 'mcp'; ref: string }
}

/** The result of re-verifying a proof chain. */
export interface VerifyResult {
  status: 'CHAIN_OK' | 'CHAIN_BROKEN'
  firstInvalidIndex: number | null
}

/**
 * Known-bad reputation client. Injected into `runScan` so the orchestrator
 * stays a pure function: Node-runnable (gallery build) and testable with a
 * recorded or mocked implementation.
 */
export interface ReputationClient {
  assessFinalUrls(urls: string[]): Promise<ReputationReport[]>
}

/** The structured outcome of the AI injection inference. */
export interface InjectionResult {
  pInjection: number
  verdict: Verdict
  findings: InjectionFinding[]
  rationale: string
}

/**
 * AI injection-inference client. Injected into `runScan` for the same purity
 * and testability reasons as `ReputationClient`. The `baseline` is passed in so
 * the implementation can enforce tighten-only escalation.
 */
export interface InferenceClient {
  detect(
    skillText: string,
    reputation: ReputationReport[],
    baseline: Verdict,
  ): Promise<InjectionResult>
}
