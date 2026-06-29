/**
 * @secureai/contract: the single definition site for every type that crosses a
 * boundary between the SecureAI Worker, the React SPA, and the published SDK.
 *
 * These are pure types (zero runtime). Each package resolves this module through
 * a TypeScript path alias, so the import erases at build and nothing needs to
 * resolve `@secureai/contract` at runtime. One definition is what lets a proof be
 * built by the Worker and re-verified, byte-identically, in the browser, and what
 * keeps the SDK's view of the scan/guard contracts from drifting out of sync with
 * the server. All identifiers are camelCase.
 */

/**
 * The outcome of evaluating content or a tool call. Three internal states; the
 * UI displays `HUMAN_APPROVAL_REQUIRED` as "REVIEW".
 */
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

/** One injection signal surfaced by the Workers AI inference layer. */
export interface InjectionFinding {
  excerpt: string
  category: string
  severity: Verdict
  rationale: string
}

/** The provenance tag of a proof step. */
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
 * appear here; anything time-varying lives outside hashed steps
 * (see {@link ScanResult.scannedAt}).
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

/**
 * The exactly-one-of scan input the SDK accepts: a stricter, client-side view of
 * {@link ScanRequest} that makes "provide exactly one of content/sourceUrl/mcp"
 * a compile-time guarantee.
 */
export type ScanInput =
  | { content: string; sourceUrl?: never; mcp?: never }
  | { sourceUrl: string; content?: never; mcp?: never }
  | { mcp: McpScanInput; content?: never; sourceUrl?: never }

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
 * stays pure: Node-runnable and testable with a recorded/mocked implementation.
 */
export interface ReputationClient {
  assessFinalUrls(urls: string[]): Promise<ReputationReport[]>
}

/** The structured outcome of the Workers AI injection inference. */
export interface InjectionResult {
  pInjection: number
  verdict: Verdict
  findings: InjectionFinding[]
  rationale: string
}

/**
 * Workers AI injection-inference client. Injected into `runScan` for the same
 * purity and testability reasons as {@link ReputationClient}. `baseline` is
 * passed in so the implementation can enforce tighten-only escalation.
 */
export interface InferenceClient {
  detect(
    skillText: string,
    reputation: ReputationReport[],
    baseline: Verdict,
  ): Promise<InjectionResult>
}

/**
 * The permission decision a Claude Code / Cursor / Codex PreToolUse hook may
 * return.
 *   - `allow`, the tool call proceeds without prompting the user.
 *   - `ask`, the agent prompts the user for approval before proceeding.
 *   - `deny`, the tool call is blocked and the reason is fed back to the agent.
 */
export type GuardPermissionDecision = 'allow' | 'ask' | 'deny'

/** A single tool call submitted to `POST /api/guard`. */
export interface GuardToolCall {
  hook_event_name: 'PreToolUse'
  tool_name: string
  tool_input: Record<string, unknown>
  session_id?: string
  transcript_path?: string
  cwd?: string
}

/**
 * The guard's decision for one tool call. `verdict` is the underlying scanner
 * verdict, or `null` when nothing scannable was present (the decision is then a
 * benign `allow`). `proof` is the tamper-evident scan proof when a scan ran, so
 * the decision can be independently re-verified (omitted when no scan ran).
 */
export interface GuardDecision {
  decision: GuardPermissionDecision
  reason: string
  verdict: Verdict | null
  proof?: Proof
}
