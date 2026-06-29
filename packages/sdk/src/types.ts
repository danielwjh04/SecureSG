/** SecureAI verdict returned by scan and guard APIs. */
export type Verdict = 'ALLOW' | 'HUMAN_APPROVAL_REQUIRED' | 'BLOCK'

export interface RuleFinding {
  ruleId: string
  severity: Verdict
  detail: string
}

export interface RedirectHop {
  from: string
  to: string
  status: number
  dangerous: boolean
  reason: string | null
}

export interface LinkChain {
  origin: string
  hops: RedirectHop[]
  finalUrl: string
  dangerousHopIndex: number | null
  depthExceeded: boolean
  loopDetected: boolean
}

export interface ReputationReport {
  url: string
  score: string
  summary: string
  title: string
  flagged: boolean
  status: string
}

export interface InjectionFinding {
  excerpt: string
  category: string
  severity: Verdict
  rationale: string
}

export interface ProofStep {
  index: number
  kind: string
  payload: Record<string, string | number | boolean>
  prevHash: string
  currHash: string
}

export interface Proof {
  genesisHash: string
  steps: ProofStep[]
  headHash: string
}

export interface McpToolInput {
  name: string
  description?: string
  permissions?: string[]
  inputSchema?: unknown
}

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

export type ScanInput =
  | { content: string; sourceUrl?: never; mcp?: never }
  | { sourceUrl: string; content?: never; mcp?: never }
  | { mcp: McpScanInput; content?: never; sourceUrl?: never }

export interface ScanResult {
  verdict: Verdict
  chains: LinkChain[]
  reputation: ReputationReport[]
  injections: InjectionFinding[]
  findings: RuleFinding[]
  proof: Proof
  scannedAt: string
  source: { kind: 'paste' | 'url' | 'mcp'; ref: string }
}

export interface VerifyResult {
  status: 'CHAIN_OK' | 'CHAIN_BROKEN'
  firstInvalidIndex: number | null
}

export interface GuardToolCall {
  hook_event_name: 'PreToolUse'
  tool_name: string
  tool_input: Record<string, unknown>
  session_id?: string
  transcript_path?: string
  cwd?: string
}

export interface GuardDecision {
  decision: 'allow' | 'ask' | 'deny'
  reason: string
  /**
   * The underlying scanner verdict, or `null` when nothing scannable was present
   * (a benign `allow`). Mirrors the server GuardDecision contract.
   */
  verdict: Verdict | null
  proof?: Proof
}

export interface SecureAiClientOptions {
  apiBase?: string
  apiKey?: string
  timeoutMs?: number
  fetch?: typeof fetch
}
