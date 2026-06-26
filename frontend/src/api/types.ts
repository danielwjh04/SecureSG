// DTOs faithful to the SecureSG backend wire shape (Pydantic model_dump). Every
// optional backend field serializes as `null`, not absent, so they are `T | null`.

export type Verdict = 'ALLOW' | 'BLOCK' | 'HUMAN_APPROVAL_REQUIRED'

export type DashboardEventKind = 'VERDICT' | 'CONTENT' | 'MODEL_STATE'

export interface DashboardEvent {
  kind: DashboardEventKind
  created_at: string
  session_id: string
  tool_name: string | null
  verdict: string | null
  rule_id: string | null
  category: string | null
  content: string | null
  reason: string | null
  model_state: string | null
  transaction_id: string | null
}

export interface CategoryCount {
  category: string
  allow: number
  human_approval_required: number
  block: number
  total: number
}

export interface SummaryReport {
  window_days: number
  generated_at: string
  categories: CategoryCount[]
}

export interface AlertView {
  id: string
  created_at: string
  session_id: string
  tool_name: string | null
  rule_id: string
  category: string
  reason: string
  redacted_payload: string
}

export interface RegistryEntry {
  id: string
  created_at: string
  session_id: string
  tool_name: string
  redacted_content: string
}

export interface IncidentReport {
  alert: AlertView
  chain_status: string
  first_invalid_seq: number | null
  generated_at: string
}

export interface SessionCreated {
  session_id: string
}

// JSON-RPC envelope of the proxy data plane.
export interface ToolCall {
  name: string
  arguments: Record<string, unknown>
}

export interface JsonRpcRequest {
  jsonrpc: '2.0'
  id: number
  method: 'tools/call'
  params: ToolCall
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0'
  id: number | string | null
  result: unknown
}

export interface JsonRpcError {
  jsonrpc: '2.0'
  id: number | string | null
  error: {
    code: number
    message: string
    data?: { verdict: string; rule_id: string }
  }
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcError
