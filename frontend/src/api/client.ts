import type {
  AlertView,
  IncidentReport,
  JsonRpcRequest,
  JsonRpcResponse,
  RegistryEntry,
  SessionCreated,
  SummaryReport,
  ToolCall,
} from './types'

const JSON_HEADERS = { 'content-type': 'application/json' }

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, init)
  } catch {
    throw new ApiError(0, 'SecureSG backend unreachable')
  }
  if (!response.ok) {
    throw new ApiError(response.status, `request to ${path} failed (${response.status})`)
  }
  return (await response.json()) as T
}

export function getSummary(windowDays = 30): Promise<SummaryReport> {
  return request<SummaryReport>(`/dashboard/summary?window_days=${windowDays}`)
}

export function getAlerts(): Promise<AlertView[]> {
  return request<AlertView[]>('/dashboard/alerts')
}

export function getRegistry(): Promise<RegistryEntry[]> {
  return request<RegistryEntry[]>('/dashboard/registry')
}

export function postReport(alertId: string): Promise<IncidentReport> {
  return request<IncidentReport>(`/dashboard/alerts/${alertId}/report`, { method: 'POST' })
}

export function createSession(intent?: string): Promise<SessionCreated> {
  return request<SessionCreated>('/sessions', {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(intent === undefined ? {} : { intent }),
  })
}

// A block/approval is HTTP 200 with a JSON-RPC `error`; an unknown session is 404
// with the same envelope shape. Both carry an inspectable body, so this returns
// the envelope and only throws when the backend is unreachable.
export async function rpcCall(
  sessionId: string,
  call: ToolCall,
  id: number,
): Promise<JsonRpcResponse> {
  const body: JsonRpcRequest = { jsonrpc: '2.0', id, method: 'tools/call', params: call }
  let response: Response
  try {
    response = await fetch(`/sessions/${sessionId}/rpc`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'SecureSG backend unreachable')
  }
  return (await response.json()) as JsonRpcResponse
}

export interface DemoClient {
  createSession(intent?: string): Promise<SessionCreated>
  rpcCall(sessionId: string, call: ToolCall, id: number): Promise<JsonRpcResponse>
}

export const defaultClient: DemoClient = { createSession, rpcCall }
