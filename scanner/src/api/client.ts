import { API } from '../config'
import type { Proof, ScanRequest, ScanResult, VerifyResult } from './types'

const JSON_HEADERS = { 'content-type': 'application/json' }

/** A failed API exchange: a non-2xx response or an unreachable backend. */
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/**
 * Same-origin JSON request helper.
 *
 * Throws {@link ApiError} on a transport failure (status 0) or a non-ok
 * response, so callers branch on one error type. Relative paths are used
 * deliberately: the Worker serves both this SPA and the API.
 *
 * Time complexity: O(n) in the response body size. Space complexity: O(n).
 */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, init)
  } catch {
    throw new ApiError(0, 'scanner backend unreachable')
  }
  if (!response.ok) {
    // Surface the worker's typed error message (e.g. "no SKILL.md found in …")
    // rather than a bare status, so the user sees exactly what to do next.
    let detail = `request to ${path} failed (${response.status})`
    try {
      const body = (await response.json()) as { message?: unknown }
      if (typeof body.message === 'string' && body.message.length > 0) {
        detail = body.message
      }
    } catch {
      /* non-JSON error body: keep the generic detail */
    }
    throw new ApiError(response.status, detail)
  }
  return (await response.json()) as T
}

/** Run a full skill scan. POSTs the request body to {@link API.scan}. */
export async function scanSkill(req: ScanRequest): Promise<ScanResult> {
  return request<ScanResult>(API.scan, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(req),
  })
}

/**
 * Server-side re-verification of a proof chain. POSTs to {@link API.verify}.
 *
 * Note: the in-browser ProofViewer tamper feature does NOT use this — it calls
 * the shared `verifyChain` directly so re-verification needs no network round
 * trip and is provably client-side.
 */
export async function verifyProof(proof: Proof): Promise<VerifyResult> {
  return request<VerifyResult>(API.verify, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ proof }),
  })
}

/** The scan capability the UI depends on, injectable for tests and the gallery. */
export interface ScanClient {
  scanSkill(r: ScanRequest): Promise<ScanResult>
}

/** The production scan client, backed by the live API. */
export const defaultScanClient: ScanClient = { scanSkill }
