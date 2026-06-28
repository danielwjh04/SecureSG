import { API } from '../config'
import type {
  AuthCredentials,
  AuthResponse,
  CheckoutResponse,
  MeResponse,
  Proof,
  RotateKeyResponse,
  ScanRequest,
  ScanResult,
  StatsResponse,
  VerifyResult,
} from './types'

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

/**
 * Send the session cookie on every account call. The Worker serves the SPA and
 * the API from one origin; `include` keeps the httpOnly session cookie flowing
 * even when a remote {@link API_BASE} is configured.
 */
const WITH_CREDENTIALS = { credentials: 'include' } as const

/** Register a new account. Sets the session cookie. 409 if the email exists. */
export async function register(
  credentials: AuthCredentials,
): Promise<AuthResponse> {
  return request<AuthResponse>(API.register, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(credentials),
    ...WITH_CREDENTIALS,
  })
}

/** Sign in to an existing account. Sets the session cookie. 401 on bad creds. */
export async function login(
  credentials: AuthCredentials,
): Promise<AuthResponse> {
  return request<AuthResponse>(API.login, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify(credentials),
    ...WITH_CREDENTIALS,
  })
}

/** Sign out, clearing the session cookie. */
export async function logout(): Promise<void> {
  await request<unknown>(API.logout, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}

/** Fetch the signed-in account. Throws {@link ApiError}(401) when logged out. */
export async function fetchMe(): Promise<MeResponse> {
  return request<MeResponse>(API.me, { ...WITH_CREDENTIALS })
}

/** Fetch the account's protection statistics. */
export async function fetchStats(): Promise<StatsResponse> {
  return request<StatsResponse>(API.stats, { ...WITH_CREDENTIALS })
}

/** Rotate the account's API key. The new key is returned once and not stored. */
export async function rotateApiKey(): Promise<RotateKeyResponse> {
  return request<RotateKeyResponse>(API.rotateKey, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}

/** Start a Stripe checkout session and return the URL to redirect to. */
export async function startCheckout(): Promise<CheckoutResponse> {
  return request<CheckoutResponse>(API.checkout, {
    method: 'POST',
    ...WITH_CREDENTIALS,
  })
}
