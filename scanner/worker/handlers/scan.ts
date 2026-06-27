/**
 * `POST /api/scan` handler.
 *
 * Parses the request body, constructs the real sponsor clients when their keys
 * are present (Exa reputation, OpenAI judge), stamps a response timestamp
 * *outside* the hashed proof, runs the pure {@link runScan} orchestrator, and
 * maps the typed error hierarchy to HTTP status codes.
 *
 * Fail-closed at the transport edge too: a missing sponsor key yields a `null`
 * client (handled fail-closed inside `runScan`, never an ALLOW), and every
 * raised `ScannerError` subclass maps to a deliberate status — a parse fault is
 * a client error (422), a config fault is a server error (500), an upstream
 * sponsor/redirect fault is a bad-gateway (502), and anything else is a generic
 * bad request (400). Unknown internal failures surface as 500, never a silent
 * 200.
 */

import type { ExaClient, JudgeClient, ScanRequest } from '../../shared/contract'
import type { Env, ScannerConfig } from '../config'
import {
  ConfigError,
  ParseError,
  RedirectResolutionError,
  ReputationError,
  ScannerError,
  SourceResolutionError,
} from '../errors'
import { runScan } from '../scan/runScan'
import { ExaReputationClient } from '../scan/exa'
import { OpenAIJudge } from '../scan/judge'

/**
 * Construct the Exa reputation client from the env key, or `null` when no key is
 * present. A `null` client is handled fail-closed inside `runScan` (it escalates
 * rather than treating missing reputation as a clean ALLOW), so the absence of a
 * key is a safe, explicit state — never a silent allow.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function maybeExaClient(env: Env, config: ScannerConfig): ExaClient | null {
  if (typeof env.EXA_API_KEY !== 'string' || env.EXA_API_KEY.length === 0) {
    return null
  }
  return new ExaReputationClient(env.EXA_API_KEY, config)
}

/**
 * Construct the OpenAI judge client from the env key, or `null` when no key is
 * present. A `null` judge is handled fail-closed inside `runScan`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function maybeJudgeClient(env: Env, config: ScannerConfig): JudgeClient | null {
  if (
    typeof env.OPENAI_API_KEY !== 'string' ||
    env.OPENAI_API_KEY.length === 0
  ) {
    return null
  }
  return new OpenAIJudge(env.OPENAI_API_KEY, config)
}

/** HTTP status codes mapped from the error hierarchy. Named, never inlined. */
const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502

/**
 * Parse and shape-validate the JSON body into a {@link ScanRequest}. Only the
 * two known fields are read; unknown fields are ignored. A body that is not a
 * JSON object, or that carries neither string field, is a `ParseError` (mapped
 * to 422) rather than an unhandled exception.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} If the body is not JSON or lacks both string fields.
 */
async function parseScanBody(request: Request): Promise<ScanRequest> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new ParseError('request body must be a JSON object')
  }
  const record = raw as Record<string, unknown>
  const content =
    typeof record.content === 'string' ? record.content : undefined
  const sourceUrl =
    typeof record.sourceUrl === 'string' ? record.sourceUrl : undefined
  if (content === undefined && sourceUrl === undefined) {
    throw new ParseError(
      'request body must include a string "content" or "sourceUrl"',
    )
  }
  return { content, sourceUrl }
}

/**
 * Map a thrown error to its HTTP status. The error class is the contract:
 *   - ParseError / SourceResolutionError → 422 (the client sent input we cannot
 *                                          turn into a scannable skill)
 *   - ConfigError                    → 500 (server misconfiguration)
 *   - ReputationError / RedirectResolutionError → 502 (an upstream dependency)
 *   - any other ScannerError         → 400 (a domain-level client fault)
 *   - anything else                  → 500 (an unexpected internal fault)
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function statusForError(error: unknown): number {
  if (error instanceof ParseError || error instanceof SourceResolutionError) {
    return STATUS_UNPROCESSABLE
  }
  if (error instanceof ConfigError) {
    return STATUS_SERVER_ERROR
  }
  if (
    error instanceof ReputationError ||
    error instanceof RedirectResolutionError
  ) {
    return STATUS_BAD_GATEWAY
  }
  if (error instanceof ScannerError) {
    return STATUS_BAD_REQUEST
  }
  return STATUS_SERVER_ERROR
}

/**
 * Handle `POST /api/scan`.
 *
 * Builds the sponsor clients (Exa, OpenAI) only when their keys are present;
 * otherwise passes `null`, which `runScan` treats fail-closed. `scannedAt` is
 * set here, at the transport edge, so the time-varying value never enters the
 * hashed proof. On any error the class name is logged and a JSON error body with
 * the mapped status is returned — never a silent success.
 *
 * Time complexity: dominated by `runScan` (O(U·H + R + F)).
 * Space complexity: O(result size).
 *
 * @param request - The inbound HTTP request.
 * @param env - The Worker environment (sponsor keys live here).
 * @param config - The validated scanner configuration.
 * @returns The JSON `ScanResult`, or a JSON error with a mapped status.
 */
export async function handleScan(
  request: Request,
  env: Env,
  config: ScannerConfig,
): Promise<Response> {
  try {
    const body = await parseScanBody(request)

    const exa: ExaClient | null = maybeExaClient(env, config)
    const judge: JudgeClient | null = maybeJudgeClient(env, config)

    const result = await runScan(body, {
      config,
      exa,
      judge,
      scannedAt: new Date().toISOString(),
    })

    return Response.json(result, { status: STATUS_OK })
  } catch (error: unknown) {
    const className =
      error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`[handleScan] ${className}: ${message}`)
    return Response.json(
      { error: className, message },
      { status: statusForError(error) },
    )
  }
}
