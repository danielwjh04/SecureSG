/**
 * `POST /api/scan` handler.
 *
 * Validates the body with Zod at the edge, builds the real clients when their
 * capabilities are present (Workers AI inference; the reputation client lands
 * with the indicator feed), stamps a response timestamp OUTSIDE the hashed
 * proof, runs the pure {@link runScan} orchestrator, and maps the typed error
 * hierarchy to HTTP status codes. Never a silent 200 on failure.
 */

import type { Env, ScannerConfig } from '../config/env'
import type { ScanRequest } from '../schemas/contract'
import {
  ConfigError,
  InferenceError,
  ParseError,
  RedirectResolutionError,
  ReputationError,
  ScannerError,
  SourceResolutionError,
} from '../errors'
import { runScan } from '../scanner/runScan'
import { buildInferenceClient, type AiRunner } from '../pipeline/inference'
import { scanRequestSchema } from '../schemas/validate'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502

/**
 * Parse and Zod-validate the JSON body into a {@link ScanRequest}. A body that
 * is not JSON, or fails validation (e.g. neither/both of content & sourceUrl),
 * is a {@link ParseError} (mapped to 422), never an unhandled throw.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} On non-JSON or schema-invalid input.
 */
async function parseScanBody(request: Request): Promise<ScanRequest> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = scanRequestSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid scan request: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Map a thrown error to its HTTP status. The error class is the contract:
 * ParseError / SourceResolutionError → 422; ConfigError → 500; ReputationError /
 * RedirectResolutionError / InferenceError → 502; any other ScannerError → 400;
 * anything else → 500.
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
    error instanceof RedirectResolutionError ||
    error instanceof InferenceError
  ) {
    return STATUS_BAD_GATEWAY
  }
  if (error instanceof ScannerError) {
    return STATUS_BAD_REQUEST
  }
  return STATUS_SERVER_ERROR
}

/**
 * Handle `POST /api/scan`. Builds the Workers AI inference client only when the
 * `AI` binding is present (free tier / no binding → `null`, handled fail-closed
 * inside `runScan`). `scannedAt` is stamped here, at the edge, so the
 * time-varying value never enters the hashed proof.
 *
 * Time complexity: dominated by `runScan` (O(U·H + R + F)).
 * Space complexity: O(result size).
 */
export async function handleScan(
  request: Request,
  env: Env,
  config: ScannerConfig,
): Promise<Response> {
  try {
    const body = await parseScanBody(request)

    const inference =
      env.AI !== undefined && env.AI !== null
        ? // The Workers AI binding's `run` is structurally an AiRunner.
          buildInferenceClient(env.AI as unknown as AiRunner, config)
        : null

    const result = await runScan(body, {
      config,
      reputation: null, // indicator-feed client lands with the D1 cache
      inference,
      scannedAt: new Date().toISOString(),
      githubToken: typeof env.GITHUB_TOKEN === 'string' ? env.GITHUB_TOKEN : undefined,
    })

    return Response.json(result, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.error(`[handleScan] ${className}: ${message}`)
    return Response.json({ error: className, message }, { status: statusForError(error) })
  }
}
