/**
 * `POST /api/verify` — re-verify a submitted proof chain. Pure: zero
 * subrequests, no bindings. This is the public half of "Don't trust us,
 * verify": anyone can re-check a proof we issued.
 */

import type { ScannerConfig } from '../config/env'
import type { VerifyResult } from '../schemas/contract'
import { deriveGenesisHash } from '../audit/chain'
import { verifyChain } from '../audit/verify'
import { ParseError } from '../errors'
import { verifyRequestSchema } from '../schemas/validate'

/**
 * Validate the body, then verify the chain. The submitted proof's
 * `genesisHash` is first checked against the genesis derived from
 * `config.genesisSeed`; a mismatch is `CHAIN_BROKEN` at index 0 (fail-closed
 * against a swapped/forged genesis) before the per-link pass runs.
 *
 * Time complexity: O(n) in step count. Space complexity: O(1) beyond input.
 *
 * @throws {ParseError} If the body is not valid JSON or fails schema validation.
 */
export async function handleVerify(
  request: Request,
  config: ScannerConfig,
): Promise<Response> {
  let body: unknown
  try {
    body = await request.json()
  } catch {
    throw new ParseError('request body is not valid JSON')
  }

  const parsed = verifyRequestSchema.safeParse(body)
  if (!parsed.success) {
    throw new ParseError(`invalid verify request: ${parsed.error.message}`)
  }

  const proof = parsed.data.proof
  const expectedGenesis = await deriveGenesisHash(config.genesisSeed)

  let result: VerifyResult
  if (proof.genesisHash !== expectedGenesis) {
    result = { status: 'CHAIN_BROKEN', firstInvalidIndex: 0 }
  } else {
    const verification = await verifyChain(proof)
    result = verification.ok
      ? { status: 'CHAIN_OK', firstInvalidIndex: null }
      : { status: 'CHAIN_BROKEN', firstInvalidIndex: verification.firstBrokenIndex }
  }

  return Response.json(result)
}
