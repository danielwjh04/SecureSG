/**
 * Zod schemas for every inbound request body. Per CLAUDE.md §4, external input
 * is parsed here before any logic runs; a parse failure becomes a structured
 * error at the boundary, never an unhandled throw.
 */

import { z } from 'zod'

const proofStepKindSchema = z.enum([
  'SKILL_INPUT',
  'URL_EXTRACTED',
  'REDIRECT_HOP',
  'REPUTATION',
  'INJECTION',
  'VERDICT',
])

const proofStepSchema = z.object({
  index: z.number().int().nonnegative(),
  kind: proofStepKindSchema,
  payload: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
  prevHash: z.string().min(1),
  currHash: z.string().min(1),
})

const proofSchema = z.object({
  genesisHash: z.string().min(1),
  steps: z.array(proofStepSchema),
  headHash: z.string().min(1),
})

/** Body of `POST /api/verify`. */
export const verifyRequestSchema = z.object({ proof: proofSchema })

/**
 * Body of `POST /api/scan`. Exactly one of `content` / `sourceUrl` must be a
 * non-empty string.
 */
export const scanRequestSchema = z
  .object({
    content: z.string().min(1).optional(),
    sourceUrl: z.string().url().optional(),
  })
  .refine(
    (body) => Boolean(body.content) !== Boolean(body.sourceUrl),
    { message: 'provide exactly one of `content` or `sourceUrl`' },
  )
