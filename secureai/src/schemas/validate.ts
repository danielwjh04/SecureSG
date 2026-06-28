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

/**
 * Body of `POST /api/guard`: a Claude Code PreToolUse hook payload. Only the
 * three load-bearing fields are validated strictly — the literal event name, a
 * non-empty tool name, and the tool-input record the scanner serializes. The
 * optional context fields Claude Code sends (`session_id`, `transcript_path`,
 * `cwd`) are accepted when present but not required, and any further fields the
 * hook protocol adds in future pass through untouched (no `.strict()`), so a
 * protocol addition never turns a real call into a parse failure.
 */
export const preToolUseSchema = z.object({
  hook_event_name: z.literal('PreToolUse'),
  tool_name: z.string().min(1),
  tool_input: z.record(z.string(), z.unknown()),
  session_id: z.string().optional(),
  transcript_path: z.string().optional(),
  cwd: z.string().optional(),
})

/** The validated PreToolUse payload `POST /api/guard` operates on. */
export type PreToolUsePayload = z.infer<typeof preToolUseSchema>

/**
 * Body of `POST /api/signup`: a single account email. Trimmed, lowercased, and
 * validated as an email so the stored value is canonical and the UNIQUE
 * constraint dedupes case/whitespace variants. `.strict()` rejects unexpected
 * fields so a malformed payload fails closed at the boundary.
 */
export const signupSchema = z
  .object({
    email: z
      .string()
      .trim()
      .toLowerCase()
      .email()
      .max(254),
  })
  .strict()

/** The validated signup payload `POST /api/signup` operates on. */
export type SignupPayload = z.infer<typeof signupSchema>
